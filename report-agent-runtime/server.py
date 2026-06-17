"""
Security Report Sub-Agent — synthesizes security reports for the Agentic SOC.
BedrockAgentCoreApp + Strands Agent (Sonnet 4.6).
Receives a natural-language request (with findings/hunting/investigation context passed in
by the Host Agent) and produces a structured security report: posture summary, incident
timeline, threat-hunt findings, or compliance assessment.
"""
import json
import logging
import os

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("report-agent")

REGION = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION', 'ap-northeast-2')
os.environ['AWS_DEFAULT_REGION'] = REGION

app = BedrockAgentCoreApp()
MODEL_ID = os.environ.get('INFERENCE_PROFILE_SONNET_ARN') or os.environ.get('BEDROCK_MODEL_ID', 'global.anthropic.claude-sonnet-4-6')

SYSTEM_PROMPT = """You are a Security Report specialist in an Agentic SOC. You synthesize the
findings gathered by other agents (Investigation, Threat Hunting, Log Query) into a clear,
executive-ready security report. You do not call tools — you receive the collected security
data/context in the request and compose the report.

## REPORT TYPES (infer from the request):
- security_posture: Overall AWS security posture — open findings by severity, top risks, exposure summary
- incident_timeline: Reconstructed timeline of a security incident with MITRE ATT&CK mapping and blast radius
- threat_hunt: Results of a proactive hunt — weaknesses found (IAM/network/encryption/logging gaps), prioritized
- compliance: Compliance assessment against CIS AWS Foundations Benchmark / NIST CSF / AWS Well-Architected

## REPORT STRUCTURE (adapt to the type):
1. 📊 Executive Summary — 1 table: 항목 / 상태 / 심각도 (CRITICAL>HIGH>MEDIUM>LOW)
2. 🔴 Key Findings — grouped by severity, each with evidence (resource ARN, account, finding type)
3. 🛡️ MITRE ATT&CK / Compliance mapping where relevant (tactic/technique IDs or CIS controls)
4. ✅ Recommendations — prioritized, specific, actionable (cite resource IDs / exact remediation)
5. Note that actual remediation goes through the Response Agent with analyst approval.

## RULES:
- ALL output in Korean (한글); keep technical terms (finding types, MITRE IDs, ARNs, CIS controls, metric names) in English.
- Use Markdown tables and severity emojis for scannability.
- Be specific — reference actual data points from the provided context. Never invent findings.
- If the provided context is sparse, say so explicitly and report on what is available.
- Keep it executive-ready: concise, prioritized, decision-oriented."""


def _extract_text(result):
    if not result or not result.message:
        return 'No response generated.'
    texts = []
    for block in result.message.get('content', []):
        if isinstance(block, dict):
            if block.get('type') == 'text':
                texts.append(block.get('text', ''))
            elif 'text' in block:
                texts.append(block['text'])
    return '\n'.join(texts) or 'No response generated.'


def _count_tool_uses(agent):
    count = 0
    for m in agent.messages:
        if m.get('role') == 'assistant' and isinstance(m.get('content'), list):
            for block in m['content']:
                if isinstance(block, dict):
                    if block.get('type') == 'tool_use' or 'toolUse' in block:
                        count += 1
    return count


def _extract_usage(result):
    """Extract token usage from Strands Agent result."""
    try:
        if not result:
            return {}
        metrics = getattr(result, 'metrics', None)
        if metrics:
            usage = metrics if isinstance(metrics, dict) else getattr(metrics, 'to_dict', lambda: {})()
            if 'inputTokens' in usage or 'outputTokens' in usage:
                return usage
            accumulated = getattr(metrics, 'accumulated', None)
            if accumulated:
                return accumulated if isinstance(accumulated, dict) else vars(accumulated)
        usage_attr = getattr(result, 'usage', None)
        if usage_attr:
            return usage_attr if isinstance(usage_attr, dict) else vars(usage_attr)
        if result.message:
            msg_usage = result.message.get('usage', {})
            if msg_usage:
                return msg_usage
    except Exception as e:
        logger.debug(f"Failed to extract usage: {e}")
    return {}


@app.entrypoint
async def handle_request(payload, context=None):
    if payload.get('type') == 'ping':
        return {"event": "pong"}

    # Accept the standard {message} contract (Host Agent passes context in the message).
    # Backward-compat: also accept legacy {report_type, data}.
    message = payload.get('message', '')
    if not message:
        report_type = payload.get('report_type', '')
        data = payload.get('data', {})
        if report_type or data:
            message = (f"다음 '{report_type}' 보안 데이터로 리포트를 작성하세요.\n\n"
                       f"{json.dumps(data, ensure_ascii=False, default=str)[:12000]}")
    if not message:
        return {"error": "No message provided"}

    logger.info(f"Report Agent request: {message[:100]}...")

    try:
        model = BedrockModel(model_id=MODEL_ID, max_tokens=8192, cache_prompt="default")
        agent = Agent(model=model, system_prompt=SYSTEM_PROMPT, tools=[])
        result = agent(message)
        return {
            "result": _extract_text(result),
            "tool_count": _count_tool_uses(agent),
            "usage": _extract_usage(result),
        }
    except Exception as e:
        logger.error(f"Report Agent error: {e}")
        return {"error": str(e)}


if __name__ == "__main__":
    app.run()
