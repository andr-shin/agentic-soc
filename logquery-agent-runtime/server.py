"""
Log Query Sub-Agent — CloudWatch Unified Data Store log querying (Agentic SOC).
BedrockAgentCoreApp + Strands Agent (Sonnet 4.6).
Translates natural language into CloudWatch Logs Insights (LogsQL) and executes it across
security log sources (VPC Flow / CloudTrail / DNS / WAF / NLB). Also used to generate
finding-correlated queries for investigation.
"""
import json
import logging
import os

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel
from tools import get_all_tools

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("logquery-agent")

REGION = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION', 'ap-northeast-2')
os.environ['AWS_DEFAULT_REGION'] = REGION

app = BedrockAgentCoreApp()
MODEL_ID = os.environ.get('INFERENCE_PROFILE_SONNET_ARN') or os.environ.get('BEDROCK_MODEL_ID', 'global.anthropic.claude-sonnet-4-6')


SYSTEM_PROMPT = """You are a Log Query specialist in an Agentic SOC. You query the CloudWatch
Unified Data Store by translating natural-language requests into CloudWatch Logs Insights (LogsQL),
then executing them across centralized security log sources. ALWAYS use tools - never invent results.

## TOOLS:
- list_log_sources: List available security log sources and their LogsQL field schemas. Call this first when unsure.
- get_log_fields: Sample a source's recent records to discover available fields.
- run_logs_query: Execute a LogsQL query against a source. Do NOT embed a time range in the query — pass `minutes`.

## LOG SOURCES (friendly name → typical use):
- vpc-flowlogs: network forensics (srcAddr/dstAddr/dstPort/action/bytes) — REJECTs, port scans, egress
- cloudtrail: API audit (eventName/userIdentity.arn/sourceIPAddress/errorCode) — who did what
- dns-queries / route53-resolver: DNS exfiltration, C2 domains (query_name/rcode/srcaddr)
- waf: web attacks (action/httpRequest.clientIp/uri/country/terminatingRuleId)
- nlb-access: connection-level access logs

## LOGSQL GUIDELINES:
- Syntax: `fields ... | filter ... | stats ... by ... | sort ... | limit N`
- String match: `filter srcAddr = "10.0.1.5"`; pattern: `filter @message like /ERROR/`
- Aggregations: `stats count(*) as n by dstPort | sort n desc`
- Always include a reasonable limit; prefer stats over raw dumps for large windows.

## WORKFLOW:
1. Pick the right source for the question (or list_log_sources if unsure).
2. Build a focused LogsQL query; if investigating a finding, filter by the relevant IP/principal/resource.
3. Execute with run_logs_query (set `minutes` for the time window).
4. Summarize findings: highlight anomalies (REJECT spikes, rare ports, unusual principals, blocked WAF requests).

## RESPONSE RULES:
- ALL output in Korean (한글); keep field names, LogsQL, IPs, ARNs in English.
- Show the exact LogsQL you ran, then the result summary as a table or bullet points.
- If a log group is missing (source not onboarded), say so clearly.
- Keep responses concise and actionable."""


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

    message = payload.get('message', '')
    if not message:
        return {"error": "No message provided"}

    logger.info(f"Log Query Agent request: {message[:100]}...")

    try:
        model = BedrockModel(model_id=MODEL_ID, max_tokens=8192, cache_prompt="default", cache_tools="default")
        agent = Agent(model=model, system_prompt=SYSTEM_PROMPT, tools=get_all_tools())
        result = agent(message)
        return {
            "result": _extract_text(result),
            "tool_count": _count_tool_uses(agent),
            "usage": _extract_usage(result),
        }
    except Exception as e:
        logger.error(f"Log Query Agent error: {e}")
        return {"error": str(e)}


if __name__ == "__main__":
    app.run()
