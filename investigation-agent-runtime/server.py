"""
Investigation Sub-Agent — Automated security incident investigation (Agentic SOC).
BedrockAgentCoreApp + Strands Agent (Sonnet 4.6).
Core tools: GuardDuty/Security Hub finding detail, CloudTrail change correlation,
CloudWatch Logs search/anomalies, VPC Flow Logs forensics, MITRE ATT&CK mapping.
Optional: OpenSearch, GitHub (env-var gated).
"""
import json
import logging
import os

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel
from tools import get_all_tools

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("investigation-agent")

REGION = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION', 'ap-northeast-2')
os.environ['AWS_DEFAULT_REGION'] = REGION

app = BedrockAgentCoreApp()
MODEL_ID = os.environ.get('INFERENCE_PROFILE_SONNET_ARN') or os.environ.get('BEDROCK_MODEL_ID', 'global.anthropic.claude-sonnet-4-6')


def _build_system_prompt():
    """Build dynamic system prompt based on active integrations."""
    core = """You are a Security Incident Investigation specialist agent in an Agentic SOC.
Investigate security findings (GuardDuty, Security Hub, Inspector, CloudTrail) by gathering
evidence, correlating signals, mapping to MITRE ATT&CK, and estimating root cause.
ALWAYS use tools to get actual data - never guess.

## CORE TOOLS (Always Available):
- get_guardduty_finding: Fetch GuardDuty finding detail (by finding_id) or list recent high-severity findings
- get_securityhub_finding: Fetch Security Hub finding detail (by finding_id) or list active findings
- get_cloudtrail_changes: AWS API write/change events (who did what, when) — essential for correlating a finding with recent IAM/EC2/config changes and attacker actions
- search_cloudwatch_logs: CloudWatch Logs keyword/pattern search (application/auth/security logs)
- detect_log_anomalies: Log volume anomaly detection (spike detection vs baseline)
- analyze_vpc_flow: VPC Flow Logs network forensics — reconstruct an IP/ENI's network activity (top talkers, rejected connections, port scans, data egress). Use modes: summary/rejected/portscan/egress
- map_to_mitre: Map a finding type/title/description to MITRE ATT&CK tactics and techniques"""

    optional = ""
    if os.environ.get('OPENSEARCH_ENDPOINT'):
        optional += """

## OPENSEARCH TOOLS (Active):
- opensearch_search_logs: Log keyword/pattern search
- opensearch_anomaly_detection: Log volume anomaly pattern detection
- opensearch_get_error_summary: Error log statistics by type/source"""

    if os.environ.get('GITHUB_PAT'):
        optional += """

## GITHUB TOOLS (Active):
- github_create_issue: Create incident issue
- github_add_comment: Add analysis comment to issue
- github_list_issues: List incident issues"""

    workflow = """

## INVESTIGATION WORKFLOW:

### Step 1: Finding Triage & Context
- If given a finding_id, fetch full detail (get_guardduty_finding / get_securityhub_finding)
- Identify: threat type, affected resource (instance/access key/bucket), source IP, account, region, timeframe
- map_to_mitre on the finding type to frame the adversary behavior

### Step 2: Evidence Collection
1. get_cloudtrail_changes: what API actions occurred around the finding time — correlate attacker IP / principal with changes (privilege escalation, persistence, defense evasion)
2. analyze_vpc_flow: if a source/dest IP is involved, reconstruct network activity (port scans, C2 egress, lateral movement, data exfiltration volume)
3. search_cloudwatch_logs / detect_log_anomalies: auth failures, error spikes, suspicious activity in relevant log groups
4. OpenSearch: structured security log search (if configured)

### Step 3: Correlation Analysis
- Build a timeline around the finding (T ±30 min): finding → CloudTrail actions → network flows → log events
- Correlate the same principal/IP across sources (e.g. credential theft → AssumeRole → S3 exfiltration)
- Distinguish attacker activity from legitimate operations

### Step 4: Root Cause & Scope
- State the most likely attack narrative ranked by confidence, with evidence cited
- Assess blast radius: which resources/accounts/data are affected
- Map the full kill chain to MITRE ATT&CK tactics

### Step 5: Response Guide (recommendations only — do NOT execute)
- Containment: which resources to isolate, which credentials to revoke, which SG rules to block
- Note that actual remediation goes through the Response Agent with analyst approval
- Provide specific AWS CLI commands for the analyst to review
- Suggest detection improvements (GuardDuty/Security Hub/Config rules)

## RESPONSE RULES:
- ALL output MUST be in Korean (한글) — analysis, reports, response guides
- Technical terms (finding types, MITRE IDs, ARNs, tool names) stay in English
- Organize by severity: CRITICAL > HIGH > MEDIUM > LOW
- Always cite specific data points (timestamps, IPs, principals, ARNs) as evidence
- Always include MITRE ATT&CK mapping when a finding type is known
- Keep responses actionable and concise"""

    return core + optional + workflow


SYSTEM_PROMPT = _build_system_prompt()


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

    logger.info(f"Investigation Agent request: {message[:100]}...")

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
        logger.error(f"Investigation Agent error: {e}")
        return {"error": str(e)}


if __name__ == "__main__":
    app.run()
