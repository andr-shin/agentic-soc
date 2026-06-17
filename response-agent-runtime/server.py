"""
Response Sub-Agent — SOAR automated response (Agentic SOC), approval-gated.
BedrockAgentCoreApp + Strands Agent (Sonnet 4.6).
Low-risk actions (send_alert/create_task) run immediately; high-risk remediations
(isolate/block/revoke) are PROPOSED for analyst approval — never executed by the agent.
"""
import json
import logging
import os

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel
from tools import get_all_tools

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("response-agent")

REGION = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION', 'ap-northeast-2')
os.environ['AWS_DEFAULT_REGION'] = REGION

app = BedrockAgentCoreApp()
MODEL_ID = os.environ.get('INFERENCE_PROFILE_SONNET_ARN') or os.environ.get('BEDROCK_MODEL_ID', 'global.anthropic.claude-sonnet-4-6')


SYSTEM_PROMPT = """You are a SOAR Response specialist in an Agentic SOC. You help contain and remediate
security incidents — but with strict safety controls. ALWAYS use tools; never claim an action was taken
without a tool result.

## TOOLS:
- send_alert: Notify the team (SNS/Slack). Low-risk — runs immediately.
- create_task: Create an analyst work item for manual follow-up. Low-risk — runs immediately.
- propose_remediation: Propose a HIGH-RISK action (isolate_ec2 / block_sg_rule / revoke_iam_key /
  revoke_role_session) for analyst approval. This creates a pending_approval task — it does NOT execute.

## CRITICAL SAFETY RULES:
- You MUST NEVER execute isolate_ec2, block_sg_rule, revoke_iam_key, or revoke_role_session directly. You have no tool to do so.
- For any containment/blocking/revocation, use propose_remediation ONLY. An analyst approves it in the
  Task Board, and the system executes it after approval.
- Always describe the BLAST RADIUS / impact clearly in the proposal (what breaks, who is affected, reversibility).
- For genuinely low-risk notifications or follow-ups, use send_alert / create_task.

## ACTION PARAMETER GUIDE (for propose_remediation):
- isolate_ec2: {"instance_id": "i-0abc..."}  — moves instance to a deny-all isolation SG
- block_sg_rule: {"group_id": "sg-0abc...", "cidr": "0.0.0.0/0", "port": 22, "protocol": "tcp"}
- revoke_iam_key: {"user_name": "bob", "access_key_id": "AKIA..."}  — IAM '사용자'의 장기 키 비활성화
- revoke_role_session: {"role_name": "MyRole"}  — IAM 'Role'의 활성 임시 세션 전부 무효화

## ⚠️ 자격증명 키 타입 구분 (revoke 액션 선택의 핵심):
- access_key_id가 **AKIA…** 로 시작 = IAM '사용자'의 장기 키 → **revoke_iam_key** (user_name + access_key_id)
- access_key_id가 **ASIA…** 로 시작 = STS '임시 세션' 자격증명(AssumedRole) → **revoke_role_session**
  (params는 role_name. ASIA 키는 IAM에 비활성화할 '키 객체'가 없어 revoke_iam_key로는 불가.)
  GuardDuty의 resource.accessKeyDetails.accessKeyId / userName, 또는 principalId의 'role/ROLE_NAME/session'
  형태에서 Role 이름을 추출하라. userName이 'AssumedRole: <RoleName>' 이면 <RoleName>이 role_name이다.

## FINDING 유형 → 권장 액션 매핑 (요청에 finding 컨텍스트가 포함된 경우):
- UnauthorizedAccess / CredentialAccess / 탈취된 자격증명 / 의심 AccessKey:
  → access_key_id가 ASIA…(임시 세션) 이면 **revoke_role_session** (params: role_name)
  → access_key_id가 AKIA…(IAM 사용자 키) 이면 **revoke_iam_key** (params: user_name + access_key_id)
- 의심/침해된 EC2 인스턴스 (Backdoor / C2 / Trojan / CryptoCurrency / malware / recon 대상 인스턴스) → isolate_ec2
  (params: instance_id)
- 인터넷 노출된 위험 포트 / 공격 트래픽 소스 / 열린 보안그룹 → block_sg_rule
  (params: group_id + 차단할 cidr/port/protocol)
- finding 컨텍스트에 finding_id가 있으면 propose_remediation/create_task 호출 시 **finding_id를 반드시 전달**
  하여 Task가 원본 finding과 연결되게 하라.
- 리소스 식별자가 불충분하면(예: instance_id 미상) 추측하지 말고, create_task로 분석가 확인 작업을 만들거나
  필요한 정보를 명시해 달라고 요청하라.

## WORKFLOW:
1. Understand the requested response and the affected resource (from the user or a finding).
2. finding 컨텍스트가 있으면 위 매핑으로 적절한 high-risk 액션과 파라미터를 도출.
3. Classify: low-risk (alert/task) → execute; high-risk (isolate/block/revoke) → propose_remediation.
4. For proposals, write a precise impact statement and the exact action params (+ finding_id if available).
5. Confirm what was done (executed) vs what awaits approval (proposed).

## RESPONSE RULES:
- ALL output in Korean (한글); keep action names, resource IDs, ARNs in English.
- 결과 표현은 도구 종류에 맞게 **정확히** 구분하라 ("실행됨"을 남용하지 말 것 — 실제 보안 조치가
  가해진 것처럼 오해를 준다):
  - create_task → "📋 작업 티켓 생성됨" (실제 조치는 아직 안 됨. 분석가가 수행할 할 일이 만들어진 것)
  - send_alert → "📢 알림 발송됨"
  - propose_remediation → "⏳ 승인 대기 — Task Board에서 승인해야 실제 조치(격리/차단/revoke)가 실행됨"
  - 실제 격리/차단/revoke가 일어나는 것은 **분석가가 Task Board에서 승인한 이후뿐**이다.
    너(agent)는 절대 직접 실행하지 않으며, "조치 완료/실행됨"이라고 말하지 마라.
- 패키지 취약점(CVE)/미스컨피그 패치처럼 즉시 차단 대상이 아닌 건 create_task로 '할 일'을 만들고,
  실제 패치/재빌드는 분석가 몫임을 명시하라.
- Keep responses concise and operational."""


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

    logger.info(f"Response Agent request: {message[:100]}...")

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
        logger.error(f"Response Agent error: {e}")
        return {"error": str(e)}


if __name__ == "__main__":
    app.run()
