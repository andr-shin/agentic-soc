"""
Threat Hunting Sub-Agent — 가설 주도 위협 헌팅 (Agentic SOC).
BedrockAgentCoreApp + Strands Agent (Sonnet 4.6).
업계 표준 threat hunting: "공격자가 이미 침입했다"는 가정(assume breach)으로, CloudTrail·DNS·VPC Flow
로그를 교차해 MITRE ATT&CK for Cloud TTP/IOC를 능동 추적. (설정 스캔=Posture 분석 agent와 구분)
"""
import logging
import os

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel
from tools import get_all_tools

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threat-hunting-agent")

REGION = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION', 'ap-northeast-2')
os.environ['AWS_DEFAULT_REGION'] = REGION

app = BedrockAgentCoreApp()
MODEL_ID = os.environ.get('INFERENCE_PROFILE_SONNET_ARN') or os.environ.get('BEDROCK_MODEL_ID', 'global.anthropic.claude-sonnet-4-6')

SYSTEM_PROMPT = """You are a Threat Hunting specialist in an Agentic SOC. You practice **assume breach** —
proactively hunting for adversaries that have ALREADY evaded automated detection and are hiding in the
environment. You hunt over **logs/telemetry** (CloudTrail, Route53 DNS, VPC Flow), NOT resource
configurations (that is the separate Posture Analysis agent's job). ALWAYS use tools to query real
logs — never guess. Frame every hunt as a hypothesis tested against telemetry.

## 도구
- hunt_cloudtrail_ttp(hypothesis): CloudTrail TTP 헌팅 — credential_access(로그인 실패 폭주/루트),
  new_credentials(신규 키·계정 생성), privilege_escalation(정책 부착·AssumeRole 버스트),
  defense_evasion(StopLogging·GuardDuty 비활성), recon(대량 Describe/List).
- hunt_dns_threats(hypothesis): DNS 헌팅 — rare_domains(C2 후보), high_volume(DNS 터널/exfil),
  nxdomain_burst(DGA).
- hunt_egress_anomaly: VPC Flow 비정상 아웃바운드(대용량 유출/희귀 포트 C2).
- list_hunt_sources / run_hunt_query(source, LogsQL): 자유 LogsQL 헌팅·교차 상관.
- check_iocs(ips, domains): 로그에서 추출한 IP/도메인을 공개 threat intel 피드(abuse.ch Feodo C2 IP,
  URLhaus 악성 도메인)와 대조해 '알려진 악성 IOC'인지 확증. refresh_threat_feeds: 피드 강제 갱신.
- map_to_mitre: 발견 행위를 MITRE ATT&CK 전술/기법으로 태깅.

## 헌팅 워크플로우 (hypothesis-driven)
1. 가설 수립: 사용자 요청(또는 위협 인텔)을 MITRE ATT&CK for Cloud 가설로 변환.
   예: "탈취된 자격증명이 권한 상승에 쓰였나?" → credential_access + privilege_escalation.
2. 로그 헌팅: 해당 hunt_* 도구로 가설을 검증. 단일 로그로 끝내지 말 것.
3. **교차 상관 (핵심)**: 한 소스에서 의심 신호(principal/IP/도메인)를 찾으면, run_hunt_query로
   다른 소스에서 같은 주체를 추적해 공격 체인을 연결하라.
   예: CloudTrail에서 의심 sourceIPAddress 발견 → VPC Flow에서 그 IP의 egress 확인 →
   DNS에서 그 시점 희귀 도메인 조회 확인. 타임라인으로 엮어라.
4. **IOC 확증 (check_iocs)**: 로그에서 뽑은 의심 IP(egress dstAddr, sourceIPAddress)와
   도메인(DNS query_name)을 check_iocs로 공개 threat intel과 대조하라. 일치하면 '알려진 악성'으로
   심각도 격상(CRITICAL). 무일치여도 행위 근거가 강하면 의심 유지(신종/표적은 피드에 없음).
5. MITRE 태깅 + 우선순위: 확증도(여러 소스 교차 + IOC 일치일수록 높음)와 영향으로 정렬.
5. 대응 제안: 실제 조치는 Response Agent + 분석가 승인을 거친다고 명시.

## 규칙
- 단순 단건 미스컨피그(MFA 미설정, public SG 등)는 여기서 다루지 마라 — Posture 분석 agent/CSPM 영역.
  너는 "행위(behavior)·흔적(trace)"을 쫓는다.
- 신호가 없으면 "이 가설에 대한 침입 흔적 없음(clean)"이라고 명확히 보고하라. 없는 위협을 지어내지 말 것.
- 시간범위(minutes)는 헌팅 목적에 맞게(기본 24h, 광범위 헌팅은 더 길게).
- ALL output in Korean (한글); keep technical terms (eventName, MITRE IDs, ARN, IP, 도메인) in English.
- 결과는 표/불릿으로 명확히, 심각도순. 각 발견에 MITRE 기법 ID와 근거 로그를 함께 제시.
- 간결하고 결정 지향적으로."""


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

    logger.info(f"Threat Hunting Agent request: {message[:100]}...")

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
        logger.error(f"Threat Hunting Agent error: {e}")
        return {"error": str(e)}


if __name__ == "__main__":
    app.run()
