"""Sub-Agent invocation tools for the SOC Host Agent orchestrator.
Environment-variable-based agent registry — only configured agents are exposed.
"""
import json
import logging
import os
import threading

import boto3
from strands import tool

logger = logging.getLogger("soc-host-agent.sub-agents")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')
_counters = {'investigation': 0, 'hunting': 0, 'threat_hunting': 0, 'logquery': 0, 'response': 0, 'report': 0}
_counter_lock = threading.Lock()


def _invoke_sub_agent(arn_env, qual_env, key, request):
    """Common helper to invoke a sub-agent runtime and return its response."""
    runtime_arn = os.environ.get(arn_env, '')
    qualifier = os.environ.get(qual_env, '')
    if not runtime_arn:
        return {'error': f'{arn_env} not configured'}
    with _counter_lock:
        _counters[key] += 1
        n = _counters[key]
    sid = f"soc-{key}-{n:032d}"
    try:
        client = boto3.client('bedrock-agentcore', region_name=REGION)
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            qualifier=qualifier,
            runtimeSessionId=sid,
            payload=json.dumps({"message": request}),
            contentType='application/json'
        )
        body = resp['response'].read() if hasattr(resp.get('response', ''), 'read') else resp.get('response', b'{}')
        return json.loads(body)
    except Exception as e:
        logger.error(f"Sub-agent {key} error: {e}")
        return {'error': str(e)}


# ============================================================
# SOC Sub-Agents
# ============================================================

@tool
def invoke_investigation_agent(request: str) -> dict:
    """보안 인시던트 심층 조사 전문 에이전트: GuardDuty/Security Hub finding 파싱, CloudWatch Logs 검색 및 이상 탐지, CloudTrail 변경 이력 상관 분석, VPC Flow 네트워크 패턴 분석, 타임라인 재구성, MITRE ATT&CK 매핑, 근본 원인 추정 및 대응 가이드 생성. 자연어 요청을 보내세요."""
    return _invoke_sub_agent('INVESTIGATION_AGENT_RUNTIME_ARN', 'INVESTIGATION_AGENT_QUALIFIER', 'investigation', request)


@tool
def invoke_hunting_agent(request: str) -> dict:
    """능동적 위협 헌팅 전문 에이전트: AWS 보안 태세에 대한 SQL 기반 능동 탐색. IAM 과다 권한, 노출된 보안 그룹, 미암호화 리소스, MFA 미설정, 비정상 API 패턴 등을 크로스 리소스 JOIN으로 헌팅합니다. 자연어 요청을 보내면 SQL을 자동 생성하고 실행합니다."""
    return _invoke_sub_agent('HUNTING_AGENT_RUNTIME_ARN', 'HUNTING_AGENT_QUALIFIER', 'hunting', request)


@tool
def invoke_threat_hunting_agent(request: str) -> dict:
    """로그 기반 위협 헌팅(assume breach) 전문 에이전트: CloudTrail/DNS/VPC Flow 로그를 교차해 공격자 행위·흔적(로그인 폭주, 권한 상승, 횡적 이동, C2 비콘, DGA, 데이터 exfil, defense evasion)을 MITRE ATT&CK 가설로 능동 추적합니다. abuse.ch IOC 피드로 평판 대조도 합니다. 행위(behavior) 점검 — 설정 점검(Posture)과 구분됩니다. 자연어 요청을 보내세요."""
    return _invoke_sub_agent('THREAT_HUNTING_AGENT_RUNTIME_ARN', 'THREAT_HUNTING_AGENT_QUALIFIER', 'threat_hunting', request)


@tool
def invoke_logquery_agent(request: str) -> dict:
    """로그 질의 전문 에이전트: CloudWatch Unified Data Store에 대한 자연어→LogsQL 변환 및 실행. VPC Flow Logs, CloudTrail, Route53 DNS, WAF, NLB 로그를 조회하고 finding과 연관된 로그 패턴을 분석합니다. 자연어 요청을 보내세요."""
    return _invoke_sub_agent('LOGQUERY_AGENT_RUNTIME_ARN', 'LOGQUERY_AGENT_QUALIFIER', 'logquery', request)


@tool
def invoke_response_agent(request: str) -> dict:
    """자동 대응(SOAR) 전문 에이전트: AgentCore Gateway를 통해 EC2 격리, 보안 그룹 규칙 차단, IAM 자격증명 비활성화 등의 조치를 수행합니다. 모든 write 액션은 승인 게이트를 거칩니다 — 분석가 승인 전에는 Task로 큐잉됩니다. 자연어 요청을 보내세요."""
    return _invoke_sub_agent('RESPONSE_AGENT_RUNTIME_ARN', 'RESPONSE_AGENT_QUALIFIER', 'response', request)


@tool
def invoke_report_agent(request: str) -> dict:
    """보안 리포트 합성 전문 에이전트: 조사·헌팅 결과를 종합하여 보안 감사, 인시던트 타임라인, 컴플라이언스 리포트를 생성합니다. 자연어 요청을 보내세요."""
    return _invoke_sub_agent('REPORT_AGENT_RUNTIME_ARN', 'REPORT_AGENT_QUALIFIER', 'report', request)


# ============================================================
# Dynamic agent registry
# ============================================================

# (env_key, tool_fn) — tool is included only when env_key is set and non-empty
_AGENT_REGISTRY = [
    ('INVESTIGATION_AGENT_RUNTIME_ARN', invoke_investigation_agent),
    ('HUNTING_AGENT_RUNTIME_ARN', invoke_hunting_agent),
    ('THREAT_HUNTING_AGENT_RUNTIME_ARN', invoke_threat_hunting_agent),
    ('LOGQUERY_AGENT_RUNTIME_ARN', invoke_logquery_agent),
    ('RESPONSE_AGENT_RUNTIME_ARN', invoke_response_agent),
    ('REPORT_AGENT_RUNTIME_ARN', invoke_report_agent),
]


def get_active_tools():
    """Return tool list filtered by which agent runtimes are configured."""
    return [fn for env, fn in _AGENT_REGISTRY if os.environ.get(env)]
