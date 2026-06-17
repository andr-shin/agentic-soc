"""Direct Sub-Agent invocation for the fast path (bypasses Host Agent orchestration).
Used when the classifier determines a single security sub-agent can handle the query."""
import json
import logging
import os
import threading
import time

import boto3
from botocore.config import Config

logger = logging.getLogger("soc-host-agent.direct-invoke")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')

# sub-agent 동기 호출은 길 수 있다 — 특히 Report(Sonnet 합성 + 수천 자 finding 컨텍스트)는
# 60초를 쉽게 넘긴다. botocore 기본 read_timeout(60s)은 'Read timeout on endpoint URL' 에러를
# 유발하고, 기본 재시도는 타임아웃 후 재호출로 지연을 배가시킨다 → 타임아웃을 늘리고 재시도를 끈다.
_INVOKE_TIMEOUT = int(os.environ.get('SUBAGENT_READ_TIMEOUT', '180'))
_BOTO_CONFIG = Config(
    read_timeout=_INVOKE_TIMEOUT,
    connect_timeout=10,
    retries={'max_attempts': 1, 'mode': 'standard'},  # 재시도 없음(첫 시도만)
)

# Lazy singleton boto3 client (thread-safe double-check locking)
_client = None
_client_lock = threading.Lock()


def _get_client():
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = boto3.client('bedrock-agentcore', region_name=REGION, config=_BOTO_CONFIG)
    return _client

# Category → (ARN env var, Qualifier env var) mapping
_AGENT_CONFIG = {
    'investigation': ('INVESTIGATION_AGENT_RUNTIME_ARN', 'INVESTIGATION_AGENT_QUALIFIER'),
    'hunting': ('HUNTING_AGENT_RUNTIME_ARN', 'HUNTING_AGENT_QUALIFIER'),
    'threat_hunting': ('THREAT_HUNTING_AGENT_RUNTIME_ARN', 'THREAT_HUNTING_AGENT_QUALIFIER'),
    'logquery': ('LOGQUERY_AGENT_RUNTIME_ARN', 'LOGQUERY_AGENT_QUALIFIER'),
    'response': ('RESPONSE_AGENT_RUNTIME_ARN', 'RESPONSE_AGENT_QUALIFIER'),
    'report': ('REPORT_AGENT_RUNTIME_ARN', 'REPORT_AGENT_QUALIFIER'),
}

# Display names for SSE tool events
_DISPLAY_NAMES = {
    'investigation': 'Investigation Agent 호출',
    'hunting': 'Posture 분석 호출',
    'threat_hunting': 'Threat Hunting Agent 호출',
    'logquery': 'Log Query Agent 호출',
    'response': 'Response Agent 호출',
    'report': 'Report Agent 호출',
}

_counters = {k: 0 for k in _AGENT_CONFIG}
_counter_lock = threading.Lock()


def _build_report_context() -> str:
    """Report Agent는 도구 없이 받은 컨텍스트만으로 합성한다. fast-path에서는 사용자 메시지만
    전달돼 빈 리포트가 나오므로, Aurora findings store에서 실제 보안 현황을 모아 주입한다.
    데이터가 없으면 빈 문자열 반환(컨텍스트 미주입)."""
    try:
        from tools.cache_direct import (
            _query_findings_summary, _query_findings_open, _query_findings_recent,
            AURORA_CLUSTER_ARN,
        )
        if not AURORA_CLUSTER_ARN:
            return ''
        parts = []
        for fn in (_query_findings_summary, _query_findings_open, _query_findings_recent):
            try:
                r = fn()
                if r and r.get('text'):
                    parts.append(r['text'])
            except Exception as e:
                logger.warning(f"report context section 실패: {e}")
        if not parts:
            return ''
        return (
            "\n\n## 📥 수집된 실제 보안 데이터 (Aurora findings store)\n"
            "아래는 현재 계정의 실제 finding 데이터입니다. 이 데이터를 근거로 리포트를 작성하세요.\n\n"
            + "\n\n".join(parts)
        )
    except Exception as e:
        logger.warning(f"_build_report_context 실패: {e}")
        return ''


def invoke_directly(category: str, message: str) -> dict:
    """Invoke a sub-agent directly, bypassing the Host Agent orchestrator.

    Returns:
        {'result': str, 'tool_count': int} on success
        {'error': str} on failure
    """
    config = _AGENT_CONFIG.get(category)
    if not config:
        return {'error': f'Unknown category: {category}'}

    arn_env, qual_env = config
    runtime_arn = os.environ.get(arn_env, '')
    qualifier = os.environ.get(qual_env, '')
    if not runtime_arn:
        return {'error': f'{arn_env} not configured'}

    # Report Agent는 도구가 없어 컨텍스트 의존 — 실제 finding 데이터를 message에 주입
    payload_message = message
    if category == 'report':
        ctx = _build_report_context()
        if ctx:
            payload_message = message + ctx
            logger.info(f"Report context 주입: +{len(ctx)} chars")
        else:
            logger.info("Report context 없음 (Aurora findings 비어있거나 미구성)")

    with _counter_lock:
        _counters[category] += 1
        sid = f"direct-{category}-{_counters[category]:032d}"

    try:
        start = time.time()
        client = _get_client()
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            qualifier=qualifier,
            runtimeSessionId=sid,
            payload=json.dumps({"message": payload_message}),
            contentType='application/json'
        )
        body = resp['response'].read() if hasattr(resp.get('response', ''), 'read') else resp.get('response', b'{}')
        data = json.loads(body)
        elapsed = round(time.time() - start, 2)
        logger.info(f"Direct invoke {category}: {elapsed}s")

        # Ensure usage key exists for upstream consumers
        data.setdefault('usage', {})

        return data
    except Exception as e:
        logger.error(f"Direct invoke {category} error: {e}")
        return {'error': str(e)}


def get_display_name(category: str) -> str:
    """Get Korean display name for a category."""
    return _DISPLAY_NAMES.get(category, category)
