"""Cache-direct bypass for simple findings queries (Tier 0 — 0 LLM calls).
Answers common security-posture queries directly from the Aurora findings store.
If the findings table is absent (pre-P1), all queries fall through to the agent safely."""

import os
import re
import json
import logging
import threading

import boto3

logger = logging.getLogger(__name__)

AURORA_CLUSTER_ARN = os.environ.get('AURORA_CLUSTER_ARN', '')
AURORA_SECRET_ARN = os.environ.get('AURORA_SECRET_ARN', '')
AURORA_DB_NAME = os.environ.get('AURORA_DB_NAME', 'agenticsoc')

# Pattern -> (query_type, params)
CACHE_PATTERNS = [
    # Findings count / summary by severity
    (r'(?:critical|심각|위험)\s*(?:finding|탐지|건수|현황|목록)', 'findings_by_severity', {'severity': 'critical'}),
    (r'(?:high|높음|고위험)\s*(?:finding|탐지|건수|현황|목록)', 'findings_by_severity', {'severity': 'high'}),
    # Open / active findings overview
    (r'(?:열린|활성|미해결|open|active)\s*(?:finding|탐지|이슈|알럿)', 'findings_open', {}),
    (r'(?:전체|모든|overall)\s*(?:finding|탐지|보안\s*현황|posture)\s*(?:현황|요약|summary|상태)?', 'findings_summary', {}),
    # Findings by source product (GuardDuty / Security Hub / Inspector)
    (r'(?:GuardDuty)\s*(?:finding|탐지|현황|목록)', 'findings_by_source', {'source': 'GuardDuty'}),
    (r'(?:Inspector)\s*(?:finding|탐지|현황|목록)', 'findings_by_source', {'source': 'Inspector'}),
    # Recent findings
    (r'(?:최근|recent|새로운|new)\s*(?:finding|탐지|이벤트)', 'findings_recent', {}),
]


def try_cache_direct(message: str) -> dict | None:
    """Try to answer from the Aurora findings store directly. Returns formatted response or None."""
    if not AURORA_CLUSTER_ARN or not AURORA_SECRET_ARN:
        return None

    for pattern, query_type, params in CACHE_PATTERNS:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            try:
                if query_type == 'findings_by_severity':
                    return _query_findings_by_severity(params['severity'])
                elif query_type == 'findings_by_source':
                    return _query_findings_by_source(params['source'])
                elif query_type == 'findings_open':
                    return _query_findings_open()
                elif query_type == 'findings_summary':
                    return _query_findings_summary()
                elif query_type == 'findings_recent':
                    return _query_findings_recent()
            except Exception as e:
                logger.warning(f"Cache-direct failed: {e}")
                return None  # Fall through to normal path
    return None


_rds_client = None
_rds_client_lock = threading.Lock()


def _get_rds_client():
    global _rds_client
    if _rds_client is None:
        with _rds_client_lock:
            if _rds_client is None:
                _rds_client = boto3.client('rds-data')
    return _rds_client


def _execute_sql(sql: str, params: list = None) -> list:
    """Execute SQL via RDS Data API."""
    client = _get_rds_client()
    kwargs = {
        'resourceArn': AURORA_CLUSTER_ARN,
        'secretArn': AURORA_SECRET_ARN,
        'database': AURORA_DB_NAME,
        'sql': sql,
        'includeResultMetadata': True,
    }
    if params:
        kwargs['parameters'] = params
    resp = client.execute_statement(**kwargs)
    columns = [col['name'] for col in resp.get('columnMetadata', [])]
    rows = []
    for record in resp.get('records', []):
        row = {}
        for i, field in enumerate(record):
            if 'stringValue' in field:
                row[columns[i]] = field['stringValue']
            elif 'longValue' in field:
                row[columns[i]] = field['longValue']
            elif 'booleanValue' in field:
                row[columns[i]] = field['booleanValue']
            elif 'isNull' in field:
                row[columns[i]] = None
            else:
                row[columns[i]] = str(field)
        rows.append(row)
    return rows


def _query_findings_by_severity(severity: str) -> dict:
    """List findings filtered by severity."""
    rows = _execute_sql(
        "SELECT finding_id, title, service, resource_id, created_at FROM findings "
        "WHERE severity = :sev AND status = 'active' ORDER BY created_at DESC LIMIT 20",
        [{'name': 'sev', 'value': {'stringValue': severity}}]
    )
    finding_list = "\n".join(
        f"  - [{r.get('service', '')}] {r.get('title', r.get('finding_id', 'N/A'))} "
        f"(리소스: {r.get('resource_id', 'N/A')})"
        for r in rows
    )
    text = f"**{severity.upper()} 활성 Finding** (상위 {len(rows)}건)\n"
    text += finding_list if finding_list else "해당 심각도의 활성 finding이 없습니다."
    return {'text': text, 'path': 'cache-direct', 'tokens': 0}


def _query_findings_by_source(source: str) -> dict:
    """List findings filtered by source product."""
    rows = _execute_sql(
        "SELECT finding_id, title, severity, resource_id, created_at FROM findings "
        "WHERE service ILIKE :src AND status = 'active' ORDER BY created_at DESC LIMIT 20",
        [{'name': 'src', 'value': {'stringValue': f'%{source}%'}}]
    )
    finding_list = "\n".join(
        f"  - [{r.get('severity', '')}] {r.get('title', r.get('finding_id', 'N/A'))} "
        f"(리소스: {r.get('resource_id', 'N/A')})"
        for r in rows
    )
    text = f"**{source} Finding** (활성 {len(rows)}건)\n"
    text += finding_list if finding_list else f"{source} 활성 finding이 없습니다."
    return {'text': text, 'path': 'cache-direct', 'tokens': 0}


def _query_findings_open() -> dict:
    """Count active/acknowledged findings by severity."""
    rows = _execute_sql(
        "SELECT severity, COUNT(*) as cnt FROM findings "
        "WHERE status IN ('active', 'acknowledged') GROUP BY severity"
    )
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    rows.sort(key=lambda r: order.get(r.get('severity', 'info'), 9))
    total = sum(r['cnt'] for r in rows)
    lines = [f"  - {r['severity']}: {r['cnt']}건" for r in rows]
    text = f"**미해결 Finding 현황** (총 {total}건)\n" + "\n".join(lines)
    return {'text': text, 'path': 'cache-direct', 'tokens': 0}


def _query_findings_summary() -> dict:
    """Overall posture summary: findings by service and severity."""
    rows = _execute_sql(
        "SELECT service, severity, COUNT(*) as cnt FROM findings "
        "WHERE status = 'active' GROUP BY service, severity ORDER BY service, severity"
    )
    by_service = {}
    for r in rows:
        by_service.setdefault(r['service'], []).append(f"{r['severity']}:{r['cnt']}")
    total = sum(r['cnt'] for r in rows)
    lines = [f"  - {svc}: {', '.join(parts)}" for svc, parts in by_service.items()]
    text = f"**전체 보안 Finding 현황** (활성 총 {total}건)\n" + "\n".join(lines)
    return {'text': text, 'path': 'cache-direct', 'tokens': 0}


def _query_findings_recent() -> dict:
    """Get most recent findings."""
    rows = _execute_sql(
        "SELECT finding_id, title, severity, service, created_at FROM findings "
        "ORDER BY created_at DESC LIMIT 15"
    )
    if not rows:
        return {'text': "최근 finding이 없습니다.", 'path': 'cache-direct', 'tokens': 0}
    lines = [
        f"  - [{r.get('created_at', '')}] ({r.get('severity', '')}) "
        f"{r.get('service', '')}: {r.get('title', r.get('finding_id', ''))}"
        for r in rows
    ]
    text = f"**최근 Finding** ({len(rows)}건)\n" + "\n".join(lines)
    return {'text': text, 'path': 'cache-direct', 'tokens': 0}
