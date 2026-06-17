"""
Aurora DB helper — RDS Data API wrapper for Agentic SOC tables.
Used by Host Agent Lambda (index.py) and Event Processor Lambda.
"""
import os
import json
import boto3
from datetime import datetime
from decimal import Decimal


def _json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

rds_data = boto3.client('rds-data')

CLUSTER_ARN = os.environ.get('AURORA_CLUSTER_ARN', '')
SECRET_ARN = os.environ.get('AURORA_SECRET_ARN', '')
DATABASE = os.environ.get('AURORA_DB_NAME', 'agenticsoc')


def _execute(sql, parameters=None):
    kwargs = {
        'resourceArn': CLUSTER_ARN,
        'secretArn': SECRET_ARN,
        'database': DATABASE,
        'sql': sql,
        'includeResultMetadata': True,
    }
    if parameters:
        kwargs['parameters'] = parameters
    return rds_data.execute_statement(**kwargs)


def _parse_records(resp):
    cols = [c['name'] for c in resp.get('columnMetadata', [])]
    rows = []
    for record in resp.get('records', []):
        row = {}
        for i, field in enumerate(record):
            if 'isNull' in field and field['isNull']:
                row[cols[i]] = None
            elif 'stringValue' in field:
                row[cols[i]] = field['stringValue']
            elif 'longValue' in field:
                row[cols[i]] = field['longValue']
            elif 'doubleValue' in field:
                row[cols[i]] = field['doubleValue']
            elif 'booleanValue' in field:
                row[cols[i]] = field['booleanValue']
            else:
                row[cols[i]] = str(field)
        rows.append(row)
    return rows


def query(sql, parameters=None):
    resp = _execute(sql, parameters)
    return _parse_records(resp)


def execute(sql, parameters=None):
    resp = _execute(sql, parameters)
    return resp.get('numberOfRecordsUpdated', 0)


# ---- findings ----

_FINDING_COLUMNS = (
    "finding_id, title, description, finding_type, product, service, severity, status, "
    "source, resource_id, resource_arn, account_id, region, recommendation, evidence, "
    "mitre_tactics, created_at, updated_at, resolved_at, reopen_count"
)


def _findings_where(status_filter, severity_filter, source_filter):
    """공유 WHERE 절 + 파라미터 빌드 (목록/카운트가 같은 필터를 쓰도록)."""
    conditions, params = [], []
    if status_filter and status_filter != 'all':
        conditions.append("status = :status")
        params.append({'name': 'status', 'value': {'stringValue': status_filter}})
    if severity_filter and severity_filter != 'all':
        conditions.append("severity = :severity")
        params.append({'name': 'severity', 'value': {'stringValue': severity_filter}})
    if source_filter and source_filter != 'all':
        conditions.append("source = :source")
        params.append({'name': 'source', 'value': {'stringValue': source_filter}})
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    return where, params


def get_findings(status_filter=None, severity_filter=None, source_filter=None, limit=100, offset=0):
    where, params = _findings_where(status_filter, severity_filter, source_filter)
    sql = f"SELECT {_FINDING_COLUMNS} FROM findings{where} ORDER BY created_at DESC LIMIT :lim OFFSET :off"
    params = params + [
        {'name': 'lim', 'value': {'longValue': limit}},
        {'name': 'off', 'value': {'longValue': offset}},
    ]
    return query(sql, params)


def get_finding_by_id(finding_id):
    """finding_id로 단건 조회 (Task Board → Finding 링크용). 없으면 None."""
    rows = query(
        f"SELECT {_FINDING_COLUMNS} FROM findings WHERE finding_id = :fid LIMIT 1",
        [{'name': 'fid', 'value': {'stringValue': finding_id}}],
    )
    return rows[0] if rows else None


def count_findings(status_filter=None, severity_filter=None, source_filter=None):
    """필터에 맞는 finding 총 개수 (페이지네이션 total용)."""
    where, params = _findings_where(status_filter, severity_filter, source_filter)
    rows = query(f"SELECT COUNT(*) AS cnt FROM findings{where}", params)
    return int(rows[0].get('cnt', 0) or 0) if rows else 0


def upsert_finding(finding):
    sql = """
        INSERT INTO findings (finding_id, title, description, finding_type, product, service,
            severity, status, source, resource_id, resource_arn, account_id, region,
            recommendation, evidence, mitre_tactics, created_at, updated_at)
        VALUES (:finding_id, :title, :description, :finding_type, :product, :service,
            :severity, :status, :source, :resource_id, :resource_arn, :account_id, :region,
            :recommendation, :evidence::jsonb, :mitre_tactics, :created_at::timestamptz, :updated_at::timestamptz)
        ON CONFLICT (finding_id) DO UPDATE SET
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            severity = EXCLUDED.severity,
            -- 상태 보존 규칙:
            --  - active면 재수집 status 반영.
            --  - acknowledged면 유지(분석가가 처리 중).
            --  - resolved인데 원본이 다시 active이고 그 재관측이 resolved 이후면 → 재발로 보고 재오픈.
            --    (resolved 직후 도착한 지연/중복 이벤트는 updated_at <= resolved_at이라 무시됨)
            status = CASE
                WHEN findings.status = 'active' THEN EXCLUDED.status
                WHEN findings.status = 'resolved' AND EXCLUDED.status = 'active'
                     AND findings.resolved_at IS NOT NULL
                     AND EXCLUDED.updated_at > findings.resolved_at
                  THEN 'active'
                ELSE findings.status END,
            reopen_count = CASE
                WHEN findings.status = 'resolved' AND EXCLUDED.status = 'active'
                     AND findings.resolved_at IS NOT NULL
                     AND EXCLUDED.updated_at > findings.resolved_at
                  THEN findings.reopen_count + 1
                ELSE findings.reopen_count END,
            resolved_at = CASE
                WHEN findings.status = 'resolved' AND EXCLUDED.status = 'active'
                     AND findings.resolved_at IS NOT NULL
                     AND EXCLUDED.updated_at > findings.resolved_at
                  THEN NULL
                ELSE findings.resolved_at END,
            evidence = EXCLUDED.evidence,
            updated_at = EXCLUDED.updated_at
    """
    now = datetime.utcnow().isoformat() + 'Z'
    evidence = finding.get('evidence', {})
    evidence_str = json.dumps(evidence, default=_json_serial) if isinstance(evidence, (dict, list)) else str(evidence or '{}')
    params = [
        {'name': 'finding_id', 'value': {'stringValue': finding.get('finding_id', finding.get('alert_id', ''))}},
        {'name': 'title', 'value': {'stringValue': finding.get('title', '')}},
        {'name': 'description', 'value': {'stringValue': finding.get('description', finding.get('message', ''))}},
        {'name': 'finding_type', 'value': {'stringValue': finding.get('finding_type', '')}},
        {'name': 'product', 'value': {'stringValue': finding.get('product', '')}},
        {'name': 'service', 'value': {'stringValue': finding.get('service', '')}},
        {'name': 'severity', 'value': {'stringValue': finding.get('severity', 'info')}},
        {'name': 'status', 'value': {'stringValue': finding.get('status', 'active')}},
        {'name': 'source', 'value': {'stringValue': finding.get('source', '')}},
        {'name': 'resource_id', 'value': {'stringValue': finding.get('resource_id', '')}},
        {'name': 'resource_arn', 'value': {'stringValue': finding.get('resource_arn', '')}},
        {'name': 'account_id', 'value': {'stringValue': finding.get('account_id', '')}},
        {'name': 'region', 'value': {'stringValue': finding.get('region', '')}},
        {'name': 'recommendation', 'value': {'stringValue': finding.get('recommendation', '')}},
        {'name': 'evidence', 'value': {'stringValue': evidence_str}},
        {'name': 'mitre_tactics', 'value': {'stringValue': finding.get('mitre_tactics', '')}},
        {'name': 'created_at', 'value': {'stringValue': finding.get('created_at', now)}},
        {'name': 'updated_at', 'value': {'stringValue': finding.get('updated_at', now)}},
    ]
    return execute(sql, params)


def update_finding_status(finding_id, new_status):
    now = datetime.utcnow().isoformat() + 'Z'
    # resolved로 가면 resolved_at 기록(재발 재오픈 판정 기준), 그 외(active/acknowledged)는 NULL로 클리어.
    # 재발 재오픈/수동 다시 열기 모두 active로 가며 resolved_at이 비워져 다음 resolve까지 깨끗한 상태 유지.
    if new_status == 'resolved':
        resolved_at_sql = ":now::timestamptz"
    else:
        resolved_at_sql = "NULL"
    sql = (
        f"UPDATE findings SET status = :status, updated_at = :now::timestamptz, "
        f"resolved_at = {resolved_at_sql} WHERE finding_id = :fid"
    )
    params = [
        {'name': 'status', 'value': {'stringValue': new_status}},
        {'name': 'now', 'value': {'stringValue': now}},
        {'name': 'fid', 'value': {'stringValue': finding_id}},
    ]
    return execute(sql, params)


# ---- reports ----

def save_report(report):
    sql = """
        INSERT INTO reports (report_id, report_type, title, content, summary, status, generation_duration_ms, trigger_type, created_at)
        VALUES (:report_id, :report_type, :title, :content::jsonb, :summary, :status, :duration, :trigger, :created_at::timestamptz)
        ON CONFLICT (report_id) DO UPDATE SET
            content = EXCLUDED.content,
            summary = EXCLUDED.summary,
            status = EXCLUDED.status,
            generation_duration_ms = EXCLUDED.generation_duration_ms
    """
    params = [
        {'name': 'report_id', 'value': {'stringValue': report.get('report_id', '')}},
        {'name': 'report_type', 'value': {'stringValue': report.get('report_type', '')}},
        {'name': 'title', 'value': {'stringValue': report.get('title', '')}},
        {'name': 'content', 'value': {'stringValue': json.dumps(report.get('content', {}), default=_json_serial)}},
        {'name': 'summary', 'value': {'stringValue': json.dumps(report.get('summary', ''), default=_json_serial) if isinstance(report.get('summary'), (dict, list)) else str(report.get('summary', ''))}},
        {'name': 'status', 'value': {'stringValue': report.get('status', 'processing')}},
        {'name': 'duration', 'value': {'longValue': report.get('generation_duration_ms', 0)}},
        {'name': 'trigger', 'value': {'stringValue': report.get('trigger_type', 'scheduled')}},
        {'name': 'created_at', 'value': {'stringValue': report.get('created_at', report.get('generated_at', datetime.utcnow().isoformat() + 'Z'))}},
    ]
    return execute(sql, params)


def get_reports_summary():
    sql = """
        SELECT DISTINCT ON (report_type) report_type, report_id, status, summary, created_at
        FROM reports
        ORDER BY report_type, created_at DESC
    """
    return query(sql)


def get_latest_report(report_type, generated_at=None):
    if generated_at:
        sql = "SELECT * FROM reports WHERE report_type = :rt AND created_at = :ga::timestamptz"
        params = [
            {'name': 'rt', 'value': {'stringValue': report_type}},
            {'name': 'ga', 'value': {'stringValue': generated_at}},
        ]
    else:
        sql = "SELECT * FROM reports WHERE report_type = :rt ORDER BY created_at DESC LIMIT 1"
        params = [{'name': 'rt', 'value': {'stringValue': report_type}}]
    rows = query(sql, params)
    if rows:
        row = rows[0]
        if isinstance(row.get('content'), str):
            try:
                row['content'] = json.loads(row['content'])
            except (json.JSONDecodeError, TypeError):
                pass
        return row
    return None


def get_reports_history(report_type, limit=20):
    sql = """
        SELECT report_type, report_id, status, summary, generation_duration_ms, trigger_type, created_at
        FROM reports WHERE report_type = :rt
        ORDER BY created_at DESC LIMIT :lim
    """
    params = [
        {'name': 'rt', 'value': {'stringValue': report_type}},
        {'name': 'lim', 'value': {'longValue': limit}},
    ]
    return query(sql, params)
