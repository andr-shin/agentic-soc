"""
Agentic SOC — REST API Lambda (Host Agent backend).

Serves the web app: findings list/acknowledge/resolve, analyst conversation threads,
security reports (P3), config, and health. Findings are written by the event-processor
Lambda (GuardDuty/SecurityHub/Inspector/CloudTrail → SNS → event-processor → Aurora/DDB).
"""
import json
import boto3
import os
import base64
import re
import time
import uuid
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from decimal import Decimal
from urllib.parse import quote

# Core clients
dynamodb = boto3.resource('dynamodb')
cloudwatch = boto3.client('cloudwatch')

# Aurora DB helper (optional — graceful fallback if not configured)
try:
    import aurora_db
    AURORA_ENABLED = bool(os.environ.get('AURORA_CLUSTER_ARN'))
except ImportError:
    AURORA_ENABLED = False

# Load agent config from SSM Parameter Store (if configured).
# Decouples agent ARN management from Lambda env vars.
_agent_config_path = os.environ.get('AGENT_CONFIG_SSM_PATH', '')
if _agent_config_path:
    try:
        _ssm = boto3.client('ssm')
        _param = _ssm.get_parameter(Name=_agent_config_path)
        _config = json.loads(_param['Parameter']['Value'])
        for _k, _v in _config.items():
            if _v:
                os.environ.setdefault(_k, _v)
    except Exception as _e:
        print(f"Warning: Failed to load agent config from SSM {_agent_config_path}: {_e}")

# AgentCore clients
MEMORY_ID = os.environ.get('MEMORY_ID', '')
REPORT_AGENT_RUNTIME_ARN = os.environ.get('REPORT_AGENT_RUNTIME_ARN', '')
REPORT_AGENT_QUALIFIER = os.environ.get('REPORT_AGENT_QUALIFIER', '')
agentcore_client = boto3.client('bedrock-agentcore') if (MEMORY_ID or REPORT_AGENT_RUNTIME_ARN) else None

AWS_REGION = os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2'))

FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'findings')

# Security report types (P3 — Report Agent synthesizes these)
REPORT_TYPES = ['security_posture', 'incident_timeline', 'threat_hunt', 'compliance']


# ============================================================
# Auth + routing
# ============================================================

def get_user_from_token(event):
    auth_header = event.get('headers', {}).get('authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header[7:]
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        return {'user_id': decoded.get('sub'), 'email': decoded.get('email')}
    except (ValueError, KeyError, TypeError) as e:
        print(f"Error parsing JWT token: {e}")
        return None


def handler(event, *args):
    context = args[0] if args else None

    if 'requestContext' in event:
        path = event.get('rawPath', '')
        method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
        user = get_user_from_token(event)

        if '/api/config' in path and method == 'GET':
            return response(get_config())
        if '/api/health' in path:
            return response(get_health())
        elif '/api/readiness' in path and method == 'GET':
            return response(get_readiness())
        # Findings
        elif '/api/findings/acknowledge' in path and method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return api_response(acknowledge_finding(body.get('finding_id', '')))
        elif '/api/findings/resolve' in path and method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return api_response(resolve_finding(body.get('finding_id', '')))
        elif '/api/findings/reopen' in path and method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return api_response(reopen_finding(body.get('finding_id', '')))
        elif '/api/findings' in path and method == 'GET':
            return api_response(get_findings(event))
        # Conversations (analyst investigation threads)
        elif re.search(r'/api/conversations/[^/]+$', path) and method == 'DELETE':
            conv_id = path.split('/')[-1]
            return api_response(delete_conversation(user, conv_id))
        elif re.search(r'/api/conversations/[^/]+$', path) and method == 'GET':
            conv_id = path.split('/')[-1]
            return api_response(get_conversation_detail(user, conv_id))
        elif '/api/conversations' in path and method == 'GET':
            return response(get_conversations(user))
        # Task Board (SOAR approval workflow)
        elif re.search(r'/api/tasks/[^/]+/approve', path) and method == 'POST':
            task_id = path.split('/api/tasks/')[1].split('/approve')[0]
            return api_response(approve_task(task_id, user))
        elif re.search(r'/api/tasks/[^/]+/reject', path) and method == 'POST':
            task_id = path.split('/api/tasks/')[1].split('/reject')[0]
            return api_response(reject_task(task_id, user))
        elif re.search(r'/api/tasks/[^/]+/complete', path) and method == 'POST':
            task_id = path.split('/api/tasks/')[1].split('/complete')[0]
            return api_response(complete_task(task_id, user))
        elif '/api/tasks' in path and method == 'GET':
            return response(get_tasks(event))
        # Log Explorer (CloudWatch Unified Data Store)
        elif '/api/logs/sources' in path and method == 'GET':
            return response(get_log_sources())
        # 저장된 쿼리 CRUD — '/api/logs/query'(in 매칭)보다 먼저 평가해야 함('/queries' 우선)
        elif re.search(r'/api/logs/queries/[^/]+$', path) and method == 'DELETE':
            query_id = path.rstrip('/').split('/')[-1]
            return api_response(delete_log_query(user, query_id))
        elif '/api/logs/queries' in path and method == 'GET':
            return response(list_log_queries(user))
        elif '/api/logs/queries' in path and method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return api_response(save_log_query(user, body))
        elif '/api/logs/query' in path and method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return api_response(run_log_query(body))
        elif '/api/logs/generate' in path and method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return response(generate_log_query(body))
        # Security reports (P3 — read endpoints; generation added later)
        elif '/api/reports/summary' in path and method == 'GET':
            return response(get_reports_summary())
        elif '/api/reports/latest' in path and method == 'GET':
            return response(get_latest_report(event))
        elif '/api/reports' in path and method == 'GET':
            return response(get_reports_history(event))
        return response({'error': 'Not found'}, 404)
    return response({'error': 'Unknown event type'}, 400)


def response(body, code=200):
    return {
        'statusCode': code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': '*',
        },
        'body': json.dumps(body, default=str),
    }


def _safe_int(value, default):
    """쿼리 파라미터를 안전하게 int로. None/비숫자/빈문자 → default (사용자 편집 URL 방어)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def api_response(result):
    """결과 dict에 'error' 키가 있으면 적절한 HTTP 상태코드로 매핑해 응답.
    (기존엔 모든 응답이 200이라 프론트 mutation이 실패를 성공으로 오인했음 — M5 수정)
    - not found 류 → 404, 검증 실패('required'/'invalid'/'필요'/'없습니다') → 400, 그 외 error → 500."""
    if isinstance(result, dict) and result.get('error'):
        msg = str(result['error']).lower()
        detail = str(result['error'])
        if 'not found' in msg or 'not exist' in msg or '찾을 수 없' in detail or '없습니다' in detail:
            return response(result, 404)
        if 'required' in msg or 'invalid' in msg or '필요' in detail or '완료할 수 있' in detail:
            return response(result, 400)
        return response(result, 500)
    return response(result)


# ============================================================
# Config + health
# ============================================================

def get_config():
    """Build AgentCore direct invocation URL + active security agent registry."""
    region = AWS_REGION
    chat_runtime_arn = os.environ.get('CHAT_AGENT_RUNTIME_ARN', '')
    chat_qualifier = os.environ.get('CHAT_AGENT_QUALIFIER', 'DEFAULT')
    host_agent_url = ''
    if chat_runtime_arn:
        encoded_arn = quote(chat_runtime_arn, safe='')
        host_agent_url = f'https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{encoded_arn}/invocations?qualifier={chat_qualifier}'

    BASIC_AGENTS = [
        {'id': 'investigation', 'name': 'Investigation', 'desc': '특정 finding 심층 조사, CloudTrail 상관, MITRE 매핑', 'icon': 'search'},
        {'id': 'hunting',       'name': 'Posture 분석',   'desc': '리소스 설정 약점·노출·공격 경로 SQL 분석 (CSPM 보완)',         'icon': 'crosshair'},
        {'id': 'report',        'name': 'Report',         'desc': '보안 감사·인시던트 타임라인·컴플라이언스 리포트 합성',            'icon': 'file-text'},
    ]
    OPTIONAL_AGENTS = [
        {'env': 'THREAT_HUNTING_AGENT_RUNTIME_ARN', 'id': 'threat_hunting', 'name': 'Threat Hunting', 'desc': '로그 기반 위협 헌팅 — CloudTrail/DNS/VPC Flow 교차로 공격자 행위·TTP 추적', 'icon': 'crosshair'},
        {'env': 'LOGQUERY_AGENT_RUNTIME_ARN', 'id': 'logquery', 'name': 'Log Query', 'desc': 'CloudWatch Unified Data Store, 자연어→LogsQL', 'icon': 'terminal'},
        {'env': 'RESPONSE_AGENT_RUNTIME_ARN', 'id': 'response', 'name': 'Response (SOAR)', 'desc': 'EC2 격리/SG 차단/IAM revoke (승인 게이트)', 'icon': 'shield'},
    ]

    active_agents = []
    if chat_runtime_arn:
        for agent in BASIC_AGENTS:
            active_agents.append({'id': agent['id'], 'name': agent['name'],
                                  'description': agent['desc'], 'icon': agent['icon']})
    for agent in OPTIONAL_AGENTS:
        if os.environ.get(agent['env']):
            active_agents.append({'id': agent['id'], 'name': agent['name'],
                                  'description': agent['desc'], 'icon': agent['icon']})

    return {'host_agent_url': host_agent_url, 'active_agents': active_agents}


def get_health():
    """SOC health summary — open findings counts by severity."""
    try:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        total_open = 0
        if AURORA_ENABLED:
            try:
                rows = aurora_db.query(
                    "SELECT severity, COUNT(*) AS cnt FROM findings "
                    "WHERE status IN ('active','acknowledged') GROUP BY severity"
                )
                for r in rows:
                    sev = (r.get('severity') or 'info').lower()
                    cnt = int(r.get('cnt', 0) or 0)
                    # 알려진 5개 외 severity(NULL/대문자/informational 등)는 'info'로 흡수 —
                    # by_severity 카드 합계와 total_open(사이드바 배지)이 항상 일치하도록.
                    if sev not in counts:
                        sev = 'info'
                    counts[sev] += cnt
                    total_open += cnt
            except Exception as e:
                # Aurora 쿼리 실패 시 0을 'healthy'로 보고하면 거짓 안심 신호 — 'unknown'으로 정직 보고(M6).
                print(f"Aurora health query failed: {e}")
                return {'overall_status': 'unknown', 'open_findings': 0, 'by_severity': counts,
                        'error': 'health query failed', 'timestamp': datetime.utcnow().isoformat() + 'Z'}

        has_critical = counts.get('critical', 0) > 0
        has_high = counts.get('high', 0) > 0
        status = 'critical' if has_critical else ('warning' if has_high else 'healthy')
        return {
            'overall_status': status,
            'open_findings': total_open,
            'by_severity': counts,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }
    except Exception as e:
        return {'overall_status': 'unknown', 'error': str(e)}


# ============================================================
# Findings
# ============================================================

def get_finding(finding_id):
    """단건 finding 조회 (Task Board → Finding 링크). {finding} 또는 {error}."""
    if AURORA_ENABLED:
        try:
            row = aurora_db.get_finding_by_id(finding_id)
            if not row:
                return {'error': 'Finding not found', 'finding_id': finding_id}
            ev = row.get('evidence')
            if isinstance(ev, str):
                try:
                    row['evidence'] = json.loads(ev)
                except (json.JSONDecodeError, TypeError):
                    pass
            return row
        except Exception as e:
            print(f"Aurora get_finding failed: {e}")
    # Fallback: DDB
    try:
        table = dynamodb.Table(FINDINGS_TABLE)
        resp = table.query(KeyConditionExpression='finding_id = :fid',
                           ExpressionAttributeValues={':fid': finding_id}, Limit=1)
        items = resp.get('Items', [])
        return items[0] if items else {'error': 'Finding not found', 'finding_id': finding_id}
    except Exception as e:
        return {'error': str(e), 'finding_id': finding_id}


def get_findings(event):
    """List security findings with optional status/severity/source filters. finding_id가 있으면 단건."""
    qp = event.get('queryStringParameters') or {}
    if qp.get('finding_id'):
        return get_finding(qp['finding_id'])
    status_filter = qp.get('status')
    severity_filter = qp.get('severity')
    source_filter = qp.get('source')
    # page 파라미터가 있으면 페이지네이션 모드({items,total,page,page_size}), 없으면 기존 배열(하위 호환).
    # URL은 사용자가 직접 편집할 수 있으므로 숫자 파싱은 방어적으로(?page=abc → 기본값).
    paged = qp.get('page') is not None
    page = max(1, _safe_int(qp.get('page'), 1))
    page_size = min(200, max(1, _safe_int(qp.get('page_size', qp.get('limit')), 100)))
    limit = page_size if paged else _safe_int(qp.get('limit'), 100)
    offset = (page - 1) * page_size if paged else 0

    def _parse_evidence(rows):
        for r in rows:
            ev = r.get('evidence')
            if isinstance(ev, str):
                try:
                    r['evidence'] = json.loads(ev)
                except (json.JSONDecodeError, TypeError):
                    pass
        return rows

    if AURORA_ENABLED:
        try:
            rows = _parse_evidence(aurora_db.get_findings(status_filter, severity_filter, source_filter, limit, offset))
            if paged:
                total = aurora_db.count_findings(status_filter, severity_filter, source_filter)
                return {'items': rows, 'total': total, 'page': page, 'page_size': page_size}
            return rows
        except Exception as e:
            print(f"Aurora get_findings failed, falling back to DDB: {e}")

    # Fallback: DynamoDB (status-index GSI)
    # 페이지네이션 모드에서는 offset/total이 정확해야 하므로 매칭 항목을 끝까지 모은다
    # (severity/source는 Python 필터라 DDB Limit 이전에 잘리면 total이 틀어짐 — M3 수정).
    # 안전 상한(DDB_FETCH_CAP)으로 폭주 방지. 비페이지 모드는 기존처럼 limit만.
    DDB_FETCH_CAP = 5000
    table = dynamodb.Table(FINDINGS_TABLE)
    try:
        items, last_key = [], None
        while True:
            if status_filter and status_filter != 'all':
                kw = dict(IndexName='status-index',
                          KeyConditionExpression='#s = :s',
                          ExpressionAttributeNames={'#s': 'status'},
                          ExpressionAttributeValues={':s': status_filter},
                          ScanIndexForward=False)
                if not paged:
                    kw['Limit'] = limit
                if last_key:
                    kw['ExclusiveStartKey'] = last_key
                resp = table.query(**kw)
            else:
                kw = {} if paged else {'Limit': limit}
                if last_key:
                    kw['ExclusiveStartKey'] = last_key
                resp = table.scan(**kw)
            items.extend(resp.get('Items', []))
            last_key = resp.get('LastEvaluatedKey')
            # 비페이지 모드는 첫 배치면 충분; 페이지 모드는 끝까지(상한까지) 수집
            if not paged or not last_key or len(items) >= DDB_FETCH_CAP:
                break
        if severity_filter and severity_filter != 'all':
            items = [i for i in items if i.get('severity') == severity_filter]
        if source_filter and source_filter != 'all':
            items = [i for i in items if i.get('source') == source_filter]
        items.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        if paged:
            window = items[offset:offset + page_size]
            return {'items': window, 'total': len(items), 'page': page, 'page_size': page_size}
        return items[:limit]
    except Exception as e:
        print(f"DDB get_findings failed: {e}")
        return {'items': [], 'total': 0, 'page': page, 'page_size': page_size} if paged else []


def acknowledge_finding(finding_id):
    return _update_finding_status(finding_id, 'acknowledged')


def resolve_finding(finding_id):
    return _update_finding_status(finding_id, 'resolved')


def reopen_finding(finding_id):
    # 수동 다시 열기 — resolved/acknowledged를 active로 되돌림(오조치 복구). resolved_at도 클리어됨.
    return _update_finding_status(finding_id, 'active')


def _update_finding_status(finding_id, new_status):
    if AURORA_ENABLED:
        try:
            aurora_db.update_finding_status(finding_id, new_status)
            return {'success': True, 'finding_id': finding_id, 'status': new_status}
        except Exception as e:
            print(f"Aurora update_finding_status failed, falling back to DDB: {e}")

    # Fallback: DynamoDB — need sort key (created_at), so look it up first
    table = dynamodb.Table(FINDINGS_TABLE)
    try:
        resp = table.query(
            KeyConditionExpression='finding_id = :fid',
            ExpressionAttributeValues={':fid': finding_id},
            ScanIndexForward=False, Limit=1,
        )
        items = resp.get('Items', [])
        if not items:
            return {'error': 'Finding not found', 'finding_id': finding_id}
        now = datetime.utcnow().isoformat() + 'Z'
        table.update_item(
            Key={'finding_id': finding_id, 'created_at': items[0]['created_at']},
            UpdateExpression='SET #s = :s, updated_at = :ua',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':s': new_status, ':ua': now},
        )
        return {'success': True, 'finding_id': finding_id, 'status': new_status}
    except Exception as e:
        return {'error': str(e), 'finding_id': finding_id}


# ============================================================
# Conversations (analyst investigation threads)
# ============================================================

def get_conversations(user):
    if not user:
        return []
    try:
        tbl = dynamodb.Table(os.environ['CONVERSATIONS_TABLE'])
        resp = tbl.query(
            IndexName='updated-at-index',
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user['user_id']},
            ScanIndexForward=False,
            Limit=50,
            ProjectionExpression='conversation_id, title, updated_at, message_count',
        )
        results = []
        for i in resp.get('Items', []):
            mc = i.get('message_count', 0)
            results.append({
                'conversation_id': i['conversation_id'],
                'title': i.get('title', 'Untitled'),
                'updated_at': i.get('updated_at', ''),
                'message_count': int(mc) if mc else 0,
            })
        return results
    except Exception as e:
        print(f"Error getting conversations: {e}")
        return []


def _load_messages_from_memory(user_id, conv_id):
    """Load conversation messages from AgentCore Memory list_events API."""
    if not MEMORY_ID or not agentcore_client:
        return None
    try:
        events = []
        next_token = None
        while True:
            kwargs = {'memoryId': MEMORY_ID, 'sessionId': conv_id, 'actorId': user_id}
            if next_token:
                kwargs['nextToken'] = next_token
            resp = agentcore_client.list_events(**kwargs)
            events.extend(resp.get('events', []))
            next_token = resp.get('nextToken')
            if not next_token:
                break
        if not events:
            return None
        messages = []
        for evt in events:
            evt_ts = evt.get('eventTimestamp')
            if evt_ts and isinstance(evt_ts, datetime):
                evt_iso = evt_ts.isoformat() + ('Z' if not evt_ts.tzinfo else '')
            elif evt_ts:
                evt_iso = datetime.utcfromtimestamp(float(evt_ts)).isoformat() + 'Z'
            else:
                evt_iso = ''
            payload_items = evt.get('payload', [])
            if not isinstance(payload_items, list):
                continue
            for item in payload_items:
                if not isinstance(item, dict):
                    continue
                if 'blob' in item:
                    continue
                conv = item.get('conversational')
                if not conv:
                    continue
                role_raw = conv.get('role', '')
                content_obj = conv.get('content', {})
                text_json = content_obj.get('text', '') if isinstance(content_obj, dict) else ''
                if not text_json:
                    continue
                try:
                    msg_wrapper = json.loads(text_json)
                    msg = msg_wrapper.get('message', {})
                    role = msg.get('role', role_raw.lower())
                    content_blocks = msg.get('content', [])
                    text = _extract_text_from_content(role, content_blocks)
                    timestamp = msg_wrapper.get('created_at') or evt_iso
                    if text:
                        messages.append({'role': role, 'content': text, 'timestamp': timestamp})
                except (json.JSONDecodeError, TypeError):
                    role = role_raw.lower() if role_raw else ''
                    if role in ('user', 'assistant') and text_json.strip():
                        messages.append({'role': role, 'content': text_json.strip(), 'timestamp': evt_iso})
        messages.sort(key=lambda m: m.get('timestamp', ''))
        return messages if messages else None
    except Exception as e:
        print(f"Memory list_events failed: {e}")
        return None


def _extract_text_from_content(role, content_blocks):
    """Extract text from Strands content blocks."""
    if not role or not content_blocks:
        return ''
    if isinstance(content_blocks, str):
        return content_blocks
    if not isinstance(content_blocks, list):
        return ''
    text_parts = []
    for block in content_blocks:
        if isinstance(block, str):
            text_parts.append(block)
        elif isinstance(block, dict):
            if block.get('type') == 'text':
                text_parts.append(block.get('text', ''))
            elif 'text' in block:
                text_parts.append(block['text'])
    return '\n'.join(text_parts) if text_parts else ''


def get_conversation_detail(user, conv_id):
    if not user:
        return {'error': 'Unauthorized'}
    try:
        tbl = dynamodb.Table(os.environ['CONVERSATIONS_TABLE'])
        resp = tbl.get_item(
            Key={'user_id': user['user_id'], 'conversation_id': conv_id},
            ProjectionExpression='conversation_id, title, messages, message_count',
        )
        item = resp.get('Item')
        title = item.get('title', '') if item else ''

        memory_messages = _load_messages_from_memory(user['user_id'], conv_id)
        if memory_messages is not None:
            return {'conversation_id': conv_id, 'title': title, 'messages': memory_messages}

        if item:
            return {'conversation_id': conv_id, 'title': title, 'messages': item.get('messages', [])}

        return {'conversation_id': conv_id, 'messages': []}
    except Exception as e:
        print(f"Error getting conversation detail: {e}")
        return {'conversation_id': conv_id, 'messages': []}


def delete_conversation(user, conv_id):
    if not user:
        return {'error': 'Unauthorized'}
    try:
        tbl = dynamodb.Table(os.environ['CONVERSATIONS_TABLE'])
        tbl.delete_item(Key={'user_id': user['user_id'], 'conversation_id': conv_id})
        return {'success': True}
    except Exception as e:
        return {'error': str(e)}


# ============================================================
# Security reports (P3 — read endpoints; generation added later)
# ============================================================

def _get_reports_table():
    return dynamodb.Table(os.environ.get('REPORTS_TABLE', 'reports'))


def get_reports_summary():
    """Latest report summary for each security report type."""
    if AURORA_ENABLED:
        try:
            rows = aurora_db.get_reports_summary()
            summary = {}
            for r in rows:
                rt = r.get('report_type', '')
                s = r.get('summary', '')
                if isinstance(s, str):
                    try:
                        s = json.loads(s)
                    except (json.JSONDecodeError, TypeError):
                        pass
                summary[rt] = {
                    'report_type': rt,
                    'status': r.get('status', 'never_generated'),
                    'generated_at': r.get('created_at', ''),
                    'summary': s,
                }
            for rt in REPORT_TYPES:
                summary.setdefault(rt, {'status': 'never_generated'})
            return {'summary': summary}
        except Exception as e:
            print(f"Aurora get_reports_summary failed, falling back to DDB: {e}")

    reports_table = _get_reports_table()
    summary = {}
    for rt in REPORT_TYPES:
        try:
            resp = reports_table.query(
                KeyConditionExpression='report_type = :t',
                ExpressionAttributeValues={':t': rt},
                ScanIndexForward=False, Limit=1,
                ProjectionExpression='report_type, generated_at, #s, summary',
                ExpressionAttributeNames={'#s': 'status'}
            )
            items = resp.get('Items', [])
            summary[rt] = items[0] if items else {'status': 'never_generated'}
        except Exception as e:
            print(f"Error querying report summary for {rt}: {e}")
            summary[rt] = {'status': 'never_generated'}
    return {'summary': summary}


def get_latest_report(event):
    """Latest completed report for a type (optionally a specific historical one)."""
    qp = event.get('queryStringParameters') or {}
    rt = qp.get('type', 'security_posture')
    generated_at = qp.get('generated_at')

    if AURORA_ENABLED:
        try:
            result = aurora_db.get_latest_report(rt, generated_at=generated_at)
            if result:
                if result.get('status') == 'completed':
                    return {'found': True, 'report': {
                        'report_type': rt, 'generated_at': result.get('created_at', ''),
                        'data': result.get('content', {}), 'summary': result.get('summary', ''),
                        'status': result.get('status'),
                        'generation_duration_ms': result.get('generation_duration_ms', 0),
                        'trigger_type': result.get('trigger_type', ''),
                        'report_id': result.get('report_id', '')}}
                return {'found': False, 'processing': result.get('status') == 'processing',
                        'generated_at': result.get('created_at', '')}
            return {'found': False, 'processing': False}
        except Exception as e:
            print(f"Aurora get_latest_report failed, falling back to DDB: {e}")

    reports_table = _get_reports_table()
    if generated_at:
        try:
            resp = reports_table.get_item(Key={'report_type': rt, 'generated_at': generated_at})
            item = resp.get('Item')
            if item and item.get('status') == 'completed':
                return {'found': True, 'report': item}
            return {'found': False, 'processing': item.get('status') == 'processing' if item else False}
        except Exception:
            return {'found': False, 'processing': False}

    resp = reports_table.query(
        KeyConditionExpression='report_type = :t',
        ExpressionAttributeValues={':t': rt},
        ScanIndexForward=False, Limit=5,
    )
    for item in resp.get('Items', []):
        if item.get('status') == 'completed':
            return {'found': True, 'report': item}
    for item in resp.get('Items', []):
        if item.get('status') == 'processing':
            return {'found': False, 'processing': True, 'generated_at': item.get('generated_at')}
    return {'found': False, 'processing': False}


def get_reports_history(event):
    """Historical reports for a type (summary only)."""
    qp = event.get('queryStringParameters') or {}
    rt = qp.get('type', 'security_posture')
    limit = _safe_int(qp.get('limit'), 20)

    if AURORA_ENABLED:
        try:
            result = aurora_db.get_reports_history(rt, limit=limit)
            if result is not None:
                reports = result if isinstance(result, list) else result.get('reports', [])
                for r in reports:
                    if 'created_at' in r and 'generated_at' not in r:
                        r['generated_at'] = r['created_at']
                    s = r.get('summary')
                    if isinstance(s, str):
                        try:
                            r['summary'] = json.loads(s)
                        except (json.JSONDecodeError, TypeError):
                            pass
                return {'reports': reports, 'report_type': rt}
        except Exception as e:
            print(f"Aurora get_reports_history failed, falling back to DDB: {e}")

    reports_table = _get_reports_table()
    resp = reports_table.query(
        KeyConditionExpression='report_type = :t',
        ExpressionAttributeValues={':t': rt},
        ScanIndexForward=False, Limit=limit,
        ProjectionExpression='report_type, generated_at, #s, summary, generation_duration_ms, trigger_type',
        ExpressionAttributeNames={'#s': 'status'}
    )
    return {'reports': resp.get('Items', []), 'report_type': rt}


# ============================================================
# Log Explorer (CloudWatch Unified Data Store / Logs Insights)
# ============================================================

# Friendly source name → CloudWatch log group + LogsQL field schema hint.
#
# 로그그룹 이름은 두 방식으로 해석한다 (우선순위 순):
#   1) data_source: CloudWatch Logs Data Sources 자동 분류(amazon_vpc/flow 등)로 실제
#      로그그룹 이름을 동적 조회. AWS가 어떤 경로(/security/*, /aws/route53resolver 등)로
#      로그를 만들든 분류만 맞으면 찾는다. (telemetry enablement rule이 강제하는 AWS 기본
#      경로에도 자동 대응 — 더 이상 경로 이름을 맞출 필요 없음)
#   2) log_group: data_source 조회 실패/미분류 시 사용하는 fallback 경로 힌트.
# 'data_source'의 name/type은 `aws logs list-log-groups --data-sources` 필터 값과 동일.
LOG_SOURCES = {
    'vpc-flowlogs': {
        'data_source': {'name': 'amazon_vpc', 'type': 'flow'},
        'log_group': os.environ.get('LOG_GROUP_VPC_FLOW', '/security/vpc-flowlogs'),
        'schema': 'srcAddr, dstAddr, srcPort, dstPort, protocol, action (ACCEPT/REJECT), bytes, packets, interfaceId',
    },
    'cloudtrail': {
        'data_source': {'name': 'aws_cloudtrail'},
        'log_group': os.environ.get('LOG_GROUP_CLOUDTRAIL', '/security/cloudtrail'),
        'schema': 'eventName, eventSource, userIdentity.arn, sourceIPAddress, awsRegion, errorCode',
    },
    'dns-queries': {
        'data_source': {'name': 'amazon_route53', 'type': 'resolver_query'},
        'log_group': os.environ.get('LOG_GROUP_DNS', '/security/dns-queries'),
        'schema': 'query_name, query_type, rcode, srcaddr, transport',
    },
    'waf': {
        'data_source': {'name': 'aws_waf'},
        'log_group': os.environ.get('LOG_GROUP_WAF', '/security/waf-logs'),
        'schema': 'action (ALLOW/BLOCK), httpRequest.clientIp, httpRequest.uri, httpRequest.country, terminatingRuleId',
    },
    'nlb-access': {
        'data_source': {'name': 'elasticloadbalancing'},
        'log_group': os.environ.get('LOG_GROUP_NLB', '/security/nlb-access'),
        'schema': 'client_ip, listener, target, tcp_connection_time, received_bytes, sent_bytes',
    },
}

# data_source → 실제 로그그룹 이름 캐시 (cold start 동안 재사용)
_LOG_GROUP_CACHE = {}


def _lookup_log_group_by_data_source(ds):
    """CloudWatch Logs Data Sources 분류로 실제 로그그룹 이름을 찾는다. 실패 시 None."""
    key = ds.get('name', '') + '/' + ds.get('type', '')
    if key in _LOG_GROUP_CACHE:
        return _LOG_GROUP_CACHE[key]
    try:
        logs = boto3.client('logs', region_name=AWS_REGION)
        flt = {'name': ds['name']}
        if ds.get('type'):
            flt['type'] = ds['type']
        groups = logs.list_log_groups(dataSources=[flt]).get('logGroups', [])
        name = groups[0]['logGroupName'] if groups else None
    except Exception as e:
        print(f'[log_sources] data-source lookup 실패({key}): {type(e).__name__}: {str(e)[:120]}')
        name = None
    _LOG_GROUP_CACHE[key] = name
    return name


def _resolve_log_group(source):
    cfg = LOG_SOURCES.get(source)
    if not cfg:
        return source  # pass through explicit log group names
    ds = cfg.get('data_source')
    if ds:
        found = _lookup_log_group_by_data_source(ds)
        if found:
            return found
    return cfg['log_group']  # fallback: 하드코딩 경로 힌트


def _log_group_exists(log_group):
    """로그그룹이 실제로 존재하는지(=검색 가능) 확인."""
    try:
        logs = boto3.client('logs', region_name=AWS_REGION)
        # 프리픽스 매칭 API라 정확히 같은 이름이 있는지만 인정 — 프리픽스만 공유하는 다른
        # 로그그룹이 '검색 가능'으로 오인식되는 것 방지(L9). limit을 늘려 정확 일치 탐색.
        found = logs.describe_log_groups(logGroupNamePrefix=log_group, limit=50).get('logGroups', [])
        return any(g.get('logGroupName') == log_group for g in found)
    except Exception as e:
        print(f'[log_sources] exists check 실패({log_group}): {type(e).__name__}: {str(e)[:120]}')
        return False


def get_log_sources():
    """Return available security log sources + schema + 검색 가능 여부(온보딩 상태)."""
    sources = []
    for name, cfg in LOG_SOURCES.items():
        ds = cfg.get('data_source')
        # data_source 동적 조회로 실제 로그그룹을 찾으면 그 자체가 '온보딩됨'의 강한 신호.
        resolved = _lookup_log_group_by_data_source(ds) if ds else None
        if resolved:
            log_group, searchable = resolved, True
        else:
            log_group = cfg['log_group']
            searchable = _log_group_exists(log_group)
        sources.append({
            'source': name,
            'log_group': log_group,
            'schema': cfg['schema'],
            'is_searchable': searchable,
            'status_detail': '활성 — 검색 가능' if searchable else '온보딩 대기 — 로그 미수집',
        })
    return {'sources': sources}


def run_log_query(body):
    """Execute a LogsQL query against a source via CloudWatch Logs Insights (direct API)."""
    source = body.get('source', '')
    query = (body.get('query') or '').strip()
    minutes = _safe_int(body.get('minutes'), 60)
    limit = _safe_int(body.get('limit'), 100)
    if not source or not query:
        return {'error': 'source and query are required'}

    log_group = _resolve_log_group(source)
    # 끝에 '| limit N' 연산자가 이미 있을 때만 건너뛴다 — 'rate_limit' 같은 필드명이
    # 들어 있어도 무한정 쿼리되지 않도록(L7). 단순 substring 검사는 부정확.
    if not re.search(r'\|\s*limit\s+\d+\s*$', query, re.IGNORECASE):
        query = f"{query} | limit {limit}"

    try:
        logs = boto3.client('logs', region_name=AWS_REGION)
        now = int(time.time())
        start = now - minutes * 60
        qid = logs.start_query(logGroupName=log_group, startTime=start, endTime=now, queryString=query)['queryId']
        for _ in range(30):
            res = logs.get_query_results(queryId=qid)
            status = res['status']
            if status == 'Complete':
                rows = [{f['field']: f['value'] for f in row} for row in res.get('results', [])]
                stats = res.get('statistics', {})
                return {'source': source, 'log_group': log_group, 'query': query, 'minutes': minutes,
                        'rows': rows, 'count': len(rows), 'records_scanned': stats.get('recordsScanned')}
            if status in ('Failed', 'Cancelled', 'Timeout'):
                return {'error': f'Query {status}', 'source': source, 'log_group': log_group, 'query': query}
            time.sleep(1)
        return {'error': 'Query did not complete in 30s', 'source': source, 'log_group': log_group}
    except Exception as e:
        msg = str(e)
        if 'ResourceNotFound' in msg or 'does not exist' in msg:
            return {'error': f'Log group not found: {log_group}. Source may not be onboarded yet.', 'source': source}
        return {'error': msg, 'source': source, 'log_group': log_group}


def generate_log_query(body):
    """Generate a LogsQL query from natural language via the Log Query Agent."""
    source = body.get('source', '')
    nl = body.get('natural_language', '')
    finding_context = body.get('finding_context')
    if not nl:
        return {'error': 'natural_language is required'}

    arn = os.environ.get('LOGQUERY_AGENT_RUNTIME_ARN', '')
    qualifier = os.environ.get('LOGQUERY_AGENT_QUALIFIER', 'DEFAULT')
    if not arn or not agentcore_client:
        return {'error': 'Log Query Agent not configured'}

    schema = LOG_SOURCES.get(source, {}).get('schema', '')
    ctx = f"\n조사 중인 finding 컨텍스트: {json.dumps(finding_context, ensure_ascii=False)}" if finding_context else ''
    prompt = (
        f"로그 소스 '{source}' (필드: {schema})에 대해 다음 요청을 CloudWatch Logs Insights LogsQL "
        f"쿼리로 변환하세요. 시간 범위는 포함하지 말고, LogsQL 쿼리 한 줄만 코드블록 없이 출력하세요.{ctx}\n\n요청: {nl}"
    )
    try:
        resp = agentcore_client.invoke_agent_runtime(
            agentRuntimeArn=arn, qualifier=qualifier,
            runtimeSessionId=f"logquery-gen-{int(time.time())}-{uuid.uuid4().hex}",
            payload=json.dumps({"message": prompt}), contentType='application/json',
        )
        data = json.loads(resp['response'].read())
        text = data.get('result', '') or data.get('text', '')
        # Extract the LogsQL line: strip code fences / prose, keep the part with a pipe or 'fields'/'filter'
        query = _extract_logsql(text)
        return {'query': query, 'raw': text, 'source': source}
    except Exception as e:
        return {'error': str(e), 'source': source}


def _extract_logsql(text):
    """Best-effort extraction of a LogsQL query from agent text output."""
    if not text:
        return ''
    cleaned = text.replace('```sql', '').replace('```', '').strip()
    # Prefer a line containing LogsQL operators
    for line in cleaned.splitlines():
        l = line.strip()
        if '|' in l or l.lower().startswith(('fields', 'filter', 'stats')):
            return l
    return cleaned.splitlines()[0].strip() if cleaned else ''


# ---- 저장된 LogsQL 쿼리 (사용자별, DynamoDB) ----

def _log_queries_table():
    return dynamodb.Table(os.environ.get('LOG_QUERIES_TABLE', 'log-queries'))


def save_log_query(user, body):
    """사용자가 작성한 LogsQL 쿼리를 저장."""
    if not user:
        return {'error': 'Unauthorized'}
    query = (body.get('query') or '').strip()
    if not query:
        return {'error': 'query is required'}
    query_id = uuid.uuid4().hex
    now = datetime.utcnow().isoformat() + 'Z'
    try:
        _log_queries_table().put_item(Item={
            'user_id': user['user_id'],
            'query_id': query_id,
            'name': (body.get('name') or '제목 없는 쿼리')[:120],
            'source': body.get('source', ''),
            'query': query[:4000],
            'minutes': int(body.get('minutes', 60)),
            'created_at': now,
        })
        return {'query_id': query_id, 'created_at': now}
    except Exception as e:
        print(f"save_log_query failed: {e}")
        return {'error': str(e)}


def list_log_queries(user):
    """사용자의 저장된 쿼리 목록(최신순)."""
    if not user:
        return []
    try:
        resp = _log_queries_table().query(
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user['user_id']},
        )
        items = resp.get('Items', [])
        items.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return [{
            'query_id': i['query_id'], 'name': i.get('name', ''),
            'source': i.get('source', ''), 'query': i.get('query', ''),
            'minutes': int(i.get('minutes', 60)), 'created_at': i.get('created_at', ''),
        } for i in items]
    except Exception as e:
        print(f"list_log_queries failed: {e}")
        return []


def delete_log_query(user, query_id):
    """저장된 쿼리 삭제(주인만)."""
    if not user:
        return {'error': 'Unauthorized'}
    try:
        _log_queries_table().delete_item(Key={'user_id': user['user_id'], 'query_id': query_id})
        return {'success': True, 'query_id': query_id}
    except Exception as e:
        return {'error': str(e)}


# ============================================================
# Task Board (SOAR approval workflow)
# ============================================================

TASKS_TABLE = os.environ.get('TASKS_TABLE', 'tasks')
SOAR_LAMBDA_ARN = os.environ.get('SOAR_LAMBDA_ARN', '')


def _tasks_table():
    return dynamodb.Table(TASKS_TABLE)


def get_tasks(event):
    """List tasks, optionally filtered by status (e.g. pending_approval)."""
    qp = event.get('queryStringParameters') or {}
    status = qp.get('status')
    limit = _safe_int(qp.get('limit'), 100)
    table = _tasks_table()
    try:
        if status and status != 'all':
            resp = table.query(
                IndexName='status-index',
                KeyConditionExpression='#s = :s',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': status},
                ScanIndexForward=False, Limit=limit,
            )
            items = resp.get('Items', [])
        else:
            items = table.scan(Limit=limit).get('Items', [])
            items.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        # Parse action_params JSON for the UI
        for it in items:
            ap = it.get('action_params')
            if isinstance(ap, str) and ap:
                try:
                    it['action_params'] = json.loads(ap)
                except (json.JSONDecodeError, TypeError):
                    pass
        return items[:limit]
    except Exception as e:
        print(f"get_tasks failed: {e}")
        return []


def approve_task(task_id, user):
    """Approve a pending_approval task → execute its remediation via SOAR Lambda (approved=true)."""
    table = _tasks_table()
    try:
        item = table.get_item(Key={'task_id': task_id}).get('Item')
    except Exception as e:
        return {'error': f'Task lookup failed: {e}'}
    if not item:
        return {'error': 'Task not found', 'task_id': task_id}
    if item.get('status') != 'pending_approval':
        return {'error': f"Task is not pending approval (status={item.get('status')})", 'task_id': task_id}

    action = item.get('proposed_action', '')
    params = item.get('action_params', {})
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except (json.JSONDecodeError, TypeError):
            params = {}
    if not action or not SOAR_LAMBDA_ARN:
        return {'error': 'No proposed_action or SOAR Lambda not configured', 'task_id': task_id}

    # Execute the high-risk action WITH approval
    try:
        lmb = boto3.client('lambda', region_name=AWS_REGION)
        resp = lmb.invoke(
            FunctionName=SOAR_LAMBDA_ARN, InvocationType='RequestResponse',
            Payload=json.dumps({'action': action, 'params': params, 'approved': True}).encode('utf-8'),
        )
        result = json.loads(resp['Payload'].read())
    except Exception as e:
        result = {'error': str(e)}

    new_status = 'executed' if result.get('success') else 'failed'
    now = datetime.utcnow().isoformat() + 'Z'
    approver = (user or {}).get('email') or (user or {}).get('user_id') or 'unknown'
    try:
        table.update_item(
            Key={'task_id': task_id},
            UpdateExpression='SET #s = :s, updated_at = :u, approved_by = :a, execution_result = :r',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={
                ':s': new_status, ':u': now, ':a': approver,
                ':r': json.dumps(result, ensure_ascii=False),
            },
        )
    except Exception as e:
        print(f"approve_task status update failed: {e}")
    return {'task_id': task_id, 'status': new_status, 'result': result}


def reject_task(task_id, user):
    """Reject a pending_approval task (no action executed)."""
    table = _tasks_table()
    now = datetime.utcnow().isoformat() + 'Z'
    approver = (user or {}).get('email') or (user or {}).get('user_id') or 'unknown'
    try:
        table.update_item(
            Key={'task_id': task_id},
            UpdateExpression='SET #s = :s, updated_at = :u, approved_by = :a',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':s': 'rejected', ':u': now, ':a': approver},
        )
        return {'task_id': task_id, 'status': 'rejected'}
    except Exception as e:
        return {'error': str(e), 'task_id': task_id}


def complete_task(task_id, user):
    """분석가 작업 티켓(open)을 완료 처리(done). 실제 조치 실행이 아니라 추적 종결.
    pending_approval(고위험 승인 대기)는 완료 불가 — 승인/거부 게이트를 우회해 감사추적이
    훼손되는 것을 막는다(반드시 approve/reject 경유)."""
    table = _tasks_table()
    now = datetime.utcnow().isoformat() + 'Z'
    actor = (user or {}).get('email') or (user or {}).get('user_id') or 'unknown'
    try:
        table.update_item(
            Key={'task_id': task_id},
            UpdateExpression='SET #s = :s, updated_at = :u, completed_by = :c',
            ConditionExpression='#s = :open',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':s': 'done', ':u': now, ':c': actor, ':open': 'open'},
        )
        return {'task_id': task_id, 'status': 'done'}
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return {'error': "open 상태의 작업만 완료할 수 있습니다 (승인 대기 건은 승인/거부로 처리하세요)",
                    'task_id': task_id}
        return {'error': str(e), 'task_id': task_id}
    except Exception as e:
        return {'error': str(e), 'task_id': task_id}


# ============================================================
# SOC Readiness (onboarding/prerequisite checks) — read-only
# ============================================================

def _ck(items, id, category, label, status, detail='', remediation=''):
    items.append({'id': id, 'category': category, 'label': label,
                  'status': status, 'detail': detail, 'remediation': remediation})


def get_readiness():
    """Check whether the AWS security services/settings the SOC depends on are enabled.
    Read-only. Each check is isolated so a permission/region issue degrades to status='error'."""
    items = []
    region = AWS_REGION

    # ---- 탐지 서비스 (Detection) ----
    try:
        gd = boto3.client('guardduty', region_name=region)
        detectors = gd.list_detectors().get('DetectorIds', [])
        if detectors:
            _ck(items, 'guardduty', 'detection', 'Amazon GuardDuty', 'ok',
                f'{len(detectors)}개 detector 활성')
        else:
            _ck(items, 'guardduty', 'detection', 'Amazon GuardDuty', 'missing',
                'detector 없음 — 위협 탐지 finding이 생성되지 않습니다',
                'aws guardduty create-detector --enable --region ' + region)
    except Exception as e:
        _ck(items, 'guardduty', 'detection', 'Amazon GuardDuty', 'error', str(e)[:200])

    # Security Hub CSPM (classic — describe_hub/enable-security-hub). 컴플라이언스 표준·컨트롤·finding 집계 허브.
    try:
        sh = boto3.client('securityhub', region_name=region)
        sh.describe_hub()
        _ck(items, 'securityhub_cspm', 'detection', 'Security Hub CSPM', 'ok',
            '활성화됨 — GuardDuty/Inspector/Macie finding 집계 + CIS/PCI/NIST 컨트롤')
    except Exception as e:
        msg = str(e)
        if 'InvalidAccess' in msg or 'not subscribed' in msg.lower() or 'ResourceNotFound' in msg:
            _ck(items, 'securityhub_cspm', 'detection', 'Security Hub CSPM', 'missing',
                '구독되지 않음 — 통합 finding 집계/컴플라이언스 컨트롤 없음',
                'aws securityhub enable-security-hub --region ' + region)
        else:
            _ck(items, 'securityhub_cspm', 'detection', 'Security Hub CSPM', 'error', msg[:200])

    # Security Hub (신규 통합 — V2 API). Essentials 기반 상관·우선순위화.
    try:
        sh = boto3.client('securityhub', region_name=region)
        v2 = sh.describe_security_hub_v2()
        if v2.get('HubV2Arn'):
            _ck(items, 'securityhub_v2', 'detection', 'Security Hub (신규 통합)', 'ok',
                f"활성화됨 (구독: {v2.get('SubscribedAt', '')[:10]})")
        else:
            _ck(items, 'securityhub_v2', 'detection', 'Security Hub (신규 통합)', 'warn',
                '미활성 — 차세대 통합 Security Hub 미사용 (CSPM으로 동작 가능)',
                'aws securityhub enable-security-hub-v2 --region ' + region)
    except Exception as e:
        msg = str(e)
        if 'ResourceNotFound' in msg or 'not subscribed' in msg.lower() or 'InvalidAccess' in msg:
            _ck(items, 'securityhub_v2', 'detection', 'Security Hub (신규 통합)', 'warn',
                '미활성 — 차세대 통합 Security Hub 미사용 (선택사항, CSPM으로 동작 가능)',
                'aws securityhub enable-security-hub-v2 --region ' + region)
        else:
            _ck(items, 'securityhub_v2', 'detection', 'Security Hub (신규 통합)', 'error', msg[:200])

    # Amazon Macie — S3 민감정보(PII) 탐지. finding은 Security Hub로 유입.
    try:
        mc = boto3.client('macie2', region_name=region)
        sess = mc.get_macie_session()
        status = sess.get('status', 'UNKNOWN')
        if status == 'ENABLED':
            _ck(items, 'macie', 'detection', 'Amazon Macie', 'ok', '활성화됨 — S3 민감정보 탐지')
        else:
            _ck(items, 'macie', 'detection', 'Amazon Macie', 'warn',
                f'상태: {status} — S3 민감정보(PII) 탐지 비활성',
                'aws macie2 enable-macie --region ' + region)
    except Exception as e:
        msg = str(e)
        if 'ResourceNotFound' in msg or 'Macie is not enabled' in msg or 'AccessDenied' in msg:
            _ck(items, 'macie', 'detection', 'Amazon Macie', 'missing',
                '미활성 — S3 버킷 민감정보(PII/자격증명) 노출 탐지 불가',
                'aws macie2 enable-macie --region ' + region)
        else:
            _ck(items, 'macie', 'detection', 'Amazon Macie', 'error', msg[:200])

    try:
        insp = boto3.client('inspector2', region_name=region)
        sts = boto3.client('sts')
        acct = sts.get_caller_identity()['Account']
        resp = insp.batch_get_account_status(accountIds=[acct])
        accounts = resp.get('accounts', [])
        state = accounts[0].get('state', {}).get('status', 'UNKNOWN') if accounts else 'UNKNOWN'
        if state == 'ENABLED':
            _ck(items, 'inspector', 'detection', 'Amazon Inspector', 'ok', '활성화됨')
        else:
            _ck(items, 'inspector', 'detection', 'Amazon Inspector', 'missing',
                f'상태: {state} — 취약점/네트워크 finding 미수집',
                'aws inspector2 enable --resource-types EC2 ECR LAMBDA --region ' + region)
    except Exception as e:
        _ck(items, 'inspector', 'detection', 'Amazon Inspector', 'error', str(e)[:200])

    # ---- 로그 소스 (Log Sources) ----
    # Log Explorer가 보는 LOG_SOURCES와 동일한 기준으로 소스별 개별 표시 — 두 페이지 일관성 유지.
    # 각 소스를 CloudWatch Logs Data Sources 분류(또는 /security/* 프리픽스)로 검색 가능 여부 판정.
    # 소스명 → 사람이 읽는 라벨 + remediation 힌트
    _LOG_SOURCE_META = {
        'vpc-flowlogs': ('VPC Flow Logs', 'aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /security/vpc-flowlogs ...'),
        'cloudtrail':   ('CloudTrail', 'CloudWatch Telemetry(Ingestion) 또는 trail의 CloudWatch Logs 전송 설정으로 CloudTrail 로그를 CW에 온보딩'),
        'dns-queries':  ('Route53 Resolver DNS', 'CloudWatch Telemetry enablement rule로 Route53 Resolver query log를 CW에 온보딩'),
        'waf':          ('WAF', 'WAF Web ACL 로깅을 CloudWatch Logs로 활성화 (aws-waf-logs-* 또는 Telemetry rule)'),
        'nlb-access':   ('NLB Access', 'NLB 액세스 로그를 CloudWatch Logs로 전송 (Telemetry rule)'),
    }
    for src, cfg in LOG_SOURCES.items():
        label = _LOG_SOURCE_META.get(src, (src, ''))[0]
        remediation = _LOG_SOURCE_META.get(src, (src, ''))[1]
        try:
            ds = cfg.get('data_source')
            resolved = _lookup_log_group_by_data_source(ds) if ds else None
            if resolved:
                lg, searchable = resolved, True
            else:
                lg, searchable = cfg['log_group'], _log_group_exists(cfg['log_group'])
            if searchable:
                _ck(items, f'log-{src}', 'logs', label, 'ok', f'활성 — 검색 가능 ({lg})')
            else:
                _ck(items, f'log-{src}', 'logs', label, 'missing',
                    'CloudWatch Logs에 미온보딩 — Log Explorer/Investigation에서 조회 불가', remediation)
        except Exception as e:
            _ck(items, f'log-{src}', 'logs', label, 'error', str(e)[:200])

    # ---- 에이전트·파이프라인 (Agents & Pipeline) ----
    try:
        acc = boto3.client('bedrock-agentcore-control', region_name=region)
        runtimes = acc.list_agent_runtimes(maxResults=50).get('agentRuntimes', [])
        ready = [r for r in runtimes if r.get('status') == 'READY' and 'agentic_soc' in r.get('agentRuntimeName', '')]
        soc_total = [r for r in runtimes if 'agentic_soc' in r.get('agentRuntimeName', '')]
        if len(ready) >= 6:
            _ck(items, 'agents', 'agents', 'AgentCore 런타임 (6종)', 'ok', f'{len(ready)}개 READY')
        elif ready:
            _ck(items, 'agents', 'agents', 'AgentCore 런타임 (6종)', 'warn',
                f'{len(ready)}/{len(soc_total)} READY — 일부 미준비')
        else:
            _ck(items, 'agents', 'agents', 'AgentCore 런타임 (6종)', 'missing', '런타임 없음 — AgentCoreStack 배포 필요')
    except Exception as e:
        _ck(items, 'agents', 'agents', 'AgentCore 런타임 (6종)', 'error', str(e)[:200])

    # findings 테이블 (Aurora)
    try:
        if AURORA_ENABLED:
            rows = aurora_db.query("SELECT COUNT(*) AS c FROM findings")
            cnt = rows[0].get('c', 0) if rows else 0
            _ck(items, 'findingsdb', 'agents', 'Findings 저장소 (Aurora)', 'ok', f'{cnt}건 저장됨')
        else:
            _ck(items, 'findingsdb', 'agents', 'Findings 저장소 (Aurora)', 'warn', 'Aurora 미구성 (DDB fallback)')
    except Exception as e:
        _ck(items, 'findingsdb', 'agents', 'Findings 저장소 (Aurora)', 'error', str(e)[:200])

    # SOAR Lambda — env에 ARN이 없으면 'missing'(하드코딩 dev 이름으로 잘못 탐색하지 않음)
    try:
        soar_arn = os.environ.get('SOAR_LAMBDA_ARN', '')
        if not soar_arn:
            _ck(items, 'soar', 'agents', 'SOAR 대응 Lambda', 'warn',
                'SOAR_LAMBDA_ARN 미설정 — 승인된 조치를 실행할 대상이 없음',
                'CDK가 host-agent Lambda에 SOAR_LAMBDA_ARN env를 주입하는지 확인')
        else:
            lmb = boto3.client('lambda', region_name=region)
            lmb.get_function(FunctionName=soar_arn)
            _ck(items, 'soar', 'agents', 'SOAR 대응 Lambda', 'ok', '배포됨')
    except Exception:
        _ck(items, 'soar', 'agents', 'SOAR 대응 Lambda', 'missing', 'SOAR Lambda 없음 — 자동 대응 불가')

    # AgentCore Memory
    try:
        acc = boto3.client('bedrock-agentcore-control', region_name=region)
        mems = acc.list_memories(maxResults=50).get('memories', [])
        soc_mem = [m for m in mems if 'agentic_soc' in m.get('id', '')]
        if any(m.get('status') == 'ACTIVE' for m in soc_mem):
            _ck(items, 'memory', 'agents', 'AgentCore Memory', 'ok', '활성 — 컨텍스트 기억 동작')
        else:
            _ck(items, 'memory', 'agents', 'AgentCore Memory', 'warn',
                'Memory 미생성 — 대화는 DDB fallback (장기기억 없음)',
                'scripts/create-memory.sh 실행 후 MEMORY_ID를 런타임에 주입')
    except Exception as e:
        _ck(items, 'memory', 'agents', 'AgentCore Memory', 'error', str(e)[:200])

    # EventBridge 룰
    try:
        evb = boto3.client('events', region_name=region)
        rules = evb.list_rules(NamePrefix='agentic-soc').get('Rules', [])
        names = ' '.join(r.get('Name', '') for r in rules)
        have = [k for k in ('GuardDuty', 'SecurityHub', 'Inspector') if k in names]
        if len(have) >= 3:
            _ck(items, 'eventrules', 'agents', 'EventBridge 수집 룰', 'ok', f'{len(rules)}개 룰')
        elif have:
            _ck(items, 'eventrules', 'agents', 'EventBridge 수집 룰', 'warn', f'일부만: {", ".join(have)}')
        else:
            _ck(items, 'eventrules', 'agents', 'EventBridge 수집 룰', 'missing', 'finding 수집 룰 없음')
    except Exception as e:
        _ck(items, 'eventrules', 'agents', 'EventBridge 수집 룰', 'error', str(e)[:200])

    # ---- Observability ----
    try:
        xr = boto3.client('xray', region_name=region)
        dest = xr.get_trace_segment_destination()
        if dest.get('Destination') == 'CloudWatchLogs' or (dest.get('Destination') == 'XRay' and dest.get('Status') == 'ACTIVE'):
            _ck(items, 'xray', 'observability', 'X-Ray Transaction Search', 'ok',
                f"목적지 {dest.get('Destination')}, {dest.get('Status')}")
        else:
            _ck(items, 'xray', 'observability', 'X-Ray Transaction Search', 'warn',
                f"상태 {dest.get('Status')} — 분산 트레이스 미수집",
                'aws xray update-trace-segment-destination --destination CloudWatchLogs')
    except Exception as e:
        _ck(items, 'xray', 'observability', 'X-Ray Transaction Search', 'error', str(e)[:200])

    try:
        logs_c = boto3.client('logs', region_name=region)
        pols = logs_c.describe_resource_policies().get('resourcePolicies', [])
        if any('xray' in (p.get('policyDocument') or '').lower() for p in pols):
            _ck(items, 'spanpolicy', 'observability', 'aws/spans resource policy', 'ok', 'X-Ray→spans 권한 설정됨')
        else:
            _ck(items, 'spanpolicy', 'observability', 'aws/spans resource policy', 'warn',
                'span 로그 쓰기 권한 미설정 — 트레이스 span 미수집',
                'logs put-resource-policy로 xray.amazonaws.com PutLogEvents 허용')
    except Exception as e:
        _ck(items, 'spanpolicy', 'observability', 'aws/spans resource policy', 'error', str(e)[:200])

    try:
        cw = boto3.client('cloudwatch', region_name=region)
        metrics = cw.list_metrics(Namespace='AWS/Bedrock-AgentCore').get('Metrics', [])
        if metrics:
            _ck(items, 'acmetrics', 'observability', 'AgentCore 메트릭', 'ok', f'{len(metrics)}개 시리즈 수신')
        else:
            _ck(items, 'acmetrics', 'observability', 'AgentCore 메트릭', 'warn', '메트릭 미수신 (호출 이력 없음일 수 있음)')
    except Exception as e:
        _ck(items, 'acmetrics', 'observability', 'AgentCore 메트릭', 'error', str(e)[:200])

    # 요약
    ok = sum(1 for i in items if i['status'] == 'ok')
    total = len(items)
    return {
        'items': items,
        'summary': {'ok': ok, 'total': total,
                    'pct': round(ok / total * 100) if total else 0,
                    'warn': sum(1 for i in items if i['status'] == 'warn'),
                    'missing': sum(1 for i in items if i['status'] == 'missing'),
                    'error': sum(1 for i in items if i['status'] == 'error')},
    }
