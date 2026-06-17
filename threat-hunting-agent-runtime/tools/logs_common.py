"""공유 CloudWatch Logs Insights 실행 유틸 — threat hunting 도구들이 공통으로 사용.
보안 로그 소스(친숙한 이름)를 실제 로그그룹으로 해석(CloudWatch Logs Data Sources 자동 분류 우선,
실패 시 /security/* 프리픽스 fallback)하고 LogsQL 쿼리를 실행한다."""
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')

# 친숙한 소스명 → CloudWatch Logs Data Sources 분류(name/type) + fallback 경로 + 스키마 힌트.
LOG_SOURCES = {
    'vpc-flowlogs': {
        'data_source': {'name': 'amazon_vpc', 'type': 'flow'},
        'log_group': os.environ.get('LOG_GROUP_VPC_FLOW', '/security/vpc-flowlogs'),
        'schema': 'srcAddr, dstAddr, srcPort, dstPort, protocol, action (ACCEPT/REJECT), bytes, packets, interfaceId',
    },
    'cloudtrail': {
        'data_source': {'name': 'aws_cloudtrail'},
        'log_group': os.environ.get('LOG_GROUP_CLOUDTRAIL', '/security/cloudtrail'),
        'schema': 'eventName, eventSource, userIdentity.arn, userIdentity.type, sourceIPAddress, awsRegion, errorCode, errorMessage',
    },
    'dns-queries': {
        'data_source': {'name': 'amazon_route53', 'type': 'resolver_query'},
        'log_group': os.environ.get('LOG_GROUP_DNS', '/security/dns-queries'),
        'schema': 'query_name, query_type, rcode, srcaddr, transport',
    },
}

_LOG_GROUP_CACHE = {}


def _lookup_log_group_by_data_source(ds: dict):
    """CloudWatch Logs Data Sources 분류로 실제 로그그룹 이름을 찾는다. 실패 시 None."""
    key = ds.get('name', '') + '/' + ds.get('type', '')
    if key in _LOG_GROUP_CACHE:
        return _LOG_GROUP_CACHE[key]
    name = None
    try:
        logs = boto3.client('logs', region_name=REGION)
        flt = {'name': ds['name']}
        if ds.get('type'):
            flt['type'] = ds['type']
        groups = logs.list_log_groups(dataSources=[flt]).get('logGroups', [])
        name = groups[0]['logGroupName'] if groups else None
    except Exception:
        name = None
    _LOG_GROUP_CACHE[key] = name
    return name


def resolve_log_group(source: str) -> str:
    """친숙한 소스명을 실제 로그그룹으로 해석(동적 조회 → fallback). 미등록이면 그대로 리터럴 취급."""
    cfg = LOG_SOURCES.get(source)
    if not cfg:
        return source
    ds = cfg.get('data_source')
    if ds:
        found = _lookup_log_group_by_data_source(ds)
        if found:
            return found
    return cfg['log_group']


def run_insights_query(source_or_group: str, query: str, minutes: int = 1440, limit: int = 100,
                       limit_seconds: int = 30) -> dict:
    """LogsQL 쿼리를 실행하고 결과 반환. source_or_group은 친숙한 소스명 또는 명시적 로그그룹.
    query에 limit이 없으면 자동 추가. 반환: {log_group, query, minutes, rows, count} 또는 {error}."""
    log_group = resolve_log_group(source_or_group)
    if not log_group:
        return {'error': f'알 수 없는 소스: {source_or_group!r}'}
    q = query.strip()
    if 'limit' not in q.lower():
        q = f"{q} | limit {limit}"
    try:
        logs_client = boto3.client('logs', region_name=REGION)
        now = datetime.now(timezone.utc)
        start = int((now - timedelta(minutes=minutes)).timestamp())
        end = int(now.timestamp())
        qid = logs_client.start_query(logGroupName=log_group, startTime=start, endTime=end, queryString=q)['queryId']
        for _ in range(limit_seconds):
            result = logs_client.get_query_results(queryId=qid)
            status = result['status']
            if status == 'Complete':
                rows = [{f['field']: f['value'] for f in row} for row in result.get('results', [])]
                return {'log_group': log_group, 'query': q, 'minutes': minutes, 'rows': rows, 'count': len(rows)}
            if status in ('Failed', 'Cancelled', 'Timeout'):
                return {'error': f'쿼리 {status}', 'log_group': log_group, 'query': q}
            time.sleep(1)
        return {'error': '쿼리가 시간 내 완료되지 않음', 'log_group': log_group}
    except logs_client.exceptions.ResourceNotFoundException:
        return {'error': f'로그그룹 없음: {log_group}. 해당 소스가 아직 온보딩되지 않았을 수 있음.',
                'source': source_or_group}
    except Exception as e:
        return {'error': str(e), 'log_group': log_group}
