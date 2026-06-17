"""CloudWatch Logs Insights tools — query the CloudWatch Unified Data Store.
Resolves friendly security log-source names to log groups, runs LogsQL queries, and
discovers fields. The LLM translates natural language into LogsQL; these tools execute it."""
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from strands import tool

logger = logging.getLogger("logquery-agent.insights")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')

# Friendly source name → CloudWatch log group. Overridable via env (JSON or individual vars).
# Defaults follow a /security/* centralization convention (CloudWatch Unified Data Store).
_DEFAULT_LOG_GROUPS = {
    'vpc-flowlogs': os.environ.get('LOG_GROUP_VPC_FLOW', '/security/vpc-flowlogs'),
    'cloudtrail': os.environ.get('LOG_GROUP_CLOUDTRAIL', '/security/cloudtrail'),
    'dns-queries': os.environ.get('LOG_GROUP_DNS', '/security/dns-queries'),
    'waf': os.environ.get('LOG_GROUP_WAF', '/security/waf-logs'),
    'nlb-access': os.environ.get('LOG_GROUP_NLB', '/security/nlb-access'),
    'route53-resolver': os.environ.get('LOG_GROUP_RESOLVER', '/security/route53-resolver'),
}

# Schema hints surfaced to the LLM so it can write correct LogsQL per source.
_SCHEMA_HINTS = {
    'vpc-flowlogs': 'fields: srcAddr, dstAddr, srcPort, dstPort, protocol, action (ACCEPT/REJECT), bytes, packets, start, end, interfaceId',
    'cloudtrail': 'fields: eventName, eventSource, userIdentity.arn, sourceIPAddress, awsRegion, errorCode, requestParameters, responseElements',
    'dns-queries': 'fields: query_name, query_type, rcode, srcaddr, transport',
    'waf': 'fields: action (ALLOW/BLOCK), httpRequest.clientIp, httpRequest.uri, httpRequest.country, terminatingRuleId',
    'nlb-access': 'fields: client_ip, listener, target, tcp_connection_time, received_bytes, sent_bytes',
    'route53-resolver': 'fields: query_name, query_type, rcode, srcaddr, answers',
}


def _resolve_log_group(source: str) -> str:
    """Resolve a friendly source name (or pass through an explicit log group name)."""
    if source in _DEFAULT_LOG_GROUPS:
        return _DEFAULT_LOG_GROUPS[source]
    return source  # treat as a literal log group name


@tool
def list_log_sources() -> dict:
    """List the available security log sources and their LogsQL field schemas.
    Use this first to learn which sources exist and what fields each supports."""
    sources = []
    for name, lg in _DEFAULT_LOG_GROUPS.items():
        sources.append({
            'source': name,
            'log_group': lg,
            'schema_hint': _SCHEMA_HINTS.get(name, ''),
        })
    return {'sources': sources, 'count': len(sources),
            'note': 'Pass a source name or an explicit log group to run_logs_query.'}


@tool
def run_logs_query(source: str, query: str, minutes: int = 60, limit: int = 100) -> dict:
    """Run a CloudWatch Logs Insights (LogsQL) query against a security log source.
    Translate the user's natural-language request into LogsQL and pass it here.
    Parameters:
      source: Friendly source name (vpc-flowlogs/cloudtrail/dns-queries/waf/nlb-access/route53-resolver)
              or an explicit CloudWatch log group name.
      query: A LogsQL query. Do NOT include a time range (set via 'minutes'). Use fields/filter/stats/sort/limit.
             Example: 'filter action="REJECT" | stats count(*) as n by srcAddr | sort n desc'
      minutes: Time range in minutes back from now (default: 60)
      limit: Max rows to return (default: 100; appended as LogsQL limit if not present)
    """
    log_group = _resolve_log_group(source)
    if not log_group:
        return {'error': f'Unknown source {source!r}. Call list_log_sources first.'}

    # Ensure a limit is present to avoid runaway result sets
    q = query.strip()
    if 'limit' not in q.lower():
        q = f"{q} | limit {limit}"

    try:
        logs_client = boto3.client('logs', region_name=REGION)
        now = datetime.now(timezone.utc)
        start = int((now - timedelta(minutes=minutes)).timestamp())
        end = int(now.timestamp())

        start_resp = logs_client.start_query(
            logGroupName=log_group,
            startTime=start,
            endTime=end,
            queryString=q,
        )
        query_id = start_resp['queryId']

        for _ in range(30):
            result = logs_client.get_query_results(queryId=query_id)
            status = result['status']
            if status == 'Complete':
                rows = [{f['field']: f['value'] for f in row} for row in result.get('results', [])]
                stats = result.get('statistics', {})
                return {
                    'source': source,
                    'log_group': log_group,
                    'query': q,
                    'minutes': minutes,
                    'rows': rows,
                    'count': len(rows),
                    'records_scanned': stats.get('recordsScanned'),
                }
            if status in ('Failed', 'Cancelled', 'Timeout'):
                return {'error': f'Query {status}', 'source': source, 'log_group': log_group, 'query': q}
            time.sleep(1)
        return {'error': 'Query did not complete in 30s', 'source': source, 'log_group': log_group}
    except logs_client.exceptions.ResourceNotFoundException:
        return {'error': f'Log group not found: {log_group}. The source may not be onboarded yet.',
                'source': source}
    except Exception as e:
        return {'error': str(e), 'source': source, 'log_group': log_group}


@tool
def get_log_fields(source: str, minutes: int = 60) -> dict:
    """Discover the most common fields present in a log source (helps build LogsQL).
    Parameters:
      source: Friendly source name or explicit log group name
      minutes: Sample window in minutes (default: 60)
    """
    log_group = _resolve_log_group(source)
    try:
        logs_client = boto3.client('logs', region_name=REGION)
        now = datetime.now(timezone.utc)
        start = int((now - timedelta(minutes=minutes)).timestamp())
        end = int(now.timestamp())
        start_resp = logs_client.start_query(
            logGroupName=log_group,
            startTime=start,
            endTime=end,
            queryString='fields @message | limit 5',
        )
        query_id = start_resp['queryId']
        for _ in range(20):
            result = logs_client.get_query_results(queryId=query_id)
            if result['status'] == 'Complete':
                samples = ['\n'.join(f"{f['field']}={f['value']}" for f in row) for row in result.get('results', [])]
                return {'source': source, 'log_group': log_group,
                        'schema_hint': _SCHEMA_HINTS.get(source, ''),
                        'samples': samples[:5]}
            if result['status'] in ('Failed', 'Cancelled', 'Timeout'):
                return {'error': f"Query {result['status']}", 'source': source}
            time.sleep(1)
        return {'error': 'timeout', 'source': source}
    except Exception as e:
        return {'error': str(e), 'source': source}
