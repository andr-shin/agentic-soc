"""VPC Flow Logs analysis tool — network forensics for incident investigation.
Runs CloudWatch Logs Insights queries against a VPC Flow Logs log group to reconstruct
an IP/ENI's network activity (top talkers, rejected connections, port scans, data egress)."""
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from strands import tool

logger = logging.getLogger("investigation-agent.vpc-flow")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')

# Default log group for VPC Flow Logs (override via env or tool param)
DEFAULT_FLOW_LOG_GROUP = os.environ.get('VPC_FLOW_LOG_GROUP', '')


def _run_insights_query(log_group: str, query: str, minutes: int, limit_seconds: int = 30) -> list:
    """Run a CloudWatch Logs Insights query and wait for results."""
    logs_client = boto3.client('logs', region_name=REGION)
    now = datetime.now(timezone.utc)
    start = int((now - timedelta(minutes=minutes)).timestamp())
    end = int(now.timestamp())

    start_resp = logs_client.start_query(
        logGroupName=log_group,
        startTime=start,
        endTime=end,
        queryString=query,
    )
    query_id = start_resp['queryId']

    for _ in range(limit_seconds):
        result = logs_client.get_query_results(queryId=query_id)
        if result['status'] == 'Complete':
            rows = []
            for row in result.get('results', []):
                rows.append({field['field']: field['value'] for field in row})
            return rows
        if result['status'] in ('Failed', 'Cancelled', 'Timeout'):
            raise RuntimeError(f"Insights query {result['status']}")
        time.sleep(1)
    raise TimeoutError("Insights query did not complete in time")


@tool
def analyze_vpc_flow(src_ip: str = "", dst_ip: str = "", log_group: str = "",
                     minutes: int = 60, mode: str = "summary") -> dict:
    """Analyze VPC Flow Logs to reconstruct network activity for incident investigation.
    Parameters:
      src_ip: Source IP to investigate (e.g. an attacker IP from a GuardDuty finding)
      dst_ip: Destination IP to investigate (e.g. a compromised instance's private IP)
      log_group: VPC Flow Logs CloudWatch log group (defaults to VPC_FLOW_LOG_GROUP env var)
      minutes: Time range in minutes (default: 60)
      mode: 'summary' (top talkers + accept/reject), 'rejected' (blocked connections),
            'portscan' (distinct ports probed), or 'egress' (outbound data volume)
    """
    log_group = log_group or DEFAULT_FLOW_LOG_GROUP
    if not log_group:
        return {'error': 'No VPC Flow Logs log group configured. Set VPC_FLOW_LOG_GROUP or pass log_group.'}

    # Build a filter clause from provided IPs
    clauses = []
    if src_ip:
        clauses.append(f'srcAddr = "{src_ip}"')
    if dst_ip:
        clauses.append(f'dstAddr = "{dst_ip}"')
    filter_clause = ('filter ' + ' and '.join(clauses)) if clauses else ''

    try:
        if mode == 'rejected':
            # Build the REJECT filter outside the f-string (f-string exprs can't contain backslashes on <3.12)
            reject_clauses = clauses + ['action = "REJECT"']
            reject_filter = 'filter ' + ' and '.join(reject_clauses)
            query = f"""fields srcAddr, dstAddr, dstPort, protocol, action
            | {reject_filter}
            | stats count(*) as attempts by srcAddr, dstAddr, dstPort
            | sort attempts desc | limit 30"""
        elif mode == 'portscan':
            query = f"""fields srcAddr, dstPort, action
            | {filter_clause}
            | stats count_distinct(dstPort) as distinct_ports, count(*) as total by srcAddr
            | sort distinct_ports desc | limit 20"""
        elif mode == 'egress':
            query = f"""fields srcAddr, dstAddr, bytes
            | {filter_clause}
            | stats sum(bytes) as total_bytes by dstAddr
            | sort total_bytes desc | limit 20"""
        else:  # summary
            query = f"""fields srcAddr, dstAddr, dstPort, action, bytes
            | {filter_clause}
            | stats count(*) as flows, sum(bytes) as total_bytes by srcAddr, dstAddr, dstPort, action
            | sort flows desc | limit 30"""

        rows = _run_insights_query(log_group, query, minutes)
        return {
            'mode': mode,
            'log_group': log_group,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'minutes': minutes,
            'rows': rows,
            'count': len(rows),
        }
    except Exception as e:
        return {'error': str(e)}
