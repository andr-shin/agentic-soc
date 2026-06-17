"""CloudWatch Logs tools for incident analysis."""
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
from strands import tool

logger = logging.getLogger("incident-agent.cloudwatch-logs")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')


@tool
def search_cloudwatch_logs(log_group: str, filter_pattern: str = "ERROR", minutes: int = 60, limit: int = 50) -> dict:
    """Search CloudWatch Logs for keywords or patterns within a time range.
    Parameters:
      log_group: CloudWatch Log Group name (required, e.g. '/aws/eks/cluster-name/cluster')
      filter_pattern: Filter pattern — keyword like 'ERROR', 'Exception', or structured like '{ $.level = "error" }' (default: 'ERROR')
      minutes: Time range in minutes (default: 60)
      limit: Max events to return (default: 50)
    """
    try:
        logs_client = boto3.client('logs', region_name=REGION)

        end_time = int(datetime.now(timezone.utc).timestamp() * 1000)
        start_time = int((datetime.now(timezone.utc) - timedelta(minutes=minutes)).timestamp() * 1000)

        resp = logs_client.filter_log_events(
            logGroupName=log_group,
            startTime=start_time,
            endTime=end_time,
            filterPattern=filter_pattern,
            limit=limit,
            interleaved=True,
        )

        events = [{
            'timestamp': datetime.fromtimestamp(e['timestamp'] / 1000, tz=timezone.utc).isoformat(),
            'message': e['message'][:2000],
            'stream': e.get('logStreamName', '-'),
        } for e in resp.get('events', [])]

        return {
            'events': events,
            'count': len(events),
            'log_group': log_group,
            'filter_pattern': filter_pattern,
            'minutes': minutes,
        }
    except Exception as e:
        return {'error': str(e)}


@tool
def detect_log_anomalies(log_group: str, minutes: int = 120, baseline_minutes: int = 1440) -> dict:
    """Detect log volume anomalies by comparing recent volume against baseline (hourly pattern analysis).
    Parameters:
      log_group: CloudWatch Log Group name (required)
      minutes: Recent time window to check for anomalies (default: 120 = last 2 hours)
      baseline_minutes: Baseline period for normal volume (default: 1440 = 24 hours)
    """
    try:
        logs_client = boto3.client('logs', region_name=REGION)

        now = datetime.now(timezone.utc)

        # Recent volume
        recent_query = f"""
        fields @timestamp
        | stats count(*) as log_count by bin(10m)
        | sort @timestamp desc
        """

        recent_start = int((now - timedelta(minutes=minutes)).timestamp())
        recent_end = int(now.timestamp())

        start_resp = logs_client.start_query(
            logGroupName=log_group,
            startTime=recent_start,
            endTime=recent_end,
            queryString=recent_query,
        )
        query_id = start_resp['queryId']

        import time
        for _ in range(30):
            result = logs_client.get_query_results(queryId=query_id)
            if result['status'] == 'Complete':
                break
            time.sleep(1)

        recent_buckets = []
        for row in result.get('results', []):
            bucket = {}
            for field in row:
                bucket[field['field']] = field['value']
            recent_buckets.append(bucket)

        recent_counts = [int(b.get('log_count', 0)) for b in recent_buckets if b.get('log_count')]
        avg_recent = sum(recent_counts) / len(recent_counts) if recent_counts else 0
        max_recent = max(recent_counts) if recent_counts else 0

        anomalies = []
        if max_recent > avg_recent * 3 and avg_recent > 0:
            anomalies.append({
                'type': 'VOLUME_SPIKE',
                'severity': 'WARNING',
                'description': f'Log volume spike detected: max={max_recent} vs avg={avg_recent:.0f} (3x+)',
            })

        return {
            'recent_buckets': recent_buckets[:12],
            'avg_recent_per_10min': round(avg_recent, 1),
            'max_recent_per_10min': max_recent,
            'anomalies': anomalies,
            'log_group': log_group,
            'minutes': minutes,
        }
    except Exception as e:
        return {'error': str(e)}
