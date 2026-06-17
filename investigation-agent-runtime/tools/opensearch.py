"""OpenSearch integration tools — log search, anomaly detection, error summary.
Only loaded when OPENSEARCH_ENDPOINT environment variable is set."""
import json
import logging
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3
from strands import tool

logger = logging.getLogger("incident-agent.opensearch")

OPENSEARCH_ENDPOINT = os.environ.get('OPENSEARCH_ENDPOINT', '')
OPENSEARCH_AUTH_TYPE = os.environ.get('OPENSEARCH_AUTH_TYPE', 'sigv4')
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')


def _os_request(method: str, path: str, body: dict = None) -> dict:
    """Make request to OpenSearch (SigV4 or basic auth)."""
    url = f"{OPENSEARCH_ENDPOINT.rstrip('/')}/{path.lstrip('/')}"
    data = json.dumps(body).encode('utf-8') if body else None
    headers = {'Content-Type': 'application/json'}

    if OPENSEARCH_AUTH_TYPE == 'sigv4':
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest

        session = boto3.Session()
        credentials = session.get_credentials().get_frozen_credentials()
        request = AWSRequest(method=method, url=url, data=data, headers=headers)
        SigV4Auth(credentials, 'es', REGION).add_auth(request)
        headers = dict(request.headers)

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return {'error': f"OpenSearch request failed: {str(e)}"}


@tool
def opensearch_search_logs(index: str, query: str, minutes: int = 60, size: int = 50) -> dict:
    """Search OpenSearch logs by keyword or pattern within a time range.
    Parameters:
      index: OpenSearch index name or pattern e.g. 'eks-app-logs*' (required)
      query: Search query string e.g. 'ERROR' or 'status:500' (required)
      minutes: Time range in minutes (default: 60)
      size: Max results (default: 50)
    """
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=minutes)

        body = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                        {"range": {"@timestamp": {
                            "gte": start.isoformat(),
                            "lte": now.isoformat(),
                        }}},
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size,
        }

        result = _os_request('POST', f'{index}/_search', body)
        if 'error' in result:
            return result

        hits = []
        for hit in result.get('hits', {}).get('hits', []):
            src = hit.get('_source', {})
            hits.append({
                'timestamp': src.get('@timestamp', '-'),
                'message': str(src.get('message', src.get('log', '-')))[:2000],
                'level': src.get('level', src.get('severity', '-')),
                'source': src.get('kubernetes', {}).get('pod_name', src.get('source', '-')),
                'index': hit.get('_index', '-'),
            })

        return {
            'hits': hits,
            'total': result.get('hits', {}).get('total', {}).get('value', 0),
            'index': index,
            'query': query,
            'minutes': minutes,
        }
    except Exception as e:
        return {'error': str(e)}


@tool
def opensearch_anomaly_detection(index: str, minutes: int = 120) -> dict:
    """Detect log volume anomaly patterns using OpenSearch aggregation (hourly bucket comparison).
    Parameters:
      index: OpenSearch index name or pattern (required)
      minutes: Time range in minutes (default: 120)
    """
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=minutes)

        body = {
            "query": {
                "range": {"@timestamp": {
                    "gte": start.isoformat(),
                    "lte": now.isoformat(),
                }}
            },
            "aggs": {
                "by_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "10m",
                    }
                },
                "by_level": {
                    "terms": {"field": "level.keyword", "size": 10}
                },
            },
            "size": 0,
        }

        result = _os_request('POST', f'{index}/_search', body)
        if 'error' in result:
            return result

        time_buckets = []
        for bucket in result.get('aggregations', {}).get('by_time', {}).get('buckets', []):
            time_buckets.append({
                'timestamp': bucket['key_as_string'],
                'count': bucket['doc_count'],
            })

        level_buckets = []
        for bucket in result.get('aggregations', {}).get('by_level', {}).get('buckets', []):
            level_buckets.append({
                'level': bucket['key'],
                'count': bucket['doc_count'],
            })

        # Detect anomalies
        counts = [b['count'] for b in time_buckets]
        avg = sum(counts) / len(counts) if counts else 0
        anomalies = []
        for b in time_buckets:
            if b['count'] > avg * 3 and avg > 0:
                anomalies.append({
                    'timestamp': b['timestamp'],
                    'count': b['count'],
                    'avg': round(avg, 1),
                    'ratio': round(b['count'] / avg, 1),
                })

        return {
            'time_buckets': time_buckets[-12:],
            'level_distribution': level_buckets,
            'anomalies': anomalies,
            'index': index,
            'minutes': minutes,
        }
    except Exception as e:
        return {'error': str(e)}


@tool
def opensearch_get_error_summary(index: str, minutes: int = 60) -> dict:
    """Get error log statistics grouped by error type/message from OpenSearch.
    Parameters:
      index: OpenSearch index name or pattern (required)
      minutes: Time range in minutes (default: 60)
    """
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=minutes)

        body = {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"level.keyword": ["ERROR", "FATAL", "error", "fatal"]}},
                        {"range": {"@timestamp": {
                            "gte": start.isoformat(),
                            "lte": now.isoformat(),
                        }}},
                    ]
                }
            },
            "aggs": {
                "by_message": {
                    "terms": {"field": "message.keyword", "size": 20}
                },
                "by_source": {
                    "terms": {"field": "kubernetes.pod_name.keyword", "size": 20}
                },
            },
            "size": 0,
        }

        result = _os_request('POST', f'{index}/_search', body)
        if 'error' in result:
            return result

        error_types = [{
            'message': b['key'][:200],
            'count': b['doc_count'],
        } for b in result.get('aggregations', {}).get('by_message', {}).get('buckets', [])]

        error_sources = [{
            'pod': b['key'],
            'count': b['doc_count'],
        } for b in result.get('aggregations', {}).get('by_source', {}).get('buckets', [])]

        total_errors = result.get('hits', {}).get('total', {}).get('value', 0)

        return {
            'total_errors': total_errors,
            'by_message': error_types,
            'by_source': error_sources,
            'index': index,
            'minutes': minutes,
        }
    except Exception as e:
        return {'error': str(e)}
