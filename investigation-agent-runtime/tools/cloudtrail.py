"""CloudTrail tools — infrastructure change event collection for incident correlation."""
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
from strands import tool

logger = logging.getLogger("incident-agent.cloudtrail")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')

# Read-only prefixes to exclude (API calls that don't change anything)
_READ_PREFIXES = ('Describe', 'List', 'Get', 'Head', 'Lookup', 'Check', 'Query', 'Search', 'Scan')


@tool
def get_cloudtrail_changes(minutes: int = 1440, max_events: int = 50) -> dict:
    """Get recent AWS infrastructure write/change events from CloudTrail.
    Filters out read-only API calls to show only changes (Create, Update, Delete, Put, Modify, etc.).
    Essential for incident correlation — answers "who changed what and when".
    Parameters:
      minutes: Time range in minutes (default: 1440 = 24 hours)
      max_events: Max events to return (default: 50)
    """
    try:
        ct = boto3.client('cloudtrail', region_name=REGION)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=minutes)

        resp = ct.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=min(max_events, 50),
        )

        events = []
        for evt in resp.get('Events', []):
            name = evt.get('EventName', '')
            # Skip read-only API calls
            if any(name.startswith(p) for p in _READ_PREFIXES):
                continue
            events.append({
                'time': evt.get('EventTime', '').isoformat() if hasattr(evt.get('EventTime', ''), 'isoformat') else str(evt.get('EventTime', '')),
                'event_name': name,
                'username': evt.get('Username', 'unknown'),
                'source': evt.get('EventSource', ''),
                'resources': [
                    {'type': r.get('ResourceType', ''), 'name': r.get('ResourceName', '')}
                    for r in evt.get('Resources', [])[:3]
                ],
            })

        # Sort by time
        events.sort(key=lambda x: x['time'])

        return {
            'events': events,
            'count': len(events),
            'minutes': minutes,
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
            },
        }
    except Exception as e:
        return {'error': str(e)}
