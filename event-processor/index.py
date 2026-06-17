"""
EventProcessor Lambda — Normalizes AWS security findings from SNS and stores them in the findings store.

Triggered by SNS subscription (EventBridge → SNS → Lambda).
Sources: GuardDuty, Security Hub (consolidated GuardDuty/Inspector/Macie/...), Inspector2.
(CloudTrail은 finding 소스가 아니다 — 감사 로그이므로 Investigation/Log Query에서 로그로만 사용.)
"""
import json
import os
import uuid
import time
from datetime import datetime
from decimal import Decimal

import boto3

try:
    import aurora_db
    AURORA_ENABLED = bool(os.environ.get('AURORA_CLUSTER_ARN'))
except ImportError:
    AURORA_ENABLED = False

dynamodb = boto3.resource('dynamodb')
FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'findings')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')

# TTL: 90 days (security findings retained longer than operational alerts)
TTL_SECONDS = 90 * 24 * 60 * 60

# Severity Label (Security Hub / Inspector) → normalized severity
_SEVERITY_LABEL_MAP = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low',
    'INFORMATIONAL': 'info',
}


def handler(event, context):
    """Process SNS records containing EventBridge security finding events."""
    processed = 0
    for record in event.get('Records', []):
        try:
            sns_message = json.loads(record['Sns']['Message'])
            finding = normalize_event(sns_message)
            if finding:
                existing = find_existing_finding(finding)
                if existing:
                    update_finding(existing, finding)
                else:
                    save_finding(finding)
                processed += 1
                # Slack notification for critical/high severity
                if SLACK_WEBHOOK_URL and finding.get('severity') in ('critical', 'high'):
                    send_slack_alert(finding)
        except Exception as e:
            print(f"Error processing record: {e}")
            print(json.dumps(record))

    return {'statusCode': 200, 'processed': processed}


def normalize_event(raw):
    """Normalize various AWS security finding event types into a unified finding format."""
    source = raw.get('source', '')
    detail_type = raw.get('detail-type', '')
    detail = raw.get('detail', {})
    now = datetime.utcnow().isoformat() + 'Z'

    if source == 'aws.guardduty':
        return normalize_guardduty_finding(raw, detail, now)
    elif source == 'aws.securityhub':
        return normalize_securityhub_finding(raw, detail, now)
    elif source == 'aws.inspector2':
        return normalize_inspector_finding(raw, detail, now)
    else:
        # CloudTrail은 finding 소스가 아니다(감사 로그). 그 외 비보안 이벤트와 함께 드롭.
        print(f"Dropping non-finding event from source={source!r}, detail-type={detail_type!r}")
        return None


def normalize_guardduty_finding(raw, detail, now):
    """GuardDuty Finding (direct EventBridge, not via Security Hub)."""
    title = detail.get('title', '')
    description = detail.get('description', '')
    severity_num = detail.get('severity', 0)
    account_id = detail.get('accountId', raw.get('account', ''))
    region = detail.get('region', raw.get('region', ''))
    finding_type = detail.get('type', '')

    # GuardDuty numeric severity → label
    if severity_num >= 7:
        severity = 'critical'
    elif severity_num >= 4:
        severity = 'high'
    elif severity_num >= 2:
        severity = 'medium'
    else:
        severity = 'low'

    # Resource extraction
    resource = detail.get('resource', {})
    resource_type = resource.get('resourceType', '')
    resource_id = ''
    resource_arn = ''
    if resource_type == 'Instance':
        instance = resource.get('instanceDetails', {})
        resource_id = instance.get('instanceId', '')
        resource_arn = instance.get('instanceArn', '')
    elif resource_type == 'AccessKey':
        resource_id = resource.get('accessKeyDetails', {}).get('accessKeyId', '')
    elif resource_type == 'S3Bucket':
        buckets = resource.get('s3BucketDetails', [{}])
        resource_id = buckets[0].get('name', '') if buckets else ''
        resource_arn = buckets[0].get('arn', '') if buckets else ''

    return {
        'finding_id': f'gd-{detail.get("id", str(uuid.uuid4()))}',
        'title': f'GuardDuty: {title}' if title else 'GuardDuty Finding',
        'description': description[:1000],
        'finding_type': finding_type,
        'product': 'GuardDuty',
        'service': resource_type or 'GuardDuty',
        'severity': severity,
        'status': 'active',
        'source': 'aws.guardduty',
        'resource_id': resource_id,
        'resource_arn': resource_arn,
        'account_id': account_id,
        'region': region,
        'recommendation': detail.get('service', {}).get('action', {}).get('actionType', ''),
        'evidence': detail,
        'created_at': now,
        'updated_at': now,
        'ttl': int(time.time()) + TTL_SECONDS,
    }


def normalize_securityhub_finding(raw, detail, now):
    """Security Hub consolidated finding (Findings - Imported). Picks the first finding."""
    findings = detail.get('findings', [])
    if not findings:
        return None
    f = findings[0]

    severity_label = f.get('Severity', {}).get('Label', 'INFORMATIONAL')
    severity = _SEVERITY_LABEL_MAP.get(severity_label, 'info')

    resources = f.get('Resources', []) or [{}]
    resource_arn = resources[0].get('Id', '')
    resource_type = resources[0].get('Type', '')
    region = resources[0].get('Region', f.get('Region', raw.get('region', '')))
    # resource_id: last segment of ARN
    resource_id = resource_arn.split('/')[-1].split(':')[-1] if resource_arn else ''

    finding_type = (f.get('Types') or [''])[0]
    remediation = f.get('Remediation', {}).get('Recommendation', {}).get('Text', '')

    # RecordState ACTIVE/ARCHIVED → status
    record_state = f.get('RecordState', 'ACTIVE')
    status = 'active' if record_state == 'ACTIVE' else 'resolved'
    # Workflow status can override (NOTIFIED/SUPPRESSED/RESOLVED)
    workflow = f.get('Workflow', {}).get('Status', '')
    if workflow == 'RESOLVED':
        status = 'resolved'
    elif workflow == 'NOTIFIED':
        status = 'acknowledged'

    return {
        'finding_id': f'sh-{f.get("Id", str(uuid.uuid4()))}',
        'title': f.get('Title', 'Security Hub Finding'),
        'description': f.get('Description', '')[:1000],
        'finding_type': finding_type,
        'product': f.get('ProductName', 'SecurityHub'),
        'service': resource_type or 'SecurityHub',
        'severity': severity,
        'status': status,
        'source': 'aws.securityhub',
        'resource_id': resource_id,
        'resource_arn': resource_arn,
        'account_id': f.get('AwsAccountId', raw.get('account', '')),
        'region': region,
        'recommendation': remediation,
        'evidence': f,
        'created_at': now,
        'updated_at': now,
        'ttl': int(time.time()) + TTL_SECONDS,
    }


def normalize_inspector_finding(raw, detail, now):
    """Amazon Inspector2 finding (vulnerability / network reachability)."""
    severity_label = detail.get('severity', 'INFORMATIONAL')
    severity = _SEVERITY_LABEL_MAP.get(severity_label.upper(), 'info')

    resources = detail.get('resources', []) or [{}]
    resource_arn = resources[0].get('id', '')
    resource_type = resources[0].get('type', '')
    region = resources[0].get('region', raw.get('region', ''))
    resource_id = resource_arn.split('/')[-1].split(':')[-1] if resource_arn else ''

    finding_type = detail.get('type', '')
    title = detail.get('title', 'Inspector Finding')

    remediation = detail.get('remediation', {}).get('recommendation', {}).get('text', '')

    return {
        'finding_id': f'insp-{detail.get("findingArn", str(uuid.uuid4())).split("/")[-1]}',
        'title': f'Inspector: {title}',
        'description': detail.get('description', '')[:1000],
        'finding_type': finding_type,
        'product': 'Inspector',
        'service': resource_type or 'Inspector',
        'severity': severity,
        'status': 'active',
        'source': 'aws.inspector2',
        'resource_id': resource_id,
        'resource_arn': resource_arn,
        'account_id': detail.get('awsAccountId', raw.get('account', '')),
        'region': region,
        'recommendation': remediation,
        'evidence': detail,
        'created_at': now,
        'updated_at': now,
        'ttl': int(time.time()) + TTL_SECONDS,
    }


def find_existing_finding(finding):
    """Check for an existing active finding with the same finding_id."""
    if AURORA_ENABLED:
        try:
            rows = aurora_db.query(
                "SELECT finding_id, status, created_at FROM findings "
                "WHERE finding_id = :fid AND status IN ('active', 'acknowledged')",
                [{'name': 'fid', 'value': {'stringValue': finding['finding_id']}}]
            )
            return rows[0] if rows else None
        except Exception as e:
            print(f"Aurora find_existing_finding failed: {e}")

    # Fallback: DynamoDB
    table = dynamodb.Table(FINDINGS_TABLE)
    try:
        resp = table.query(
            KeyConditionExpression='finding_id = :fid',
            ExpressionAttributeValues={':fid': finding['finding_id']},
            ScanIndexForward=False,
            Limit=1
        )
        items = resp.get('Items', [])
        if items and items[0].get('status') in ('active', 'acknowledged'):
            return items[0]
    except Exception as e:
        print(f"Error querying existing finding: {e}")
    return None


def save_finding(finding):
    """Save a new finding to Aurora (with DDB fallback)."""
    if AURORA_ENABLED:
        try:
            aurora_db.upsert_finding(finding)
            return
        except Exception as e:
            print(f"Aurora save_finding failed, falling back to DDB: {e}")

    # Fallback: DynamoDB
    table = dynamodb.Table(FINDINGS_TABLE)
    item = json.loads(json.dumps(finding, default=str), parse_float=Decimal)
    try:
        table.put_item(Item=item)
    except Exception as e:
        print(f"Error saving finding: {e}")
        raise


def update_finding(existing, new_finding):
    """Update an existing finding with new state information."""
    if AURORA_ENABLED:
        try:
            aurora_db.upsert_finding(new_finding)
            return
        except Exception as e:
            print(f"Aurora update_finding failed: {e}")

    # Fallback: DynamoDB
    table = dynamodb.Table(FINDINGS_TABLE)
    try:
        update_expr = 'SET updated_at = :ua, #s = :s, description = :d, severity = :sev'
        expr_values = {
            ':ua': new_finding['updated_at'],
            ':s': new_finding['status'],
            ':d': new_finding['description'],
            ':sev': new_finding['severity'],
        }
        table.update_item(
            Key={'finding_id': existing['finding_id'], 'created_at': existing['created_at']},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues=expr_values,
        )
    except Exception as e:
        print(f"Error updating finding: {e}")


def send_slack_alert(finding):
    """Send a Slack notification for critical/high severity findings."""
    if not SLACK_WEBHOOK_URL:
        return None

    import urllib.request

    severity_emoji = {
        'critical': ':red_circle:',
        'high': ':large_orange_circle:',
        'medium': ':large_yellow_circle:',
        'low': ':large_blue_circle:',
        'info': ':white_circle:',
    }

    emoji = severity_emoji.get(finding.get('severity', 'info'), ':white_circle:')
    payload = {
        'text': f"{emoji} *{finding.get('title', 'Security Finding')}*\n"
                f"Severity: {finding.get('severity', 'unknown')} | Product: {finding.get('product', 'unknown')}\n"
                f"Resource: {finding.get('resource_id', 'N/A')} ({finding.get('account_id', '')}/{finding.get('region', '')})\n"
                f"{finding.get('description', '')[:200]}",
    }

    try:
        req = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"Slack notification failed: {e}")

    return None
