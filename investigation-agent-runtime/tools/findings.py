"""Security finding detail tools — GuardDuty & Security Hub.
Retrieve full finding context to drive investigation (the Host Agent passes a finding_id;
these tools fetch the raw detail directly from the source service)."""
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
from strands import tool

logger = logging.getLogger("investigation-agent.findings")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')


@tool
def get_guardduty_finding(finding_id: str = "", detector_id: str = "", max_findings: int = 10) -> dict:
    """Retrieve GuardDuty finding detail(s) for investigation.
    If finding_id is given, fetch that specific finding's full detail. Otherwise list the most
    recent high-severity findings across the active detector.
    Parameters:
      finding_id: GuardDuty finding ID (optional — the raw id, not the 'gd-' prefixed store id)
      detector_id: GuardDuty detector ID (optional — auto-resolved from the first active detector)
      max_findings: Max findings to list when no finding_id given (default: 10)
    """
    try:
        gd = boto3.client('guardduty', region_name=REGION)

        if not detector_id:
            detectors = gd.list_detectors().get('DetectorIds', [])
            if not detectors:
                return {'error': 'No GuardDuty detector found in this region', 'findings': []}
            detector_id = detectors[0]

        # Normalize: strip 'gd-' store prefix if present
        if finding_id.startswith('gd-'):
            finding_id = finding_id[3:]

        if finding_id:
            resp = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id])
            findings = resp.get('Findings', [])
        else:
            # List recent findings sorted by severity desc
            lst = gd.list_findings(
                DetectorId=detector_id,
                FindingCriteria={'Criterion': {'severity': {'GreaterThanOrEqual': 4}}},
                SortCriteria={'AttributeName': 'updatedAt', 'OrderBy': 'DESC'},
                MaxResults=min(max_findings, 50),
            )
            ids = lst.get('FindingIds', [])
            findings = gd.get_findings(DetectorId=detector_id, FindingIds=ids).get('Findings', []) if ids else []

        simplified = []
        for f in findings:
            svc = f.get('Service', {})
            resource = f.get('Resource', {})
            simplified.append({
                'id': f.get('Id', ''),
                'type': f.get('Type', ''),
                'severity': f.get('Severity', 0),
                'title': f.get('Title', ''),
                'description': f.get('Description', ''),
                'region': f.get('Region', ''),
                'account_id': f.get('AccountId', ''),
                'resource_type': resource.get('ResourceType', ''),
                'resource': _summarize_gd_resource(resource),
                'first_seen': svc.get('EventFirstSeen', ''),
                'last_seen': svc.get('EventLastSeen', ''),
                'count': svc.get('Count', 0),
                'action': svc.get('Action', {}),
            })

        return {'detector_id': detector_id, 'findings': simplified, 'count': len(simplified)}
    except Exception as e:
        return {'error': str(e)}


def _summarize_gd_resource(resource: dict) -> dict:
    """Extract the key identifiers from a GuardDuty resource block."""
    rtype = resource.get('ResourceType', '')
    if rtype == 'Instance':
        d = resource.get('InstanceDetails', {})
        return {'instance_id': d.get('InstanceId', ''),
                'image_id': d.get('ImageId', ''),
                'network': [ni.get('PublicIp', '') for ni in d.get('NetworkInterfaces', [])]}
    if rtype == 'AccessKey':
        d = resource.get('AccessKeyDetails', {})
        return {'access_key_id': d.get('AccessKeyId', ''),
                'principal_id': d.get('PrincipalId', ''),
                'user_type': d.get('UserType', ''),
                'user_name': d.get('UserName', '')}
    if rtype == 'S3Bucket':
        buckets = resource.get('S3BucketDetails', [])
        return {'buckets': [b.get('Name', '') for b in buckets]}
    return {k: v for k, v in resource.items() if k != 'ResourceType'}


@tool
def get_securityhub_finding(finding_id: str = "", severity_label: str = "", max_findings: int = 10) -> dict:
    """Retrieve Security Hub finding detail(s) for investigation.
    If finding_id is given, fetch that specific finding. Otherwise list recent active findings,
    optionally filtered by severity_label (CRITICAL/HIGH/MEDIUM/LOW).
    Parameters:
      finding_id: Security Hub finding Id (optional — the raw ARN-style id, not the 'sh-' prefixed store id)
      severity_label: Filter by severity when listing (optional)
      max_findings: Max findings to return (default: 10)
    """
    try:
        sh = boto3.client('securityhub', region_name=REGION)

        if finding_id.startswith('sh-'):
            finding_id = finding_id[3:]

        filters = {'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]}
        if finding_id:
            filters = {'Id': [{'Value': finding_id, 'Comparison': 'EQUALS'}]}
        elif severity_label:
            filters['SeverityLabel'] = [{'Value': severity_label.upper(), 'Comparison': 'EQUALS'}]

        resp = sh.get_findings(Filters=filters, MaxResults=min(max_findings, 100))
        findings = resp.get('Findings', [])

        simplified = []
        for f in findings:
            resources = f.get('Resources', []) or [{}]
            simplified.append({
                'id': f.get('Id', ''),
                'title': f.get('Title', ''),
                'description': f.get('Description', ''),
                'severity': f.get('Severity', {}).get('Label', ''),
                'types': f.get('Types', []),
                'product': f.get('ProductName', ''),
                'account_id': f.get('AwsAccountId', ''),
                'region': resources[0].get('Region', ''),
                'resource_id': resources[0].get('Id', ''),
                'resource_type': resources[0].get('Type', ''),
                'compliance': f.get('Compliance', {}).get('Status', ''),
                'workflow_status': f.get('Workflow', {}).get('Status', ''),
                'remediation': f.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                'created_at': f.get('CreatedAt', ''),
                'updated_at': f.get('UpdatedAt', ''),
            })

        return {'findings': simplified, 'count': len(simplified)}
    except Exception as e:
        return {'error': str(e)}
