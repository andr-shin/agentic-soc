"""
SOAR Remediation Lambda — Agentic SOC automated response actions.

Single Lambda with an action dispatcher. Exposed two ways:
  1. AgentCore Gateway (MCP tool) — low-risk actions only (send_alert, create_task)
  2. Authenticated REST approval handler — high-risk actions, only with approved=true

SAFETY: high-risk actions (isolate_ec2, block_sg_rule, revoke_iam_key) REQUIRE
`approved=true` in the event. This is a second line of defense — the LLM-facing path
can only create pending-approval tasks, never pass approved=true.
"""
import json
import os
import time
import uuid
from datetime import datetime, timezone

import boto3

REGION = os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2'))
TASKS_TABLE = os.environ.get('TASKS_TABLE', 'tasks')
ALERTS_TOPIC_ARN = os.environ.get('ALERTS_TOPIC_ARN', '')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')
# SG used to isolate compromised instances (deny-all). Auto-created per-VPC if not provided.
ISOLATION_SG_ID = os.environ.get('ISOLATION_SG_ID', '')

LOW_RISK = {'send_alert', 'create_task'}
HIGH_RISK = {'isolate_ec2', 'block_sg_rule', 'revoke_iam_key', 'revoke_role_session'}

dynamodb = boto3.resource('dynamodb', region_name=REGION)


def handler(event, context=None):
    """Dispatch a SOAR action. event = {action, params, approved?}.

    Accepts either a direct dict (boto3 invoke / Gateway) or, defensively, an
    AgentCore-style payload. Returns {success, ...} or {error}.
    """
    if isinstance(event, str):
        try:
            event = json.loads(event)
        except json.JSONDecodeError:
            return {'error': 'Invalid event payload'}

    action = event.get('action', '')
    params = event.get('params', {}) or {}
    approved = bool(event.get('approved', False))

    if not action:
        return {'error': 'No action specified'}

    if action in HIGH_RISK and not approved:
        _audit(action, params, approved, {'denied': 'requires_approval'})
        return {'error': f"Action '{action}' is high-risk and requires analyst approval (approved=true).",
                'requires_approval': True}

    try:
        if action == 'send_alert':
            result = _send_alert(params)
        elif action == 'create_task':
            result = _create_task(params)
        elif action == 'isolate_ec2':
            result = _isolate_ec2(params)
        elif action == 'block_sg_rule':
            result = _block_sg_rule(params)
        elif action == 'revoke_iam_key':
            result = _revoke_iam_key(params)
        elif action == 'revoke_role_session':
            result = _revoke_role_session(params)
        else:
            return {'error': f'Unknown action: {action}'}
        _audit(action, params, approved, result)
        return result
    except Exception as e:
        err = {'error': str(e), 'action': action}
        _audit(action, params, approved, err)
        return err


def _audit(action, params, approved, result):
    """Emit a structured SOAR audit record to CloudWatch Logs (queryable via Log Query Agent).
    This is the tamper-evident action trail for every remediation attempt."""
    risk = 'high' if action in HIGH_RISK else 'low'
    record = {
        'audit': 'soar_action',
        'action': action,
        'risk': risk,
        'approved': approved,
        'params': params,
        'success': bool(result.get('success')) if isinstance(result, dict) else False,
        'result': result,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    print('SOAR_AUDIT ' + json.dumps(record, ensure_ascii=False, default=str))


# ── Low-risk actions ──────────────────────────────────────────────

def _send_alert(params):
    """Publish an alert to SNS and/or Slack."""
    title = params.get('title', 'SOC Alert')
    message = params.get('message', '')
    severity = params.get('severity', 'info')
    text = f"[{severity.upper()}] {title}\n{message}"

    delivered = []
    if ALERTS_TOPIC_ARN:
        sns = boto3.client('sns', region_name=REGION)
        sns.publish(TopicArn=ALERTS_TOPIC_ARN, Subject=title[:100], Message=text)
        delivered.append('sns')
    if SLACK_WEBHOOK_URL:
        import urllib.request
        req = urllib.request.Request(
            SLACK_WEBHOOK_URL, data=json.dumps({'text': text}).encode('utf-8'),
            headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=5)
        delivered.append('slack')

    return {'success': True, 'action': 'send_alert', 'delivered': delivered or ['none-configured']}


def _create_task(params):
    """Create a task in the tasks table (analyst work item or pending-approval remediation)."""
    table = dynamodb.Table(TASKS_TABLE)
    now = datetime.now(timezone.utc).isoformat()
    task_id = params.get('task_id') or f"task-{uuid.uuid4().hex[:12]}"
    item = {
        'task_id': task_id,
        'title': params.get('title', 'Untitled task'),
        'description': params.get('description', ''),
        'status': params.get('status', 'open'),
        'severity': params.get('severity', 'medium'),
        'finding_id': params.get('finding_id', ''),
        'proposed_action': params.get('proposed_action', ''),
        'action_params': json.dumps(params.get('action_params', {}), ensure_ascii=False),
        'impact': params.get('impact', ''),
        'created_at': now,
        'updated_at': now,
        'ttl': int(time.time()) + 90 * 24 * 60 * 60,
    }
    table.put_item(Item=item)
    return {'success': True, 'action': 'create_task', 'task_id': task_id, 'status': item['status']}


# ── High-risk actions (require approved=true) ─────────────────────

def _isolate_ec2(params):
    """Isolate an EC2 instance by replacing its security groups with a deny-all isolation SG."""
    instance_id = params.get('instance_id', '')
    if not instance_id:
        return {'error': 'instance_id required'}
    ec2 = boto3.client('ec2', region_name=REGION)

    # Resolve VPC of the instance
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = desc.get('Reservations', [])
    if not reservations:
        return {'error': f'Instance {instance_id} not found'}
    inst = reservations[0]['Instances'][0]
    vpc_id = inst.get('VpcId', '')
    original_sgs = [g['GroupId'] for g in inst.get('SecurityGroups', [])]

    isolation_sg = ISOLATION_SG_ID or _ensure_isolation_sg(ec2, vpc_id)

    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[isolation_sg])
    ec2.create_tags(Resources=[instance_id], Tags=[
        {'Key': 'SOC:Isolated', 'Value': datetime.now(timezone.utc).isoformat()},
        {'Key': 'SOC:OriginalSGs', 'Value': ','.join(original_sgs)[:255]},
    ])
    return {'success': True, 'action': 'isolate_ec2', 'instance_id': instance_id,
            'isolation_sg': isolation_sg, 'original_sgs': original_sgs}


def _ensure_isolation_sg(ec2, vpc_id):
    """Find or create a deny-all isolation SG in the given VPC (no ingress, no egress)."""
    name = 'soc-isolation-deny-all'
    existing = ec2.describe_security_groups(Filters=[
        {'Name': 'group-name', 'Values': [name]},
        {'Name': 'vpc-id', 'Values': [vpc_id]},
    ]).get('SecurityGroups', [])
    if existing:
        return existing[0]['GroupId']
    sg = ec2.create_security_group(
        GroupName=name, Description='SOC isolation - deny all traffic', VpcId=vpc_id)
    sg_id = sg['GroupId']
    # Remove the default allow-all egress rule
    try:
        ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=[
            {'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])
    except Exception:
        pass
    return sg_id


def _block_sg_rule(params):
    """Remove an inbound rule from a security group (e.g. an over-permissive 0.0.0.0/0 rule)."""
    group_id = params.get('group_id', '')
    if not group_id:
        return {'error': 'group_id required'}
    ec2 = boto3.client('ec2', region_name=REGION)

    # Either pass explicit ip_permissions, or (protocol, from_port, to_port, cidr)
    ip_permissions = params.get('ip_permissions')
    if not ip_permissions:
        cidr = params.get('cidr', '0.0.0.0/0')
        from_port = int(params.get('from_port', params.get('port', 0)))
        to_port = int(params.get('to_port', params.get('port', from_port)))
        protocol = params.get('protocol', 'tcp')
        ip_permissions = [{
            'IpProtocol': protocol, 'FromPort': from_port, 'ToPort': to_port,
            'IpRanges': [{'CidrIp': cidr}],
        }]

    ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=ip_permissions)
    return {'success': True, 'action': 'block_sg_rule', 'group_id': group_id,
            'removed': ip_permissions}


def _revoke_iam_key(params):
    """Deactivate an IAM USER's long-term access key (AKIA...), sets Status=Inactive.

    주의: 이 액션은 IAM '사용자'의 장기 키(AKIA...)에만 동작한다. Role을 AssumeRole해서 나온
    임시 세션 키(ASIA...)는 IAM에 비활성화할 '키' 객체가 없어 UpdateAccessKey가 NoSuchEntity로
    실패한다 → 그 경우는 revoke_role_session(Role 세션 무효화)을 써야 한다."""
    access_key_id = params.get('access_key_id', '')
    user_name = params.get('user_name', '')
    if not access_key_id:
        return {'error': 'access_key_id required'}

    # 임시 자격증명(ASIA)을 IAM 사용자 키 비활성화로 끄려는 시도는 구조적으로 불가 — 명확히 거부하고
    # 올바른 액션을 안내한다(예전엔 NoSuchEntity로 모호하게 실패했음).
    if access_key_id.startswith('ASIA'):
        return {'error': "access_key_id가 ASIA…(STS 임시 세션 자격증명)입니다. IAM 사용자 키가 아니므로 "
                         "revoke_iam_key로 비활성화할 수 없습니다. Role 세션을 무효화하려면 "
                         "revoke_role_session 액션(params: role_name)을 사용하세요.",
                'action': 'revoke_iam_key', 'hint': 'use_revoke_role_session', 'access_key_id': access_key_id}

    iam = boto3.client('iam')
    if not user_name:
        return {'error': 'user_name required to deactivate access key'}

    iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status='Inactive')
    return {'success': True, 'action': 'revoke_iam_key', 'access_key_id': access_key_id,
            'user_name': user_name, 'status': 'Inactive'}


def _revoke_role_session(params):
    """탈취된 IAM Role의 '활성 세션'을 전부 무효화한다(AWS 콘솔의 'Revoke active sessions'와 동일).

    구현: Role에 인라인 정책 'AWSRevokeOlderSessions'를 붙여, 지금 이전에 발급된 모든 임시
    자격증명(aws:TokenIssueTime < 현재)으로 하는 모든 요청을 Deny한다. 새로 AssumeRole하면
    그 이후 세션은 정상 동작하므로, 합법 사용자는 재인증으로 복구된다. Role 자체나 권한은 삭제하지 않는다."""
    # GuardDuty finding의 자격증명 주체는 보통 Role 이름 또는 'role/Name/sessionName' 형태.
    role_name = params.get('role_name', '') or params.get('user_name', '')
    # role_name이 'AssumedRole'의 세션 식별자(arn 일부)면 Role 이름만 떼어낸다.
    if '/' in role_name:
        role_name = role_name.split('/')[0]
    if not role_name:
        return {'error': 'role_name required to revoke role sessions'}

    iam = boto3.client('iam')
    # 발급 시각 기준 deny — 현재 시각 이전 토큰 전부 무효화.
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AWSRevokeOlderSessions",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}},
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName='AWSRevokeOlderSessions',
                        PolicyDocument=json.dumps(policy))
    return {'success': True, 'action': 'revoke_role_session', 'role_name': role_name,
            'revoked_before': now, 'note': 'Role의 기존 임시 세션 전부 무효화됨. 합법 사용자는 재-AssumeRole로 복구.'}
