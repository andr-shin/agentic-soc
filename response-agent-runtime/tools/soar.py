"""SOAR response tools — Agentic SOC automated response (approval-gated).

SAFETY: high-risk actions (isolate/block/revoke) are NEVER executed by the agent.
The agent can only:
  - send_alert / create_task: low-risk, executed immediately via the SOAR Lambda
  - propose_remediation: creates a pending_approval task; an analyst must approve it in the
    Task Board before the high-risk action runs (executed by the authenticated REST handler).
"""
import json
import logging
import os

import boto3
from strands import tool

logger = logging.getLogger("response-agent.soar")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')
SOAR_LAMBDA_ARN = os.environ.get('SOAR_LAMBDA_ARN', '')

_lambda_client = None


def _invoke_soar(action: str, params: dict, approved: bool = False) -> dict:
    """Invoke the SOAR Lambda. The agent never passes approved=True for high-risk actions."""
    global _lambda_client
    if not SOAR_LAMBDA_ARN:
        return {'error': 'SOAR_LAMBDA_ARN not configured'}
    if _lambda_client is None:
        _lambda_client = boto3.client('lambda', region_name=REGION)
    try:
        resp = _lambda_client.invoke(
            FunctionName=SOAR_LAMBDA_ARN,
            InvocationType='RequestResponse',
            Payload=json.dumps({'action': action, 'params': params, 'approved': approved}).encode('utf-8'),
        )
        return json.loads(resp['Payload'].read())
    except Exception as e:
        logger.error(f"SOAR invoke {action} failed: {e}")
        return {'error': str(e)}


@tool
def send_alert(title: str, message: str, severity: str = "info") -> dict:
    """Send a security alert notification (SNS/Slack). Low-risk — executed immediately.
    Parameters:
      title: Short alert title
      message: Alert body / details
      severity: critical/high/medium/low/info
    """
    return _invoke_soar('send_alert', {'title': title, 'message': message, 'severity': severity})


@tool
def create_task(title: str, description: str = "", severity: str = "medium", finding_id: str = "") -> dict:
    """Create an analyst work item (task) — e.g. for manual follow-up. Low-risk — executed immediately.
    Parameters:
      title: Task title
      description: What the analyst should do
      severity: critical/high/medium/low
      finding_id: Related finding id (optional)
    """
    return _invoke_soar('create_task', {
        'title': title, 'description': description, 'severity': severity,
        'finding_id': finding_id, 'status': 'open',
    })


@tool
def propose_remediation(action: str, params: dict, impact: str, finding_id: str = "",
                        title: str = "", severity: str = "high") -> dict:
    """Propose a HIGH-RISK remediation for analyst approval. Creates a pending_approval task —
    does NOT execute the action. The analyst approves it in the Task Board to run it.
    Use this for isolate_ec2, block_sg_rule, revoke_iam_key, revoke_role_session — never execute directly.
    Parameters:
      action: One of 'isolate_ec2', 'block_sg_rule', 'revoke_iam_key', 'revoke_role_session'
      params: Action parameters, e.g. {'instance_id': 'i-...'} / {'group_id': 'sg-...', 'cidr': '0.0.0.0/0', 'port': 22}
              / {'user_name': 'bob', 'access_key_id': 'AKIA...'}  (IAM 사용자 장기 키)
              / {'role_name': 'MyRole'}  (Role 임시 세션 ASIA… 무효화)
      impact: Clear description of the blast radius / impact of this action (shown to the analyst)
      finding_id: Related finding id (optional)
      title: Task title (optional; auto-generated from action if empty)
      severity: Task severity (default: high)
    """
    valid = {'isolate_ec2', 'block_sg_rule', 'revoke_iam_key', 'revoke_role_session'}
    if action not in valid:
        return {'error': f"action must be one of {sorted(valid)}; got {action!r}"}
    task_title = title or f"[승인 대기] {action}"
    return _invoke_soar('create_task', {
        'title': task_title,
        'description': f"제안된 자동 대응: {action}\n영향: {impact}",
        'status': 'pending_approval',
        'severity': severity,
        'finding_id': finding_id,
        'proposed_action': action,
        'action_params': params,
        'impact': impact,
    })
