"""CDK Trigger that initializes Aurora schema via RDS Data API.

Uses aws_cdk.triggers.TriggerFunction to run a Lambda after Aurora is ready.
Re-runs on every deployment; all statements use IF NOT EXISTS for idempotency.
"""
import textwrap

import aws_cdk as cdk
from aws_cdk import (
    aws_iam as iam,
    aws_lambda as _lambda,
    triggers,
)
from constructs import Construct

SCHEMA_STATEMENTS = [
    # -- findings (security findings from GuardDuty / Security Hub / Inspector / CloudTrail)
    "CREATE TABLE IF NOT EXISTS findings ("
    "finding_id TEXT PRIMARY KEY, "
    "title TEXT NOT NULL, "
    "description TEXT, "
    "finding_type TEXT, "
    "product TEXT, "
    "service TEXT, "
    "severity TEXT NOT NULL DEFAULT 'info', "
    "status TEXT NOT NULL DEFAULT 'active', "
    "source TEXT, "
    "resource_id TEXT, "
    "resource_arn TEXT, "
    "account_id TEXT, "
    "region TEXT, "
    "recommendation TEXT, "
    "evidence JSONB DEFAULT '{}', "
    "mitre_tactics TEXT, "
    "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), "
    "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
    "CREATE INDEX IF NOT EXISTS idx_findings_status_created ON findings(status, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
    "CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source)",
    # -- finding 상태 워크플로우: 분석가 resolve 시각(resolved_at) + 재발 재오픈 횟수(reopen_count).
    #    upsert_finding이 'resolved 이후 재관측되면 재오픈' 판정에 resolved_at을 사용한다.
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS reopen_count INTEGER NOT NULL DEFAULT 0",
    # -- reports (security report synthesis — used by Report Agent, P3)
    "CREATE TABLE IF NOT EXISTS reports (report_id TEXT PRIMARY KEY, report_type TEXT NOT NULL, title TEXT, content JSONB, summary TEXT, status TEXT DEFAULT 'processing', generation_duration_ms INTEGER, trigger_type TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
    "CREATE INDEX IF NOT EXISTS idx_reports_type_created ON reports(report_type, created_at DESC)",
]

# Lambda handler code — embedded as inline string
_HANDLER_CODE = textwrap.dedent("""\
    import os, json, boto3

    client = boto3.client("rds-data")

    STATEMENTS = json.loads(os.environ["STATEMENTS"])
    CLUSTER_ARN = os.environ["CLUSTER_ARN"]
    SECRET_ARN = os.environ["SECRET_ARN"]
    DATABASE = os.environ["DATABASE"]

    def handler(event, context):
        results = []
        for i, sql in enumerate(STATEMENTS):
            try:
                client.execute_statement(
                    resourceArn=CLUSTER_ARN,
                    secretArn=SECRET_ARN,
                    database=DATABASE,
                    sql=sql,
                )
                results.append(f"[{i}] OK")
            except Exception as e:
                results.append(f"[{i}] ERROR: {e}")
                raise
        return {"statusCode": 200, "body": "\\n".join(results)}
""")


class AuroraSchemaInit(Construct):
    def __init__(self, scope: Construct, id: str, *,
                 cluster_arn: str, secret_arn: str,
                 database: str = "agenticsoc",
                 execute_after=None):
        super().__init__(scope, id)

        import json
        self.trigger_fn = triggers.TriggerFunction(self, "SchemaInitFn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(_HANDLER_CODE),
            timeout=cdk.Duration.seconds(60),
            environment={
                "CLUSTER_ARN": cluster_arn,
                "SECRET_ARN": secret_arn,
                "DATABASE": database,
                "STATEMENTS": json.dumps(SCHEMA_STATEMENTS),
            },
            execute_after=execute_after or [],
        )

        self.trigger_fn.role.add_to_policy(iam.PolicyStatement(
            actions=["rds-data:ExecuteStatement"],
            resources=[cluster_arn],
        ))
        self.trigger_fn.role.add_to_policy(iam.PolicyStatement(
            actions=["secretsmanager:GetSecretValue"],
            resources=[secret_arn],
        ))
