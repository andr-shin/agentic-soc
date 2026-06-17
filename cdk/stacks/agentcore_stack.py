import os
import json
import textwrap

import aws_cdk as cdk
from aws_cdk import (
    aws_codebuild as codebuild,
    aws_ecr as ecr,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_s3_assets as s3_assets,
    aws_ssm as ssm,
    triggers,
    CfnOutput,
    RemovalPolicy,
)
from constructs import Construct

try:
    import aws_cdk.aws_bedrock_agentcore_alpha as agentcore
except ImportError:
    pass

from config.agents import SUB_AGENTS, CHAT_AGENT

# Bedrock Application Inference Profiles (cost tracking) — empty by default.
# Agents fall back to direct model IDs (BEDROCK_MODEL_ID / global.anthropic.*).
# To enable cost-allocation tags, create profiles in this account/region with
# `aws bedrock create-inference-profile` and set the two ARNs here.
_INFERENCE_PROFILES: dict[str, str] = {}

# Per-agent extra IAM policies (write actions not covered by ReadOnlyAccess)
# SOC agents: read-heavy for investigation/hunting/logquery; response agent is
# approval-gated and delegates write actions to SOAR Lambdas via AgentCore Gateway.
_AGENT_EXTRA_POLICIES: dict[str, list[dict]] = {
    "investigation": [
        # CloudWatch Logs Insights + CloudTrail correlation + security log search
        {"actions": ["logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery",
                      "logs:GetQueryResults", "logs:DescribeLogGroups", "logs:DescribeLogStreams"], "resources": ["*"]},
        {"actions": ["cloudtrail:LookupEvents"], "resources": ["*"]},
        # GuardDuty / Security Hub finding detail retrieval
        {"actions": ["guardduty:ListDetectors", "guardduty:GetFindings", "guardduty:ListFindings",
                      "securityhub:GetFindings", "securityhub:DescribeHub"], "resources": ["*"]},
    ],
    "hunting": [
        # Cross-account read-only assume for posture hunting (Steampipe-style)
        {"actions": ["sts:AssumeRole"], "resources": ["arn:aws:iam::*:role/AgenticSOC-ReadOnly"]},
        {"actions": ["securityhub:GetFindings", "guardduty:ListFindings"], "resources": ["*"]},
    ],
    "threat_hunting": [
        # 로그 기반 헌팅: CloudWatch Logs Insights(CloudTrail/DNS/VPC Flow) + Data Sources 동적 해석
        {"actions": ["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults",
                      "logs:DescribeLogGroups", "logs:ListLogGroups",
                      "logs:GetLogEvents", "logs:FilterLogEvents"], "resources": ["*"]},
        {"actions": ["cloudtrail:LookupEvents"], "resources": ["*"]},
        {"actions": ["guardduty:ListFindings", "securityhub:GetFindings"], "resources": ["*"]},
    ],
    "logquery": [
        # CloudWatch Logs Insights over the Unified Data Store (security log sources)
        {"actions": ["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults",
                      "logs:GetLogGroupFields", "logs:DescribeLogGroups",
                      "logs:GetLogEvents", "logs:FilterLogEvents"], "resources": ["*"]},
    ],
    "report": [
        {"actions": ["rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement"], "resources": ["__AURORA_CLUSTER_ARN__"]},
        {"actions": ["secretsmanager:GetSecretValue"], "resources": ["__AURORA_SECRET_ARN__"]},
    ],
    "response": [
        # SOAR: invoke the remediation Lambda. Low-risk runs immediately; high-risk only
        # creates pending-approval tasks (the agent never passes approved=true).
        {"actions": ["lambda:InvokeFunction"], "resources": ["__SOAR_LAMBDA_ARN__"]},
    ],
}

# Lambda handler: starts CodeBuild builds in parallel and waits for all to complete
_BUILD_TRIGGER_HANDLER = textwrap.dedent("""\
    import os, json, time, boto3

    cb = boto3.client("codebuild")

    def handler(event, context):
        builds_json = os.environ["BUILDS"]
        builds = json.loads(builds_json)

        # Start all builds in parallel
        build_ids = []
        for b in builds:
            resp = cb.start_build(
                projectName=b["project"],
                sourceTypeOverride="S3",
                sourceLocationOverride=b["source_location"],
            )
            build_ids.append(resp["build"]["id"])
            print(f"Started {b['project']}: {resp['build']['id']}")

        # Poll until all complete
        while build_ids:
            time.sleep(15)
            resp = cb.batch_get_builds(ids=build_ids)
            still_running = []
            for build in resp["builds"]:
                status = build["buildStatus"]
                name = build["projectName"]
                if status == "IN_PROGRESS":
                    still_running.append(build["id"])
                elif status == "SUCCEEDED":
                    print(f"OK: {name}")
                else:
                    raise RuntimeError(f"Build failed: {name} -> {status}")
            build_ids = still_running
            if build_ids:
                print(f"Waiting... {len(build_ids)} builds remaining")

        return {"statusCode": 200, "body": "All builds succeeded"}
""")


class AgentCoreStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str,
                 project_name: str, env_name: str, infra, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.project_name = project_name
        self.env_name = env_name
        self.infra = infra

        delivery_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        self.sub_agent_runtimes = {}
        self.sub_agent_endpoints = {}
        self.ecr_repos = {}

        all_agents = {**SUB_AGENTS, "chat": CHAT_AGENT}

        # ── ECR + CodeBuild + S3 Assets per agent ─────────────────────
        build_configs = []  # for trigger Lambda env
        codebuild_projects = []  # for trigger dependency

        for agent_key, agent_cfg in all_agents.items():
            # ECR Repository
            repo = ecr.Repository(self, f"{agent_key}Ecr",
                repository_name=f"{project_name}-{env_name}-{agent_key}-runtime",
                removal_policy=RemovalPolicy.DESTROY,
                empty_on_delete=True,
                # 매 배포마다 새 :latest 이미지가 쌓여 옛 다이제스트가 무한 누적 — 최근 5개만 유지(M3).
                lifecycle_rules=[ecr.LifecycleRule(max_image_count=5)],
            )
            self.ecr_repos[agent_key] = repo

            # S3 Asset — CDK uploads source code, auto-detects changes via hash
            source_path = os.path.join(delivery_root, agent_cfg["source_dir"])
            asset = s3_assets.Asset(self, f"{agent_key}Source",
                path=source_path,
                exclude=["*.pyc", "__pycache__", ".git", "*.egg-info"],
            )

            # CodeBuild Project
            cb_project = codebuild.Project(self, f"{agent_key}Build",
                project_name=f"{project_name}-{env_name}-{agent_key}-build",
                source=codebuild.Source.s3(
                    bucket=asset.bucket,
                    path=asset.s3_object_key,
                ),
                environment=codebuild.BuildEnvironment(
                    build_image=codebuild.LinuxArmBuildImage.AMAZON_LINUX_2_STANDARD_3_0,
                    privileged=True,
                    compute_type=codebuild.ComputeType.LARGE,
                ),
                environment_variables={
                    "ECR_REPO_URI": codebuild.BuildEnvironmentVariable(
                        value=repo.repository_uri),
                    "AWS_ACCOUNT_ID": codebuild.BuildEnvironmentVariable(
                        value=self.account),
                },
                build_spec=codebuild.BuildSpec.from_object({
                    "version": "0.2",
                    "phases": {
                        "pre_build": {
                            "commands": [
                                "aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com",
                            ],
                        },
                        "build": {
                            "commands": [
                                "docker build -t $ECR_REPO_URI:latest .",
                                "docker push $ECR_REPO_URI:latest",
                            ],
                        },
                    },
                }),
                timeout=cdk.Duration.minutes(15),
            )
            repo.grant_pull_push(cb_project)
            codebuild_projects.append(cb_project)

            build_configs.append({
                "project": cb_project.project_name,
                "source_location": f"{asset.s3_bucket_name}/{asset.s3_object_key}",
            })

        # ── CDK Trigger: start all CodeBuild builds during cdk deploy ─
        trigger_fn = triggers.TriggerFunction(self, "BuildTriggerFn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(_BUILD_TRIGGER_HANDLER),
            timeout=cdk.Duration.minutes(14),
            environment={
                "BUILDS": json.dumps(build_configs),
            },
            execute_after=codebuild_projects,
        )
        # Grant CodeBuild permissions
        trigger_fn.role.add_to_policy(iam.PolicyStatement(
            actions=["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
            resources=[p.project_arn for p in codebuild_projects],
        ))
        # Grant S3 read for source override
        for agent_key, agent_cfg in all_agents.items():
            trigger_fn.role.add_to_policy(iam.PolicyStatement(
                actions=["s3:GetObject", "s3:GetBucketLocation"],
                resources=["*"],
            ))
            break  # Only need one wildcard statement

        # ── Bedrock Application Inference Profiles (cost tracking) ────
        # TODO: Inference Profile은 배포 후 CLI로 생성:
        #   aws bedrock create-inference-profile \
        #     --inference-profile-name agentic-soc-dev-sonnet \
        #     --model-source '{"copyFrom":"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-6-v1"}' \
        #     --tags '[{"key":"Project","value":"agentic-soc"},{"key":"CostCenter","value":"ai-ops"}]' \
        #     --region ap-northeast-2

        # ── Sub-Agent Runtimes ────────────────────────────────────────
        # Agents that need Aurora access (findings store / report data)
        _AURORA_CACHE_AGENTS = {"report"}

        # Runtimes depend on trigger_fn completing (images must exist in ECR)
        for agent_key, agent_cfg in SUB_AGENTS.items():
            role = iam.Role(self, f"{agent_key}Role",
                role_name=f"{project_name}-{env_name}-{agent_key}-agentcore-role",
                assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
                managed_policies=[
                    iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"),
                ],
            )
            role.add_to_policy(iam.PolicyStatement(
                actions=["ecr:GetAuthorizationToken", "ecr:BatchGetImage",
                         "ecr:GetDownloadUrlForLayer"],
                resources=["*"],
            ))
            role.add_to_policy(iam.PolicyStatement(
                actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                resources=["*"],
            ))
            # Agent-specific write permissions from CFN migration
            # Resolve Aurora ARN placeholders to actual cluster/secret ARNs
            _arn_replacements = {
                "__AURORA_CLUSTER_ARN__": infra.aurora_cluster.cluster_arn,
                "__AURORA_SECRET_ARN__": infra.aurora_cluster.secret.secret_arn,
                "__SOAR_LAMBDA_ARN__": infra.soar_fn.function_arn,
            }
            for pol in _AGENT_EXTRA_POLICIES.get(agent_key, []):
                resolved = [_arn_replacements.get(r, r) for r in pol["resources"]]
                role.add_to_policy(iam.PolicyStatement(
                    actions=pol["actions"],
                    resources=resolved,
                ))

            safe_name = f"{project_name}_{env_name}_{agent_key}".replace("-", "_")
            repo = self.ecr_repos[agent_key]

            agent_env = {**_INFERENCE_PROFILES}
            if agent_key in _AURORA_CACHE_AGENTS:
                agent_env.update({
                    "AURORA_CLUSTER_ARN": infra.aurora_cluster.cluster_arn,
                    "AURORA_SECRET_ARN": infra.aurora_cluster.secret.secret_arn,
                    "AURORA_DB_NAME": "agenticsoc",
                })
            if agent_key == "response":
                agent_env["SOAR_LAMBDA_ARN"] = infra.soar_fn.function_arn
            runtime = agentcore.Runtime(self, f"{agent_key}Runtime",
                runtime_name=safe_name,
                agent_runtime_artifact=agentcore.AgentRuntimeArtifact.from_ecr_repository(repo, "latest"),
                execution_role=role,
                description=agent_cfg["description"],
                network_configuration=agentcore.RuntimeNetworkConfiguration.using_public_network(),
                protocol_configuration=agentcore.ProtocolType.HTTP,
                environment_variables=agent_env,
            )

            endpoint = runtime.add_endpoint("default",
                description=f"Default endpoint for {agent_key}",
            )

            runtime.node.add_dependency(trigger_fn)
            self.sub_agent_runtimes[agent_key] = runtime
            self.sub_agent_endpoints[agent_key] = endpoint

            CfnOutput(self, f"{agent_key}RuntimeArn",
                value=runtime.agent_runtime_arn,
            )

        # ── Chat Agent Runtime ────────────────────────────────────────
        safe_prefix = f"{project_name}_{env_name}".replace("-", "_")

        chat_role = iam.Role(self, "chatRole",
            role_name=f"{project_name}-{env_name}-chat-agentcore-role",
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
        )
        chat_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"))
        chat_role.add_to_policy(iam.PolicyStatement(
            actions=["ecr:GetAuthorizationToken", "ecr:BatchGetImage",
                     "ecr:GetDownloadUrlForLayer"],
            resources=["*"],
        ))
        chat_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            resources=["*"],
        ))
        chat_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:InvokeAgentRuntime"],
            resources=[f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:runtime/*"],
        ))
        chat_role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query",
                     "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
            resources=[infra.conversations_table.table_arn,
                       f"{infra.conversations_table.table_arn}/index/*",
                       infra.tasks_table.table_arn],
        ))
        chat_role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:CreateEvent", "bedrock-agentcore:ListEvents",
                     "bedrock-agentcore:ListSessions", "bedrock-agentcore:RetrieveMemoryRecords"],
            resources=[f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:memory/*"],
        ))
        # Cache-direct bypass: Aurora Data API access for simple resource queries
        chat_role.add_to_policy(iam.PolicyStatement(
            actions=["rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement"],
            resources=[infra.aurora_cluster.cluster_arn],
        ))
        chat_role.add_to_policy(iam.PolicyStatement(
            actions=["secretsmanager:GetSecretValue"],
            resources=[infra.aurora_cluster.secret.secret_arn],
        ))

        chat_env = {
            "AWS_DEFAULT_REGION": self.region,
            "CONVERSATIONS_TABLE": infra.conversations_table.table_name,
            "AURORA_CLUSTER_ARN": infra.aurora_cluster.cluster_arn,
            "AURORA_SECRET_ARN": infra.aurora_cluster.secret.secret_arn,
            "AURORA_DB_NAME": "agenticsoc",
            **_INFERENCE_PROFILES,
        }
        # AgentCore Memory — context로 memory_id를 주면 chat 런타임 env에 자동 주입(재배포가 JWT
        # authorizer/env를 안전하게 보존하므로 수동 update-agent-runtime의 함정을 피한다).
        memory_id = self.node.try_get_context("memory_id")
        if memory_id:
            chat_env["MEMORY_ID"] = memory_id
        for agent_key, runtime in self.sub_agent_runtimes.items():
            upper_key = agent_key.upper()
            chat_env[f"{upper_key}_AGENT_RUNTIME_ARN"] = runtime.agent_runtime_arn
            chat_env[f"{upper_key}_AGENT_QUALIFIER"] = "default"

        chat_repo = self.ecr_repos["chat"]

        self.chat_runtime = agentcore.Runtime(self, "chatRuntime",
            runtime_name=f"{safe_prefix}_chat",
            agent_runtime_artifact=agentcore.AgentRuntimeArtifact.from_ecr_repository(chat_repo, "latest"),
            execution_role=chat_role,
            description=CHAT_AGENT["description"],
            network_configuration=agentcore.RuntimeNetworkConfiguration.using_public_network(),
            protocol_configuration=agentcore.ProtocolType.HTTP,
            environment_variables=chat_env,
            authorizer_configuration=agentcore.RuntimeAuthorizerConfiguration.using_cognito(
                infra.user_pool, [infra.pkce_client],
            ),
        )

        self.chat_runtime.node.add_dependency(trigger_fn)
        self.chat_endpoint = self.chat_runtime.add_endpoint("default",
            description="Default endpoint for chat agent",
        )

        CfnOutput(self, "ChatRuntimeArn", value=self.chat_runtime.agent_runtime_arn)
        CfnOutput(self, "ChatEndpointName", value="default")

        # ── AgentCore Gateway: SOAR low-risk tools as MCP ─────────────
        # Standard MCP exposure surface for the SOAR Lambda. Only the two LOW-RISK
        # actions (send_alert, create_task) are exposed as tools — high-risk
        # remediations are intentionally NOT exposed here (approval-gated path only).
        try:
            string_schema = {"type": agentcore.SchemaDefinitionType.STRING}
            gw_name = f"{project_name}-{env_name}-soar-gw".replace("_", "-")
            soar_gateway = agentcore.Gateway(self, "SoarGateway",
                gateway_name=gw_name,
                description="SOAR low-risk response tools (send_alert, create_task)",
                authorizer_configuration=agentcore.IamAuthorizer(),
            )
            soar_gateway.add_lambda_target("SoarTools",
                lambda_function=infra.soar_fn,
                tool_schema=agentcore.InlineToolSchema(schema=[
                    agentcore.ToolDefinition(
                        name="send_alert",
                        description="Send a security alert notification (SNS/Slack). Low-risk.",
                        input_schema=agentcore.SchemaDefinition(
                            type=agentcore.SchemaDefinitionType.OBJECT,
                            properties={
                                "title": string_schema,
                                "message": string_schema,
                                "severity": string_schema,
                            },
                            required=["title", "message"],
                        ),
                    ),
                    agentcore.ToolDefinition(
                        name="create_task",
                        description="Create an analyst work item (task). Low-risk.",
                        input_schema=agentcore.SchemaDefinition(
                            type=agentcore.SchemaDefinitionType.OBJECT,
                            properties={
                                "title": string_schema,
                                "description": string_schema,
                                "severity": string_schema,
                                "finding_id": string_schema,
                            },
                            required=["title"],
                        ),
                    ),
                ]),
            )
            CfnOutput(self, "SoarGatewayArn", value=soar_gateway.gateway_arn)
        except Exception as e:
            # Gateway is an optional MCP exposure surface; the core SOAR path
            # (Response Agent → SOAR Lambda direct invoke) works without it.
            print(f"Warning: SOAR Gateway provisioning skipped: {e}")

        for agent_key, runtime in self.sub_agent_runtimes.items():
            upper_key = agent_key.upper()
            CfnOutput(self, f"{upper_key}AgentQualifier", value="default")
        CfnOutput(self, "ChatAgentQualifier", value="default")

        # ── Store AgentCore ARNs in SSM Parameter ─────────────────────
        # SSM decouples agent ARN ownership from Lambda env vars.
        # InfraStack can be deployed independently without resetting ARNs.
        agent_config = {}
        for agent_key, runtime in self.sub_agent_runtimes.items():
            upper_key = agent_key.upper()
            agent_config[f"{upper_key}_AGENT_RUNTIME_ARN"] = runtime.agent_runtime_arn
            agent_config[f"{upper_key}_AGENT_QUALIFIER"] = "default"
        agent_config["CHAT_AGENT_RUNTIME_ARN"] = self.chat_runtime.agent_runtime_arn
        agent_config["CHAT_AGENT_QUALIFIER"] = "default"
        # REPORT is already in sub_agent_runtimes; ensure explicit keys for Lambda
        # (Lambda reads REPORT_AGENT_RUNTIME_ARN directly for report generation)

        ssm_param_name = f"/{project_name}/{env_name}/agent-config"

        ssm.StringParameter(self, "AgentConfigParam",
            parameter_name=ssm_param_name,
            string_value=json.dumps(agent_config),
            description="AgentCore Runtime ARNs and qualifiers for Host Agent Lambda",
        )

        CfnOutput(self, "AgentConfigSSMPath", value=ssm_param_name)
