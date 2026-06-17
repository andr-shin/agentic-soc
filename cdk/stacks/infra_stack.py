import os

import aws_cdk as cdk
from aws_cdk import (
    Aws,
    CfnOutput,
    RemovalPolicy,
    aws_apigatewayv2 as apigwv2,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_cognito as cognito,
    aws_dynamodb as dynamodb,
    aws_ec2 as ec2,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_rds as rds,
    aws_s3 as s3,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subs,
)
from aws_cdk.aws_apigatewayv2_authorizers import HttpJwtAuthorizer
from aws_cdk.aws_apigatewayv2_integrations import HttpLambdaIntegration
from constructs import Construct

from cdk_constructs.aurora_init import AuroraSchemaInit


class InfraStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str,
                 project_name: str, env_name: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.project_name = project_name
        self.env_name = env_name

        delivery_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        # -------------------------------------------------------
        # Cognito
        # -------------------------------------------------------
        # Pre Sign-up trigger: auto-verify email for admin-created users
        auto_verify_fn = _lambda.Function(self, "AutoVerifyFn",
            function_name=f"{project_name}-{env_name}-auto-verify-email",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(
                "def handler(event, context):\n"
                "    event['response']['autoConfirmUser'] = True\n"
                "    event['response']['autoVerifyEmail'] = True\n"
                "    return event\n"
            ),
        )

        self.user_pool = cognito.UserPool(
            self, "UserPool",
            user_pool_name=f"{project_name}-{env_name}-user-pool",
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            self_sign_up_enabled=False,
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_uppercase=True,
                require_lowercase=True,
                require_digits=True,
                require_symbols=False,
            ),
            lambda_triggers=cognito.UserPoolTriggers(
                pre_sign_up=auto_verify_fn,
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.user_pool_client = self.user_pool.add_client(
            "WebClient",
            user_pool_client_name="WebClient",
            auth_flows=cognito.AuthFlow(user_srp=True),
            generate_secret=False,
        )

        self.pkce_client = self.user_pool.add_client(
            "WebPKCEClient",
            user_pool_client_name="WebPKCEClient",
            auth_flows=cognito.AuthFlow(user_srp=True),
            generate_secret=False,
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[
                    cognito.OAuthScope.OPENID,
                    cognito.OAuthScope.PROFILE,
                ],
                callback_urls=["http://localhost:5173/callback"],
                logout_urls=["http://localhost:5173"],
            ),
        )

        self.user_pool_domain = self.user_pool.add_domain(
            "UserPoolDomain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=f"{project_name}-{env_name}-{Aws.ACCOUNT_ID}",
            ),
        )

        # -------------------------------------------------------
        # DynamoDB Tables
        # -------------------------------------------------------
        self.agent_state_table = dynamodb.Table(
            self, "AgentStateTable",
            table_name=f"{project_name}-{env_name}-agent-state",
            partition_key=dynamodb.Attribute(name="agent_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="timestamp", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl",
        )

        self.findings_table = dynamodb.Table(
            self, "FindingsTable",
            table_name=f"{project_name}-{env_name}-findings",
            partition_key=dynamodb.Attribute(name="finding_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="created_at", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )
        self.findings_table.add_global_secondary_index(
            index_name="status-index",
            partition_key=dynamodb.Attribute(name="status", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="created_at", type=dynamodb.AttributeType.STRING),
        )

        self.conversations_table = dynamodb.Table(
            self, "ConversationsTable",
            table_name=f"{project_name}-{env_name}-conversations",
            partition_key=dynamodb.Attribute(name="user_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="conversation_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl",
        )
        self.conversations_table.add_global_secondary_index(
            index_name="updated-at-index",
            partition_key=dynamodb.Attribute(name="user_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="updated_at", type=dynamodb.AttributeType.STRING),
        )

        self.tasks_table = dynamodb.Table(
            self, "TasksTable",
            table_name=f"{project_name}-{env_name}-tasks",
            partition_key=dynamodb.Attribute(name="task_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl",
        )
        self.tasks_table.add_global_secondary_index(
            index_name="status-index",
            partition_key=dynamodb.Attribute(name="status", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="created_at", type=dynamodb.AttributeType.STRING),
        )

        # Log Explorer 저장 쿼리 (사용자별) — user_id + query_id
        self.log_queries_table = dynamodb.Table(
            self, "LogQueriesTable",
            table_name=f"{project_name}-{env_name}-log-queries",
            partition_key=dynamodb.Attribute(name="user_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="query_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.reports_table = dynamodb.Table(
            self, "ReportsTable",
            table_name=f"{project_name}-{env_name}-reports",
            partition_key=dynamodb.Attribute(name="report_type", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="generated_at", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl",
        )

        # -------------------------------------------------------
        # Aurora VPC
        # -------------------------------------------------------
        self.aurora_vpc = ec2.Vpc(self, "AuroraVPC",
            ip_addresses=ec2.IpAddresses.cidr("10.100.0.0/16"),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="aurora",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True,
        )

        self.aurora_sg = ec2.SecurityGroup(self, "AuroraSG",
            vpc=self.aurora_vpc,
            description="Aurora PostgreSQL access",
            allow_all_outbound=False,
        )
        self.aurora_sg.add_ingress_rule(
            ec2.Peer.ipv4("10.100.0.0/16"),
            ec2.Port.tcp(5432),
            "PostgreSQL from VPC",
        )

        # -------------------------------------------------------
        # Aurora Serverless v2
        # -------------------------------------------------------
        self.aurora_cluster = rds.DatabaseCluster(self, "AuroraCluster",
            engine=rds.DatabaseClusterEngine.aurora_postgres(
                version=rds.AuroraPostgresEngineVersion.VER_15_10,
            ),
            default_database_name="agenticsoc",
            serverless_v2_min_capacity=0.5,
            serverless_v2_max_capacity=4,
            writer=rds.ClusterInstance.serverless_v2("Writer"),
            vpc=self.aurora_vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
            security_groups=[self.aurora_sg],
            storage_encrypted=True,
            backup=rds.BackupProps(retention=cdk.Duration.days(7)),
            enable_data_api=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # -------------------------------------------------------
        # Aurora Schema Init (Custom Resource)
        # -------------------------------------------------------
        AuroraSchemaInit(self, "AuroraSchema",
            cluster_arn=self.aurora_cluster.cluster_arn,
            secret_arn=self.aurora_cluster.secret.secret_arn,
            execute_after=[self.aurora_cluster],
        )

        # -------------------------------------------------------
        # Lambda – Host Agent
        # -------------------------------------------------------
        # SSM path where AgentCoreStack stores agent ARNs (convention-based).
        # Lambda reads this at cold start to discover agent runtimes.
        self.agent_config_ssm_path = f"/{project_name}/{env_name}/agent-config"

        self.host_agent_fn_env = {
            "AURORA_CLUSTER_ARN": self.aurora_cluster.cluster_arn,
            "AURORA_SECRET_ARN": self.aurora_cluster.secret.secret_arn,
            "AURORA_DB_NAME": "agenticsoc",
            "CONVERSATIONS_TABLE": self.conversations_table.table_name,
            "FINDINGS_TABLE": self.findings_table.table_name,
            "REPORTS_TABLE": self.reports_table.table_name,
            "AGENT_STATE_TABLE": self.agent_state_table.table_name,
            "TASKS_TABLE": self.tasks_table.table_name,
            "LOG_QUERIES_TABLE": self.log_queries_table.table_name,
            "BEDROCK_MODEL_ID": self.node.try_get_context("model_id") or "us.anthropic.claude-sonnet-4-6-v1",
            "AGENT_CONFIG_SSM_PATH": self.agent_config_ssm_path,
        }
        # AgentCore Memory (장기기억) — scripts/create-memory.sh로 생성한 MEMORY_ID를 context로 주입하면
        # 재배포 시 host-agent Lambda + chat 런타임 env에 자동 반영(수동 update-agent-runtime 불필요).
        memory_id = self.node.try_get_context("memory_id")
        if memory_id:
            self.host_agent_fn_env["MEMORY_ID"] = memory_id
        # 최신 boto3/botocore Layer — Python 3.11 런타임 기본 boto3는 CloudWatch Logs
        # Data Sources API(list_aggregate_log_group_summaries, groupBy=DATA_SOURCE_NAME_AND_TYPE)를
        # 지원하지 않으므로, 별도 publish한 boto3 1.43.24+ Layer를 부착한다.
        # (Layer는 scripts/build-boto3-layer.sh 로 publish — ARN은 context로 주입, 없으면 미부착)
        boto3_layer_arn = self.node.try_get_context("boto3_layer_arn")
        host_agent_layers = []
        if boto3_layer_arn:
            host_agent_layers.append(
                _lambda.LayerVersion.from_layer_version_arn(self, "Boto3LatestLayer", boto3_layer_arn))

        self.host_agent_fn = _lambda.Function(self, "HostAgentFunction",
            function_name=f"{project_name}-{env_name}-host-agent",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=_lambda.Code.from_asset(os.path.join(delivery_root, "lambda")),
            timeout=cdk.Duration.seconds(900),
            memory_size=1024,
            environment=self.host_agent_fn_env,
            layers=host_agent_layers or None,
            log_retention=logs.RetentionDays.THREE_MONTHS,
        )
        # SOC 읽기 + 스코프된 SOAR에 ReadOnlyAccess는 과도하나, 아래 명시 정책으로 좁히기 전까지의
        # 광범위 읽기는 host-agent가 다양한 보안 서비스를 조회해야 해 잠정 유지. (감사 H1 — 후속 스코핑 대상)
        self.host_agent_fn.role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"))
        self.aurora_cluster.secret.grant_read(self.host_agent_fn)
        self.aurora_cluster.grant_data_api_access(self.host_agent_fn)
        self.conversations_table.grant_read_write_data(self.host_agent_fn)
        self.findings_table.grant_read_write_data(self.host_agent_fn)
        self.reports_table.grant_read_write_data(self.host_agent_fn)
        self.agent_state_table.grant_read_write_data(self.host_agent_fn)
        self.tasks_table.grant_read_write_data(self.host_agent_fn)
        self.log_queries_table.grant_read_write_data(self.host_agent_fn)
        self.host_agent_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            resources=["*"],
        ))
        self.host_agent_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:InvokeAgentRuntime"],
            resources=[f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:runtime/*"],
        ))
        self.host_agent_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:ListEvents", "bedrock-agentcore:ListSessions"],
            resources=[f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:memory/*"],
        ))
        self.host_agent_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["ssm:GetParameter"],
            resources=[f"arn:aws:ssm:{self.region}:{self.account}:parameter/{project_name}/{env_name}/agent-config"],
        ))
        # Aurora findings/reports store access via Data API
        self.host_agent_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement"],
            resources=[self.aurora_cluster.cluster_arn],
        ))
        self.host_agent_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["secretsmanager:GetSecretValue"],
            resources=[self.aurora_cluster.secret.secret_arn],
        ))
        # Log Explorer — CloudWatch Logs Insights direct execution (/api/logs/query)
        self.host_agent_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults",
                     "logs:GetLogGroupFields", "logs:DescribeLogGroups"],
            resources=["*"],
        ))

        # -------------------------------------------------------
        # Lambda – Event Processor
        # -------------------------------------------------------
        self.event_processor_fn = _lambda.Function(self, "EventProcessorFunction",
            function_name=f"{project_name}-{env_name}-event-processor",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(os.path.join(delivery_root, "event-processor")),
            timeout=cdk.Duration.seconds(30),
            memory_size=256,
            environment={
                "AURORA_CLUSTER_ARN": self.aurora_cluster.cluster_arn,
                "AURORA_SECRET_ARN": self.aurora_cluster.secret.secret_arn,
                "AURORA_DB_NAME": "agenticsoc",
                "FINDINGS_TABLE": self.findings_table.table_name,
            },
            log_retention=logs.RetentionDays.THREE_MONTHS,
        )
        self.aurora_cluster.secret.grant_read(self.event_processor_fn)
        self.aurora_cluster.grant_data_api_access(self.event_processor_fn)
        self.findings_table.grant_read_write_data(self.event_processor_fn)

        # -------------------------------------------------------
        # EventBridge Schedules
        # -------------------------------------------------------
        # (Operational ETL/health/report schedules removed in SOC migration.
        #  Security findings arrive event-driven via GuardDuty/SecurityHub/Inspector.
        #  Scheduled security report generation will be added in P3.)

        # -------------------------------------------------------
        # HTTP API Gateway with JWT Auth
        # -------------------------------------------------------
        jwt_issuer = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool.user_pool_id}"

        authorizer = HttpJwtAuthorizer("CognitoAuth", jwt_issuer,
            jwt_audience=[
                self.user_pool_client.user_pool_client_id,
                self.pkce_client.user_pool_client_id,
            ],
        )

        # 프로덕션 프론트는 CloudFront를 통해 /api로 same-origin 호출하므로 CORS preflight가 발생하지
        # 않는다 — 와일드카드 origin은 JWT 인증 API에 과도. 로컬 개발(vite 5173/5174) origin만 허용하고,
        # 별도 도메인이 필요하면 context `cors_extra_origin`으로 주입. (JWT 인증 API에 "*" 금지)
        cors_origins = ["http://localhost:5173", "http://localhost:5174"]
        extra_origin = self.node.try_get_context("cors_extra_origin")
        if extra_origin:
            cors_origins.append(extra_origin)
        self.api = apigwv2.HttpApi(self, "ApiGateway",
            api_name=f"{project_name}-{env_name}-api",
            cors_preflight=apigwv2.CorsPreflightOptions(
                allow_origins=cors_origins,
                allow_methods=[apigwv2.CorsHttpMethod.ANY],
                allow_headers=["authorization", "content-type"],
                allow_credentials=False,
            ),
        )

        integration = HttpLambdaIntegration("HostAgentIntegration", self.host_agent_fn)

        api_routes = [
            ("GET", "/api/health"),
            ("GET", "/api/config"),
            ("GET", "/api/readiness"),
            # Findings
            ("GET", "/api/findings"),
            ("POST", "/api/findings/acknowledge"),
            ("POST", "/api/findings/resolve"),
            ("POST", "/api/findings/reopen"),
            # Log Explorer (CloudWatch Unified Data Store)
            ("GET", "/api/logs/sources"),
            ("POST", "/api/logs/query"),
            ("POST", "/api/logs/generate"),
            # Log Explorer 저장 쿼리 (사용자별)
            ("GET", "/api/logs/queries"),
            ("POST", "/api/logs/queries"),
            ("DELETE", "/api/logs/queries/{queryId}"),
            # Task Board (SOAR approval workflow)
            ("GET", "/api/tasks"),
            ("POST", "/api/tasks/{taskId}/approve"),
            ("POST", "/api/tasks/{taskId}/reject"),
            ("POST", "/api/tasks/{taskId}/complete"),
            # Conversations (analyst investigation threads)
            ("GET", "/api/conversations"),
            ("GET", "/api/conversations/{conversationId}"),
            ("DELETE", "/api/conversations/{conversationId}"),
            # Security reports (P3 — read-only; 생성 트리거 핸들러 없음)
            ("GET", "/api/reports"),
            ("GET", "/api/reports/summary"),
            ("GET", "/api/reports/latest"),
        ]

        for method_str, path in api_routes:
            http_method = getattr(apigwv2.HttpMethod, method_str)
            self.api.add_routes(
                path=path,
                methods=[http_method],
                integration=integration,
                authorizer=authorizer,
            )

        # -------------------------------------------------------
        # CfnOutputs
        # -------------------------------------------------------
        CfnOutput(self, "CognitoUserPoolId", value=self.user_pool.user_pool_id)
        CfnOutput(self, "CognitoClientId", value=self.pkce_client.user_pool_client_id)
        CfnOutput(self, "CognitoDomain",
                  value=f"{self.user_pool_domain.domain_name}.auth.{Aws.REGION}.amazoncognito.com")
        CfnOutput(self, "AuroraClusterArn", value=self.aurora_cluster.cluster_arn)
        CfnOutput(self, "AuroraSecretArn", value=self.aurora_cluster.secret.secret_arn)
        CfnOutput(self, "AuroraEndpoint", value=self.aurora_cluster.cluster_endpoint.hostname)
        CfnOutput(self, "ApiEndpoint", value=self.api.api_endpoint)

        # -------------------------------------------------------
        # S3 Frontend Bucket
        # -------------------------------------------------------
        self.frontend_bucket = s3.Bucket(self, "FrontendBucket",
            bucket_name=f"{project_name}-{env_name}-frontend-{cdk.Aws.ACCOUNT_ID}",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        CfnOutput(self, "FrontendBucketName", value=self.frontend_bucket.bucket_name)

        # -------------------------------------------------------
        # CloudFront Distribution
        # -------------------------------------------------------
        enable_cf = self.node.try_get_context("enable_cloudfront") != "false"

        if enable_cf:
            self.distribution = cloudfront.Distribution(self, "Distribution",
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origins.S3BucketOrigin.with_origin_access_control(self.frontend_bucket),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                ),
                additional_behaviors={
                    "/api/*": cloudfront.BehaviorOptions(
                        origin=origins.HttpOrigin(
                            f"{self.api.api_id}.execute-api.{self.region}.amazonaws.com",
                        ),
                        allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                        cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                        origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                        viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    ),
                },
                default_root_object="index.html",
                error_responses=[
                    cloudfront.ErrorResponse(
                        http_status=403, response_page_path="/index.html",
                        response_http_status=200, ttl=cdk.Duration.seconds(0),
                    ),
                    cloudfront.ErrorResponse(
                        http_status=404, response_page_path="/index.html",
                        response_http_status=200, ttl=cdk.Duration.seconds(0),
                    ),
                ],
                price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            )
            CfnOutput(self, "CloudFrontDomain", value=self.distribution.distribution_domain_name)
            CfnOutput(self, "CloudFrontDistributionId", value=self.distribution.distribution_id)

            # Add CloudFront domain to Cognito PKCE client callback/logout URLs
            cf_origin = cdk.Fn.join("", ["https://", self.distribution.distribution_domain_name])
            cfn_pkce_client = self.pkce_client.node.default_child
            cfn_pkce_client.add_property_override("CallbackURLs", [
                "http://localhost:5173/callback",
                cdk.Fn.join("", [cf_origin, "/callback"]),
            ])
            cfn_pkce_client.add_property_override("LogoutURLs", [
                "http://localhost:5173",
                cf_origin,
            ])
        else:
            self.distribution = None

        # Frontend upload is handled by deploy.sh (aws s3 sync + CloudFront invalidation)
        # to avoid ordering issues: InfraStack must deploy before frontend build.

        # -------------------------------------------------------
        # SNS Alerts Topic
        # -------------------------------------------------------
        self.alerts_topic = sns.Topic(self, "AlertsSNSTopic",
            topic_name=f"{project_name}-{env_name}-alerts",
        )
        self.alerts_topic.add_subscription(
            sns_subs.LambdaSubscription(self.event_processor_fn)
        )

        # -------------------------------------------------------
        # Lambda – SOAR Remediation (automated response actions)
        # -------------------------------------------------------
        # SAFETY: high-risk actions require approved=true (enforced in the Lambda).
        # The LLM path can only create pending-approval tasks; execution happens via the
        # authenticated /api/tasks/{id}/approve handler.
        self.soar_fn = _lambda.Function(self, "SoarFunction",
            function_name=f"{project_name}-{env_name}-soar",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(os.path.join(delivery_root, "soar-lambdas")),
            timeout=cdk.Duration.seconds(60),
            memory_size=256,
            environment={
                "TASKS_TABLE": self.tasks_table.table_name,
                "ALERTS_TOPIC_ARN": self.alerts_topic.topic_arn,
            },
            log_retention=logs.RetentionDays.THREE_MONTHS,
        )
        self.tasks_table.grant_read_write_data(self.soar_fn)
        self.alerts_topic.grant_publish(self.soar_fn)
        # Remediation permissions (real actions).
        # ec2:* 격리/SG 차단은 리전 한정 조건으로, iam:UpdateAccessKey는 별도 statement로 분리해
        # blast radius를 제한(감사 H2). 조치 자체는 승인 게이트(approved=true) 뒤에서만 실행됨.
        self.soar_fn.add_to_role_policy(iam.PolicyStatement(
            actions=[
                "ec2:DescribeInstances", "ec2:ModifyInstanceAttribute", "ec2:CreateTags",
                "ec2:DescribeSecurityGroups", "ec2:CreateSecurityGroup",
                "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
            ],
            resources=["*"],
            conditions={"StringEquals": {"aws:RequestedRegion": Aws.REGION}},
        ))
        self.soar_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["iam:UpdateAccessKey"],
            resources=[f"arn:aws:iam::{Aws.ACCOUNT_ID}:user/*"],
        ))
        # revoke_role_session: 탈취된 Role의 임시 세션 무효화(AWSRevokeOlderSessions 인라인 정책 부착).
        # role/* 한정 — 키 비활성화(user/*)와 분리된 별도 statement.
        self.soar_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["iam:PutRolePolicy"],
            resources=[f"arn:aws:iam::{Aws.ACCOUNT_ID}:role/*"],
        ))
        # Host Agent (REST) invokes SOAR for approved remediations + reads/writes tasks
        self.host_agent_fn.add_environment("SOAR_LAMBDA_ARN", self.soar_fn.function_arn)
        self.soar_fn.grant_invoke(self.host_agent_fn)

        # -------------------------------------------------------
        # EventBridge Rules
        # -------------------------------------------------------
        rules_config = [
            ("GuardDuty", {"source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"]}),
            ("SecurityHub", {"source": ["aws.securityhub"], "detail-type": ["Security Hub Findings - Imported"]}),
            ("Inspector", {"source": ["aws.inspector2"], "detail-type": ["Inspector2 Finding"]}),
        ]

        for rule_name, pattern in rules_config:
            event_pattern_kwargs = {}
            if "source" in pattern:
                event_pattern_kwargs["source"] = pattern["source"]
            if "detail-type" in pattern:
                event_pattern_kwargs["detail_type"] = pattern["detail-type"]

            rule = events.Rule(self, rule_name,
                rule_name=f"{project_name}-{env_name}-{rule_name}",
                event_pattern=events.EventPattern(**event_pattern_kwargs),
            )
            rule.add_target(events_targets.SnsTopic(self.alerts_topic))
        # 참고: CloudTrail은 finding 소스가 아니다(탐지 서비스가 아닌 감사 로그). 과거엔 IAM/EC2
        # 민감 API 호출을 pseudo-finding으로 합성했으나, 의미 혼란을 줘 제거했다. CloudTrail은
        # Investigation / Log Query 에이전트에서 '로그'로만 활용한다.
