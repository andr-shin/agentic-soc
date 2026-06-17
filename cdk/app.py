#!/usr/bin/env python3
import os
import aws_cdk as cdk
from stacks.infra_stack import InfraStack
from stacks.agentcore_stack import AgentCoreStack

app = cdk.App()

env_name = app.node.try_get_context("env") or "dev"
project_name = app.node.try_get_context("project") or "agentic-soc"
region = app.node.try_get_context("region") or "ap-northeast-2"

env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=region,
)

infra = InfraStack(app, f"{project_name}-{env_name}-infra",
    env=env,
    project_name=project_name,
    env_name=env_name,
)

agentcore = AgentCoreStack(app, f"{project_name}-{env_name}-agentcore",
    env=env,
    project_name=project_name,
    env_name=env_name,
    infra=infra,
)
agentcore.add_dependency(infra)

# ── Cost allocation tags ──────────────────────────────────────
cdk.Tags.of(app).add("Project", project_name)
cdk.Tags.of(app).add("Environment", env_name)
cdk.Tags.of(app).add("Component", "agentic-soc")

app.synth()
