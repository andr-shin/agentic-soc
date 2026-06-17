"""
Threat Hunting Sub-Agent — SQL-based proactive security hunting via Steampipe (579 AWS tables).
BedrockAgentCoreApp + Strands Agent (Sonnet 4.6) + Steampipe binary.
The LLM autonomously generates and executes SQL to hunt across the AWS security posture.
"""
import json
import logging
import os
import pathlib
import subprocess
import sys
import time

# Configure logging FIRST — before any heavy imports
logging.basicConfig(level=logging.INFO, force=True)
logger = logging.getLogger("hunting-agent")

REGION = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION', 'ap-northeast-2')
os.environ['AWS_DEFAULT_REGION'] = REGION

# Steampipe configuration
STEAMPIPE_CONFIG_DIR = pathlib.Path(os.environ.get("HOME", "/home/steampipe")) / ".steampipe" / "config"
steampipe_ready = False


def generate_aws_spc():
    """Generate aws.spc dynamically based on environment variables."""
    target_accounts = os.environ.get("TARGET_ACCOUNTS", "").strip()
    target_regions = os.environ.get("TARGET_REGIONS", "").strip()
    target_role_name = os.environ.get("TARGET_ROLE_NAME", "AgenticSOC-ReadOnly").strip()

    regions_block = ""
    if target_regions:
        region_list = [r.strip() for r in target_regions.split(",") if r.strip()]
        if region_list:
            regions_str = ", ".join(f'"{r}"' for r in region_list)
            regions_block = f"  regions = [{regions_str}]\n"

    if not target_accounts:
        spc_content = f'''connection "aws" {{
  plugin = "aws"
{regions_block}}}
'''
    else:
        account_list = [a.strip() for a in target_accounts.split(",") if a.strip()]
        connections = []
        connection_names = []

        local_name = "aws_local"
        connections.append(f'''connection "{local_name}" {{
  plugin = "aws"
{regions_block}}}
''')
        connection_names.append(f'"{local_name}"')

        for account_id in account_list:
            conn_name = f"aws_{account_id}"
            role_arn = f"arn:aws:iam::{account_id}:role/{target_role_name}"
            connections.append(f'''connection "{conn_name}" {{
  plugin  = "aws"
  role_arn = "{role_arn}"
{regions_block}}}
''')
            connection_names.append(f'"{conn_name}"')

        all_connections = ", ".join(connection_names)
        connections.append(f'''connection "aws" {{
  plugin      = "aws"
  type        = "aggregator"
  connections = [{all_connections}]
}}
''')
        spc_content = "\n".join(connections)

    STEAMPIPE_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    spc_path = STEAMPIPE_CONFIG_DIR / "aws.spc"
    spc_path.write_text(spc_content)
    logger.info(f"Generated aws.spc at {spc_path}")
    return spc_content


def wait_for_steampipe(max_retries=30, delay=2):
    """Wait for Steampipe PostgreSQL service to be ready."""
    global steampipe_ready
    import psycopg2

    for i in range(max_retries):
        try:
            conn = psycopg2.connect(
                host="localhost", port=9193,
                user="steampipe", password="steampipe",
                dbname="steampipe", connect_timeout=5
            )
            conn.close()
            steampipe_ready = True
            logger.info(f"Steampipe ready after {i+1} attempts")
            return True
        except Exception as e:
            logger.info(f"Waiting for Steampipe... attempt {i+1}/{max_retries}: {e}")
            time.sleep(delay)
    logger.error("Steampipe failed to start after all retries")
    return False


# ── Initialize Steampipe BEFORE heavy imports ──
# Start Steampipe service synchronously. The container's first health check may fail
# while this runs (~10s), but AgentCore Runtime retries and the container stays alive.

logger.info("Generating aws.spc configuration...")
try:
    generate_aws_spc()
except Exception as e:
    logger.error(f"Failed to generate aws.spc: {e}")

logger.info("Starting Steampipe service...")
try:
    # Use subprocess.run to capture output; steampipe service start daemonizes and returns quickly
    result = subprocess.run(
        ["steampipe", "service", "start", "--database-listen", "local", "--database-port", "9193"],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "HOME": os.environ.get("HOME", "/home/steampipe")}
    )
    logger.info(f"steampipe service start: rc={result.returncode}")
    if result.stdout.strip():
        logger.info(f"stdout: {result.stdout.strip()[:300]}")
    if result.stderr.strip():
        logger.info(f"stderr: {result.stderr.strip()[:300]}")
except subprocess.TimeoutExpired:
    logger.warning("steampipe service start timed out (30s) — may still be starting")
except Exception as e:
    logger.error(f"Failed to start Steampipe: {e}")

logger.info("Waiting for Steampipe DB...")
wait_for_steampipe()


# ── Heavy imports AFTER Steampipe is initialized ──
from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel
from tools import get_all_tools

app = BedrockAgentCoreApp()
MODEL_ID = os.environ.get('INFERENCE_PROFILE_SONNET_ARN') or os.environ.get('BEDROCK_MODEL_ID', 'global.anthropic.claude-sonnet-4-6')


SYSTEM_PROMPT = """You are a Threat Hunting specialist in an Agentic SOC. You proactively hunt for
security weaknesses and adversary footholds across the AWS security posture using SQL over 579 AWS
tables via Steampipe. ALWAYS use tools to execute queries - never guess results.

Available tools:
- execute_steampipe_sql: Execute SQL queries against AWS resources via Steampipe
- list_steampipe_tables: List available Steampipe tables (can filter by name pattern)

Table naming convention: aws_<service>_<resource>
Examples: aws_iam_user, aws_iam_role, aws_iam_policy, aws_ec2_security_group, aws_s3_bucket,
aws_kms_key, aws_ec2_instance, aws_vpc_security_group_rule, aws_guardduty_finding, aws_securityhub_finding

## 스코프 — CSPM과 중복하지 말 것 (중요)
단일 리소스의 단순 미스컨피그(MFA 미설정, 단일 SG의 0.0.0.0/0, 미암호화 버킷, CloudTrail 비활성 등)는
**AWS Security Hub CSPM / Config 표준 컨트롤이 이미 지속적으로 자동 감지**하며 그 결과는 SOC findings에
들어온다. 그런 단건 점검을 SQL로 재탕하지 마라 — 중복이고 가치가 낮다.
Threat Hunting의 가치는 **CSPM이 개별 컨트롤로는 못 잡는, 여러 신호를 결합/상관해야 보이는 복합 위험**
이다. JOIN·CTE·집계로 "조합된 공격 경로"를 찾는 데 집중하라.

## THREAT HUNTING PLAYBOOKS (상관·교차 분석 중심으로 SQL 생성):

### 1. 복합 노출 경로 (여러 약점이 한 리소스에 겹침 = 실제 위험)
- public + 과다권한 + 미암호화가 **동시에** 성립하는 리소스 (개별로는 CSPM이 잡아도 "겹침"은 못 잡음)
  예: 0.0.0.0/0 SG에 붙은 EC2가 AdministratorAccess 역할을 달고 있고, 그 인스턴스가 접근하는 S3가 public
- 인터넷 노출 리소스(SG 0.0.0.0/0 / publicly_accessible)에 연결된 과다권한 IAM 주체 추적

### 2. 권한 상승·횡적 이동 경로 (attack path)
- assume_role 신뢰 체인: 외부/광범위 주체가 assume 가능한 역할 → 그 역할이 가진 과다권한 → 도달 가능 리소스
- 과다권한 역할을 달 수 있는 노출된 컴퓨트(EC2/Lambda) — credential 탈취 시 폭발 반경

### 3. Finding ↔ 리소스 상관
- 열린 GuardDuty/Security Hub finding(aws_guardduty_finding/aws_securityhub_finding)을 위 노출/권한
  리소스와 JOIN — "이미 경보가 난 리소스가 동시에 과다 노출/권한"인 우선순위 케이스 도출

### 4. 집계·이상 패턴
- 계정/리전별 복합 약점 밀도 집계로 remediation 우선순위
- 정책 패턴 이상치(같은 권한을 가진 주체 그룹에서 벗어난 단일 주체 등)

원천 테이블은 자유롭게(579개): aws_iam_*, aws_ec2_*, aws_vpc_security_group_rule, aws_s3_bucket,
aws_rds_db_instance, aws_guardduty_finding, aws_securityhub_finding 등. 단순 단건 점검 컬럼도 JOIN의
재료로는 쓰되, 결과는 항상 "조합된 위험"으로 제시하라.

Key behaviors:
- First use list_steampipe_tables to discover table names if unsure.
- Only SELECT and WITH (CTE) queries are allowed. JOIN/CTE를 적극 활용해 상관 분석하라.
- For large result sets, use LIMIT to avoid timeouts.
- 우선순위: 겹친 약점 수가 많을수록 critical (public + privileged + unencrypted = critical).
- 단건 미스컨피그만 나왔다면 "이건 CSPM이 이미 감지하는 영역"임을 명시하고 상관 관점을 덧붙여라.
- ALL output MUST be in Korean (한글); keep technical terms (table/column names, ARNs) in English.
- Present results clearly with tables or bullet points, organized by severity.
- For each hunt finding, suggest the remediation but note that actual changes go through the Response Agent with analyst approval.
- Keep responses concise and focused."""


def _extract_text(result):
    """Extract text content from Strands Agent result."""
    if not result or not result.message:
        return 'No response generated.'
    texts = []
    for block in result.message.get('content', []):
        if isinstance(block, dict):
            if block.get('type') == 'text':
                texts.append(block.get('text', ''))
            elif 'text' in block:
                texts.append(block['text'])
    return '\n'.join(texts) or 'No response generated.'


def _count_tool_uses(agent):
    """Count tool uses in agent message history."""
    count = 0
    for m in agent.messages:
        if m.get('role') == 'assistant' and isinstance(m.get('content'), list):
            for block in m['content']:
                if isinstance(block, dict):
                    if block.get('type') == 'tool_use' or 'toolUse' in block:
                        count += 1
    return count


def _extract_usage(result):
    """Extract token usage from Strands Agent result."""
    try:
        if not result:
            return {}
        metrics = getattr(result, 'metrics', None)
        if metrics:
            usage = metrics if isinstance(metrics, dict) else getattr(metrics, 'to_dict', lambda: {})()
            if 'inputTokens' in usage or 'outputTokens' in usage:
                return usage
            accumulated = getattr(metrics, 'accumulated', None)
            if accumulated:
                return accumulated if isinstance(accumulated, dict) else vars(accumulated)
        usage_attr = getattr(result, 'usage', None)
        if usage_attr:
            return usage_attr if isinstance(usage_attr, dict) else vars(usage_attr)
        if result.message:
            msg_usage = result.message.get('usage', {})
            if msg_usage:
                return msg_usage
    except Exception as e:
        logger.debug(f"Failed to extract usage: {e}")
    return {}


@app.entrypoint
async def handle_request(payload, context=None):
    # Warm-up ping
    if payload.get('type') == 'ping':
        return {"event": "pong", "steampipe_ready": steampipe_ready}

    # Legacy compatibility: direct SQL invocation (from old FastAPI pattern)
    if 'input' in payload:
        from tools.steampipe_tools import _execute_query, _list_tables
        action = payload['input'].get('action', 'query')
        if action == 'query':
            sql = payload['input'].get('sql', '')
            timeout = payload['input'].get('timeout', 30)
            result = _execute_query(sql, timeout)
            # Truncate if too large
            result_str = json.dumps(result)
            if len(result_str) > 50000:
                result["rows"] = result["rows"][:50]
                result["truncated"] = True
                result["message"] = f"Results truncated to 50 rows (original: {result['row_count']})"
            return {"output": result}
        elif action == 'list_tables':
            schema = payload['input'].get('schema', 'aws')
            return {"output": _list_tables(schema)}
        elif action == 'health':
            return {"output": _execute_query("SELECT 1 as health_check")}
        return {"error": f"Unknown action: {action}"}

    message = payload.get('message', '')
    if not message:
        return {"error": "No message provided"}

    if not steampipe_ready:
        return {"error": "Steampipe service not ready"}

    logger.info(f"Hunting Agent request: {message[:100]}...")

    try:
        model = BedrockModel(model_id=MODEL_ID, max_tokens=8192, cache_prompt="default", cache_tools="default")
        agent = Agent(model=model, system_prompt=SYSTEM_PROMPT, tools=get_all_tools())
        result = agent(message)
        return {
            "result": _extract_text(result),
            "tool_count": _count_tool_uses(agent),
            "usage": _extract_usage(result),
        }
    except Exception as e:
        logger.error(f"Hunting Agent error: {e}")
        return {"error": str(e)}


if __name__ == "__main__":
    app.run()
