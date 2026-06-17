"""
SOC Host Agent — Orchestrator with Sub-Agent Architecture (Agentic SOC).
Browser connects directly via JWT auth. Routes security queries/findings to specialized Sub-Agents
(Investigation / Threat Hunting / Log Query / Response / Report).
v10: 2-Tier Classification — Haiku pre-router for fast path (single agent) + full Sonnet orchestration for complex queries.
"""
import asyncio
import base64
import concurrent.futures
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone

import boto3
from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel
from tools import get_all_tools
from tools.cache_direct import try_cache_direct
from tools.classifier import classify_query, _get_active_categories, CLASSIFIER_MODEL_ID
from tools.direct_invoke import invoke_directly, get_display_name

# Inference Profile ARNs (preferred) → fallback to direct model IDs
SONNET_MODEL = os.environ.get('INFERENCE_PROFILE_SONNET_ARN') or os.environ.get('BEDROCK_MODEL_ID', 'global.anthropic.claude-sonnet-4-6')
HAIKU_MODEL = os.environ.get('INFERENCE_PROFILE_HAIKU_ARN') or 'global.anthropic.claude-haiku-4-5-20251001-v1:0'

# Lazy singleton for bedrock-runtime synthesis client (thread-safe)
_synth_client = None
_synth_client_lock = threading.Lock()


def _get_synth_client():
    global _synth_client
    if _synth_client is None:
        with _synth_client_lock:
            if _synth_client is None:
                _synth_client = boto3.client('bedrock-runtime', region_name=REGION)
    return _synth_client

# AgentCore Memory integration (optional — graceful fallback if not available)
try:
    from bedrock_agentcore.memory.integrations.strands.config import AgentCoreMemoryConfig
    from bedrock_agentcore.memory.integrations.strands.session_manager import AgentCoreMemorySessionManager
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("host-agent")

# Ensure region is set for boto3 (AgentCore may not set AWS_DEFAULT_REGION)
REGION = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION', 'ap-northeast-2')
os.environ['AWS_DEFAULT_REGION'] = REGION

app = BedrockAgentCoreApp()

# DynamoDB for conversation metadata persistence
dynamodb = boto3.resource('dynamodb', region_name=REGION)
CONVERSATIONS_TABLE = os.environ.get('CONVERSATIONS_TABLE', '')

# AgentCore Memory
MEMORY_ID = os.environ.get('MEMORY_ID', '')
agentcore_client = boto3.client('bedrock-agentcore', region_name=REGION) if MEMORY_ID else None

# ============================================================
# Dynamic System Prompt — only active agents are included
# ============================================================

_AGENT_DESCRIPTIONS = {
    'INVESTIGATION_AGENT_RUNTIME_ARN': {
        'name': 'Investigation Agent', 'tool': 'invoke_investigation_agent',
        'desc': '보안 인시던트 심층 조사: GuardDuty/Security Hub finding 파싱, CloudWatch Logs 검색/이상 탐지, CloudTrail 변경 이력 상관 분석, VPC Flow 네트워크 패턴, 타임라인 재구성, MITRE ATT&CK 매핑, 근본 원인 추정, 대응 가이드',
        'keywords': 'finding, 침해, 근본 원인, 상관 분석, CloudTrail, MITRE, 타임라인',
    },
    'HUNTING_AGENT_RUNTIME_ARN': {
        'name': 'Posture 분석', 'tool': 'invoke_hunting_agent',
        'desc': 'Posture(보안 태세) 분석: Steampipe SQL로 리소스 설정 약점(IAM 과다권한, 노출 SG, 미암호화, public)과 복합 공격 경로를 크로스 JOIN으로 탐색. 구성(config) 점검 — CSPM 보완.',
        'keywords': 'IAM 과다권한, 노출, 암호화, posture, 태세, 공격 경로, attack path, 설정 점검',
    },
    'THREAT_HUNTING_AGENT_RUNTIME_ARN': {
        'name': 'Threat Hunting Agent', 'tool': 'invoke_threat_hunting_agent',
        'desc': '로그 기반 위협 헌팅(assume breach): CloudTrail/DNS/VPC Flow 로그를 교차해 공격자 행위·흔적(로그인 폭주, 권한 상승, C2/exfil, defense evasion)을 MITRE ATT&CK 가설로 능동 추적. 행위(behavior) 점검.',
        'keywords': '헌팅, 침입 흔적, TTP, IOC, 로그인 폭주, 권한 상승, C2, exfil, 횡적 이동, assume breach',
    },
    'LOGQUERY_AGENT_RUNTIME_ARN': {
        'name': 'Log Query Agent', 'tool': 'invoke_logquery_agent',
        'desc': 'CloudWatch Unified Data Store 로그 질의: 자연어→LogsQL 변환, VPC Flow/CloudTrail/Route53 DNS/WAF/NLB 로그 조회, finding 연관 로그 패턴 분석',
        'keywords': 'VPC Flow, CloudTrail 로그, DNS, WAF, 로그 조회, LogsQL',
    },
    'RESPONSE_AGENT_RUNTIME_ARN': {
        'name': 'Response Agent', 'tool': 'invoke_response_agent',
        'desc': '자동 대응(SOAR): AgentCore Gateway 통해 EC2 격리, 보안 그룹 규칙 차단, IAM 자격증명 비활성화. 모든 write 액션은 승인 게이트를 거쳐 Task로 큐잉됨',
        'keywords': '격리, 차단, revoke, 대응, SOAR, isolate, block, 조치',
    },
    'REPORT_AGENT_RUNTIME_ARN': {
        'name': 'Report Agent', 'tool': 'invoke_report_agent',
        'desc': '보안 리포트 합성: 조사·헌팅 결과 종합, 보안 감사 리포트, 인시던트 타임라인, 컴플라이언스 보고서 생성',
        'keywords': '리포트, 보고서, 타임라인, 컴플라이언스, 요약',
    },
}


def _build_system_prompt():
    """Build system prompt with only active agents listed."""
    active = [(info['name'], info['tool'], info['desc'])
              for env, info in _AGENT_DESCRIPTIONS.items() if os.environ.get(env)]

    if not active:
        return "You are a security operations assistant. No sub-agents are configured."

    agent_list = '\n'.join(
        f'{i}. **{name}** ({tool}): {desc}'
        for i, (name, tool, desc) in enumerate(active, 1)
    )

    routing_rules = """
Routing Guidelines:
- GuardDuty/Security Hub finding 조사, CloudTrail 상관 분석, 근본 원인 추정, MITRE ATT&CK 매핑: → Investigation Agent
- IAM 과다권한/노출 SG/미암호화/MFA 미설정 등 리소스 '설정' 약점·공격경로 점검(CSPM): → Posture 분석 (invoke_hunting_agent)
- 로그에서 공격자 '행위'·흔적 능동 추적(로그인 폭주/권한상승/C2/exfil/TTP, assume breach): → Threat Hunting Agent (invoke_threat_hunting_agent)
- VPC Flow/CloudTrail/DNS/WAF 로그 조회, 자연어→LogsQL: → Log Query Agent
- EC2 격리/SG 차단/IAM revoke 등 자동 대응 (승인 필요): → Response Agent
- 보안 리포트/인시던트 타임라인/컴플라이언스 보고서 합성: → Report Agent"""

    disambiguation = """

Routing Disambiguation (중복 해소):
- finding 심층 조사·상관 분석 → Investigation Agent | 리소스 '설정' 약점 점검(CSPM) → Posture 분석 | 로그 기반 '행위' 헌팅 → Threat Hunting Agent
- 특정 로그 조회 → Log Query Agent | 로그 기반 인시던트 상관 분석 → Investigation Agent
- 조치 실행 → Response Agent (반드시 승인 게이트) | 조사·분석 → Investigation Agent

Multi-Agent Chaining (복합 질문):
- "이 finding 조사하고 연관 로그 보여줘" → Investigation Agent (finding 분석) → Log Query Agent (연관 로그 조회)
- "침해 조사 후 대응" → Investigation Agent (근본 원인) → Response Agent (승인 후 격리/차단)
- "보안 태세 점검 후 리포트" → Threat Hunting Agent (헌팅) → Report Agent (리포트 합성)
- When chaining, pass the first agent's findings as context in the second agent's request.

SAFETY: Response Agent의 모든 조치는 승인 게이트를 거칩니다. 사용자가 명시적으로 요청하지 않는 한 격리/차단/revoke를 자동 실행하지 마세요. 조치 제안 시 영향 범위를 명확히 설명하세요."""

    return f"""You are an expert AWS Security Operations (SOC) assistant that orchestrates specialized security sub-agents. ALWAYS use the appropriate sub-agent tool to get actual data - never guess or make up information.

Available Sub-Agents:
{agent_list}
{routing_rules}
{disambiguation}

Key behaviors:
- Send clear, specific natural language requests to sub-agents. Include relevant context (e.g. finding IDs, resource ARNs, IP addresses) when available.
- For multi-step investigations, chain multiple sub-agent calls. Example: investigate a finding, then query correlated logs.
- Always respond in the same language as the user's question (Korean if asked in Korean).
- Present data in a clear, organized format with tables or bullet points. Organize by severity: CRITICAL > HIGH > MEDIUM > LOW.
- If a sub-agent returns an error, explain it clearly and suggest alternatives.
- IMPORTANT: Keep responses concise and focused. Summarize findings in bullet points.
- **수행 가이드 요청 예외**: 사용자가 보안 작업의 수행 절차·CLI/코드 가이드를 요청하면(예: CVE 패치,
  패키지 업그레이드, 이미지 재빌드, 설정 변경 — 이미 분류된 작업 티켓 처리), 적절한 sub-agent 도구가
  없을 때는 **너의 AWS 보안 전문 지식으로 직접 단계별 절차 + 복사해서 쓸 수 있는 정확한 CLI/코드 블록을
  작성**하라. 이 경우 sub-agent를 억지로 호출하지 마라(특히 SOAR/Response는 격리/차단/revoke '실행'
  전용이라 가이드 작성에 부적합 — 호출 시 불필요한 티켓만 생긴다). 실제 리소스 값이 불확실하면 플레이스홀더로
  표시하고 무엇을 채워야 하는지 명시하라. 단, 실제 데이터(finding 내용 등)는 지어내지 마라."""

SYSTEM_PROMPT = _build_system_prompt()

# Tool display names for Korean UI
TOOL_DISPLAY_NAMES = {
    'invoke_investigation_agent': 'Investigation Agent 호출',
    'invoke_hunting_agent': 'Posture 분석 호출',
    'invoke_threat_hunting_agent': 'Threat Hunting Agent 호출',
    'invoke_logquery_agent': 'Log Query Agent 호출',
    'invoke_response_agent': 'Response Agent 호출',
    'invoke_report_agent': 'Report Agent 호출',
}

# Sub-agent ARN/qualifier env var pairs for warm-up (only active ones are pinged)
_SUB_AGENT_CONFIGS = [
    ('INVESTIGATION_AGENT_RUNTIME_ARN', 'INVESTIGATION_AGENT_QUALIFIER', 'investigation'),
    ('HUNTING_AGENT_RUNTIME_ARN', 'HUNTING_AGENT_QUALIFIER', 'hunting'),
    ('THREAT_HUNTING_AGENT_RUNTIME_ARN', 'THREAT_HUNTING_AGENT_QUALIFIER', 'threat_hunting'),
    ('LOGQUERY_AGENT_RUNTIME_ARN', 'LOGQUERY_AGENT_QUALIFIER', 'logquery'),
    ('RESPONSE_AGENT_RUNTIME_ARN', 'RESPONSE_AGENT_QUALIFIER', 'response'),
    ('REPORT_AGENT_RUNTIME_ARN', 'REPORT_AGENT_QUALIFIER', 'report'),
]


def _ping_sub_agent(arn_env, qual_env, name):
    """Fire-and-forget ping to warm up a sub-agent."""
    runtime_arn = os.environ.get(arn_env, '')
    qualifier = os.environ.get(qual_env, '')
    if not runtime_arn:
        return
    try:
        client = boto3.client('bedrock-agentcore', region_name=REGION)
        # runtimeSessionId는 최소 33자 — uuid4().hex(32)로 길이 보장
        # (기존 f"warmup-{name}-{ts}"는 24~31자라 ParamValidationError로 ping이 전부 실패,
        #  sub-agent 예열이 안 돼 실제 요청 시 콜드스타트 지연을 유발했음)
        client.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            qualifier=qualifier,
            runtimeSessionId=f"warmup-{name}-{uuid.uuid4().hex}",
            payload=json.dumps({"type": "ping"}),
            contentType='application/json'
        )
        logger.info(f"Sub-agent {name} pinged successfully")
    except Exception as e:
        logger.warning(f"Sub-agent {name} ping failed: {e}")


def _warm_up_sub_agents():
    """Warm up all configured sub-agents in parallel (fire-and-forget)."""
    active = [(a, q, n) for a, q, n in _SUB_AGENT_CONFIGS if os.environ.get(a)]
    if not active:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(active)) as executor:
        for arn_env, qual_env, name in active:
            executor.submit(_ping_sub_agent, arn_env, qual_env, name)


def _extract_user_id(context):
    """Extract user_id from AgentCore context (JWT claims or headers)."""
    try:
        if not context:
            logger.info("No context provided")
            return 'anonymous'

        # Log all context attributes for debugging
        all_attrs = [a for a in dir(context) if not a.startswith('_')]
        logger.info(f"Context attrs: {all_attrs}")

        # Method 1: Check if AgentCore provides JWT claims directly via context
        # (e.g., context.identity, context.claims, context.authorizer, context.caller_identity)
        for attr_name in ['identity', 'claims', 'authorizer', 'caller_identity', 'auth', 'principal', 'user']:
            val = getattr(context, attr_name, None)
            if val:
                logger.info(f"Context.{attr_name} = {val}")
                if isinstance(val, dict):
                    sub = val.get('sub') or val.get('user_id') or val.get('username')
                    if sub:
                        logger.info(f"Found user_id from context.{attr_name}: {sub}")
                        return sub

        # Method 2: Try headers (requestHeaderAllowlist)
        headers = {}
        raw_headers = getattr(context, 'request_headers', None) or getattr(context, 'headers', None) or {}
        headers = {k.lower(): v for k, v in raw_headers.items()} if raw_headers else {}
        logger.info(f"Headers available: {list(headers.keys())}")

        auth_header = headers.get('authorization', '')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            payload_part = token.split('.')[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            claims = json.loads(base64.b64decode(payload_part))
            sub = claims.get('sub', 'anonymous')
            logger.info(f"Extracted user_id from JWT header: {sub}")
            return sub

        logger.info("No user_id found in context or headers, returning anonymous")
        return 'anonymous'
    except Exception as e:
        logger.warning(f"Failed to extract user_id: {e}")
        return 'anonymous'


def _load_conversation_metadata(conversation_id, user_id):
    """Load conversation metadata (title, counts) from DDB. No messages loaded."""
    if not CONVERSATIONS_TABLE or not conversation_id:
        return None
    try:
        table = dynamodb.Table(CONVERSATIONS_TABLE)
        resp = table.get_item(
            Key={'user_id': user_id, 'conversation_id': conversation_id},
            ProjectionExpression='user_id, conversation_id, #t, message_count, tool_count, updated_at, created_at',
            ExpressionAttributeNames={'#t': 'title'},
        )
        return resp.get('Item')
    except Exception as e:
        logger.warning(f"Failed to load conversation metadata: {e}")
        return None


def _save_conversation_metadata(conversation_id, user_id, title, message_count=0, tool_count=0):
    """Save conversation metadata (title, counts) to DDB. Messages are in AgentCore Memory."""
    if not CONVERSATIONS_TABLE:
        raise ValueError("CONVERSATIONS_TABLE not set")
    table = dynamodb.Table(CONVERSATIONS_TABLE)
    now = datetime.now(timezone.utc).isoformat()
    logger.info(f"Saving metadata: conv={conversation_id}, user={user_id}, table={CONVERSATIONS_TABLE}, title={title[:30] if title else ''}")
    table.update_item(
        Key={'user_id': user_id, 'conversation_id': conversation_id},
        UpdateExpression='SET #t = :t, message_count = :mc, tool_count = :tc, updated_at = :ua, created_at = if_not_exists(created_at, :ca)',
        ExpressionAttributeNames={'#t': 'title'},
        ExpressionAttributeValues={
            ':t': title,
            ':mc': message_count,
            ':tc': tool_count,
            ':ua': now,
            ':ca': now,
        },
    )
    logger.info(f"Metadata saved successfully: conv={conversation_id}")


def _load_ddb_messages(conversation_id, user_id):
    """Load messages from DDB (legacy fallback for pre-Memory conversations)."""
    if not CONVERSATIONS_TABLE or not conversation_id:
        return []
    try:
        table = dynamodb.Table(CONVERSATIONS_TABLE)
        resp = table.get_item(Key={'user_id': user_id, 'conversation_id': conversation_id})
        item = resp.get('Item')
        if item and item.get('user_id') == user_id:
            return item.get('messages', [])
        return []
    except Exception as e:
        logger.warning(f"Failed to load DDB messages: {e}")
        return []


def _save_conversation_full(conversation_id, user_id, title, messages, tool_count=0):
    """Save full conversation to DDB (legacy fallback when MEMORY_ID is not set).
    Only saves user messages and the FINAL assistant response per turn,
    filtering out intermediate tool_use/tool_result messages."""
    if not CONVERSATIONS_TABLE:
        raise ValueError("CONVERSATIONS_TABLE not set")
    table = dynamodb.Table(CONVERSATIONS_TABLE)
    serialized = []
    for msg in messages:
        role = msg.get('role', 'user')
        content = msg.get('content', '')

        # Skip tool_result messages (Strands wraps these as user role with toolResult blocks)
        if isinstance(content, list):
            has_tool_result = any(
                isinstance(b, dict) and ('toolResult' in b or b.get('type') == 'tool_result')
                for b in content
            )
            if has_tool_result:
                continue

            # For assistant messages, skip if it contains tool_use (intermediate orchestration)
            has_tool_use = any(
                isinstance(b, dict) and ('toolUse' in b or b.get('type') == 'tool_use')
                for b in content
            )
            if role == 'assistant' and has_tool_use:
                # Extract only text parts (skip if no meaningful text)
                text_parts = []
                for block in content:
                    if isinstance(block, dict):
                        if block.get('type') == 'text':
                            text_parts.append(block.get('text', ''))
                        elif 'text' in block and 'toolUse' not in block and 'toolResult' not in block:
                            text_parts.append(block['text'])
                text = '\n'.join(t for t in text_parts if t.strip())
                # Skip intermediate messages like "에이전트를 호출합니다"
                if not text or len(text) < 50:
                    continue
                content = text
            else:
                # Normal text extraction
                text_parts = []
                for block in content:
                    if isinstance(block, dict):
                        if block.get('type') == 'text':
                            text_parts.append(block.get('text', ''))
                        elif 'text' in block:
                            text_parts.append(block['text'])
                content = '\n'.join(text_parts)

        if not content or (isinstance(content, str) and not content.strip()):
            continue

        serialized.append({'role': role, 'content': content})

    now = datetime.now(timezone.utc).isoformat()
    logger.info(f"Saving full conversation: conv={conversation_id}, user={user_id}, msgs={len(serialized)}")
    table.put_item(Item={
        'conversation_id': conversation_id,
        'user_id': user_id,
        'title': title,
        'messages': serialized,
        'message_count': len(serialized),
        'tool_count': tool_count,
        'updated_at': now,
        'created_at': now,
    })
    logger.info(f"Full conversation saved successfully: conv={conversation_id}")


def _retrieve_long_term_memories(user_id, message):
    """Retrieve long-term SOC memory from AgentCore Memory.
    Namespaces are reframed for security context:
      /facts/      → assets, threat intel, observed indicators (security knowledge)
      /preferences/→ analyst workflow preferences
      /summaries/  → past investigation/incident session summaries
    """
    if not MEMORY_ID or not agentcore_client:
        return ''
    # RetrieveMemoryRecords requires memoryId + searchCriteria{searchQuery} and a namespace.
    # actorId is encoded into the namespace path (/facts/{actorId}/ etc).
    namespaces = [
        (f'/facts/{user_id}/', 'Security Knowledge'),
        (f'/preferences/{user_id}/', 'Analyst Preference'),
        (f'/summaries/{user_id}/', 'Past Investigation Summary'),
    ]
    memory_lines = []
    for ns, label in namespaces:
        try:
            resp = agentcore_client.retrieve_memory_records(
                memoryId=MEMORY_ID,
                namespace=ns,
                searchCriteria={'searchQuery': message[:1000], 'topK': 5},
                maxResults=5,
            )
            for rec in resp.get('memoryRecordSummaries', []):
                content = rec.get('content', {})
                text = content.get('text', '') if isinstance(content, dict) else str(content)
                if text:
                    memory_lines.append(f"[{label}] {text}")
        except Exception as e:
            logger.warning(f"Memory retrieve failed for {ns}: {e}")
    if not memory_lines:
        return ''
    return '\n\n--- SOC Memory Context (assets, threat intel, prior investigations) ---\n' + '\n'.join(memory_lines) + '\n--- End Memory Context ---'


def _generate_title(message):
    """Generate a short title from the first user message."""
    title = message.strip()[:50]
    if len(message.strip()) > 50:
        title += '...'
    return title


@app.entrypoint
async def handle_request(payload, context=None):
    """Main entrypoint — yields SSE events for real-time streaming."""

    # Warm-up ping
    if payload.get('type') == 'ping':
        yield {'event': 'pong'}
        # Fire-and-forget: warm up all sub-agents in parallel
        threading.Thread(target=_warm_up_sub_agents, daemon=True).start()
        return

    message = payload.get('message', '')
    model_id = payload.get('model_id') or SONNET_MODEL
    conversation_id = payload.get('conversation_id') or str(uuid.uuid4())

    if not message:
        yield {'event': 'error', 'data': {'message': 'No message provided'}}
        return

    # Extract user_id: prefer payload (from frontend JWT decode), fallback to context headers
    user_id = payload.get('user_id') or _extract_user_id(context)
    session_id = context.session_id if context else None

    logger.info(f"Request: user={user_id}, conv={conversation_id}, session={session_id}, model={model_id}")

    # Send start event
    yield {'event': 'start', 'data': {'conversation_id': conversation_id}}

    # ── Tier 0: Cache-direct bypass (0 LLM calls) ────────────────────
    # Skip cache-direct for follow-up conversations (client sends conversation_id)
    is_followup = bool(payload.get('conversation_id'))
    cache_result = try_cache_direct(message) if not is_followup else None
    if cache_result:
        logger.info("Cache-direct hit — bypassing all LLM calls")
        # Stream cache-direct result
        result_text = cache_result['text']
        chunk_size = 100
        for i in range(0, len(result_text), chunk_size):
            yield {'event': 'text', 'data': {'content': result_text[i:i+chunk_size]}}

        # Save conversation
        conv_metadata = _load_conversation_metadata(conversation_id, user_id)
        title = conv_metadata.get('title', _generate_title(message)) if conv_metadata else _generate_title(message)
        try:
            cache_messages = [
                {'role': 'user', 'content': message},
                {'role': 'assistant', 'content': result_text},
            ]
            await asyncio.to_thread(
                _save_conversation_full,
                conversation_id, user_id, title,
                cache_messages, 0,
            )
        except Exception as e:
            logger.warning(f"Cache-direct save failed: {e}")

        yield {
            'event': 'metadata',
            'data': {
                'tool_count': 0,
                'tool_names': [],
                'thinking': '',
                'classification': 'cache-direct',
                'path': 'cache-direct',
                'tokens': {'input': 0, 'output': 0},
            }
        }
        yield {
            'event': 'done',
            'data': {
                'conversation_id': conversation_id,
                '_diag': {
                    'save_mode': 'legacy',
                    'classification': 'cache-direct',
                    'path': 'cache-direct',
                    'table': CONVERSATIONS_TABLE,
                    'memory_id': MEMORY_ID,
                    'user_id': user_id,
                },
            },
        }
        return

    # Load conversation metadata from DDB
    conv_metadata = _load_conversation_metadata(conversation_id, user_id)

    # Determine if Memory is enabled
    use_memory = bool(MEMORY_ID and MEMORY_AVAILABLE)
    logger.info(f"Memory config: MEMORY_ID={MEMORY_ID!r}, MEMORY_AVAILABLE={MEMORY_AVAILABLE}, use_memory={use_memory}")

    # Retrieve long-term memories and enhance system prompt
    long_term_context = _retrieve_long_term_memories(user_id, message) if use_memory else ''
    enhanced_prompt = SYSTEM_PROMPT + long_term_context if long_term_context else SYSTEM_PROMPT

    # Create Memory session manager (if Memory enabled)
    session_manager = None
    if use_memory:
        try:
            config = AgentCoreMemoryConfig(
                memory_id=MEMORY_ID,
                session_id=conversation_id,
                actor_id=user_id,
                batch_size=10,
            )
            session_manager = AgentCoreMemorySessionManager(
                agentcore_memory_config=config,
                region_name=REGION,
            )
            logger.info(f"Memory session manager created: conv={conversation_id}")
        except Exception as e:
            logger.warning(f"Failed to create Memory session manager: {e}")
            session_manager = None

    # ── 2-Tier Classification: fast path for single-agent queries ────
    # Load conversation history for classification context
    prev_messages = []
    if conv_metadata:
        if use_memory and session_manager:
            pass  # Memory session will load history automatically
        else:
            prev_messages = _load_ddb_messages(conversation_id, user_id)

    category = await asyncio.to_thread(classify_query, message, prev_messages)
    logger.info(f"Classification result: {category}")

    # ── Parallel multi-agent fast path (comma-separated categories) ────
    if ',' in category:
        categories = [c.strip() for c in category.split(',')]
        active_categories = set(_get_active_categories())
        categories = [c for c in categories if c in active_categories]

        if len(categories) >= 2:
            logger.info(f"Parallel dispatch: {categories}")

            # SSE: tool events for each agent
            display_names = []
            for cat in categories:
                dn = get_display_name(cat)
                display_names.append(dn)
                yield {'event': 'tool', 'data': {'name': dn, 'tool_name': f'invoke_{cat}_agent'}}

            # Parallel invocation via ThreadPoolExecutor
            parallel_usage = {}

            def _parallel_invoke():
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(categories)) as executor:
                    futures = {
                        executor.submit(invoke_directly, cat, message): cat
                        for cat in categories
                    }
                    results = {}
                    for future in concurrent.futures.as_completed(futures):
                        cat = futures[future]
                        try:
                            res = future.result()
                            text = res.get('result', '') or res.get('text', '') or res.get('response', '')
                            if not text and isinstance(res, dict) and not res.get('error'):
                                text = json.dumps(res, ensure_ascii=False)
                            results[cat] = text or f"Error: {res.get('error', 'empty response')}"
                            parallel_usage[cat] = res.get('usage', {})
                        except Exception as e:
                            results[cat] = f"Error: {str(e)}"
                    return results

            parallel_results = await asyncio.to_thread(_parallel_invoke)
            logger.info(f"Parallel results received: {list(parallel_results.keys())}")

            # Check if all failed
            all_failed = all(v.startswith('Error:') for v in parallel_results.values())
            if not all_failed:
                # Synthesize with lightweight Sonnet call
                combined = "\n\n".join(
                    f"[{get_display_name(cat)}]\n{res}" for cat, res in parallel_results.items()
                )
                synthesis_prompt = (
                    f"다음은 여러 에이전트의 분석 결과입니다. 사용자 질문에 맞게 종합하여 답변하세요.\n\n"
                    f"사용자: {message}\n\n{combined}"
                )

                try:
                    synth_resp = _get_synth_client().converse(
                        modelId=SONNET_MODEL,
                        system=[{'text': '사용자 질문에 대해 여러 에이전트 결과를 종합하여 명확하고 간결하게 답변하세요. 한국어로 답변하세요.'}],
                        messages=[{'role': 'user', 'content': [{'text': synthesis_prompt}]}],
                        inferenceConfig={'maxTokens': 4096, 'temperature': 0},
                    )
                    synth_output = synth_resp.get('output', {}).get('message', {}).get('content', [])
                    result_text = synth_output[0].get('text', '') if synth_output else combined
                except Exception as e:
                    logger.warning(f"Synthesis failed, returning raw results: {e}")
                    result_text = combined

                # Stream the synthesized result
                chunk_size = 100
                for i in range(0, len(result_text), chunk_size):
                    yield {'event': 'text', 'data': {'content': result_text[i:i+chunk_size]}}

                # Save conversation
                title = conv_metadata.get('title', _generate_title(message)) if conv_metadata else _generate_title(message)
                total_tool_count = len(categories)
                try:
                    fast_messages = list(prev_messages) if prev_messages else []
                    fast_messages.append({'role': 'user', 'content': message})
                    fast_messages.append({'role': 'assistant', 'content': result_text})
                    if session_manager:
                        await asyncio.to_thread(
                            _save_conversation_metadata,
                            conversation_id, user_id, title,
                            len(fast_messages), total_tool_count,
                        )
                    else:
                        await asyncio.to_thread(
                            _save_conversation_full,
                            conversation_id, user_id, title,
                            fast_messages, total_tool_count,
                        )
                except Exception as e:
                    logger.warning(f"Parallel path save failed: {e}")

                # Collect token usage: classifier + sub-agents
                classifier_tokens = {'inputTokens': 60, 'outputTokens': 10}
                total_sub_input = sum(u.get('inputTokens', 0) for u in parallel_usage.values())
                total_sub_output = sum(u.get('outputTokens', 0) for u in parallel_usage.values())
                parallel_tokens = {
                    'input': classifier_tokens['inputTokens'] + total_sub_input,
                    'output': classifier_tokens['outputTokens'] + total_sub_output,
                    'classifier': classifier_tokens,
                    'sub_agents': parallel_usage,
                }

                # Metadata + done
                yield {
                    'event': 'metadata',
                    'data': {
                        'tool_count': total_tool_count,
                        'tool_names': display_names,
                        'thinking': '',
                        'classification': category,
                        'path': 'parallel',
                        'tokens': parallel_tokens,
                    }
                }
                yield {
                    'event': 'done',
                    'data': {
                        'conversation_id': conversation_id,
                        '_diag': {
                            'save_mode': 'memory' if session_manager else 'legacy',
                            'classification': category,
                            'path': 'parallel',
                            'table': CONVERSATIONS_TABLE,
                            'memory_id': MEMORY_ID,
                            'user_id': user_id,
                        },
                    },
                }
                return
            else:
                logger.warning("All parallel invocations failed, falling back to full path")

    # Fast path: single agent, bypass Host Agent orchestration
    if category not in ('multi', 'general') and ',' not in category:
        display_name = get_display_name(category)
        tool_name = f'invoke_{category}_agent'

        # SSE: tool event
        yield {'event': 'tool', 'data': {'name': display_name, 'tool_name': tool_name}}

        # Direct sub-agent invocation (run in thread to avoid blocking event loop)
        result = await asyncio.to_thread(invoke_directly, category, message)

        if result.get('error'):
            # Fallback: if direct invoke fails, fall through to full path
            logger.warning(f"Fast path failed for {category}: {result['error']}, falling back to full path")
        else:
            # Stream the result text
            result_text = result.get('result', '')
            if not result_text and isinstance(result, dict):
                # Some agents return different keys
                result_text = result.get('text', '') or result.get('response', '') or json.dumps(result, ensure_ascii=False)

            # Emit text in chunks for smooth SSE streaming
            chunk_size = 100
            for i in range(0, len(result_text), chunk_size):
                yield {'event': 'text', 'data': {'content': result_text[i:i+chunk_size]}}

            # Save conversation (fast path)
            title = conv_metadata.get('title', _generate_title(message)) if conv_metadata else _generate_title(message)
            tool_count = result.get('tool_count', 1)
            try:
                fast_messages = list(prev_messages) if prev_messages else []
                fast_messages.append({'role': 'user', 'content': message})
                fast_messages.append({'role': 'assistant', 'content': result_text})
                if session_manager:
                    await asyncio.to_thread(
                        _save_conversation_metadata,
                        conversation_id, user_id, title,
                        len(fast_messages), tool_count,
                    )
                else:
                    await asyncio.to_thread(
                        _save_conversation_full,
                        conversation_id, user_id, title,
                        fast_messages, tool_count,
                    )
            except Exception as e:
                logger.warning(f"Fast path save failed: {e}")

            # Collect token usage: classifier + sub-agent
            sub_usage = result.get('usage', {})
            classifier_tokens = {'inputTokens': 60, 'outputTokens': 10}
            fast_tokens = {
                'input': sub_usage.get('inputTokens', 0) + classifier_tokens['inputTokens'],
                'output': sub_usage.get('outputTokens', 0) + classifier_tokens['outputTokens'],
                'classifier': classifier_tokens,
                'sub_agent': sub_usage,
            }

            # Metadata + done
            yield {
                'event': 'metadata',
                'data': {
                    'tool_count': tool_count,
                    'tool_names': [display_name],
                    'thinking': '',
                    'classification': category,
                    'path': 'fast',
                    'tokens': fast_tokens,
                }
            }
            yield {
                'event': 'done',
                'data': {
                    'conversation_id': conversation_id,
                    '_diag': {
                        'save_mode': 'memory' if session_manager else 'legacy',
                        'classification': category,
                        'path': 'fast',
                        'table': CONVERSATIONS_TABLE,
                        'memory_id': MEMORY_ID,
                        'user_id': user_id,
                    },
                },
            }
            return

    # ── General path: lightweight Haiku, no tools (casual/greeting/non-AWS) ──
    if category == 'general':
        logger.info("General path: lightweight Haiku response (no tools)")
        general_system_prompt = (
            "당신은 AWS 보안 운영(SOC) 전문 AI 어시스턴트입니다. 친절하고 간결하게 답변하세요. "
            "보안 관련 질문(finding 조사, 위협 헌팅, 로그 분석, 대응)이면 구체적인 에이전트에게 문의하도록 안내하세요."
        )
        try:
            general_model = BedrockModel(
                model_id=CLASSIFIER_MODEL_ID,
                max_tokens=2048,
            )
            general_agent = Agent(
                model=general_model,
                system_prompt=general_system_prompt + (long_term_context if long_term_context else ''),
                tools=[],
            )

            # Load conversation history for context
            if prev_messages:
                for msg in prev_messages:
                    content = msg.get('content', '')
                    role = msg.get('role', 'user')
                    if isinstance(content, str) and content.strip():
                        general_agent.messages.append({"role": role, "content": [{"text": content}]})
                    elif isinstance(content, list) and content:
                        general_agent.messages.append({"role": role, "content": content})

            result = await asyncio.to_thread(general_agent, message)
            result_text = ''
            if result and result.message:
                for block in result.message.get('content', []):
                    if isinstance(block, dict):
                        if block.get('type') == 'text':
                            result_text += block.get('text', '')
                        elif 'text' in block:
                            result_text += block['text']
            result_text = result_text or 'No response generated.'

            # Emit text in chunks for smooth SSE streaming
            chunk_size = 100
            for i in range(0, len(result_text), chunk_size):
                yield {'event': 'text', 'data': {'content': result_text[i:i+chunk_size]}}

            # Save conversation
            title = conv_metadata.get('title', _generate_title(message)) if conv_metadata else _generate_title(message)
            try:
                general_messages = list(prev_messages) if prev_messages else []
                general_messages.append({'role': 'user', 'content': message})
                general_messages.append({'role': 'assistant', 'content': result_text})
                if session_manager:
                    await asyncio.to_thread(
                        _save_conversation_metadata,
                        conversation_id, user_id, title,
                        len(general_messages), 0,
                    )
                else:
                    await asyncio.to_thread(
                        _save_conversation_full,
                        conversation_id, user_id, title,
                        general_messages, 0,
                    )
            except Exception as e:
                logger.warning(f"General path save failed: {e}")

            # Token usage: classifier (Haiku) + general response (Haiku)
            general_classifier_tokens = {'inputTokens': 60, 'outputTokens': 10}
            general_response_tokens = {'inputTokens': 200, 'outputTokens': 300}
            general_tokens = {
                'input': general_classifier_tokens['inputTokens'] + general_response_tokens['inputTokens'],
                'output': general_classifier_tokens['outputTokens'] + general_response_tokens['outputTokens'],
                'classifier': general_classifier_tokens,
                'host': general_response_tokens,
            }

            # Metadata + done
            yield {
                'event': 'metadata',
                'data': {
                    'tool_count': 0,
                    'tool_names': [],
                    'thinking': '',
                    'classification': category,
                    'path': 'general',
                    'tokens': general_tokens,
                }
            }
            yield {
                'event': 'done',
                'data': {
                    'conversation_id': conversation_id,
                    '_diag': {
                        'save_mode': 'memory' if session_manager else 'legacy',
                        'classification': category,
                        'path': 'general',
                        'table': CONVERSATIONS_TABLE,
                        'memory_id': MEMORY_ID,
                        'user_id': user_id,
                    },
                },
            }
            return
        except Exception as e:
            logger.warning(f"General path failed: {e}, falling back to full path")

    # ── Full path: Host Agent orchestration (multi/fallback) ──
    logger.info(f"Full path: category={category}, model={model_id}")

    # Set up asyncio.Queue bridge for Strands (sync) → async yield
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue()

    def streaming_callback(**kwargs):
        """Strands callback (sync thread) → asyncio.Queue → async yield."""
        try:
            if 'data' in kwargs:
                asyncio.run_coroutine_threadsafe(
                    queue.put({'event': 'text', 'data': {'content': kwargs['data']}}),
                    loop
                )
            if 'reasoningText' in kwargs:
                asyncio.run_coroutine_threadsafe(
                    queue.put({'event': 'thinking', 'data': {'content': kwargs['reasoningText']}}),
                    loop
                )
            if 'current_tool_use' in kwargs:
                tool_use = kwargs['current_tool_use']
                tool_name = tool_use.get('name', '') if isinstance(tool_use, dict) else ''
                if tool_name:
                    display = TOOL_DISPLAY_NAMES.get(tool_name, tool_name)
                    asyncio.run_coroutine_threadsafe(
                        queue.put({'event': 'tool', 'data': {'name': display, 'tool_name': tool_name}}),
                        loop
                    )
        except Exception as e:
            logger.warning(f"Callback error: {e}")

    # Create Strands Agent
    # Haiku 4.5 does not support adaptive thinking
    model_kwargs = dict(
        model_id=model_id,
        max_tokens=16384,
        cache_prompt="default",
        cache_tools="default",
    )
    if 'haiku' not in model_id.lower():
        model_kwargs['additional_request_fields'] = {
            "thinking": {"type": "adaptive"}
        }
    model = BedrockModel(**model_kwargs)
    agent_kwargs = dict(
        model=model,
        system_prompt=enhanced_prompt,
        tools=get_all_tools(),
        callback_handler=streaming_callback,
    )
    if session_manager:
        agent_kwargs['session_manager'] = session_manager

    agent = Agent(**agent_kwargs)

    # Dual-read fallback: if Memory has no history (pre-Memory conversation), load from DDB
    # Reuse prev_messages loaded during classification to avoid duplicate DDB reads
    if session_manager and not agent.messages and conv_metadata and prev_messages:
        for msg in prev_messages:
            content = msg.get('content', '')
            role = msg.get('role', 'user')
            if isinstance(content, str) and content.strip():
                agent.messages.append({"role": role, "content": [{"text": content}]})
            elif isinstance(content, list) and content:
                agent.messages.append({"role": role, "content": content})
        logger.info(f"Dual-read fallback: loaded {len(prev_messages)} messages from DDB for conv={conversation_id}")

    # Legacy path: no Memory, load history from DDB manually
    if not session_manager and conv_metadata:
        for msg in prev_messages:
            content = msg.get('content', '')
            role = msg.get('role', 'user')
            if isinstance(content, str) and content.strip():
                agent.messages.append({"role": role, "content": [{"text": content}]})
            elif isinstance(content, list) and content:
                agent.messages.append({"role": role, "content": content})

    # Run Strands Agent in a separate thread (it's synchronous)
    agent_result = {}

    def run_agent():
        try:
            result = agent(message)
            # Extract final text and metadata
            final_text = ''
            thinking_text = ''
            tool_count = 0
            tool_names_seen = []
            if result and result.message:
                for block in result.message.get('content', []):
                    if isinstance(block, dict):
                        if block.get('type') == 'thinking':
                            thinking_text += block.get('thinking', '')
                        elif block.get('type') == 'text':
                            final_text += block.get('text', '')
                        elif 'text' in block:
                            final_text += block['text']

            for m in agent.messages:
                if m.get('role') == 'assistant' and isinstance(m.get('content'), list):
                    for block in m['content']:
                        if isinstance(block, dict):
                            tool_use = block.get('toolUse') or (block if block.get('type') == 'tool_use' else None)
                            if tool_use:
                                tool_count += 1
                                raw_name = tool_use.get('name', '') if isinstance(tool_use, dict) else ''
                                display = TOOL_DISPLAY_NAMES.get(raw_name, raw_name)
                                if display and display not in tool_names_seen:
                                    tool_names_seen.append(display)

            agent_result['text'] = final_text or 'No response generated.'
            agent_result['thinking'] = thinking_text
            agent_result['tool_count'] = tool_count
            agent_result['tool_names'] = tool_names_seen
            agent_result['messages'] = agent.messages
            agent_result['message_count'] = len(agent.messages)

            # Flush Memory session buffer
            if session_manager:
                try:
                    session_manager.close()
                except Exception as e:
                    logger.warning(f"Failed to close session manager: {e}")

            # Save conversation to DDB (in thread, before DONE signal)
            save_mode = 'memory' if session_manager else 'legacy'
            save_error = None
            title = conv_metadata.get('title', _generate_title(message)) if conv_metadata else _generate_title(message)
            try:
                if session_manager:
                    _save_conversation_metadata(
                        conversation_id, user_id, title,
                        message_count=len(agent.messages),
                        tool_count=tool_count,
                    )
                else:
                    _save_conversation_full(
                        conversation_id, user_id, title,
                        agent.messages, tool_count,
                    )
            except Exception as e:
                save_error = str(e)
                logger.error(f"Save failed: {e}")

            agent_result['save_mode'] = save_mode
            agent_result['save_error'] = save_error
            agent_result['title'] = title

            asyncio.run_coroutine_threadsafe(queue.put(('DONE', None)), loop)

        except Exception as e:
            err_str = str(e)
            logger.error(f"Agent error: {err_str}")

            # Flush Memory session buffer even on error
            if session_manager:
                try:
                    session_manager.close()
                except Exception:
                    pass

            # Try to extract partial response on MaxTokensReached
            if 'max_tokens' in err_str.lower() or 'MaxTokensReached' in err_str:
                partial_text = ''
                for m in agent.messages:
                    if m.get('role') == 'assistant' and isinstance(m.get('content'), list):
                        for block in m['content']:
                            if isinstance(block, dict):
                                if block.get('type') == 'text':
                                    partial_text = block.get('text', '')
                                elif 'text' in block:
                                    partial_text = block['text']
                if partial_text:
                    suffix = "\n\n---\n*응답이 너무 길어 일부만 표시됩니다. 더 구체적인 질문으로 나누어 질문해 주세요.*"
                    agent_result['text'] = partial_text + suffix
                    agent_result['thinking'] = ''
                    agent_result['tool_count'] = 0
                    agent_result['messages'] = agent.messages
                    agent_result['message_count'] = len(agent.messages)
                    # Save even on MaxTokensReached
                    title = conv_metadata.get('title', _generate_title(message)) if conv_metadata else _generate_title(message)
                    try:
                        if session_manager:
                            _save_conversation_metadata(conversation_id, user_id, title, message_count=len(agent.messages))
                        else:
                            _save_conversation_full(conversation_id, user_id, title, agent.messages)
                    except Exception:
                        pass
                    agent_result['save_mode'] = 'memory' if session_manager else 'legacy'
                    agent_result['save_error'] = None
                    agent_result['title'] = title
                    asyncio.run_coroutine_threadsafe(queue.put(('DONE', None)), loop)
                    return

            asyncio.run_coroutine_threadsafe(queue.put(('ERROR', e)), loop)

    thread = threading.Thread(target=run_agent, daemon=True)
    thread.start()

    # Yield events from queue (real-time SSE streaming)
    while True:
        item = await queue.get()
        if isinstance(item, tuple):
            status, error = item
            if status == 'DONE':
                # Token usage for full path: classifier + host agent (estimated)
                classifier_tokens = {'inputTokens': 60, 'outputTokens': 10}
                full_tokens = {
                    'input': classifier_tokens['inputTokens'],
                    'output': classifier_tokens['outputTokens'],
                    'classifier': classifier_tokens,
                    'path': 'full',
                }

                yield {
                    'event': 'metadata',
                    'data': {
                        'tool_count': agent_result.get('tool_count', 0),
                        'tool_names': agent_result.get('tool_names', []),
                        'thinking': agent_result.get('thinking', ''),
                        'classification': category,
                        'path': 'full',
                        'tokens': full_tokens,
                    }
                }
                yield {
                    'event': 'done',
                    'data': {
                        'conversation_id': conversation_id,
                        '_diag': {
                            'save_mode': agent_result.get('save_mode'),
                            'save_error': agent_result.get('save_error'),
                            'classification': category,
                            'path': 'full',
                            'table': CONVERSATIONS_TABLE,
                            'memory_id': MEMORY_ID,
                            'memory_available': MEMORY_AVAILABLE,
                            'user_id': user_id,
                        },
                    },
                }
                break
            elif status == 'ERROR':
                yield {'event': 'error', 'data': {'message': str(error)}}
                break
        else:
            yield item  # text, tool, or thinking event


if __name__ == "__main__":
    app.run()
