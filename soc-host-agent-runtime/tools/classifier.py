"""2-Tier Classification — Haiku-based lightweight query router (SOC).
Classifies user queries / findings into a single security sub-agent category or 'multi'/'general'.
Keyword pre-classifier skips Haiku for obvious single-agent queries.
~50 input tokens, ~20 output tokens per call (when Haiku is needed)."""
import json
import logging
import os
import re

import boto3

logger = logging.getLogger("soc-host-agent.classifier")
REGION = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')

CLASSIFIER_MODEL_ID = os.environ.get('INFERENCE_PROFILE_HAIKU_ARN') or 'global.anthropic.claude-haiku-4-5-20251001-v1:0'

# ── Keyword Pre-Classifier (SOC categories) ────────────────────────────
# 주의: 한글에는 \b(단어 경계)를 쓰지 않는다 — Python re의 \b는 ASCII 단어문자 기준이라
# "스 리포트를"처럼 한글 사이에 낀 키워드를 매칭하지 못한다(영문 키워드에만 \b가 의미 있음).
# 평가 순서가 곧 우선순위: 산출물 의도가 명확한 report를 먼저 둔다
# ("컴플라이언스 리포트"는 hunting(컴플라이언스)이 아니라 report).
KEYWORD_MAP = [
    (r'(?:리포트|report|보고서|타임라인|timeline|요약\s*보고)', 'report'),
    # threat_hunting: 로그 기반 행위·흔적 헌팅(assume breach). hunting(posture)보다 먼저 평가.
    (r'(?:헌팅|위협\s*사냥|threat\s*hunt|침입\s*흔적|TTP|IOC|로그인\s*폭주|brute\s*force|횡적\s*이동|lateral|권한\s*상승|privilege\s*escalation|exfil|데이터\s*유출|C2|비콘|beacon|DGA|터널링|tunnel)', 'threat_hunting'),
    (r'(?:GuardDuty|finding|침해|malware|악성|compromise|backdoor|UnauthorizedAccess|Recon)', 'investigation'),
    # hunting = Posture 분석(설정 약점/노출/공격경로). 행위가 아닌 '구성' 점검.
    (r'(?:IAM|권한\s*과다|over.?privileg|access\s*key|MFA|암호화|encryption|노출|posture|태세|컴플라이언스|CIS|보안\s*감사|공격\s*경로|attack\s*path|미설정|public)', 'hunting'),
    (r'(?:VPC\s*Flow|CloudTrail|DNS|로그\s*조회|log\s*quer|LogsQL|WAF\s*log|NLB\s*log)', 'logquery'),
    (r'(?:격리|차단|isolate|block|revoke|quarantine|대응|remediat|SOAR|send_alert|create_task|propose|알림.{0,4}(?:발송|보내|전송)|발송해|통보|티켓.{0,4}생성)', 'response'),
]

# report 산출물 의도가 분명한 동사 — 다른 카테고리와 동시 매칭돼도 report로 확정
_REPORT_INTENT = re.compile(r'(?:리포트|report|보고서|타임라인|timeline)', re.IGNORECASE)
_REPORT_VERB = re.compile(r'(?:작성|생성|만들|합성|뽑아|정리)', re.IGNORECASE)

# '가이드/방법/절차'를 묻는 의도 — Response(실행)가 아니라 Host 직접 가이드(multi)로 가야 한다.
# "EC2 격리하는 방법 알려줘"가 response로 가서 불필요한 티켓을 만드는 오라우팅 방지.
_GUIDE_INTENT = re.compile(r'(?:방법|절차|어떻게|가이드|how\s*to|단계|예시|설명해|알려줘|뭐야|무엇)', re.IGNORECASE)
# 실제 '실행' 지시 — 가이드 단어가 섞여 있어도 이게 있으면 진짜 조치 요청으로 본다.
_EXECUTE_VERB = re.compile(r'(?:실행해|격리해|차단해|revoke해|비활성화해|조치해|당장|즉시)', re.IGNORECASE)


def _keyword_classify(message: str) -> str | None:
    """Keyword-based pre-classification. Returns category or None."""
    # 명시적 의도 접두어 — UI(Task Board 'AI로 처리' 등)가 붙이는 결정적 라우팅 신호. Haiku/기타 키워드보다
    # 절대 우선. 입력창에 보여도 자연스러운 한국어이고, classifier는 이 정확한 구를 우선 매칭한다.
    #   "(작업 가이드 요청)" → 작업 수행 절차·CLI 가이드는 Host(Sonnet) 직접 답변(multi)으로.
    #   "(대응 실행 제안)"   → 실제 고위험 조치(격리/차단/revoke) 실행 제안은 response로.
    if '(작업 가이드 요청)' in message:
        return 'multi'
    if '(대응 실행 제안)' in message:
        return 'response' if 'response' in _get_active_categories() else 'multi'

    matches = []
    for pattern, category in KEYWORD_MAP:
        if re.search(pattern, message, re.IGNORECASE):
            matches.append(category)

    # "리포트/보고서 + 작성/생성" 의도가 있으면 다른 키워드와 충돌해도 report 우선
    # (예: "보안 컴플라이언스 리포트를 작성해줘" → hunting(컴플라이언스) 무시하고 report)
    if 'report' in matches and _REPORT_INTENT.search(message) and _REPORT_VERB.search(message):
        return 'report'

    # response 키워드가 잡혔지만 '실행' 지시 없이 '방법/절차/가이드'를 묻는 경우 → multi(Host 직접 가이드).
    # (예: "EC2 격리하는 방법 알려줘" → response로 가면 불필요한 티켓 생성. 가이드는 Host Sonnet이 직접 답변.)
    if 'response' in matches and _GUIDE_INTENT.search(message) and not _EXECUTE_VERB.search(message):
        return 'multi'

    # 단일 report 매칭이라도 '작성' 의도/맥락 없이 질문이면("리포트가 뭐야?") Haiku로 넘겨 오버스펜드 방지.
    if matches == ['report'] and not _REPORT_VERB.search(message):
        return None

    if len(matches) == 1:
        return matches[0]  # Unambiguous single match
    elif len(matches) > 1:
        return None  # Ambiguous → fall through to Haiku
    return None  # No match → fall through to Haiku


# Agent key → env var mapping (only active agents are classification targets)
_AGENT_ENV_MAP = {
    'investigation': 'INVESTIGATION_AGENT_RUNTIME_ARN',
    'hunting': 'HUNTING_AGENT_RUNTIME_ARN',
    'threat_hunting': 'THREAT_HUNTING_AGENT_RUNTIME_ARN',
    'logquery': 'LOGQUERY_AGENT_RUNTIME_ARN',
    'response': 'RESPONSE_AGENT_RUNTIME_ARN',
    'report': 'REPORT_AGENT_RUNTIME_ARN',
}


def _get_active_categories():
    """Return list of active agent categories based on environment variables."""
    return [key for key, env in _AGENT_ENV_MAP.items() if os.environ.get(env)]


def _build_classification_prompt():
    """Build classification system prompt with only active agent categories."""
    active = _get_active_categories()
    categories = ', '.join(active + ['multi', 'general'])

    agent_hints = []
    hints = {
        'investigation': 'investigation: 특정 GuardDuty/Security Hub finding 1건 심층 조사, CloudTrail 상관, VPC Flow, MITRE 매핑, 근본 원인',
        'hunting': 'hunting: Posture 분석 — 리소스 설정 약점(IAM 과다권한/노출 SG/미암호화/public)과 공격 경로 교차(Steampipe SQL). 구성 점검.',
        'threat_hunting': 'threat_hunting: 로그 기반 위협 헌팅(assume breach) — CloudTrail/DNS/VPC Flow에서 공격자 행위·흔적(로그인 폭주/권한상승/C2/exfil/TTP) 가설 추적. 행위 점검.',
        'logquery': 'logquery: 단순 로그 조회, VPC Flow/CloudTrail/DNS/WAF 로그, 자연어→LogsQL',
        'response': 'response: 자동 대응(SOAR), EC2 격리, SG 차단, IAM revoke (승인 필요)',
        'report': 'report: 보안 리포트, 인시던트 타임라인, 컴플라이언스 보고서 합성',
    }
    for key in active:
        if key in hints:
            agent_hints.append(hints[key])

    return f"""Classify the user query (or security finding) into the appropriate category.
Categories: {categories}
- 2개 이상의 에이전트가 필요하면 쉼표로 구분하여 반환하세요 (예: investigation,logquery). 최대 3개까지.
- general: not security-related, casual conversation, greetings
- **보안 작업의 수행 절차·CLI/코드 가이드를 작성/설명해 달라는 요청**(예: CVE 패치 방법, 이미지 재빌드
  절차, 설정 변경 단계 — 이미 분류된 작업 티켓 처리 포함)은 **multi**로 분류하세요. Host가 직접
  단계별 가이드를 생성합니다. response는 실제 격리/차단/revoke/알림/티켓 '실행'을 요청할 때만 쓰세요
  ('가이드/방법/절차/작성'은 response가 아닙니다).

{chr(10).join(agent_hints)}

Reply with ONLY the category name(s), nothing else. Examples: investigation / hunting / investigation,logquery / response / multi"""


_classification_prompt = None


def classify_query(message: str, conversation_history: list = None) -> str:
    """Classify a user query / finding into a security agent category.

    Returns one of: investigation, hunting, logquery, response, report, multi, general.
    Falls back to 'multi' on any error (safest default).
    """
    # Keyword pre-classification (0 tokens, ~0ms)
    keyword_result = _keyword_classify(message)
    if keyword_result:
        # multi/general은 실제 sub-agent가 아닌 가상 카테고리라 active 목록에 없음 — 바로 반환.
        # (접두어 강제 라우팅 '(작업 가이드 요청)'→multi가 active 체크에 막혀 Haiku로 새던 버그 수정)
        if keyword_result in ('multi', 'general') or keyword_result in _get_active_categories():
            logger.info(f"Keyword pre-classified: {keyword_result}")
            return keyword_result

    global _classification_prompt
    if _classification_prompt is None:
        _classification_prompt = _build_classification_prompt()

    active = _get_active_categories()
    valid_categories = set(active + ['multi', 'general'])

    # Build messages: optional recent context + current query
    messages = []
    if conversation_history:
        # Include last 2 messages for context (helps with follow-up questions)
        recent = conversation_history[-2:]
        for msg in recent:
            role = msg.get('role', 'user')
            content = msg.get('content', '')
            if isinstance(content, list):
                text_parts = [b.get('text', '') for b in content if isinstance(b, dict) and b.get('type') == 'text']
                content = ' '.join(text_parts)
            if isinstance(content, str) and content.strip():
                # Truncate to keep classification input small
                messages.append({'role': role, 'content': [{'text': content[:200]}]})

    messages.append({'role': 'user', 'content': [{'text': message[:300]}]})

    try:
        client = boto3.client('bedrock-runtime', region_name=REGION)
        resp = client.converse(
            modelId=CLASSIFIER_MODEL_ID,
            system=[{'text': _classification_prompt}],
            messages=messages,
            inferenceConfig={'maxTokens': 20, 'temperature': 0},
        )
        output = resp.get('output', {}).get('message', {}).get('content', [])
        if output:
            raw = output[0].get('text', '').strip().lower()

            # Handle comma-separated multi-agent response (e.g. "investigation,logquery")
            if ',' in raw:
                parts = [p.strip() for p in raw.split(',')]
                valid_parts = [p for p in parts if p in valid_categories and p not in ('multi', 'general')]
                if len(valid_parts) >= 2:
                    category = ','.join(valid_parts[:3])  # Cap at 3
                    logger.info(f"Classification: '{message[:50]}...' → {category} (parallel)")
                    return category
                elif len(valid_parts) == 1:
                    logger.info(f"Classification: '{message[:50]}...' → {valid_parts[0]}")
                    return valid_parts[0]
                # All invalid → fall through to multi

            # Single category
            if raw in valid_categories:
                logger.info(f"Classification: '{message[:50]}...' → {raw}")
                return raw
            logger.warning(f"Classification returned invalid category: '{raw}', falling back to multi")

    except Exception as e:
        logger.warning(f"Classification failed: {e}, falling back to multi")

    return 'multi'
