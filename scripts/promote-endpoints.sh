#!/usr/bin/env bash
#
# AgentCore 런타임의 소문자 `default` 엔드포인트를 최신 런타임 버전으로 승격한다.
#
# 왜 필요한가: update-agent-runtime(또는 CDK 재배포)는 새 런타임 버전을 만들지만, 호출에 실제
# 쓰이는 소문자 `default` 엔드포인트의 liveVersion은 자동으로 따라오지 않는다(대문자 DEFAULT만
# 자동 승격). 그래서 코드를 바꿔 배포해도 웹/host-agent가 계속 옛 코드를 보는 함정이 있다.
# 이 스크립트는 프로젝트의 모든 SOC 런타임에 대해 default 엔드포인트를 최신 버전으로 승격한다(멱등).
#
# 사용법:
#   ./scripts/promote-endpoints.sh [--region REGION] [--project NAME] [--env ENV]
#
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

REGION="${AWS_DEFAULT_REGION:-ap-northeast-2}"
PROJECT_NAME="${PROJECT_NAME:-agentic-soc}"
ENV_NAME="${ENVIRONMENT:-dev}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --project) PROJECT_NAME="$2"; shift 2 ;;
        --env) ENV_NAME="$2"; shift 2 ;;
        -h|--help) echo "Usage: $0 [--region REGION] [--project NAME] [--env ENV]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# 런타임 이름 프리픽스: CDK는 '{project}_{env}' (하이픈을 언더스코어로) 로 런타임을 만든다.
NAME_PREFIX=$(echo "${PROJECT_NAME}_${ENV_NAME}" | tr '-' '_')

echo -e "${GREEN}=== AgentCore default 엔드포인트 승격 ===${NC}"
echo "  Region: $REGION / Prefix: ${NAME_PREFIX}*"
echo ""

# 대상 런타임 목록 (id 만)
RUNTIME_IDS=$(aws bedrock-agentcore-control list-agent-runtimes \
    --region "$REGION" --max-results 100 \
    --query "agentRuntimes[?starts_with(agentRuntimeName, '${NAME_PREFIX}')].agentRuntimeId" \
    --output text 2>/dev/null || true)

if [ -z "$RUNTIME_IDS" ]; then
    echo -e "${YELLOW}  대상 런타임 없음 (${NAME_PREFIX}*) — 건너뜀${NC}"
    exit 0
fi

PROMOTED=0; SKIPPED=0
for RID in $RUNTIME_IDS; do
    # 런타임의 최신 버전 (= 현재 런타임 버전)
    LATEST=$(aws bedrock-agentcore-control get-agent-runtime \
        --agent-runtime-id "$RID" --region "$REGION" \
        --query "agentRuntimeVersion" --output text 2>/dev/null || echo "")
    [ -z "$LATEST" ] && continue

    # 소문자 default 엔드포인트의 현재 liveVersion
    LIVE=$(aws bedrock-agentcore-control get-agent-runtime-endpoint \
        --agent-runtime-id "$RID" --endpoint-name default --region "$REGION" \
        --query "liveVersion" --output text 2>/dev/null || echo "")

    if [ "$LIVE" = "$LATEST" ]; then
        echo -e "  ${RID}: default=v${LIVE} (최신, 건너뜀)"
        SKIPPED=$((SKIPPED+1))
        continue
    fi

    echo -e "  ${RID}: default v${LIVE:-?} → ${CYAN}v${LATEST}${NC} 승격..."
    aws bedrock-agentcore-control update-agent-runtime-endpoint \
        --agent-runtime-id "$RID" --endpoint-name default \
        --agent-runtime-version "$LATEST" --region "$REGION" >/dev/null
    PROMOTED=$((PROMOTED+1))
done

echo ""
echo -e "${GREEN}완료: ${PROMOTED}개 승격, ${SKIPPED}개 최신.${NC}"
echo -e "${YELLOW}(승격된 엔드포인트는 READY가 되기까지 수십 초 걸릴 수 있음)${NC}"
