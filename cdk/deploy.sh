#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DELIVERY_ROOT="$(dirname "$SCRIPT_DIR")"
CDK_DIR="$SCRIPT_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

ENV_NAME="${1:-dev}"
PROJECT_NAME="${2:-agentic-soc}"
REGION="${3:-ap-northeast-2}"

# 선택적 context — 환경변수로 주입(없으면 미적용):
#   MEMORY_ID        : AgentCore Memory ID (scripts/create-memory.sh 출력) → 장기기억 활성
#   BOTO3_LAYER_ARN  : 최신 boto3 Layer ARN (scripts/build-boto3-layer.sh 출력) → Log Explorer 데이터소스
#   MODEL_ID         : Bedrock 모델 ID 오버라이드
EXTRA_CONTEXT=""
[ -n "${MEMORY_ID:-}" ]       && EXTRA_CONTEXT="$EXTRA_CONTEXT --context memory_id=${MEMORY_ID}"
[ -n "${BOTO3_LAYER_ARN:-}" ] && EXTRA_CONTEXT="$EXTRA_CONTEXT --context boto3_layer_arn=${BOTO3_LAYER_ARN}"
[ -n "${MODEL_ID:-}" ]        && EXTRA_CONTEXT="$EXTRA_CONTEXT --context model_id=${MODEL_ID}"

echo -e "${GREEN}=== Agentic SOC CDK Deploy ===${NC}"
echo -e "  Environment: ${CYAN}${ENV_NAME}${NC}"
echo -e "  Project:     ${CYAN}${PROJECT_NAME}${NC}"
echo -e "  Region:      ${CYAN}${REGION}${NC}"
[ -n "${MEMORY_ID:-}" ]       && echo -e "  Memory ID:   ${CYAN}${MEMORY_ID}${NC}"
[ -n "${BOTO3_LAYER_ARN:-}" ] && echo -e "  boto3 Layer: ${CYAN}set${NC}"
echo ""

CDK_CONTEXT="--context env=${ENV_NAME} --context project=${PROJECT_NAME} --context region=${REGION}${EXTRA_CONTEXT}"
INFRA_STACK="${PROJECT_NAME}-${ENV_NAME}-infra"
AGENTCORE_STACK="${PROJECT_NAME}-${ENV_NAME}-agentcore"

# ── Step 1: CDK Bootstrap ─────────────────────────────────────────
echo -e "${CYAN}[1/5] Checking CDK bootstrap...${NC}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws cloudformation describe-stacks --stack-name CDKToolkit --region "$REGION" >/dev/null 2>&1 || {
    echo "  Bootstrapping CDK..."
    cd "$CDK_DIR"
    PATH=".venv/bin:$PATH" cdk bootstrap "aws://${ACCOUNT_ID}/${REGION}"
}
echo "  CDK bootstrap OK"

# ── Step 2: Deploy InfraStack ──────────────────────────────────────
echo -e "${CYAN}[2/5] Deploying InfraStack...${NC}"
cd "$CDK_DIR"
PATH=".venv/bin:$PATH" cdk deploy "$INFRA_STACK" \
    $CDK_CONTEXT --require-approval never

# ── Step 3: Generate frontend .env + build ─────────────────────────
echo -e "${CYAN}[3/5] Building frontend...${NC}"

USER_POOL_ID=$(aws cloudformation describe-stacks --stack-name "$INFRA_STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='CognitoUserPoolId'].OutputValue" \
    --output text --region "$REGION")

CLIENT_ID=$(aws cloudformation describe-stacks --stack-name "$INFRA_STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='CognitoClientId'].OutputValue" \
    --output text --region "$REGION")

COGNITO_DOMAIN=$(aws cloudformation describe-stacks --stack-name "$INFRA_STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='CognitoDomain'].OutputValue" \
    --output text --region "$REGION")

cat > "$DELIVERY_ROOT/frontend/.env" <<EOF
VITE_API_BASE_URL=/api
VITE_COGNITO_USER_POOL_ID=${USER_POOL_ID}
VITE_COGNITO_CLIENT_ID=${CLIENT_ID}
VITE_COGNITO_DOMAIN=${COGNITO_DOMAIN}
VITE_COGNITO_REGION=${REGION}
EOF
echo "  Generated frontend/.env"

cd "$DELIVERY_ROOT/frontend"
[ -d node_modules ] || npm install
npm run build
echo "  Frontend built"

# ── Step 4: Deploy AgentCoreStack ──────────────────────────────────
# CDK auto-detects source changes, triggers CodeBuild via CDK Trigger,
# and creates/updates AgentCore Runtimes. No local Docker needed.
echo -e "${CYAN}[4/5] Deploying AgentCoreStack (ECR + CodeBuild + Runtimes)...${NC}"
cd "$CDK_DIR"
PATH=".venv/bin:$PATH" cdk deploy "$AGENTCORE_STACK" \
    $CDK_CONTEXT --require-approval never

# ── Step 5: Upload frontend to S3 + CloudFront invalidation ───────
echo -e "${CYAN}[5/5] Uploading frontend + CloudFront invalidation...${NC}"
FRONTEND_BUCKET=$(aws cloudformation describe-stacks --stack-name "$INFRA_STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='FrontendBucketName'].OutputValue" \
    --output text --region "$REGION")
aws s3 sync "$DELIVERY_ROOT/frontend/dist" "s3://${FRONTEND_BUCKET}/" --delete --region "$REGION"
echo "  Frontend uploaded to s3://${FRONTEND_BUCKET}/"

CF_DIST_ID=$(aws cloudformation describe-stacks --stack-name "$INFRA_STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='CloudFrontDistributionId'].OutputValue" \
    --output text --region "$REGION" 2>/dev/null || echo "")
if [ -n "$CF_DIST_ID" ] && [ "$CF_DIST_ID" != "None" ]; then
    aws cloudfront create-invalidation --distribution-id "$CF_DIST_ID" --paths "/*" >/dev/null
    echo "  CloudFront invalidation created"
fi

# ── Step 6: Promote lowercase `default` endpoints to latest version ───
# AgentCore 런타임 코드를 재배포하면 새 버전이 생기지만, 호출에 쓰이는 소문자 `default`
# 엔드포인트의 liveVersion은 자동 갱신되지 않는다(웹/host-agent가 옛 코드를 봄). 모든 SOC 런타임의
# default 엔드포인트를 최신 버전으로 승격. (멱등 — 이미 최신이면 변화 없음)
echo -e "${CYAN}[6/6] Promoting AgentCore default endpoints to latest...${NC}"
PATH=".venv/bin:$PATH" bash "$SCRIPT_DIR/../scripts/promote-endpoints.sh" --region "$REGION" --project "$PROJECT_NAME" --env "$ENV_NAME" || \
    echo -e "${YELLOW}  (엔드포인트 승격 건너뜀 — scripts/promote-endpoints.sh 수동 실행 가능)${NC}"

# ── Done ──────────────────────────────────────────────────────────
# NOTE: Agent ARNs/Qualifiers are injected into Host Agent Lambda automatically
# via CDK cross-stack references in AgentCoreStack. No manual Step 7 needed.
echo ""
echo -e "${GREEN}=== Deployment Complete ===${NC}"

API_ENDPOINT=$(aws cloudformation describe-stacks --stack-name "$INFRA_STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" \
    --output text --region "$REGION" 2>/dev/null || echo "N/A")

CF_DOMAIN=$(aws cloudformation describe-stacks --stack-name "$INFRA_STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='CloudFrontDomain'].OutputValue" \
    --output text --region "$REGION" 2>/dev/null || echo "N/A")

echo -e "  API:        ${CYAN}${API_ENDPOINT}${NC}"
echo -e "  CloudFront: ${CYAN}https://${CF_DOMAIN}${NC}"
echo ""
echo -e "${YELLOW}Next: Create a Cognito user:${NC}"
echo -e "  aws cognito-idp admin-create-user --user-pool-id ${USER_POOL_ID} --username admin@example.com --region ${REGION}"
