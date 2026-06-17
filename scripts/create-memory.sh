#!/bin/bash
# =============================================================================
# AgentCore Memory Resource Creation Script
# v8.0: Creates AgentCore Memory with 3 long-term memory strategies
# =============================================================================
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Defaults
REGION="${AWS_DEFAULT_REGION:-ap-northeast-2}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
PROJECT_NAME="${PROJECT_NAME:-agentic-soc}"
MEMORY_NAME=$(echo "${PROJECT_NAME}_${ENVIRONMENT}_memory" | tr '-' '_')
EVENT_EXPIRY_DURATION=90

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Creates an AgentCore Memory resource with long-term memory strategies."
    echo ""
    echo "Options:"
    echo "  --region REGION          AWS region (default: ap-northeast-2)"
    echo "  --environment ENV        Environment name (default: dev)"
    echo "  --project-name NAME      Project name (default: agentic-soc)"
    echo "  --event-expiry DAYS      Event expiry in days (default: 90)"
    echo "  --stack-name NAME        CloudFormation stack name (to auto-update MEMORY_ID)"
    echo "  -h, --help               Show this help"
    echo ""
    echo "After creation, set the MEMORY_ID environment variable on:"
    echo "  1. Lambda function (via CloudFormation or aws lambda update-function-configuration)"
    echo "  2. Host Agent AgentCore Runtime (via aws bedrock-agentcore-control update-agent-runtime)"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --environment) ENVIRONMENT="$2"; shift 2 ;;
        --project-name) PROJECT_NAME="$2"; shift 2 ;;
        --event-expiry) EVENT_EXPIRY_DURATION="$2"; shift 2 ;;
        --stack-name) STACK_NAME="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; usage; exit 1 ;;
    esac
done

MEMORY_NAME=$(echo "${PROJECT_NAME}_${ENVIRONMENT}_memory" | tr '-' '_')

echo -e "${GREEN}=== AgentCore Memory Creation ===${NC}"
echo "Region:       $REGION"
echo "Memory Name:  $MEMORY_NAME"
echo "Event Expiry: ${EVENT_EXPIRY_DURATION} days"
echo ""

# Check if memory already exists
echo -e "${YELLOW}Checking for existing memory...${NC}"
EXISTING=$(aws bedrock-agentcore-control list-memories \
    --region "$REGION" \
    --query "memories[?contains(id, '${MEMORY_NAME}')].id | [0]" \
    --output text 2>/dev/null || true)

if [ -n "$EXISTING" ] && [ "$EXISTING" != "None" ]; then
    echo -e "${YELLOW}Memory already exists: ${EXISTING}${NC}"
    MEMORY_ID="$EXISTING"
else
    echo -e "${YELLOW}Creating AgentCore Memory...${NC}"

    # Create memory with 3 strategies (SOC framing):
    # 1. SecurityKnowledge: Extract assets, threat intel, observed indicators from investigations
    # 2. AnalystPreference: Learn analyst workflow preferences
    # 3. InvestigationSummarizer: Summarize past investigation/incident sessions
    RESULT=$(aws bedrock-agentcore-control create-memory \
        --region "$REGION" \
        --name "$MEMORY_NAME" \
        --event-expiry-duration "$EVENT_EXPIRY_DURATION" \
        --memory-strategies '[
            {
                "semanticMemoryStrategy": {
                    "name": "SecurityKnowledge",
                    "namespaces": ["/facts/{actorId}/"]
                }
            },
            {
                "userPreferenceMemoryStrategy": {
                    "name": "AnalystPreference",
                    "namespaces": ["/preferences/{actorId}/"]
                }
            },
            {
                "summaryMemoryStrategy": {
                    "name": "InvestigationSummarizer",
                    "namespaces": ["/summaries/{actorId}/{sessionId}/"]
                }
            }
        ]' \
        --output json)

    # create-memory returns {"memory": {"id": ...}}; fall back to top-level "id" for older API
    MEMORY_ID=$(echo "$RESULT" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('memory',{}).get('id') or d['id'])")
    echo -e "${GREEN}Memory created successfully!${NC}"
fi

echo ""
echo -e "${GREEN}=== Memory ID ===${NC}"
echo "$MEMORY_ID"
echo ""

# Update Lambda if stack name provided
if [ -n "${STACK_NAME:-}" ]; then
    echo -e "${YELLOW}Updating Lambda MEMORY_ID...${NC}"
    LAMBDA_NAME="${STACK_NAME}-host-agent"

    # Get current env vars
    CURRENT_ENV=$(aws lambda get-function-configuration \
        --function-name "$LAMBDA_NAME" \
        --region "$REGION" \
        --query 'Environment.Variables' \
        --output json 2>/dev/null || echo '{}')

    # Add/update MEMORY_ID
    UPDATED_ENV=$(echo "$CURRENT_ENV" | python3 -c "
import sys, json
env = json.load(sys.stdin)
env['MEMORY_ID'] = '$MEMORY_ID'
print(json.dumps({'Variables': env}))
")

    aws lambda update-function-configuration \
        --function-name "$LAMBDA_NAME" \
        --region "$REGION" \
        --environment "$UPDATED_ENV" \
        --output text --query 'FunctionName' > /dev/null

    echo -e "${GREEN}Lambda updated: ${LAMBDA_NAME}${NC}"
fi

echo ""
echo -e "${GREEN}=== Next Steps ===${NC}"
echo "권장: MEMORY_ID를 CDK context로 주입해 재배포하면 host-agent Lambda + chat 런타임 env에"
echo "      한 번에 안전하게 반영됩니다(수동 update-agent-runtime 불필요 — JWT/env 보존)."
echo ""
echo "   MEMORY_ID=${MEMORY_ID} ./cdk/deploy.sh ${ENVIRONMENT} ${PROJECT_NAME} ${REGION}"
echo ""
echo "   (인프라/에이전트 스택만 따로:"
echo "     cd cdk && MEMORY_ID 대신 -c memory_id=${MEMORY_ID} 를 cdk deploy에 전달)"
echo ""
echo "이후 채팅 메시지를 보내고 AgentCore Memory 이벤트가 쌓이는지로 검증하세요."
