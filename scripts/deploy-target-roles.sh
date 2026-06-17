#!/bin/bash
# =============================================================================
# AgenticSOC - Target Account Role Deployment Script
# =============================================================================
# 이 스크립트는 타겟 계정에 cross-account 읽기 전용 역할을 배포합니다.
# 각 타겟 계정에서 실행하거나, 중앙 계정에서 AWS Organizations 권한으로 실행할 수 있습니다.
#
# 사용법:
#   # 단일 계정에 배포 (해당 계정의 AWS 자격증명이 설정된 상태에서)
#   ./deploy-target-roles.sh --central-account-id 123456789012
#
#   # 여러 계정에 일괄 배포 (Organizations 관리 계정에서)
#   ./deploy-target-roles.sh --central-account-id 123456789012 \
#     --target-accounts "111111111111,222222222222,333333333333"
#
#   # StackSets로 Organizations 전체 배포
#   ./deploy-target-roles.sh --central-account-id 123456789012 --use-stacksets
# =============================================================================

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
CENTRAL_ACCOUNT_ID=""
TARGET_ACCOUNTS=""
ROLE_NAME="AgenticSOC-ReadOnly"
CENTRAL_ROLE_NAME=""
REGION="ap-northeast-2"
STACK_NAME="agentic-soc-target-role"
TEMPLATE_FILE="../templates/target-account-role.yaml"
USE_STACKSETS=false

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --central-account-id ID    (Required) AgenticSOC 중앙 계정 ID"
    echo "  --target-accounts IDs      타겟 계정 ID 목록 (콤마 구분, Organizations 관리 계정에서 실행 시)"
    echo "  --role-name NAME           생성할 역할 이름 (기본: AgenticSOC-ReadOnly)"
    echo "  --central-role-name NAME   중앙 계정 역할 이름 (선택)"
    echo "  --region REGION            배포 리전 (기본: ap-northeast-2)"
    echo "  --stack-name NAME          스택 이름 (기본: agentic-soc-target-role)"
    echo "  --template FILE            템플릿 파일 경로 (기본: ../templates/target-account-role.yaml)"
    echo "  --use-stacksets            StackSets로 Organizations 전체 배포"
    echo "  -h, --help                 도움말"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --central-account-id) CENTRAL_ACCOUNT_ID="$2"; shift 2;;
        --target-accounts) TARGET_ACCOUNTS="$2"; shift 2;;
        --role-name) ROLE_NAME="$2"; shift 2;;
        --central-role-name) CENTRAL_ROLE_NAME="$2"; shift 2;;
        --region) REGION="$2"; shift 2;;
        --stack-name) STACK_NAME="$2"; shift 2;;
        --template) TEMPLATE_FILE="$2"; shift 2;;
        --use-stacksets) USE_STACKSETS=true; shift;;
        -h|--help) usage;;
        *) echo -e "${RED}Unknown option: $1${NC}"; usage;;
    esac
done

# Validate required params
if [[ -z "$CENTRAL_ACCOUNT_ID" ]]; then
    echo -e "${RED}Error: --central-account-id is required${NC}"
    usage
fi

if [[ ! "$CENTRAL_ACCOUNT_ID" =~ ^[0-9]{12}$ ]]; then
    echo -e "${RED}Error: Central Account ID must be 12 digits${NC}"
    exit 1
fi

# Check template file exists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$TEMPLATE_FILE" == ../* ]]; then
    TEMPLATE_FILE="$SCRIPT_DIR/$TEMPLATE_FILE"
fi
if [[ ! -f "$TEMPLATE_FILE" ]]; then
    echo -e "${RED}Error: Template file not found: $TEMPLATE_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}AgenticSOC Target Account Role Deployment${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "Central Account: ${YELLOW}$CENTRAL_ACCOUNT_ID${NC}"
echo -e "Role Name: ${YELLOW}$ROLE_NAME${NC}"
echo -e "Region: ${YELLOW}$REGION${NC}"
echo ""

deploy_single_account() {
    echo -e "${GREEN}Deploying to current account...${NC}"
    CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    echo -e "Current Account: ${YELLOW}$CURRENT_ACCOUNT${NC}"

    PARAMS="ParameterKey=CentralAccountId,ParameterValue=$CENTRAL_ACCOUNT_ID"
    PARAMS="$PARAMS ParameterKey=RoleName,ParameterValue=$ROLE_NAME"
    if [[ -n "$CENTRAL_ROLE_NAME" ]]; then
        PARAMS="$PARAMS ParameterKey=CentralRoleName,ParameterValue=$CENTRAL_ROLE_NAME"
    fi

    aws cloudformation deploy \
        --template-file "$TEMPLATE_FILE" \
        --stack-name "$STACK_NAME" \
        --parameter-overrides $PARAMS \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION" \
        --no-fail-on-empty-changeset

    echo ""
    echo -e "${GREEN}Deployment complete!${NC}"
    ROLE_ARN=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" \
        --output text)
    echo -e "Role ARN: ${YELLOW}$ROLE_ARN${NC}"
    echo ""
    echo -e "${GREEN}Next step:${NC} Add account ${YELLOW}$CURRENT_ACCOUNT${NC} to the central stack's TargetAccountIds parameter."
}

deploy_to_multiple_accounts() {
    IFS=',' read -ra ACCOUNTS <<< "$TARGET_ACCOUNTS"
    echo -e "Target Accounts: ${YELLOW}${ACCOUNTS[*]}${NC}"
    echo ""

    SUCCEEDED=()
    FAILED=()

    for ACCOUNT_ID in "${ACCOUNTS[@]}"; do
        ACCOUNT_ID=$(echo "$ACCOUNT_ID" | tr -d ' ')
        echo -e "${YELLOW}--- Deploying to account: $ACCOUNT_ID ---${NC}"

        # Assume role in target account (requires Organizations permissions)
        ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/OrganizationAccountAccessRole"
        CREDS=$(aws sts assume-role \
            --role-arn "$ROLE_ARN" \
            --role-session-name "agentic-soc-deploy-${ACCOUNT_ID}" \
            --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
            --output text 2>/dev/null) || {
            echo -e "${RED}  Failed to assume role in $ACCOUNT_ID (OrganizationAccountAccessRole not available)${NC}"
            FAILED+=("$ACCOUNT_ID")
            continue
        }

        export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | awk '{print $1}')
        export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | awk '{print $2}')
        export AWS_SESSION_TOKEN=$(echo "$CREDS" | awk '{print $3}')

        PARAMS="ParameterKey=CentralAccountId,ParameterValue=$CENTRAL_ACCOUNT_ID"
        PARAMS="$PARAMS ParameterKey=RoleName,ParameterValue=$ROLE_NAME"
        if [[ -n "$CENTRAL_ROLE_NAME" ]]; then
            PARAMS="$PARAMS ParameterKey=CentralRoleName,ParameterValue=$CENTRAL_ROLE_NAME"
        fi

        aws cloudformation deploy \
            --template-file "$TEMPLATE_FILE" \
            --stack-name "$STACK_NAME" \
            --parameter-overrides $PARAMS \
            --capabilities CAPABILITY_NAMED_IAM \
            --region "$REGION" \
            --no-fail-on-empty-changeset 2>/dev/null && {
            echo -e "${GREEN}  Success: $ACCOUNT_ID${NC}"
            SUCCEEDED+=("$ACCOUNT_ID")
        } || {
            echo -e "${RED}  Failed: $ACCOUNT_ID${NC}"
            FAILED+=("$ACCOUNT_ID")
        }

        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "Results:"
    echo -e "  Succeeded: ${GREEN}${#SUCCEEDED[@]}${NC} - ${SUCCEEDED[*]:-none}"
    echo -e "  Failed: ${RED}${#FAILED[@]}${NC} - ${FAILED[*]:-none}"
    echo ""
    if [[ ${#SUCCEEDED[@]} -gt 0 ]]; then
        echo -e "${GREEN}Next step:${NC} Add these account IDs to the central stack's TargetAccountIds parameter:"
        echo -e "${YELLOW}$(IFS=,; echo "${SUCCEEDED[*]}")${NC}"
    fi
}

deploy_with_stacksets() {
    echo -e "${GREEN}Deploying with CloudFormation StackSets...${NC}"

    STACKSET_NAME="agentic-soc-target-roles"

    # Create or update StackSet
    aws cloudformation create-stack-set \
        --stack-set-name "$STACKSET_NAME" \
        --template-body "file://$TEMPLATE_FILE" \
        --parameters \
            ParameterKey=CentralAccountId,ParameterValue="$CENTRAL_ACCOUNT_ID" \
            ParameterKey=RoleName,ParameterValue="$ROLE_NAME" \
        --capabilities CAPABILITY_NAMED_IAM \
        --permission-model SERVICE_MANAGED \
        --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
        --region "$REGION" 2>/dev/null || {
        echo -e "${YELLOW}StackSet already exists, updating...${NC}"
        aws cloudformation update-stack-set \
            --stack-set-name "$STACKSET_NAME" \
            --template-body "file://$TEMPLATE_FILE" \
            --parameters \
                ParameterKey=CentralAccountId,ParameterValue="$CENTRAL_ACCOUNT_ID" \
                ParameterKey=RoleName,ParameterValue="$ROLE_NAME" \
            --capabilities CAPABILITY_NAMED_IAM \
            --region "$REGION"
    }

    echo -e "${GREEN}StackSet deployed: $STACKSET_NAME${NC}"
    echo -e "The role will be automatically deployed to all Organization member accounts."
    echo -e "New accounts will automatically receive the role on creation."
}

# Main execution
if [[ "$USE_STACKSETS" == true ]]; then
    deploy_with_stacksets
elif [[ -n "$TARGET_ACCOUNTS" ]]; then
    deploy_to_multiple_accounts
else
    deploy_single_account
fi
