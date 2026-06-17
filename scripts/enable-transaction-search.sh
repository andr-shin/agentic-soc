#!/usr/bin/env bash
#
# X-Ray Transaction Search 활성화 — 분산 트레이스 span을 CloudWatch Logs(`aws/spans`)로 수집.
#
# 왜 필요한가: 기본 X-Ray는 span을 X-Ray 백엔드에 저장해 trace_sampled=True여도 `aws/spans`
# 로그그룹에 구조화 로그가 쌓이지 않는다. 에이전트 라우팅/오류를 실제 trace 로그로 디버깅하려면
# (1) trace segment 목적지를 CloudWatchLogs로 바꾸고 (2) X-Ray 서비스가 aws/spans 로그그룹에
# 쓸 수 있게 resource policy를 허용해야 한다. 둘 다 멱등 — 이미 설정돼 있으면 변화 없음.
#
# 앱 동작에는 영향 없는 '관측성(디버깅)' 기능이므로 선택사항이다.
#
# 사용법:
#   ./scripts/enable-transaction-search.sh [--region REGION]
#
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
REGION="${AWS_DEFAULT_REGION:-ap-northeast-2}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        -h|--help) echo "Usage: $0 [--region REGION]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "${GREEN}=== X-Ray Transaction Search 활성화 ===${NC}"
echo "  Account: $ACCOUNT_ID / Region: $REGION"
echo ""

# ── 1. CloudWatch Logs resource policy — X-Ray가 aws/spans에 PutLogEvents 허용 ──
# AWS 콘솔이 자동 생성하는 표준 정책(TransactionSearchXRayAccess)과 동일 형태.
echo -e "${CYAN}[1/2] aws/spans resource policy 설정...${NC}"
POLICY_DOC=$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TransactionSearchXRayAccess",
      "Effect": "Allow",
      "Principal": { "Service": "xray.amazonaws.com" },
      "Action": "logs:PutLogEvents",
      "Resource": [
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:aws/spans:*",
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:/aws/application-signals/data:*"
      ],
      "Condition": {
        "StringEquals": { "aws:SourceAccount": "${ACCOUNT_ID}" },
        "ArnLike": { "aws:SourceArn": "arn:aws:xray:${REGION}:${ACCOUNT_ID}:*" }
      }
    }
  ]
}
JSON
)
aws logs put-resource-policy \
    --region "$REGION" \
    --policy-name "TransactionSearchXRayAccess" \
    --policy-document "$POLICY_DOC" >/dev/null
echo -e "  ${GREEN}resource policy 설정됨${NC}"

# ── 2. Trace segment 목적지를 CloudWatchLogs로 ──
echo -e "${CYAN}[2/2] trace segment 목적지를 CloudWatchLogs로...${NC}"
aws xray update-trace-segment-destination \
    --region "$REGION" \
    --destination CloudWatchLogs >/dev/null
echo -e "  ${GREEN}목적지 = CloudWatchLogs${NC}"

echo ""
DEST=$(aws xray get-trace-segment-destination --region "$REGION" --query "{dest:Destination,status:Status}" --output text 2>/dev/null || echo "?")
echo -e "${GREEN}완료.${NC} 현재 목적지/상태: ${DEST}"
echo -e "${YELLOW}(span은 호출이 발생해야 aws/spans 로그그룹에 쌓이기 시작합니다)${NC}"
