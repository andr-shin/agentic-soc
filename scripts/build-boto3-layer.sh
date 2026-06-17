#!/usr/bin/env bash
#
# 최신 boto3/botocore를 Lambda Layer로 publish한다.
#
# 왜 필요한가: Lambda Python 3.11 런타임에 내장된 boto3는 오래되어 CloudWatch Logs
# Data Sources API (list_aggregate_log_group_summaries, groupBy=DATA_SOURCE_NAME_AND_TYPE)를
# 지원하지 않는다. 온보딩 Status의 '보안 로그 중앙화' 체크가 amazon_vpc.flow 같은 AWS
# 자동 데이터 소스 분류를 직접 읽으려면 boto3 1.43.24+ 가 필요하다.
#
# 사용법:
#   ./scripts/build-boto3-layer.sh [REGION]
# 출력된 LayerVersionArn을 CDK context로 주입해 배포:
#   npx cdk deploy AgenticSocDev-Infra -c boto3_layer_arn=<ARN>
#
set -euo pipefail

REGION="${1:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
LAYER_NAME="agentic-soc-boto3-latest"
BOTO3_VERSION="1.43.24"
BUILD_DIR="$(mktemp -d)"

# 사람이 읽는 진행 로그는 stderr로 — stdout 마지막 줄에는 순수 ARN만 남겨
# `export BOTO3_LAYER_ARN=$(... | tail -1)` 로 바로 캡처할 수 있게 한다.
echo "[1/3] boto3 ${BOTO3_VERSION} 설치 (python3.11 / x86_64)..." >&2
python3 -m pip install \
  --target "${BUILD_DIR}/python" \
  --python-version 3.11 \
  --only-binary=:all: \
  --implementation cp \
  --abi cp311 \
  --platform manylinux2014_x86_64 \
  "boto3==${BOTO3_VERSION}" "botocore==${BOTO3_VERSION}" >/dev/null

# 용량 절감: 캐시/메타데이터 제거
find "${BUILD_DIR}/python" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}/python" -name "*.dist-info" -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "[2/3] zip 생성..." >&2
( cd "${BUILD_DIR}" && zip -qr layer.zip python )

echo "[3/3] Layer publish (${REGION})..." >&2
ARN=$(aws lambda publish-layer-version \
  --region "${REGION}" \
  --layer-name "${LAYER_NAME}" \
  --description "boto3/botocore ${BOTO3_VERSION} — CloudWatch Logs Data Sources API 지원" \
  --license-info "Apache-2.0" \
  --compatible-runtimes python3.11 python3.12 \
  --compatible-architectures x86_64 \
  --zip-file "fileb://${BUILD_DIR}/layer.zip" \
  --query "LayerVersionArn" --output text)

rm -rf "${BUILD_DIR}"

# 사람이 읽는 안내는 stderr로
echo "" >&2
echo "✅ Layer publish 완료. 아래 ARN을 BOTO3_LAYER_ARN으로 사용하세요:" >&2
echo "   (예) MEMORY_ID=... BOTO3_LAYER_ARN=${ARN} ./cdk/deploy.sh \$ENV \$PROJECT \$REGION" >&2

# stdout 마지막 줄 = 순수 ARN (캡처용)
echo "${ARN}"
