# Agentic SOC on AWS

Amazon Bedrock AgentCore 기반 **Agentic SOC(보안 운영 센터)**. AWS 네이티브 탐지 서비스
(GuardDuty / Security Hub / Inspector)의 finding과 로그(CloudTrail / VPC Flow / DNS)를 에이전틱 AI로 연결하여
**탐지 → 트리아지 → 조사 → 위협 헌팅 → (승인 후) 자동 대응** 루프를 구축합니다.

AWS 네이티브 보안 시그널과 Bedrock AgentCore, Strands Agents를 결합하면 별도 도구 없이도
보안 운영 센터를 구성할 수 있습니다. 자세한 설계는 [docs/AGENTIC_SOC_DESIGN.md](./docs/AGENTIC_SOC_DESIGN.md)를 참고하세요.

<img width="1712" height="871" alt="image" src="https://github.com/user-attachments/assets/f4442020-0a66-40b5-85a8-1273ae226497" />

## 주요 기능

- **AI Agentic 채팅**: Host Agent 오케스트레이터가 자연어 질의를 6개 보안 Sub-Agent로 라우팅
- **Findings 대시보드**: GuardDuty/Security Hub/Inspector finding 수집·정규화·트리아지 (acknowledge/resolve)
- **위협 조사 (Investigation)**: GuardDuty finding 파싱, CloudTrail 상관 분석, VPC Flow 포렌식, MITRE ATT&CK 매핑
- **Posture 분석 (Hunting)**: Steampipe SQL로 리소스 '설정' 약점(IAM 과다권한·노출 SG·미암호화·MFA 미설정)·공격 경로 탐색 (CSPM 보완)
- **위협 헌팅 (Threat Hunting)**: CloudTrail/DNS/VPC Flow 로그를 교차해 공격자 '행위'·흔적(로그인 폭주·권한상승·C2·exfil)을 MITRE 가설로 추적, abuse.ch IOC 평판 대조 (assume breach)
- **로그 분석 (Log Explorer)**: CloudWatch Unified Data Store에 자연어→LogsQL 변환·실행
- **자동 대응 (SOAR)**: 알림/태스크는 즉시 실행, 격리/SG차단/IAM revoke는 **분석가 승인 게이트** 후 실행
- **컨텍스트 메모리**: AgentCore Memory로 자산·위협 인텔·과거 조사 세션 기억

## 아키텍처

<img width="1291" height="629" alt="image" src="https://github.com/user-attachments/assets/1500697e-f933-4c2d-b798-13054dc183f5" />

## 빠른 시작

### 사전 요구사항

- **Node.js 18+**, **Python 3.11+**, **AWS CLI v2** (관리자 권한 자격증명), `jq`
- **AWS CDK CLI — 검증된 버전 2.1126.0** (`npm install -g aws-cdk@2.1126.0`)
  > ⚠️ 구버전 CDK CLI(예: 2.1100.x)는 스키마 불일치로 `cdk deploy`가 실패할 수 있습니다.
  > `cdk --version`으로 확인하고, 다른 `cdk`가 PATH에 먼저 잡히면 `which -a cdk`로 점검하세요.
- **Amazon Bedrock Claude 모델 사용 가능 여부** — 본 프로젝트는 **Claude Sonnet 4.6**(조사·합성)과
  **Claude Haiku 4.5**(경량 분류)를 cross-region inference profile(`global.anthropic.*` / `us.anthropic.*`)로
  호출합니다. 해당 프로필이 배포 리전·계정에서 호출 가능한지 확인하세요:
  ```bash
  aws bedrock list-inference-profiles --region "$REGION" \
    --query "inferenceProfileSummaries[?contains(inferenceProfileId,'claude-sonnet-4-6') || contains(inferenceProfileId,'claude-haiku-4-5')].inferenceProfileId" --output text
  ```
- **AgentCore 지원 리전** — Bedrock AgentCore는 일부 리전에서만 GA입니다. 본 프로젝트는
  **ap-northeast-2**에서 검증됐습니다. 다른 리전 배포 시 AgentCore/Claude 모델 가용성을 먼저 확인하세요
  (미지원 리전에서는 AgentCoreStack이 실패합니다).
- **보안 신호 소스 활성화** — finding은 EventBridge를 통해 다음 탐지 서비스에서 자동 수집·정규화됩니다.
  웹앱에 finding이 보이려면 대상 계정에 **하나 이상** 활성화되어 있어야 하며, **최소 GuardDuty**는 켜는 것을 권장합니다.
  - **Amazon GuardDuty** (권장 — 가장 풍부한 위협 탐지 신호)
  - **AWS Security Hub** (Consolidated Findings — GuardDuty/Inspector/Macie 등을 집계)
  - **Amazon Inspector** (취약점 finding)
  > CloudTrail은 finding 소스가 아니라 **감사 로그**입니다. Investigation·Log Query 에이전트가
  > 조사 단계에서 로그로 활용하며, finding 목록에는 나타나지 않습니다.

> 로컬 Docker 불필요 — 에이전트 이미지는 AWS CodeBuild(ARM64)에서 자동 빌드됩니다.

> **배포 변수 (한 번만 설정)** — 아래 모든 명령은 이 세 변수를 참조합니다. 기본값 그대로 써도 되고,
> 회사/환경에 맞게 바꿔도 됩니다. **바꿀 경우 여기 한 곳만 고치면** 이후 명령이 모두 일관되게 동작합니다.
> 새 터미널을 열면 다시 `export` 하세요.
>
> ```bash
> export ENV=dev                # 환경 이름 (dev / staging / prod ...)
> export PROJECT=agentic-soc    # 프로젝트(=리소스 접두어) 이름
> export REGION=ap-northeast-2  # 배포 리전 (AgentCore/Claude 지원 리전)
> export STACK=$PROJECT-$ENV    # 스택 접두어 — 바꾸지 마세요(파생값)
> ```

### 1단계 — 기본 배포

```bash
# 배포 대상 계정 확인 (중요) — deploy.sh는 현재 AWS 자격증명이 가리키는 계정에 배포합니다.
# 여러 프로필을 쓴다면 AWS_PROFILE로 대상 계정을 명시하고, 출력 계정 ID가 맞는지 꼭 확인하세요.
#   export AWS_PROFILE=<대상-계정-프로필>
aws sts get-caller-identity --query Account --output text   # 의도한 계정 ID인지 확인

# CDK 의존성 (최초 1회)
cd cdk
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd ..

# 전체 배포 (CDK bootstrap → InfraStack → 프론트 빌드 → AgentCoreStack → S3 업로드
#           → default 엔드포인트 승격)
./cdk/deploy.sh "$ENV" "$PROJECT" "$REGION"
```

배포 완료 시 CloudFront URL과 Cognito User Pool ID가 출력됩니다.

```bash
# 출력된 User Pool ID를 변수로 받기 (또는 직접 붙여넣기)
export POOL_ID=$(aws cloudformation describe-stacks --stack-name "$STACK-infra" \
  --query "Stacks[0].Outputs[?OutputKey=='CognitoUserPoolId'].OutputValue" --output text --region "$REGION")

# Cognito 사용자 생성
aws cognito-idp admin-create-user \
  --user-pool-id "$POOL_ID" --username analyst@example.com \
  --user-attributes Name=email,Value=analyst@example.com Name=email_verified,Value=true \
  --message-action SUPPRESS --region "$REGION"

aws cognito-idp admin-set-user-password \
  --user-pool-id "$POOL_ID" --username analyst@example.com \
  --password 'YourPassword1!' --permanent --region "$REGION"
```

CloudFront URL로 접속해 로그인하면 대시보드/Findings가 동작합니다.

### 2단계 — 전체 기능 활성화 (권장)

기본 배포만으로 대시보드·조사·헌팅·채팅이 동작하지만, 아래 두 기능은 추가 리소스가 필요합니다.
각 스크립트가 ARN/ID를 출력하면, 그 값을 **환경변수로 주고 재배포**하면 CDK가 안전하게 주입합니다
(수동 `update-agent-runtime` 불필요 — JWT authorizer/env 자동 보존).

```bash
# (A) Log Explorer — 최신 boto3 Layer (CloudWatch Logs Data Sources API)
#     출력된 LayerVersionArn을 BOTO3_LAYER_ARN으로 사용
export BOTO3_LAYER_ARN=$(./scripts/build-boto3-layer.sh "$REGION" | tail -1 | tr -d ' ')

# (B) 컨텍스트 메모리 — AgentCore Memory 생성. 출력 끝에 MEMORY_ID가 표시됨
ENVIRONMENT="$ENV" PROJECT_NAME="$PROJECT" ./scripts/create-memory.sh --region "$REGION" --stack-name "$STACK"
export MEMORY_ID=<위 출력의 MEMORY_ID>

# (C) 두 값을 주입해 재배포 — host-agent Lambda + chat 런타임 env에 자동 반영
MEMORY_ID="$MEMORY_ID" BOTO3_LAYER_ARN="$BOTO3_LAYER_ARN" ./cdk/deploy.sh "$ENV" "$PROJECT" "$REGION"
```

**(선택) 트레이스 디버깅 — X-Ray Transaction Search**: 에이전트 라우팅/오류를 실제 분산 트레이스
로그(`aws/spans`)로 디버깅하려면 활성화합니다. 앱 동작에는 영향 없는 관측성 기능이며, 멱등 스크립트입니다.
(미설정 시 온보딩 Status의 "X-Ray Transaction Search" / "aws/spans resource policy"가 ⚠️로 표시됩니다.)

```bash
./scripts/enable-transaction-search.sh --region "$REGION"
# trace segment 목적지를 CloudWatchLogs로 전환 + X-Ray의 aws/spans PutLogEvents 권한 설정
```

### 3단계 — 멀티계정 위협 헌팅 (선택)

Posture/Threat Hunting이 **다른 계정**의 리소스를 읽으려면, 대상 계정마다 read-only 역할
(`AgenticSOC-ReadOnly`)을 배포해야 합니다. (단일 계정만 쓸 거면 생략 가능)

```bash
# 대상 계정 자격증명으로 실행 — CloudFormation StackSet 또는 단일 스택
# <SOC계정ID>는 위에서 배포한 중앙(SOC) 계정의 12자리 ID
./scripts/deploy-target-roles.sh --central-account-id <SOC계정ID>
# 상세 옵션: ./scripts/deploy-target-roles.sh --help  (templates/target-account-role.yaml)
```

### 업데이트 배포

```bash
# 전체 재배포 (코드 변경 후 — default 엔드포인트 승격까지 자동 수행)
# Memory/Layer를 이미 켰다면 그 변수도 함께 넘겨야 유지됩니다
MEMORY_ID="${MEMORY_ID:-}" BOTO3_LAYER_ARN="${BOTO3_LAYER_ARN:-}" ./cdk/deploy.sh "$ENV" "$PROJECT" "$REGION"

# 개별 스택만 (이 경우 엔드포인트 승격을 직접 실행)
cd cdk && source .venv/bin/activate
cdk deploy "$STACK-infra"     --context env="$ENV" --context project="$PROJECT" --context region="$REGION"
cdk deploy "$STACK-agentcore" --context env="$ENV" --context project="$PROJECT" --context region="$REGION"
cd .. && ./scripts/promote-endpoints.sh --region "$REGION" --project "$PROJECT" --env "$ENV"
```

> **AgentCore 엔드포인트 함정 (자동 처리됨)**: 런타임 코드를 재배포하면 새 버전이 생기지만, 호출에
> 쓰이는 소문자 `default` 엔드포인트의 `liveVersion`은 자동 갱신되지 않습니다. `deploy.sh`는 마지막에
> `scripts/promote-endpoints.sh`로 모든 런타임의 default 엔드포인트를 최신 버전으로 승격합니다(멱등).
> 개별 `cdk deploy`만 한 경우엔 이 스크립트를 직접 실행하세요.

<img width="555" height="735" alt="image" src="https://github.com/user-attachments/assets/2e451dcd-1e97-4cc4-9dba-e977542b8a28" />

## 디렉터리 구조

```
cdk/                         # CDK (InfraStack + AgentCoreStack), deploy.sh, config/agents.py
frontend/                    # React 대시보드 (Dashboard / Findings / Log Explorer / Task Board / Chat)
lambda/                      # REST API Lambda (findings, tasks, logs, conversations, reports)
event-processor/             # EventBridge→SNS 보안 finding 정규화 Lambda
soar-lambdas/                # SOAR 자동조치 Lambda (isolate-ec2 / block-sg / revoke-key / alert / task)
soc-host-agent-runtime/      # Host Agent (오케스트레이터 + 분류 라우팅)
investigation-agent-runtime/ # 보안 조사 (GuardDuty/CloudTrail/VPC Flow/MITRE)
hunting-agent-runtime/       # Posture 분석 (Steampipe SQL — 설정 약점)
threat-hunting-agent-runtime/# 위협 헌팅 (로그 기반 행위 추적 + IOC)
logquery-agent-runtime/      # 로그 질의 (CloudWatch Logs Insights)
response-agent-runtime/      # SOAR 대응 (승인 게이트)
report-agent-runtime/        # 보안 리포트 합성
scripts/                     # build-boto3-layer.sh, create-memory.sh, promote-endpoints.sh, enable-transaction-search.sh, deploy-target-roles.sh
templates/                   # target-account-role.yaml (멀티계정 read-only 롤)
docs/                        # AGENTIC_SOC_DESIGN.md (설계 문서)
```


## 기술 스택

- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, React Query
- **Backend**: AWS Lambda (Python), Amazon Bedrock, API Gateway
- **Agent**: Bedrock AgentCore Runtime, Strands Agents SDK
- **Infra**: AWS CDK, Aurora Serverless v2, DynamoDB, Cognito, CloudFront, EventBridge
- **분석**: Steampipe (579 AWS tables), CloudWatch Logs Insights
- **Observability**: AgentCore Observability (CloudWatch 메트릭/로그), ADOT 트레이스, SOAR 감사 로그

## 안전 설계 (SOAR)

고위험 조치(EC2 격리, 보안 그룹 규칙 차단, IAM 키 비활성화)는 **LLM이 직접 실행할 수 없습니다.**
Response Agent는 `propose_remediation`으로 `pending_approval` 태스크만 생성하고, 분석가가
Task Board에서 승인해야 SOAR Lambda가 실행합니다. SOAR Lambda도 `approved=true`가 없으면
고위험 액션을 2차 거부합니다. 모든 조치는 `SOAR_AUDIT` 구조화 로그로 감사 추적됩니다.
