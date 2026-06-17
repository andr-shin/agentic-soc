"""CloudTrail 기반 위협 헌팅 도구 — 가설별 TTP 패턴을 CloudTrail 로그(LogsQL)에서 능동 추적.
GuardDuty finding이 없어도 공격자 행위(계정 이상·권한 상승·로깅 무력화)를 직접 사냥한다.
MITRE ATT&CK for Cloud 매핑 기준."""
from strands import tool

from tools.logs_common import run_insights_query


@tool
def hunt_cloudtrail_ttp(hypothesis: str = "credential_access", minutes: int = 1440,
                        principal: str = "", source_ip: str = "") -> dict:
    """CloudTrail 로그에서 가설별 공격자 TTP를 헌팅한다 (MITRE ATT&CK for Cloud).
    Parameters:
      hypothesis: 헌팅 가설 — 다음 중 하나:
        'credential_access'   : 콘솔 로그인 실패 폭주 / 루트 사용 (T1110 Brute Force, T1078 Valid Accounts)
        'new_credentials'     : 신규 AccessKey/User/LoginProfile 생성 (T1136 Create Account, 지속성)
        'privilege_escalation': IAM 정책 부착/인라인 정책/AssumeRole 버스트 (T1098, T1548)
        'defense_evasion'     : CloudTrail StopLogging/DeleteTrail, GuardDuty/Config 비활성 (T1562 Impair Defenses)
        'recon'               : Describe/List 대량 호출(정찰) (T1580 Cloud Infra Discovery)
      minutes: 조회 시간범위(분, 기본 1440=24h)
      principal: 특정 IAM 주체 ARN으로 한정(선택)
      source_ip: 특정 소스 IP로 한정(선택)
    반환: {hypothesis, mitre, rows, count} 또는 {error}
    """
    # 공통 필터(주체/IP 한정)
    extra = []
    if principal:
        extra.append(f'userIdentity.arn like "{principal}"')
    if source_ip:
        extra.append(f'sourceIPAddress = "{source_ip}"')
    extra_filter = (' and ' + ' and '.join(extra)) if extra else ''

    H = hypothesis.lower()
    if H == 'credential_access':
        mitre = 'T1110 Brute Force / T1078 Valid Accounts'
        query = (
            'filter eventName = "ConsoleLogin"' + extra_filter + '\n'
            '| fields sourceIPAddress, userIdentity.arn, errorMessage, '
            'responseElements.ConsoleLogin as result, awsRegion\n'
            '| stats count(*) as attempts, '
            'count(result="Failure" or errorMessage like /Failed/) as failures by sourceIPAddress, userIdentity.arn\n'
            '| sort failures desc'
        )
    elif H == 'new_credentials':
        mitre = 'T1136 Create Account / 지속성(persistence)'
        query = (
            'filter eventName in ["CreateAccessKey","CreateUser","CreateLoginProfile",'
            '"UpdateLoginProfile","CreateServiceSpecificCredential"]' + extra_filter + '\n'
            '| fields eventTime, eventName, userIdentity.arn, sourceIPAddress, '
            'requestParameters.userName as target_user\n'
            '| sort eventTime desc'
        )
    elif H == 'privilege_escalation':
        mitre = 'T1098 Account Manipulation / T1548 Privilege Escalation'
        query = (
            'filter eventName in ["AttachUserPolicy","AttachRolePolicy","PutUserPolicy",'
            '"PutRolePolicy","CreatePolicyVersion","AddUserToGroup","AssumeRole",'
            '"UpdateAssumeRolePolicy"]' + extra_filter + '\n'
            '| fields eventTime, eventName, userIdentity.arn, sourceIPAddress, '
            'requestParameters.policyArn as policy, awsRegion\n'
            '| stats count(*) as cnt by userIdentity.arn, eventName | sort cnt desc'
        )
    elif H == 'defense_evasion':
        mitre = 'T1562 Impair Defenses'
        query = (
            'filter eventName in ["StopLogging","DeleteTrail","UpdateTrail",'
            '"DeleteDetector","DisableSecurityHub","StopMonitoringMembers",'
            '"DeleteFlowLogs","PutEventSelectors","LeaveOrganization"]' + extra_filter + '\n'
            '| fields eventTime, eventName, userIdentity.arn, sourceIPAddress, awsRegion\n'
            '| sort eventTime desc'
        )
    elif H == 'recon':
        mitre = 'T1580 Cloud Infrastructure Discovery'
        query = (
            'filter (eventName like /^Describe/ or eventName like /^List/ or eventName like /^Get/)'
            + extra_filter + '\n'
            '| stats count(*) as api_calls, count_distinct(eventName) as distinct_apis '
            'by userIdentity.arn, sourceIPAddress\n'
            '| sort distinct_apis desc'
        )
    else:
        return {'error': f'알 수 없는 가설: {hypothesis}. credential_access/new_credentials/'
                         'privilege_escalation/defense_evasion/recon 중 선택.'}

    res = run_insights_query('cloudtrail', query, minutes=minutes)
    if 'error' in res:
        return {'hypothesis': hypothesis, 'mitre': mitre, **res}
    return {'hypothesis': hypothesis, 'mitre': mitre, 'log_group': res['log_group'],
            'minutes': minutes, 'rows': res['rows'], 'count': res['count']}
