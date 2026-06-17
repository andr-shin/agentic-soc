"""DNS / 네트워크 기반 위협 헌팅 — C2 비콘, DNS 터널링/exfiltration, 비정상 egress 추적.
Route53 Resolver 쿼리 로그 + VPC Flow Logs를 교차해 공격자의 명령제어·데이터 유출 흔적을 사냥한다."""
from strands import tool

from tools.logs_common import run_insights_query


@tool
def hunt_dns_threats(hypothesis: str = "rare_domains", minutes: int = 1440, srcaddr: str = "") -> dict:
    """Route53 Resolver DNS 쿼리 로그에서 C2/exfiltration 흔적을 헌팅 (MITRE ATT&CK).
    Parameters:
      hypothesis: 헌팅 가설 —
        'rare_domains'  : 조회 빈도 낮은 희귀 도메인 — C2 후보 (T1071 Application Layer Protocol)
        'high_volume'   : 특정 출발지의 DNS 쿼리 폭증 — DNS 터널링/exfil 의심 (T1048 Exfiltration, T1071.004 DNS)
        'nxdomain_burst': NXDOMAIN(rcode) 폭주 — DGA(도메인 생성 알고리즘) 의심 (T1568.002)
      minutes: 시간범위(분, 기본 24h)
      srcaddr: 특정 출발지 IP로 한정(선택)
    반환: {hypothesis, mitre, rows, count} 또는 {error}
    """
    extra = f' and srcaddr = "{srcaddr}"' if srcaddr else ''
    H = hypothesis.lower()
    if H == 'rare_domains':
        mitre = 'T1071 Application Layer Protocol (C2 비콘 후보)'
        # 조회 횟수가 적은(=희귀) 도메인 — 정상 트래픽에 묻히지 않는 C2 후보
        query = (
            'filter query_name like /./' + extra + '\n'
            '| stats count(*) as queries, count_distinct(srcaddr) as distinct_srcs by query_name\n'
            '| sort queries asc'
        )
    elif H == 'high_volume':
        mitre = 'T1048 Exfiltration Over Alternative Protocol / T1071.004 DNS'
        query = (
            'filter query_name like /./' + extra + '\n'
            '| stats count(*) as queries, count_distinct(query_name) as distinct_domains by srcaddr\n'
            '| sort queries desc'
        )
    elif H == 'nxdomain_burst':
        mitre = 'T1568.002 Domain Generation Algorithms'
        query = (
            'filter rcode = "NXDOMAIN"' + extra + '\n'
            '| stats count(*) as nxdomain_count, count_distinct(query_name) as distinct_failed by srcaddr\n'
            '| sort nxdomain_count desc'
        )
    else:
        return {'error': f'알 수 없는 가설: {hypothesis}. rare_domains/high_volume/nxdomain_burst 중 선택.'}

    res = run_insights_query('dns-queries', query, minutes=minutes)
    if 'error' in res:
        return {'hypothesis': hypothesis, 'mitre': mitre, **res}
    return {'hypothesis': hypothesis, 'mitre': mitre, 'log_group': res['log_group'],
            'minutes': minutes, 'rows': res['rows'], 'count': res['count']}


@tool
def hunt_egress_anomaly(minutes: int = 1440, srcaddr: str = "", min_bytes: int = 0) -> dict:
    """VPC Flow Logs에서 비정상 아웃바운드(egress) 데이터 전송을 헌팅 — 대용량 유출/희귀 포트 C2.
    (MITRE T1048 Exfiltration / T1571 Non-Standard Port)
    Parameters:
      minutes: 시간범위(분, 기본 24h)
      srcaddr: 특정 내부 출발지 IP로 한정(선택)
      min_bytes: 이 바이트 이상 전송만(선택, 기본 0)
    반환: {rows(목적지별 전송량/포트), count} 또는 {error}
    """
    clauses = ['action = "ACCEPT"']
    if srcaddr:
        clauses.append(f'srcAddr = "{srcaddr}"')
    filter_clause = 'filter ' + ' and '.join(clauses)
    query = (
        f'{filter_clause}\n'
        '| stats sum(bytes) as total_bytes, count(*) as flows by srcAddr, dstAddr, dstPort\n'
        '| sort total_bytes desc'
    )
    res = run_insights_query('vpc-flowlogs', query, minutes=minutes)
    if 'error' in res:
        return {'mitre': 'T1048 / T1571', **res}
    rows = res['rows']
    if min_bytes:
        rows = [r for r in rows if int(r.get('total_bytes', 0) or 0) >= min_bytes]
    return {'mitre': 'T1048 Exfiltration / T1571 Non-Standard Port', 'log_group': res['log_group'],
            'minutes': minutes, 'rows': rows, 'count': len(rows)}
