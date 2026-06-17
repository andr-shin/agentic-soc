"""Threat Hunting Agent Tools — 로그/텔레메트리 기반 가설 주도 위협 헌팅.
CloudTrail(계정·권한·로깅 TTP), DNS(C2/터널링), VPC Flow(egress 이상)를 교차해 침입 흔적을 능동 추적하고,
발견된 행위를 MITRE ATT&CK로 태깅한다. 설정 스캔(Posture)이 아니라 '이미 침입했다'는 가정의 로그 헌팅."""
from tools.cloudtrail_hunt import hunt_cloudtrail_ttp
from tools.dns_hunt import hunt_dns_threats, hunt_egress_anomaly
from tools.free_query import list_hunt_sources, run_hunt_query
from tools.threat_intel import check_iocs, refresh_threat_feeds
from tools.mitre import map_to_mitre

ALL_TOOLS = [
    hunt_cloudtrail_ttp,
    hunt_dns_threats,
    hunt_egress_anomaly,
    list_hunt_sources,
    run_hunt_query,
    check_iocs,
    refresh_threat_feeds,
    map_to_mitre,
]


def get_all_tools():
    return ALL_TOOLS
