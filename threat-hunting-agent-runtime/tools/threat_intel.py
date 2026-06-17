"""Threat Intelligence IOC 매칭 — 무료/키리스 공개 피드와 로그에서 추출한 지표(IP/도메인)를 대조.
행위 헌팅(hunt_*)이 '비정상 행동'을 찾는다면, 이 도구는 '알려진 악성 지표(IOC)'와의 일치를 찾는다.

피드(abuse.ch, API 키 불요):
  - Feodo Tracker: botnet C2 IP 블록리스트 (plain-text, 1 IP/line)
  - URLhaus: 활성 악성 URL 피드 (호스트/도메인 추출)
콜드스타트 후 메모리 캐시(TTL). 외부 호출 실패 시 graceful — IOC 없이 빈 매칭 반환."""
import logging
import os
import time
import urllib.request
from urllib.parse import urlparse

from strands import tool

logger = logging.getLogger("threat-hunting-agent.threat-intel")

_FEEDS = {
    'feodo_c2_ip': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    'urlhaus_urls': 'https://urlhaus.abuse.ch/downloads/text_online/',
}
_FETCH_TIMEOUT = int(os.environ.get('TI_FETCH_TIMEOUT', '8'))
_CACHE_TTL = int(os.environ.get('TI_CACHE_TTL', '3600'))  # 1h

# 캐시: {'ips': set, 'domains': set, 'fetched_at': float, 'errors': [...]}
_cache = {}


def _http_get(url: str) -> str:
    req = urllib.request.Request(url, headers={'User-Agent': 'agentic-soc-threat-hunting/1.0'})
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
        return resp.read().decode('utf-8', errors='replace')


def _load_iocs(force: bool = False) -> dict:
    """피드를 받아 IP/도메인 IOC 집합을 캐시. TTL 내면 캐시 재사용."""
    now = time.time()
    if not force and _cache.get('fetched_at') and (now - _cache['fetched_at'] < _CACHE_TTL):
        return _cache

    ips, domains, errors = set(), set(), []

    # Feodo: 1 IP/line, # 주석
    try:
        for line in _http_get(_FEEDS['feodo_c2_ip']).splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                ips.add(line.split(',')[0].strip())
    except Exception as e:
        errors.append(f'feodo: {type(e).__name__}: {str(e)[:80]}')

    # URLhaus: 1 URL/line → 호스트(도메인/IP) 추출
    try:
        for line in _http_get(_FEEDS['urlhaus_urls']).splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            host = urlparse(line).hostname
            if not host:
                continue
            # IP면 ips, 아니면 domains
            if host.replace('.', '').isdigit():
                ips.add(host)
            else:
                domains.add(host.lower())
    except Exception as e:
        errors.append(f'urlhaus: {type(e).__name__}: {str(e)[:80]}')

    _cache.update({'ips': ips, 'domains': domains, 'fetched_at': now, 'errors': errors})
    logger.info(f"IOC 피드 로드: ip={len(ips)} domain={len(domains)} errors={errors}")
    return _cache


@tool
def check_iocs(ips: list = None, domains: list = None) -> dict:
    """로그에서 추출한 IP/도메인을 공개 threat intel 피드(악성 IOC)와 대조한다.
    행위 헌팅으로 의심 IP/도메인을 찾았으면 이 도구로 '알려진 악성인지' 확증하라.
    Parameters:
      ips: 확인할 IP 주소 리스트 (예: VPC Flow egress의 dstAddr)
      domains: 확인할 도메인 리스트 (예: DNS query_name)
    반환: {matched_ips, matched_domains, feed_size, errors} — matched가 비었으면 알려진 IOC와 무일치
    """
    cache = _load_iocs()
    ti_ips, ti_domains = cache.get('ips', set()), cache.get('domains', set())

    matched_ips = sorted(set(ips or []) & ti_ips)
    # 도메인은 정확/서픽스 매칭(서브도메인 대응)
    matched_domains = []
    for d in (domains or []):
        dl = d.lower().rstrip('.')
        if dl in ti_domains or any(dl == t or dl.endswith('.' + t) for t in ti_domains):
            matched_domains.append(d)

    return {
        'checked_ips': len(ips or []),
        'checked_domains': len(domains or []),
        'matched_ips': matched_ips,
        'matched_domains': sorted(set(matched_domains)),
        'feed_size': {'malicious_ips': len(ti_ips), 'malicious_domains': len(ti_domains)},
        'feeds': 'abuse.ch Feodo Tracker (C2 IP) + URLhaus (malicious URLs)',
        'errors': cache.get('errors', []),
        'note': 'matched가 비어있으면 공개 피드 기준 알려진 악성 IOC와 일치 없음(무죄 입증 아님 — 신종/표적 위협은 피드에 없을 수 있음)',
    }


@tool
def refresh_threat_feeds() -> dict:
    """threat intel 피드를 강제로 다시 받아 캐시를 갱신한다(최신 IOC 반영)."""
    cache = _load_iocs(force=True)
    return {'malicious_ips': len(cache.get('ips', set())),
            'malicious_domains': len(cache.get('domains', set())),
            'errors': cache.get('errors', []),
            'feeds': list(_FEEDS.keys())}
