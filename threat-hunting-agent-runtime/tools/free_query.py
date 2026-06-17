"""자유 LogsQL 헌팅 도구 — 정해진 가설 외에, LLM이 직접 만든 LogsQL을 로그 소스에 실행.
교차 상관(같은 principal/IP를 여러 소스에서 추적)이나 가설 변형을 위해 사용."""
from strands import tool

from tools.logs_common import run_insights_query, LOG_SOURCES


@tool
def list_hunt_sources() -> dict:
    """헌팅 가능한 로그 소스와 필드 스키마를 나열. 자유 쿼리 작성 전에 먼저 호출."""
    return {'sources': [
        {'source': name, 'schema': cfg['schema']} for name, cfg in LOG_SOURCES.items()
    ], 'note': 'run_hunt_query에 source명(cloudtrail/vpc-flowlogs/dns-queries)과 LogsQL을 전달.'}


@tool
def run_hunt_query(source: str, query: str, minutes: int = 1440, limit: int = 100) -> dict:
    """로그 소스에 임의 LogsQL 쿼리를 실행(자유 헌팅·교차 상관용).
    Parameters:
      source: 'cloudtrail' / 'vpc-flowlogs' / 'dns-queries' (또는 명시적 로그그룹명)
      query: LogsQL. 시간범위는 넣지 말 것(minutes로 지정). fields/filter/stats/sort 사용.
             예: 'filter sourceIPAddress="1.2.3.4" | stats count(*) by eventName | sort count(*) desc'
      minutes: 시간범위(분, 기본 24h)
      limit: 최대 행수(기본 100)
    반환: {log_group, query, rows, count} 또는 {error}
    """
    return run_insights_query(source, query, minutes=minutes, limit=limit)
