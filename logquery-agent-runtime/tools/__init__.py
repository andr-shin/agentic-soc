"""Log Query Agent Tools — CloudWatch Unified Data Store (Logs Insights).
Natural-language → LogsQL query generation and execution across security log sources."""
from tools.logs_insights import list_log_sources, run_logs_query, get_log_fields

ALL_TOOLS = [
    list_log_sources,
    run_logs_query,
    get_log_fields,
]


def get_all_tools():
    return list(ALL_TOOLS)
