"""SOC Host Agent Tools — dynamic orchestrator with env-gated security sub-agent invocation."""
from tools.sub_agents import get_active_tools


def get_all_tools():
    """Return the active tool list based on configured environment variables."""
    return get_active_tools()
