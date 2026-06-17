"""Response Agent Tools — SOAR automated response (approval-gated).
Low-risk actions (send_alert/create_task) execute immediately; high-risk remediations
are proposed for analyst approval via propose_remediation."""
from tools.soar import send_alert, create_task, propose_remediation

ALL_TOOLS = [
    send_alert,
    create_task,
    propose_remediation,
]


def get_all_tools():
    return list(ALL_TOOLS)
