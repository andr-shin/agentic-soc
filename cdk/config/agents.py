"""
Agent configuration registry — Agentic SOC.
Single source of truth for all agent names, roles, and descriptions.

Migrated from AIOps (operational) to SOC (security) domain:
  incident-agent  → investigation-agent  (GuardDuty/CloudTrail correlation, MITRE mapping)
  steampipe-agent → hunting-agent        (proactive SQL threat hunting)
  report-agent    → report-agent          (security report synthesis, retained)

  logquery-agent  (P3 — CloudWatch Unified Data Store, NL→LogsQL)
  response-agent  (P4 — SOAR, approval-gated)
"""

SUB_AGENTS = {
    "investigation": {
        "source_dir": "investigation-agent-runtime",
        "description": "Security investigation agent (GuardDuty findings, CloudTrail correlation, VPC Flow, MITRE ATT&CK mapping)",
    },
    "hunting": {
        "source_dir": "hunting-agent-runtime",
        "description": "Posture analysis agent (Steampipe SQL — misconfig/exposure & attack-path correlation across AWS resource config)",
    },
    "threat_hunting": {
        "source_dir": "threat-hunting-agent-runtime",
        "description": "Threat hunting agent (log-based, assume-breach — CloudTrail/DNS/VPC Flow cross-correlation for MITRE ATT&CK TTPs/IOCs)",
    },
    "logquery": {
        "source_dir": "logquery-agent-runtime",
        "description": "Log query agent (CloudWatch Unified Data Store, natural-language to LogsQL)",
    },
    "response": {
        "source_dir": "response-agent-runtime",
        "description": "SOAR response agent (alert/task immediately; isolate/block/revoke via approval-gated proposals)",
    },
    "report": {
        "source_dir": "report-agent-runtime",
        "description": "Security report synthesis agent",
    },
}

CHAT_AGENT = {
    "source_dir": "soc-host-agent-runtime",
    "description": "SOC Host Agent orchestrator (triage + routing)",
}

ALL_AGENT_KEYS = list(SUB_AGENTS.keys()) + ["chat"]
