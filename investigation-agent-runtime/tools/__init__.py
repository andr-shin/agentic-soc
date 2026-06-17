"""Investigation Agent Tools — security incident investigation.
Core tools (always active): security finding detail (GuardDuty/Security Hub), CloudTrail change
correlation, CloudWatch Logs search/anomalies, VPC Flow Logs network forensics, MITRE ATT&CK mapping.
Optional integrations (env-gated): OpenSearch log search, GitHub issue tracking."""
import os

from tools.findings import get_guardduty_finding, get_securityhub_finding
from tools.cloudtrail import get_cloudtrail_changes
from tools.cloudwatch_logs import search_cloudwatch_logs, detect_log_anomalies
from tools.vpc_flow import analyze_vpc_flow
from tools.mitre import map_to_mitre

# Core tools — always active
ALL_TOOLS = [
    get_guardduty_finding,
    get_securityhub_finding,
    get_cloudtrail_changes,
    search_cloudwatch_logs,
    detect_log_anomalies,
    analyze_vpc_flow,
    map_to_mitre,
]

# OpenSearch tools — activated when OPENSEARCH_ENDPOINT is set
if os.environ.get('OPENSEARCH_ENDPOINT'):
    from tools.opensearch import opensearch_search_logs, opensearch_anomaly_detection, opensearch_get_error_summary
    ALL_TOOLS.extend([opensearch_search_logs, opensearch_anomaly_detection, opensearch_get_error_summary])

# GitHub tools — activated when GITHUB_PAT is set (incident issue tracking)
if os.environ.get('GITHUB_PAT'):
    from tools.github_issues import github_create_issue, github_add_comment, github_list_issues
    ALL_TOOLS.extend([github_create_issue, github_add_comment, github_list_issues])


def get_all_tools():
    return list(ALL_TOOLS)
