"""MITRE ATT&CK mapping tool.
Maps AWS security finding types (GuardDuty/Security Hub) to MITRE ATT&CK tactics and techniques,
so investigations can be framed in a standard adversary-behavior taxonomy."""
import logging
import re

from strands import tool

logger = logging.getLogger("investigation-agent.mitre")

# Finding-type keyword → (tactic, technique_id, technique_name)
# Keys are matched case-insensitively as substrings against the finding type/title.
_MITRE_MAP = [
    # Reconnaissance / Discovery
    (r'recon|portprobe|portscan|port\s*scan', ('Reconnaissance', 'T1595', 'Active Scanning')),
    (r'discovery|enumerat', ('Discovery', 'T1580', 'Cloud Infrastructure Discovery')),
    # Initial Access
    (r'unauthorizedaccess|bruteforce|brute\s*force|rdpbruteforce|sshbruteforce',
        ('Credential Access', 'T1110', 'Brute Force')),
    (r'anomaloubehavior|consolelogin|console\s*login',
        ('Initial Access', 'T1078', 'Valid Accounts')),
    # Credential Access
    (r'credential|accesskey|instancecredential',
        ('Credential Access', 'T1552', 'Unsecured Credentials')),
    (r'passwordpolicy|mfa',
        ('Credential Access', 'T1556', 'Modify Authentication Process')),
    # Privilege Escalation
    (r'privilegeescalation|privilege\s*escalation|assumerole|policyversion',
        ('Privilege Escalation', 'T1548', 'Abuse Elevation Control Mechanism')),
    # Defense Evasion
    (r'stoplogging|deletetrail|cloudtrail.*delet|disable.*logging|defenseevasion',
        ('Defense Evasion', 'T1562', 'Impair Defenses')),
    (r'deletesecuritygroup|authorizesecuritygroup|modifysecuritygroup',
        ('Defense Evasion', 'T1562.007', 'Disable or Modify Cloud Firewall')),
    # Exfiltration
    (r'exfiltration|s3.*download|datacompromis|exfil',
        ('Exfiltration', 'T1530', 'Data from Cloud Storage')),
    (r'dns.*exfil|dnsdataexfiltration',
        ('Exfiltration', 'T1048', 'Exfiltration Over Alternative Protocol')),
    # Impact
    (r'cryptocurrency|cryptomining|bitcoin|miner',
        ('Impact', 'T1496', 'Resource Hijacking')),
    (r'ransom|encrypt.*s3|deletebucket|impact',
        ('Impact', 'T1485', 'Data Destruction')),
    # Command and Control
    (r'backdoor|c2|command.*control|trojan|trojandns',
        ('Command and Control', 'T1071', 'Application Layer Protocol')),
    (r'maliciousip|knownmalicious|threatlist',
        ('Command and Control', 'T1071.001', 'Web Protocols')),
    # Persistence
    (r'persistence|createuser|createaccesskey',
        ('Persistence', 'T1136', 'Create Account')),
]


@tool
def map_to_mitre(finding_type: str = "", title: str = "", description: str = "") -> dict:
    """Map an AWS security finding to MITRE ATT&CK tactics and techniques.
    Pass any combination of the finding's type string, title, and description; the tool
    matches known patterns and returns the relevant ATT&CK tactic(s) and technique(s).
    Parameters:
      finding_type: The finding type string (e.g. 'Recon:EC2/PortProbeUnprotectedPort', GuardDuty type or Security Hub Types[])
      title: The finding title (optional, improves matching)
      description: The finding description (optional, improves matching)
    """
    haystack = ' '.join([finding_type or '', title or '', description or '']).lower()
    if not haystack.strip():
        return {'error': 'Provide finding_type, title, or description to map.'}

    matches = []
    seen = set()
    for pattern, (tactic, tech_id, tech_name) in _MITRE_MAP:
        if re.search(pattern, haystack):
            key = (tactic, tech_id)
            if key not in seen:
                seen.add(key)
                matches.append({
                    'tactic': tactic,
                    'technique_id': tech_id,
                    'technique_name': tech_name,
                    'reference': f'https://attack.mitre.org/techniques/{tech_id.replace(".", "/")}/',
                })

    # Compact summary string suitable for the findings.mitre_tactics column
    summary = '; '.join(f"{m['tactic']} ({m['technique_id']})" for m in matches)

    return {
        'finding_type': finding_type,
        'mitre_matches': matches,
        'count': len(matches),
        'summary': summary or 'No direct ATT&CK mapping — analyze behavior manually.',
    }
