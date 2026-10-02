"""Built-in seed catalog.

Technique ids/names are real MITRE ATT&CK Enterprise identifiers. The control->technique
and detection->technique mappings are ILLUSTRATIVE (hand-written for this demo, loosely
inspired by public CIS v8 -> ATT&CK work); they are NOT an authoritative mapping.
The real catalog (``--catalog real``/``nist``) uses the official public mappings instead.
"""
from __future__ import annotations

from .models import Catalog, Control, Detection, LogSource, Technique

_T = [
    ("T1059.001", "PowerShell", "execution", "adversary runs powershell commands and scripts"),
    ("T1059.003", "Windows Command Shell", "execution", "adversary runs cmd.exe commands and batch scripts"),
    ("T1218.011", "Rundll32", "defense-evasion", "proxy execution of malicious dll via rundll32 signed binary"),
    ("T1055", "Process Injection", "defense-evasion", "inject code into running processes to evade defenses"),
    ("T1562.001", "Disable or Modify Tools", "defense-evasion", "disable antivirus endpoint security tools and logging"),
    ("T1070.001", "Clear Windows Event Logs", "defense-evasion", "clear windows event logs audit trail to hide activity"),
    ("T1053.005", "Scheduled Task", "persistence", "create scheduled task for persistence and execution"),
    ("T1547.001", "Registry Run Keys / Startup Folder", "persistence", "registry run keys startup folder autostart persistence"),
    ("T1543.003", "Windows Service", "persistence", "create or modify windows service for persistence"),
    ("T1136.001", "Create Local Account", "persistence", "create local user account for persistence"),
    ("T1098", "Account Manipulation", "persistence", "modify account permissions group membership credentials"),
    ("T1003.001", "LSASS Memory", "credential-access", "dump credentials from lsass process memory"),
    ("T1110", "Brute Force", "credential-access", "guess passwords brute force password spraying authentication"),
    ("T1558.003", "Kerberoasting", "credential-access", "request kerberos service tickets to crack service account passwords"),
    ("T1550.002", "Pass the Hash", "lateral-movement", "authenticate with stolen password hash ntlm"),
    ("T1021.001", "Remote Desktop Protocol", "lateral-movement", "move laterally using remote desktop rdp sessions"),
    ("T1021.002", "SMB/Windows Admin Shares", "lateral-movement", "move laterally over smb admin shares network segments"),
    ("T1570", "Lateral Tool Transfer", "lateral-movement", "copy tools between internal hosts across network segments"),
    ("T1078", "Valid Accounts", "initial-access", "use stolen valid account credentials to log in"),
    ("T1133", "External Remote Services", "initial-access", "access via vpn or external remote services"),
    ("T1190", "Exploit Public-Facing Application", "initial-access", "exploit vulnerability in internet facing application"),
    ("T1566.001", "Spearphishing Attachment", "initial-access", "phishing email with malicious attachment"),
    ("T1087.002", "Domain Account", "discovery", "enumerate domain accounts and groups"),
    ("T1018", "Remote System Discovery", "discovery", "discover remote systems hosts on the network"),
    ("T1046", "Network Service Discovery", "discovery", "scan network services ports on internal segments"),
    ("T1071.001", "Web Protocols", "command-and-control", "command and control over http https web traffic"),
    ("T1071.004", "DNS", "command-and-control", "command and control tunneled over dns queries"),
    ("T1105", "Ingress Tool Transfer", "command-and-control", "download tools from external web server"),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration", "exfiltrate data over non standard protocol"),
    ("T1567.002", "Exfiltration to Cloud Storage", "exfiltration", "exfiltrate data to cloud storage service upload"),
    ("T1530", "Data from Cloud Storage", "collection", "access data in cloud storage buckets"),
    ("T1486", "Data Encrypted for Impact", "impact", "ransomware encrypts data files for impact"),
    ("T1490", "Inhibit System Recovery", "impact", "delete backups shadow copies to inhibit recovery"),
]

_LS = [
    ("win_security", "Windows Security Event Log", 1.0),
    ("sysmon", "Sysmon (process/registry/network)", 1.5),
    ("edr", "EDR telemetry", 4.0),
    ("proxy", "Web proxy logs", 1.5),
    ("dns", "DNS resolver logs", 1.0),
    ("firewall", "Internal firewall / flow logs", 1.5),
    ("cloudtrail", "Cloud audit logs", 1.0),
    ("email_gw", "Email gateway logs", 1.0),
    ("vpn", "VPN / remote access logs", 0.5),
]

# (id, title, techniques, required log sources, cost)
_D = [
    ("sig_ps_encoded", "Encoded PowerShell command line", {"T1059.001"}, {"sysmon"}, 1),
    ("sig_cmd_susp", "Suspicious cmd.exe child of Office", {"T1059.003", "T1566.001"}, {"sysmon"}, 1),
    ("sig_rundll32", "Rundll32 without DLL exports", {"T1218.011"}, {"sysmon"}, 1),
    ("sig_runkey", "Registry Run key modification", {"T1547.001"}, {"sysmon"}, 1),
    ("sig_svc_new", "New service installed", {"T1543.003"}, {"win_security"}, 1),
    ("sig_schtask", "Scheduled task created", {"T1053.005"}, {"win_security"}, 1),
    ("sig_localacct", "Local account created", {"T1136.001"}, {"win_security"}, 1),
    ("sig_group_add", "User added to privileged group", {"T1098"}, {"win_security"}, 1),
    ("sig_logclear", "Security log cleared", {"T1070.001"}, {"win_security"}, 1),
    ("sig_bruteforce", "Many failed logons", {"T1110"}, {"win_security"}, 1),
    ("sig_kerberoast", "RC4 TGS requests burst", {"T1558.003"}, {"win_security"}, 2),
    ("sig_pth", "NTLM pass-the-hash logon pattern", {"T1550.002"}, {"win_security"}, 2),
    ("sig_domain_enum", "Domain group enumeration command", {"T1087.002"}, {"sysmon"}, 1),
    ("sig_lsass_access", "LSASS handle access", {"T1003.001"}, {"sysmon"}, 1),
    ("sig_edr_inject", "EDR: process injection", {"T1055"}, {"edr"}, 1),
    ("sig_edr_tamper", "EDR: security tool tampering", {"T1562.001"}, {"edr"}, 1),
    ("sig_edr_ransom", "EDR: mass file encryption", {"T1486"}, {"edr"}, 1),
    ("sig_edr_shadow", "EDR: shadow copy deletion", {"T1490"}, {"edr"}, 1),
    ("sig_edr_cred", "EDR: credential dumping", {"T1003.001"}, {"edr"}, 1),
    ("sig_edr_ps", "EDR: malicious PowerShell", {"T1059.001", "T1105"}, {"edr"}, 1),
    ("sig_edr_lateral", "EDR: remote exec over admin share", {"T1021.002", "T1570"}, {"edr"}, 1),
    ("sig_rdp_internal", "Internal RDP from workstation", {"T1021.001"}, {"firewall"}, 1),
    ("sig_portscan", "Internal port scan", {"T1046", "T1018"}, {"firewall"}, 1),
    ("sig_proxy_c2", "Beacon-like HTTP periodicity", {"T1071.001"}, {"proxy"}, 2),
    ("sig_proxy_upload", "Large upload to cloud storage", {"T1567.002"}, {"proxy"}, 1),
    ("sig_proxy_dl", "Executable download from rare domain", {"T1105"}, {"proxy"}, 1),
    ("sig_dns_tunnel", "Long/high-entropy DNS queries", {"T1071.004", "T1048"}, {"dns"}, 1),
    ("sig_cloud_bucket", "Unusual bucket GetObject volume", {"T1530"}, {"cloudtrail"}, 1),
    ("sig_phish_attach", "Macro attachment delivered", {"T1566.001"}, {"email_gw"}, 1),
    ("sig_vpn_anomaly", "VPN login from new country", {"T1133", "T1078"}, {"vpn"}, 1),
]

# (id, framework, title, mitigates, free-text policy)
_C = [
    ("CIS-8.2", "CIS v8", "Collect audit logs",
     {"T1070.001", "T1136.001", "T1098", "T1053.005", "T1543.003", "T1110"},
     "Collect audit logs for account creation, group membership changes, scheduled task and "
     "service creation, event log clearing, and failed authentication."),
    ("CIS-8.8", "CIS v8", "Collect command-line audit logs",
     {"T1059.001", "T1059.003", "T1218.011", "T1087.002"},
     "Collect command-line audit logs for powershell, cmd and signed binary proxy execution "
     "such as rundll32, including domain account enumeration."),
    ("CIS-10.1", "CIS v8", "Deploy and maintain anti-malware software",
     {"T1486", "T1055", "T1562.001", "T1003.001"},
     "Deploy anti-malware endpoint protection to block ransomware encryption, process injection, "
     "credential dumping from lsass memory and tampering with security tools."),
    ("CIS-11.1", "CIS v8", "Establish a data recovery process",
     {"T1490", "T1486"},
     "Maintain backups protected from deletion so shadow copies and backups cannot be removed "
     "to inhibit recovery after ransomware."),
    ("CIS-6.3", "CIS v8", "Require MFA for externally-exposed applications",
     {"T1078", "T1133", "T1110"},
     "Require multi-factor authentication for vpn and external remote services to stop stolen "
     "valid account credentials and password brute force."),
    ("CIS-5.4", "CIS v8", "Restrict administrator privileges",
     {"T1550.002", "T1558.003", "T1098", "T1003.001"},
     "Restrict administrator privileges to dedicated accounts, limiting pass the hash, "
     "kerberoasting of service accounts and account manipulation."),
    ("CIS-12.2", "CIS v8", "Establish and maintain a secure network architecture",
     {"T1021.001", "T1021.002", "T1570", "T1046", "T1018"},
     "Segment the network so remote desktop, smb admin shares, lateral tool transfer and "
     "internal service discovery across segments are restricted."),
    ("CIS-9.2", "CIS v8", "Use DNS filtering services",
     {"T1071.004", "T1048"},
     "Use dns filtering to block dns tunneling command and control and exfiltration over dns."),
    ("CIS-13.3", "CIS v8", "Deploy a network intrusion detection solution",
     {"T1071.001", "T1105", "T1567.002"},
     "Monitor web traffic for command and control beaconing, tool downloads and uploads to "
     "cloud storage."),
    ("CIS-9.7", "CIS v8", "Deploy and maintain email server anti-malware protections",
     {"T1566.001"},
     "Scan email attachments to block phishing with malicious attachments."),
    ("CIS-7.1", "CIS v8", "Establish a vulnerability management process",
     {"T1190"},
     "Patch vulnerabilities in internet facing applications to prevent exploitation."),
    ("CIS-3.3", "CIS v8", "Configure data access control lists",
     {"T1530"},
     "Restrict access to cloud storage buckets and sensitive data."),
    ("CIS-4.1", "CIS v8", "Establish a secure configuration process",
     {"T1547.001", "T1053.005"},
     "Harden configurations to restrict registry run keys autostart and scheduled task abuse."),
]


def load_seed_catalog() -> Catalog:
    cat = Catalog(
        techniques={t[0]: Technique(*t) for t in _T},
        controls={c[0]: Control(c[0], c[1], c[2], frozenset(c[3]), c[4]) for c in _C},
        log_sources={s[0]: LogSource(*s) for s in _LS},
        detections={
            d[0]: Detection(d[0], d[1], frozenset(d[2]), frozenset(d[3]), float(d[4])) for d in _D
        },
    )
    cat.validate()
    return cat
