# VANTAGE audit report: Acme Corp (synthetic)

> Generated from a declared posture file. Treat as SENSITIVE: this document is a map of blind spots.

## Summary

- Techniques in scope: 33
- Claimed (paper) coverage: **93.9%**
- True (defended) coverage: **45.5%**
- Paper-only techniques: 16  |  Blind: 2  |  Detected without control: 0
- Deployed-but-dead detections (log source not ingested): 8
- Zero-Trust posture score: **53.2/100**

## Compliant but undetectable

| Technique | Name | Claimed by | Why undetectable |
| --- | --- | --- | --- |
| T1018 | Remote System Discovery | CIS-12.2 | no detection deployed |
| T1021.001 | Remote Desktop Protocol | CIS-12.2 | no detection deployed |
| T1046 | Network Service Discovery | CIS-12.2 | no detection deployed |
| T1053.005 | Scheduled Task | CIS-4.1, CIS-8.2 | rules deployed but missing log source: sig_schtask (needs win_security) |
| T1059.003 | Windows Command Shell | CIS-8.8 | no detection deployed |
| T1070.001 | Clear Windows Event Logs | CIS-8.2 | rules deployed but missing log source: sig_logclear (needs win_security) |
| T1087.002 | Domain Account | CIS-8.8 | no detection deployed |
| T1098 | Account Manipulation | CIS-5.4, CIS-8.2 | rules deployed but missing log source: sig_group_add (needs win_security) |
| T1110 | Brute Force | CIS-6.3, CIS-8.2 | rules deployed but missing log source: sig_bruteforce (needs win_security) |
| T1136.001 | Create Local Account | CIS-8.2 | rules deployed but missing log source: sig_localacct (needs win_security) |
| T1218.011 | Rundll32 | CIS-8.8 | no detection deployed |
| T1543.003 | Windows Service | CIS-8.2 | rules deployed but missing log source: sig_svc_new (needs win_security) |
| T1547.001 | Registry Run Keys / Startup Folder | CIS-4.1 | no detection deployed |
| T1550.002 | Pass the Hash | CIS-5.4 | rules deployed but missing log source: sig_pth (needs win_security) |
| T1558.003 | Kerberoasting | CIS-5.4 | rules deployed but missing log source: sig_kerberoast (needs win_security) |
| T1567.002 | Exfiltration to Cloud Storage | CIS-13.3 | no detection deployed |

## Heatmap

```
Legend: [D] defended  [P] paper-only (claimed, not detectable)  [d] detected, no control  [ ] blind

collection           [ ]T1530
command-and-control  [D]T1071.001 [D]T1071.004 [D]T1105
credential-access    [D]T1003.001 [P]T1110 [P]T1558.003
defense-evasion      [D]T1055 [P]T1070.001 [P]T1218.011 [D]T1562.001
discovery            [P]T1018 [P]T1046 [P]T1087.002
execution            [D]T1059.001 [P]T1059.003
exfiltration         [D]T1048 [P]T1567.002
impact               [D]T1486 [D]T1490
initial-access       [D]T1078 [D]T1133 [ ]T1190 [D]T1566.001
lateral-movement     [P]T1021.001 [D]T1021.002 [P]T1550.002 [D]T1570
persistence          [P]T1053.005 [P]T1098 [P]T1136.001 [P]T1543.003 [P]T1547.001
```

## Single points of failure

- log_source `edr` -> 9 techniques dark (27.3% of matrix)
- detection `sig_dns_tunnel` -> 2 techniques dark (6.1% of matrix)
- detection `sig_edr_lateral` -> 2 techniques dark (6.1% of matrix)
- detection `sig_edr_ps` -> 2 techniques dark (6.1% of matrix)
- detection `sig_vpn_anomaly` -> 2 techniques dark (6.1% of matrix)

## Recommended next actions (greedy set cover)

1. onboard_log_source `win_security` (cost 1) -> +8 techniques: T1053.005, T1070.001, T1098, T1110, T1136.001, T1543.003, T1550.002, T1558.003
2. deploy_detection `sig_proxy_upload` (cost 1) -> +1 techniques: T1567.002
3. onboard_log_source `firewall` (cost 3.5) -> +3 techniques: T1018, T1021.001, T1046
4. onboard_log_source `sysmon` (cost 7.5) -> +4 techniques: T1059.003, T1087.002, T1218.011, T1547.001
5. onboard_log_source `cloudtrail` (cost 2) -> +1 techniques: T1530

## Zero-Trust components

- segmentation: 0.692
- mfa: 0.6
- privileged_access: 0.25
- device_posture: 0.0
- account_hygiene: 0.9
- Lateral/discovery techniques exposed by open flows into critical segments: T1018, T1021.001, T1021.002, T1046, T1087.002, T1550.002, T1570
