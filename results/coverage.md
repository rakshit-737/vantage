### A. Telemetry tier x claimed CIS Implementation Group

| tier | claims | log_sources | claimed_pct | detectable_pct | true_pct | gap_pp | paper_only | dead_rules |
|---|---|---|---|---|---|---|---|---|
| T0 classic Windows event logs | IG1 | 3 | 46.9 | 13.2 | 10.5 | 36.4 | 254 | 2416 |
| T0 classic Windows event logs | IG2 | 3 | 53.9 | 13.2 | 11.2 | 42.7 | 298 | 2416 |
| T0 classic Windows event logs | IG3 | 3 | 54.2 | 13.2 | 11.2 | 43.0 | 300 | 2416 |
| T1 + PowerShell logging | IG1 | 8 | 46.9 | 22.0 | 14.9 | 32.0 | 223 | 2250 |
| T1 + PowerShell logging | IG2 | 8 | 53.9 | 22.0 | 16.5 | 37.4 | 261 | 2250 |
| T1 + PowerShell logging | IG3 | 8 | 54.2 | 22.0 | 16.5 | 37.7 | 263 | 2250 |
| T2 + Sysmon/EDR-class endpoint | IG1 | 31 | 46.9 | 41.3 | 26.1 | 20.8 | 145 | 623 |
| T2 + Sysmon/EDR-class endpoint | IG2 | 31 | 53.9 | 41.3 | 29.4 | 24.5 | 171 | 623 |
| T2 + Sysmon/EDR-class endpoint | IG3 | 31 | 54.2 | 41.3 | 29.7 | 24.5 | 171 | 623 |
| T3 + cloud & identity audit | IG1 | 46 | 46.9 | 46.1 | 29.1 | 17.8 | 124 | 446 |
| T3 + cloud & identity audit | IG2 | 46 | 53.9 | 46.1 | 32.7 | 21.2 | 148 | 446 |
| T3 + cloud & identity audit | IG3 | 46 | 54.2 | 46.1 | 33.0 | 21.2 | 148 | 446 |
| T4 + network, web, Linux, macOS | IG1 | 72 | 46.9 | 50.6 | 32.6 | 14.3 | 100 | 134 |
| T4 + network, web, Linux, macOS | IG2 | 72 | 53.9 | 50.6 | 36.4 | 17.5 | 122 | 134 |
| T4 + network, web, Linux, macOS | IG3 | 72 | 54.2 | 50.6 | 36.7 | 17.5 | 122 | 134 |
| T5 every Sigma log source | IG1 | 116 | 46.9 | 52.1 | 33.4 | 13.5 | 94 | 0 |
| T5 every Sigma log source | IG2 | 116 | 53.9 | 52.1 | 37.4 | 16.5 | 115 | 0 |
| T5 every Sigma log source | IG3 | 116 | 54.2 | 52.1 | 37.7 | 16.5 | 115 | 0 |

### B. Random synthetic orgs (25 per maturity level)

| maturity | orgs | claimed_pct | true_pct | gap_pp |
|---|---|---|---|---|
| 0.2 | 25 | 50.5 +/- 1.8 | 17.2 +/- 5.0 | 33.3 +/- 5.2 |
| 0.4 | 25 | 52.0 +/- 1.5 | 23.6 +/- 4.3 | 28.4 +/- 4.6 |
| 0.6 | 25 | 52.9 +/- 1.3 | 29.5 +/- 3.1 | 23.4 +/- 3.3 |
| 0.8 | 25 | 53.6 +/- 0.6 | 33.5 +/- 1.5 | 20.1 +/- 1.5 |

### C. Engine performance

| deployed_rules | ingested_log_sources | coverage_ms | spof_fast_s | spof_bruteforce_s | speedup | identical_results |
|---|---|---|---|---|---|---|
| 2877 | 46 | 5.0 | 0.004 | 62.88 | 17058.5 | True |
