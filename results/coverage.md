### A. Telemetry tier x claimed CIS Implementation Group

| tier | claims | log_sources | claimed_pct | detectable_pct | true_pct | weighted_true_pct | gap_pp | paper_only | dead_rules |
|---|---|---|---|---|---|---|---|---|---|
| T0 classic Windows event logs | IG1 | 3 | 46.9 | 13.2 | 10.5 | 8.7 | 36.4 | 254 | 2416 |
| T0 classic Windows event logs | IG2 | 3 | 53.9 | 13.2 | 11.2 | 9.2 | 42.8 | 298 | 2416 |
| T0 classic Windows event logs | IG3 | 3 | 54.2 | 13.2 | 11.2 | 9.2 | 43.0 | 300 | 2416 |
| T1 + PowerShell logging | IG1 | 8 | 46.9 | 22.0 | 14.9 | 12.5 | 32.0 | 223 | 2250 |
| T1 + PowerShell logging | IG2 | 8 | 53.9 | 22.0 | 16.5 | 13.6 | 37.4 | 261 | 2250 |
| T1 + PowerShell logging | IG3 | 8 | 54.2 | 22.0 | 16.5 | 13.6 | 37.7 | 263 | 2250 |
| T2 + Sysmon/EDR-class endpoint | IG1 | 31 | 46.9 | 41.3 | 26.1 | 23.7 | 20.8 | 145 | 623 |
| T2 + Sysmon/EDR-class endpoint | IG2 | 31 | 53.9 | 41.3 | 29.4 | 26.6 | 24.5 | 171 | 623 |
| T2 + Sysmon/EDR-class endpoint | IG3 | 31 | 54.2 | 41.3 | 29.7 | 26.9 | 24.5 | 171 | 623 |
| T3 + cloud & identity audit | IG1 | 46 | 46.9 | 46.1 | 29.1 | 26.1 | 17.8 | 124 | 446 |
| T3 + cloud & identity audit | IG2 | 46 | 53.9 | 46.1 | 32.7 | 29.2 | 21.2 | 148 | 446 |
| T3 + cloud & identity audit | IG3 | 46 | 54.2 | 46.1 | 33.0 | 29.5 | 21.2 | 148 | 446 |
| T4 + network, web, Linux, macOS | IG1 | 72 | 46.9 | 50.6 | 32.6 | 29.1 | 14.3 | 100 | 134 |
| T4 + network, web, Linux, macOS | IG2 | 72 | 53.9 | 50.6 | 36.4 | 32.6 | 17.5 | 122 | 134 |
| T4 + network, web, Linux, macOS | IG3 | 72 | 54.2 | 50.6 | 36.7 | 32.8 | 17.5 | 122 | 134 |
| T5 every Sigma log source | IG1 | 116 | 46.9 | 52.1 | 33.4 | 29.9 | 13.5 | 94 | 0 |
| T5 every Sigma log source | IG2 | 116 | 53.9 | 52.1 | 37.4 | 33.5 | 16.5 | 115 | 0 |
| T5 every Sigma log source | IG3 | 116 | 54.2 | 52.1 | 37.7 | 33.7 | 16.5 | 115 | 0 |

`weighted_true_pct` scores each defended technique by rule quality (ADR 0007) instead of 0/1.

### B. Random synthetic orgs (25 per maturity level)

| maturity | orgs | claimed_pct | true_pct | gap_pp | gap_95ci |
|---|---|---|---|---|---|
| 0.2 | 25 | 50.5 +/- 1.8 | 17.2 +/- 5.0 | 33.3 +/- 5.2 | [31.2, 35.4] |
| 0.4 | 25 | 52.0 +/- 1.5 | 23.6 +/- 4.3 | 28.4 +/- 4.6 | [26.5, 30.3] |
| 0.6 | 25 | 52.9 +/- 1.3 | 29.5 +/- 3.1 | 23.4 +/- 3.3 | [22.0, 24.8] |
| 0.8 | 25 | 53.6 +/- 0.6 | 33.5 +/- 1.5 | 20.1 +/- 1.5 | [19.4, 20.7] |

Values are mean +/- sd over 25 orgs (seeds 0-24); gap_95ci is a t-interval of the mean gap.

### C. Engine performance

| deployed_rules | ingested_log_sources | coverage_ms | spof_fast_s | spof_bruteforce_s | speedup | identical_results |
|---|---|---|---|---|---|---|
| 2877 | 46 | 2.9 | 0.002 | 7.66 | 4902.8 | True |

### D. NIST SP 800-53 rev5 claims (CTID mapping, ATT&CK v16.1 carried to v19.2)

| tier | claimed_pct | detectable_pct | true_pct | weighted_true_pct | gap_pp | paper_only |
|---|---|---|---|---|---|---|
| T0 classic Windows event logs | 66.9 | 13.2 | 11.2 | 9.2 | 55.7 | 388 |
| T1 + PowerShell logging | 66.9 | 22.0 | 16.6 | 13.6 | 50.2 | 350 |
| T2 + Sysmon/EDR-class endpoint | 66.9 | 41.3 | 31.4 | 28.2 | 35.4 | 247 |
| T3 + cloud & identity audit | 66.9 | 46.1 | 35.6 | 31.6 | 31.3 | 218 |
| T4 + network, web, Linux, macOS | 66.9 | 50.6 | 39.2 | 34.8 | 27.7 | 193 |
| T5 every Sigma log source | 66.9 | 52.1 | 40.3 | 35.9 | 26.5 | 185 |

### E. Structural ceilings (CIS v8 mapping, SigmaHQ)

| quantity | value |
|---|---|
| techniques_v19.2 | 697 |
| cis_mapped_v19.2 | 378 |
| cis_mapped_pct | 54.2 |
| not_claimable_by_cis | 319 |
| not_claimable_pp | 45.8 |
| added_after_v8.2 | 172 |
| added_after_v8.2_pp | 24.7 |
| v8.2_era_never_mapped | 147 |
| v8.2_era_never_mapped_pp | 21.1 |
| techniques_v8.2 | 530 |
| cis_mapped_v8.2 | 383 |
| cis_coverage_v8.2_pct | 72.3 |
| detectable_T5_stable_test | 363 |
| detectable_T5_stable_test_pct | 52.1 |
| detectable_T5_all_rules | 378 |
| detectable_T5_all_rules_pct | 54.2 |
| rules_all | 2877 |

The CIS mapping reaches 54.2% of ATT&CK v19.2. Of the 45.8 pp it cannot claim, 24.7 pp are 172 techniques added after v8.2 and 21.1 pp are 147 v8.2-era techniques CIS never mapped. On v8.2 itself CIS covers 72.3% (383 of 530). With every log source ingested, stable+test rules detect 52.1% and all 2877 rules 54.2%.

_Source: GitHub Actions `realdata` run [37092934843](https://github.com/rakshit-737/vantage/actions/runs/37092934843) at commit `6ff466dd6215` (Linux-6.17.0-1022-azure-x86_64-with-glibc2.39, Python 3.12.14)._
