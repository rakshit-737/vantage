### How-it-works walkthrough (synthetic Acme posture, real catalog)

| technique | claimed by (IG2 safeguards) | live rules | dead rules (deployed, log source missing) | most common missing source | status |
|---|---|---|---|---|---|
| T1003.001 OS Credential Dumping: LSASS Memory | 14 | 7 | 61 | `windows/process_creation` (28) | defended |
| T1055 Process Injection | 7 | 0 | 29 | `windows/process_creation` (12) | paper_only |

Matrix: claimed 53.9% vs defended 17.6% of 697 techniques, 253 paper-only, 2132 dead rules. Top single point of failure: log_source `windows/security` (39 techniques go dark).

Recommender's first pick: onboard `windows/ps_script` (cost 1.15), which unlocks 134 rules and makes 51 techniques newly detectable. Defended coverage goes from 123 (17.6%) to 153 (22.0%) techniques, +30 (152 if only the posture's already-deployed rules come alive). The recommender maximises newly *detectable* techniques, not defended ones.

_Source: GitHub Actions `realdata` run [37092934843](https://github.com/rakshit-737/vantage-compliance-attack-mapping/actions/runs/37092934843) at commit `6ff466dd6215` (Linux-6.17.0-1022-azure-x86_64-with-glibc2.39, Python 3.12.14)._
