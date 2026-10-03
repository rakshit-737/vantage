### Techniques newly detectable vs onboarding budget (start: Acme real posture, 153 techniques already detectable, 99 candidate log sources)

| budget | greedy | optimal | greedy/optimal | most-rules | cheapest | random(mean) | random 2.5-97.5% | greedy/random(mean) | greedy_ms | ilp_ms |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 8 | 8 | 1.0 | 8 | 0 | 1.1 | 0.0-8.0 | 7.5 | 74 | 8 |
| 2 | 51 | 51 | 1.0 | 51 | 6 | 4.6 | 0.0-42.0 | 11.2 | 77 | 10 |
| 3 | 64 | 64 | 1.0 | 33 | 7 | 3.8 | 0.0-32.2 | 17.0 | 113 | 29 |
| 5 | 85 | 85 | 1.0 | 61 | 8 | 11.0 | 0.2-48.8 | 7.7 | 151 | 36 |
| 8 | 152 | 152 | 1.0 | 152 | 9 | 19.5 | 2.0-118.9 | 7.8 | 131 | 8 |
| 12 | 175 | 175 | 1.0 | 155 | 10 | 25.7 | 4.5-63.8 | 6.8 | 246 | 6 |
| 20 | 201 | 201 | 1.0 | 185 | 13 | 51.4 | 14.0-156.5 | 3.9 | 531 | 9 |

Greedy finds 3.9-16.8x the mean of 50 random orders and 1.0-2.7x their 97.5th percentile; it beats most-rules-first by 0-31 techniques. Greedy equals the exact ILP at 7 of 7 budgets (an empirical result on this instance, not a guarantee).

### Greedy plan (first 5 steps)

| step | onboard | cost | new_techniques | rules_unlocked |
|---|---|---|---|---|
| 1 | windows/ps_script | 1.15 | 51 | 134 |
| 2 | windows/process_creation | 6.7 | 101 | 1147 |
| 3 | cisco/aaa | 1.05 | 7 | 10 |
| 4 | linux/process_creation | 2.6 | 16 | 96 |
| 5 | bitbucket/audit | 1.0 | 4 | 12 |

_Source: GitHub Actions `realdata` run [37092934843](https://github.com/rakshit-737/vantage/actions/runs/37092934843) at commit `6ff466dd6215` (Linux-6.17.0-1022-azure-x86_64-with-glibc2.39, Python 3.12.14)._
