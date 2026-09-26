### Techniques newly detectable vs onboarding budget (start: Acme real posture, 153 techniques already detectable, 99 candidate log sources)

| budget | greedy | optimal | greedy/optimal | most-rules | cheapest | random(mean) | greedy_ms | ilp_ms |
|---|---|---|---|---|---|---|---|---|
| 1 | 8 | 8 | 1.0 | 8 | 0 | 1.1 | 441 | 100 |
| 2 | 51 | 51 | 1.0 | 51 | 6 | 4.6 | 732 | 88 |
| 3 | 64 | 64 | 1.0 | 33 | 7 | 3.8 | 1157 | 220 |
| 5 | 85 | 85 | 1.0 | 61 | 8 | 11.0 | 1762 | 284 |
| 8 | 152 | 152 | 1.0 | 152 | 9 | 19.5 | 1250 | 58 |
| 12 | 175 | 175 | 1.0 | 155 | 10 | 25.7 | 2376 | 46 |
| 20 | 201 | 201 | 1.0 | 185 | 13 | 51.4 | 4427 | 61 |

### Greedy plan (first 5 steps)

| step | onboard | cost | new_techniques | rules_unlocked |
|---|---|---|---|---|
| 1 | windows/ps_script | 1.15 | 51 | 134 |
| 2 | windows/process_creation | 6.7 | 101 | 1147 |
| 3 | cisco/aaa | 1.05 | 7 | 10 |
| 4 | linux/process_creation | 2.6 | 16 | 96 |
| 5 | bitbucket/audit | 1.0 | 4 | 12 |
