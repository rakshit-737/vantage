### Techniques newly detectable vs onboarding budget (start: Acme real posture, 153 techniques already detectable, 99 candidate log sources)

| budget | greedy | optimal | greedy/optimal | most-rules | cheapest | random(mean) | greedy_ms | ilp_ms |
|---|---|---|---|---|---|---|---|---|
| 1 | 8 | 8 | 1.0 | 8 | 0 | 1.1 | 201 | 42 |
| 2 | 51 | 51 | 1.0 | 51 | 6 | 4.6 | 176 | 23 |
| 3 | 64 | 64 | 1.0 | 33 | 7 | 3.8 | 302 | 79 |
| 5 | 85 | 85 | 1.0 | 61 | 8 | 11.0 | 934 | 251 |
| 8 | 152 | 152 | 1.0 | 152 | 9 | 19.5 | 1287 | 59 |
| 12 | 175 | 175 | 1.0 | 155 | 10 | 25.7 | 2384 | 52 |
| 20 | 201 | 201 | 1.0 | 185 | 13 | 51.4 | 5880 | 58 |

### Greedy plan (first 5 steps)

| step | onboard | cost | new_techniques | rules_unlocked |
|---|---|---|---|---|
| 1 | windows/ps_script | 1.15 | 51 | 134 |
| 2 | windows/process_creation | 6.7 | 101 | 1147 |
| 3 | cisco/aaa | 1.05 | 7 | 10 |
| 4 | linux/process_creation | 2.6 | 16 | 96 |
| 5 | bitbucket/audit | 1.0 | 4 | 12 |
