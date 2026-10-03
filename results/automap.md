### ATT&CK v8.2 (labels exactly as published)

Cells are the macro mean over mapped safeguards with a 95% percentile bootstrap interval (1,000 resamples of safeguards, seed 0).

| mapper | P@10 | R@20 | R@50 | MAP@200 | seconds |
|---|---|---|---|---|---|
| baseline-random | 0.062 [0.040, 0.086] | 0.045 [0.028, 0.069] | 0.096 [0.070, 0.126] | 0.033 [0.026, 0.041] | 0.05 |
| baseline-popularity | 0.206 [0.153, 0.260] | 0.147 [0.115, 0.183] | 0.330 [0.277, 0.381] | 0.161 [0.129, 0.196] | 0.05 |
| tfidf-direct | 0.162 [0.122, 0.203] | 0.162 [0.125, 0.204] | 0.271 [0.226, 0.316] | 0.120 [0.095, 0.148] | 0.26 |
| mitigation-bridge[tfidf] | 0.311 [0.244, 0.376] | 0.347 [0.283, 0.411] | 0.550 [0.479, 0.620] | 0.343 [0.281, 0.401] | 0.28 |
| embed-direct[all-MiniLM-L6-v2] | 0.166 [0.127, 0.208] | 0.180 [0.139, 0.228] | 0.293 [0.244, 0.350] | 0.130 [0.101, 0.161] | 1.21 |
| mitigation-bridge[all-MiniLM-L6-v2] | 0.384 [0.317, 0.457] | 0.395 [0.326, 0.465] | 0.621 [0.553, 0.696] | 0.417 [0.357, 0.478] | 2.26 |
| embed-direct[bge-small-en-v1.5] | 0.187 [0.143, 0.228] | 0.183 [0.141, 0.226] | 0.295 [0.241, 0.348] | 0.138 [0.107, 0.166] | 2.11 |
| mitigation-bridge[bge-small-en-v1.5] | 0.388 [0.323, 0.457] | 0.418 [0.352, 0.495] | 0.623 [0.551, 0.694] | 0.412 [0.353, 0.475] | 4.12 |

Random baseline over 10 seeds: P@10 0.055 +/- 0.007, R@20 0.04 +/- 0.006, MAP@200 0.031 +/- 0.003.

Oracle ceiling: a perfect ranker scores P@10 = 0.747, because 47 of 105 safeguards have fewer than 10 gold techniques.

Paired differences over the same safeguards (paired bootstrap, 2,000 resamples; two-sided sign-flip permutation test, 20,000 draws, p never 0; not multiplicity-adjusted):

| comparison (ATT&CK v8.2) | MAP@200 diff | 95% CI (paired bootstrap) | p (sign-flip) |
|---|---|---|---|
| mitigation-bridge[all-MiniLM-L6-v2] - mitigation-bridge[bge-small-en-v1.5] | +0.005 | [-0.044, +0.054] | 0.84 |
| mitigation-bridge[all-MiniLM-L6-v2] - baseline-popularity | +0.256 | [+0.192, +0.317] | 5.0e-05 |
| mitigation-bridge[tfidf] - baseline-popularity | +0.182 | [+0.120, +0.239] | 5.0e-05 |
| mitigation-bridge[all-MiniLM-L6-v2] - mitigation-bridge[tfidf] | +0.074 | [+0.020, +0.128] | 0.0081 |
| mitigation-bridge[all-MiniLM-L6-v2] - embed-direct[all-MiniLM-L6-v2] | +0.288 | [+0.230, +0.344] | 5.0e-05 |
| mitigation-bridge[tfidf] - tfidf-direct | +0.223 | [+0.169, +0.277] | 5.0e-05 |
| tfidf-direct - baseline-popularity | -0.041 | [-0.081, -0.004] | 0.039 |

### ATT&CK v19.2 (labels carried forward via revoked-by)

| mapper | P@10 | R@20 | R@50 | MAP@200 | seconds |
|---|---|---|---|---|---|
| baseline-random | 0.052 [0.031, 0.076] | 0.033 [0.021, 0.048] | 0.089 [0.065, 0.117] | 0.020 [0.015, 0.025] | 0.05 |
| baseline-popularity | 0.206 [0.153, 0.260] | 0.148 [0.116, 0.185] | 0.339 [0.285, 0.391] | 0.162 [0.130, 0.198] | 0.06 |
| tfidf-direct | 0.125 [0.093, 0.155] | 0.147 [0.113, 0.185] | 0.258 [0.208, 0.307] | 0.085 [0.068, 0.104] | 0.37 |
| mitigation-bridge[tfidf] | 0.272 [0.217, 0.330] | 0.300 [0.245, 0.355] | 0.544 [0.477, 0.608] | 0.285 [0.237, 0.332] | 0.42 |
| embed-direct[all-MiniLM-L6-v2] | 0.129 [0.098, 0.160] | 0.181 [0.139, 0.230] | 0.304 [0.249, 0.364] | 0.094 [0.072, 0.120] | 1.22 |
| mitigation-bridge[all-MiniLM-L6-v2] | 0.325 [0.267, 0.386] | 0.347 [0.285, 0.413] | 0.527 [0.456, 0.600] | 0.309 [0.261, 0.362] | 2.35 |
| embed-direct[bge-small-en-v1.5] | 0.143 [0.105, 0.181] | 0.154 [0.114, 0.198] | 0.269 [0.215, 0.325] | 0.094 [0.074, 0.115] | 2.12 |
| mitigation-bridge[bge-small-en-v1.5] | 0.334 [0.277, 0.394] | 0.363 [0.303, 0.435] | 0.558 [0.489, 0.635] | 0.323 [0.276, 0.372] | 4.35 |

Per-safeguard scores for every mapper: `results/automap_per_control.csv.gz`.

_Source: GitHub Actions `realdata` run [37092934843](https://github.com/rakshit-737/vantage/actions/runs/37092934843) at commit `6ff466dd6215` (Linux-6.17.0-1022-azure-x86_64-with-glibc2.39, Python 3.12.14)._
