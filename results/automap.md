### ATT&CK v8.2 (labels exactly as published)

| mapper | P@5 | P@10 | R@10 | R@20 | R@50 | MAP@200 | seconds |
|---|---|---|---|---|---|---|---|
| baseline-random | 0.061 | 0.062 | 0.02 | 0.045 | 0.096 | 0.033 | 0.03 |
| baseline-popularity | 0.253 | 0.206 | 0.1 | 0.147 | 0.33 | 0.161 | 0.07 |
| tfidf-direct | 0.19 | 0.162 | 0.114 | 0.162 | 0.271 | 0.12 | 1.61 |
| mitigation-bridge[tfidf] | 0.349 | 0.311 | 0.209 | 0.347 | 0.55 | 0.343 | 1.74 |
| embed-direct[all-MiniLM-L6-v2] | 0.2 | 0.166 | 0.115 | 0.18 | 0.293 | 0.13 | 17.4 |
| mitigation-bridge[all-MiniLM-L6-v2] | 0.432 | 0.384 | 0.294 | 0.395 | 0.621 | 0.417 | 16.17 |
| embed-direct[bge-small-en-v1.5] | 0.236 | 0.187 | 0.133 | 0.183 | 0.295 | 0.138 | 11.49 |
| mitigation-bridge[bge-small-en-v1.5] | 0.45 | 0.388 | 0.276 | 0.418 | 0.623 | 0.412 | 36.7 |

### ATT&CK v19.2 (labels carried forward via revoked-by)

| mapper | P@5 | P@10 | R@10 | R@20 | R@50 | MAP@200 | seconds |
|---|---|---|---|---|---|---|---|
| baseline-random | 0.042 | 0.052 | 0.013 | 0.033 | 0.089 | 0.02 | 0.04 |
| baseline-popularity | 0.253 | 0.206 | 0.1 | 0.148 | 0.339 | 0.162 | 0.08 |
| tfidf-direct | 0.13 | 0.125 | 0.108 | 0.147 | 0.258 | 0.085 | 2.37 |
| mitigation-bridge[tfidf] | 0.295 | 0.272 | 0.182 | 0.3 | 0.544 | 0.285 | 2.88 |
| embed-direct[all-MiniLM-L6-v2] | 0.131 | 0.129 | 0.103 | 0.181 | 0.304 | 0.094 | 8.3 |
| mitigation-bridge[all-MiniLM-L6-v2] | 0.366 | 0.325 | 0.227 | 0.347 | 0.527 | 0.309 | 17.59 |
| embed-direct[bge-small-en-v1.5] | 0.168 | 0.143 | 0.111 | 0.154 | 0.269 | 0.094 | 16.35 |
| mitigation-bridge[bge-small-en-v1.5] | 0.356 | 0.334 | 0.254 | 0.363 | 0.558 | 0.323 | 29.49 |
