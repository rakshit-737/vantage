### Frameworks in one ATT&CK release (v19.2)

| framework | source ATT&CK | controls (mapped) | pairs | pairs/control | techniques | % of ATT&CK v19.2 | carried fwd / dropped | candidate techniques |
|---|---|---|---|---|---|---|---|---|
| CIS v8 | 8.2 | 105 | 2919 | 27.8 | 378 | 54.2 | 134 / 14 | 525 |
| NIST 800-53 | 16.1 | 109 | 5236 | 48.0 | 466 | 66.9 | 173 / 1 | 653 |
| AWS | 16.1 | 20 | 467 | 23.4 | 213 | 30.6 | 21 / 0 | 653 |
| Azure | 16.1 | 38 | 938 | 24.7 | 409 | 58.7 | 26 / 0 | 653 |
| GCP | 16.1 | 40 | 507 | 12.7 | 289 | 41.5 | 16 / 0 | 653 |
| M365 | 16.1 | 38 | 684 | 18.0 | 218 | 31.3 | 27 / 0 | 653 |
| CRI-2.1 | 16.1 | 60 | 2146 | 35.8 | 427 | 61.3 | 45 / 0 | 653 |
| CSA-CCM-4.1 | 17.1 | 57 | 783 | 13.7 | 212 | 30.4 | 40 / 0 | 677 |

`candidate techniques` = v19.2 techniques that existed (directly or via revoked-by) in the ATT&CK release the framework was mapped against; auto-mappers are scored over that set only.

Union over all frameworks: 594 techniques; mapped by every framework: 48.

Technique-set overlap (Jaccard):

|  | CIS v8 | NIST 800-53 | AWS | Azure | GCP | M365 | CRI-2.1 | CSA-CCM-4.1 |
|---|---|---|---|---|---|---|---|---|
| CIS v8 | 1.0 | 0.77 | 0.36 | 0.51 | 0.36 | 0.26 | 0.72 | 0.37 |
| NIST 800-53 | 0.77 | 1.0 | 0.35 | 0.61 | 0.47 | 0.35 | 0.84 | 0.39 |
| AWS | 0.36 | 0.35 | 1.0 | 0.4 | 0.39 | 0.26 | 0.36 | 0.44 |
| Azure | 0.51 | 0.61 | 0.4 | 1.0 | 0.5 | 0.35 | 0.59 | 0.37 |
| GCP | 0.36 | 0.47 | 0.39 | 0.5 | 1.0 | 0.42 | 0.45 | 0.4 |
| M365 | 0.26 | 0.35 | 0.26 | 0.35 | 0.42 | 1.0 | 0.36 | 0.38 |
| CRI-2.1 | 0.72 | 0.84 | 0.36 | 0.59 | 0.45 | 0.36 | 1.0 | 0.44 |
| CSA-CCM-4.1 | 0.37 | 0.39 | 0.44 | 0.37 | 0.4 | 0.38 | 0.44 | 1.0 |

### NIST SP 800-53B baselines (CTID mapping, base controls only)

| baseline | controls in baseline (incl. enhancements) | of which base controls with a CTID mapping | techniques mitigated | % of ATT&CK v19.2 | median controls per technique |
|---|---|---|---|---|---|
| LOW | 149 | 51 | 460 | 66.0 | 7 |
| MODERATE | 287 | 79 | 466 | 66.9 | 10 |
| HIGH | 370 | 83 | 466 | 66.9 | 10 |
| PRIVACY | 96 | 7 | 237 | 34.0 | 1 |

MODERATE adds 6 techniques over LOW (T1090.004, T1535, T1550.004, T1595.003, T1657, T1666); HIGH adds 0 over MODERATE.

### Auto-mapping transfer summary (TF-IDF encoder)

MAP@200 with 95% bootstrap intervals over the test framework's controls; differences are paired bootstraps over the same controls (`*` = interval excludes 0). The pooled source (every *other* framework's labels) is fixed in advance, so no test labels pick it. Nested LOO re-chooses the transfer weights without the held-out control. Text-rich frameworks: CIS v8, NIST 800-53, CSA-CCM-4.1, CRI-2.1; the cloud security-stack mappings only give a product name.

| test framework | n | direct (no bridge) | zero-shot bridge | bridge - direct (paired) | pooled transfer (all other fw) | pooled - zero-shot (paired) | single-source transfer mean (min-max) | sources below zero-shot | in-framework nested LOO |
|---|---|---|---|---|---|---|---|---|---|
| CIS v8 | 105 | 0.115 | 0.346 [0.289, 0.399] | +0.231 [+0.181, +0.280] * | 0.374 [0.325, 0.428] | +0.028 [-0.013, +0.068] | 0.268 (0.163-0.349) | 6/7 | 0.531 [0.469, 0.592] |
| NIST 800-53 | 109 | 0.091 | 0.214 [0.173, 0.259] | +0.124 [+0.087, +0.166] * | 0.258 [0.215, 0.301] | +0.044 [+0.010, +0.075] * | 0.182 (0.126-0.252) | 6/7 | 0.383 [0.323, 0.437] |
| AWS | 20 | 0.052 | 0.124 [0.055, 0.215] | +0.072 [+0.009, +0.153] * | 0.204 [0.113, 0.312] | +0.080 [+0.037, +0.128] * | 0.169 (0.145-0.222) | 0/7 | 0.195 [0.141, 0.249] |
| Azure | 38 | 0.137 | 0.186 [0.124, 0.255] | +0.049 [-0.012, +0.114] | 0.229 [0.175, 0.290] | +0.043 [-0.020, +0.103] | 0.170 (0.126-0.197) | 5/7 | 0.167 [0.122, 0.215] |
| GCP | 40 | 0.044 | 0.092 [0.047, 0.150] | +0.048 [+0.018, +0.091] * | 0.194 [0.136, 0.261] | +0.102 [+0.043, +0.160] * | 0.139 (0.092-0.183) | 0/7 | 0.167 [0.125, 0.218] |
| M365 | 38 | 0.075 | 0.092 [0.060, 0.124] | +0.017 [-0.026, +0.056] | 0.176 [0.122, 0.233] | +0.084 [+0.046, +0.124] * | 0.136 (0.094-0.177) | 0/7 | 0.452 [0.372, 0.533] |
| CRI-2.1 | 60 | 0.121 | 0.359 [0.284, 0.437] | +0.238 [+0.155, +0.322] * | 0.416 [0.348, 0.485] | +0.056 [+0.006, +0.104] * | 0.281 (0.183-0.348) | 7/7 | 0.390 [0.314, 0.469] |
| CSA-CCM-4.1 | 57 | 0.115 | 0.245 [0.180, 0.309] | +0.129 [+0.056, +0.202] * | 0.338 [0.274, 0.402] | +0.093 [+0.047, +0.139] * | 0.216 (0.149-0.275) | 5/7 | 0.432 [0.354, 0.519] |

#### Single-source transfer matrix, MAP@200 (tfidf); first row = zero-shot bridge

Diagonal = leave-one-out with weights tuned on the same folds (optimistic; see nested LOO above).

| train / test | CIS v8 | NIST 800-53 | AWS | Azure | GCP | M365 | CRI-2.1 | CSA-CCM-4.1 |
|---|---|---|---|---|---|---|---|---|
| zero-shot | 0.346 | 0.214 | 0.124 | 0.186 | 0.092 | 0.092 | 0.359 | 0.245 |
| CIS v8 | 0.531 | 0.252 | 0.148 | 0.163 | 0.092 | 0.101 | 0.335 | 0.237 |
| NIST 800-53 | 0.344 | 0.383 | 0.145 | 0.141 | 0.124 | 0.094 | 0.343 | 0.216 |
| AWS | 0.170 | 0.142 | 0.231 | 0.197 | 0.183 | 0.172 | 0.189 | 0.164 |
| Azure | 0.279 | 0.172 | 0.222 | 0.200 | 0.170 | 0.146 | 0.274 | 0.227 |
| GCP | 0.250 | 0.184 | 0.211 | 0.183 | 0.182 | 0.177 | 0.293 | 0.245 |
| M365 | 0.163 | 0.126 | 0.160 | 0.126 | 0.167 | 0.457 | 0.183 | 0.149 |
| CRI-2.1 | 0.349 | 0.210 | 0.147 | 0.183 | 0.120 | 0.126 | 0.390 | 0.275 |
| CSA-CCM-4.1 | 0.324 | 0.186 | 0.149 | 0.196 | 0.115 | 0.134 | 0.348 | 0.432 |

Labels-only prior (train framework's technique frequencies), MAP@200 (tfidf):

| train / test | CIS v8 | NIST 800-53 | AWS | Azure | GCP | M365 | CRI-2.1 | CSA-CCM-4.1 |
|---|---|---|---|---|---|---|---|---|
| CIS v8 | 0.162 | 0.155 | 0.066 | 0.068 | 0.059 | 0.046 | 0.129 | 0.079 |
| NIST 800-53 | 0.142 | 0.161 | 0.125 | 0.086 | 0.103 | 0.062 | 0.135 | 0.108 |
| AWS | 0.073 | 0.104 | 0.231 | 0.169 | 0.149 | 0.164 | 0.096 | 0.086 |
| Azure | 0.087 | 0.100 | 0.190 | 0.150 | 0.121 | 0.118 | 0.097 | 0.082 |
| GCP | 0.074 | 0.099 | 0.198 | 0.144 | 0.153 | 0.153 | 0.090 | 0.101 |
| M365 | 0.063 | 0.077 | 0.137 | 0.092 | 0.132 | 0.350 | 0.092 | 0.074 |
| CRI-2.1 | 0.126 | 0.130 | 0.091 | 0.086 | 0.084 | 0.085 | 0.136 | 0.111 |
| CSA-CCM-4.1 | 0.089 | 0.100 | 0.127 | 0.091 | 0.113 | 0.119 | 0.119 | 0.169 |

Fitted weights (beta = kNN label transfer, gamma = prior): CIS v8: 0.25/0.0; NIST 800-53: 0.25/0.0; AWS: 0.0/0.5; Azure: 0.25/0.1; GCP: 0.0/0.25; M365: 1.0/0.5; CRI-2.1: 0.25/0.0; CSA-CCM-4.1: 0.25/0.0; pooled -> CIS v8: 0.25/0.0; pooled -> NIST 800-53: 0.25/0.0; pooled -> AWS: 0.25/0.0; pooled -> Azure: 0.25/0.0; pooled -> GCP: 0.25/0.0; pooled -> M365: 0.25/0.0; pooled -> CRI-2.1: 0.25/0.0; pooled -> CSA-CCM-4.1: 0.25/0.0

NIST 800-53 zero-shot MAP@200, full OSCAL statement vs CTID title only: tfidf: 0.214 vs 0.197

Wall time: 453 s (tfidf).
