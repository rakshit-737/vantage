# ADR 0004: Cost model and optimality check for the coverage recommender

- Status: accepted
- Date: 2026-09-26

## Context
The recommender is greedy weighted set cover (new techniques per unit cost). With the real
SigmaHQ catalog a naive cost of 1.0 per rule made onboarding `windows/process_creation`
(1,147 rules) look about 1,000 times more expensive than it is.

## Decision
- Log-source onboarding cost (relative units, `vantage/ingest/sigma.py:logsource_cost`):
  1.0 for standard OS and cloud audit logs (Windows Security/System, PowerShell, CloudTrail,
  Azure, M365, Okta, ...), 1.5 for agent- or config-dependent sources (Sysmon-class Windows
  categories, proxy, DNS, web server, Linux), 2.0 for heavier telemetry (auditd, Zeek, macOS).
- Rule deployment and tuning cost: 0.05 (20 rules cost about one standard log source).
- These are documented assumptions, not measurements. Edit the catalog JSON to use your own.

We benchmark greedy against an exact integer program (budgeted maximum coverage, solved with
`scipy.optimize.milp` / HiGHS) and three heuristics (`results/recommend.md`). On the Acme real
posture greedy matched the optimum at all seven budgets from 1 to 20 cost units, beat
"most rules first" by up to 31 techniques (budget 3), and beat random ordering by 4-17x.

## Consequences
- Recommendations are explainable: "onboard X, unlocks N rules, +M techniques".
- The ILP certifies optimality for this instance. In general, cost-ratio greedy only has a
  constant-factor guarantee for budgeted coverage when combined with a "best single affordable
  action" check (Khuller, Moss and Naor, 1999), which VANTAGE does not add; the ILP comparison is
  the empirical check, and `scipy` is only needed for the benchmark.
- Costs are coarse; a real deployment should replace them with its own estimates.
