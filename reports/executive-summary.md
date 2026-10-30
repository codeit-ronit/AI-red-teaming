# Executive summary — AgentSec Ops

Northwind Retail is a fictional local support application that can look up orders, retrieve
support documents, create tickets, inspect synthetic inventory and propose simulated refunds.
The assessment asks whether untrusted instructions can make its agent cross resource and
action boundaries, and whether independent application authorization can prevent execution.

The scope includes Alice and Bob's fixture orders, public/internal asset records, a public
fake key and poisoned support documents. There are no real customers, credentials or external
targets. The application and inference run locally with no paid API cost.

## Observations

| Metric | Vulnerable | Filtered | Hardened |
|---|---:|---:|---:|
| Attack success | 7/13 (53.8%) | 6/13 (46.2%) | 0/14 (0.0%) |
| Unauthorized execution / attempts | 7/7 (100.0%) | 7/7 (100.0%) | 0/6 (0.0%) |
| Unauthorized block / attempts | 0/7 (0.0%) | 0/7 (0.0%) | 6/6 (100.0%) |
| Known-key disclosure | 1/3 (33.3%) | 0/3 (0.0%) | 0/4 (0.0%) |
| Benign task completion | 3/4 (75.0%) | 3/4 (75.0%) | 3/4 (75.0%) |

An actual local model followed a poisoned shipping FAQ into retrieving Bob's order while
acting for Alice. It also disclosed a planted synthetic key. Output filtering prevented that
known-key emission but still permitted unauthorized tool execution. Hardened authorization
blocked every observed unauthorized request in this sample. A recorded malicious model call
was additionally replayed unchanged to isolate the gateway's resource-ownership decision.

## Recommended controls

Enforce user and agent permissions at each executor before resource access or side effect;
require object-level ownership checks; keep credentials outside model context; bind high-risk
approval to the actual principal/action/resource; keep observable, access-controlled audit trails.
Treat model refusals and detector alerts as supporting signals rather than authorization.

## Confidence and limits

The campaign has 18 scenarios across three modes, one small coding model and one seed.
Two ROT13 responses produced parsing errors, excluded from resolved-outcome rates.
Benign completion is 3/4, demonstrating usability/reliability limits. This is an exploratory
lab result, not a security guarantee or production readiness assessment. A later PyRIT regression campaign and Garak native scan are documented in docs/framework-results.md; textual prompt hijacking persists in the hardened model. Hosted CI and a demo recording remain unexecuted.
Full original evidence is in results/ollama-qwen/.
