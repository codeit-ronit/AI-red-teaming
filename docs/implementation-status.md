# Implementation status and acceptance evidence

| Milestone | Status | Evidence |
|---|---|---|
| M0 inspect | Complete | Original README preserved; Python, installed model and tool inventory inspected |
| M1 target | Complete | FastAPI, 5 tools, fixture identities/data, three modes, actual Ollama adapter |
| M2 authorization | Complete | Schema checks, principal/agent scope, ownership, simulated bound approval, audit events, tests |
| M3 benchmark | Complete | 18 scenarios, 54 paired executions for fixtures and model campaign; direct/indirect/API cases |
| M4 detection/reporting | Complete | Original event rules, confusion metrics, JSONL/JSON/Markdown, actual-model case study and replay |
| M5 Promptfoo | Implemented and locally executed | Pinned CLI/provider/config and actual saved outputs |
| M5 PyRIT | Implemented and locally executed | 12 real HTTP evaluations; native target, JSON converter and key scorer; correlated application outcomes |
| M5 Garak | Implemented and locally executed | 24 native probe requests, reports/hitlogs/HTML; all native attempts correlated to private target traces |
| M6 CI | Hosted run verified | 54 tests, deterministic benchmark, Bandit, pip-audit, Gitleaks and uploaded artifacts verified; see final-audit.md |
| M6 documentation | Complete | README, architecture, threat model, methods, findings, case study, portfolio, executive summary, interview guide |
| Short working demo | Narrated terminal replay completed | docs/media/agentsec-ops-demo.mp4; fresh capture, trace evidence and media verification in results/demo-v1 |

## MVP acceptance mapping

1. Local startup: real Uvicorn startup and `results/http-smoke.json`.
2. Authorized task: Alice's own order returns 200; core and model benign cases use registered tools.
3. Vulnerable authorization failure: API A01 and actual model D01/I02/T01/T02/T03 evidence.
4. Hardened equivalent denied: paired runs, authorization tests and captured-proposal replay.
5. Malicious document tested against model: I01–I03 raw messages and responses in model traces.
6. Model behavior distinct from gateway: proposal field, authorization decisions, execution events and replay.
7. Machine-readable traces: JSONL and report JSON for each core campaign.
8. Observed metrics: explicit numerators/denominators generated from events and labels.
9. Testable detector: alerts and regression coverage for denied calls, retrieval, known keys and repetition.
10. Reports/mitigation: generated findings, paired retests and human-readable real execution case study.
11. Tests: core pytest evidence; model tests separately marked and opt-in.
12. Free/model-free CI: standard workflow uses fixtures and open-source scanners.
13. Setup: project-local venv, uv lock, hash-locked runtime requirements, tested CLI/API commands.
14. Controlled scope: synthetic identities/orders/key/assets, loopback-only examples, no paid services.

The broad brief is implemented as an MVP with explicit optional-integration and production-readiness
limits. The external-framework experiments are now executed; see [results](framework-results.md). Hosted CI is now verified with a run/artifact receipt. A 1:58 narrated terminal-replay demonstration is now available; a separate manual desktop screen recording is not provided. See [final audit](final-audit.md) for the new response contract, frozen reference labels, benign utility costs and remaining raw model vulnerabilities.
