> Historical campaign figures. Current hardening results, hosted CI verification and resume claims are in [final-audit.md](final-audit.md), [final-hardening-report.md](final-hardening-report.md) and [resume-bullets.md](resume-bullets.md).

# Portfolio summary

AgentSec Ops is a standalone local AI-security laboratory that measures prompt injection,
synthetic-secret disclosure and agent/API authorization failures against a Northwind support application.
It combines an original Python execution gateway, event detector and paired evidence-based evaluator
with actual Ollama experiments and deterministic CI regressions.

## Proposed resume bullets — implemented features only

- Built a FastAPI/Ollama red-teaming lab with 18 versioned scenarios, direct and indirect injection, API BOLA, structured tool traces, and JSON/Markdown assessment generation.
- Implemented principal/agent/resource authorization, strict tool schemas, simulated bound approvals and audit logging; the observed hardened model campaign executed 0 of 6 unauthorized attempts, versus 7 of 7 in the vulnerable campaign.
- Developed event-based security detection and confusion-matrix metrics, model-free pytest regressions, a live Promptfoo provider, and CI checks for static analysis, dependency advisories and accidental secrets.

## Verified technologies

Python 3.13, FastAPI, Pydantic, HTTPX, pytest, Uvicorn, Ollama, Qwen2.5-Coder 3B,
JSON Schema, Promptfoo, Bandit, pip-audit, Gitleaks, uv lockfiles. GitHub Actions workflow
is implemented and hosted execution/artifacts are verified in final-audit.md. PyRIT 1.1.0 and Garak 0.17.1 were installed in separate environments and executed; native and correlated application outcomes are preserved.

## Measured outcomes

| Metric | Vulnerable | Filtered | Hardened |
|---|---:|---:|---:|
| Attack success | 7/13 (53.8%) | 6/13 (46.2%) | 0/14 (0.0%) |
| Unauthorized execution / attempts | 7/7 (100.0%) | 7/7 (100.0%) | 0/6 (0.0%) |
| Unauthorized block / attempts | 0/7 (0.0%) | 0/7 (0.0%) | 6/6 (100.0%) |
| Known-key disclosure | 1/3 (33.3%) | 0/3 (0.0%) | 0/4 (0.0%) |
| Benign task completion | 3/4 (75.0%) | 3/4 (75.0%) | 3/4 (75.0%) |

Core tests: 38 passed; 1 model test skipped by default. Read [verified results](verified-results.md) for denominators,
model details, detector scores and error handling. Do not replace the distinct denominators
with a generalized “100% secure” or universal percentage-improvement claim.

## Incomplete features

Recorded video,
production authentication/approval UI, persistent effects, multi-seed/multi-model campaigns,
and general semantic leakage detection. The supplied video artifact is a recording script only.
