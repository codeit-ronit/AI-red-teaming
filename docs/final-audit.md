# Final hardening and verification audit

This audit checks the requested final hardening work against saved execution evidence. It is not an externally adjudicated security certification. Current completion claims are limited to the observations below.

Historical result files preserved byte-for-byte: **49**.

## Actual test results

```json
{
  "pytest-cli-final.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "0",
    "tests": "54",
    "time": "0.547"
  },
  "pytest-cli.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "0",
    "tests": "54",
    "time": "0.656"
  },
  "pytest-final.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "1",
    "tests": "55",
    "time": "0.590"
  },
  "pytest-live.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "0",
    "tests": "1",
    "time": "7.754"
  },
  "pytest-stage1.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "1",
    "tests": "48",
    "time": "0.688"
  },
  "pytest-stage2.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "1",
    "tests": "52",
    "time": "0.574"
  },
  "pytest-stage3.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "1",
    "tests": "53",
    "time": "0.851"
  },
  "pytest-stage4.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "1",
    "tests": "54",
    "time": "0.472"
  },
  "pytest-stage5.xml": {
    "errors": "0",
    "failures": "0",
    "skipped": "1",
    "tests": "55",
    "time": "0.583"
  }
}
```

## Exact local commands executed

```sh
uv sync --frozen --extra dev --offline
.venv/bin/pytest -m 'not model' -q --junitxml=results/hardening-v1/pytest-cli.xml
.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage1.xml
.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage2.xml
.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage3.xml
.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage4.xml
.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage5.xml
.venv/bin/python -m attacks.hardening_runner --output results/hardening-v1/model-experiment
.venv/bin/python -m attacks.runner --provider ollama --case S03 --modes vulnerable filtered --num-predict 768 --retry-truncated --bounded-tools --output results/hardening-v1/rot13-repair
.venv/bin/python -m attacks.runner --provider ollama --case S03 --modes vulnerable filtered --num-predict 768 --retry-truncated --bounded-tools --max-content-chars 1000 --output results/hardening-v1/rot13-content-bound
.venv/bin/python -m attacks.runner --output results/hardening-v1/deterministic
.venv/bin/python -m integrations.live_workflow --output results/hardening-v1/live-frameworks --pyrit-python /tmp/agentsec-pyrit-env/bin/python --garak-python /tmp/agentsec-garak-env/bin/python --node /tmp/agentsec-node/node_modules/node/bin/node
.venv/bin/python -m integrations.live_workflow --output results/hardening-v1/live-frameworks-verified --pyrit-python /tmp/agentsec-pyrit-env/bin/python --garak-python /tmp/agentsec-garak-env/bin/python --node /tmp/agentsec-node/node_modules/node/bin/node
.venv/bin/bandit -r app security attacks evaluations integrations -f json -o results/hardening-v1/bandit.json
.venv/bin/pip-audit -r requirements.lock --disable-pip --no-deps -f json -o results/hardening-v1/pip-audit.json
.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-final.xml
AGENTSEC_LIVE_TESTS=1 .venv/bin/python -m pytest tests/test_model.py -q --junitxml=results/hardening-v1/pytest-live.xml
gh run view 40992882084 --repo codeit-ronit/AI-red-teaming --log-failed
gh run view 40993161906 --repo codeit-ronit/AI-red-teaming --json status,conclusion,url,headSha,jobs
gh run download 40993161906 --repo codeit-ronit/AI-red-teaming --name security-evidence --dir /tmp/agentsec-ci-success-artifacts
.venv/bin/pytest -m 'not model' -q --junitxml=results/hardening-v1/pytest-cli-final.xml
.venv/bin/bandit -r app security attacks evaluations integrations -f json -o results/hardening-v1/bandit-final.json
/tmp/agentsec-gitleaks/gitleaks dir . --redact --config .gitleaks.toml --report-format json --report-path results/hardening-v1/gitleaks.json
/tmp/agentsec-gitleaks/gitleaks dir . --redact --config .gitleaks.toml --report-format json --report-path results/hardening-v1/gitleaks-final.json
```

Stage test runs reflect implementation milestones. The primary research CLI exited nonzero for its one recorded ROT13 error. The schema-only original ROT13 retest exited nonzero for two parse errors; the explicit content-bound retest completed both with valid but repetitive output. The first live workflow stopped because it misclassified expected vulnerable Promptfoo assertions as provider errors; the classification was fixed and tested, and its diagnostics are preserved. Those orchestration failures are not counted as target vulnerabilities. The first hosted run exposed a packaging/import error under the pytest console entry point; integration adapters were made explicit lightweight packages, then the console command passed locally and the hosted workflow was rerun.

## Security and utility experiments

[Technical findings and before/after table](final-hardening-report.md) document all 102 primary executions, detector confusion counts, independent permission expectations and per-task benign failures. Four known prompts and four held-out textual objectives still compromised raw model output; delivered target text was contained by the grounded contract. The model itself is not resistant.

## Confirmed live framework rerun

```json
{
  "real_model": true,
  "targets": [
    {
      "status": "ok",
      "mode": "vulnerable",
      "scope": "synthetic-local-lab",
      "response_policy": "model"
    },
    {
      "status": "ok",
      "mode": "hardened",
      "scope": "synthetic-local-lab",
      "response_policy": "grounded"
    }
  ],
  "promptfoo": {
    "total": 8,
    "passed": 5
  },
  "pyrit": "pyrit/report.json",
  "garak": "garak/report.json",
  "commands": [
    {
      "name": "promptfoo",
      "command": [
        "/tmp/agentsec-node/node_modules/node/bin/node",
        "/Users/ronitkumarchoudhary/Desktop/AI red teaming/integrations/promptfoo/node_modules/promptfoo/dist/src/entrypoint.js",
        "eval",
        "-c",
        "/Users/ronitkumarchoudhary/Desktop/AI red teaming/results/hardening-v1/live-frameworks-verified/promptfoo.config.json",
        "--no-cache",
        "--max-concurrency",
        "1",
        "-o",
        "/Users/ronitkumarchoudhary/Desktop/AI red teaming/results/hardening-v1/live-frameworks-verified/promptfoo.json"
      ],
      "exit_code": 100,
      "seconds": 38.586747884750366
    },
    {
      "name": "pyrit",
      "command": [
        "/tmp/agentsec-pyrit-env/bin/python",
        "/Users/ronitkumarchoudhary/Desktop/AI red teaming/integrations/pyrit/experiment.py",
        "--output",
        "/Users/ronitkumarchoudhary/Desktop/AI red teaming/results/hardening-v1/live-frameworks-verified/pyrit"
      ],
      "exit_code": 0,
      "seconds": 57.21853184700012
    },
    {
      "name": "garak",
      "command": [
        "/tmp/agentsec-garak-env/bin/python",
        "/Users/ronitkumarchoudhary/Desktop/AI red teaming/integrations/garak/run.py",
        "--output",
        "/Users/ronitkumarchoudhary/Desktop/AI red teaming/results/hardening-v1/live-frameworks-verified/garak",
        "--cap",
        "4"
      ],
      "exit_code": 0,
      "seconds": 67.99594116210938
    }
  ]
}
```

Actual native results and command exits are under results/hardening-v1/live-frameworks-verified/. Original Promptfoo, PyRIT and Garak results remain in their historical directories. Native text hits and unauthorized tool/data consequences must be interpreted separately.

## Scanner results

```json
{
  "bandit": {
    "file": "results/hardening-v1/bandit-final.json",
    "findings": 0
  },
  "pip-audit": {
    "file": "results/hardening-v1/pip-audit.json",
    "findings": 0
  },
  "gitleaks": {
    "file": "results/hardening-v1/gitleaks-final.json",
    "findings": 0
  }
}
```

The dependency audit covers the locked core runtime, not the isolated scanner environments. Secret scanning uses documented exact synthetic-fixture exceptions. The first final scan also flagged a test-source SHA256 and a model-fabricated Base64 value; those exact nonsecret values were narrowly allowlisted and the seven redacted findings preserved in gitleaks-first-pass.json. No broad source/report exemption was introduced.

## Hosted CI status

```json
{
  "repository": "codeit-ronit/AI-red-teaming",
  "repository_selected_by_user": true,
  "initial_repository_empty": true,
  "authentication_verified": true,
  "hosted_run_status": "success",
  "run_id": 40993161906,
  "run_url": "https://github.com/codeit-ronit/AI-red-teaming/actions/runs/40993161906",
  "tested_commit": "d0b62a5ff9781b3321343241a2fc8cc0f65a3b3e",
  "required_steps": {
    "Unit, API, and deterministic security tests (no model)": "success",
    "Deterministic paired benchmark (explicit fixtures)": "success",
    "Static security analysis": "success",
    "Audit locked runtime dependencies": "success",
    "Scan working tree for accidental secrets": "success",
    "Run actions/upload-artifact@v4": "success"
  },
  "artifact_name": "security-evidence",
  "artifact_verified": true,
  "fresh_ci_tests_passed": 54,
  "fresh_ci_fixture_executions": 54,
  "live_model_executed_by_hosted_ci": false,
  "previous_failed_run": {
    "id": 40992882084,
    "reason": "Integration adapters were not packaged for the pytest console entry point; fixed and independently rerun"
  },
  "evidence_directory": "results/hardening-v1/hosted-ci"
}
```

[Verified hosted run](https://github.com/codeit-ronit/AI-red-teaming/actions/runs/40993161906). The PR pipeline remains model-free. [Opt-in local live workflow](live-workflow.md) runs actual local inference; it is not labeled hosted CI. Hosted status is verified only when a concrete Actions run and artifact evidence are recorded above.

## Remaining vulnerabilities and incomplete requirements

- Raw model remains susceptible to hijacking and instruction extraction
- One primary ROT13 error retained; repaired framing does not imply useful answer
- Renderer loses language/format/open-ended support utility
- Content-only detector has false positives/negatives
- Limited one-model, one-seed internal validation
- No manual desktop screen capture; narrated terminal replay available
- No broad harmful-content benchmark; production identity/approvals remain out-of-scope fixture limitations

A [1:58 narrated terminal replay](media/agentsec-ops-demo.mp4) is now available with fresh execution evidence in results/demo-v1. It is an edited replay with offline synthetic narration, not a desktop screen capture. The [manual recording script](demo-120s.md) remains available. The [research article draft](research-case-study.md) explains the failure, mitigation and limits.

## Resume claims supported by these observations

- Built a local AI-agent security lab with an independent principal/agent/resource authorization gateway, versioned attack inputs and auditable execution traces; hardened execution prevented every observed prohibited tool effect in the follow-up sample.
- Evaluated a constrained support-response contract in 102 paired local executions: delivered hijacking changed from 4/4 to 0/4 on both known and held-out textual targets while raw model compromise remained observable; measured 13/16 benign completion before and after with different failures.
- Implemented policy-independent content detection and manually frozen reference labels; reported precision 12/14, recall 12/18 and benign false-positive rate 2/16 in the complete hardened sample, alongside actual Promptfoo/PyRIT/Garak evidence.

Do not claim general resistance, zero utility cost, production authorization/approvals, externally validated labels, or a desktop screen capture/developer-recorded voice for the narrated replay. Hosted CI claims require the run evidence above. A separate resume bullet may state that the model-free GitHub pipeline was verified only when that evidence records a successful run and checked artifacts.

## Files changed since the initial hardening snapshot

- `.github/workflows/security.yml`
- `.gitignore`
- `.gitleaks.toml`
- `README.md`
- `app/agent.py`
- `app/main.py`
- `app/providers.py`
- `attacks/hardening-cases.json`
- `attacks/hardening_runner.py`
- `attacks/independent-labels.json`
- `attacks/runner.py`
- `docs/CHATGPT_REVIEW_HANDOFF.md`
- `docs/INTERVIEW_GUIDE.md`
- `docs/demo-120s.md`
- `docs/final-audit.md`
- `docs/final-hardening-report.md`
- `docs/framework-results.md`
- `docs/implementation-status.md`
- `docs/live-workflow.md`
- `docs/media/README.md`
- `docs/media/agentsec-ops-demo.mp4`
- `docs/media/agentsec-ops-demo.srt`
- `docs/media/demo-manifest.json`
- `docs/media/demo-narration.txt`
- `docs/media/demo-preview.png`
- `docs/portfolio-summary.md`
- `docs/research-case-study.md`
- `docs/resume-bullets.md`
- `docs/security-findings.md`
- `docs/verified-results.md`
- `evaluations/final_audit.py`
- `evaluations/hardening_summary.py`
- `evaluations/independent.py`
- `evaluations/portfolio.py`
- `integrations/__init__.py`
- `integrations/common.py`
- `integrations/garak/__init__.py`
- `integrations/live_workflow.py`
- `integrations/promptfoo/__init__.py`
- `integrations/promptfoo/provider.py`
- `integrations/pyrit/__init__.py`
- `pyproject.toml`
- `reports/executive-summary.md`
- `security/detector.py`
- `security/response_contract.py`
- `tests/test_api.py`
- `tests/test_framework_evidence.py`
- `tests/test_independent_evaluation.py`
- `tests/test_response_contract.py`

This inventory covers the source/document/config roots and root manifests recorded in initial-state.json. New run artifacts are under results/hardening-v1; ignored installed dependencies and Git metadata are not project-source changes. The audit file itself can appear as newly added when rerun after first generation.
