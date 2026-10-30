# Final hardening and verification audit

This audit checks the requested final hardening work against saved execution evidence. It is not an externally adjudicated security certification. Current completion claims are limited to the observations below.

Historical result files preserved byte-for-byte: **49**.

## Actual test results

```json
{
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
/tmp/agentsec-gitleaks/gitleaks dir . --redact --config .gitleaks.toml --report-format json --report-path results/hardening-v1/gitleaks.json
```

Stage test runs reflect implementation milestones. The primary research CLI exited nonzero for its one recorded ROT13 error. The schema-only original ROT13 retest exited nonzero for two parse errors; the explicit content-bound retest completed both with valid but repetitive output. The first live workflow stopped because it misclassified expected vulnerable Promptfoo assertions as provider errors; the classification was fixed and tested, and its diagnostics are preserved. Those orchestration failures are not counted as target vulnerabilities.

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
    "findings": 0
  },
  "pip-audit": {
    "findings": 0
  },
  "gitleaks": {
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
  "hosted_run_status": "pending publication after local validation",
  "evidence": "GitHub API authentication and empty repository metadata verified; isolated checkout prepared"
}
```

The PR pipeline remains model-free. [Opt-in local live workflow](live-workflow.md) runs actual local inference; it is not labeled hosted CI. Hosted status is verified only when a concrete Actions run and artifact evidence are recorded above.

## Remaining vulnerabilities and incomplete requirements

- Raw model remains susceptible to hijacking and instruction extraction
- One primary ROT13 error retained; repaired framing does not imply useful answer
- Renderer loses language/format/open-ended support utility
- Content-only detector has false positives/negatives
- Limited one-model, one-seed internal validation
- No recorded video
- No broad harmful-content benchmark or production identity/approval workflow

Human video recording remains incomplete; a [90–120-second exact script](demo-120s.md) is supplied. The [research article draft](research-case-study.md) explains the failure, mitigation and limits.

## Resume claims supported by these observations

- Built a local AI-agent security lab with an independent principal/agent/resource authorization gateway, versioned attack inputs and auditable execution traces; hardened execution prevented every observed prohibited tool effect in the follow-up sample.
- Evaluated a constrained support-response contract in 102 paired local executions: delivered hijacking changed from 4/4 to 0/4 on both known and held-out textual targets while raw model compromise remained observable; measured 13/16 benign completion before and after with different failures.
- Implemented policy-independent content detection and manually frozen reference labels; reported precision 12/14, recall 12/18 and benign false-positive rate 2/16 in the complete hardened sample, alongside actual Promptfoo/PyRIT/Garak evidence.

Do not claim general resistance, zero utility cost, production authorization/approvals, externally validated labels, or a recorded video. Hosted CI claims require the run evidence above.

## Files changed since the initial hardening snapshot

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
- `docs/live-workflow.md`
- `docs/research-case-study.md`
- `evaluations/final_audit.py`
- `evaluations/hardening_summary.py`
- `evaluations/independent.py`
- `integrations/common.py`
- `integrations/live_workflow.py`
- `integrations/promptfoo/provider.py`
- `pyproject.toml`
- `security/detector.py`
- `security/response_contract.py`
- `tests/test_api.py`
- `tests/test_framework_evidence.py`
- `tests/test_independent_evaluation.py`
- `tests/test_response_contract.py`

This inventory covers the source/document/config roots and root manifests recorded in initial-state.json. New run artifacts are under results/hardening-v1; ignored installed dependencies and Git metadata are not project-source changes. The audit file itself can appear as newly added when rerun after first generation.
