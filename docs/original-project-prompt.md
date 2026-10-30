# Project: AgentSec Ops — Automated AI Red-Teaming & Security Evaluation Framework

## 1. Your role

Act as a senior AI Security Research Engineer, Application Security Engineer, and Python Backend Architect.

Your task is to **build a working, standalone, reproducible AI security research project** based on the attached README.

Do not simply produce architecture documents, boilerplate, or a project skeleton. Implement functioning software, execute tests, collect genuine results where a model is available, and provide complete documentation.

The project is intended for a **Security Research Intern application at Harness Security Labs**. Engineering depth, reproducibility, realistic threat models, security testing, and clear documentation are more important than superficial features.

### Important constraints

- Development machine: MacBook Pro M2, 8GB RAM.
- Budget: ₹0. No paid APIs or cloud infrastructure.
- Local models through Ollama are preferred.
- Reuse installed tools and models where possible.
- Keep the system standalone; it must not depend on RECAP.
- Avoid Kubernetes, complex infrastructure, paid services, and elaborate frontends.
- Use Python for core application, detection, and evaluation logic.
- Prioritize a functioning MVP over implementing every optional integration.
- Only attack applications, agents, accounts, and data belonging to this controlled laboratory.
- Use synthetic credentials and test data exclusively.
- Do not invent benchmark scores, completed experiments, successful exploits, or research findings.

**Time constraint:** Optimize for approximately 6 hours of core implementation effort, with optional enhancements only after the MVP passes its acceptance tests.

Do not spend time on unnecessary clarification questions. Inspect the repository, make reasonable technical choices, implement, test, and document your decisions.

---

## 2. Project objective

Build an automated security-testing system that can:

1. Create or run deliberately vulnerable LLM applications.
2. Execute controlled adversarial attacks.
3. Test direct and indirect prompt injection.
4. Test jailbreaks, system-prompt leakage, and synthetic-secret disclosure.
5. Test unauthorized agent tool invocation.
6. Detect application and API authorization violations.
7. Implement deterministic security controls.
8. Evaluate attack success and detection effectiveness separately.
9. Compare vulnerable and hardened configurations.
10. Generate reproducible technical security assessment reports.
11. Automate security regression testing.
12. Map actual findings to relevant OWASP LLM/Agentic AI and MITRE ATLAS references.

The key research question is:

**Can an attacker manipulate an LLM application or action-taking AI agent into violating its intended security boundaries, and can independent security controls prevent harmful consequences even when the model follows malicious instructions?**

---

## 3. Target application: Northwind Retail

Build a fictional customer-support application exposing a FastAPI interface and communicating with an LLM through Ollama.

The target must support two distinct operating modes:

- `vulnerable`: intentionally lacks selected controls for reproducible testing.
- `hardened`: applies security controls at deterministic application and tool-execution boundaries.

The same attack suite must run against both configurations.

Use explicit authorization context, synthetic customer records, and fake secrets.

### Features

- Customer-support chatbot.
- Order lookup.
- Support ticket creation.
- Retrieval of customer-support documents.
- Simulated internal asset inventory.
- An intentionally restricted administrative operation.
- Structured agent tool calls and responses.

Model-facing tools should include:

- `get_order(order_id)`
- `create_support_ticket(description)`
- `read_support_document(document_id)`
- `get_asset_inventory(asset_id)`
- `admin_refund_order(order_id)`

Do not expose real customer data, infrastructure, or external services.

The target should be reasonably realistic but minimal. A small SQLite database or in-memory fixtures are sufficient.

---

## 4. Attack categories

Implement a version-controlled attack dataset containing benign and adversarial cases.

### A. Direct prompt injection

Test whether attacker-controlled user instructions override the application's defined task or safety boundaries.

### B. Indirect prompt injection

Insert malicious instructions into lower-trust material:

- Retrieved support documents.
- Knowledge-base articles.
- Mock tool responses.
- Simulated diagnostic logs.

The attacker should not control the system instructions or tool-authorization configuration.

### C. System-prompt leakage

Test whether the model discloses protected system-level instructions or controlled canary markers.

### D. Sensitive-data disclosure

Plant synthetic secrets only.

Compare:

1. A vulnerable configuration with a fake secret in model context.
2. A configuration with output filtering.
3. A hardened configuration where the secret is excluded from model context and protected by application-level authorization.

Demonstrate why deterministic access controls are preferable to relying on model refusals alone.

### E. Encoding and instruction-obfuscation tests

Include a small set of controlled encoding-based attacks, such as Base64 or ROT13.

### F. Agent tool abuse

Inject instructions that attempt to make the agent:

- Invoke a prohibited administrative tool.
- Access another user's order.
- Query a restricted inventory record.
- Perform an operation requiring approval.
- Treat tool-output text as a trusted command.

The application must check every proposed tool call independently of the LLM.

### G. Application/API authorization

Create two synthetic customers, Alice and Bob.

Test whether Alice can access Bob's order through:

- Direct API requests.
- Agent-mediated tool calls.
- Malicious instructions in retrieved documents.

Demonstrate an intentionally vulnerable BOLA/IDOR configuration and a hardened configuration that enforces object-level authorization.

All attacks must stay entirely within the local test environment.

---

## 5. Security policy and execution gateway

Implement a small, original Python security enforcement layer.

This is a major engineering contribution and must not be replaced by a prompt telling the LLM to behave safely.

Required controls:

- Explicit principal/user identity.
- Separate simulated agent identity.
- Tool allow-list.
- Resource-level authorization.
- Least-privilege policy evaluation.
- Human approval requirement for high-risk actions.
- Deny-by-default behavior.
- Structured authorization decisions.
- Audit logging.

Security decisions must take place **before executing tool calls**.

Use a clear policy interface such as:

`authorize(principal, agent_identity, tool_name, resource_id, action, approval_context)`

Return a structured decision with allow/deny, reason, policy identifier, and relevant audit fields.

For the initial MVP, approval can be simulated through explicit test fixtures. Do not pretend a simulated approval is a production approval workflow.

Optional, only after core completion:

- Scoped, expiring mock credentials.
- Emergency agent-access revocation.

These must have real enforcement tests if implemented.

---

## 6. Custom attack detection engine

Build an original Python event-based detection component.

The detector should analyze structured events and identify:

- Unauthorized tool-call attempts.
- Cross-user resource-access attempts.
- Attempts to disclose known synthetic secrets.
- Suspicious attempts to turn retrieved content into tool instructions.
- Repeated prohibited operations.

Separate **attack detection** from **policy enforcement**.

A request may be detected but not blocked, or blocked without the detector correctly identifying the malicious instruction.

Define ground-truth labels for evaluation cases. Track:

- True positives.
- False positives.
- True negatives.
- False negatives.

Calculate precision, recall, F1, and false-positive rate.

Use explicit detection rules and documented limitations. Avoid claiming that simple keyword matching provides comprehensive prompt-injection detection.

---

## 7. Automated security evaluation

Implement a Python evaluation runner.

Each attack case should contain:

- Test identifier.
- Attack category.
- Legitimate task.
- Attacker-controlled input.
- Target configuration.
- Expected security invariant.
- Expected authorization behavior.
- Ground-truth label.

For each execution, record:

- Model/provider identifier.
- Test configuration.
- Attack attempt.
- Model response.
- Proposed tool calls.
- Authorization decisions.
- Actual tool-execution results.
- Detection decisions.
- Evaluation outcome.
- Execution duration.

### Metrics

Calculate:

- Attack Success Rate (ASR).
- Unauthorized-action execution rate.
- Unauthorized-action block rate.
- Synthetic-secret disclosure rate.
- Detection precision, recall, and F1.
- False-positive rate.
- Benign task-completion rate.

Use appropriate denominators and clearly defined success criteria.

Do not automatically equate a model proposing a prohibited action with a successful unauthorized execution.

Distinguish model compromise, policy enforcement, and detector performance.

Run the same scenarios across vulnerable and hardened configurations, using identical inputs where possible.

A model's nondeterminism must be acknowledged. Store model versions, seeds if supported, prompts, and execution configuration.

---

## 8. Red-teaming framework integration

The original README proposes Garak, PyRIT, and Promptfoo.

Keep them in the architecture, but implement them according to the following priorities.

### Priority 1 — Promptfoo

Integrate Promptfoo for repeatable LLM red-team evaluations.

Use it for attack datasets, assertions, baseline comparisons, and saved test results.

Ensure its configuration targets the actual local application or model instead of producing fake results.

### Priority 2 — Microsoft PyRIT

Add a minimal, separately runnable PyRIT experiment.

Demonstrate an adversarial prompt sent to the same controlled target, with the actual response and an interpretable evaluation result.

Follow the current installed version's official APIs. Do not invent imports or unsupported interfaces.

### Priority 3 — Garak

Add a minimal Garak integration for relevant prompt-injection and leakage probes, if compatible with the available model and remaining time.

Garak must not block completion of the core application.

**Important:** The original Python evaluation engine must work even when Promptfoo, PyRIT, or Garak are not installed.

The project should demonstrate original engineering, not just a wrapper around third-party scanners.

---

## 9. Mitigation and retesting

Implement an actual before/after security experiment.

For every demonstrated vulnerability:

1. Define the legitimate task and attacker-controlled surface.
2. Reproduce the insecure behavior.
3. Capture the execution trace.
4. Explain the violated security invariant.
5. Apply a concrete mitigation.
6. Rerun the identical test.
7. Report the new outcome.
8. Document remaining risks and limitations.

At least one experiment must demonstrate **model-level manipulation versus independent tool-execution authorization**.

Example research question:

"If a model accepts malicious instructions from a retrieved support document, does the authorization gateway still prevent a prohibited administrative operation?"

Do not hardcode outcomes or claim that the attack succeeded if the model did not actually follow the injected instructions.

---

## 10. Security regression tests

Implement automated tests using Pytest.

Required coverage:

- Cross-user access denial.
- Authorized access success.
- Unauthorized tool-call blocking.
- Approval-required action handling.
- Synthetic-secret protection.
- Security event generation.
- Detection metric correctness.
- Malformed tool calls.
- Unknown tool names.
- Missing identity.
- Deny-by-default policy behavior.

Include deterministic mock-model tests so the core suite runs without Ollama.

Add actual LLM integration tests separately.

Use clear markers or test classifications to distinguish:

- Unit tests.
- Deterministic security tests.
- Integration tests.
- Model-dependent adversarial experiments.

---

## 11. CI/CD and software supply-chain checks

Create a GitHub Actions workflow that runs without paid APIs, GPU hardware, or an Ollama server.

The standard CI pipeline must execute:

- Python unit tests.
- Deterministic security regression tests.
- Dependency vulnerability scanning.
- Static security checks.
- Synthetic secret scanning.

Prefer lightweight, maintained open-source tools such as:

- Bandit or Semgrep for static analysis.
- pip-audit for Python dependency auditing.
- Gitleaks for detecting accidentally committed secrets.

Use pinned dependencies or reproducible lockfiles where practical.

The CI job must not claim to execute LLM-based security benchmarks when no model endpoint is available.

Document separate local commands for running those benchmarks.

For supply-chain findings, distinguish actual dependency vulnerabilities from scanner configuration failures or missing data.

---

## 12. Vulnerability reports

Automatically generate Markdown and JSON reports for test runs.

Each substantive finding should include:

- Finding ID.
- Vulnerability title.
- Severity and severity rationale.
- Affected component.
- Attack surface and trust boundary.
- Preconditions.
- Reproduction steps.
- Observed evidence.
- Security impact.
- Relevant OWASP category.
- Relevant MITRE ATLAS technique, when applicable.
- Mitigation.
- Retest result.
- Known limitations.

Keep scanner output separate from validated security findings.

Do not label every model refusal failure or unexpected response as a confirmed vulnerability.

Create at least one detailed human-readable case study based on a real test execution.

---

## 13. Repository structure

Use a structure similar to:

```text
agentsec-ops/
├── app/
│   ├── main.py
│   ├── agent.py
│   ├── tools.py
│   ├── models.py
│   └── fixtures/
├── security/
│   ├── authorization.py
│   ├── policies.py
│   ├── detector.py
│   ├── audit.py
│   └── approvals.py
├── attacks/
│   ├── scenarios.json
│   └── runner.py
├── evaluations/
│   ├── metrics.py
│   ├── evaluator.py
│   └── reporting.py
├── integrations/
│   ├── promptfoo/
│   ├── pyrit/
│   └── garak/
├── tests/
├── reports/
├── docs/
│   ├── threat-model.md
│   ├── security-findings.md
│   └── architecture.md
├── .github/workflows/
├── pyproject.toml
├── README.md
└── .gitignore
```

Adapt this if a simpler structure results in more maintainable code.

Do not create empty placeholder modules just to satisfy the folder layout.

---

## 14. Development milestones

Implement in this order.

### M0 — Inspect and plan

- Review the provided README.
- Inspect existing repository contents.
- Check Python, Ollama, available local models, and installed dependencies.
- Identify the smallest architecture that meets the requirements.
- Avoid unnecessary installations.

### M1 — Working vulnerable target

- FastAPI chatbot and mock tools.
- Ollama adapter.
- Synthetic data.
- Vulnerable and hardened configuration switches.
- Smoke tests.

### M2 — Agent authorization

- Tool gateway.
- Identity and resource scoping.
- High-risk approval enforcement.
- Authorization audit events.
- Unit tests.

### M3 — Adversarial benchmark

- Direct and indirect prompt-injection scenarios.
- Synthetic-secret disclosure tests.
- Unauthorized tool-use tests.
- Cross-user access tests.
- Automated runner.
- Before/after comparisons.

### M4 — Detection and reporting

- Custom event detector.
- Security metrics.
- JSON and Markdown reports.
- Reproducible findings.

### M5 — External integrations

- Promptfoo integration.
- Minimal PyRIT example.
- Garak only if feasible.

### M6 — CI and portfolio polish

- GitHub Actions.
- Static/dependency/secret scanning.
- Documentation.
- Threat model.
- Research write-up.
- Reproducible demo instructions.

---

## 15. Acceptance criteria

The MVP is complete only when:

1. The application starts locally.
2. A legitimate user can complete an authorized request.
3. A deliberately vulnerable configuration demonstrates a real authorization failure under a controlled test.
4. The hardened configuration blocks the equivalent unauthorized operation.
5. A malicious retrieved document is tested against the model.
6. Model behavior and execution authorization are evaluated separately.
7. Attack outcomes are stored in machine-readable traces.
8. Metrics are calculated from observed results.
9. The custom detector produces testable security alerts.
10. Reports include reproducible evidence and mitigation outcomes.
11. Deterministic unit/security tests pass.
12. The standard CI workflow does not require paid or GPU-dependent services.
13. Setup instructions are accurate and usable.
14. No real credentials, proprietary data, or uncontrolled external targets are included.

If an LLM integration cannot run, complete the deterministic tests and clearly report model-based evaluations as unexecuted.

Do not substitute simulated behavior for real model test results without labeling it.

---

## 16. Documentation for GitHub and resume

The README must explain:

- What security problem the project solves.
- Why LLM and agent security matters.
- Threat model and attacker capabilities.
- Architecture and technology decisions.
- Vulnerable versus hardened configurations.
- How to run the project.
- How to reproduce a security test.
- How to interpret the results.
- Measured outcomes.
- Limitations.
- Future improvements.

Provide an architecture diagram and a short demonstration flow.

Prepare a separate `docs/portfolio-summary.md` containing:

1. A two-sentence project summary.
2. Three proposed resume bullets based ONLY on implemented features.
3. A list of verified technologies.
4. Actual measured security results.
5. A clear statement of incomplete features.

Never invent quantitative improvements or claim a defense guarantees security.

---

## 17. Working instructions

Work milestone by milestone, but continue implementing without asking for approval after every step.

After each milestone:

- Run the relevant tests.
- Fix defects.
- Document verified behavior.
- Record remaining limitations.
- Avoid regressions.

Prioritize secure and maintainable engineering over visual design.

If time or compute is constrained, preserve M1–M4 before spending effort on optional integrations.

**Final objective:** Deliver a functioning security research artifact that demonstrates original AI red-teaming, tool-authorization engineering, vulnerability reproduction, detection evaluation, and security reporting — not just a demonstration of running existing scanners.

Begin by examining the attached README and the repository. Then implement the smallest working end-to-end vertical slice before expanding functionality.