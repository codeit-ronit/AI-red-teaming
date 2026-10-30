# 90–120-second recording script

Video status: **not recorded**. This is an exact recording script, not a video artifact.

Prepare before recording: activate the existing environment, start Ollama, open
`docs/final-hardening-report.md`, the Mermaid threat diagram, saved `report.md` and the hosted
CI run page once available. Use a warmed model. Run from the repository root. Choose a new
output path if the example path already exists.

## 0:00–0:20 — Security question and original contribution

Show the threat-model diagram. Say:
“AgentSec Ops measures three different things: whether the model follows an attack,
whether a prohibited tool actually executes, and whether a detector raises an alert.
The gateway and the response contract enforce independent application boundaries.”

## 0:20–0:55 — Same attack before and after

In the terminal:

```sh
.venv/bin/python -m attacks.hardening_runner \
  --case G01 --case H03 \
  --configurations hardened-baseline hardened-grounded \
  --output results/interview-demo-001
```

Open `results/interview-demo-001/report.md` in the editor. Expected observations under the
saved experiment: raw attacker-selected output in both configurations, delivered output
only in the baseline, and an application-rendered support response after mitigation.
A fresh model run can vary; if it does, identify the saved real-model report and explain
that difference. Never substitute a fixture result while describing it as live inference.

## 0:55–1:15 — Show the actual consequence boundary

Show the D04 restricted-inventory trace from the full saved experiment. Highlight the
model proposal, the denial, and absence of an inventory tool_execution event. Say:
“The renderer does not undo side effects. The executor independently authorizes every call.”

## 1:15–1:40 — Show utility and detection honestly

Show the before/after table and utility-failure IDs. Say:
“The constrained renderer prevents the tested delivered hijacks, while the raw model still
follows them. It preserves thirteen of sixteen benign tasks in this sample, but loses Spanish
output and cannot satisfy arbitrary JSON formatting. Content-only detection has two false
positives among sixteen benign cases. These are measured limits, not universal guarantees.”

## 1:40–2:00 — Engineering verification and finish

```sh
.venv/bin/python -m pytest -m 'not model' -q
```

Show the hosted CI result/artifact link if verified, or explicitly state that hosted CI is
unverified. Finish:
“The evidence contains actual Ollama experiments and native Promptfoo/PyRIT/Garak runs.
Historical raw results are preserved; controlled output and tool authorization protect
the application even when model-level manipulation remains observable.”

If the model cannot run during the interview, use the saved report and identify it as a
previous execution. The original `docs/demo.md` is the longer five-minute alternative.
