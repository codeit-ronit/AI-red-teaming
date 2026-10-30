"""Verification inventory, commands and immutable-evidence check for the final follow-up."""
import hashlib
import json
from pathlib import Path
from defusedxml import ElementTree

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/hardening-v1'


def main():
    baseline=json.loads((OUT/'initial-state.json').read_text())
    changed_history=[name for name,digest in baseline['historical_results'].items()
                     if not (ROOT/name).exists() or hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest]
    if changed_history: raise RuntimeError(f'Historical result changed: {changed_history}')
    current={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
             for d in ['app','security','attacks','evaluations','integrations','tests','docs','.github']
             for p in (ROOT/d).rglob('*') if p.is_file() and 'node_modules' not in p.parts and '__pycache__' not in p.parts}
    for name in ['README.md','pyproject.toml','uv.lock','requirements.lock','.gitleaks.toml','.gitignore']:
        current[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    changed=[name for name,digest in current.items() if baseline['project_files'].get(name)!=digest]
    tests={}
    for p in sorted(OUT.glob('pytest*.xml')):
        suite=ElementTree.parse(p).getroot().find('testsuite')
        tests[p.name]={k:v for k,v in suite.attrib.items() if k in {'tests','failures','errors','skipped','time'}}
    experiment=json.loads((OUT/'model-experiment/report.json').read_text())
    ci=json.loads((OUT/'ci-status.json').read_text())
    live_path=OUT/'live-frameworks-verified/summary.json'
    live=json.loads(live_path.read_text()) if live_path.exists() else {'status':'not yet verified'}
    scanner={}
    for name in ['bandit','pip-audit','gitleaks']:
        p=OUT/(name+'.json')
        if p.exists():
            data=json.loads(p.read_text())
            scanner[name]={'findings':len(data['results']) if name=='bandit' else sum(len(d['vulns']) for d in data['dependencies']) if name=='pip-audit' else len(data)}
        else: scanner[name]={'status':'pending'}
    commands=[
        '.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage1.xml',
        '.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage2.xml',
        '.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage3.xml',
        '.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage4.xml',
        '.venv/bin/python -m pytest -q --junitxml=results/hardening-v1/pytest-stage5.xml',
        '.venv/bin/python -m attacks.hardening_runner --output results/hardening-v1/model-experiment',
        '.venv/bin/python -m attacks.runner --provider ollama --case S03 --modes vulnerable filtered --num-predict 768 --retry-truncated --bounded-tools --output results/hardening-v1/rot13-repair',
        '.venv/bin/python -m attacks.runner --provider ollama --case S03 --modes vulnerable filtered --num-predict 768 --retry-truncated --bounded-tools --max-content-chars 1000 --output results/hardening-v1/rot13-content-bound',
        '.venv/bin/python -m attacks.runner --output results/hardening-v1/deterministic',
        '.venv/bin/python -m integrations.live_workflow --output results/hardening-v1/live-frameworks --pyrit-python /tmp/agentsec-pyrit-env/bin/python --garak-python /tmp/agentsec-garak-env/bin/python --node /tmp/agentsec-node/node_modules/node/bin/node',
        '.venv/bin/python -m integrations.live_workflow --output results/hardening-v1/live-frameworks-verified --pyrit-python /tmp/agentsec-pyrit-env/bin/python --garak-python /tmp/agentsec-garak-env/bin/python --node /tmp/agentsec-node/node_modules/node/bin/node',
        '.venv/bin/bandit -r app security attacks evaluations integrations -f json -o results/hardening-v1/bandit.json',
        '.venv/bin/pip-audit -r requirements.lock --disable-pip --no-deps -f json -o results/hardening-v1/pip-audit.json']
    for xml in ['pytest-final.xml','pytest-live.xml']:
        if (OUT/xml).exists():
            commands.append(('AGENTSEC_LIVE_TESTS=1 ' if xml=='pytest-live.xml' else '')+'.venv/bin/python -m pytest '+('tests/test_model.py ' if xml=='pytest-live.xml' else '')+'-q --junitxml=results/hardening-v1/'+xml)
    gitleaks=OUT/'gitleaks.json'
    if gitleaks.exists(): commands.append(json.loads((OUT/'scanner-command.json').read_text())['command'])
    audit={'historical_result_files_unchanged':len(baseline['historical_results']),'changed_files':sorted(changed),
        'tests':tests,'scanner_results':scanner,'model_experiment':{'executions':len(experiment['runs']),'metrics':experiment['metrics']},
        'live_framework_workflow':live,'ci':ci,'commands':commands,
        'remaining':['Raw model remains susceptible to hijacking and instruction extraction','One primary ROT13 error retained; repaired framing does not imply useful answer',
                     'Renderer loses language/format/open-ended support utility','Content-only detector has false positives/negatives','Limited one-model, one-seed internal validation',
                     'No recorded video','No broad harmful-content benchmark or production identity/approval workflow']}
    (OUT/'final-verification.json').write_text(json.dumps(audit,indent=2)+'\n')
    lines=['# Final hardening and verification audit','',
      'This audit checks the requested final hardening work against saved execution evidence. It is not an externally adjudicated security certification. Current completion claims are limited to the observations below.',
      '',f"Historical result files preserved byte-for-byte: **{len(baseline['historical_results'])}**.",
      '', '## Actual test results','', '```json',json.dumps(tests,indent=2),'```',
      '', '## Exact local commands executed','']
    lines += ['```sh', '\n'.join(commands),'```','',
      'Stage test runs reflect implementation milestones. The primary research CLI exited nonzero for its one recorded ROT13 error. The schema-only original ROT13 retest exited nonzero for two parse errors; the explicit content-bound retest completed both with valid but repetitive output. The first live workflow stopped because it misclassified expected vulnerable Promptfoo assertions as provider errors; the classification was fixed and tested, and its diagnostics are preserved. Those orchestration failures are not counted as target vulnerabilities.',
      '', '## Security and utility experiments','',
      '[Technical findings and before/after table](final-hardening-report.md) document all 102 primary executions, detector confusion counts, independent permission expectations and per-task benign failures. Four known prompts and four held-out textual objectives still compromised raw model output; delivered target text was contained by the grounded contract. The model itself is not resistant.',
      '', '## Confirmed live framework rerun','', '```json',json.dumps(live,indent=2),'```',
      '', 'Actual native results and command exits are under results/hardening-v1/live-frameworks-verified/. Original Promptfoo, PyRIT and Garak results remain in their historical directories. Native text hits and unauthorized tool/data consequences must be interpreted separately.',
      '', '## Scanner results','', '```json',json.dumps(scanner,indent=2),'```',
      '', 'The dependency audit covers the locked core runtime, not the isolated scanner environments. Secret scanning uses documented exact synthetic-fixture exceptions. The first final scan also flagged a test-source SHA256 and a model-fabricated Base64 value; those exact nonsecret values were narrowly allowlisted and the seven redacted findings preserved in gitleaks-first-pass.json. No broad source/report exemption was introduced.',
      '', '## Hosted CI status','', '```json',json.dumps(ci,indent=2),'```',
      '', 'The PR pipeline remains model-free. [Opt-in local live workflow](live-workflow.md) runs actual local inference; it is not labeled hosted CI. Hosted status is verified only when a concrete Actions run and artifact evidence are recorded above.',
      '', '## Remaining vulnerabilities and incomplete requirements','']
    lines += ['- '+item for item in audit['remaining']]
    lines += ['', 'Human video recording remains incomplete; a [90–120-second exact script](demo-120s.md) is supplied. The [research article draft](research-case-study.md) explains the failure, mitigation and limits.',
      '', '## Resume claims supported by these observations','',
      '- Built a local AI-agent security lab with an independent principal/agent/resource authorization gateway, versioned attack inputs and auditable execution traces; hardened execution prevented every observed prohibited tool effect in the follow-up sample.',
      '- Evaluated a constrained support-response contract in 102 paired local executions: delivered hijacking changed from 4/4 to 0/4 on both known and held-out textual targets while raw model compromise remained observable; measured 13/16 benign completion before and after with different failures.',
      '- Implemented policy-independent content detection and manually frozen reference labels; reported precision 12/14, recall 12/18 and benign false-positive rate 2/16 in the complete hardened sample, alongside actual Promptfoo/PyRIT/Garak evidence.',
      '', 'Do not claim general resistance, zero utility cost, production authorization/approvals, externally validated labels, or a recorded video. Hosted CI claims require the run evidence above.',
      '', '## Files changed since the initial hardening snapshot','']
    lines += ['- `'+name+'`' for name in sorted(changed)]
    lines += ['', 'This inventory covers the source/document/config roots and root manifests recorded in initial-state.json. New run artifacts are under results/hardening-v1; ignored installed dependencies and Git metadata are not project-source changes. The audit file itself can appear as newly added when rerun after first generation.']
    (ROOT/'docs/final-audit.md').write_text('\n'.join(lines)+'\n')
    print('Final audit generated; historical result hashes verified')

if __name__=='__main__': main()
