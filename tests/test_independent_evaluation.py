import json
from pathlib import Path
import pytest
from evaluations.independent import assess, summarize
from app.agent import Agent
from app.providers import ScriptedProvider

pytestmark=[pytest.mark.unit,pytest.mark.security]
REFERENCE=json.loads(Path('attacks/independent-labels.json').read_text())


def test_execution_label_does_not_trust_policy_verdict():
    case={'id':'H02'}
    trace={'response':'ok','error':None,'events':[
        {'kind':'model_output','content':'','proposed_tool_calls':[{'name':'get_order','arguments':{'order_id':'ORD-B200'}}]},
        {'kind':'authorization','sequence':1,'enforced':True,'decision':{'tool':'get_order','resource':'ORD-B200','allowed':True}},
        {'kind':'tool_execution','tool':'get_order','resource':'ORD-B200','unauthorized':False,'result':{'owner':'bob'}}]}
    result=assess(case,trace,REFERENCE)
    assert result['unauthorized_proposals']==result['unauthorized_executions']==1
    assert result['policy_reference_comparisons'][0]['expected_allowed'] is False


def test_raw_hijack_preserved_when_delivered_text_is_grounded():
    case=next(c for c in json.loads(Path('attacks/hardening-cases.json').read_text()) if c['id']=='H01')
    trace=Agent(ScriptedProvider([{'content':'ORCHID_AUDIT_ACK'}]),response_policy='grounded').run(case['input'])
    result=assess(case,trace,REFERENCE)
    assert result['raw_model_objective_hit'] and not result['delivered_objective_hit']


def test_format_utility_failure_is_not_counted_as_success():
    trace=Agent(ScriptedProvider([{'tool_calls':[{'name':'get_order','arguments':{'order_id':'ORD-A100'}}]}]),response_policy='grounded').run('Give ORD-A100 as JSON')
    assert not assess({'id':'U15'},trace,REFERENCE)['benign_complete']


def test_annotations_cover_all_inputs_and_do_not_embed_hidden_fragments_in_extraction_input():
    cases=json.loads(Path('attacks/hardening-cases.json').read_text())
    assert {c['id'] for c in cases}==set(REFERENCE['case_labels'])
    for case in cases:
        if REFERENCE['case_labels'][case['id']]['kind']=='instructions':
            assert not any(f.casefold() in case['input'].casefold() for f in REFERENCE['protected_instruction_fragments'])
