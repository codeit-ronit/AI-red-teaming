import json
import pytest
from integrations.garak.run import correlate
from integrations.common import write_report

pytestmark = [pytest.mark.unit, pytest.mark.security]


def test_native_attempt_correlation_requires_prompt_and_output():
    rows = [{"trace":{"input":"x", "response":"actual"}}, {"trace":{"input":"x", "response":"different"}}]
    native = [{"entry_type":"attempt", "status":2, "uuid":"native-1", "probe_classname":"encoding.InjectBase64",
               "prompt":{"turns":[{"content":{"text":"x"}}]}, "outputs":[{"text":"actual"}],
               "detector_results":{"encoding.DecodeMatch":[1.0]}}]
    result = correlate(rows,native)
    assert rows[0]["garak_attempt_id"] == "native-1"
    assert "garak_correlation_error" in rows[1]
    assert result["target_traces_without_native_attempt"] == 1


def test_unlabeled_native_probes_do_not_invent_detection_accuracy(tmp_path):
    row = {"case":{"id":"native", "malicious":None},
           "trace":{"mode":"hardened", "error":None},
           "outcome":{"attack_success":False,"unauthorized_attempts":0,"unauthorized_executions":0,
                      "secret_disclosed":False,"canary_disclosed":False}}
    report = write_report([row],tmp_path,{"framework":"test", "framework_version":"1", "ground_truth_available":False})
    assert "precision" not in report["metrics"]["hardened"]
    assert "attack_success_rate" not in report["metrics"]["hardened"]
    assert report["metrics"]["hardened"]["target_requests"] == 1
    assert json.loads((tmp_path/"report.json").read_text())["runs"][0]["case"]["malicious"] is None


def test_live_workflow_distinguishes_assertion_failures_from_provider_errors():
    from integrations.live_workflow import validate_promptfoo_results
    expected={'success':False,'error':'Custom function returned false','response':{'output':json.dumps({'outcome':{'attack_success':True}})},
              'gradingResult':{'componentResults':[{'reason':'Custom function returned false'}]}}
    validate_promptfoo_results([expected])
    with pytest.raises(RuntimeError):
        validate_promptfoo_results([{'response':{'error':'Local model unavailable'}}])
    with pytest.raises(RuntimeError):
        validate_promptfoo_results([{**expected,'gradingResult':{'componentResults':[{'reason':'Custom function threw error: SyntaxError'}]}}])
