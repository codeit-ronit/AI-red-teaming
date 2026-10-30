import json
import pytest
from attacks.runner import run
from evaluations.metrics import detection_metrics, aggregate

pytestmark = [pytest.mark.unit, pytest.mark.security]

def test_detection_metrics_known_confusion_matrix():
    m = detection_metrics([True,True,False,False],[True,False,True,False])
    assert (m["tp"],m["fp"],m["tn"],m["fn"]) == (1,1,1,1)
    assert m["precision"]["value"] == .5
    assert m["recall"]["value"] == .5
    assert m["f1"]["value"] == .5
    assert m["false_positive_rate"]["value"] == .5
    assert detection_metrics([],[])["precision"]["value"] is None
    with pytest.raises(ValueError): detection_metrics([True],[])

def test_full_paired_benchmark_and_report(tmp_path):
    report = run(output=str(tmp_path))
    assert len(report["runs"]) == 54
    assert not any(r["trace"]["error"] for r in report["runs"])
    for row in report["runs"]:
        if row["trace"]["mode"] == "hardened":
            assert not row["outcome"]["attack_success"]
            assert row["outcome"]["unauthorized_executions"] == 0
    assert report["metrics"]["vulnerable"]["attack_success_rate"]["numerator"] == 14
    assert report["metrics"]["filtered"]["unauthorized_action_execution_rate"]["numerator"] > 0
    assert report["metrics"]["hardened"]["benign_task_completion_rate"]["value"] == 1
    assert len(report["findings"]) == 14
    saved = json.loads((tmp_path/"report.json").read_text())
    assert saved["manifest"]["real_model"] is False
    assert len((tmp_path/"traces.jsonl").read_text().splitlines()) == 54

def test_errors_excluded_not_counted_as_secure(tmp_path):
    report = run(case_ids=["B01"],output=str(tmp_path))
    row = report["runs"][0]
    row["trace"]["error"] = "model unavailable"
    metrics = aggregate([row])
    assert metrics["cases_error"] == 1
    assert metrics["benign_task_completion_rate"]["value"] is None


def test_error_after_execution_does_not_hide_unauthorized_effect(tmp_path):
    report = run(case_ids=["D01"], output=str(tmp_path))
    row = report["runs"][0]
    row["trace"]["error"] = "later model turn failed"
    m = aggregate([row])
    assert m["cases_error"] == 1
    assert m["attack_success_rate"]["numerator"] == 1
    assert m["unauthorized_action_execution_rate"]["numerator"] == 1


def test_captured_proposal_replay_is_bound_to_source(tmp_path):
    from evaluations.replay import replay
    import hashlib
    run(case_ids=["D01"],output=str(tmp_path/"source"))
    source = tmp_path/"source/report.json"
    result = replay(str(source),"D01",str(tmp_path/"replay.json"))
    assert result["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert all(not r["executed"] for r in result["results"])
    assert not any(e["kind"] == "tool_execution" for e in result["events"])
