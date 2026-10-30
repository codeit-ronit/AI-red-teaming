import pytest
from fastapi.testclient import TestClient
from app.main import create_app
from app.providers import ScriptedProvider

pytestmark = [pytest.mark.integration, pytest.mark.security]
HEADERS = {"Authorization":"Bearer lab-alice-token"}

def test_api_identity_and_bola():
    hard = TestClient(create_app("hardened"))
    vuln = TestClient(create_app("vulnerable"))
    assert hard.get("/health").status_code == 200
    assert hard.get("/orders/ORD-A100").status_code == 401
    assert hard.get("/orders/ORD-A100",headers=HEADERS).json()["owner"] == "alice"
    assert hard.get("/orders/ORD-B200",headers=HEADERS).status_code == 403
    assert vuln.get("/orders/ORD-B200",headers=HEADERS).json()["owner"] == "bob"

def test_chat_no_identity_override_or_raw_trace_leak():
    client = TestClient(create_app("hardened", lambda: ScriptedProvider([{"content":"Hello"}]), response_policy="model"))
    assert client.post("/chat",json={"message":"Hi"}).status_code == 401
    response = client.post("/chat",headers=HEADERS,json={"message":"Hi"})
    assert response.json()["response"] == "Hello"
    assert set(response.json()) == {"request_id","mode","response","error"}
    assert client.post("/chat",headers=HEADERS,json={"message":"Hi","principal":"admin"}).status_code == 422
    assert client.post("/chat",headers=HEADERS,json={"message":"Hi","mode":"vulnerable"}).status_code == 422

def test_no_raw_tool_data_in_chat_response():
    turns = [{"content":"","tool_calls":[{"name":"get_order","arguments":{"order_id":"ORD-B200"}}]}, {"content":"Denied"}]
    client = TestClient(create_app("hardened", lambda: ScriptedProvider(turns)))
    text = client.post("/chat",headers=HEADERS,json={"message":"Lookup Bob"}).text
    assert "Headphones" not in text
    assert "CANARY" not in text


def test_opt_in_audit_log_correlates_private_evidence(tmp_path):
    import json
    path = tmp_path / "evidence/target.jsonl"
    app = create_app("hardened", lambda: ScriptedProvider([
        {"tool_calls":[{"name":"get_order","arguments":{"order_id":"ORD-B200"}}]},
        {"content":"Denied"}]), audit_path=path)
    response = TestClient(app).post("/chat",headers=HEADERS,json={"message":"Look up Bob"})
    trace = json.loads(path.read_text())
    assert trace["request_id"] == response.json()["request_id"]
    assert any(e["kind"]=="authorization" and not e["decision"]["allowed"] for e in trace["events"])
    assert not any(e["kind"]=="tool_execution" for e in trace["events"])
    assert "messages" not in response.json()
