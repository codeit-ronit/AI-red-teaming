import pytest
from app.tools import Gateway, load_data
from security.audit import Audit
from security.authorization import Authorizer
from security.approvals import Approval

pytestmark = [pytest.mark.unit, pytest.mark.security]

def gateway(mode="hardened", principal="alice", agent="support-agent", approval=None):
    return Gateway(mode, Audit(), principal, agent, approval)

def execute(gw, name="get_order", **arguments):
    return gw.execute({"name": name, "arguments": arguments})

def test_own_order():
    assert execute(gateway(), order_id="ORD-A100")["result"]["owner"] == "alice"

def test_cross_user_denial_and_actual_vulnerable_reproduction():
    hardened = gateway()
    assert not execute(hardened, order_id="ORD-B200")["executed"]
    assert not any(e["kind"] == "tool_execution" for e in hardened.audit.events)
    vulnerable = gateway("vulnerable")
    assert execute(vulnerable, order_id="ORD-B200")["result"]["owner"] == "bob"
    assert vulnerable.audit.events[-1]["unauthorized"]

@pytest.mark.parametrize("principal,agent", [(None,"support-agent"),("mallory","support-agent"),("alice","unknown-agent")])
def test_missing_unknown_identity_denied(principal, agent):
    assert not execute(gateway(principal=principal,agent=agent), order_id="ORD-A100")["executed"]

def test_admin_tool_scoped_and_approved():
    no_approval = gateway(principal="admin",agent="refund-agent")
    assert not execute(no_approval,"admin_refund_order",order_id="ORD-B200")["executed"]
    assert no_approval.audit.events[-1]["decision"]["policy_id"] == "approval"
    approval = Approval("admin","admin_refund_order","ORD-B200","lab-reviewer")
    approved = gateway(principal="admin", agent="refund-agent", approval=approval)
    assert execute(approved,"admin_refund_order",order_id="ORD-B200")["executed"]
    assert approved.refunds == ["ORD-B200"]
    assert not execute(gateway(principal="admin",agent="refund-agent",approval=approval),"admin_refund_order",order_id="ORD-A100")["executed"]
    assert not execute(gateway(principal="admin",approval=approval),"admin_refund_order",order_id="ORD-B200")["executed"]

def test_customer_cannot_become_admin_with_fixture_approval():
    approval = Approval("alice","admin_refund_order","ORD-A100","lab-reviewer")
    assert not execute(gateway(principal="alice",agent="refund-agent",approval=approval),"admin_refund_order",order_id="ORD-A100")["executed"]

@pytest.mark.parametrize("raw", [None, {}, {"name":"shell","arguments":{}},
 {"name":"get_order","arguments":{}}, {"name":"get_order","arguments":{"order_id":42}},
 {"name":"get_order","arguments":{"order_id":"ORD-A100","principal":"admin"}},
 {"name":"get_order","arguments":{"order_id":"ORD-A100"},"approval":True}])
def test_malformed_unknown_fail_closed(raw):
    gw = gateway()
    assert not gw.execute(raw)["executed"]
    assert gw.audit.events[-1]["kind"] == "invalid_tool"
    assert not any(e["kind"] == "tool_execution" for e in gw.audit.events)

def test_action_cannot_be_spoofed():
    decision = Authorizer(load_data()).authorize("alice","support-agent","get_order","ORD-A100","refund")
    assert not decision.allowed

def test_inventory_and_ticket():
    gw = gateway()
    assert not execute(gw,"get_asset_inventory",asset_id="INTERNAL-1")["executed"]
    assert execute(gw,"get_asset_inventory",asset_id="PUBLIC-1")["executed"]
    assert execute(gw,"create_support_ticket",description="Help")["result"]["owner"] == "alice"


def test_unknown_mode_cannot_silently_bypass_policy():
    with pytest.raises(ValueError):
        gateway("typo")
