from dataclasses import asdict, dataclass
from security.approvals import Approval
from security.policies import AGENTS, PRINCIPALS, TOOL_POLICY

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    policy_id: str
    principal: str | None
    agent: str
    tool: str
    resource: str
    action: str

    def to_dict(self):
        return asdict(self)

class Authorizer:
    def __init__(self, data):
        self.data = data

    def authorize(self, principal, agent_identity, tool_name, resource_id, action, approval_context=None):
        def decision(allow, reason, policy):
            return Decision(allow, reason, policy, principal, agent_identity, tool_name, resource_id, action)
        if principal not in PRINCIPALS:
            return decision(False, "Missing or unknown principal", "identity")
        if tool_name not in TOOL_POLICY or agent_identity not in AGENTS:
            return decision(False, "Unknown tool or agent", "deny-default")
        if tool_name not in AGENTS[agent_identity] or action != TOOL_POLICY[tool_name][0]:
            return decision(False, "Tool/action outside agent scope", "least-privilege")
        role = PRINCIPALS[principal]
        if tool_name in {"get_order", "admin_refund_order"}:
            obj = self.data["orders"].get(resource_id)
            if not obj:
                return decision(False, "Resource unavailable", "resource-exists")
            if obj["owner"] != principal and role != "admin":
                return decision(False, "Cross-user resource access", "object-owner")
        if tool_name == "get_asset_inventory":
            obj = self.data["assets"].get(resource_id)
            if not obj or (obj["restricted"] and role != "admin"):
                return decision(False, "Restricted inventory", "asset-scope")
        if tool_name == "read_support_document" and resource_id not in self.data["documents"]:
            return decision(False, "Resource unavailable", "resource-exists")
        if tool_name == "admin_refund_order":
            if role != "admin":
                return decision(False, "Administrative role required", "admin-role")
            if not isinstance(approval_context, Approval) or not approval_context.matches(principal, tool_name, resource_id):
                return decision(False, "Human approval required", "approval")
        return decision(True, "Authorized", "allow-scoped")
