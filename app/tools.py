import json
from dataclasses import replace
from importlib.resources import files
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from app.models import ToolCall
from security.authorization import Authorizer
from security.policies import TOOL_POLICY
from security.execution_scope import ExecutionScope

class OrderArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    order_id: str = Field(min_length=1, max_length=80)
class DocumentArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    document_id: str = Field(min_length=1, max_length=80)
class AssetArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    asset_id: str = Field(min_length=1, max_length=80)
class TicketArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    description: str = Field(min_length=1, max_length=1000)

SCHEMAS = {"get_order": OrderArgs, "admin_refund_order": OrderArgs,
           "read_support_document": DocumentArgs, "get_asset_inventory": AssetArgs,
           "create_support_ticket": TicketArgs}

def load_data():
    return json.loads(files("app").joinpath("fixtures/data.json").read_text())

class Gateway:
    def __init__(self, mode, audit, principal="alice", agent="support-agent", approval=None, data=None, execution_scope=ExecutionScope()):
        if mode not in {"vulnerable", "filtered", "hardened"}:
            raise ValueError("Unknown mode; refusing to disable authorization implicitly")
        self.mode, self.audit, self.principal, self.agent, self.approval = mode, audit, principal, agent, approval
        self.data = data if data is not None else load_data()
        self.authorizer = Authorizer(self.data)
        self.tickets = []
        self.refunds = []
        self.execution_scope = execution_scope
        self.tool_attempts = 0

    def execute(self, raw):
        self.tool_attempts += 1
        if self.mode == "hardened" and self.execution_scope and self.tool_attempts > self.execution_scope.max_tool_calls:
            self.audit.emit("execution_denied", policy="tool-budget", reason="Request tool budget exhausted")
            return {"error": "Request tool budget exhausted", "executed": False}
        try:
            call = ToolCall.model_validate(raw)
            if call.name not in SCHEMAS:
                raise ValueError("Unknown tool")
            args = SCHEMAS[call.name].model_validate(call.arguments).model_dump()
        except (ValidationError, ValueError, TypeError):
            self.audit.emit("invalid_tool", proposed=raw, reason="Unknown tool or malformed arguments")
            return {"error": "Invalid tool call", "executed": False}
        action, key = TOOL_POLICY[call.name]
        resource = args[key]
        decision = self.authorizer.authorize(self.principal, self.agent, call.name, resource, action, self.approval)
        # Vulnerable/filtered modes deliberately bypass semantic authorization only.
        # Schema validation is still enforced. Shadow policy supplies independent labels.
        enforced = self.mode == "hardened"
        if enforced and decision.allowed and self.execution_scope:
            reason = self.execution_scope.denial(call.name, len(self.tickets))
            if reason:
                decision = replace(decision, allowed=False, reason=reason, policy_id="request-capability")
        if enforced and decision.allowed and call.name == "admin_refund_order":
            if not self.approval.consume(self.principal, call.name, resource):
                decision = replace(decision, allowed=False, reason="Approval expired or already consumed", policy_id="approval-freshness")
        self.audit.emit("authorization", decision=decision.to_dict(), enforced=enforced)
        if enforced and not decision.allowed:
            return {"error": "Denied", "reason": decision.reason, "executed": False}
        if call.name == "get_order":
            result = self.data["orders"].get(resource, {"error": "Not found"})
        elif call.name == "get_asset_inventory":
            result = self.data["assets"].get(resource, {"error": "Not found"})
        elif call.name == "read_support_document":
            result = {"content": self.data["documents"].get(resource, "Not found")}
            self.audit.emit("retrieval", document_id=resource, content=result["content"], source="tool")
        elif call.name == "create_support_ticket":
            result = {"ticket_id": f"T-{len(self.tickets)+1}", "owner": self.principal, **args}
            self.tickets.append(result)
        else:
            result = {"order_id": resource, "refunded": resource in self.data["orders"]}
            if result["refunded"]:
                self.refunds.append(resource)
        self.audit.emit("tool_execution", tool=call.name, resource=resource, result=result,
                        unauthorized=not decision.allowed)
        return {"executed": True, "result": result}
