"""Server-side test fixture approvals, bound to principal, action, and object.
This immutable context is injected by trusted Python callers only, never by the LLM/HTTP body.
No production human approval UI, token issuance, expiry, or replay prevention is claimed.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class Approval:
    principal: str
    tool: str
    resource: str
    approved_by: str

    def matches(self, principal: str, tool: str, resource: str) -> bool:
        return (self.principal, self.tool, self.resource) == (principal, tool, resource) and self.approved_by == "lab-reviewer"
