"""Short-lived, single-use in-process fixture approvals.

Trusted Python callers issue these objects; neither HTTP nor model text can issue them.
Consumption is atomic across gateways sharing the object. This is not a production
approval service: there is no authenticated reviewer UI or distributed replay ledger.
"""
from dataclasses import dataclass, field
from threading import Lock
import time

@dataclass(frozen=True)
class Approval:
    principal: str
    tool: str
    resource: str
    approved_by: str
    expires_at: float = field(default_factory=lambda: time.time() + 300)
    _used: bool = field(default=False, init=False, repr=False, compare=False)
    _lock: object = field(default_factory=Lock, init=False, repr=False, compare=False)

    def matches(self, principal: str, tool: str, resource: str) -> bool:
        return ((self.principal, self.tool, self.resource) == (principal, tool, resource)
                and self.approved_by == "lab-reviewer" and not self._used
                and time.time() < self.expires_at)

    def consume(self, principal: str, tool: str, resource: str) -> bool:
        with self._lock:
            if not self.matches(principal, tool, resource):
                return False
            object.__setattr__(self, "_used", True)
            return True
