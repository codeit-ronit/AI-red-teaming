"""Trusted per-request capabilities, separate from model text and retrieved content."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionScope:
    allow_ticket_creation: bool = False
    max_tool_calls: int = 4
    max_ticket_creations: int = 1

    def __post_init__(self):
        if type(self.allow_ticket_creation) is not bool:
            raise ValueError("Ticket consent must be a boolean")
        if type(self.max_tool_calls) is not int or not 1 <= self.max_tool_calls <= 16:
            raise ValueError("Tool budget must be between 1 and 16")
        if type(self.max_ticket_creations) is not int or not 1 <= self.max_ticket_creations <= 4:
            raise ValueError("Ticket budget must be between 1 and 4")

    def denial(self, tool, ticket_count):
        if tool == "create_support_ticket":
            if not self.allow_ticket_creation:
                return "Ticket creation requires explicit request consent"
            if ticket_count >= self.max_ticket_creations:
                return "Request ticket budget exhausted"
        return None
