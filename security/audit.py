"""Structured request-local audit trail. Returned traces are for this synthetic lab only."""
from datetime import datetime, timezone
from uuid import uuid4

class Audit:
    def __init__(self):
        self.request_id = str(uuid4())
        self.events = []

    def emit(self, kind, **fields):
        event = {"request_id": self.request_id, "sequence": len(self.events),
                 "time": datetime.now(timezone.utc).isoformat(), "kind": kind, **fields}
        self.events.append(event)
        return event
