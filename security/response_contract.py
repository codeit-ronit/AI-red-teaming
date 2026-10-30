"""A narrow support-output contract, independent of attacker-selected output strings.

Model text remains available in private traces; delivered text is rendered from allowlisted
support facts and authorized execution events. This limits product scope and can reduce
utility (e.g. translations/free-form answers). It does not undo tool effects or prove that
model reasoning resisted injection.
"""
import re
from dataclasses import dataclass

RETURNS_POLICY = "Northwind accepts returns within 30 days. Contact support for assistance."
SCOPE_REPLY = "Hello. I can help with order status, returns, support tickets and public support inventory. Please provide an order ID or describe your support issue."

@dataclass(frozen=True)
class ContractResult:
    text: str
    task: str
    evidence_sequences: tuple[int, ...]
    reason: str


def render_support_response(message, events):
    lower = message.casefold()
    order_ids = set(re.findall(r"\bORD-[A-Z0-9]+\b", message.upper()))
    assets = set(re.findall(r"\b(?:PUBLIC|INTERNAL)-[A-Z0-9]+\b", message.upper()))
    valid = [e for e in events if e["kind"] == "tool_execution" and not e.get("unauthorized", True)
             and isinstance(e.get("result"), dict) and not e["result"].get("error")]
    # Ticket descriptions, retrieved text and model-supplied claims are never rendered.
    if "ticket" in lower and any(x in lower for x in ["create", "open", "raise", "log"]):
        ticket = next((e for e in valid if e["tool"] == "create_support_ticket"), None)
        if ticket and re.fullmatch(r"T-\d+", str(ticket["result"].get("ticket_id", ""))):
            return ContractResult(f"Support ticket {ticket['result']['ticket_id']} was created.", "ticket", (ticket["sequence"],), "Authorized ticket receipt; untrusted description omitted")
        return ContractResult("A support ticket was not created. Please describe the issue and try again.", "ticket", (), "No authorized ticket receipt")
    if order_ids:
        order = next((e for e in valid if e["tool"] == "get_order" and e["resource"] in order_ids), None)
        if order and order["result"].get("status") in {"shipped", "processing", "delivered", "cancelled"}:
            return ContractResult(f"Order {order['resource']}: {order['result']['status']}.", "order", (order["sequence"],), "Authorized order status; requested object only")
        return ContractResult("I could not provide an authorized order status for that request.", "order", (), "No authorized requested-order result")
    if assets:
        asset = next((e for e in valid if e["tool"] == "get_asset_inventory" and e["resource"] in assets), None)
        if asset and asset["resource"].startswith("PUBLIC-") and not asset["result"].get("restricted", True):
            return ContractResult(f"Public support asset {asset['resource']} is available.", "inventory", (asset["sequence"],), "Authorized public-inventory receipt; free-form name omitted")
        return ContractResult("That inventory record is unavailable for this support request.", "inventory", (), "No authorized public inventory result")
    if any(x in lower for x in ["return", "refund"]):
        # Server-maintained policy, not text copied from an attacker-controlled retrieved document.
        return ContractResult(RETURNS_POLICY, "policy", (), "Approved server policy; retrieved instructions are not authoritative")
    return ContractResult(SCOPE_REPLY, "scope", (), "Free-form output is outside the supported response contract")
