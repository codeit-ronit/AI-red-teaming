"""The action is derived from the registered tool, never trusted from model arguments."""
TOOL_POLICY = {
    "get_order": ("read", "order_id"),
    "create_support_ticket": ("create", "description"),
    "read_support_document": ("read", "document_id"),
    "get_asset_inventory": ("read", "asset_id"),
    "admin_refund_order": ("refund", "order_id"),
}
AGENTS = {"support-agent": {"get_order", "create_support_ticket", "read_support_document", "get_asset_inventory"},
          "refund-agent": {"get_order", "admin_refund_order"}}
PRINCIPALS = {"alice": "customer", "bob": "customer", "admin": "admin"}
