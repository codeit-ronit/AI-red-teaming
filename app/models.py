"""Strict model-facing schemas. No principal, approval, or policy fields are model controlled."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

Mode = Literal["vulnerable", "filtered", "hardened"]

class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any]

class ModelReply(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    content: str = Field(default="", max_length=12000)
    tool_calls: list[ToolCall] = Field(default_factory=list, max_length=4)

class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=6000)
    document_id: str | None = Field(default=None, max_length=80)
