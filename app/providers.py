"""Ollama and explicitly labeled scripted test providers."""
import json
import httpx
from app.models import ModelReply
from app.tools import SCHEMAS

TOOL_SCHEMAS = [{"type": "function", "function": {"name": name,
                 "description": name.replace("_", " "), "parameters": schema.model_json_schema()}}
                for name, schema in SCHEMAS.items()]

class ScriptedProvider:
    name = "scripted-fixture-not-an-llm"
    metadata = {"provider": "scripted", "model": "fixture", "seed": None, "real_model": False}
    def __init__(self, turns):
        self.turns = iter(turns)
    def reply(self, messages):
        return ModelReply.model_validate(next(self.turns, {"content": "Support request complete."}))

class OllamaProvider:
    def __init__(self, model="qwen2.5-coder:3b", base_url="http://127.0.0.1:11434", seed=42, num_predict=384, retry_truncated=False, bounded_tools=False, max_content_chars=None):
        if not 128 <= num_predict <= 1536:
            raise ValueError("Generation budget must be between 128 and 1536")
        self.name, self.base_url, self.seed = model, base_url.rstrip("/"), seed
        self.retry_truncated = retry_truncated
        self.bounded_tools = bounded_tools
        if max_content_chars is not None and not 100 <= max_content_chars <= 12000:
            raise ValueError("Content limit must be between 100 and 12000 characters")
        self.max_content_chars = max_content_chars
        self.last_attempts = []
        self.metadata = {"provider": "ollama", "model": model, "seed": seed, "temperature": 0,
                         "num_ctx": 4096, "num_predict": num_predict, "retry_truncated": retry_truncated, "bounded_tools": bounded_tools, "max_content_chars": max_content_chars, "real_model": True}
    def describe(self):
        with httpx.Client(timeout=15, trust_env=False) as client:
            response = client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            self.metadata["installed_models"] = response.json()["models"]
            version = client.get(f"{self.base_url}/api/version")
            version.raise_for_status()
            self.metadata["server_version"] = version.json()
        return self.metadata
    def reply(self, messages):
        # JSON schema works even for small models lacking native tool-call support.
        payload = {"model": self.name, "messages": messages, "stream": False,
                   "format": ModelReply.model_json_schema(), "keep_alive": "5m",
                   "options": {k: self.metadata[k] for k in ["seed", "temperature", "num_ctx", "num_predict"]}}
        if self.max_content_chars is not None:
            payload["format"]["properties"]["content"]["maxLength"] = self.max_content_chars
        if self.bounded_tools:
            payload["format"]["$defs"]["ToolCall"] = {"oneOf": [
                {"type": "object", "additionalProperties": False, "required": ["name", "arguments"],
                 "properties": {"name": {"const": name}, "arguments": args.model_json_schema()}}
                for name, args in SCHEMAS.items()]}
        self.last_attempts = []
        for attempt in range(2 if self.retry_truncated else 1):
            with httpx.Client(timeout=180, trust_env=False) as client:
                response = client.post(f"{self.base_url}/api/chat", json=payload)
                response.raise_for_status()
            raw = response.json()
            self.metadata["last_runtime_model"] = raw.get("model")
            content = raw["message"]["content"]
            self.last_raw_response = content
            self.last_attempts.append({"attempt": attempt + 1, "num_predict": payload["options"]["num_predict"],
                "done_reason": raw.get("done_reason"), "eval_count": raw.get("eval_count"), "raw_response": content})
            try:
                return ModelReply.model_validate(json.loads(content))
            except (ValueError, TypeError):
                if attempt == 0 and self.retry_truncated and raw.get("done_reason") == "length" and payload["options"]["num_predict"] < 1536:
                    payload["options"]["num_predict"] = min(1536, payload["options"]["num_predict"] * 2)
                    continue
                raise
