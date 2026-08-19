from .base import Source
from .jsonl import JsonlSource
from .wazuh import WazuhSource

__all__ = ["Source", "JsonlSource", "WazuhSource", "build"]


def build(kind: str, **kwargs) -> Source:
    if kind == "jsonl":
        return JsonlSource(**kwargs)
    if kind == "wazuh":
        return WazuhSource(**kwargs)
    raise ValueError(f"unknown source: {kind}")
