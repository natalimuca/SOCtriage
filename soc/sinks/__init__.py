from .base import Sink
from .indexer import IndexerSink
from .webhook import WebhookSink

__all__ = ["Sink", "IndexerSink", "WebhookSink", "build"]


def build(kind: str, **kwargs) -> Sink:
    if kind == "indexer":
        return IndexerSink(**kwargs)
    if kind == "webhook":
        return WebhookSink(**kwargs)
    raise ValueError(f"unknown sink: {kind}")
