import os

import httpx

from ..schema import Result
from .base import Sink
from .payload import document

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}


class WebhookSink(Sink):
    """Posts escalations to a webhook (Slack-compatible JSON). Only escalated incidents
    are sent, so the channel stays a queue of things a human should look at, not a firehose."""

    name = "webhook"

    def __init__(self, url: str | None = None, min_severity: str = "medium", escalated_only: bool = True):
        self.url = url or os.getenv("SOC_WEBHOOK_URL", "")
        self.min_severity = min_severity
        self.escalated_only = escalated_only
        self.order = ["informational", "low", "medium", "high", "critical"]
        self.client = httpx.Client(timeout=10.0)
        if not self.url:
            raise ValueError("webhook sink needs a URL (SOC_WEBHOOK_URL or url=)")

    def _wanted(self, result: Result) -> bool:
        t = result.triage
        if self.escalated_only and not t.escalate:
            return False
        return self.order.index(t.severity) >= self.order.index(self.min_severity)

    def emit(self, result: Result) -> bool:
        if not self._wanted(result):
            return False
        t = result.triage
        i = result.incident
        emoji = SEVERITY_EMOJI.get(t.severity, "⚪")
        techniques = ", ".join(x.id for x in t.techniques) or "none mapped"
        text = (
            f"{emoji} *{t.severity.upper()}* on `{i.host}` — {t.verdict} "
            f"({t.confidence:.0%} conf)\n"
            f"{t.summary}\n"
            f"*{len(i.alerts)} alerts*, {i.enrichment.distinct_rules} rules, "
            f"max level {i.max_level} · ATT&CK: {techniques}\n"
            f"Incident `{i.id}` · {result.analyst}"
        )
        payload = {"text": text, "soc_triage": document(result)}
        resp = self.client.post(self.url, json=payload)
        resp.raise_for_status()
        return True

    def close(self) -> None:
        self.client.close()
