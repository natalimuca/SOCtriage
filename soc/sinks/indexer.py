import httpx

from ..config import settings
from ..schema import Result
from .base import Sink
from .payload import document

MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "incident": {
                "properties": {
                    "id": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "alert_count": {"type": "integer"},
                    "max_rule_level": {"type": "integer"},
                    "rule_ids": {"type": "keyword"},
                }
            },
            "triage": {
                "properties": {
                    "verdict": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "escalate": {"type": "boolean"},
                    "summary": {"type": "text"},
                    "narrative": {"type": "text"},
                    "techniques": {"type": "keyword"},
                    "tactics": {"type": "keyword"},
                }
            },
            "asset": {"properties": {"criticality": {"type": "keyword"}, "exposure": {"type": "keyword"}}},
            "analyst": {"type": "keyword"},
            "cost_usd": {"type": "float"},
        }
    }
}


class IndexerSink(Sink):
    """Writes each triage verdict back to the Wazuh indexer as a queryable document,
    so verdicts sit alongside the alerts they summarise and show up in the dashboard."""

    name = "indexer"

    def __init__(self, index: str = "soc-triage", url: str | None = None):
        self.index = index
        self.url = (url or settings.indexer_url).rstrip("/")
        self.client = httpx.Client(
            auth=(settings.indexer_user, settings.indexer_password),
            verify=settings.indexer_verify,
            timeout=15.0,
        )
        self._ensured = False

    def _ensure_index(self) -> None:
        if self._ensured:
            return
        resp = self.client.head(f"{self.url}/{self.index}")
        if resp.status_code == 404:
            self.client.put(f"{self.url}/{self.index}", json=MAPPING)
        self._ensured = True

    def emit(self, result: Result) -> bool:
        self._ensure_index()
        doc = document(result)
        resp = self.client.post(
            f"{self.url}/{self.index}/_doc/{result.incident.id}",
            json=doc,
        )
        resp.raise_for_status()
        return True

    def close(self) -> None:
        self.client.close()
