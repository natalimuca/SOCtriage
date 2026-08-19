from datetime import datetime, timezone
from typing import Iterator

import httpx

from ..config import settings
from ..schema import Alert
from .base import Source


def parse(doc: dict) -> Alert:
    src = doc["_source"]
    rule = src.get("rule", {})
    data = src.get("data", {})
    agent = src.get("agent", {})
    mitre = rule.get("mitre", {})
    predecoder = src.get("predecoder", {})
    return Alert(
        id=doc["_id"],
        timestamp=datetime.fromisoformat(src["timestamp"].replace("Z", "+00:00")),
        rule_id=str(rule.get("id", "0")),
        rule_level=int(rule.get("level", 0)),
        rule_description=rule.get("description", ""),
        rule_groups=rule.get("groups", []),
        technique_ids=mitre.get("id", []) if isinstance(mitre.get("id"), list) else [],
        host=predecoder.get("hostname") or agent.get("name") or src.get("manager", {}).get("name", "unknown"),
        src_ip=data.get("srcip") or data.get("src_ip"),
        src_user=data.get("srcuser") or data.get("dstuser"),
        process=data.get("process") or (src.get("syscheck") or {}).get("path"),
        full_log=src.get("full_log", ""),
        raw=src,
    )


class WazuhSource(Source):
    DEFAULT_EXCLUDED = ("sca", "rootcheck", "vulnerability-detector", "syscollector")

    def __init__(
        self,
        url: str | None = None,
        index: str = "wazuh-alerts-*",
        min_level: int = 3,
        exclude_groups: tuple[str, ...] | None = None,
    ):
        self.url = (url or settings.indexer_url).rstrip("/")
        self.index = index
        self.min_level = min_level
        self.exclude_groups = self.DEFAULT_EXCLUDED if exclude_groups is None else exclude_groups
        self.client = httpx.Client(
            auth=(settings.indexer_user, settings.indexer_password),
            verify=settings.indexer_verify,
            timeout=30.0,
        )

    def fetch(self, since: datetime | None = None, limit: int = 500) -> Iterator[Alert]:
        must: list[dict] = [{"range": {"rule.level": {"gte": self.min_level}}}]
        if since:
            must.append({"range": {"timestamp": {"gt": since.astimezone(timezone.utc).isoformat()}}})
        body = {
            "size": limit,
            "sort": [{"timestamp": "asc"}],
            "query": {
                "bool": {
                    "must": must,
                    "must_not": [{"terms": {"rule.groups": list(self.exclude_groups)}}],
                }
            },
        }
        resp = self.client.post(f"{self.url}/{self.index}/_search", json=body)
        resp.raise_for_status()
        for doc in resp.json()["hits"]["hits"]:
            yield parse(doc)

    def health(self) -> dict:
        resp = self.client.get(f"{self.url}/_cluster/health")
        resp.raise_for_status()
        return resp.json()
