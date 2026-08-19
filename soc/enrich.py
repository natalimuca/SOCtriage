import ipaddress
import json
import math
from collections import Counter
from pathlib import Path

import yaml

from . import attack
from .config import DATA, ROOT
from .schema import Alert, Asset, Enrichment, Incident

ASSETS_PATH = ROOT / "assets.yml"
BASELINE_PATH = DATA / "baseline.json"
FLAGGED_PATH = ROOT / "indicators.txt"


def load_assets(path: Path | None = None) -> dict[str, Asset]:
    path = path or ASSETS_PATH
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {host: Asset(host=host, **fields) for host, fields in raw.items()}


def load_flagged(path: Path | None = None) -> set[str]:
    path = path or FLAGGED_PATH
    if not path.exists():
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


class Baseline:
    def __init__(self, path: Path | None = None):
        self.path = path or BASELINE_PATH
        self.counts: Counter[str] = Counter()
        if self.path.exists():
            self.counts.update(json.loads(self.path.read_text(encoding="utf-8")))

    def observe(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            self.counts[f"{alert.host}:{alert.rule_id}"] += 1

    def seen(self, alert: Alert) -> int:
        return self.counts[f"{alert.host}:{alert.rule_id}"]

    def rarity(self, alerts: list[Alert]) -> float:
        if not alerts:
            return 0.0
        scores = [1.0 / (1.0 + math.log1p(self.seen(a))) for a in alerts]
        return round(max(scores), 3)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(dict(self.counts), indent=0, sort_keys=True), encoding="utf-8")


def ip_scope(ip: str | None) -> str:
    if not ip:
        return "none"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "none"
    if addr.is_loopback:
        return "loopback"
    return "private" if addr.is_private else "public"


def correlate(alerts: list[Alert], window: int = 600) -> list[Incident]:
    incidents: list[Incident] = []
    by_host: dict[str, list[Alert]] = {}
    for alert in sorted(alerts, key=lambda a: a.timestamp):
        by_host.setdefault(alert.host, []).append(alert)

    for host, host_alerts in by_host.items():
        bucket: list[Alert] = []
        for alert in host_alerts:
            if bucket and (alert.timestamp - bucket[-1].timestamp).total_seconds() > window:
                incidents.append(_incident(host, bucket))
                bucket = []
            bucket.append(alert)
        if bucket:
            incidents.append(_incident(host, bucket))

    return sorted(incidents, key=lambda i: i.started)


def _incident(host: str, alerts: list[Alert]) -> Incident:
    return Incident(
        id=f"{host}-{int(alerts[0].timestamp.timestamp())}",
        host=host,
        started=alerts[0].timestamp,
        ended=alerts[-1].timestamp,
        alerts=list(alerts),
    )


def enrich(
    incident: Incident,
    assets: dict[str, Asset],
    baseline: Baseline,
    flagged: set[str] | None = None,
) -> Incident:
    flagged = flagged or set()
    technique_ids = [tid for a in incident.alerts for tid in a.technique_ids]
    src_ips = [a.src_ip for a in incident.alerts if a.src_ip]

    incident.enrichment = Enrichment(
        asset=assets.get(incident.host),
        rule_seen_before=min((baseline.seen(a) for a in incident.alerts), default=0),
        rule_rarity=baseline.rarity(incident.alerts),
        src_ip_scope=ip_scope(src_ips[0] if src_ips else None),
        src_ip_flagged=any(ip in flagged for ip in src_ips),
        tactics=attack.chain(technique_ids),
        technique_names={tid: attack.name(tid) for tid in dict.fromkeys(technique_ids)},
        distinct_rules=len({a.rule_id for a in incident.alerts}),
        span_seconds=(incident.ended - incident.started).total_seconds(),
    )
    return incident
