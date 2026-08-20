from datetime import datetime, timezone

from ..schema import Result


def document(result: Result) -> dict:
    t = result.triage
    i = result.incident
    asset = i.enrichment.asset
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "id": i.id,
            "host": i.host,
            "started": i.started.isoformat(),
            "ended": i.ended.isoformat(),
            "alert_count": len(i.alerts),
            "distinct_rules": i.enrichment.distinct_rules,
            "max_rule_level": i.max_level,
            "rule_ids": sorted({a.rule_id for a in i.alerts}),
        },
        "triage": {
            "verdict": t.verdict,
            "severity": t.severity,
            "confidence": t.confidence,
            "escalate": t.escalate,
            "summary": t.summary,
            "narrative": t.narrative,
            "techniques": [x.id for x in t.techniques],
            "tactics": i.enrichment.tactics,
            "containment": t.containment,
            "investigation": t.investigation,
            "caveats": t.caveats,
        },
        "asset": (
            {
                "criticality": asset.criticality,
                "exposure": asset.exposure,
                "role": asset.role,
                "owner": asset.owner,
            }
            if asset
            else None
        ),
        "analyst": result.analyst,
        "cost_usd": result.cost_usd,
        "latency_ms": result.latency_ms,
    }
