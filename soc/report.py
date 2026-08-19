from datetime import datetime, timezone

from .schema import Result


def incident_report(result: Result) -> str:
    t = result.triage
    i = result.incident
    asset = i.enrichment.asset

    lines = [
        f"# {t.severity.upper()} — {i.host} — {i.id}",
        "",
        t.summary,
        "",
        "| field | value |",
        "| --- | --- |",
        f"| verdict | {t.verdict} |",
        f"| confidence | {t.confidence:.2f} |",
        f"| escalate | {'yes' if t.escalate else 'no'} |",
        f"| window | {i.started.isoformat()} to {i.ended.isoformat()} |",
        f"| alerts | {len(i.alerts)} ({i.enrichment.distinct_rules} distinct rules, max level {i.max_level}) |",
        f"| asset | {asset.criticality}/{asset.exposure}, {asset.role}, owner {asset.owner} |" if asset else "| asset | no record |",
        f"| rarity | {i.enrichment.rule_rarity} (seen {i.enrichment.rule_seen_before}x before) |",
        f"| analyst | {result.analyst} |",
        "",
        "## Assessment",
        "",
        t.narrative,
        "",
    ]

    if t.techniques:
        lines += ["## Techniques", "", "| id | name | tactic | evidence |", "| --- | --- | --- | --- |"]
        lines += [f"| {x.id} | {x.name} | {x.tactic} | {x.evidence} |" for x in t.techniques]
        lines.append("")

    if t.containment:
        lines += ["## Containment", ""] + [f"{n}. {step}" for n, step in enumerate(t.containment, 1)] + [""]

    if t.investigation:
        lines += ["## Investigation", ""] + [f"{n}. {step}" for n, step in enumerate(t.investigation, 1)] + [""]

    if t.caveats:
        lines += ["## Caveats", ""] + [f"- {c}" for c in t.caveats] + [""]

    lines += ["## Alerts", "", "| time | rule | level | description |", "| --- | --- | --- | --- |"]
    lines += [
        f"| {a.timestamp.strftime('%H:%M:%S')} | {a.rule_id} | {a.rule_level} | {a.rule_description} |"
        for a in i.alerts
    ]

    return "\n".join(lines) + "\n"


def run_summary(results: list[Result]) -> str:
    if not results:
        return "No incidents.\n"

    escalated = [r for r in results if r.triage.escalate]
    cost = sum(r.cost_usd for r in results)
    latency = sorted(r.latency_ms for r in results)
    p50 = latency[len(latency) // 2]
    cache = sum(r.cache_read_tokens for r in results)

    lines = [
        f"# Triage run — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"{len(results)} incidents, {sum(len(r.incident.alerts) for r in results)} alerts, "
        f"{len(escalated)} escalated, ${cost:.4f}, p50 {p50} ms, {cache} cached input tokens",
        "",
        "| severity | verdict | conf | host | incident | summary |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for r in sorted(results, key=lambda r: (order[r.triage.severity], -r.triage.confidence)):
        mark = "**" if r.triage.escalate else ""
        lines.append(
            f"| {mark}{r.triage.severity}{mark} | {r.triage.verdict} | {r.triage.confidence:.2f} | "
            f"{r.incident.host} | {r.incident.id} | {r.triage.summary} |"
        )

    return "\n".join(lines) + "\n"
