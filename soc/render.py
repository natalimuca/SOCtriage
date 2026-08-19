from .schema import Incident


def incident_text(incident: Incident) -> str:
    e = incident.enrichment
    lines = [
        "## Incident",
        f"id: {incident.id}",
        f"host: {incident.host}",
        f"window: {incident.started.isoformat()} to {incident.ended.isoformat()} ({e.span_seconds:.0f}s)",
        f"alerts: {len(incident.alerts)} across {e.distinct_rules} distinct rules, max rule level {incident.max_level}",
        "",
        "## Asset",
    ]
    if e.asset:
        lines += [
            f"criticality: {e.asset.criticality}",
            f"exposure: {e.asset.exposure}",
            f"role: {e.asset.role}",
            f"owner: {e.asset.owner}",
            f"tags: {', '.join(e.asset.tags) or 'none'}",
        ]
    else:
        lines.append("no asset record for this host")

    lines += [
        "",
        "## Enrichment",
        f"times this host has produced the rarest of these rules before: {e.rule_seen_before}",
        f"rarity score (1.0 = never seen on this host): {e.rule_rarity}",
        f"source address scope: {e.src_ip_scope}",
        f"source address on the flagged-indicator list: {e.src_ip_flagged}",
        f"tactics asserted by the firing rules, in kill-chain order: {', '.join(e.tactics) or 'none'}",
        "",
        "## Techniques asserted by the Wazuh rules",
    ]
    if e.technique_names:
        for tid, tname in e.technique_names.items():
            lines.append(f"{tid} {tname}")
    else:
        lines.append("none asserted")

    lines += ["", "## Alerts"]
    for alert in incident.alerts:
        lines.append(
            f"[{alert.timestamp.isoformat()}] rule {alert.rule_id} level {alert.rule_level}: {alert.rule_description}"
        )
        detail = []
        if alert.src_ip:
            detail.append(f"src_ip={alert.src_ip}")
        if alert.src_user:
            detail.append(f"user={alert.src_user}")
        if alert.process:
            detail.append(f"process={alert.process}")
        if alert.rule_groups:
            detail.append(f"groups={','.join(alert.rule_groups)}")
        if detail:
            lines.append("  " + " ".join(detail))
        if alert.full_log:
            lines.append(f"  log: {alert.full_log[:400]}")

    return "\n".join(lines)
