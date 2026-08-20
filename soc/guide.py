"""Adapter for Microsoft's GUIDE dataset (Kaggle: Microsoft/microsoft-security-incident-prediction).

GUIDE is 1M incidents whose triage grade was assigned by real customer SOC analysts, so it is
an external, multi-annotator answer to "who labelled this". This module reshapes a sample of
its Defender-schema rows into the same Incident objects the Wazuh pipeline produces, and maps
its IncidentGrade to the verdict the harness scores. It grounds the verdict in real analyst
judgement; it carries no severity or inconclusive band, which are noted as gaps.
"""
from __future__ import annotations

import random
from datetime import datetime, timezone

import pandas as pd

from .schema import Alert, Incident

GRADE_TO_VERDICT = {
    "TruePositive": "true_positive",
    "BenignPositive": "false_positive",
    "FalsePositive": "false_positive",
}

# Columns we read if present; GUIDE ships ~45 and names drift slightly between versions.
WANTED = [
    "Id", "OrgId", "IncidentId", "AlertId", "Timestamp", "DetectorId",
    "AlertTitle", "Category", "MitreTechniques", "IncidentGrade",
    "EntityType", "DeviceName", "Sha256", "IpAddress", "AccountName",
]


def _first(row: pd.Series, *names: str) -> str | None:
    for n in names:
        if n in row and pd.notna(row[n]) and str(row[n]).strip():
            return str(row[n]).strip()
    return None


def _techniques(value) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []
    parts = value.replace(";", ",").split(",")
    return [p.strip() for p in parts if p.strip().startswith("T")]


def load(
    path: str,
    sample_incidents: int = 60,
    max_alerts: int = 12,
    seed: int = 0,
) -> tuple[list[Incident], dict]:
    """Read a GUIDE CSV, sample incidents balanced across the three grades, and return our
    Incident objects plus a labels dict keyed by incident id."""
    usecols = None
    header = pd.read_csv(path, nrows=0)
    usecols = [c for c in WANTED if c in header.columns]
    if "IncidentId" not in usecols or "IncidentGrade" not in usecols:
        raise ValueError("GUIDE CSV is missing IncidentId or IncidentGrade")

    df = pd.read_csv(path, usecols=usecols, low_memory=False)
    df = df[df["IncidentGrade"].isin(GRADE_TO_VERDICT)]

    rng = random.Random(seed)
    per_grade = max(1, sample_incidents // 3)
    chosen: list = []
    for grade in GRADE_TO_VERDICT:
        ids = df.loc[df["IncidentGrade"] == grade, "IncidentId"].dropna().unique().tolist()
        rng.shuffle(ids)
        chosen.extend((iid, grade) for iid in ids[:per_grade])

    incidents: list[Incident] = []
    labels: dict[str, dict] = {}
    for iid, grade in chosen:
        rows = df[df["IncidentId"] == iid].head(max_alerts)
        alerts = [_alert(r, iid, n) for n, (_, r) in enumerate(rows.iterrows())]
        if not alerts:
            continue
        alerts.sort(key=lambda a: a.timestamp)
        case = f"guide-{iid}"
        incidents.append(
            Incident(
                id=case,
                host=alerts[0].host,
                started=alerts[0].timestamp,
                ended=alerts[-1].timestamp,
                alerts=alerts,
            )
        )
        verdict = GRADE_TO_VERDICT[grade]
        labels[case] = {
            "verdict": verdict,
            "escalate": verdict == "true_positive",
            "severity": "high" if verdict == "true_positive" else "informational",
            "techniques": sorted({t for a in alerts for t in a.technique_ids}),
            "note": f"GUIDE analyst grade: {grade}",
        }
    return incidents, labels


def _alert(row: pd.Series, iid, n: int) -> Alert:
    ts = _first(row, "Timestamp")
    try:
        stamp = datetime.fromisoformat(str(ts).replace("Z", "+00:00")) if ts else datetime.now(timezone.utc)
    except ValueError:
        stamp = datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)

    host = _first(row, "DeviceName", "IpAddress", "AccountName") or f"org{_first(row, 'OrgId') or '0'}"
    desc = _first(row, "AlertTitle", "Category") or "GUIDE alert"
    groups = [g for g in [_first(row, "Category"), _first(row, "EntityType")] if g]
    return Alert(
        id=f"{iid}-{n}",
        timestamp=stamp,
        rule_id=str(_first(row, "DetectorId") or "guide"),
        rule_level=7,
        rule_description=desc,
        rule_groups=groups,
        technique_ids=_techniques(row.get("MitreTechniques")),
        host=host,
        src_ip=_first(row, "IpAddress"),
        src_user=_first(row, "AccountName"),
        full_log=f"{desc} [{_first(row, 'Category') or ''}]",
        raw={"case": f"guide-{iid}", "grade": _first(row, "IncidentGrade")},
    )
