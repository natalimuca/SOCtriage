"""Adapter for the AIT Alert Data Set (Zenodo 8263181).

AIT-ADS is native Wazuh alerts from AIT's published testbeds, with a documented attack schedule.
Unlike GUIDE it is not anonymized: rule descriptions, IPs, and hosts are readable. Each testbed
runs one real kill chain (scans -> web attack -> web shell -> cracking -> reverse shell ->
privilege escalation -> service stop -> DNS exfil) at known UTC times, so every alert can be
labelled attack or benign from the schedule. This module builds one incident per attack phase
(true positive) and samples benign windows (false positive), then the harness scores our triage
against those external labels.
"""
from __future__ import annotations

import json
import random
import zipfile
from datetime import datetime
from pathlib import Path

from .schema import Alert, Incident
from .sources.wazuh import parse as parse_wazuh

ATTACK_TIMES = json.loads((Path(__file__).parent / "ait_attacktimes.json").read_text(encoding="utf-8"))
ATTACK_PHASES = [
    "network_scans", "service_scans", "dirb", "wpscan", "webshell",
    "cracking", "reverse_shell", "privilege_escalation", "service_stop", "dnsteal",
]
BENIGN_WINDOWS = ["false_positive_test", "false_positive_same_day"]


def _windows(testbed: str) -> dict[str, tuple[datetime, datetime]]:
    out = {}
    for name, (lo, hi) in ATTACK_TIMES[testbed].items():
        out[name] = (datetime.fromisoformat(lo), datetime.fromisoformat(hi))
    return out


def _phase_of(ts: datetime, windows: dict) -> str | None:
    for phase in ATTACK_PHASES:
        lo, hi = windows.get(phase, (None, None))
        if lo and lo <= ts < hi:
            return phase
    return None


def _alerts(zip_path: str, testbed: str) -> list[Alert]:
    with zipfile.ZipFile(zip_path) as z:
        raw = z.read(f"{testbed}_wazuh.json").decode("utf-8", "replace").strip()
    try:
        docs = json.loads(raw)
        if isinstance(docs, dict):
            docs = [docs]
    except json.JSONDecodeError:
        docs = [json.loads(line) for line in raw.splitlines() if line.strip()]

    alerts = []
    for i, src in enumerate(docs):
        # AIT uses the ISO @timestamp field; our Wazuh parser expects `timestamp`.
        if "timestamp" not in src and "@timestamp" in src:
            src["timestamp"] = src["@timestamp"]
        src.setdefault("data", {})
        try:
            alerts.append(parse_wazuh({"_id": src.get("id", f"ait{i}"), "_source": src}))
        except (KeyError, ValueError):
            continue
    return alerts


def _top(alerts: list[Alert], k: int) -> list[Alert]:
    """Surface the alerts carrying the attack signal: highest rule level first, then most recent."""
    ranked = sorted(alerts, key=lambda a: (a.rule_level, a.timestamp), reverse=True)[:k]
    return sorted(ranked, key=lambda a: a.timestamp)


def load(
    zip_path: str,
    testbeds: list[str] | None = None,
    benign_per_testbed: int = 8,
    benign_window_seconds: int = 300,
    max_alerts: int = 14,
    min_attack_level: int = 6,
    balance: bool = True,
    seed: int = 0,
) -> tuple[list[Incident], dict]:
    """Build labelled incidents from AIT. Attack phases become true-positive incidents built from
    the highest-severity alerts in their window; benign windows become false-positive incidents.
    Phases with no elevated alert are dropped, because host-based Wazuh did not detect them and a
    triage cannot be faulted for the same blind spot. With balance=True the two classes are
    matched in size so the majority-class floor is 0.5."""
    testbeds = testbeds or list(ATTACK_TIMES)
    rng = random.Random(seed)
    tp: list[tuple[Incident, dict]] = []
    fp: list[tuple[Incident, dict]] = []

    for testbed in testbeds:
        windows = _windows(testbed)
        alerts = sorted(_alerts(zip_path, testbed), key=lambda a: a.timestamp)
        if not alerts:
            continue

        for phase in ATTACK_PHASES:
            lo, hi = windows.get(phase, (None, None))
            if not lo:
                continue
            window = [a for a in alerts if lo <= a.timestamp < hi]
            # keep the phase only if Wazuh actually flagged something during it
            if not window or max(a.rule_level for a in window) < min_attack_level:
                continue
            phase_alerts = _top(window, max_alerts)
            case = f"ait-{testbed}-{phase}"
            tp.append((
                _incident(case, phase_alerts),
                {
                    "verdict": "true_positive", "escalate": True, "severity": "high",
                    "techniques": sorted({t for a in phase_alerts for t in a.technique_ids}),
                    "note": f"AIT {testbed} attack phase: {phase}",
                },
            ))

        benign_lo, benign_hi = windows.get("false_positive_same_day", (None, None))
        attack_lo = min((windows[p][0] for p in ATTACK_PHASES if p in windows), default=None)
        if benign_lo and attack_lo:
            pool = [a for a in alerts if benign_lo <= a.timestamp < min(attack_lo, benign_hi)]
            picked = attempts = 0
            while picked < benign_per_testbed and pool and attempts < 60:
                attempts += 1
                anchor = rng.choice(pool)
                window = [
                    a for a in pool
                    if 0 <= (a.timestamp - anchor.timestamp).total_seconds() < benign_window_seconds
                ][:max_alerts]
                if len(window) < 2:
                    continue
                case = f"ait-{testbed}-benign-{picked}"
                fp.append((
                    _incident(case, window),
                    {
                        "verdict": "false_positive", "escalate": False,
                        "severity": "informational", "techniques": [],
                        "note": f"AIT {testbed} benign window",
                    },
                ))
                picked += 1

    if balance:
        n = min(len(tp), len(fp))
        rng.shuffle(tp)
        rng.shuffle(fp)
        tp, fp = tp[:n], fp[:n]

    incidents: list[Incident] = []
    labels: dict[str, dict] = {}
    for inc, lab in tp + fp:
        incidents.append(inc)
        labels[inc.id] = lab
    return incidents, labels


def _incident(case: str, alerts: list[Alert]) -> Incident:
    for a in alerts:
        a.raw["case"] = case
    host = alerts[0].host
    return Incident(
        id=case,
        host=host,
        started=alerts[0].timestamp,
        ended=alerts[-1].timestamp,
        alerts=alerts,
    )
