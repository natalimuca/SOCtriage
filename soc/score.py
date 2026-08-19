import json
from collections import Counter
from pathlib import Path

from .enrich import Baseline, load_assets, load_flagged
from .pipeline import Pipeline
from .schema import Result
from .sources import build as build_source
from .triage import build as build_analyst

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def case_of(result: Result) -> str:
    counts = Counter(a.raw.get("case", "unlabelled") for a in result.incident.alerts)
    return counts.most_common(1)[0][0]


def pure(result: Result) -> bool:
    return len({a.raw.get("case") for a in result.incident.alerts}) == 1


def prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def evaluate(
    analyst: str = "claude",
    corpus: str = "eval/alerts.jsonl",
    labels: str = "eval/labels.json",
    model: str | None = None,
) -> dict:
    truth = json.loads(Path(labels).read_text(encoding="utf-8"))

    pipeline = Pipeline(
        build_source("jsonl", path=corpus),
        build_analyst(analyst, model=model),
        baseline=Baseline(path=Path("eval/baseline.json")),
        assets=load_assets(),
        flagged=load_flagged(),
    )
    results = pipeline.run(limit=10_000, learn=False)

    rows = []
    esc_tp = esc_fp = esc_fn = 0
    tech_tp = tech_fp = tech_fn = 0
    verdict_hits = severity_hits = severity_near = 0
    brier = 0.0

    for result in results:
        name = case_of(result)
        expected = truth.get(name)
        if expected is None:
            continue
        t = result.triage

        verdict_ok = t.verdict == expected["verdict"]
        verdict_hits += verdict_ok
        brier += (t.confidence - (1.0 if verdict_ok else 0.0)) ** 2

        gap = abs(SEVERITY_ORDER.index(t.severity) - SEVERITY_ORDER.index(expected["severity"]))
        severity_hits += gap == 0
        severity_near += gap <= 1

        if t.escalate and expected["escalate"]:
            esc_tp += 1
        elif t.escalate and not expected["escalate"]:
            esc_fp += 1
        elif not t.escalate and expected["escalate"]:
            esc_fn += 1

        predicted = {x.id for x in t.techniques}
        wanted = set(expected["techniques"])
        tech_tp += len(predicted & wanted)
        tech_fp += len(predicted - wanted)
        tech_fn += len(wanted - predicted)

        rows.append(
            {
                "case": name,
                "pure": pure(result),
                "verdict": t.verdict,
                "verdict_expected": expected["verdict"],
                "verdict_ok": verdict_ok,
                "severity": t.severity,
                "severity_expected": expected["severity"],
                "escalate": t.escalate,
                "escalate_expected": expected["escalate"],
                "confidence": t.confidence,
                "techniques": sorted(predicted),
                "techniques_expected": sorted(wanted),
                "summary": t.summary,
                "latency_ms": result.latency_ms,
                "cost_usd": result.cost_usd,
            }
        )

    n = len(rows) or 1
    latencies = sorted(r["latency_ms"] for r in rows) or [0]
    escalation = prf(esc_tp, esc_fp, esc_fn)
    techniques = prf(tech_tp, tech_fp, tech_fn)
    correct = [r["confidence"] for r in rows if r["verdict_ok"]]
    wrong = [r["confidence"] for r in rows if not r["verdict_ok"]]

    return {
        "analyst": results[0].analyst if results else analyst,
        "cases_labelled": len(truth),
        "incidents_produced": len(results),
        "metrics": {
            "correlation_purity": sum(r["pure"] for r in rows) / n,
            "verdict_accuracy": verdict_hits / n,
            "severity_exact": severity_hits / n,
            "severity_within_one": severity_near / n,
            "escalation_precision": escalation["precision"],
            "escalation_recall": escalation["recall"],
            "escalation_f1": escalation["f1"],
            "escalation_false_alarms": esc_fp,
            "escalation_misses": esc_fn,
            "technique_precision": techniques["precision"],
            "technique_recall": techniques["recall"],
            "technique_f1": techniques["f1"],
            "brier": brier / n,
            "confidence_when_right": sum(correct) / len(correct) if correct else 0.0,
            "confidence_when_wrong": sum(wrong) / len(wrong) if wrong else 0.0,
            "latency_p50_ms": latencies[len(latencies) // 2],
            "latency_p95_ms": latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))],
            "cost_total_usd": sum(r["cost_usd"] for r in rows),
            "cost_per_incident_usd": sum(r["cost_usd"] for r in rows) / n,
        },
        "cases": sorted(rows, key=lambda r: r["case"]),
    }
