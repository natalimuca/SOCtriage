import json
import random
from collections import Counter
from pathlib import Path

from .enrich import Baseline, load_assets, load_flagged
from .pipeline import Pipeline
from .schema import Result
from .sources import build as build_source
from .triage import build as build_analyst

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
HEADLINE = [
    "escalation_f1",
    "verdict_accuracy",
    "severity_exact",
    "technique_f1",
    "brier",
]


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


def counters(row: dict) -> dict:
    predicted = set(row["techniques"])
    wanted = set(row["techniques_expected"])
    gap = abs(
        SEVERITY_ORDER.index(row["severity"]) - SEVERITY_ORDER.index(row["severity_expected"])
    )
    verdict_ok = row["verdict"] == row["verdict_expected"]
    return {
        "esc_tp": int(row["escalate"] and row["escalate_expected"]),
        "esc_fp": int(row["escalate"] and not row["escalate_expected"]),
        "esc_fn": int(not row["escalate"] and row["escalate_expected"]),
        "tech_tp": len(predicted & wanted),
        "tech_fp": len(predicted - wanted),
        "tech_fn": len(wanted - predicted),
        "verdict_ok": int(verdict_ok),
        "sev_exact": int(gap == 0),
        "sev_near": int(gap <= 1),
        "brier": (row["confidence"] - (1.0 if verdict_ok else 0.0)) ** 2,
        "pure": int(row.get("pure", True)),
        "cost_usd": row.get("cost_usd", 0.0),
        "latency_ms": row.get("latency_ms", 0),
    }


def aggregate(rows: list[dict]) -> dict:
    n = len(rows) or 1
    c = {key: sum(r[key] for r in rows) for key in rows[0] if key != "latency_ms"} if rows else {}
    latencies = sorted(r["latency_ms"] for r in rows) or [0]
    escalation = prf(c["esc_tp"], c["esc_fp"], c["esc_fn"])
    techniques = prf(c["tech_tp"], c["tech_fp"], c["tech_fn"])
    return {
        "correlation_purity": c["pure"] / n,
        "verdict_accuracy": c["verdict_ok"] / n,
        "severity_exact": c["sev_exact"] / n,
        "severity_within_one": c["sev_near"] / n,
        "escalation_precision": escalation["precision"],
        "escalation_recall": escalation["recall"],
        "escalation_f1": escalation["f1"],
        "escalation_false_alarms": c["esc_fp"],
        "escalation_misses": c["esc_fn"],
        "technique_precision": techniques["precision"],
        "technique_recall": techniques["recall"],
        "technique_f1": techniques["f1"],
        "brier": c["brier"] / n,
        "latency_p50_ms": latencies[len(latencies) // 2],
        "latency_p95_ms": latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))],
        "cost_total_usd": c["cost_usd"],
        "cost_per_incident_usd": c["cost_usd"] / n,
    }


def intervals(rows: list[dict], draws: int = 4000, seed: int = 0) -> dict:
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {k: [] for k in HEADLINE}
    for _ in range(draws):
        drawn = [rows[rng.randrange(len(rows))] for _ in rows]
        metrics = aggregate(drawn)
        for key in HEADLINE:
            samples[key].append(metrics[key])
    out = {}
    for key, values in samples.items():
        values.sort()
        out[key] = {
            "low": values[int(0.025 * draws)],
            "high": values[int(0.975 * draws) - 1],
        }
    return out


def compare(left: str | Path, right: str | Path, draws: int = 4000, seed: int = 0) -> dict:
    """Paired bootstrap over the same cases: is the difference bigger than the corpus noise?"""
    a = json.loads(Path(left).read_text(encoding="utf-8"))
    b = json.loads(Path(right).read_text(encoding="utf-8"))
    by_case_a = {r["case"]: counters(r) for r in a["cases"]}
    by_case_b = {r["case"]: counters(r) for r in b["cases"]}
    shared = sorted(set(by_case_a) & set(by_case_b))
    if not shared:
        raise ValueError("the two runs share no cases")

    base_a, base_b = aggregate([by_case_a[c] for c in shared]), aggregate([by_case_b[c] for c in shared])
    rng = random.Random(seed)
    deltas: dict[str, list[float]] = {k: [] for k in HEADLINE}
    for _ in range(draws):
        picks = [shared[rng.randrange(len(shared))] for _ in shared]
        left_metrics = aggregate([by_case_a[c] for c in picks])
        right_metrics = aggregate([by_case_b[c] for c in picks])
        for key in HEADLINE:
            deltas[key].append(right_metrics[key] - left_metrics[key])

    out = {"left": a.get("analyst", str(left)), "right": b.get("analyst", str(right)), "cases": len(shared), "metrics": {}}
    for key, values in deltas.items():
        values.sort()
        low, high = values[int(0.025 * draws)], values[int(0.975 * draws) - 1]
        out["metrics"][key] = {
            "left": base_a[key],
            "right": base_b[key],
            "delta": base_b[key] - base_a[key],
            "ci_low": low,
            "ci_high": high,
            "separated": low > 0 or high < 0,
        }
    return out


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
    for result in results:
        name = case_of(result)
        expected = truth.get(name)
        if expected is None:
            continue
        t = result.triage
        rows.append(
            {
                "case": name,
                "pure": pure(result),
                "verdict": t.verdict,
                "verdict_expected": expected["verdict"],
                "verdict_ok": t.verdict == expected["verdict"],
                "severity": t.severity,
                "severity_expected": expected["severity"],
                "escalate": t.escalate,
                "escalate_expected": expected["escalate"],
                "confidence": t.confidence,
                "techniques": sorted({x.id for x in t.techniques}),
                "techniques_expected": sorted(expected["techniques"]),
                "summary": t.summary,
                "latency_ms": result.latency_ms,
                "cost_usd": result.cost_usd,
            }
        )

    counted = [counters(r) for r in rows]
    return {
        "analyst": results[0].analyst if results else analyst,
        "cases_labelled": len(truth),
        "incidents_produced": len(results),
        "metrics": aggregate(counted),
        "intervals": intervals(counted),
        "cases": sorted(rows, key=lambda r: r["case"]),
    }
