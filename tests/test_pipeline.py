from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc.enrich import Baseline, correlate, enrich, ip_scope
from soc.pipeline import Pipeline
from soc.schema import Alert, Asset
from soc.score import case_of, prf
from soc.sources import build as build_source
from soc.triage import RuleAnalyst

BASE = datetime(2026, 8, 18, tzinfo=timezone.utc)


def alert(offset_seconds: int, host: str = "web01", rule_id: str = "5710", level: int = 5) -> Alert:
    return Alert(
        id=f"{host}-{offset_seconds}",
        timestamp=BASE + timedelta(seconds=offset_seconds),
        rule_id=rule_id,
        rule_level=level,
        rule_description="test",
        host=host,
    )


def test_correlate_splits_on_the_window():
    alerts = [alert(0), alert(60), alert(1200)]
    incidents = correlate(alerts, window=600)
    assert [len(i.alerts) for i in incidents] == [2, 1]


def test_correlate_separates_hosts():
    incidents = correlate([alert(0, "web01"), alert(30, "db01")], window=600)
    assert {i.host for i in incidents} == {"web01", "db01"}


@pytest.mark.parametrize(
    "address,expected",
    [("10.0.0.4", "private"), ("8.8.8.8", "public"), ("127.0.0.1", "loopback"), (None, "none"), ("nope", "none")],
)
def test_ip_scope(address, expected):
    assert ip_scope(address) == expected


def test_rarity_falls_as_a_rule_repeats(tmp_path):
    baseline = Baseline(path=tmp_path / "b.json")
    first = baseline.rarity([alert(0)])
    baseline.observe([alert(0) for _ in range(20)])
    assert baseline.rarity([alert(0)]) < first


def test_enrichment_attaches_the_asset(tmp_path):
    incident = correlate([alert(0), alert(30)], window=600)[0]
    assets = {"web01": Asset(host="web01", criticality="high", exposure="internet")}
    enriched = enrich(incident, assets, Baseline(path=tmp_path / "b.json"))
    assert enriched.enrichment.asset.exposure == "internet"
    assert enriched.enrichment.rule_rarity == 1.0


def test_corpus_runs_end_to_end(tmp_path):
    corpus = Path("eval/alerts.jsonl")
    assert corpus.exists(), "run: python eval/make.py"
    pipeline = Pipeline(
        build_source("jsonl", path=corpus),
        RuleAnalyst(),
        baseline=Baseline(path=tmp_path / "b.json"),
    )
    results = pipeline.run(limit=1000, learn=False)
    assert len(results) >= 14
    assert all(len({a.raw["case"] for a in r.incident.alerts}) == 1 for r in results)
    assert {case_of(r) for r in results} >= {"bruteforce_success", "admin_maintenance"}


def test_prf():
    assert prf(0, 0, 0) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    assert prf(2, 2, 0)["precision"] == 0.5
    assert prf(2, 0, 2)["recall"] == 0.5


def test_intervals_bracket_the_point_estimate():
    from soc.score import aggregate, counters, intervals

    rows = [
        counters(
            {
                "verdict": "true_positive" if n % 3 else "false_positive",
                "verdict_expected": "true_positive",
                "severity": "high",
                "severity_expected": "high" if n % 2 else "critical",
                "escalate": True,
                "escalate_expected": n % 4 != 0,
                "confidence": 0.8,
                "techniques": ["T1110.001"],
                "techniques_expected": ["T1110.001"],
            }
        )
        for n in range(12)
    ]
    point = aggregate(rows)
    bounds = intervals(rows, draws=400)
    for key, band in bounds.items():
        assert band["low"] <= point[key] <= band["high"], key


def test_compare_reports_no_difference_against_itself(tmp_path):
    from soc.score import compare

    scores = Path("eval/scores.json")
    assert scores.exists(), "run: python -m soc.cli eval --analyst rules"
    report = compare(scores, scores, draws=300)
    for key, m in report["metrics"].items():
        assert m["delta"] == 0.0, key
        assert not m["separated"], key


def test_rules_baseline_holds():
    from soc.score import evaluate

    metrics = evaluate(analyst="rules")["metrics"]
    floors = {
        "correlation_purity": 1.0,
        "escalation_f1": 0.55,
        "verdict_accuracy": 0.40,
        "technique_f1": 0.90,
    }
    below = {k: metrics[k] for k, floor in floors.items() if metrics[k] < floor - 1e-9}
    assert not below, f"baseline regressed: {below}"


def test_webhook_sink_filters_and_formats():
    from soc.schema import Alert, Incident, Result, Triage
    from soc.sinks.webhook import WebhookSink

    sent = []

    class FakeClient:
        def post(self, url, json):
            sent.append(json)

            class R:
                def raise_for_status(self_inner):
                    pass

            return R()

    def make(escalate: bool, severity: str) -> Result:
        a = alert(0)
        inc = Incident(id="h-1", host="web01", started=a.timestamp, ended=a.timestamp, alerts=[a])
        tri = Triage(
            verdict="true_positive", confidence=0.8, severity=severity, escalate=escalate,
            summary="s", narrative="n", techniques=[], containment=[], investigation=[], caveats=[],
        )
        return Result(incident=inc, triage=tri, analyst="rules")

    sink = WebhookSink(url="http://x")
    sink.client = FakeClient()

    assert sink.emit(make(True, "high")) is True
    assert sink.emit(make(False, "critical")) is False  # not escalated
    assert sink.emit(make(True, "low")) is False  # below min_severity
    assert len(sent) == 1
    assert "text" in sent[0] and "soc_triage" in sent[0]


def test_indexer_document_shape():
    from soc.schema import Alert, Incident, Result, Triage
    from soc.sinks.payload import document

    a = alert(0)
    inc = Incident(id="h-9", host="db01", started=a.timestamp, ended=a.timestamp, alerts=[a])
    tri = Triage(
        verdict="inconclusive", confidence=0.55, severity="medium", escalate=True,
        summary="s", narrative="n", techniques=[], containment=[], investigation=["look"], caveats=["gap"],
    )
    doc = document(Result(incident=inc, triage=tri, analyst="claude"))
    assert doc["incident"]["id"] == "h-9"
    assert doc["triage"]["verdict"] == "inconclusive"
    assert doc["triage"]["escalate"] is True
    assert "@timestamp" in doc


def test_agreement_against_self_is_perfect(tmp_path):
    import json

    from soc.score import agreement

    labels = Path("eval/labels.json")
    scores = Path("eval/scores.json")
    assert labels.exists() and scores.exists()

    # a run compared against labels built from that same run agrees perfectly
    data = json.loads(scores.read_text(encoding="utf-8"))
    synth = {r["case"]: {"verdict": r["verdict"], "escalate": r["escalate"], "techniques": [], "severity": r["severity"]} for r in data["cases"]}
    p = tmp_path / "labels.json"
    p.write_text(json.dumps(synth), encoding="utf-8")

    report = agreement(labels=str(p), scores=str(scores))
    assert report["verdict_kappa"] == 1.0
    assert report["contested"] == []


def test_agreement_reports_real_disagreement():
    from soc.score import agreement

    report = agreement()  # labels vs opus
    assert 0.0 <= report["verdict_kappa"] <= 1.0
    assert report["cases"] == 40
    for c in report["contested"]:
        assert c["label_verdict"] != c["model_verdict"]


def test_guide_adapter_groups_and_maps(tmp_path):
    pd = pytest.importorskip("pandas")

    from soc.guide import GRADE_TO_VERDICT, load

    rows = []
    for iid, grade in enumerate(["TruePositive", "BenignPositive", "FalsePositive"]):
        for a in range(2):
            rows.append(
                dict(
                    IncidentId=iid, Timestamp=f"2024-03-1{iid}T0{a}:00:00Z",
                    DetectorId=f"d{a}", AlertTitle=f"alert {grade}", Category="Execution",
                    MitreTechniques="T1059.001" if grade == "TruePositive" else "",
                    IncidentGrade=grade, DeviceName=f"host{iid}",
                )
            )
    csv = tmp_path / "guide.csv"
    pd.DataFrame(rows).to_csv(csv, index=False)

    incidents, labels = load(str(csv), sample_incidents=3)
    assert len(incidents) == 3
    for inc in incidents:
        assert len(inc.alerts) == 2  # grouped by IncidentId
        assert labels[inc.id]["verdict"] in GRADE_TO_VERDICT.values()
    # the true-positive incident escalates, the benign/false ones do not
    verdicts = {labels[i.id]["verdict"] for i in incidents}
    assert verdicts == {"true_positive", "false_positive"}
    assert sum(labels[i.id]["escalate"] for i in incidents) == 1


def test_ait_phase_labelling_and_ranking():
    from datetime import datetime, timezone

    from soc.ait import ATTACK_TIMES, _phase_of, _top, _windows

    # every shipped testbed has the full phase schedule
    assert set(ATTACK_TIMES) and all("webshell" in v for v in ATTACK_TIMES.values())

    tb = next(iter(ATTACK_TIMES))
    windows = _windows(tb)
    lo, hi = windows["webshell"]
    mid = lo + (hi - lo) / 2
    assert _phase_of(mid, windows) == "webshell"
    assert _phase_of(lo.replace(year=1990), windows) is None

    # _top surfaces the highest-severity alerts regardless of arrival order
    lvls = [alert(n, level=lvl) for n, lvl in enumerate([3, 12, 5, 9])]
    top2 = _top(lvls, 2)
    assert {a.rule_level for a in top2} == {12, 9}
