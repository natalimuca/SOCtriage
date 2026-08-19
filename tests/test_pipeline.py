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
