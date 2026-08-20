import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import attack
from .config import OUT, ROOT, settings
from .pipeline import Pipeline
from .report import incident_report, run_summary
from .schema import Result
from .sinks import build as build_sink
from .sources import build as build_source
from .triage import MissingCredentials
from .triage import build as build_analyst

app = typer.Typer(add_completion=False, help="LLM alert triage over a Wazuh SIEM.")
console = Console()

SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "dim",
}


def build_checked(name: str, model: str | None = None):
    try:
        return build_analyst(name, model=model)
    except MissingCredentials as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1)


def build_sinks(names: list[str] | None):
    sinks = []
    for name in names or []:
        try:
            sinks.append(build_sink(name))
            console.print(f"[dim]sink: {name}[/]")
        except (ValueError, Exception) as exc:
            console.print(f"[red]sink {name} unavailable: {exc}[/]")
            raise typer.Exit(code=1)
    return sinks


def show(results: list[Result]) -> None:
    table = Table(show_lines=False)
    for column in ("severity", "verdict", "conf", "host", "alerts", "summary"):
        table.add_column(column, overflow="fold")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for r in sorted(results, key=lambda r: order[r.triage.severity]):
        style = SEVERITY_COLOR[r.triage.severity]
        table.add_row(
            f"[{style}]{r.triage.severity}[/]",
            r.triage.verdict,
            f"{r.triage.confidence:.2f}",
            r.incident.host,
            str(len(r.incident.alerts)),
            r.triage.summary,
        )
    console.print(table)
    cost = sum(r.cost_usd for r in results)
    console.print(
        f"{len(results)} incidents, {sum(1 for r in results if r.triage.escalate)} escalated, "
        f"${cost:.4f}, {sum(r.cache_read_tokens for r in results)} cached input tokens"
    )


def persist(results: list[Result], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for r in results:
        (out / f"{r.incident.id}.md").write_text(incident_report(r), encoding="utf-8")
    (out / "summary.md").write_text(run_summary(results), encoding="utf-8")
    (out / "results.jsonl").write_text(
        "\n".join(r.model_dump_json() for r in results) + "\n", encoding="utf-8"
    )


@app.command()
def sync():
    """Download the MITRE ATT&CK enterprise matrix and build the local index."""
    with console.status("fetching enterprise-attack.json"):
        count = attack.sync()
    console.print(f"indexed {count} techniques")


@app.command()
def run(
    source: str = typer.Option("jsonl", help="jsonl or wazuh"),
    path: str = typer.Option("eval/alerts.jsonl", help="corpus path for the jsonl source"),
    analyst: str = typer.Option("claude", help="claude or rules"),
    model: str = typer.Option(None),
    limit: int = typer.Option(500),
    out: str = typer.Option(str(OUT)),
    sink: list[str] = typer.Option(None, help="indexer and/or webhook; repeatable"),
):
    """Triage a batch of alerts and write incident reports."""
    src = build_source(source, path=path) if source == "jsonl" else build_source(source)
    pipeline = Pipeline(src, build_checked(analyst, model=model), sinks=build_sinks(sink))
    results = pipeline.run(limit=limit)
    if not results:
        console.print("no alerts")
        raise typer.Exit()
    show(results)
    persist(results, Path(out))
    console.print(f"reports written to {out}")


@app.command()
def watch(
    interval: int = typer.Option(60),
    analyst: str = typer.Option("claude"),
    out: str = typer.Option(str(OUT)),
    sink: list[str] = typer.Option(None, help="indexer and/or webhook; repeatable"),
):
    """Poll the Wazuh indexer and triage new alerts as they arrive."""
    pipeline = Pipeline(build_source("wazuh"), build_checked(analyst), sinks=build_sinks(sink))
    since = datetime.now(timezone.utc)
    console.print(f"watching {settings.indexer_url} from {since.isoformat()}")
    while True:
        results = pipeline.run(since=since)
        if results:
            since = max(r.incident.ended for r in results)
            show(results)
            persist(results, Path(out))
        time.sleep(interval)


@app.command(name="eval")
def evaluate(
    analyst: str = typer.Option("claude"),
    corpus: str = typer.Option("eval/alerts.jsonl"),
    labels: str = typer.Option("eval/labels.json"),
    model: str = typer.Option(None),
    out: str = typer.Option("eval/scores.json"),
):
    """Score an analyst against the labelled corpus."""
    from .score import evaluate as run_eval

    build_checked(analyst, model=model)

    report = run_eval(analyst=analyst, corpus=corpus, labels=labels, model=model)
    Path(out).write_text(json.dumps(report, indent=2), encoding="utf-8")

    table = Table(title=f"{analyst} vs labels")
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_column("95% CI", justify="right")
    for key, value in report["metrics"].items():
        ci = report["intervals"].get(key)
        table.add_row(
            key,
            f"{value:.3f}" if isinstance(value, float) else str(value),
            f"[{ci['low']:.3f}, {ci['high']:.3f}]" if ci else "",
        )
    console.print(table)
    console.print(
        f"intervals are a {report['incidents_produced']}-case bootstrap; "
        "differences smaller than the interval are not evidence"
    )
    console.print(f"scores written to {out}")


@app.command()
def compare(
    left: str = typer.Argument(..., help="baseline scores file"),
    right: str = typer.Argument(..., help="scores file to test against it"),
):
    """Paired bootstrap between two scored runs over the same cases."""
    from .score import compare as run_compare

    report = run_compare(left, right)
    table = Table(title=f"{report['left']}  ->  {report['right']}  ({report['cases']} cases)")
    for column in ("metric", "left", "right", "delta", "95% CI of delta", "verdict"):
        table.add_column(column, justify="right" if column != "metric" else "left")
    for key, m in report["metrics"].items():
        separated = m["separated"]
        table.add_row(
            key,
            f"{m['left']:.3f}",
            f"{m['right']:.3f}",
            f"{m['delta']:+.3f}",
            f"[{m['ci_low']:+.3f}, {m['ci_high']:+.3f}]",
            "[green]separated[/]" if separated else "[dim]overlaps zero[/]",
        )
    console.print(table)
    console.print("overlaps zero means the corpus is too small to call the difference real")


@app.command()
def agreement(
    labels: str = typer.Option("eval/labels.json"),
    scores: str = typer.Option("eval/scores-opus.json", help="a model run to treat as a second annotator"),
):
    """Inter-annotator agreement between the hand labels and a model's independent verdicts."""
    from .score import agreement as run_agreement

    report = run_agreement(labels=labels, scores=scores)
    console.print(
        f"[bold]{report['annotator']}[/] as second annotator over {report['cases']} cases"
    )
    table = Table()
    for col in ("dimension", "Cohen's kappa", "raw agreement"):
        table.add_column(col)
    table.add_row("verdict", f"{report['verdict_kappa']:.3f}", f"{report['verdict_agreement']:.3f}")
    table.add_row("escalation", f"{report['escalation_kappa']:.3f}", f"{report['escalation_agreement']:.3f}")
    console.print(table)
    if report["contested"]:
        console.print(f"\n[yellow]{len(report['contested'])} contested cases[/] (label != model):")
        for c in report["contested"]:
            console.print(
                f"  {c['case']}: label=[cyan]{c['label_verdict']}[/] model=[magenta]{c['model_verdict']}[/]"
            )
    else:
        console.print("no contested cases")


@app.command()
def stack(action: str = typer.Argument(..., help="up, down, status, or logs")):
    """Control the Wazuh docker stack."""
    docker = ROOT / "docker"
    commands = {
        "up": ["docker", "compose", "up", "-d", "--build"],
        "down": ["docker", "compose", "down"],
        "status": ["docker", "compose", "ps"],
        "logs": ["docker", "compose", "logs", "--tail", "50"],
    }
    if action not in commands:
        raise typer.BadParameter(f"expected one of {', '.join(commands)}")
    subprocess.run(commands[action], cwd=docker, check=False)


if __name__ == "__main__":
    app()
