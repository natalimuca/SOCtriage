from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from .config import settings
from .enrich import Baseline, correlate, enrich, load_assets, load_flagged
from .schema import Result
from .sinks.base import Sink
from .sources.base import Source
from .triage import Analyst


class Pipeline:
    def __init__(
        self,
        source: Source,
        analyst: Analyst,
        baseline: Baseline | None = None,
        assets: dict | None = None,
        flagged: set[str] | None = None,
        window: int | None = None,
        concurrency: int | None = None,
        sinks: list[Sink] | None = None,
    ):
        self.source = source
        self.analyst = analyst
        self.baseline = baseline if baseline is not None else Baseline()
        self.assets = assets if assets is not None else load_assets()
        self.flagged = flagged if flagged is not None else load_flagged()
        self.window = window or settings.correlation_window
        self.concurrency = concurrency or settings.concurrency
        self.sinks = sinks or []

    def run(self, since: datetime | None = None, limit: int = 500, learn: bool = True) -> list[Result]:
        alerts = list(self.source.fetch(since=since, limit=limit))
        if not alerts:
            return []

        incidents = [
            enrich(incident, self.assets, self.baseline, self.flagged)
            for incident in correlate(alerts, self.window)
        ]

        if learn:
            self.baseline.observe(alerts)
            self.baseline.save()

        if self.concurrency <= 1:
            results = [self.analyst.triage(i) for i in incidents]
        else:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                results = list(pool.map(self.analyst.triage, incidents))

        for result in results:
            for sink in self.sinks:
                try:
                    sink.emit(result)
                except Exception as exc:  # a sink failure must not lose the triage result
                    print(f"sink {sink.name} failed on {result.incident.id}: {exc}")

        return results
