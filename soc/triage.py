import time
from abc import ABC, abstractmethod
from pathlib import Path

import anthropic

from . import attack
from .config import settings
from .render import incident_text
from .schema import Incident, Result, Technique, Triage

PLAYBOOK = (Path(__file__).parent / "playbook.md").read_text(encoding="utf-8")

PRICING = {
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
}


NO_KEY_MESSAGE = """The claude analyst needs an Anthropic API key.

Create one at https://console.anthropic.com under Settings, then API keys, and write it to
.env in the repo root:

    ANTHROPIC_API_KEY=sk-ant-...

Until then, --analyst rules runs the threshold baseline and needs no key."""


class MissingCredentials(RuntimeError):
    pass


class Analyst(ABC):
    name: str

    @abstractmethod
    def triage(self, incident: Incident) -> Result:
        ...


class RuleAnalyst(Analyst):
    name = "rules"

    def triage(self, incident: Incident) -> Result:
        start = time.perf_counter()
        level = incident.max_level
        asset = incident.enrichment.asset

        if level >= 12:
            severity = "critical"
        elif level >= 10:
            severity = "high"
        elif level >= 7:
            severity = "medium"
        elif level >= 5:
            severity = "low"
        else:
            severity = "informational"

        if asset and asset.criticality == "crown_jewel" and severity in ("medium", "high"):
            severity = {"medium": "high", "high": "critical"}[severity]

        escalate = severity in ("high", "critical")
        verdict = "true_positive" if level >= 10 else "inconclusive"

        triage = Triage(
            verdict=verdict,
            confidence=0.5,
            severity=severity,
            escalate=escalate,
            summary=f"{len(incident.alerts)} alerts on {incident.host}, max rule level {level}",
            narrative="Severity derived from Wazuh rule level and asset criticality. No content analysis performed.",
            techniques=[
                Technique(
                    id=tid,
                    name=name,
                    tactic=min(attack.tactics(tid), key=attack.order, default="unknown"),
                    evidence="asserted by firing rule",
                )
                for tid, name in incident.enrichment.technique_names.items()
            ],
            containment=[],
            investigation=["Review the raw alerts."],
            caveats=["Threshold baseline, not an analysis."],
        )
        return Result(
            incident=incident,
            triage=triage,
            analyst=self.name,
            latency_ms=int((time.perf_counter() - start) * 1000),
        )


class ClaudeAnalyst(Analyst):
    name = "claude"

    def __init__(self, model: str | None = None, client: anthropic.Anthropic | None = None):
        if client is None and not settings.has_credentials:
            raise MissingCredentials(NO_KEY_MESSAGE)
        self.model = model or settings.model
        self.client = client or anthropic.Anthropic()

    def _system(self) -> list[dict]:
        return [
            {
                "type": "text",
                "text": PLAYBOOK,
                "cache_control": {"type": "ephemeral", "ttl": "1h"},
            }
        ]

    def _user(self, incident: Incident) -> str:
        technique_ids = [tid for a in incident.alerts for tid in a.technique_ids]
        reference = attack.brief(technique_ids)
        parts = [incident_text(incident)]
        if reference:
            parts += ["", "## ATT&CK reference for the asserted techniques", reference]
        parts += ["", "Triage this incident."]
        return "\n".join(parts)

    def triage(self, incident: Incident) -> Result:
        start = time.perf_counter()
        response = self.client.beta.messages.parse(
            model=self.model,
            max_tokens=settings.max_tokens,
            system=self._system(),
            messages=[{"role": "user", "content": self._user(incident)}],
            output_format=Triage,
            output_config={"effort": settings.effort},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        latency = int((time.perf_counter() - start) * 1000)
        served_by = response.model

        if response.stop_reason == "refusal":
            triage = Triage(
                verdict="inconclusive",
                confidence=0.0,
                severity="informational",
                escalate=True,
                summary="Model declined to analyse this incident.",
                narrative="The request was declined by a safety classifier, so no triage was produced. Route to a human analyst.",
                techniques=[],
                containment=[],
                investigation=["Analyse manually."],
                caveats=[f"stop_reason=refusal ({getattr(response.stop_details, 'category', None)})"],
            )
        else:
            triage = response.parsed_output

        usage = response.usage
        return Result(
            incident=incident,
            triage=triage,
            analyst=f"{self.name}:{served_by}",
            latency_ms=latency,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cost_usd=self._cost(usage),
        )

    def _cost(self, usage) -> float:
        rate_in, rate_out = PRICING.get(self.model, (5.0, 25.0))
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
        total = (
            usage.input_tokens * rate_in
            + cache_read * rate_in * 0.1
            + cache_write * rate_in * 1.25
            + usage.output_tokens * rate_out
        )
        return round(total / 1_000_000, 6)


def build(name: str, model: str | None = None) -> Analyst:
    if name == "rules":
        return RuleAnalyst()
    if name == "claude":
        return ClaudeAnalyst(model=model)
    raise ValueError(f"unknown analyst: {name}")
