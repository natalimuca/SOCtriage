from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["true_positive", "false_positive", "inconclusive"]
Severity = Literal["informational", "low", "medium", "high", "critical"]
Criticality = Literal["low", "medium", "high", "crown_jewel"]
Exposure = Literal["internal", "dmz", "internet"]


class Alert(BaseModel):
    id: str
    timestamp: datetime
    rule_id: str
    rule_level: int
    rule_description: str
    rule_groups: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    host: str
    src_ip: str | None = None
    src_user: str | None = None
    process: str | None = None
    full_log: str = ""
    raw: dict = Field(default_factory=dict)


class Asset(BaseModel):
    host: str
    criticality: Criticality = "medium"
    exposure: Exposure = "internal"
    owner: str = "unassigned"
    role: str = "unknown"
    tags: list[str] = Field(default_factory=list)


class Enrichment(BaseModel):
    asset: Asset | None = None
    rule_seen_before: int = 0
    rule_rarity: float = 0.0
    src_ip_scope: Literal["private", "public", "loopback", "none"] = "none"
    src_ip_flagged: bool = False
    tactics: list[str] = Field(default_factory=list)
    technique_names: dict[str, str] = Field(default_factory=dict)
    distinct_rules: int = 0
    span_seconds: float = 0.0


class Incident(BaseModel):
    id: str
    host: str
    started: datetime
    ended: datetime
    alerts: list[Alert]
    enrichment: Enrichment = Field(default_factory=Enrichment)

    @property
    def max_level(self) -> int:
        return max(a.rule_level for a in self.alerts)


class Technique(BaseModel):
    id: str
    name: str
    tactic: str
    evidence: str


class Triage(BaseModel):
    verdict: Verdict
    confidence: float
    severity: Severity
    escalate: bool
    summary: str
    narrative: str
    techniques: list[Technique]
    containment: list[str]
    investigation: list[str]
    caveats: list[str]


class Result(BaseModel):
    incident: Incident
    triage: Triage
    analyst: str
    latency_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cost_usd: float = 0.0
