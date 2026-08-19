import json
from functools import lru_cache

import httpx

from .config import DATA

BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
INDEX_PATH = DATA / "attack.json"

KILL_CHAIN = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def sync(timeout: float = 180.0) -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        bundle = client.get(BUNDLE_URL).json()

    index: dict[str, dict] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ref:
            continue
        tid = ref["external_id"]
        index[tid] = {
            "id": tid,
            "name": obj["name"],
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            "description": " ".join(obj.get("description", "").split())[:400],
            "platforms": obj.get("x_mitre_platforms", []),
            "parent": tid.split(".")[0] if "." in tid else None,
        }

    INDEX_PATH.write_text(json.dumps(index, indent=0, sort_keys=True), encoding="utf-8")
    return len(index)


@lru_cache(maxsize=1)
def index() -> dict[str, dict]:
    if not INDEX_PATH.exists():
        return {}
    return json.loads(INDEX_PATH.read_text(encoding="utf-8"))


def technique(tid: str) -> dict | None:
    return index().get(tid)


def name(tid: str) -> str:
    t = technique(tid)
    return t["name"] if t else tid


def tactics(tid: str) -> list[str]:
    t = technique(tid)
    return t["tactics"] if t else []


def order(tactic: str) -> int:
    return KILL_CHAIN.index(tactic) if tactic in KILL_CHAIN else len(KILL_CHAIN)


def chain(technique_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    for tid in technique_ids:
        seen.update(tactics(tid))
    return sorted(seen, key=order)


def brief(technique_ids: list[str]) -> str:
    lines = []
    for tid in dict.fromkeys(technique_ids):
        t = technique(tid)
        if not t:
            lines.append(f"{tid}: not in local ATT&CK index")
            continue
        lines.append(f"{t['id']} {t['name']} [{', '.join(t['tactics'])}] {t['description']}")
    return "\n".join(lines)
