# soc

Alert triage for a Wazuh SIEM. Alerts are correlated into incidents, enriched with asset and
rarity context, and sent to Claude for a verdict, a severity, an ATT&CK mapping tied to
evidence, and an escalation decision. Every run is scored against a labelled corpus and
against a threshold baseline, so the question "is the model actually better than sorting by
rule level" has an answer rather than a demo.

The stack is real. `docker/` brings up a Wazuh manager, indexer, and dashboard, plus a
generator container that writes attack and benign activity into a log volume the manager
monitors. Wazuh's own decoders and rules produce the alerts; nothing about the detection is
simulated on the Python side.

## Flow

```
generator container ──► /var/log/lab/*.log ──► wazuh.manager (decoders + rules)
                                                     │
                                                filebeat
                                                     ▼
                                              wazuh.indexer  ◄── WazuhSource (REST)
                                                                      │
                                          correlate ──► enrich ──► triage ──► report
                                          (per host,   (asset,     (Claude    (markdown
                                           time gap)    rarity,     or rule     + JSONL)
                                                        ATT&CK)     baseline)
```

`JsonlSource` swaps in for `WazuhSource` behind the same interface, which is how the
evaluation runs without the stack.

## Setup

```bash
python -m venv .venv && .venv/Scripts/python.exe -m pip install -e ".[dev]"
```

```bash
cp .env.example .env
```

Set `ANTHROPIC_API_KEY` in `.env`. Then pull the ATT&CK matrix once:

```bash
.venv/Scripts/python.exe -m soc.cli sync
```

## The stack

Certificates are generated once, then the stack comes up:

```bash
docker compose -f docker/generate-indexer-certs.yml run --rm generator
```

```bash
.venv/Scripts/python.exe -m soc.cli stack up
```

Four containers: `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard` (https://localhost:8443,
`admin` / `SecretPassword`), and `victim`, which fires one of six scenes every ninety seconds.
Three scenes are attacks (credential guessing that succeeds and creates an account, a web
shell delivered after a scan, cron persistence pulling a remote script), three are benign
(admin maintenance, internet background noise, a failing backup job). Fire one on demand:

```bash
docker compose -f docker/docker-compose.yml exec victim python scenes.py --scene web_shell
```

The indexer needs `vm.max_map_count` at 262144 inside the Docker VM. On Docker Desktop:
`wsl -d docker-desktop -e sh -c 'echo 262144 > /proc/sys/vm/max_map_count'`.

## Running

Triage what is in the indexer now:

```bash
.venv/Scripts/python.exe -m soc.cli run --source wazuh --analyst claude
```

Follow the stack continuously:

```bash
.venv/Scripts/python.exe -m soc.cli watch --interval 60
```

Both write one markdown report per incident, a `summary.md` ranked by severity, and
`results.jsonl` into `out/`. Compliance and inventory alerts (`sca`, `rootcheck`,
`vulnerability-detector`, `syscollector`) are excluded by default: a fresh Wazuh manager
produces about two hundred of them at first boot and they are a posture report, not events.

## Evaluation

`eval/alerts.jsonl` is 39 Wazuh-shaped alerts forming 14 labelled cases: six true positives
(credential access ending in account creation, web shell, cron persistence, staged
exfiltration from the database, lateral movement by new SSH key, local privilege escalation),
six false positives (package upgrade file-integrity burst, admin maintenance, internet noise,
nightly backup failure, scanner 404s, CI workspace churn), and two genuinely ambiguous cases
where the honest answer is `inconclusive` with an escalation.

```bash
.venv/Scripts/python.exe -m soc.cli eval --analyst claude
```

```bash
.venv/Scripts/python.exe -m soc.cli eval --analyst rules
```

The corpus is regenerated from `eval/make.py`, which holds the alerts and the labels
together so a case and its ground truth cannot drift apart.

### Metrics

Escalation precision and recall matter most: a missed escalation is an incident nobody looks
at, a false one is analyst time. Alongside those the harness scores verdict accuracy, severity
(exact and within one band), micro-averaged ATT&CK technique precision and recall, and a
Brier score over the model's stated confidence, which catches an analyst that is right often
but certain always. It also reports correlation purity, the fraction of incidents whose
alerts all belong to one case, so a correlation bug cannot hide inside a triage score.

### Baseline

`--analyst rules` is severity from Wazuh rule level, escalation above level 10, techniques
copied from whatever the firing rules asserted. It exists to be beaten:

| metric | rules baseline |
| --- | --- |
| escalation F1 | 0.800 |
| escalation misses | 2 |
| escalation false alarms | 1 |
| verdict accuracy | 0.500 |
| severity exact | 0.571 |
| technique F1 | 0.909 |
| Brier | 0.250 |
| correlation purity | 1.000 |

The baseline is deliberately not weak. Rule level alone gets escalation F1 to 0.8 on this
corpus, and copying rule-asserted techniques scores 0.909 because Wazuh's own ATT&CK mapping
is decent. Verdict accuracy is where it collapses: a threshold cannot tell a package upgrade
from an attacker, so it sits at 0.500 and reports 0.5 confidence on everything, which is what
the Brier score of 0.250 measures.

**No Claude numbers are recorded here yet.** This machine has no Anthropic credentials, so
the `claude` analyst has never been executed against the corpus. Add a key and run
`soc eval --analyst claude` to fill in the second column. Publishing a comparison before
running it would defeat the point of building the harness.

## Design notes

The playbook in `soc/playbook.md` is the entire system prompt and it never changes between
calls, so it sits in a single cached system block with a one-hour TTL. Everything volatile
(the incident, the ATT&CK reference for its techniques) goes in the user message, after the
cache breakpoint. `soc eval` prints cached input tokens so a silent cache invalidation shows
up as a cost regression rather than going unnoticed.

Requests run on `claude-opus-5` at `high` effort with adaptive thinking, through
`client.beta.messages.parse` with the `Triage` pydantic model as the output schema, so the
verdict, severity, confidence, and technique list are validated on arrival instead of parsed
out of prose. Server-side fallbacks are enabled: this workload asks a model to reason in
detail about intrusion technique, and an occasional policy decline on a live alert queue
should degrade to another model rather than drop the incident. A refusal that survives the
fallback is turned into an `inconclusive` verdict flagged for escalation, never a silent
skip.

Enrichment is deliberately small and local. `assets.yml` carries criticality, exposure, and
owner per host, which is what moves severity. `data/baseline.json` counts how often each host
has produced each rule, which is what separates a first-ever alert from nightly noise; it
learns on every `run` and `watch`, and is frozen during `eval` so scores are not affected by
the order cases happen to arrive in. `indicators.txt` is a flat list of addresses seen in
prior confirmed incidents.

Correlation groups alerts per host with a ten-minute gap between them. This is the crudest
part of the system and the metric that watches it is `correlation_purity`.

## Limits

Fourteen cases is a small corpus, and I wrote both the alerts and the labels, so it measures
agreement with one analyst's judgement rather than ground truth from a real environment.
Treat the numbers as a regression harness for changes to the prompt, model, or enrichment,
not as evidence about production performance. Feeding it real labelled alerts is the obvious
next step and nothing in the pipeline needs to change to do it.

The lab generator writes log lines rather than performing the attacks, so Wazuh's decoders
and rules are exercised end to end but its file-integrity and rootcheck modules are not.
Alerts are attributed to the syslog hostname in the line, which is how a single manager
container can stand in for several hosts.
