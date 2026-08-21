# SOCtriage

[![ci](https://github.com/natalimuca/SOCtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/natalimuca/SOCtriage/actions/workflows/ci.yml)

Alert triage for a Wazuh SIEM. Alerts are correlated into incidents, enriched with asset and
rarity context, and sent to Claude for a verdict, a severity, an ATT&CK mapping tied to
evidence, and an escalation decision. Every run is scored against a labelled corpus and
against a threshold baseline, so the question "is the model actually better than sorting by
rule level" has an answer rather than a demo.

The stack is real. `docker/` brings up a Wazuh manager, indexer, and dashboard, plus a
generator container that writes attack and benign activity into a log volume the manager
monitors. Wazuh's own decoders and rules produce the alerts; nothing about the detection is
simulated on the Python side.

## The problem

A SIEM hands an analyst hundreds of alerts a day: authentication failures, successes, file
changes, a chart of which ATT&CK techniques fired. What it cannot say is whether any of those
successes followed the failures on the same host within minutes, which is the difference
between background noise and an intrusion. Answering that is a person reading alerts one at a
time. This pipeline does that first pass.

![Triage output](docs/triage-run.png)

The same alerts, after the pipeline: twelve incidents, nine worth escalating, 16 cents, each a
paragraph a human can act on. The second row is the tell. The model reports the attacker
escalating to root and creating a UID-0 backdoor *while separating out `natali`, a legitimate
admin doing routine work on the same host in the same window*. A rule threshold cannot make
that distinction; it is the difference the evaluation measures.

A fuller illustrated tour, from raw alerts through the live agent to verdicts written back into
the SIEM dashboard, is in [docs/WALKTHROUGH.md](docs/WALKTHROUGH.md).

## Flow

```
generator container ──► /var/log/lab/*.log ──► wazuh.manager (decoders + rules)
                                                     │
                                                filebeat
                                                     ▼
                                              wazuh.indexer  ◄── WazuhSource (REST)
                                                                      │
                                          correlate ──► enrich ──► triage ──► report + sinks
                                          (per host,   (asset,     (Claude    (markdown,
                                           time gap)    rarity,     or rule     indexer,
                                                        ATT&CK)     baseline)   webhook)
```

`JsonlSource` swaps in for `WazuhSource` behind the same interface, which is how the
evaluation runs without the stack.

## Setup

```bash
python -m venv .venv
```

Activate it. On Windows PowerShell:

```bash
.venv\Scripts\Activate.ps1
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

```bash
pip install -e ".[dev]"
```

```bash
cp .env.example .env
```

Every command below assumes that environment is active. Set `ANTHROPIC_API_KEY` in `.env`,
then pull the ATT&CK matrix once:

```bash
python -m soc.cli sync
```

## The stack

Certificates are generated once, then the stack comes up:

```bash
docker compose -f docker/generate-indexer-certs.yml run --rm generator
```

```bash
python -m soc.cli stack up
```

Four containers: `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard` (https://localhost:8443,
`admin` / `SecretPassword`), and `victim`, which runs a real Wazuh agent and fires one of eight
scenes every two minutes. The attack scenes perform real actions on the host, credential
guessing that lands and creates a UID-0 account, a web shell written into a monitored web root,
cron persistence, an `/etc/passwd` edit, an SSH key drop, so the agent's own file-integrity and
rootcheck modules detect them. Benign scenes cover admin maintenance, background noise, and
scanner 404s. Fire one on demand:

```bash
docker compose -f docker/docker-compose.yml exec victim python3 /opt/attacks.py --scene web_shell
```

The agent installs and enrols itself against the manager on first boot, so the stack takes a
couple of minutes to produce its first agent-side alerts. Endpoint protection on the host may
quarantine the web-shell payload in `docker/agent/attacks.py`; it is assembled at runtime to
avoid that, which is itself a sign the simulation is realistic enough to trip a real scanner.

The passwords in `docker/` are the defaults shipped with Wazuh's own single-node example and
are committed on purpose so the lab comes up in one command. They protect nothing but a
throwaway container; change them before pointing this at anything real. Credentials that
matter live in `.env`, which is not tracked.

The indexer needs `vm.max_map_count` at 262144. On Linux that is
`sudo sysctl -w vm.max_map_count=262144` on the host. On Docker Desktop it has to be set
inside the VM, and it resets when Docker restarts:

```bash
wsl -d docker-desktop -e sh -c 'echo 262144 > /proc/sys/vm/max_map_count'
```

## Running

Triage what is in the indexer now:

```bash
python -m soc.cli run --source wazuh --analyst claude
```

Follow the stack continuously:

```bash
python -m soc.cli watch --interval 60
```

Both write one markdown report per incident, a `summary.md` ranked by severity, and
`results.jsonl` into `out/`, and both accept `--sink` to push verdicts to the Wazuh indexer or a
webhook (see Integrations). Compliance and inventory alerts (`sca`, `rootcheck`,
`vulnerability-detector`, `syscollector`) are excluded by default: a fresh Wazuh manager
produces about two hundred of them at first boot and they are a posture report, not events.

## Integrations

Triage output does not only land in `out/`. Two sinks push it where a SOC would actually consume
it, wired in with `--sink` (repeatable) on `run` and `watch`.

The **indexer** sink writes each verdict back to the Wazuh indexer as a document in a
`soc-triage` index, keyed by incident id, so the model's conclusion sits alongside the alerts it
summarises and is queryable from the same dashboard:

```bash
python -m soc.cli run --source wazuh --analyst claude --sink indexer
```

Filtered to `triage.escalate: true`, the `soc-triage` index becomes the escalation queue,
each incident carrying the model's verdict, severity, and narrative as columns an analyst can
sort and search inside the SIEM's own UI rather than a text file (screenshot in
[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md)).

The **webhook** sink posts escalations to a Slack-compatible URL. Only incidents the analyst
escalated are sent, so the channel is a queue of things a human should look at rather than a
copy of every alert. Each post carries a rendered `text` field and the full structured verdict
under `soc_triage` for downstream automation:

```bash
SOC_WEBHOOK_URL=https://hooks.slack.com/services/...   python -m soc.cli watch --analyst claude --sink webhook --sink indexer
```

A sink that fails is logged and skipped, never allowed to drop a triage result. New sinks
implement one `emit(result)` method behind `soc/sinks/base.py`, the same shape as the alert
sources.

## Evaluation

`eval/alerts.jsonl` is 93 Wazuh-shaped alerts forming 40 labelled cases: 16 true positives, 16
false positives, and 8 genuinely ambiguous cases where the honest verdict is `inconclusive`
with an escalation. The true positives span credential access, web shells, cron and systemd
persistence, reverse shells, `/etc/shadow` reads, log tampering, DNS tunnelling, ransomware-style
mass encryption, VPN and mail abuse, and a sudoers backdoor. The false positives are the things
that look identical to a threshold but are not attacks: package upgrades and removals, certbot
renewals, logrotate, config-management pushes, developer git activity, CI image churn, a
crash-looping service, monitoring probes. The ambiguous cases are the ones a real analyst
escalates without being sure: an off-hours database dump, a dormant account waking up, a login
from a new country, a lone binary changing with no package to explain it.

```bash
python -m soc.cli eval --analyst claude
```

```bash
python -m soc.cli eval --analyst rules
```

The corpus is regenerated from `eval/make.py`, which holds the alerts and the labels together
so a case and its ground truth cannot drift apart. CI regenerates it on every push and fails if
the committed copy differs.

### Metrics

Escalation precision and recall matter most: a missed escalation is an incident nobody looks
at, a false one is analyst time. Alongside those the harness scores verdict accuracy, severity
(exact and within one band), micro-averaged ATT&CK technique precision and recall, and a Brier
score over the model's stated confidence, which catches an analyst that is right often but
certain always. It also reports correlation purity, the fraction of incidents whose alerts all
belong to one case, so a correlation bug cannot hide inside a triage score.

Every headline metric carries a 95% bootstrap interval, and `soc compare` runs a paired
bootstrap between two scored runs. Forty cases is still small, so a difference smaller than the
interval is not a finding, and the sections below only claim what clears it.

### Results

`--analyst rules` is the baseline: severity from Wazuh rule level, escalation above level 10,
techniques copied from whatever the firing rules asserted. It exists to be beaten. Both models
run the same playbook (`soc/playbook.md`); Opus adds nothing to the prompt that Haiku does not
get.

| metric | rules baseline | haiku 4.5 | opus 5 |
| --- | --- | --- | --- |
| escalation F1 | 0.650<br>[0.44, 0.81] | 0.870<br>[0.74, 0.96] | 0.980<br>[0.93, 1.00] |
| escalation misses | 11 | 4 | 0 |
| escalation false alarms | 3 | 2 | 1 |
| verdict accuracy | 0.475<br>[0.33, 0.62] | 0.850<br>[0.72, 0.95] | 0.900<br>[0.80, 0.97] |
| severity exact | 0.500<br>[0.35, 0.65] | 0.575<br>[0.42, 0.72] | 0.725<br>[0.57, 0.85] |
| severity within one band | 0.650 | 0.850 | 1.000 |
| technique F1 | 0.959<br>[0.90, 1.00] | 0.817<br>[0.70, 0.91] | 0.623<br>[0.51, 0.73] |
| Brier | 0.250<br>[0.25, 0.25] | 0.139<br>[0.06, 0.23] | 0.085<br>[0.05, 0.13] |
| cost per incident | $0.000 | $0.006 | $0.049 |
| latency p50 | 0 ms | 10,230 ms | 28,523 ms |

Square brackets are 95% bootstrap intervals over the forty cases. Correlation purity is 1.000
for all three by construction: correlation runs before any analyst is called.

### What survives the intervals

A point estimate on forty cases still moves if a couple of incidents change, so every claim
here is a **paired bootstrap**: resample the cases, rerun both analysts on the same resample,
and check whether the difference clears zero.

```bash
python -m soc.cli compare eval/scores-rules.json eval/scores.json
```

**Both models beat the threshold baseline, and now the corpus can prove it.** Against the rules
baseline, Haiku separates on escalation F1 (+0.22), verdict accuracy (+0.38), and Brier
(-0.11); Opus separates on the same three by more. This is the result the project was built to
test, and on the earlier 14-case corpus none of it cleared the intervals. The difference is
sample size, not a change to the models: a threshold cannot tell a package upgrade from an
attacker, so it sits at 0.475 verdict accuracy and reports a constant 0.5 confidence, which is
exactly what its Brier score of 0.250 measures.

**Opus beats Haiku on one thing: the escalation gate.** Escalation F1 goes 0.870 to 0.980,
and the paired interval [+0.005, +0.234] clears zero. Opus misses none of the 24 cases that
should escalate and raises one false alarm; Haiku misses four. On verdict accuracy, severity,
and Brier the two models are inside each other's noise. So the case for paying roughly eight
times as much per incident is specifically that it does not drop incidents, not that it
understands them better across the board.

**Neither model matches the baseline's technique score, and that one is the metric's fault.**
Technique F1 is 0.959 for the baseline against 0.817 for Haiku and 0.623 for Opus, and the gap
is statistically clear. But recall runs the other way: Opus finds 0.917 of the labelled
techniques, more than the baseline in absolute terms. It loses on precision because it adds
techniques the labels do not carry, and most of the additions are defensible, `T1595 Active
Scanning` on a 404 sweep, `T1005 Data from Local System` on a `mysqldump --all-databases`. The
labels omit those because they were written to a convention: minimal sets on true positives,
empty sets on false positives even when a technique was observed. **So `technique_f1` measures
agreement with that convention, not correctness**, and a bigger, more thorough model is
penalised precisely for being more thorough. The honest fix is multi-annotator labels or credit
for defensible supersets, and neither is in this repo.

**Severity is the one place the corpus still cannot separate the models from the baseline.**
Exact-severity deltas against the baseline overlap zero for both. Opus reaches 0.725 and lands
every case within one band, which is real improvement, but not enough of it to clear the
interval at this sample size.

## Cost

Opus costs about 8x per incident, $0.049 against $0.006, and roughly 3x the latency, 29 seconds
against 10. The corpus establishes one thing it buys: a near-perfect escalation gate. For a
queue where a missed escalation is the expensive failure, that is the trade most teams would
take. For bulk noise-tuning where the usual answer is "this is fine," Haiku already beats the
baseline decisively at a tenth of the price. The full runs cost about $0.25 (Haiku) and $2.00
(Opus).

Per-case detail lands in the scores file, showing exactly which cases each analyst got wrong
and what it said. Committed runs: `eval/scores-rules.json`, `eval/scores.json` (Haiku), and
`eval/scores-opus.json` (Opus 5), all on the current 40-case corpus.

## External validation

The single-annotator problem has a real fix: score against labels other people wrote. Two public
datasets were tried, and together they say more than either would alone.

### AIT: real Wazuh alerts, external labels

The [AIT Alert Data Set](https://zenodo.org/record/8263181) is native Wazuh alerts from eight
published testbeds at the Austrian Institute of Technology. Each testbed ran one real kill chain
(network and service scans, WordPress and directory brute-forcing, a web shell, password
cracking, a reverse shell, privilege escalation, service stop, DNS exfiltration) at documented
UTC times, so every alert can be labelled attack or benign from the schedule the authors
published. Unlike GUIDE the content is readable: rule descriptions, source IPs, and hosts are
intact. `soc/ait.py` builds one incident per attack phase that Wazuh actually flagged and
samples benign windows for the negatives, balanced so the majority-class floor is 0.5.

```bash
python -m soc.cli ait --analyst claude
```

On 32 balanced incidents of real Wazuh alerts labelled by AIT's schedule:

| metric | rules baseline | haiku 4.5 |
| --- | --- | --- |
| verdict accuracy | 0.344 [0.19, 0.53] | 0.625 [0.44, 0.78] |
| escalation F1 | 0.647 | 0.667 |
| escalation precision | 0.611 | 1.000 |
| escalation recall | 0.688 | 0.500 |
| Brier | 0.250 | 0.203 |

The model beats both the 0.5 majority floor and the rule-level baseline on verdict accuracy,
against labels it never saw and content from someone else's lab. The shape of the result is the
honest part. Escalation precision is 1.000: all sixteen benign windows were correctly left
alone, so the model never cried wolf on real background traffic. Recall is 0.500: it caught the
web attacks and scans that left a clear trace and missed the phases where host-based Wazuh emits
only generic "IDS event" alerts that genuinely do not distinguish an attack from noise. That is
a detection-coverage limit, not a triage failure, and it is visible because the labels come from
ground truth rather than from the alerts themselves.

The paired bootstrap puts the verdict-accuracy gain over the baseline at +0.281 with the
interval just touching zero at this sample size, so the effect is large but not separated on 32
cases. It points the same direction as the lab corpus, on data nobody in this project labelled.

### GUIDE: what anonymization costs

Microsoft's [GUIDE dataset](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction)
is 1M incidents graded by real customer analysts, which is a stronger label source, but it is
anonymized: alert titles, hosts, IPs, and usernames are all integer hashes. Only the category,
the ATT&CK technique, and the entity type survive. On 45 incidents, Haiku returned `inconclusive`
on 43 and was right on the 2 it committed to.

That is the correct behaviour, not a failure. With the deciding evidence hashed away, an honest
triage says "I cannot call this, send it to a human", which is what the playbook instructs.
Escalation recall was 1.000, so every real incident was still caught, while the model declined
to invent verdicts it could not support. GUIDE therefore validates calibration under
distribution shift rather than verdict accuracy: handed data far outside its lab corpus and
stripped of readable content, the model fails safe instead of hallucinating. A system that
returned confident guesses on those features would score higher on paper and be worse in
practice.

Both adapters and their commands (`soc ait`, `soc guide`) are in the repo, so either check
reruns against the full datasets. Neither dataset carries a severity or an `inconclusive` grade,
so both validate the verdict and escalation axes, not severity.

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

Forty cases is still a small corpus, and I wrote both the alerts and the labels, so the lab
scoreboard measures agreement with one analyst's judgement rather than ground truth. That is why
the External validation section scores the same pipeline against two public datasets nobody in
this project labelled: on AIT's real Wazuh alerts the model beats the baseline on labels it
never saw, and on GUIDE's anonymized data it fails safe rather than guessing. Expanding the lab
corpus from fourteen to forty cases roughly halved the intervals and turned the headline result,
that the models beat the threshold baseline, from "cannot tell" into an established finding; it
did not make the lab corpus representative, which is what the external datasets are for. Treat the numbers as a regression harness for changes to
the prompt, model, or enrichment, not as evidence about production performance. Feeding it real
labelled alerts is the obvious next step and nothing in the pipeline needs to change to do it.

Single annotator is the harder half of that problem, and there is a partial check for it in the
repo. `soc agreement` treats a model's independent verdicts as a second annotator and reports
inter-annotator agreement against the hand labels:

```bash
python -m soc.cli agreement
```

Opus, which never saw the labels, agrees with them on verdict at Cohen's κ = 0.85 (0.90 raw)
and on the escalate decision at κ = 0.95. That is "almost perfect" agreement by the usual
reading, which is some evidence the labels are not arbitrary. The four cases where they
disagree are all on the `inconclusive` boundary, exactly where a real analyst would also
hesitate:

| case | my label | Opus |
| --- | --- | --- |
| `vpn_bruteforce_success` | true_positive | inconclusive |
| `mail_relay_abuse` | true_positive | inconclusive |
| `service_crashloop` | false_positive | inconclusive |
| `encoded_command` | inconclusive | true_positive |

A model is not a second human and this does not remove the bias, since I both wrote the labels
and chose the model. But it names the four cases a second human should adjudicate first, which
is more useful than asserting the single annotator was right. Two independent human annotators,
with disagreements resolved in the open, remain the real fix.

Each analyst was run once per configuration, so run-to-run variance is unmeasured and is not
in the intervals. The bootstrap covers which cases are in the corpus, not whether the model
would answer the same way twice.

The `victim` container runs a real Wazuh agent, and the attack scenes perform the actions
rather than describing them: they create files in a monitored web root, append a UID-0 line to
`/etc/passwd`, drop an SSH key, and rewrite a crontab. The agent's own syscheck and rootcheck
modules detect those, so file-integrity monitoring is exercised end to end (32 "Integrity
checksum changed" and 26 "File added" alerts in a representative run, all tagged `victim01`).
Brute-force and web scenes drive a real `sshd` and write framed syslog into a shared volume the
manager reads. The one thing still simulated is the network origin: the SSH attempts come from
loopback with spoofed source addresses in the log line, not from a separate attacker host.
