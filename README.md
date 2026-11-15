<p align="center">
  <a href="https://chris91ss.github.io/ai4ci-agentic-soc/"><img src="web/public/social.png" width="857" alt="Agentic SOC: a local-LLM analyst that investigates, contains and shows its evidence, beside an incident the agent contained: risk 0.95, alerts from three detectors, and the attacker's techniques"></a>
</p>

<p align="center">
  <a href="https://github.com/Chris91ss/ai4ci-agentic-soc/actions/workflows/ci.yml"><img src="https://github.com/Chris91ss/ai4ci-agentic-soc/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://chris91ss.github.io/ai4ci-agentic-soc/"><img src="https://github.com/Chris91ss/ai4ci-agentic-soc/actions/workflows/pages.yml/badge.svg?branch=main" alt="Live demo"></a>
  <img src="https://img.shields.io/badge/python-3.12-blue.svg" alt="Python 3.12">
  <img src="https://img.shields.io/badge/Next.js-16-black.svg" alt="Next.js 16">
  <img src="https://img.shields.io/badge/LLM-gpt--oss%3A20b%20on%20Ollama-6e56cf.svg" alt="gpt-oss:20b on Ollama">
  <img src="https://img.shields.io/badge/agent%20tools-MCP-0a7ea4.svg" alt="Agent tools over MCP">
</p>

Agentic SOC is a Security Operations Center for a simulated company of 200 people and 250 hosts. A seeded simulator emits three asynchronous streams, sign-ins, network flows and endpoint processes, and hides a multi-stage intrusion among benign look-alikes. Three detectors score the streams online, a correlation engine links their alerts into incidents, and a triage agent running locally on gpt-oss:20b investigates the risky ones through seven MCP tools, decides a verdict and contains the attack. Its actions go back into the simulator, where blocked addresses, revoked sessions and isolated hosts stall the attacker. Over ten seeded 48-hour runs the agent's reference analyst stopped every intrusion before exfiltration without a single false containment, where playbooks on the same detectors made 46. An AI4CI course project; the design is in the [RFC](docs/rfc/0001-agentic-soc.md).

<p align="center">
  <a href="https://chris91ss.github.io/ai4ci-agentic-soc/"><img src="docs/assets/demo.gif" width="857" alt="The live demo: the overview of a recorded run replaying, the incident queue, an incident the agent contained with its alert lanes, the agent's investigation over MCP tool by tool, the evidence behind the verdict, and the evaluation of the agent against the baselines"></a>
</p>
<p align="center"><em>The <a href="https://chris91ss.github.io/ai4ci-agentic-soc/">live demo</a> on GitHub Pages: a recorded run, an incident the agent contained, its investigation, its evidence, and the evaluation.</em></p>

| 10/10 | 0 vs 46 | −81% | 4 h | 10.9× |
| :---: | :---: | :---: | :---: | :---: |
| intrusions stopped before exfiltration, over ten seeded runs | false containments: the agent against playbooks on the same detectors | alerts folded into incidents by correlation (182 → 30 a run) | from the move to remote work to the drift alarm (scenario S1) | event burst absorbed with the stream lag held at one minute (S2) |

## What's inside

| Part | What it does | How it is checked |
| --- | --- | --- |
| **[Simulated enterprise](#the-simulated-enterprise)** | 200 users and 250 hosts with roles, offices, schedules and network zones; three streams with their own rates, delivery delays, duplicates and malformed events; one ATT&CK campaign among benign look-alikes; containment applied back to the simulation | Unit tests of volumes, seasonality, determinism under a seed, and of how each containment changes what the simulator emits |
| **[Streaming and storage](#how-an-incident-is-handled)** | Redpanda topics, schema validation with a dead-letter topic, de-duplication, normalisation and enrichment; TimescaleDB as the hot store, a Parquet lake and DuckDB for the offline ETL | Unit tests, and integration tests against Redpanda and TimescaleDB |
| **[Detectors](#detectors)** | M1, Isolation Forests on sign-ins per account and per source address; M2, LightGBM on flows with beacon-periodicity features; M3, rarity of parent-child process pairs; event-time windows with watermarks; served over REST | Scored on held-out test weeks: PR-AUC, recall at 1% FPR, false positives per day, detection delay |
| **[Correlation and routing](#how-an-incident-is-handled)** | Alerts linked by user, host and address into risk-scored incidents; low-risk ones are logged, the rest go to the agent by priority, and to deterministic playbooks when it times out or its queue saturates | Unit tests, and the S2 load run |
| **[Triage agent](#the-triage-agent)** | gpt-oss:20b on Ollama in a ReAct loop over seven MCP tools, returning a JSON-schema decision; log fields reach it only as quoted data, dismissals must cite evidence, actions pass a policy gate, and an optional verifier vetoes actions its evidence does not justify | Tests with a planted prompt injection and malformed tool calls; three seeds on the local LLM |
| **[Evidence and feedback](#the-console)** | Every verdict stored with the events, detector scores, entity baselines and tool calls it cites, filterable by entity, stream, detector and time; analyst feedback feeds per-detector false-positive statistics | Tests that every cited item exists and that feedback reaches the statistics |
| **[Console](#the-console)** | Next.js 16 with Tabler icons, framer-motion and Recharts: overview, incident queue, timelines, agent trace, evidence, approvals, metrics with the drift monitor, the evaluation and the audit log; live over server-sent events, or a recorded run replayed as a static site | Lint and build in CI; this README's images are regenerated from the static build in headless Chrome |
| **[Evaluation](#results)** | `soc evaluate`: the detectors on held-out weeks, ten seeds of the agent against rules and against detectors with playbooks, paired Wilcoxon tests, S1 drift, S2 load, and the local LLM | The raw numbers and the report in [docs/evaluation](docs/evaluation/README.md) |

**Contents:** [Try it](#try-it) · [The console](#the-console) · [How an incident is handled](#how-an-incident-is-handled) · [The simulated enterprise](#the-simulated-enterprise) · [Detectors](#detectors) · [The triage agent](#the-triage-agent) · [Results](#results) · [Running it](#running-it) · [Layout](#repository-layout) · [Tests and CI](#tests-and-ci) · [Credits](#authors-and-credits)

## Try it

**[Open the live demo](https://chris91ss.github.io/ai4ci-agentic-soc/).** It replays a recorded 72-hour run of scenario S1: on the second day most of the company moves to remote work, the drift monitor alarms and M1 is retrained, and on the third day the intrusion begins. The replay plays the pipeline's log at 15 simulated minutes a second (pause, restart or speed it up in the top bar); every incident, the agent's investigation, the evidence, the metrics and the evaluation can be opened. Approvals and feedback are read-only in the demo. Press <kbd>⌘</kbd> <kbd>K</kbd> to search incidents and entities.

Or run the whole loop yourself, with the console attached to the live pipeline:

```bash
brew install libomp                    # macOS: LightGBM needs OpenMP
uv sync
uv run soc etl build                   # simulate the datasets into data/, about 7 minutes
uv run soc train                       # train M1-M3 into models/
uv run soc demo --speed 120            # simulator, pipeline, console API; attack at 1.5 h
cd web && npm install && npm run dev   # the console, on http://localhost:3000
```

The demo uses the scripted analyst; with [Ollama](https://ollama.com) and `ollama pull gpt-oss:20b`, `--llm ollama:gpt-oss:20b` puts the local model in its place, in `soc demo` as in `soc run`.

## The console

<p align="center">
  <img src="docs/assets/overview.png" width="857" alt="The overview of the recorded run: 545 thousand events, 251 alerts, 77 incidents and 5 containments, the stream health chart of sign-ins, flows and processes, the incident status donut, the highest-priority incidents, and the activity replay">
</p>

- **The overview** counts the run's events, alerts, incidents, containments and the agent's latency, charts the three streams as they were ingested, and replays the pipeline's activity: alerts, incidents, routing, decisions and actions, as they happened. The card at the foot of the sidebar says what is on screen, the live pipeline or a recorded run, how far its replay has got, and which agent decided.
- **The incident queue** ranks incidents by priority and risk, with the detectors, techniques and entities of each.

<p align="center">
  <img src="docs/assets/incident.png" width="857" alt="An incident the agent contained: INC-00055, priority 1, malicious with 96% confidence, risk 0.95; rare process launches and a network sweep from the foothold workstation, the ATT&CK techniques coloured by tactic, the users and hosts involved, and the alert lanes of M1, M2 and M3 over three hours with the agent's responses">
</p>

- **An incident** shows its risk and where it comes from, the ATT&CK techniques along the kill chain, every entity involved, and its alerts on one lane per detector, with the agent's responses beneath. Hovering an alert explains it; a click opens it with its top features.

<p align="center">
  <img src="docs/assets/trace.png" width="857" alt="The agent's trace for that incident: a malicious verdict that notes a prompt injection in the log data, the actions it took, isolating the workstation and blocking the attacker's address, the alerts it cited, and its nine ReAct steps over MCP, from get_incident to score_flows and get_entity_timeline">
</p>

- **The agent trace** shows each decision with its rationale, the actions it proposed and the evidence it cited, and every step of the investigation: which MCP tool it called, with which arguments, how long it took, and what came back. Here it also noticed the attacker's instruction to AI analysts, planted in a command line, and flagged it instead of obeying it.
- **The evidence** behind a verdict lists the triggering events, the detector scores with their top features, the baselines of the entities involved and the tool calls, each with the ID the agent cited, filterable by entity, stream, detector and time window, so a suspected false positive can be checked rather than taken on trust.
- **Response** holds the actions, with approve and reject for the high-impact ones in a live run, and the analyst's verdict, which feeds the per-detector false-positive statistics on the **Metrics** page, beside the drift monitor. The **Audit log** is hash-chained and can be verified from the console.

<table>
  <tr>
    <td width="50%"><img src="docs/assets/queue.png" alt="The incident queue of the recorded run: 20 incidents at risk 0.5 or more, the two contained P1 intrusions first, each with its status, the agent's verdict, its detectors, ATT&CK techniques, kill-chain progress, risk, time span and entities, with filters by status, risk and text"><br><b>The incident queue.</b> Every routed incident by priority and risk, with its status, verdict, detectors, techniques and entities.</td>
    <td width="50%"><img src="docs/assets/evidence.png" alt="The evidence behind the verdict on INC-00055: 244 items, alerts, events, baselines and tool calls, the 17 the agent cited starred, with filters by kind, stream, detector and entity"><br><b>Evidence.</b> The 244 items behind INC-00055, the 17 the agent cited starred, filterable by kind, stream, detector and entity.</td>
  </tr>
  <tr>
    <td><img src="docs/assets/entity.png" alt="The foothold workstation WS-0156: its owner, zone and criticality, the two incidents that involve it, the isolation taken on it, and its flows, sign-ins and processes over 24 hours"><br><b>An entity.</b> The foothold workstation: its owner and zone, its incidents, the isolation taken on it, and its timeline across the three streams.</td>
    <td><img src="docs/assets/actions.png" alt="The containment actions of the run: the workstation isolated and four attacker addresses blocked, each with its impact, who requested it, how the policy gate decided, and the rationale"><br><b>Actions.</b> Every containment the agent and the playbooks proposed, its impact, how the policy gate decided, and why.</td>
  </tr>
  <tr>
    <td><img src="docs/assets/audit.png" alt="The audit log: decisions, proposals and executions by the agent, the policy gate and the executor, each entry linked to the hash of the previous one, with the chain verified"><br><b>The audit log.</b> Every decision, proposal, approval and execution in a hash chain, verified in the page.</td>
    <td><img src="docs/assets/palette.png" alt="The command palette searching for WS-0156: the incidents that involve it, with priority and status, and the matching entities"><br><b>The command palette</b> (<kbd>⌘</kbd> <kbd>K</kbd>): any incident, entity or page, by name.</td>
  </tr>
  <tr>
    <td colspan="2"><img src="docs/assets/monitor.png" alt="The drift monitor: the largest PSI of M1's per-account and per-address features, hour by hour, crossing the 0.25 alarm line after the move to remote work, with the two alarms and two retrains marked and the most shifted features listed"><br><b>The drift monitor</b>, on the Metrics page: M1's features against its training data, hour by hour, with the alarms and retrains of scenario S1.</td>
  </tr>
</table>

## How an incident is handled

```mermaid
flowchart TB
    %% declared bottom-up so that the layout reads top-down
    subgraph response ["Response"]
        direction LR
        router{"<b>Risk router</b>"} -- "escalated" --> agent["<b>Triage agent</b><br/>gpt-oss:20b<br/>ReAct loop"]
        agent <-- "7 tools" --> mcp["<b>MCP server</b>"]
        mcp --> gate["<b>Policy gate</b><br/>evidence<br/>verifier"]
        router -- "agent slow or down" --> playbooks["<b>Playbooks</b>"]
        playbooks --> gate
        router -- "low risk" --> logged["Logged"]
    end
    subgraph pipeline ["Detection pipeline, in event time"]
        direction LR
        ingest["<b>Ingestion</b><br/>validate<br/>de-duplicate<br/>enrich"] --> windows["<b>Windows</b><br/>watermarks<br/>entity resolution"]
        windows --> detectors["<b>Detectors</b><br/>M1 · M2 · M3"] --> correlation["<b>Correlation</b><br/>risk-scored<br/>incidents"]
        ingest --> store[("<b>Hot store</b><br/>TimescaleDB<br/>Parquet lake")]
    end
    subgraph enterprise ["Simulated enterprise"]
        direction LR
        sim["<b>Simulator</b><br/>200 users<br/>250 hosts<br/>an intrusion"] -- "sign-ins · flows · processes" --> broker[("<b>Redpanda</b>")]
    end
    enterprise --> pipeline --> response
    response --> console["<b>Console</b><br/>evidence<br/>audit log"]
    response -- "revoke · disable<br/>isolate · block" --> enterprise
```

Every event carries its own time, and the pipeline works in event time: windows close when their watermark passes, so late, out-of-order and duplicated deliveries land where they belong. Entity resolution links the identifiers each stream uses for the same thing: an address is a host's DHCP or VPN lease at that moment, an account is a person. The correlation engine then links alerts that share a user, host or address within a time window, and scores each incident on the strength of its evidence, how many detectors corroborate it, how far along the kill chain it is, and what is at stake.

The agent's latency is charged in simulated time: while it investigates, the attack goes on. When its queue saturates or it stops answering, a circuit breaker hands incidents to the playbooks, which act on the same detectors without investigating. Executed actions are published on an `actions` topic, and the simulator applies them: a blocked address stops reaching the company, a revoked session has to sign in again, a disabled account cannot, and an isolated host stops emitting flows, so the campaign stalls or pivots.

## The simulated enterprise

The company has two offices in Romania, 200 employees with a workstation each, 50 servers (domain controllers, file, database, application, ERP, mail, backup, build, jump hosts and more), VPN and SaaS sign-ins, and, in scenario S1, a ZTNA egress for remote work. Benign activity follows diurnal and weekly cycles, with heavy-tailed flow sizes and the look-alikes that make detection hard: password typos, business travel and consumer VPNs, admin RDP sessions on patch night, nightly backups and archive jobs, Intune's encoded PowerShell.

The campaign is one ATT&CK-mapped intrusion ([`campaign.py`](src/agentic_soc/simulator/campaign.py)): a password spray against the VPN portal from rented servers, a VPN logon with a sprayed account through the MFA-less legacy endpoint and RDP to the victim's workstation, discovery, a PowerShell download cradle installing an implant that beacons to C2 with jitter, an LSASS dump that yields an administrator's account, lateral movement with PsExec and RDP to a file and a database server, collection with 7-Zip, and exfiltration over the C2 channel. It reacts to containment: blocked addresses make it rotate to spare infrastructure, a revoked session makes it switch to another sprayed account, a disabled account stops the steps that need it, and an isolated host loses its implant; with no way forward left, it stalls. The download cradle's command line and some of the spray's user agents carry an instruction to AI analysts to ignore the activity, to test indirect prompt injection.

Ground truth is kept for every event, the dataset plan of `soc etl build` splits training, validation and test weeks in time, and runs are deterministic under a seed. Scenario S1 ([`config/scenarios/s1-remote-work.yaml`](config/scenarios/s1-remote-work.yaml)) moves 80% of staff to remote work behind a ZTNA service on the second morning; S2 ([`config/scenarios/s2-burst.yaml`](config/scenarios/s2-burst.yaml)) adds an hour with ten times the event rate during the intrusion.

## Detectors

| Detector | Model | Features | Test weeks: PR-AUC | Recall at 1% FPR | False positives per day |
| --- | --- | --- | ---: | ---: | ---: |
| M1, per account | Isolation Forest | New networks, countries and devices, unusual hours, failures, MFA, against the account's baseline | 0.996 | 0.994 | 16.0 |
| M1, per source address | Isolation Forest | Accounts tried, unknown usernames, failures, successes after failing, hosting, anonymiser and foreign sources | 0.979 | 1.000 | 4.3 |
| M2 | LightGBM | Volume, ports and direction of a host's flows, the networks they reach, fan-out, and the regularity of repeated connections (beacons) | 0.999 | 1.000 | 0.8 |
| M3 | Parent-child n-gram rarity | Process pairs rare among the host's peers, encoded commands, living-off-the-land binaries | 0.749 | 1.000 | 4.5 |

They score event-time windows per entity (fifteen minutes for sign-ins and flows, ten for processes), each at a threshold calibrated on the validation weeks, and explain each alert by its top features. `soc serve-detectors` serves them over REST; the agent reaches them through the MCP scoring tools.

<p align="center">
  <img src="docs/assets/detectors.png" width="857" alt="The detectors on the evaluation page: PR-AUC, ROC-AUC, recall and precision of M1 per account, M1 per address, M2 and M3, their ranking and operating points, and the recall of each detector at each attack stage with its median detection delay">
</p>

## The triage agent

The agent runs on gpt-oss:20b through Ollama, so no telemetry leaves the machine. Each incident it is given starts a ReAct loop over seven MCP tools:

| Tool | What it returns |
| --- | --- |
| `get_incident` | Risk and its breakdown, detectors, techniques, entities, the strongest alert of every kind, actions already taken |
| `get_entity_timeline` | The events of a user, host or address in a time window, across the three streams |
| `get_asset_context` | Role, criticality and owner of a host; usual countries, hours and devices of an account; GeoIP, network category and the recent lease of an address |
| `score_signins`, `score_flows`, `score_processes` | M1, M2 or M3 run on an entity's windows, with each alert's top features |
| `propose_action` | A containment action through the policy gate |

It ends with a decision validated against a JSON Schema: verdict, ATT&CK techniques, cited evidence, actions and confidence. The guardrails come from the problems the RFC set out (P5):

- **Untrusted data is quoted.** Every log field reaches the model wrapped as untrusted data, and text that looks like an instruction is flagged, so a command line cannot steer it.
- **Dismissals must cite evidence,** and a high-risk incident it dismisses is escalated to an analyst instead.
- **No hallucinated evidence.** Every evidence ID and action target in a decision must have appeared in a tool result of the conversation; an invalid decision gets two repair attempts with schema-constrained output.
- **Actions pass a policy gate** with an allow-list and impact levels: revoking sessions and blocking an external address run at once; disabling an account and isolating a host wait for an analyst's approval, auto-approved in unattended evaluation runs. Only an analyst may isolate protected infrastructure (domain controllers, VPN, proxy, EDR, backup, mail), and internal, office and major providers' addresses and service accounts are refused.
- **The evidence verifier** (`--verifier`), the RFC's stretch goal, checks each action against the alerts the agent cited before it runs: a blocked address must have sprayed, signed in as a stolen account or be the far end of C2 or exfiltration, and not be a corporate or cloud egress; an account must have been used from attacker-like infrastructure or have run attacker tooling; an isolated host must show late-stage activity or C2. It is deterministic and reads only the cited alerts, never the rationale.
- **Malformed tool calls** are rejected by the MCP layer with the reason, and the model tries again.

The evaluation also uses a scripted analyst: a deterministic expert system that speaks the same chat protocol, calls the same tools and sees only their results, never the ground truth. It is the agent's reference policy, so that ten seeds of three configurations run in minutes rather than hours, and it is what the local LLM is compared against.

## Results

The report with every table and the raw numbers is in [docs/evaluation](docs/evaluation/README.md), and on the console's Evaluation page.

<p align="center">
  <img src="docs/assets/evaluation.png" width="857" alt="The evaluation page: over ten seeds each, the agent stopped 10 of 10 intrusions with 0 false containments, detectors with playbooks 10 of 10 with 46, and Sigma-style rules 10 of 10 with 33; median times to detect and contain, exfiltrated data, incidents and actions per run">
</p>

**End to end: ten seeds of 48 hours, the same attacks for every configuration.** Every configuration stopped every intrusion before exfiltration, at very different costs:

| | Agent (scripted analyst) | Detectors + playbooks | Rules + playbooks |
| --- | --- | --- | --- |
| Stopped before exfiltration | 10/10 | 10/10 | 10/10 |
| False containments, all runs | **0** | 46 | 33 |
| Runs without a false containment | **10/10** | 1/10 | 0/10 |
| Time to contain, median | 16 min | 12 min | 15 min |
| Incidents per run (alerts → incidents) | 30 (−81%) | 31 (−83%) | 113 (−67%) |

The agent's 73 containment actions all hit the attacker (action correctness 1.00; verdict precision 1.00, recall 0.68, F1 0.81; the attack incidents it did not call malicious it left "suspicious" for an analyst; no invalid tool calls). Compared on the same seeds with Wilcoxon signed-rank tests, it makes fewer false containments than the detectors' playbooks (median −3.5 per run, p = 0.004) and the rules (−3.0, p = 0.002) and raises 83 fewer incidents per run than the rules (p = 0.002), but contains about 3 minutes later than the playbooks (p = 0.002): it investigates before acting, and its latency, about 2 minutes per triage, is charged in simulated time while the attack goes on. In exchange the attacker usually got one kill-chain stage further (median +1 against both baselines, not significant), typically to its C2 beacon, but was stopped before credential access in 9 of 10 runs and before collection in all.

**Local LLM: gpt-oss:20b through Ollama, three seeds.** Every intrusion was still stopped before exfiltration, contained in about 15 minutes (median), as by the scripted analyst on the same seeds. It is a noisier analyst: 18% of its tool calls were malformed and rejected by the MCP layer, its verdict precision was 0.57 (recall 0.80), and in one run it revoked the sessions of two accounts outside the attack (action correctness 0.92). With the evidence verifier the same seeds produced one false containment instead of two (action correctness 0.93), at the same time to contain.

<p align="center">
  <img src="docs/assets/llm.png" width="857" alt="The local LLM on the evaluation page: the scripted analyst, gpt-oss:20b, and gpt-oss:20b with the evidence verifier, each stopping 3 of 3 intrusions, with 0, 2 and 1 false containments, their verdict quality, invalid tool calls and latency">
</p>

<p align="center">
  <img src="docs/assets/drift.png" width="857" alt="Scenario S1 on seed 301: false M1 alerts per hour around the move to remote work; both runs jump to about 28 an hour at the shift, the drift monitor alarms 4 hours later, and after the retrains the run with retraining stays near zero while the one without climbs back above 20 the next morning">
</p>

**S1, drift: three seeds of 72 hours.** When most staff move to remote work through a new ZTNA egress, the drift monitor alarms 4 hours after the shift (M1's per-address features, PSI above 1). False M1 alerts jump from 0.5–0.7 an hour to about 14. Without retraining they stay at 8–10 an hour the next day, 7–12 times the pre-shift busy-hour rate, and never recover within the run; with retraining, 7 and 35 hours after the shift, they fall to 1.8–2.7 an hour, and M1 is back within twice its pre-shift rate by the next morning in 2 of 3 runs. The agent checks where a suspicious sign-in came from before revoking sessions, so in neither configuration did the look-alike sign-ins through the company's own ZTNA egress lead to a false containment, and every intrusion was stopped before exfiltration.

**S2, high load: Redpanda at 60 times real time.** A one-hour burst raised the event rate 10.9-fold, to about 3,000 events a second. The pipeline kept up: the p95 stream lag stayed at the simulator's one-minute tick, and the consumer lag peaked at about 3,200 messages, around one second of input. With the local LLM four times slower during the burst, 4 of 15 triages timed out, the circuit breaker opened once and the playbooks decided those incidents; the intrusion was stopped before credential access in both runs.

<p align="center">
  <img src="docs/assets/load.png" width="857" alt="Scenario S2 with the local LLM four times slower during the burst: a 10.9-fold event rate, a one-minute p95 stream lag, a consumer lag of at most 3,228 messages, 4 agent timeouts and one breaker trip; the stream lag and consumer lag over six hours with the burst shaded, and the lag per phase">
</p>

**What the numbers leave open.** Everything runs on one simulated company and one campaign, whose look-alikes were written by the same team that wrote the detectors; the default calibration of benign activity is hand-set priors shaped like the LANL data, and `soc calibrate` refits it from the public datasets, which are not redistributed here. The ten-seed comparison uses the scripted analyst; the local LLM ran on three seeds, too few to test, and on a laptop GPU, so its latency, not its reasoning alone, shapes the time to contain. The detectors' test weeks come from the same simulator as their training weeks.

## Running it

Requirements: Python 3.12 and [uv](https://docs.astral.sh/uv/), Node 20 or later for the console, and Docker for the live stack (`make up` starts Redpanda and TimescaleDB). On macOS, LightGBM needs OpenMP: `brew install libomp`.

```bash
uv run soc etl build                                 # simulate the datasets into data/
uv run soc train                                     # M1-M3 into the registry, models/
uv run soc run                                       # closed loop, the scripted analyst
uv run soc run --llm ollama:gpt-oss:20b              # ... with the agent on the local LLM
uv run soc run --llm ollama:gpt-oss:20b --verifier   # ... and the evidence verifier
uv run soc run --mode detectors                      # baseline: detectors + playbooks
uv run soc run --mode rules                          # baseline: rules + playbooks

# scenario S1: 72 hours, M1 retrained when the drift monitor alarms
uv run soc run --scenario config/scenarios/s1-remote-work.yaml --hours 72 --retrain-on-drift
```

`soc run` writes `data/soc-runs/<mode>-seed<seed>/`: the SOC store (`soc.db`), the run summary, the pipeline log and the simulator's ground truth. High-impact actions are auto-approved in these unattended runs; `--approval-delay` models an analyst's response time instead.

The console API (FastAPI) serves a recorded run read-only, or a live demo in which the simulator, the pipeline and the API share one process and an analyst approves or rejects held actions. `soc export` writes a recorded run as the static files the GitHub Pages demo replays; [web/README.md](web/README.md) has the details.

```bash
uv run soc api --run data/soc-runs/agent-seed201           # a recorded run, read-only
uv run soc demo --speed 120                                # live, with approvals
uv run soc export --run data/soc-runs/s1-retrain-seed301   # into web/public/data
```

Both serve the API on `http://127.0.0.1:8000/api`. Endpoints: `/api/health`, `/api/stream-health`, `/api/incidents[/{id}[/evidence|/trace|/feedback]]`, `/api/entities/{entity}[/timeline]`, `/api/actions[/{id}/approve|/reject]`, `/api/metrics`, `/api/audit[/verify]`, `/api/evaluation`, `/api/log` and `/api/events` (server-sent events of the live pipeline).

Live mode streams through Redpanda, with the simulator and the pipeline in separate processes. The pipeline stores into `$SOC_DB`: set it to the TimescaleDB that `make up` starts on `localhost:15432` (the Makefile's `test-integration` has the URL), or leave it unset for SQLite.

```bash
make up
uv run soc simulate --broker kafka://localhost:19092 --speed 60 --out data/runs/live
uv run soc pipeline --inventory data/runs/live/inventory.json --api-port 8000
```

`soc evaluate` runs the experiments of the RFC's evaluation plan and merges each into [docs/evaluation](docs/evaluation/README.md):

```bash
uv run soc evaluate models                           # M1-M3 on the held-out test weeks
uv run soc evaluate e2e --seeds 401-410              # agent vs both baselines
uv run soc evaluate llm --seeds 401-403              # the agent on gpt-oss:20b
uv run soc evaluate llm --seeds 401-403 --verifier   # ... with the evidence verifier
uv run soc evaluate s1 --seeds 301-303               # S1, with and without retraining
uv run soc evaluate s2                               # S2 burst through Redpanda (make up)
```

End-to-end runs are 48-hour closed loops on successive weeks. Each reports the time to detect and to contain from the start of the intrusion, how far the attacker got, exfiltrated data, false containments (executed actions on anything outside the attack, or on a future victim before it), the alert-to-incident reduction and the agent's verdict quality.

## Repository layout

```text
.
├── .github/workflows/
│   ├── ci.yml                  # Python lint and tests, the console's lint and build
│   └── pages.yml               # the static console, deployed to GitHub Pages
├── src/agentic_soc/
│   ├── schemas/                # event schemas (OCSF-inspired) and the agent's decision
│   ├── simulator/              # enterprise, benign activity, campaign, containment
│   ├── broker/                 # Kafka (Redpanda) and an in-memory broker for tests
│   ├── ingestion/              # validation, dead letters, de-duplication, enrichment
│   ├── storage/                # TimescaleDB/SQLite hot store, Parquet lake, audit log
│   ├── etl/                    # DuckDB: lake, analytics, time-split datasets, replays
│   ├── features/               # event-time windows, watermarks, entity resolution
│   ├── detectors/              # M1-M3, the model registry and the REST scoring service
│   ├── drift/                  # PSI and KS references, the drift monitor, retraining M1
│   ├── correlation/            # incidents and their risk
│   ├── routing/                # the risk router, the circuit breaker, the playbooks
│   ├── rules/                  # the Sigma-style rules baseline
│   ├── actions/                # the action manager and the policy gate
│   ├── mcp_server/             # the SOC tools and untrusted-data quoting
│   ├── agent/                  # ReAct agent, Ollama client, scripted analyst, verifier
│   ├── evidence/               # evidence bundles and analyst feedback
│   ├── pipeline/               # the pipeline, in virtual time or live on threads
│   ├── api/                    # the console API, server-sent events, the static export
│   ├── evaluation/             # metrics, end to end, model level, S2 load, the report
│   └── cli.py                  # soc
├── web/                        # the Next.js console and the README's capture script
├── config/                     # the simulator, its calibration, scenarios S1 and S2
├── deploy/docker-compose.yml   # Redpanda and TimescaleDB
├── docs/
│   ├── rfc/                    # RFC-0001 and its architecture figure
│   ├── evaluation/             # results.json and the report
│   └── assets/                 # this README's images
└── tests/                      # unit tests, integration tests against the live stack
```

## Tests and CI

```bash
make lint                                 # ruff check and format
make test                                 # unit tests, about 2 minutes
make up && make test-integration          # against Redpanda and TimescaleDB
SOC_TEST_LLM=1 uv run pytest -m llm       # the agent on gpt-oss:20b, served by Ollama
cd web && npm run lint && npm run build   # the console
```

| Workflow | Job | What it checks |
| --- | --- | --- |
| CI | Python | `uv sync --frozen`, ruff, and the 182 unit tests: the simulator, ingestion, storage, features, the detectors, correlation, routing, the policy gate, MCP tools and quoting, the agent with a planted prompt injection, the pipeline in a closed loop and live on a broker, drift, evidence, the API, the static export and the evaluation |
| CI | Web | `npm ci`, ESLint and the production build of the console |
| Pages | Build and deploy | The console exported as a static site with the recorded run, then deployed to GitHub Pages |

`node web/scripts/capture.mjs` regenerates this README's images, the demo GIF and the link preview from the static build.

## Authors and credits

Adi, Cristi and Dragos, for the AI4CI course; the design is [RFC-0001](docs/rfc/0001-agentic-soc.md).

- The activity model is shaped after the [LANL Comprehensive, Multi-Source Cyber-Security Events](https://csr.lanl.gov/data/cyber1/) (Kent, 2015) and the [Login Data Set for Risk-Based Authentication](https://doi.org/10.5281/zenodo.6782156) (Wiefling et al., 2022); neither is redistributed.
- The agent runs [gpt-oss-20b](https://huggingface.co/openai/gpt-oss-20b) (Apache 2.0) on [Ollama](https://ollama.com), with tools served by the [Model Context Protocol](https://modelcontextprotocol.io) Python SDK.
- The pipeline uses [Redpanda](https://redpanda.com), [TimescaleDB](https://www.timescale.com), [DuckDB](https://duckdb.org), [Apache Arrow](https://arrow.apache.org), [scikit-learn](https://scikit-learn.org), [LightGBM](https://lightgbm.readthedocs.io), [FastAPI](https://fastapi.tiangolo.com) and [SQLAlchemy](https://www.sqlalchemy.org).
- The console uses [Next.js](https://nextjs.org), [Tailwind CSS](https://tailwindcss.com), [Tabler icons](https://tabler.io/icons), [framer-motion](https://motion.dev), [TanStack Query](https://tanstack.com/query), [Recharts](https://recharts.org), [Radix UI](https://www.radix-ui.com), [cmdk](https://cmdk.paco.me) and [sonner](https://sonner.emilkowal.ski).
