# Milestone 2: architecture and implementation plan

**Agentic SOC for a simulated enterprise** · Adi, Cristi, Dragos · AI4CI · 19 November 2026

The proposal is [RFC-0001](../rfc/0001-agentic-soc.md) (Milestone 1). This document covers Milestone 2: the system's architecture and the reasons for it, its data and AI modules, how models are trained and used, how the system is evaluated, and the plan up to the final presentation in week 14 (11–17 January 2027).

> [!NOTE]
> **Where the project stands.** The architecture below is implemented and runs end to end. The code is in this repository (commits of 13–15 November), CI runs the 182 unit tests and builds the console on every push, a recorded run is [live on GitHub Pages](https://chris91ss.github.io/ai4ci-agentic-soc/), and the first results are in [docs/evaluation](../evaluation/README.md).

**Contents:** [1. Problem and industrial context](#1-problem-and-industrial-context) · [2. Data sources](#2-data-sources)

## 1. Problem and industrial context

A security operations centre (SOC) protects a company whose identity provider, network and endpoints are connected systems, run by different teams and logged separately: who signs in from where, which hosts exchange how much data, and what runs on each host. An intrusion leaves weak traces in all three, minutes or hours apart, and rarely a conclusive one in any. Analysts receive thousands of alerts a day and ignore most of them, and breaches still take months to identify and contain ([RFC §1](../rfc/0001-agentic-soc.md#1-project-description)). The decision that matters is made per incident: is this an attack, and what should be contained now, without locking out the business?

The company is simulated. Example Corp has 200 employees, each with a workstation, in two offices in Cluj-Napoca and Bucharest, and 50 servers: domain controllers, file, database, application, ERP, mail, backup, build and jump hosts, and a DMZ with web servers, proxies and the VPN gateway. Staff sign in to the VPN and to SaaS applications through single sign-on. A seeded simulator stands in for the company: it emits its telemetry, hides one ATT&CK-mapped intrusion among benign activity, and applies the SOC's containment. A decision therefore has consequences (the attacker pivots or stalls), and every result has ground truth.

### Stakeholders

| Stakeholder | What they need | What the system gives them |
| --- | --- | --- |
| SOC analysts (tier 1 and 2) | Fewer, better-founded alerts, and evidence they can check | Incidents instead of alerts (81% fewer), each with the agent's verdict, its investigation and the evidence it cited; approve or reject high-impact actions; label verdicts |
| Incident responders, SOC lead | Containment before data leaves, and a record of what was done and why | Containment within minutes of detection; a hash-chained audit log of every decision, proposal, approval and execution |
| Employees and IT operations | Not to be locked out by mistake | False containment is the main cost metric; high-impact actions wait for an analyst; only an analyst may isolate core servers, and office and major providers' addresses cannot be blocked |
| Detection and ML engineers | To know when a model degrades, and to roll back | A drift monitor with alarms and retraining; a versioned model registry with promotion and rollback |
| CISO and compliance | Lower risk, without sending telemetry to third parties | A local LLM, so no log data leaves the company; every action traceable to its evidence |

### Decisions the system supports

1. **Is this window of activity anomalous?** Detectors M1–M3 score each entity's window of events, thousands an hour, and raise alerts.
2. **Which alerts belong together, and how risky are they?** Correlation links alerts by user, host and address into incidents with a risk score.
3. **Does this incident need investigating now?** The risk router logs it, queues it for the agent by priority, or hands it to a playbook when the agent is slow or down.
4. **Is it an attack, and what should be contained?** The triage agent returns a verdict, ATT&CK techniques, the evidence it relied on and up to three containment actions: revoke sessions, disable an account, isolate a host or block an address.
5. **May this action run?** The evidence verifier, the policy gate and, for high-impact actions, an analyst decide whether it executes, waits or is refused.
6. **Is M1 still valid?** The drift monitor raises an alarm and M1 is retrained.

The goal, set in the RFC, is to stop the intrusion before exfiltration with as few false containments as possible, and to show it end to end against a rule-based SOC and against detectors with playbooks.

## 2. Data sources

All operational data comes from the simulator, shaped like the telemetry a real SOC collects. Public datasets are used only offline, to calibrate it.

### Event streams

Volumes are from a 48-hour run (seed 201): the average an hour, and the busiest hour.

| Stream, topic | Produced by | One event is | Main fields | Volume per 48 h | Delivery |
| --- | --- | --- | --- | --- | --- |
| Sign-ins, `signin` | Identity provider: VPN, single sign-on, Windows logons | An authentication attempt | user, source address, application, destination host, logon type, protocol, outcome and failure reason, MFA, user agent, device, country and city, assigned VPN address | 10.4 thousand: 216 an hour, 610 at peak | Median delay 2 s; 1% late by 1–10 min; 0.3% duplicated; 35% of VPN sign-ins from an old appliance on schema 0.9 |
| Network flows, `flow` | Firewall and flow sensors | A connection record | source and destination address and port, protocol, duration, bytes and packets each way, firewall action, sensor | 281 thousand: 5,850 an hour, 13,300 at peak | Median 15 s; 2% late by 2–15 min; 1% duplicated; one sensor on schema 0.9 |
| Endpoint processes, `process` | EDR agents on the 250 hosts | A process launch | host, user, process and parent name, command line, image path, integrity level, pid and ppid | 125 thousand: 2,600 an hour, 6,900 at peak | Median 4 s; 3% late by 5–60 min; 0.5% duplicated; 3% of agents' clocks off by 30 s to 3 min |

Activity follows the working day and week: employees' activity at night is a few percent of its daytime peak and weekends carry about a fifth of a weekday's, while servers stay busy at night with batch jobs and backups; flow sizes are heavy-tailed. Malformed payloads, 0.03–0.05% of each stream or about 150 a run, go to a dead-letter topic. The JSON Schemas of every event version are in [docs/schemas](../schemas), generated from the Pydantic models with `soc schemas`.

### Context, labels and public data

- **Inventory**, slowly changing: 200 users with role, department, office and privileges, service accounts; 250 hosts with role, zone (corporate, data centre, DMZ), operating system and criticality 1–5; office egress netblocks; DHCP and VPN leases, which say which address a host or person had at a given time; GeoIP and network categories (ISP, hosting, anonymiser, cloud, CDN).
- **Ground truth**: the simulator labels every malicious event with its campaign stage and ATT&CK technique, and records the campaign's progress (stages reached, pivots, bytes exfiltrated, why it stalled) in each run's `truth.json`. Labels train M2 and score the evaluation; the agent never sees them.
- **Public datasets**, offline only and not redistributed: the [LANL multi-source events](https://csr.lanl.gov/data/cyber1/) (authentication, process and flow records) and the [RBA login dataset](https://doi.org/10.5281/zenodo.6782156). `soc calibrate` fits hourly and weekly activity profiles, flow size and duration distributions, and failure and new-country rates from them into [config/calibration](../../config/calibration). The current default is a hand-set prior shaped like LANL; fitting it on the real files is planned for weeks 9–10.
- **Analyst feedback**: verdicts entered in the console label the incident's alerts as true, false or benign positives.

### How new data enters the system

1. The simulator advances in 60-second ticks of simulated time. Each generator emits events with their event time, at rates that follow the calibrated daily and weekly profiles; the campaign's steps are interleaved with benign look-alikes (typos, travel, consumer VPNs, admin maintenance, nightly backups).
2. A delivery model gives each event an arrival time (a log-normal delay, stragglers, duplicates, producer clock skew), corrupts a few, and publishes them to their stream's topic, keyed by user, source address or host.
3. The ingestion consumer validates each payload against its schema version, sends failures to the dead-letter topic with an error code, upgrades 0.9 payloads, drops duplicates by event ID, normalises user and host names, and enriches the event from the inventory (person, role, zone, criticality, GeoIP, lease) before writing it to the hot store.
4. The feature pipeline puts each event into its event-time window: 15 minutes per account and per external source address for sign-ins, 15 minutes per source address for flows, and 10 minutes per host for processes. A window closes when the watermark, the latest arrival time minus 60 s (90 s for processes), passes its end. A late event re-opens its window and fires it again, for up to two hours.
5. In live mode the simulator publishes through Redpanda at a chosen speed, 60 or 120 times real time. Evaluation runs replay the same streams in process, in virtual time, faster than real time and deterministic under the seed.
