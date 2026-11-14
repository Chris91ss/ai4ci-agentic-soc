# Evaluation

Generated 2026-11-14 18:14 UTC. Raw numbers: [results.json](results.json).

## Model level (M1-M3)

Held-out test weeks test-1, test-2 (4.0 days), scored by the promoted models at their operating thresholds.

| Detector | Windows | Attack windows | PR-AUC | ROC-AUC | Recall @1% FPR | Recall @threshold | FP / day | Precision |
|---|---|---|---|---|---|---|---|---|
| M1-user | 13449 | 323 | 0.996 | 1.000 | 0.994 | 0.991 | 16.0 | 0.833 |
| M1-ip | 2438 | 28 | 0.979 | 1.000 | 1.000 | 1.000 | 4.2 | 0.622 |
| M2 | 492957 | 481 | 0.999 | 1.000 | 1.000 | 0.969 | 0.8 | 0.994 |
| M3 | 63812 | 18 | 0.749 | 0.944 | 1.000 | 0.889 | 4.5 | 0.471 |

Detection delay: minutes from the start of an attack stage (ground truth) to the end of the first alerting window covering it, per test week.

| Detector | Stage | Delay (min) |
|---|---|---|
| M1-user | initial_access | 4.4, 1.4 |
| M1-user | lateral_movement | 11.1, 10.8 |
| M1-user | spray | 11.0, 13.1 |
| M1-ip | initial_access | 4.4, 1.4 |
| M1-ip | spray | 11.0, 13.1 |
| M2 | command_and_control | 8.6, 13.0 |
| M2 | discovery | 4.3, 4.3 |
| M2 | exfiltration | 19.1 |
| M2 | lateral_movement | 11.1, 10.8 |
| M2 | spray | 11.0, 13.1 |
| M3 | collection | 4.1, 11.2 |
| M3 | credential_access | 2.3, 5.2 |
| M3 | discovery | 4.3, 9.3 |
| M3 | execution | 8.7, 8.1 |
| M3 | initial_access | 9.4, 11.4 |
| M3 | lateral_movement | 1.1, 0.8 |

## End to end

10 seeded 48-hour closed-loop runs per configuration on the same company (org_seed 7), one attack per run, on weeks after the dataset's test weeks. Times are measured from the start of the attack; MTTD counts window and delivery delays, MTTC is the first executed action on an entity the attacker used, after the attack started. False containments are executed actions on anything else, or on a future victim before the attack.

| Configuration | Runs | Detected | MTTD (min, median) | Contained | MTTC (min, median) | Stopped before exfiltration | Exfiltrated (GB, mean) | Furthest stage (mean of 9) | False containments (mean) | Runs without false containment | Alerts (mean) | Incidents (mean) | Alert reduction |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Agent (scripted analyst) + M1-M3 | 10 | 100% | 11.5 | 100% | 16.2 | 100% | 0.00 | 4.4 | 0.0 | 100% | 182 | 30 | 0.810 |
| Detectors M1-M3 + playbooks | 10 | 100% | 11.5 | 100% | 11.5 | 100% | 0.00 | 3.4 | 4.6 | 10% | 211 | 31 | 0.830 |
| Rules + playbooks | 10 | 100% | 13.2 | 100% | 15.2 | 100% | 0.00 | 2.8 | 3.3 | 0% | 358 | 113 | 0.670 |

Paired comparisons over the same seeds (Wilcoxon signed-rank):

| Comparison | Metric | Paired runs | Median difference | Wilcoxon p |
|---|---|---|---|---|
| agent vs detectors | false_containments | 10 | -3.50 | 0.0039 |
| agent vs detectors | furthest_stage_index | 10 | 1.00 | 0.3438 |
| agent vs detectors | exfil_gb | 10 | 0.00 | – |
| agent vs detectors | mttc_min | 10 | 3.00 | 0.0020 |
| agent vs detectors | incidents | 10 | -0.50 | 0.1562 |
| agent vs rules | false_containments | 10 | -3.00 | 0.0020 |
| agent vs rules | furthest_stage_index | 10 | 1.00 | 0.0938 |
| agent vs rules | exfil_gb | 10 | 0.00 | – |
| agent vs rules | mttc_min | 10 | 3.00 | 0.8047 |
| agent vs rules | incidents | 10 | -83.00 | 0.0020 |

### Triage agent

| Configuration | Decisions | Verdict precision | Verdict recall | Verdict F1 | Attack incidents flagged | Action correctness | Invalid tool calls | Latency mean (s) | Latency p95 (s) | Timeouts | Escalated dismissals |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Agent (scripted analyst) + M1-M3 | 111 | 1.000 | 0.680 | 0.810 | 25/25 | 1.000 | 0.0000 | 117.5 | 165.0 | 0 | 0 |

### Local LLM (gpt-oss:20b via Ollama)

| Configuration | Runs | Detected | MTTD (min, median) | Contained | MTTC (min, median) | Stopped before exfiltration | Exfiltrated (GB, mean) | Furthest stage (mean of 9) | False containments (mean) | Runs without false containment | Alerts (mean) | Incidents (mean) | Alert reduction |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Agent (scripted analyst) + M1-M3 | 3 | 100% | 12.4 | 100% | 15.4 | 100% | 0.00 | 5.0 | 0.0 | 100% | 198 | 30 | 0.840 |
| Agent (gpt-oss:20b) + M1-M3 | 3 | 100% | 12.4 | 100% | 14.6 | 100% | 0.00 | 5.0 | 0.7 | 67% | 228 | 30 | 0.860 |
| Agent (gpt-oss:20b) + M1-M3, evidence verifier | 3 | 100% | 12.4 | 100% | 15.4 | 100% | 0.00 | 5.0 | 0.3 | 67% | 249 | 29 | 0.880 |

| Configuration | Decisions | Verdict precision | Verdict recall | Verdict F1 | Attack incidents flagged | Action correctness | Invalid tool calls | Latency mean (s) | Latency p95 (s) | Timeouts | Escalated dismissals |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Agent (scripted analyst) + M1-M3 | 35 | 1.000 | 0.714 | 0.833 | 7/7 | 1.000 | 0.0000 | 118.7 | 165.0 | 0 | 0 |
| Agent (gpt-oss:20b) + M1-M3 | 32 | 0.571 | 0.800 | 0.667 | 5/5 | 0.920 | 0.1838 | 68.0 | 114.6 | 2 | 0 |
| Agent (gpt-oss:20b) + M1-M3, evidence verifier | 37 | 0.625 | 0.833 | 0.714 | 6/6 | 0.930 | 0.1758 | 75.3 | 149.9 | 3 | 0 |

## S1: drift (move to remote work over ZTNA)

False M1 alerts are sign-in alerts without attack events. Busy hours have at least half the pre-shift peak sign-in volume. Recovered after: hours from the shift until the false-alert rate over the last three busy hours is back within twice the pre-shift busy-hour rate (or that rate plus one); – means not within the run. Next day: the rate 24-36 hours after the shift, and its ratio to the pre-shift busy-hour rate.

| Configuration | Seed | Alarm after (h) | False M1 alerts/h before (all / busy hours) | …first 6 h | …next day | Recovered after (h) | Retrainings | False containments | Furthest stage | Exfiltrated (GB) |
|---|---|---|---|---|---|---|---|---|---|---|
| Agent (scripted analyst) + M1-M3 | 301 | 4.0 | 0.46 / 0.78 | 14.17 | 9.67 (12.4x) | – | 0 | 0 | command_and_control | 0.00 |
| Agent (scripted analyst) + M1-M3 | 302 | 4.0 | 0.54 / 0.88 | 13.83 | 7.83 (8.9x) | – | 0 | 0 | command_and_control | 0.00 |
| Agent (scripted analyst) + M1-M3 | 303 | 4.0 | 0.71 / 1.25 | 14.17 | 9.42 (7.5x) | – | 0 | 0 | collection | 0.00 |
| Agent, M1 retrained on drift | 301 | 4.0 | 0.46 / 0.78 | 14.17 | 2.25 (2.9x) | 30.0 | 2 | 0 | command_and_control | 0.00 |
| Agent, M1 retrained on drift | 302 | 4.0 | 0.54 / 0.88 | 13.83 | 2.67 (3.1x) | – | 2 | 0 | command_and_control | 0.00 |
| Agent, M1 retrained on drift | 303 | 4.0 | 0.71 / 1.25 | 14.17 | 1.75 (1.4x) | 25.0 | 2 | 0 | command_and_control | 0.00 |

## S2: high load (10x event burst)

| Variant | Phase | Events consumed / wall s | Stream lag p50 (sim s) | Stream lag p95 (sim s) | Stream lag p95 (wall s) | Consumer lag max (msgs) | Agent queue max |
|---|---|---|---|---|---|---|---|
| LLM ×1 in burst | before | 229 | 0 | 60 | 1.00 | 18683 | 1 |
| LLM ×1 in burst | burst | 3004 | 0 | 60 | 1.00 | 3229 | 1 |
| LLM ×1 in burst | after | 300 | 0 | 60 | 1.00 | 970 | 1 |
| LLM ×4 in burst | before | 228 | 0 | 60 | 1.00 | 42059 | 1 |
| LLM ×4 in burst | burst | 3042 | 0 | 60 | 1.00 | 3228 | 1 |
| LLM ×4 in burst | after | 323 | 0 | 60 | 1.00 | 3017 | 1 |

| Variant | Event rate in burst | Routes (agent / playbook) | Shed to playbooks | Agent timeouts | Breaker trips | Decisions (agent / playbook) | Campaign |
|---|---|---|---|---|---|---|---|
| LLM ×1 in burst | ×10.9 | 15 / 0 | 0 | 0 | 0 | 15 / 0 | stalled (foothold WS-0158 isolated before credential_access) |
| LLM ×4 in burst | ×10.9 | 15 / 0 | 0 | 4 | 1 | 11 / 4 | stalled (foothold WS-0158 isolated before credential_access) |
