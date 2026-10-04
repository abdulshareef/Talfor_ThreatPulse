# Talfor_ThreatPulse

**Hybrid rule + self-learning threat hunting for Windows telemetry — with forensic-grade evidence handling.**

Author: **Dr. Abdul Shareef Pallivalappil** · [TALFOR Cybersecurity & Digital Forensics](https://talfor.in), Bengaluru
License: Apache-2.0 · Status: **v0.1.0 alpha**

---

## Why

Recent benchmarks show that LLM agents score well on security quizzes but struggle to hunt through raw event logs on their own. Rule-only detection has the opposite problem: it is precise, but it cannot see what nobody has written a rule for.

ThreatPulse splits the work:

| Layer | What it does | Speed | Explainable |
|---|---|---|---|
| **1. Predefined rules** | 10 hypothesis-driven detections (ATT&CK-mapped) + drop-in **Sigma** rules | ~20k events/s/core | Fully |
| **2. Learning engine** | Streaming Half-Space Trees, rarity baselines, beacon/DNS/burst analytics, and a fusion model that **learns from analyst TP/FP feedback** | Online, CPU-only, no GPU | Per-alert "why" |
| **3. Local LLM (optional)** | Writes alert narratives and drafts new hypothesis rules from threat intel (Ollama, on-prem) | Off the hot path | Never decides a verdict |

Every run is **hash-chained, tamper-evident and hashed on input**. It also produces a technical annexure to support certification under **Section 63, Bharatiya Sakshya Adhiniyam 2023**.

## The 10 hunting hypotheses

| ID | Hypothesis | ATT&CK |
|---|---|---|
| TP-H01 | Office spawns a shell / script host / LOLBin (weaponised document) | T1566.001, T1204.002, T1059 |
| TP-H02 | Non-system process opens LSASS with memory-read rights | T1003.001 |
| TP-H03 | Encoded or download-cradle PowerShell | T1059.001, T1027, T1105 |
| TP-H04 | C2 beaconing: periodic, low-jitter outbound connections *(analytic)* | T1071.001, T1573 |
| TP-H05 | certutil / rundll32 / regsvr32 / mshta / bitsadmin fetch or proxy-execute | T1218, T1105, T1140 |
| TP-H06 | New persistence: Run key, scheduled task, service | T1547.001, T1053.005, T1543.003 |
| TP-H07 / H07b | Remote exec via PsExec / WMI / WinRM / SMBExec, plus a **first-seen** user→host network logon *(learned)* | T1021, T1047, T1078 |
| TP-H08 / H08b | Shadow-copy / backup destruction, plus a **mass file-write burst** *(analytic)* | T1490, T1486 |
| TP-H09 | Log clearing, Defender / Sysmon tampering | T1070.001, T1562 |
| TP-H10 | DNS tunnelling / DGA: high-entropy, high-volume subdomains *(analytic)* | T1071.004, T1048.003 |

Plus **TP-ML**, which raises learned behavioural anomalies that no rule covers, such as a `svchost.exe` running from a user's AppData. See [docs/HYPOTHESES.md](docs/HYPOTHESES.md).

## Quick start

```bash
pip install git+https://github.com/abdulshareef/Talfor_ThreatPulse
# extras: [evtx] for .evtx files, [dashboard] for the web UI

threatpulse demo                      # synthetic intrusion end-to-end, scored against ground truth
```

### Real data

```bash
# 1. Learn what "normal" looks like (clean period, no alerts raised)
threatpulse baseline ./logs/clean_week/

# 2. Hunt
threatpulse hunt ./logs/incident/ --operator "Dr. Abdul Shareef" --case TALFOR/2026/041

# 3. Teach it: label alerts
threatpulse feedback 9d1c3800f380fc51 fp
threatpulse feedback 4ba06326059620c3 tp

# 4. Prove integrity later
threatpulse verify <run-id>

# Bring your own rules (native or SigmaHQ)
threatpulse hunt ./logs --rules ./sigma/rules/windows/process_creation

# Web dashboard with one-click TP/FP
threatpulse serve        # http://127.0.0.1:8046
```

**Inputs:** Sysmon and Windows Security / System / Defender events as JSON Lines, JSON arrays, Winlogbeat/Elastic documents (flattened automatically), CSV, or `.evtx` (needs `pip install python-evtx`). Security 4688 fields are aliased to Sysmon names, so the same rules cover both.

## How it learns

1. **Baseline (unsupervised).** Half-Space Trees score each process launch against your environment's feature distribution: command-line length and entropy, user-writable path, masquerading system names, URL or base64 content, time of day, parent→child rarity, and image-on-host rarity. Scores are calibrated as percentiles ("rarer than 99.6% of what this model has seen").
2. **Anti-poisoning.** Events the model flags are not learned as normal, so an intruder cannot train the baseline to accept their own activity.
3. **Feedback (supervised).** An online logistic-regression fusion model starts from expert prior weights, so it is useful on day one. It updates by SGD with a replay buffer on every TP/FP label, and L2 regularisation pulls it back toward the priors rather than toward zero.
4. **Noise control.** A Bayesian Beta posterior is kept per rule and per alert *signature*. A signature marked FP three times with no TP is auto-suppressed fleet-wide, and a later TP lifts the suppression. Every label is written to its own hash-chained `feedback.jsonl`.

The model is stored as JSON with a SHA-256 sidecar. It is never pickled, because loading a pickle is code execution.

## Demo results (synthetic data)

`threatpulse demo` generates 3 clean days and 1 intrusion day across 14 hosts. The intrusion chain runs: phishing doc → encoded PowerShell → certutil download → rundll32 C2 beacon → comsvcs LSASS dump → Run key + scheduled task → masquerading implant → DNS tunnel → WMI/SMBExec lateral movement → Defender disabled + logs cleared → shadow copies deleted → mass encryption.

| | Result |
|---|---|
| Hypotheses detected | **12 / 12** scenarios (10 hypotheses + first-seen logon + ML-only implant) |
| Caught **only** by the learning layer | Masquerading `svchost.exe` in AppData; the ransomware binary in `C:\Users\Public` |
| Benign alerts | 4 (OneDrive autorun, ranked below every true alert) → **0 after 3 FP labels** |
| Attack chains | WS-07 (7 tactics) and SRV-01 (4 tactics) ranked top |
| Throughput | ~20,000 events/s on one CPU core (194k events in 9.4 s) |

> ⚠️ **Honest limits.** These numbers come from a **synthetic** dataset this project generated. They show the pipeline works; they are **not** evidence of real-world detection rates. Validate on your own telemetry (and on public corpora such as OTRF Security-Datasets / Mordor or EVTX-ATTACK-SAMPLES) before relying on it. Alerts and ML scores are investigative leads for human review, not findings of fact.

## Local LLM layer (optional)

```bash
ollama pull llama3.1:8b
threatpulse hunt ./logs --llm            # narratives for the top alerts
threatpulse hypothesize advisory.txt     # draft a new rule from threat intel
```

Guardrails:
- The LLM runs on-prem, so no evidence leaves the box.
- It never changes a score or verdict.
- Log content is passed as quoted, untrusted data.
- Drafted rules are compiled and validated, then saved with `status: draft` in `rules/drafts/`. They stay inactive until a human reviews them.

## Evidence handling

Each run writes these files to `threatpulse_runs/<run-id>/`:

| File | Contents |
|---|---|
| `manifest.json` | SHA-256 of every input, tool-build digest, rule-set digest, model digests before/after, UTC + IST timestamps, operator, case ID |
| `alerts.jsonl` | Hash-chained ledger (`hash = SHA-256(prev_hash ‖ record)`). Edits, deletions, re-ordering and truncation are all detected by `threatpulse verify` |
| `certificate_annex.md` | Technical particulars to support a **BSA 2023 s.63(4)** certificate. Part A and Part B of the Schedule must still be completed and signed by the competent persons |
| `report.html` | Offline, phone-friendly report: attack chains and ranked alerts with "why" |

## Writing rules

Native rules use the Sigma `detection` syntax (`contains`, `startswith`, `endswith`, `re`, `all`, `gt`/`lt`, wildcards, `1 of`/`all of`, `not`, parentheses) with a Windows channel/EventID `logsource`. `tp_image` and `tp_parent` are pre-lower-cased file names for fast matching. Analytic rules (`type: analytic`) configure the beacon, burst, first_seen and dns_tunnel detectors. Sigma correlation/aggregation rules (`| count()`) are not supported in v0.1; they are skipped and reported.

## Roadmap

- Linux auditd and Zeek network logs
- ETW / live Sysmon streaming agent (pairs with the TALFOR remote acquisition tooling)
- Validation against public attack datasets, with published precision/recall
- Sigma correlation rules; per-host peer-group baselines

## Citation

```
Pallivalappil, A. S. (2026). Talfor_ThreatPulse: hybrid rule and self-learning
threat hunting with forensic evidence handling (v0.1.0). TALFOR Cybersecurity &
Digital Forensics. https://github.com/abdulshareef/Talfor_ThreatPulse
```

---
© 2026 Dr. Abdul Shareef Pallivalappil / TALFOR. Licensed under the Apache License 2.0. Built with AI-assisted development.
