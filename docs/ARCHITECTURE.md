# Architecture

```
 logs (.jsonl/.json/.csv/.evtx, Winlogbeat)
        │  normalise: flatten, alias 4688→Sysmon names, tp_* fast fields, UTC time
        ▼
 ┌──────────────────────── per event ────────────────────────┐
 │ RuleSet index (channel, EventID) → only candidate rules    │  Layer 1: deterministic
 │   match rules (Sigma detection syntax, compiled closures)  │
 │   analytic rules → beacon | burst | first_seen | dns_tunnel│
 │                                                            │
 │ process events → features → Half-Space Trees percentile    │  Layer 2: learning
 │                → parent>child rarity, image@host rarity    │
 │ registry events → autorun-target masquerade features       │
 │                                                            │
 │ Fusion: online logistic regression (expert priors + SGD    │
 │ from feedback) + Beta reliability per rule & signature     │
 │   → score, priority band, top-4 "why" contributions        │
 │   → suppressed signatures dropped; benign events learned   │
 └────────────────────────────────────────────────────────────┘
        ▼
 alerts → correlate per host (≤1 h gaps) → attack chains by tactic count
        ▼
 optional local LLM narratives (top N, never alters score)    Layer 3
        ▼
 run dir: manifest.json · alerts.jsonl (hash chain) · certificate_annex.md · report.html
```

## Design choices

- **The speed comes from dispatch, not hardware.** Rules are compiled once and indexed by
  `(channel, EventID)`, so an event is tested only against rules that can match it.
  Learning runs only on process-creation events, about 20% of volume.
- **Day-one usefulness.** The fusion model ships with interpretable prior weights. Feedback
  adapts them, and L2 regularisation toward the priors stops a few labels from erasing
  expert knowledge.
- **Anti-poisoning.** Only events the fusion model scores below 0.5 update the baseline.
- **Safe persistence.** The model is stored as JSON plus a SHA-256 sidecar and is verified on load.
- **LLM containment.** Output is advisory, the LLM runs locally, prompts treat log
  content as untrusted, and generated rules are saved as drafts only.
