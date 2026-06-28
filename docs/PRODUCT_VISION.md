# Security Automation — Product Vision

> **For AI agents:** Read this document before writing any code, opening any issue, or proposing any architecture change. This document defines what the platform is, what it is not, and why every major decision was made. Violating these principles requires a Product Owner review.

---

## Mission

Give a single operator complete, real-time situational awareness of every automated security decision made on their infrastructure — and the confidence to act on it.

---

## Vision

Security Automation is the **Unified Operator Console** for self-hosted WAF automation. It is the single pane of glass where one person can understand, verify, and explain every ban, every suppression, every enrichment, and every provider interaction — without opening a second tool.

By v2.0, an operator who receives a security alert at 3am should be able to:

1. Open the console
2. Understand what happened and why
3. Verify the decision was correct
4. Act if needed
5. Close the alert with an audit trail

In under five minutes. Without touching a CLI.

---

## North Star

> **One operator. Full context. Zero ambiguity.**

Every feature is evaluated against this question: *does this help a single operator understand what the platform decided, and why?*

If a feature adds noise, requires a second tool, or obscures a decision — it does not belong.

---

## What this software is

- A **security automation platform** for self-hosted, single-operator environments
- A **decision audit trail** — every automated action is recorded, explainable, and reproducible
- A **signal aggregator** — CrowdSec, Cloudflare WAF, AbuseIPDB, VirusTotal, Spamhaus feed into one event model
- A **read-first interface** — the console surfaces data; mutations are explicit, gated, and logged
- A **forensic tool** — any past decision can be reconstructed from immutable evidence records
- A **noise filter** — the platform's primary job is deciding what *not* to act on as much as what to act on

## What this software is not

- A SIEM — it does not ingest arbitrary log formats or replace a log aggregation stack
- A multi-tenant platform — it is designed for a single operator on a single infrastructure
- A managed service — the operator owns the data, the keys, and the decisions
- An autonomous threat responder — the platform informs and executes decisions, but the operator sets policy
- A dashboard-first product — the interface follows the operator's workflow, not the other way around

---

## Persona

**The Operator** is a technically fluent individual — a developer, a sysadmin, or a security engineer — running their own infrastructure. They are not a SOC analyst with a team. They are not a manager reading a summary. They are someone who:

- Runs their own servers and owns the consequences
- Understands WAF rules, IP reputation, and network concepts
- Has limited time and zero tolerance for false positives that take their legitimate users offline
- Trusts the platform only as far as they can verify its decisions
- Works alone, often outside business hours
- Wants to understand what happened, not just see that something happened

Everything in the interface is designed for this person.

---

## Operator Journey

The platform is built around this workflow. Every page, every feature, every data point exists to support one of these steps.

```
Alert
  ↓
Investigate        — who is this IP? what signals do we have?
  ↓
Timeline           — what did the platform record and when?
  ↓
Correlate          — is this part of a broader campaign?
  ↓
Understand         — why did the platform make this decision?
  ↓
Decide             — is the decision correct? should I override?
  ↓
Act                — note, suppress, escalate, or confirm
  ↓
Observe            — monitor for recurrence or related IPs
  ↓
Audit              — close the loop; leave a record for the next alert
```

This is not a list of pages. This is the operator's mental model. Every feature request must map to a step in this journey. If it does not, it belongs in a different product.

---

## Principles

### 1. Explainability over automation

Every automated decision must be explainable in plain language. An operator who asks "why was this IP banned?" should get a complete answer from the interface — not from logs.

### 2. Immutability over convenience

Evidence records are append-only. Filtering is not deletion. The forensic chain must always be reproducible. No feature may retroactively alter what the platform recorded.

### 3. Noise reduction over completeness

The platform should surface fewer, higher-confidence signals — not every possible event. A suppressed event is a success, not a failure. The operator's attention is the scarcest resource.

### 4. Local-first over cloud-dependent

The platform runs on the operator's hardware. All credentials are stored locally, encrypted. No telemetry is sent to third parties. The operator can disconnect the internet and the audit trail still works.

### 5. Read-first over mutation-first

The interface is a forensic console, not an admin panel. Every mutation surface (ban, deban, provider toggle) requires explicit action, CSRF protection, and is recorded in the audit trail.

### 6. Server-first over SPA

The UI is rendered server-side in Go. No JavaScript framework. No client-side routing. Dark theme only. Monospace for data, humanist sans-serif for copy. This is not a tradeoff — it is a deliberate choice that keeps the interface fast, auditable, and maintainable by one engineer.

### 7. One name per concept

Every concept in the interface has exactly one canonical name. Labels are product contracts. An evolution of vocabulary requires a Product Owner review.

---

## Canonical Glossary

| Concept | Canonical name | Do not use |
|---|---|---|
| IP investigation page | Investigate | Forensic, Lookup |
| Chronological event stream | Timeline | Events, Activity feed, Log |
| Per-IP campaign view | Focus Incident | Incident detail, Case |
| Enrichment data for an IP | IP Enrichment | Forensic enrichment |
| Raw recorded events (business concept) | Evidence | Logs, Records |
| Observed security activity | Activity | Feed, Stream |
| Platform health dashboard | Health | Status, Monitoring |
| Cloudflare projected state | Cloudflare Overview | CF status |
| Live diff vs Cloudflare API | Cloudflare Rule Diff | Classic diff, CF diff |
| Operator annotations | Operator Notes | Comments, Tags |
| Automated enforcement decision | Decision | Action, Rule |
| A recorded event with all signals | SecurityEvent | Log entry, Record |

---

## Why Timeline

The Timeline is the primary forensic surface. It is the answer to "what did the platform do?" — not a filtered view of a database, but a structured stream of security decisions with provenance (source, confidence, suppression reason, IP enrichment, correlation ID).

The Timeline exists because the operator needs to understand causality, not just state. Knowing that an IP is banned is less useful than knowing the sequence of events that led to the ban.

---

## Why SecurityEvent

From v1.8.5, every discrete platform event (WAF trigger, CrowdSec signal, ban decision, enrichment lookup, suppression) is modelled as a `SecurityEvent` with a unified schema:

```
EventID, CorrelationID, RequestID, TimelineID
Source (nginx / cloudflare / crowdsec / operator)
Timestamp, IP
Nginx payload | Cloudflare payload | CrowdSec payload (typed union)
Enrichment (ASN, country, ISP, AbuseIPDB score)
Decision (suppress / report / ban / allow / observe)
Outcome (pending / confirmed / overridden)
```

This unified model enables correlation across sources, reproducible forensics, and explainable decisions. Without it, every provider integration is a separate data silo.

---

## Why Explainability

An operator who cannot explain a decision to themselves cannot defend it to a user who was wrongly blocked. Explainability is not a feature — it is a prerequisite for trust. The AI Explain feature exists to translate raw signal data into plain language, not to replace the operator's judgment.

---

## Why Immutability

Evidence records must be append-only. This is an architectural invariant, not a preference. The reasons:

1. **Forensic reproducibility** — any past decision must be reconstructable from the record
2. **Legal defensibility** — a mutable audit trail has no evidentiary value
3. **Trust** — an operator who can delete evidence cannot trust the evidence that remains

Filtering is not deletion. Suppression is not removal. The full record always exists.

---

## Why Noise Reduction

The WAF generates thousands of events per day. Most are benign. The platform's most important function is determining what *not* to act on. Every suppression decision — protected target, benign signal, recently reported — is as important as every ban decision. The operator's time is finite.

---

## Why Server First

Server-side rendering in Go is not a nostalgic choice. It is:

- **Auditable** — the HTML returned by the server is the source of truth; there is no client-side state to debug
- **Fast** — a 30MB Go binary renders a complex dashboard in under 5ms
- **Maintainable** — one engineer can understand and modify the entire UI without a JavaScript build chain
- **Secure** — no client-side secrets, no XSS attack surface from SPA routing, no CDN dependency for the interface to function

The dark theme is not aesthetic preference. It reduces eye strain during incident response at night, the most common time an operator is using this console.

---

## Release Gate

Before any milestone is released, the implementing agent must answer:

| Question | Purpose |
|---|---|
| **Why does this milestone exist?** | Product intent — if the answer is vague, the milestone was premature |
| **What changes for an operator?** | User impact — if the answer is "nothing visible", reconsider |
| **What becomes simpler?** | Architecture quality — every release should reduce complexity somewhere |
| **What has been removed?** | Technical debt — deletion is as important as addition |
| **Why does this prepare the next milestone?** | Strategic continuity — milestones are not independent |
| **What is deliberately left untreated?** | Scope discipline — what is out of scope and why |

---

## Roadmap (strategic, not binding)

### v1.8.0 — Unified Operator Console
First release without V1/V2 terminology. The interface is simply "Security Automation". Operator Journey is the primary design lens.

### v1.8.5 — SecurityEvent Unified Schema
Every platform event converges on the `SecurityEvent` model. Timeline, Timeline Correlated, and Evidence become views over the same data, not separate stores.

### v1.9.0 — Operator Journey Completion
All seven steps of the Operator Journey (Alert → Audit) are fully navigable without leaving the console. No dead ends, no missing pivots.

### v2.0 — Explainability at Every Step
Every decision surface in the platform can produce a plain-language explanation of the automated decision, the signals considered, and the suppression rationale.

---

## What this document is

This document is the product contract. It defines what the platform is, for whom, and why every major technical decision was made. It is not a feature backlog, not a sprint plan, and not a technical specification.

**It should be read before any of those are written.**
