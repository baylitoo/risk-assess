# IT Risk Assessment Platform — Architecture & Roadmap

**Target:** Enterprise-grade, multi-agent platform that performs full IT risk assessments for a large bank.
**Inputs:** SATS documents, architecture diagrams, technical specs, network details, configs, past assessments.
**Output:** A defensible, auditable risk assessment (findings, risk register, scores, remediation plan) produced through a multi-phase evaluation pipeline with human review gates.

---

## 0. Design principles (the opinions everything else follows from)

1. **Workflow first, agents second.** A risk assessment is not an open-ended task — it has a known shape (scope → gather evidence → analyze → score → report). The *phases* are deterministic, code-orchestrated workflow steps. Agents (model-driven loops) live *inside* phases where the work is genuinely exploratory (reading a 200-page SATS, correlating CVEs against an inventory). This is the single biggest cost/reliability lever: multi-agent setups carry ~60–285% token overhead vs single-agent, so you only pay for agency where it buys you something.
2. **The model is a reasoning engine, not a database.** Every factual claim in the output must be grounded in a retrievable source: a document chunk, an NVD record, a KEV entry, an internal taxonomy node. The report is assembled from *citations*, and the platform can show "finding F-12 ← SATS §4.2 + CVE-2026-XXXXX + control gap C-7".
3. **Untrusted input everywhere.** Customer documents, web content, and even CVE descriptions are prompt-injection vectors. Agents that read them run with least privilege; agents with write/execution power never consume raw external content directly.
4. **Auditability is a feature, not logging.** EU AI Act Art. 19 + internal model risk management (ECB / SR 11-7 style) mean every agent span — retrieval, tool call, inference, human override — is persisted, replayable, and attributable. Design this in at day one; retrofitting it is a rewrite.
5. **Humans gate, agents draft.** The platform produces a *draft* assessment at expert quality and speed. A named risk officer signs off at defined gates. This is both the regulatory posture and the adoption strategy.

---

## 0.1 Build doctrine (jointly agreed, v1.2)

1. **Ship typed artifacts before the graph** — but **ship stable entity IDs now.** Every artifact object (system, component, data asset, control, finding, evidence, assumption) carries a canonical ID from day one; the graph arrives later, entity-resolution hell never does.
2. **Ship minimal policy-as-code in Phase 1** — per-agent YAML (can_read / can_write / cannot) with tests, enforced by the harness; graduates to OPA/Cedar in Phase 3. "Temporary harness checks" are not allowed to become sedimentary architecture.
3. **DORA is a scoping module, not a reporting lens** — for EU-bank ICT systems it changes the assessment *path* (criticality, third-party ICT, impact tolerance, testing evidence), not just the report's annex.
4. **The critic is a missing-risk detector, not a citation checker** — deterministic coverage rules (internet-facing ⇒ abuse/rate-limit finding expected; PII ⇒ privacy finding; third party ⇒ resilience/exit scenario; admin plane ⇒ IAM finding; GenAI component ⇒ injection/leakage scenario) fire *before* the LLM critique pass.
5. **Design evals for the corpus you want (200+), fill with the corpus you have (20–50).** Schema, labeling capture, and regression harness are 200-scale from the start.

---

## 1. System architecture (target state)

```
┌────────────────────────────────────────────────────────────────────┐
│ Clients: Web UI (review console) · REST API · CI/CD hook · Batch   │
└───────────────┬────────────────────────────────────────────────────┘
                │
┌───────────────▼───────────────┐    ┌────────────────────────────┐
│  API Gateway / AuthN-Z (SSO,  │    │  Admin: tenants, prompts,  │
│  RBAC, data-classification)   │    │  model versions, evals     │
└───────────────┬───────────────┘    └────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────────────────┐
│  ORCHESTRATION LAYER — durable workflow engine (Temporal)          │
│  AssessmentWorkflow = phases as activities; retries, timeouts,     │
│  human-signal gates, idempotency keys per tool call                │
└───┬──────────────┬──────────────┬──────────────┬───────────────────┘
    │              │              │              │
┌───▼────┐   ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
│ Intake │   │ Specialist│  │ Specialist│  │ Synthesis │   ← agent
│ agents │   │ agent pool│  │ agent pool│  │ agents    │     workers
└───┬────┘   └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
    │              │              │              │
┌───▼──────────────▼──────────────▼──────────────▼──────────────────┐
│  TOOL & DATA PLANE                                                 │
│  • Company-managed LiteLLM proxy (routing, rate-limit, cache)      │
│  • Sandboxed CLI runtime (per-run container, no-egress default)    │
│  • MCP servers: internal-docs search, vuln-intel, media-intel      │
│  • Stores: Postgres (+pgvector), object store (raw docs),          │
│    knowledge graph (taxonomy/CMDB), Redis (queues/cache)           │
│  • Observability: OTel traces → Langfuse/Grafana; immutable        │
│    audit log (append-only, WORM bucket)                            │
└────────────────────────────────────────────────────────────────────┘
```

### 1.1 Model serving — the bank constraint

- **No provider or model coupling in RiskOS.** Every generation request goes through a company-managed **LiteLLM proxy**. Application code selects a stable task route such as `inventory-extraction` or `risk-synthesis`; the proxy owns deployment selection, provider policy, failover, and residency controls.
- **One managed proxy** in front of all generation calls: enforces per-team quotas, retries/failover, PII controls, request tracing, and prompt-caching discipline. RiskOS persists the task route, prompt version, schema version, and budgets for reproducibility without recording provider/model identifiers in domain artifacts.
- **Task-route tiering:** extraction, classification, synthesis, and review routes are configured externally. Route-to-deployment changes do not require RiskOS code or prompt changes.

### 1.2 Orchestration — durable execution

An assessment runs minutes-to-days (human gates included). Use **Temporal** (or equivalent: Step Functions, Restate, DBOS):

- `AssessmentWorkflow` is the source of truth for state; each phase is an activity or child workflow.
- Agent loops run **inside activities** with checkpointing: every model turn + tool result is persisted, so a crashed worker resumes mid-conversation instead of rerunning a $40 phase.
- **Idempotency keys** derived from `(workflow_id, step_id, tool_call_hash)` for every non-idempotent tool call (ticket creation, report publication).
- Human review gates are workflow *signals* — the workflow sleeps for days at zero compute cost waiting for the risk officer.

### 1.3 Ingestion & knowledge plane

Two pipelines:

**A. Per-assessment intake** (runs when a project submits its dossier):
1. Normalize: PDF/DOCX/XLSX/Visio/draw.io → text + images. Diagrams go through a **proxy-routed vision pass**: extract components, data flows, trust boundaries into a structured graph (nodes/edges JSON) — this becomes the input for threat modeling, *not* the raw pixels.
2. Classify & route: which doc is the SATS, which is the network spec, which is boilerplate. Proxy-routed classifier + rules.
3. Chunk with structure awareness (headings, tables kept whole), embed → **pgvector**, with rich metadata (doc type, section, system, classification level).
4. Extract an **asset & dataflow inventory**: systems, software + versions (→ CPE candidates), network zones, third parties, data categories. This structured inventory is the backbone the agents work against.

**B. Standing knowledge base** (maintained continuously):
- Internal taxonomy / control catalog / policies / past assessments → versioned corpus + knowledge graph (controls ↔ threats ↔ asset classes). Past assessments are gold: few-shot exemplars *and* the eval set (retrieved as *precedent*, never blind-copied — staleness/conflict checks apply).
- **Evidence ontology, grown not designed:** the durable semantic layer is a typed object model — `System, Component, DataFlow, DataAsset, Control, ThreatScenario, RiskFinding, Evidence` — but it is *derived from the artifact schemas* the workflow already produces, and promoted into a queryable graph only when multi-hop questions (portfolio rollups, drift detection) actually need it. Building the full ontology before the eval harness is the classic way these programs die.
- **Retrieval is mode-routed:** exact/keyword for control IDs and policy clauses, vector for semantic recall, graph traversal for multi-hop ("which systems share this control gap"). One retrieval API, three backends.
- External intel mirror: NVD 2.0 sync, CISA KEV, EPSS daily, vendor advisories (MSRC, etc.). Mirror locally — don't let agents hit the public internet ad hoc, and don't depend on NVD enrichment latency (NIST now only fast-tracks KEV/critical-software CVEs; everything else needs CNA-data fallback + EPSS-driven prioritization).

---

## 2. The agent roster

Each agent = a system prompt + a scoped toolset + an output schema (structured outputs, validated). Agents never share a context window; they communicate through **artifacts** (typed JSON documents persisted by the workflow), not chat.

| Agent | Tier | Tools | Produces |
|---|---|---|---|
| **Intake/Inventory** | Mid | doc search, vision, table extract | Asset & dataflow inventory, doc map |
| **Internal-docs analyst** | Mid | RAG over taxonomy/policies/past assessments, knowledge-graph query | Control mapping, policy-gap findings, applicable risk taxonomy nodes |
| **Media/external intel** | Mid | search over mirrored intel (Gartner, MSRC, vendor advisories), allowlisted web fetch | Threat-landscape brief per technology in inventory |
| **Vuln-scan operator** | Mid | **`riskctl` CLI in sandbox** (see §3): NVD, KEV, EPSS, CPE match, internal scanner imports | Vulnerability findings, exploitability-ranked |
| **Threat modeler** | Frontier | dataflow graph, STRIDE knowledge pack (skill), control catalog | Threat model: STRIDE-per-element + abuse cases, mapped to controls |
| **Risk synthesizer** | Frontier | all prior artifacts (read-only), methodology skill (ISO 27005 / EBIOS RM workshops / FAIR params) | Risk register: scenario, likelihood, impact, inherent/residual score, rationale + citations |
| **Report writer** | Frontier | artifacts, report template skill | Draft assessment report (bank template), exec summary |
| **Critic/verifier** | Frontier | artifacts + report | Challenge pass: unsupported claims, missing citations, score inconsistencies → blocking findings |

Notes:
- The **critic agent** is cheap insurance and the thing reviewers learn to trust. It runs with a different prompt persona ("adversarial reviewer") and a checklist derived from past QA rejections.
- Specialist agents fan out **in parallel** (evidence gathering is embarrassingly parallel); synthesis is sequential.
- Keep the roster small. Every additional agent is a new prompt to maintain, eval, and audit. Resist "one agent per data source" sprawl — agents per *capability*, sources per *tool*.

---

## 3. The agent CLI (`riskctl`) — how to do "an agent with a CLI" right

This was a core ask, so the design stance in detail:

**Why a CLI at all (vs. N individual tool definitions):** a suite of vuln operations (query NVD, resolve CPEs, pull EPSS, diff scanner output, check KEV) is 15–30 operations. As flat tools they bloat the prompt and the agent composes them poorly. A CLI gives the agent *programmatic leverage*: it can pipe, filter, loop — and you ship one tool (`bash` in a sandbox with `riskctl` installed) plus tool-search/skill docs.

**Design rules for agent CLI workflows:**
1. **Typed subcommands, JSON-first output.** `riskctl cve get CVE-2026-1234 --json`, `riskctl cpe match "nginx 1.24" --json`, `riskctl epss top --cpe-file inventory.json --min 0.1`. Deterministic, schema'd stdout; errors to stderr with actionable messages (the agent reads them and self-corrects).
2. **`--help` is the contract.** The agent discovers usage via help text — write help for an agent audience: examples, exit codes, common pitfalls. Ship a `SKILL.md`-style usage guide loaded on demand rather than burning system-prompt tokens.
3. **Sandbox per run.** Each agent run gets a fresh container: read-only mount of the assessment workspace, writable scratch dir, **no network egress except the internal intel mirror** via the CLI's own client. The credential for the intel APIs lives in the CLI's environment injected by the harness — never in the prompt or the conversation (prompts are persisted; secrets in them leak into the audit log).
4. **Promote dangerous ops out of the CLI.** Anything irreversible or outward-facing (publish report, open Jira ticket, trigger an *active* scan against a live system) is a **dedicated tool** with typed args, so the harness can gate it (auto-deny, or human confirmation), render it, and audit it specifically. Rule of thumb: bash/CLI for breadth and read-paths; dedicated tools where you need to gate, render, audit, or parallelize.
5. **Budget the loop.** Max tool calls per phase, max tokens per run (the model is told its budget), wall-clock timeout from Temporal. A flailing agent must fail fast and surface a structured "blocked: missing X" rather than burn the budget.

**MCP vs CLI:** both, by role. MCP servers for *retrieval* surfaces shared across agents (internal-docs search, intel queries) — they're easy to permission per-agent and reuse. The CLI for the vuln-operator where *composition* matters. Treat third-party/community MCP servers as untrusted code; only internally-built servers in this environment.

---

## 4. The assessment workflow (multi-phase evaluation)

```
Phase 0  INTAKE          Dossier upload → parse, classify, inventory extraction.
                         Gate: completeness check (deterministic). Missing SATS
                         sections → bounce back to requester with a precise list.

Phase 1  SCOPING         Inventory + taxonomy → assessment scope: which risk
                         domains apply, which methodology depth (fast-track vs
                         full), which agents to schedule. Human gate #1:
                         risk officer confirms scope (5-min review).

Phase 2  EVIDENCE        Parallel fan-out: internal-docs analyst, media intel,
         (parallel)      vuln operator, threat modeler (diagram → dataflow graph
                         first, then STRIDE). Each emits typed artifacts with
                         citations. No agent sees another's raw transcript.

Phase 3  SYNTHESIS       Risk synthesizer consumes artifacts → risk register
                         per methodology (ISO 27005 scales; optionally FAIR
                         quantification for top scenarios). Deterministic code
                         computes scores from the agent's structured factor
                         judgments — the model proposes factors, code does math.

Phase 4  CHALLENGE       Critic agent + automated checks (every finding has ≥1
                         citation; scores within scale; register covers all
                         inventory assets; no orphan threats). Failures loop
                         back to Phase 3 with the critique attached (max 2 loops).

Phase 5  REVIEW & SIGN   Draft report + risk register to the review console.
                         Reviewer edits/accepts/rejects per finding (every action
                         logged → becomes eval data). Human gate #2: sign-off.

Phase 6  PUBLISH         Render to bank template (DOCX/PDF), file the risk
                         register into GRC tooling (Archer/ServiceNow), archive
                         the full trace bundle (inputs, artifacts, transcripts,
                         model versions) as the audit record.
```

### 4.1 Conditional assessment modules (scoped in Phase 1, activated per system type)

The bank's internal taxonomy is the *primary* methodology; external frameworks are **lenses** activated by the scoping phase, and mapping metadata for audit — not N parallel methodologies:

- **DORA module** (EU bank — first-class, not optional): system criticality, impact tolerances, ICT third-party dependencies (provider, service, data processed, outsourcing classification, exit plan, concentration risk), resilience-testing evidence, incident-reporting hooks.
- **Privacy module:** LINDDUN pass + DPIA trigger detection, retention/cross-border/data-minimization checks — activated when the inventory flags personal data.
- **GenAI-system module:** when the *target system* itself contains LLM/RAG/agentic components — OWASP LLM Top 10 + agentic threat extensions, model/data supply chain, eval & monitoring evidence, prompt-injection exposure of *their* system.
- **Adversary lens:** MITRE ATT&CK mapping for top scenarios; OWASP ASVS/API checks when the system is internet-facing.

Each activated module adds eval surface you must maintain — that's the price of a lens, and why scoping decides, not default-on.

Key mechanics:
- **Artifacts over conversation.** Phase outputs are versioned JSON documents with schemas. This is what makes the system debuggable, replayable, and lets you swap an agent's implementation without touching neighbors.
- **Score math is code.** The model assesses qualitative factors (exposure, exploitability, control strength, business impact class) under a rubric; a deterministic scorer turns factors into the bank's scale. Never let the model "feel out" a 1–25 number — that's where reviewers lose trust and where consistency across assessments dies.
- **Confidence is computed, not vibed.** Every finding carries a confidence score derived deterministically from evidence properties — source reliability × extraction confidence × mapping confidence × validation status — never from the model self-reporting "I'm 80% sure" (LLM self-assessed confidence is poorly calibrated). Low-confidence + high-severity ⇒ status `requires_confirmation`, surfaced to the reviewer as a question, not asserted as a risk.
- **Findings have a schema from day one:** title, scenario, affected assets, threat refs, likelihood/impact factors, inherent/residual score, confidence, citations, mapped controls, owner, remediation. The **control gap matrix** is a mandatory publish deliverable alongside the report and register — auditors ask for it by name.
- **The challenge loop is bounded.** Two iterations max, then escalate to human. Unbounded self-correction loops are a cost incident generator.

---

## 5. Evaluation & quality (the part that actually makes it enterprise-grade)

This is the moat and the hardest 40% of the work.

0. **The KPI hierarchy starts with false-safe rate.** The catastrophic failure mode for a risk tool is not a noisy draft — it's a material risk the system *failed to surface and implicitly blessed*. False-safe rate (missed risks present in the signed register / SME holdout) and unsupported-critical rate (high findings without grounding) are board-level metrics; precision and reviewer-acceptance come after.
1. **Golden set:** 20–50 past assessments to start (be honest: nobody has 200 labeled packs on day one), redacted, with their final signed risk registers. Split: dev / regression / holdout. Grow toward 100+ via the reviewer-label flywheel.
2. **Phase-level evals,** not just end-to-end:
   - Intake: inventory extraction precision/recall vs hand-labeled inventories.
   - Vuln: known-answer tests (this stack ⇒ these CVEs must be found; these must be filtered as N/A).
   - Threat model: coverage vs SME-authored threat models (recall on threats that mattered).
   - Synthesis: score agreement (within ±1 band) with the signed register; rationale faithfulness (LLM-judge + sampled SME review — judge for triage, humans for truth).
3. **Regression on every change** to a prompt, model version, or tool — run the regression set in CI (Batch API at 50% cost). No prompt edits land without a green run.
4. **Production telemetry as eval feed:** every reviewer edit in Phase 5 is a labeled datapoint (accepted / edited / rejected per finding). Weekly triage of rejections → prompt/tool/retrieval fixes.
5. **Model risk management package:** model cards, intended-use, known failure modes, performance bounds, monitoring plan — written for the bank's model validation team from day one. This is what gets you to production in a bank, not the demo.

---

## 6. Security & governance

- **Prompt injection:** documents are attacker-controlled (a vendor SATS could embed "ignore previous instructions"). Mitigations: agents reading raw docs have read-only toolsets; structured-output schemas constrain what they can emit; the synthesis agent consumes *artifacts* (already-structured), not raw text; injection canaries in eval set.
- **Sandboxing:** per-run containers, default-deny egress, read-only inputs, scratch-only writes, secrets injected at runtime never in prompts.
- **RBAC & tenancy:** assessment workspaces isolated per project; classification labels flow from documents to artifacts to report; reviewers see only their book of work.
- **Declarative policy layer (Phase 3):** tool authorization, data access, and side-effect gates move from scattered if-statements into an OPA/Cedar-style policy engine — per-agent allow/deny matrices as versioned policy-as-code. The auditor question "show me the rule that allowed this" gets a file and a commit hash, not an archaeology session.
- **Platform as a monitored asset:** admin actions, tool calls, policy denials, and data access feed the bank's SIEM; the platform gets its own threat register (tool poisoning, retrieval poisoning, cross-agent contamination, model supply chain) and red-team suite, not just an injection canary.
- **Audit trail:** append-only event log (WORM storage) of every span: model id + version, full prompt hash, tool calls + results, human actions. Retention ≥ the bank's record-keeping rules (EU AI Act Art. 19 sets the floor for high-risk AI logging).
- **Data residency:** the company-managed LiteLLM proxy enforces approved in-region deployments; no data leaves the boundary. Web-facing intel collection runs in a separate, segregated collector that imports into the mirror.

---

## 7. Delivery roadmap

### Phase 0 — Foundations & proof of grounding (weeks 1–6)
- Stand up: company-managed LiteLLM proxy integration, Postgres/pgvector, object store, Temporal dev cluster, OTel→Langfuse tracing.
- Build intake pipeline v1 (PDF/diagram → text + dataflow graph) and the asset-inventory extractor.
- Acquire and label the golden set from past assessments. Build the eval harness *before* the agents.
- **Exit criterion:** inventory extraction ≥ target P/R on golden set; one document dossier flows end-to-end into structured artifacts.

### Phase 1 — Single-pipeline MVP (weeks 6–14)
- One workflow, three steps: intake → single "analyst" agent (RAG over internal corpus, no CLI yet) → templated report draft. Human review console v1 (accept/edit/reject per finding, capture labels).
- Ship to 2–3 friendly risk officers on real (low-stakes) assessments. The goal is *trust calibration* and label collection, not coverage.
- **Exit criterion:** reviewers accept ≥60% of findings unedited; full audit trace per assessment.

### Phase 2 — Specialist agents & the CLI (weeks 14–26)
- Build `riskctl` + sandbox runtime + intel mirror (NVD 2.0/KEV/EPSS sync). Add vuln-operator agent with known-answer evals.
- Add threat modeler (vision → dataflow graph → STRIDE) and media-intel agent.
- Split synthesis out; add the critic/challenge loop; deterministic scoring engine per the bank's methodology (ISO 27005-aligned, FAIR option flagged for later).
- **Exit criterion:** full multi-phase pipeline beats Phase-1 MVP on regression set; vuln known-answer suite green; cost per assessment within budget envelope.

### Phase 3 — Enterprise hardening & scale (weeks 26–38)
- Multi-tenancy, RBAC, classification propagation; WORM audit store; DR/HA for Temporal + gateway.
- Throughput: worker autoscaling, Batch API for non-interactive phases, prompt-cache audit (target >70% cached input tokens on document-heavy phases), per-assessment budget caps + alerting.
- Policy engine (OPA/Cedar) for tool authorization and side-effect gates; SIEM integration for platform events.
- Model risk management package + validation team engagement; pen test of the sandbox; injection red-teaming.
- **Exit criterion:** production approval from model validation + security; N concurrent assessments at SLA.

### Phase 4 — Continuous & comparative risk (weeks 38+)
- Continuous mode: re-run vuln + intel phases on a schedule against the living inventory; diff-based alerts ("EPSS for your stack moved", "new KEV entry matches system X") instead of point-in-time PDFs.
- **Architecture & control drift:** diff CMDB / cloud-config / IaC / network facts against the last *approved* inventory and control evidence — continuous risk is not just CVEs; it's the system quietly no longer matching its assessment.
- Portfolio view: cross-assessment analytics, systemic-risk rollups for the CISO.
- FAIR quantification for top-N scenarios; integration with GRC workflow for remediation tracking.

---

## 8. Stack summary (defaults, all swappable)

| Layer | Choice | Why |
|---|---|---|
| Generation | Company-managed LiteLLM proxy with stable task routes | RiskOS remains model/provider agnostic; routing, failover, and residency policy stay external |
| Policy | OPA/Cedar policy-as-code for tool authz & side-effect gates | Auditable rules, per-agent allow/deny matrices |
| Agent loop | RiskOS-owned bounded loop, Python | Approval gates, budgets, structured outputs, and audit behavior remain under platform control |
| Orchestration | Temporal | Durable, human-gate signals, replayable history |
| Data | Postgres + pgvector, S3, Neo4j-or-Postgres graph | Boring, bank-approvable |
| Tool surface | Internal MCP servers (retrieval) + `riskctl` CLI in per-run sandbox (composition) + dedicated gated tools (side effects) | §3 |
| Observability | OpenTelemetry → Langfuse/Grafana; WORM audit bucket | Trace-per-span; Art. 19 retention |
| Evals | Custom harness + Batch API for regression; reviewer labels as data flywheel | §5 |
| UI | Review console (React) — finding-level accept/edit/reject | Labels + trust |

---

## 9. Top risks to the program itself

1. **Eval debt.** If agents ship before the harness, quality regressions are invisible until a reviewer escalates. Mitigation: Phase 0 ordering above is non-negotiable.
2. **Reviewer trust collapse.** One hallucinated CVE in front of the wrong audience sets adoption back months. Mitigation: citations-or-it-doesn't-ship, critic agent, conservative Phase-1 scope.
2b. **False-safe failure.** Worse than the hallucinated CVE is the real risk the system missed and implicitly blessed — that's the failure that ends the program *and* surfaces in an incident postmortem. Mitigation: false-safe rate as the top eval KPI (§5), coverage checks in the challenge phase, confidence-gated assertions.
3. **Cost runaway.** Document-heavy + multi-agent = token bonfire. Mitigation: caching discipline, model tiering, budget caps per phase, batch where async.
4. **NVD data gap.** Post-2026 NVD enrichment is selective. Mitigation: CNA fallback + EPSS/KEV-first prioritization built into `riskctl`, not bolted on.
5. **Methodology drift.** If the deterministic scorer doesn't exactly match the bank's risk matrix and definitions, the GRC team rejects the output wholesale. Mitigation: codify the methodology with the risk team in Phase 0; version it.
