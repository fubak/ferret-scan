# Product Positioning: ferret-scan

> Status: Strategy document. Internal-facing but publishable. Last reviewed: 2026-05-28.
>
> ferret-scan is an MIT-licensed npm CLI (v2.6.1) that statically scans AI coding-assistant
> configurations for security risk — locally, offline by default.

---

## One-line positioning

**ferret-scan is the default local linter for AI-agent configs — the `ESLint` for `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, and `.mcp.json`.**

It scans the files your AI assistant trusts before you do: catching prompt injection, jailbreaks, credential leaks, data exfiltration, backdoors, supply-chain risk, and obfuscation across 80 built-in rules in 9 threat categories — with zero accounts, zero cloud, and inline diagnostics in your editor.

---

## The problem / market context

AI coding assistants execute on instructions and tool definitions that live in plaintext config files inside the repo: `.cursorrules`, `.cursor/rules/*.mdc`, `CLAUDE.md`, `AGENTS.md`, `.mcp.json`, and an expanding set of hook scripts. These files are **code that runs with the assistant's privileges** — they shape behavior, register tools, and grant capabilities — yet almost nothing in the existing security stack reads them.

The threat is no longer theoretical:

- **postmark-mcp backdoor (Sept 2025)** — widely cited as the first malicious MCP server in the wild; a trojanized server BCC'd every email it processed to an attacker-controlled address.
- **MCPoison / CVE-2025-54136 (Cursor)** — Cursor trusted an MCP entry by its *key name* rather than the command it resolved to, allowing a benign-looking entry to be swapped for a malicious command after approval.
- **Snyk "ToxicSkills" research** — found that 36.8% of analyzed agent skills contained a flaw.

Adoption is large and growing — community trackers cite on the order of **10,000+ MCP servers** (exact counts vary widely by source; see *Evidence caveats*). Meanwhile the **EU AI Act** reaches full effect in **August 2026**, adding documentation and provenance pressure (SBOM/AIBOM-style artifacts) on top of the security pressure.

The window is **open but closing**: incidents are driving urgency right now, and incumbents are moving into the exact scan target. Positioning has to assume a 12–24 month race, not a green field.

---

## Competitive landscape

The market splits into three bands. Only one is a *direct* competitor for the same scan target.

| Player / category | What they scan | Relationship to ferret-scan |
|---|---|---|
| **gitleaks, TruffleHog** (secret scanners) | Git history & files for credentials | **Adjacent.** Do not parse AI-agent config semantics. Complementary, not a substitute. |
| **Semgrep, Snyk Code, CodeQL** (SAST) | Application source code | **Adjacent.** No model of AI configs, MCP tool definitions, or prompt-injection patterns. |
| **Lakera, Protect AI** (LLM-runtime security) | Inference-time prompts/responses of deployed apps | **Adjacent / different layer.** Protect apps at runtime, not config files at rest. (Lakera reported acquired — acquirer contested; Protect AI acquired by Palo Alto.) |
| **Snyk "Agent Scan"** (incl. Invariant Labs, acq. June 2025) | AI-agent configs & MCP — *same target* | **DIRECT.** Free OSS core + enterprise platform. Coined "tool poisoning"/"MCP rug pull." Already winning marketplace deals (Vercel `skills.sh`, Tessl). The incumbent to respect. |
| **Codacy "AgentLinter"** (2026) | AI-agent configs / linting | **DIRECT.** Platform-attached entrant. |
| **OSS clones** (rodolfboctor/mcp-scan, AgentShield, AgentAudit) | MCP / agent configs | **DIRECT, displaceable.** Narrower coverage and weaker DX. The realistic land-grab. |

**Read of the board:** the direct zone is crowding and consolidating. Snyk has the security-team and marketplace motion; the OSS clones have neither breadth nor developer experience. ferret-scan should **not** try to out-platform Snyk. It should win the developer's local workflow and the breadth-of-coverage argument, and treat the OSS clones — not Snyk — as the displacement target.

---

## Target buyers

Three segments, very different expectations.

### 1. Individual developers (primary)
- **Expect:** free / open source, no signup, no telemetry.
- **Want:** zero-config local CLI (`npx`), instant editor diagnostics, fast feedback, broad client coverage so it "just works" regardless of which assistant they use.
- **Won't tolerate:** sending repo/config contents to a vendor cloud; mandatory accounts; heavyweight setup.

### 2. AppSec / security teams (secondary)
- **Expect:** CI/CD gating, SARIF output, policy controls, framework mapping (MITRE ATLAS), auditable artifacts.
- **Want:** consolidation — ideally one platform. This is structurally where Snyk is strongest.
- **Reachable when:** the org is regulated, air-gapped, or vendor-neutral by mandate, *or* already standardized on ferret-scan bottom-up via developers.

### 3. Marketplace / registry operators (opportunistic)
- **Expect:** a neutral scan-at-publish engine they can embed in submission pipelines.
- **Highest value per deal, lowest probability** — Snyk is already capturing this band (Vercel, Tessl). Pursue only where a registry explicitly wants to stay outside the Snyk orbit.

---

## Differentiators / the moat

What is *durable* is the intersection — not any single feature, which an incumbent can copy.

- **Neutral.** No commercial-platform lock-in, no upsell funnel. A registry or regulated buyer can adopt it without endorsing a vendor.
- **Already-installed / frictionless.** `npx ferret-scan` runs anywhere Node runs, no account, no provisioning. Distribution is the moat — being the thing already in the `package.json` and the editor.
- **Offline / local-first by default.** Config contents never leave the machine. This is both a security argument and a compliance argument (air-gapped, regulated, data-residency-sensitive buyers).
- **Broadest client coverage.** Across assistants and config formats (`.cursorrules`, `.cursor/rules/*.mdc`, `CLAUDE.md`, `AGENTS.md`, `.mcp.json`, hook scripts) and across editors via an **LSP server (5+ editors)** plus a **VS Code extension** with inline diagnostics.
- **Depth where it counts.** 80 rules across 9 threat categories; `ferret mcp audit` MCP-server trust scoring; CycloneDX **SBOM + AIBOM**; MITRE ATLAS mapping; SARIF/CSV/HTML output; runtime monitoring; community rule sharing.

> **The moat is: neutral, already-installed, offline, broad coverage — not out-platforming Snyk.**
> Every roadmap decision should defend that intersection, not chase platform parity.

---

## Recommended positioning (ranked)

### 1. PRIMARY — "The default local linter for AI-agent configs"

- **Thesis:** make scanning AI configs as reflexive as running ESLint. Developer-first, frictionless `npx`, best-in-class multi-editor LSP / VS Code inline diagnostics, broadest client coverage, offline by default.
- **Target buyer:** individual developers (segment 1); flows upward into segment 2 via bottom-up adoption.
- **Wedge:** developer experience + breadth. Lower time-to-first-finding than any competitor, and "works with whatever assistant you use."
- **Competitor to avoid:** do **not** position against Snyk's platform. Compete on local DX and coverage; let Snyk own the enterprise console.
- **Displacement target:** the OSS clones (mcp-scan, AgentShield, AgentAudit) — beat them on DX and breadth.
- **Risks:** Snyk's free OSS core is "good enough" for many devs and rides their brand; DX advantages are copyable; "AI config linter" is not yet a habit the way ESLint is, so category education is on us.

### 2. SECONDARY — "Vendor-neutral MCP trust + AIBOM / compliance layer"

- **Thesis:** the local, no-account way to produce CycloneDX **AIBOM** + **MITRE ATLAS** mapping + **MCP trust scoring** for buyers who cannot or will not send config data to a commercial cloud.
- **Target buyer:** AppSec / security teams in regulated or air-gapped environments (segment 2).
- **Wedge:** "compliance artifacts without the cloud." **EU AI Act** (full effect Aug 2026) is the tailwind; neutrality + offline operation is the differentiator vs. SaaS-only incumbents.
- **Competitor to avoid:** don't try to match Snyk's policy-management and dashboarding surface. Win on neutrality, locality, and artifact quality.
- **Risks:** security teams structurally prefer one consolidated platform; "compliance-grade" raises support/accuracy expectations; AIBOM/ATLAS standards are still maturing and may shift.

### 3. OPPORTUNISTIC — "Neutral scan-at-publish engine"

- **Thesis:** an embeddable, neutral engine that marketplaces and registries run at submission time.
- **Target buyer:** marketplace / registry operators (segment 3).
- **Wedge:** neutrality — a registry that doesn't want to hand its supply-chain gate to a commercial security vendor.
- **Competitor to avoid:** head-to-head with Snyk on already-captured marketplaces (Vercel, Tessl). Pursue only registries explicitly outside that orbit.
- **Risks:** highest value, lowest probability. Snyk has first-mover marketplace momentum; these deals demand SLAs and partnership investment that an OSS project may not be resourced for.

---

## What this implies for the roadmap

Priorities follow the ranking. Defend the moat (neutral / installed / offline / broad), don't chase platform parity.

**Defend the primary wedge (DX + breadth):**
- Treat **time-to-first-finding** as the headline metric. `npx ferret-scan` in a fresh repo should surface a real result in seconds with zero config.
- Keep **client/format coverage** ahead of all competitors — track new assistants and config formats and add detection fast. Breadth is the claim least easy for a platform vendor to match.
- Invest in **LSP + VS Code** quality: accurate inline diagnostics, low false-positive rate, quick-fixes. The editor is where the "linter" habit forms.
- Keep **install/run frictionless**: no account, no telemetry by default, fast cold start.

**Strengthen the secondary wedge (neutral compliance):**
- Harden **AIBOM / SBOM (CycloneDX)** and **MITRE ATLAS** outputs toward audit-grade; track EU AI Act artifact expectations into Aug 2026.
- Make **offline / air-gapped** operation a first-class, documented mode — the differentiator against SaaS-only rivals.
- Deepen **`ferret mcp audit`** trust scoring with transparent, explainable methodology.

**Keep the opportunistic door open (without over-investing):**
- Keep the engine **embeddable** (stable CLI/exit-code/SARIF contract, library entry point) so a registry can adopt it without bespoke work.

**Cross-cutting:**
- **False-positive discipline** — a noisy linter gets disabled. Precision protects the primary wedge.
- **Community rule sharing** — leans into neutrality and breadth; a defensible, hard-to-copy asset for a platform vendor.
- **Avoid** building a hosted dashboard / policy console as a headline feature; that is the fight to lose against Snyk.

---

## Evidence caveats

This document is built on a point-in-time industry analysis. Known soft spots, stated plainly:

- **MCP server counts vary by source.** "~10,000+" is directional, not authoritative; ecosystem trackers disagree and the number moves quickly.
- **Lakera acquirer is contested.** Reporting has linked Lakera to both Cisco and Check Point; treat the specific acquirer as unconfirmed. Protect AI → Palo Alto is the firmer of the runtime-vendor data points.
- **No public adoption baseline.** There is no reliable public figure for "% of orgs with `.mcp.json` gated in CI," so claims about current scanning coverage are inference, not data.
- **Competitor capabilities move fast.** Snyk Agent Scan, Codacy AgentLinter, and the OSS clones are all actively developed; feature comparisons decay quickly and should be re-verified before external use.
- **Incident attributions** (e.g., "first malicious MCP server") reflect contemporaneous reporting and may be revised.

When in doubt, prefer the durable structural claims (neutral / installed / offline / broad coverage) over specific numbers that may age out.
