# Detection Engineering Methodology

This portfolio is built on evidence-based detection engineering — the practice of deriving detection coverage from observed real-world attacker behavior rather than theoretical threat modeling. This document explains the methodology behind every artifact in this portfolio.

---

## Core Principle: Evidence Before Coverage

Most detection frameworks start with a matrix (MITRE ATT&CK) and ask "what should we detect?" This creates coverage on paper that may not reflect actual attacker behavior in your environment.

This portfolio starts with cases. Real incidents, real techniques, real evasion patterns. The ATT&CK matrix is used as a classification and gap analysis tool — not as a shopping list for detections.

**The practical difference:**
- Theoretical approach: "T1059.001 exists, therefore I need a PowerShell detection"
- Evidence-based approach: "In 8 of 22 cases, PowerShell was used to execute AADInternals functions specifically. The detection needs to distinguish that from the 10,000 legitimate PowerShell executions per day."

---

## The Six-Step Process

### Step 1: Case Collection

Cases are collected from production security incidents observed during an MDR service evaluation (September 2025 – January 2026). For each case:

- What triggered the alert (or what should have triggered it, if it was a miss)?
- What was the actual attacker behavior?
- What was the alert volume context (how many similar events occur legitimately)?
- What was the outcome (contained, missed, FP)?

Cases are not theoretical. They represent real attacker behavior in a production enterprise environment.

### Step 2: Technique Extraction

Each case is mapped to one or more ATT&CK techniques. This is done with discipline:

- The technique must reflect the *specific behavior observed*, not the general category
- Ambiguous cases get the most specific applicable technique, not the parent
- Multiple techniques per case are recorded when the kill chain spans multiple tactics

**Example:** An AADInternals execution is tagged T1528 (Steal Application Access Token) and T1556 (Modify Authentication Process) — both applied in the observed case. Not just T1059.001 (PowerShell) which is the execution mechanism, not the attack goal.

### Step 3: Coverage Assessment

For each extracted technique, the question is: *does a detection exist that would have fired on this specific behavior?*

Coverage has three states:
- **Covered** — A rule exists, it fires with acceptable FP rate, and analysts respond
- **Partial** — A rule exists but has known blind spots (evasion variants, data source gaps)
- **Gap** — No automated detection exists; addressed via hunt hypothesis or new rule

Coverage is assessed against *actual detection outcomes* — did the rule fire? Was it actionable? A rule that fires 10,000 times daily with 0.1% TP rate is not "covered" — it's noise.

### Step 4: Blind Spot Analysis

For every "Covered" or "Partial" detection, the question is: *what would cause this rule to miss?*

This analysis drives:
- Hunt hypotheses (when the evasion variant is plausible but not yet observed)
- Detection improvements (when the blind spot represents a likely attacker technique)
- Risk acceptance documentation (when the blind spot is too noisy to detect)

**Example:** DET-001 detects AADInternals via PowerShell script blocks. The blind spot is REST API-based replication of the same operations — documented as a gap and addressed in HUNT-004.

### Step 5: Detection Writing

New detections are written to address identified gaps. The writing process has three components:

**Detection logic** — What exactly should match? The specificity balance:
- Too broad → unmanageable FP rate, analysts tune out the alert
- Too narrow → attacker makes one modification and evades

**False positive analysis** — What legitimate activity would trigger this? Every detection includes explicit FP scenarios and suppression rationale.

**Tuning documentation** — The before/after analysis is not optional. It demonstrates that alert volume was considered, not just detection capability.

### Step 6: Tuning and Validation

Detections are not complete at the logic level. They're complete when:

- Alert volume is within analyst capacity (generally: ≤20 alerts/day for a single rule)
- True positive rate is documented (target: >80% for CRITICAL, >60% for HIGH)
- Suppression logic is documented with reasoning
- Blind spots from suppression are acknowledged and mitigated

---

## Detection Format Selection

Three formats are used in this portfolio, each serving a different purpose:

### Next-Gen SIEM Queries
Used for: detections that require multi-event correlation, process telemetry, or file system events that benefit from the Next-Gen SIEM data model.

When to use: when the detection logic is specific to the platform's event schema and correlation capabilities (e.g., correlating host_id within a time window).

### Sigma Rules
Used for: detections that should be portable across SIEMs. Sigma is the lingua franca of detection engineering — a rule written once can be converted to Splunk SPL, KQL, QRadar AQL, and others.

When to use: when the data source is standardized (Windows Event Logs, Azure AD logs) and the detection logic doesn't require platform-specific correlation primitives.

### Pseudo-Detection Logic
Used for: complex detections that communicate the *intent* to a detection engineer who will implement in their specific stack. Also used for detections that require multi-platform data correlation that can't be expressed in a single SIEM query.

When to use: when the detection concept is clear but the implementation depends heavily on platform capabilities, data source availability, or organizational context.

---

## Hunt Methodology

Hunts in this portfolio are structured around a specific hypothesis — a falsifiable statement about attacker behavior that current automated detection would miss.

Each hunt pack includes:
- **Hypothesis** — what behavior are we looking for, and why do we think we'd miss it?
- **Data sources** — what telemetry is required?
- **Queries** — platform-specific queries for Next-Gen SIEM, KQL, or Sigma-portable formats
- **Analysis methodology** — how to triage the results, not just collect them
- **Expected findings** — what does legitimate look like vs. suspicious?
- **Success criteria** — how do we know when the hunt is done?
- **Detection rules created** — hunts should produce either: (a) confidence that coverage is adequate, or (b) new detection rules that automate the hunt

---

## Tuning Philosophy

The before/after analysis in `tuning/before_after_analysis.md` documents 10 tuning decisions. The core principles:

**1. Suppress the noise, not the technique.** Every suppression targets a specific FP source. "Too many alerts" is never a reason to suppress — it's a symptom of a poorly scoped detection.

**2. Layer defenses.** When suppression creates a blind spot, a complementary detection covers it. The MFA filter in DET-002 is mitigated by DET-010 (MFA bombing).

**3. Document the trade-off.** Every suppression decision is a risk acceptance. Document what you chose not to see, and why.

**4. Measure outcomes, not volume.** 12 alerts/month at 95% TP is better than 800 alerts/month at 5% TP. The goal is analysts investigating real threats, not alert triage.

---

## Coverage Matrix Maintenance

The `coverage-matrix/detection_coverage_matrix.md` is a living document. It should be updated:
- When new cases are observed (add technique, assess coverage)
- When new detections are added (update coverage status)
- When detections are tuned into ineffectiveness (downgrade to Partial or Gap)
- Quarterly review as a baseline cadence

The `scripts/coverage_gap_checker.py` automates the detection inventory portion — it scans rule files and extracts technique tags. The human judgment portion (is the coverage actually effective?) requires analyst input.

---

## AI Risk Extension

The AI risk section (`ai-risk/`) represents a forward-looking extension of the methodology to an emerging threat surface. The approach is the same:

1. **Identify the behavior** — local LLM process execution, port binding, sensitive file access sequence
2. **Assess current coverage** — no existing detection for this surface
3. **Write detection** — DET-009, scoped to what's detectable without content inspection
4. **Document the gap** — content inspection remains a gap; risk acceptance and policy controls mitigate
5. **Risk assessment** — `local_ai_risk_assessment.md` documents the full risk surface, not just the detectable portion

The methodology doesn't change when the threat surface is new. Evidence-based, gap-aware, and explicitly documented.
