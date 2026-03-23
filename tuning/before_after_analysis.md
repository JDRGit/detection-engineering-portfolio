# Before vs. After Tuning Analysis

## Philosophy

Detection tuning is not about reducing alerts — it's about increasing the ratio of actionable signals to noise without creating blind spots. Every suppression rule is a trade-off: something you choose not to see in exchange for being able to see everything else more clearly.

This analysis documents 10 tuning decisions grounded in operational experience, showing the reasoning behind each suppression and what was preserved.

---

## Summary Table

| Detection | Before (Monthly) | After (Monthly) | Reduction | TP Rate Change |
|-----------|------------------|-----------------|-----------|----------------|
| DET-001: AADInternals Token Theft | ~800 alerts | 5-12 alerts | 98.5% | Low → 95%+ |
| DET-002: Impossible Travel | ~9,600 alerts | 60-100 alerts | 99% | 8% → 85% |
| DET-003: Mshta Remote Payload | ~150 alerts | 0-2 alerts | 99% | ~20% → 100% |
| DET-004: Jupyter Startup Shortcut | N/A (new) | 0-1 alerts | — | N/A → ~100% |
| DET-005: Credential Vault | N/A (new) | 0 alerts | — | N/A → ~100% |
| DET-006: VS Code Tunnel | ~15,000 alerts | 8-20 alerts | 99.9% | <1% → ~80% |
| DET-007: CherryLoader | ~50 alerts | 0-3 alerts | 94% | ~30% → 95%+ |
| DET-008: Multi-Stage Correlation | N/A (new) | 1-3 alerts | — | N/A → ~95% |
| DET-009: Local LLM Exfiltration | N/A (new) | 2-8 alerts | — | N/A → ~70% |
| DET-010: MFA Fatigue Push Bombing | N/A (new) | 1-3 weekly | — | N/A → ~85% |

---

## DET-001: AADInternals Token Theft

**What was noisy:** Module import statements in PowerShell profile scripts triggered on the broad string "AADInternals" even when no kill chain functions were executed.

**What we suppressed:** Import-Module and Get-Module references; informational cmdlets (Get-AADIntTenant, Get-AADIntCompanyInformation) that don't represent active compromise.

**What we preserved:** All kill chain functions: token retrieval (Get-AADIntAccessToken*), device joining (Join-AADIntDevice*), PRT generation (Get-AADIntPRT*), authentication bypass (Install-AADIntPassThroughAuthentication).

**Trade-off reasoning:** An attacker who only imports the module without calling kill chain functions has not yet progressed beyond staging. We accept the risk of missing the staging phase in exchange for 98.5% noise reduction, knowing that any progression to actual token theft or auth manipulation will still trigger.

---

## DET-002: Impossible Travel

**What was noisy:** VPN split-tunnel configurations where users connect from their home IP and the corporate VPN egress IP within minutes. Mobile hotspot users whose carrier IP changes during normal travel.

**What we suppressed:** Internal RFC1918 source IPs; MFA-verified sessions (attacker with stolen token typically cannot complete MFA); known corporate egress IP ranges.

**What we preserved:** Multiple external IPs without MFA verification; logins from geographies inconsistent with user history; simultaneous sessions from different ISPs.

**Trade-off reasoning:** MFA suppression accepts the risk that an attacker with both stolen session token AND MFA bypass would evade detection. This is mitigated by a separate detection for MFA fatigue/push bombing. The combined coverage addresses both scenarios.

---

## DET-003: Mshta Remote Payload

**What was noisy:** Legacy internal applications using HTA files for UI elements, launching mshta.exe with local file paths.

**What we suppressed:** Any mshta.exe execution without a remote URL argument; executions with Microsoft-owned domains (microsoft.com, windows.net, office.com).

**What we preserved:** All mshta.exe executions with external, non-Microsoft URL arguments — the attack vector.

**Trade-off reasoning:** Mshta.exe with an external URL is almost universally malicious. The Microsoft domain exclusion is narrow and defensible: if an attacker hosts payload on a compromised microsoft.com subdomain, that would represent a supply chain attack beyond the scope of endpoint detection. For defense-in-depth, we also recommend blocking mshta.exe entirely via AppLocker/WDAC.

---

## DET-006: VS Code Tunnel

**What was noisy:** Development teams legitimately use VS Code tunnels for remote development workflows. 500+ daily DNS resolutions for devtunnels.ms from developer endpoints.

**What we suppressed:** VS Code tunnel activity from endpoints in developer/engineering/IT admin groups.

**What we preserved:** VS Code tunnel activity on non-developer endpoints (finance, HR, sales, executive workstations) where tunnel usage is unexpected and potentially indicates compromise.

**Trade-off reasoning:** An attacker who installs VS Code on a compromised developer workstation and uses tunnels may blend in with legitimate traffic. This is mitigated by: (a) monitoring for VS Code installations on endpoints where it wasn't previously present, (b) correlating tunnel activity with authentication anomalies, and (c) proxy-level blocking of devtunnels.ms for non-developer groups as a preventive control.

---

## DET-007: CherryLoader

**What was noisy:** CherryTree is a legitimate note-taking application used by some employees. Filename-only detection triggered on legitimate installations.

**What we suppressed:** CherryTree executions without the characteristic loader command line pattern (6-digit password + .Data modules).

**What we preserved:** Executions matching the loader's unique CLI pattern; file modifications involving Spof.Data and similar module names.

**Trade-off reasoning:** The command line regex `\d{6}[A-Za-z@!]+\s+\w+\.Data` is highly specific to the loader and has no overlap with legitimate CherryTree usage patterns. An attacker who modifies the loader to use different CLI patterns would evade this specific rule but would still be caught by generic ransomware behavioral detection (file encryption patterns, shadow copy deletion, etc.).

---

## DET-009: Local LLM Data Exfiltration

**What was noisy:** N/A — new detection for an unmonitored surface. No prior baseline exists for local LLM usage in enterprise environments.

**What we preserved:** All four signals: process execution (known LLM runtimes), port binding (LLM API servers), sensitive file access → LLM sequence, and large model file downloads. Each signal targets a distinct risk scenario.

**What we suppressed (by design):**
- Data science/ML teams with approved use cases — excluded by user group membership
- Security researchers testing LLM behavior — excluded via exception process with manager approval
- Developer endpoints running LLMs for application development — same exception process

**Trade-off reasoning:** The "sensitive file + LLM sequence" signal (DET-009 Signal 3) has an inherent limitation — it detects the *precondition* for data exposure, not the exposure itself. A user who opens a sensitive document and then runs an LLM may or may not have fed the document into the model. The detection creates an audit trail; the investigation determines the actual risk. A ~70% TP rate reflects this ambiguity. The remaining 30% are coincidental file access before legitimate LLM usage — worth investigating to build a usage baseline, not noise to suppress blindly.

---

## DET-010: MFA Fatigue Push Bombing

**What was noisy:** N/A — new detection. No prior rule existed for MFA push frequency, despite MFA bombing being responsible for several high-profile breaches in 2022-2024.

**What we preserved:** The signal: ≥5 MFA challenges for a single user within 10 minutes. This threshold was calibrated against normal authentication patterns (most users never receive more than 2 MFA prompts in 10 minutes) while allowing for legitimate troubleshooting scenarios.

**What we suppressed:**
- Automated Intune/Endpoint Manager enrollment flows — excluded by AppDisplayName
- Known IT provisioning operations that batch MFA challenges

**Trade-off reasoning:** A threshold of 5 in 10 minutes accepts the risk that a very slow bombing attack (e.g., 4 pushes over 9 minutes) would evade detection. This is a deliberate choice: lowering the threshold to 3 would double the FP rate from users troubleshooting authentication issues. The mitigating control is DET-002 (impossible travel) — if the bomber succeeds, the subsequent impossible travel should fire. The combined coverage of DET-010 (bombing attempt) + DET-002 (successful stolen session usage) is more reliable than a hair-trigger bombing threshold alone.

---

## Principles Applied

1. **Suppress the noise, not the technique.** Every tuning decision targets a specific FP source while preserving the core attack behavior detection.

2. **Layer defenses.** When suppression creates a theoretical blind spot, a complementary detection or preventive control covers the gap.

3. **Document the trade-off.** Every suppression rule includes explicit reasoning about what risk is accepted and how it's mitigated.

4. **New detections fill gaps, they don't add noise.** DET-004, DET-005, DET-008, DET-009, and DET-010 were created specifically because no prior detection existed for the observed attack patterns. They start with inherently low FP rates by design.

5. **Measure outcomes, not volume.** The goal is not fewer alerts — it's more actionable alerts. A reduction from 800 to 12 alerts with 95% TP rate means analysts investigate 11-12 real threats instead of triaging 800 alerts to find 4-5 real threats.
