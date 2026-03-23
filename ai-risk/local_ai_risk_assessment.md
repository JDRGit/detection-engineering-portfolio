# Local AI Risk Assessment

**Version:** 1.0
**Date:** March 2026
**Scope:** Local large language model (LLM) usage and shadow AI on corporate endpoints
**Classification:** Internal — Security Risk Assessment

---

## Executive Summary

Local LLMs represent a new and largely unmonitored risk surface in enterprise environments. Unlike cloud-based AI services (ChatGPT, Copilot, Claude), which are subject to corporate acceptable use policies, network controls, and vendor DLP, local models run entirely on-device — invisible to proxy logs, DLP tooling, and most EDR behavioral baselines.

**Primary risks:**
1. **Data exfiltration without network traffic** — sensitive documents processed locally leave no detectable artifact in network telemetry
2. **Policy bypass** — employees blocked from cloud AI turn to local alternatives with no guardrails
3. **Model integrity** — GGUF model files downloaded from unvetted sources could be backdoored
4. **Compute abuse** — GPU-intensive inference on corporate hardware impacts performance and may violate policy

**Current detection coverage:** DET-009 (process-level and sequence-based detection)
**Current detection gap:** Model file integrity verification, network exfiltration from local model API exposure

---

## Threat Landscape (March 2026)

### The Local LLM Ecosystem

As of early 2026, running capable LLMs locally requires only:
- A modern laptop GPU (8GB VRAM runs 7B–13B parameter models)
- A 4–30 GB model file downloaded from Hugging Face or Ollama Hub
- One of several free, open-source runtimes (Ollama, LM Studio, llama.cpp, GPT4All)

**Time to operational:** A motivated employee can have a capable local model running in under 30 minutes with no admin privileges required for user-space installations.

### Risk Actors

| Actor | Motivation | Risk Profile |
|-------|-----------|-------------|
| Productivity-seeking employee | Faster work, blocked by cloud AI policy | Medium — accidental data exposure |
| Developer building LLM app | Testing, prototyping | Low if authorized — Medium if not |
| Data science / ML researcher | Model evaluation | Low if authorized |
| Policy-aware employee circumventing controls | "I know I'm not supposed to use ChatGPT, but..." | High — intentional policy bypass |
| Insider threat | Exfiltration via LLM assistance | High |
| External attacker (post-compromise) | Exfiltrate data via local model installed on compromised endpoint | High |

---

## Risk Analysis

### Risk 1: Sensitive Data Input to Local Models

**Scenario:** Employee copies financial projections, customer PII, source code, or M&A documents into a local model prompt to generate summaries, analyze patterns, or get writing assistance.

**Why this is hard to detect:**
- No network traffic — all processing is local
- EDR captures process creation but not model input/output content
- Files accessed before the LLM session don't create obvious causation links

**Detection approach (DET-009 Signal 3):**
- Sequence: sensitive file access → LLM process activity within 5 minutes
- Imperfect but creates an audit trail for investigation

**Data categories at highest risk:**
- M&A documents, financial forecasts, strategic plans
- Customer PII / PHI (regulatory exposure)
- Source code, API keys, credentials in files
- Legal privileged communications

**Likelihood:** High — multiple employees using local AI is near-certain given adoption rates
**Impact:** Medium to High — depends on data sensitivity; regulatory risk if PII involved

---

### Risk 2: Policy Bypass via Shadow AI

**Scenario:** Organization has blocked ChatGPT and Copilot via proxy/DLP policy. Employee installs Ollama locally and uses it for the same tasks the policy was designed to prevent.

**Current state:** Most organizations' AI acceptable use policies reference cloud AI services explicitly but do not address local models. Local AI is a genuine policy gap, not just an enforcement gap.

**Recommended policy language:**
> "Use of AI models — whether cloud-hosted, locally-installed, or accessed via API — for processing company data requires prior approval from [IT/Legal/Security]. Approved AI tools are listed at [internal link]. Use of unapproved AI tools to process company-classified data is prohibited regardless of where processing occurs."

**Detection (DET-009 Signals 1 & 2):**
- Process execution detection for known local LLM runtimes
- Port binding detection (Ollama's API on :11434 is highly specific)

**Likelihood:** High
**Impact:** Medium — primarily policy/governance risk; regulatory risk if PII involved

---

### Risk 3: Model File Integrity (Supply Chain)

**Scenario:** An attacker who has compromised a developer's endpoint replaces a locally-installed GGUF model file with a backdoored variant. The backdoored model executes a payload when loaded, or exfiltrates conversation context to a C2 server via the model runtime's network stack.

**Why this is feasible:**
- GGUF files are not code-signed — no integrity verification mechanism exists in current LLM runtimes
- Ollama stores models at `~/.ollama/models/` (user-writable, no admin required to modify)
- Model loading is a trusted operation — EDR behavioral engines don't inspect model content
- A backdoored runtime could make legitimate API calls to external services without raising alerts

**Current detection gap:**
- No detection exists for model file modification
- Runtime network calls blend with legitimate LLM API traffic

**Recommended control (not yet implemented):**
```python
# Conceptual: model integrity check via stored hash
# Would run as a periodic scheduled task or endpoint health check

import hashlib
import json
import os

def verify_model_integrity(model_path, expected_hashes_file):
    """Verify GGUF model files against stored SHA-256 hashes."""
    with open(expected_hashes_file) as f:
        expected = json.load(f)

    for model_file in Path(model_path).glob("**/*.gguf"):
        sha256 = hashlib.sha256(model_file.read_bytes()).hexdigest()
        if str(model_file) in expected:
            if sha256 != expected[str(model_file)]:
                alert(f"Model file integrity violation: {model_file}")
        else:
            alert(f"Unknown model file detected: {model_file}")
```

**Likelihood:** Low (requires endpoint compromise first)
**Impact:** High (stealthy persistence/exfil mechanism)

---

### Risk 4: Local LLM API Exposure

**Scenario:** Ollama runs a local API server on port 11434 (default: bound to localhost). If a developer misconfigures it to bind to `0.0.0.0`, any network-adjacent host can query the LLM — potentially including an attacker who has lateral movement access.

**Additional scenario:** A developer exposes Ollama via VS Code tunnel (DET-006) — creating a remotely-accessible LLM API that routes through devtunnels.ms.

**Detection (DET-009 Signal 2):**
- Alert on LLM ports binding to non-localhost interfaces
- DET-006 already covers VS Code tunnel exposure

**Likelihood:** Medium (developer misconfiguration)
**Impact:** Medium — API access + data exfiltration via LLM API

---

## Current Control Coverage

| Risk | Preventive Control | Detective Control | Gaps |
|------|-------------------|------------------|------|
| Sensitive data input | Policy (partial) | DET-009 (Signal 3) | Content inspection not possible |
| Shadow AI / policy bypass | Proxy block (cloud AI only) | DET-009 (Signals 1, 2) | Local models bypass proxy entirely |
| Model integrity | None | None | Full gap — future work |
| API exposure | None | DET-009 (Signal 2) | No alerting for 0.0.0.0 bind |

---

## Recommended Program Controls

### Immediate (0–30 days)

1. **Deploy DET-009** — baseline detection for local LLM process execution across all endpoints
2. **Update AI Acceptable Use Policy** — explicitly address local models
3. **Inventory existing local LLM usage** — run DET-009 queries historically to understand current footprint
4. **Communicate policy** — don't assume employees know local AI is in scope

### Near-term (30–90 days)

5. **Establish approved local AI exception process** — developers and data scientists need a legitimate path; provide one or they'll route around policy
6. **Deploy Ollama port monitoring** — alert on :11434, :1234, :8080 binding to non-localhost
7. **Integrate with DLP workflow** — DET-009 HIGH alerts (sensitive file → LLM sequence) route to DLP team, not just SOC

### Long-term (90+ days)

8. **Model integrity verification** — implement hash-based verification for any approved local model deployments
9. **LLM-specific DLP policy** — work with legal/privacy on what data categories require explicit prohibition even in approved local AI tools
10. **Periodic audit** — quarterly hunt using DET-009 query set to identify new local AI deployments

---

## Detection Summary

| Detection | Signal | Severity | Routing |
|-----------|--------|----------|---------|
| DET-009 Signal 1 | Local LLM process execution | Medium | IT Policy review |
| DET-009 Signal 2 | LLM API port binding | Medium | IT + Security review |
| DET-009 Signal 3 | Sensitive file → LLM sequence | High | Security + DLP |
| DET-009 Signal 4 | Large model file download (>1GB .gguf) | Low | IT Inventory |

---

*See also: DET-009 (Local LLM Data Exfil detection rule), DET-006 (VS Code Tunnel — covers LLM API tunnel exposure)*
