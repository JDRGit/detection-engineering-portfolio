# Detection Coverage Matrix

Maps MITRE ATT&CK techniques observed across production MDR evaluation (Sep 2025 – Jan 2026) against current detection coverage. Techniques are drawn from confirmed incident cases, not theoretical threat modeling.

**Coverage Definitions:**
- **Covered** — Automated detection with ≥80% true positive rate and alert volume within analyst capacity
- **Partial** — Detection exists but has known blind spots (evasion variants, data source gaps, high FP rate)
- **Gap** — No automated detection; addressed via hunt hypothesis or new detection rule

---

## Coverage Summary

| Status | Count |
|--------|-------|
| Covered | 17 |
| Partial | 7 |
| Gap | 2 |
| **Total** | **26** |

---

## Identity & Credential Access

| ID | Technique | Detection Rule | Coverage | Notes |
|----|-----------|---------------|----------|-------|
| T1078 | Valid Accounts — Impossible Travel | DET-002 | ✅ Covered | Azure SignIn logs; MFA + internal IP filter |
| T1528 | Steal Application Access Token | DET-001 | ✅ Covered | Script block logging; kill chain functions only |
| T1556 | Modify Authentication Process | DET-001 (partial) | ⚠️ Partial | PTA modification via PS covered; REST API variant → HUNT-004 |
| T1555 | Credentials from Password Stores | DET-005 | ✅ Covered | DPAPI/Vault file access by non-system processes |
| T1552.001 | Credentials In Files | None | ⚠️ Partial | No automated detection; covered by HUNT-001 |
| T1003.001 | LSASS Memory | DET-008 (correlated) | ✅ Covered | Via multi-stage correlation; standalone rule in SIEM |
| T1621 | MFA Request Generation | DET-010 | ✅ Covered | Push bombing threshold detection; Azure SignIn logs |

---

## Execution

| ID | Technique | Detection Rule | Coverage | Notes |
|----|-----------|---------------|----------|-------|
| T1059.001 | PowerShell | DET-001, DET-008 | ✅ Covered | Script block logging; kill chain functions |
| T1059 | Command and Scripting Interpreter | DET-008 | ✅ Covered | Stage 1 correlation |
| T1204 | User Execution | DET-007 (loader) | ✅ Covered | CherryLoader CLI pattern |
| T1218.005 | Mshta | DET-003 | ✅ Covered | Remote URL argument; Microsoft domain exclusion |

---

## Persistence

| ID | Technique | Detection Rule | Coverage | Notes |
|----|-----------|---------------|----------|-------|
| T1547.009 | Shortcut Modification | DET-004 | ✅ Covered | Startup folder .lnk with Jupyter reference |
| T1547.001 | Registry Run Keys | DET-008 (correlated) | ⚠️ Partial | Covered in multi-stage context; no standalone rule |
| T1574.001 | DLL Search Order Hijacking | DET-008 (correlated) | ✅ Covered | Stage 2 correlation; technique tag required |
| T1053 | Scheduled Task/Job | None | ⚠️ Partial | No standalone detection; HUNT-003 addresses gap |
| T1546 | Event Triggered Execution (WMI) | None | ❌ Gap | No detection; HUNT-003 P2 priority |

---

## Defense Evasion

| ID | Technique | Detection Rule | Coverage | Notes |
|----|-----------|---------------|----------|-------|
| T1055.001 | DLL Injection | DET-008 (correlated) | ✅ Covered | Stage 3 correlation |
| T1564.003 | Hidden Window | DET-008 (correlated) | ✅ Covered | Stage 3 correlation |
| T1036.005 | Match Legitimate Name | DET-007 | ✅ Covered | CherryLoader masquerading as CherryTree |
| T1562.001 | Disable Security Tools | DET-008 (correlated) | ⚠️ Partial | Correlated only; standalone generates too much FP |
| T1027 | Obfuscated Files | DET-008 (correlated) | ⚠️ Partial | Correlated only |

---

## Lateral Movement & Impact

| ID | Technique | Detection Rule | Coverage | Notes |
|----|-----------|---------------|----------|-------|
| T1486 | Data Encrypted for Impact | Existing SIEM rule | ✅ Covered | File entropy + shadow copy deletion correlation |
| T1105 | Ingress Tool Transfer | HUNT-002 (LOLBin) | ⚠️ Partial | Mshta covered (DET-003); other LOLBins → HUNT-002 |

---

## Discovery & Collection

| ID | Technique | Detection Rule | Coverage | Notes |
|----|-----------|---------------|----------|-------|
| T1087 | Account Discovery | Existing SIEM rule | ✅ Covered | net user, Get-ADUser volume thresholds |
| T1082 | System Information Discovery | None | ⚠️ Partial | High FP standalone; useful only in kill chain context |
| T1005 | Data from Local System | DET-009 (partial) | ⚠️ Partial | Sensitive file access preceding LLM; broader coverage gap |
| T1558.003 | Kerberoasting | DET-008 (correlated) | ✅ Covered | Stage 4 correlation; Kerberos TGS request volume |

---

## Command & Control

| ID | Technique | Detection Rule | Coverage | Notes |
|----|-----------|---------------|----------|-------|
| T1219 | Remote Access Software | DET-006 | ⚠️ Partial | VS Code tunnel covered; ScreenConnect/TeamViewer → HUNT-005 |
| T1566.001 | Spearphishing Attachment | Email gateway | ⚠️ Partial | Email scanning covers known malicious attachments; novel attachments are a gap |
| T1572 | Protocol Tunneling | DET-006, DET-009 | ✅ Covered | VS Code tunnel + local LLM API exposure |
| T1048 | Exfiltration over Alternative Protocol | DET-009 | ⚠️ Partial | Local LLM exfil detection; network-based exfil needs DLP |

---

## AI / Emerging Risk

| ID | Technique | Detection Rule | Coverage | Notes |
|----|-----------|---------------|----------|-------|
| T1567 | Exfiltration over Web Service | DET-009 | ✅ Covered | Local LLM process + sensitive file access sequence |
| — | Shadow AI / Unauthorized Model Usage | DET-009 | ✅ Covered | Process and port-binding detection for local LLM runtimes |
| — | LLM Model Integrity (supply chain) | None | ❌ Gap | No detection for tampered GGUF model files; future work |

---

## Gap Remediation Map

| Gap | Addressed By | Priority |
|-----|-------------|----------|
| T1552.001 Credentials in Files (non-PS) | HUNT-001 | P1 |
| T1546 WMI Event Subscriptions | HUNT-003 | P2 |
| T1556 REST API authentication manipulation | HUNT-004 | P1 |
| T1105 LOLBin payload delivery (non-Mshta) | HUNT-002 | P3 |
| T1219 Remote access tool scope creep | HUNT-005 | P2 |
| LLM model integrity / supply chain | Future DET-011 | P3 |

---

*Last updated: March 2026. Coverage reflects MDR evaluation period Sep 2025 – Jan 2026 plus forward-looking AI risk additions.*
