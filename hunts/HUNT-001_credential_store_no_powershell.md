# HUNT-001: Credential Store Access Without PowerShell

**Priority:** P1
**Effort:** Medium
**Impact:** High
**Addresses Gap:** T1555, T1552.001
**Related Detection:** DET-005 (post-hunt automation)

---

## Hypothesis

Adversaries may access credential stores (Windows Vault, browser credential databases) via compiled executables or .NET assemblies rather than PowerShell, bypassing script block-based detections. Infostealer malware typically falls into this category — no PS, no script blocks, just a compiled binary reading files directly.

**Confidence basis:** The MDR evaluation period showed at least one credential access case where no PowerShell activity preceded vault file access. The accessing process was a compiled Go binary with no code signing.

---

## Data Sources Required

| Source | Platform | Availability |
|--------|----------|-------------|
| File access events with process attribution | SentinelOne / Next-Gen SIEM | High |
| Process creation with parent chain | SentinelOne / Next-Gen SIEM | High |
| Code signing status per process | SentinelOne | High |
| Process hash / reputation | SentinelOne + VirusTotal | Medium |

---

## Target Paths

```
# Windows Credential Manager
%APPDATA%\Microsoft\Credentials\*
%LOCALAPPDATA%\Microsoft\Credentials\*
%APPDATA%\Microsoft\Protect\*           # DPAPI master keys

# Chrome
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data

# Firefox
%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json
%APPDATA%\Mozilla\Firefox\Profiles\*\key4.db

# Edge
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

# Windows Vault (legacy)
%APPDATA%\Microsoft\Vault\*
%LOCALAPPDATA%\Microsoft\Vault\*
```

---

## Hunt Queries

### Query 1 — Non-browser processes accessing browser credential databases (Next-Gen SIEM)
```sql
FROM file
WHERE file_path ILIKE ANY (
  '%\Google\Chrome\User Data\Default\Login Data%',
  '%\Google\Chrome\User Data\Default\Cookies%',
  '%\Microsoft\Edge\User Data\Default\Login Data%',
  '%\Mozilla\Firefox\Profiles\%\logins.json%',
  '%\Mozilla\Firefox\Profiles\%\key4.db%'
)
AND event_type IN ('read', 'open', 'copy')
AND process_name NOT IN (
  'chrome.exe', 'msedge.exe', 'firefox.exe',
  'ChromeUpdate.exe', 'MicrosoftEdgeUpdate.exe',
  'MsMpEng.exe'    -- Defender scanning
)
ORDER BY timestamp DESC
LIMIT 500
```

### Query 2 — Unsigned executables accessing DPAPI paths (Next-Gen SIEM)
```sql
FROM file
WHERE (
  file_path ILIKE '%\AppData\Roaming\Microsoft\Credentials\%'
  OR file_path ILIKE '%\AppData\Local\Microsoft\Credentials\%'
  OR file_path ILIKE '%\AppData\Roaming\Microsoft\Protect\%'
)
AND event_type IN ('read', 'open')
AND process_signing_status != 'signed'
AND process_name NOT IN ('lsass.exe', 'svchost.exe')
ORDER BY timestamp DESC
```

### Query 3 — File copy operations targeting credential databases (Next-Gen SIEM)
```sql
FROM file
WHERE (
  source_path ILIKE '%Login Data%'
  OR source_path ILIKE '%logins.json%'
  OR source_path ILIKE '%key4.db%'
  OR source_path ILIKE '%\Credentials\%'
)
AND event_type = 'copy'
ORDER BY timestamp DESC
```

### Query 4 — Sigma: non-browser credential file access (portable)
```yaml
# Adapt to your SIEM
title: Non-Browser Process Accessing Browser Credential Database
detection:
  selection:
    TargetFilename|contains:
      - '\Google\Chrome\User Data\Default\Login Data'
      - '\Microsoft\Edge\User Data\Default\Login Data'
      - '\Mozilla\Firefox\Profiles\'
      - '\logins.json'
      - '\key4.db'
  filter_browsers:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\ChromeUpdate.exe'
  condition: selection and not filter_browsers
```

---

## Analysis Methodology

1. Run Query 1 for 30-day lookback, export results
2. Group results by `process_name` and `process_hash`
3. **Tier 1 — Immediate investigation:** unsigned processes, unknown hashes, processes from `%TEMP%` or `%APPDATA%`
4. **Tier 2 — Review and whitelist:** known legitimate tools (password managers, backup agents) — verify code signing before excluding
5. **Tier 3 — Baseline:** browser processes accessing their own files (expected, document as baseline)
6. For any Tier 1 hits: pivot to process tree, check what spawned the accessing process, check network connections from same process within ±5 minutes

---

## Expected Findings

| Category | Example | Action |
|----------|---------|--------|
| **Legitimate** | 1Password accessing its vault | Verify signing, add to allowlist |
| **Legitimate** | IT inventory scanner reading file metadata | Verify signing, add to allowlist |
| **Suspicious** | Unknown executable from `%TEMP%` reading Login Data | Investigate immediately |
| **Malicious** | Go/Rust binary with no signing reading Chrome DB + network connection | Incident response |

---

## Success Criteria

- [ ] Complete inventory of all processes accessing credential paths in 30-day window
- [ ] All Tier 1 (unsigned/unknown) hits triaged and dispositioned
- [ ] Allowlist created for legitimate tools with verification of code signing
- [ ] DET-005 tuned based on findings (add legitimate tool exclusions)
- [ ] At least one credential access variant identified that bypasses current PS-based detection

---

## Detection Rules Created from This Hunt

- **DET-005** (existing): Credential Vault Extraction via Non-System Process — tuning informed by hunt findings
- **Future DET-011** (if needed): Specific infostealer process indicators based on hunt findings
