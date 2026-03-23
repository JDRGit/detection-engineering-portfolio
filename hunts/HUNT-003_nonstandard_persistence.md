# HUNT-003: Persistence via Non-Standard Startup Mechanisms

**Priority:** P2
**Effort:** High
**Impact:** High
**Addresses Gap:** T1547 (broader), T1053, T1546
**Related Detections:** DET-004 (Shortcut/Jupyter), DET-008 (multi-stage correlated)

---

## Hypothesis

Current persistence detection focuses on Startup folder shortcuts (DET-004) and Registry Run keys (correlated in DET-008). Adversaries may achieve persistence via scheduled tasks, WMI event subscriptions, or COM object hijacking without triggering existing rules. These mechanisms are less monitored, harder to discover, and often persist across reboots and user logoffs.

**Confidence basis:** Multi-stage cases during the evaluation period showed persistence mechanisms in the kill chain (Stage 2 of DET-008), but the specific persistence technique was not always individually alerted — it was only surfaced through correlation. This hunt proactively inventories all persistence mechanisms to find what correlation misses.

---

## Data Sources Required

| Source | Platform | Availability |
|--------|----------|-------------|
| Scheduled task creation events | Windows Event Log (TaskScheduler/Operational) | Medium |
| WMI activity events | Windows Event Log (WMI-Activity/Operational) | Medium |
| Registry modification events | SentinelOne / Next-Gen SIEM | High |
| Process creation | SentinelOne / Next-Gen SIEM | High |

---

## Hunt Queries

### Track A: Scheduled Task Inventory

#### Query 1 — New scheduled tasks in last 90 days (Next-Gen SIEM/EDR)
```sql
FROM process
WHERE process_name IN ('schtasks.exe', 'at.exe')
AND arguments ILIKE '%/create%'
AND timestamp > now() - 90d
ORDER BY timestamp DESC
```

#### Query 2 — Scheduled tasks referencing user-writable paths (Next-Gen SIEM)
```sql
FROM process
WHERE process_name = 'schtasks.exe'
AND arguments ILIKE '%/create%'
AND (
  arguments ILIKE '%%TEMP%%'
  OR arguments ILIKE '%%APPDATA%%'
  OR arguments ILIKE '%%USERPROFILE%%'
  OR arguments ILIKE '%\Users\%\AppData\%'
  OR arguments ILIKE '%powershell%'
  OR arguments ILIKE '%-enc%'       -- encoded command
  OR arguments ILIKE '%-e %'        -- short form encoded
)
ORDER BY timestamp DESC
```

#### Query 3 — Windows Event Log: scheduled task registration (SIEM)
```
index=wineventlog EventCode=4698
| table _time, TaskName, TaskContent, SubjectUserName, SubjectDomainName
| eval suspicious=if(match(TaskContent,"(?i)(temp|appdata|userprofile|powershell.*-e[nc])"), "YES", "NO")
| where suspicious="YES"
```

---

### Track B: WMI Event Subscriptions

#### Query 4 — WMI permanent event subscriptions (Next-Gen SIEM)
```sql
FROM process
WHERE process_name = 'wmic.exe'
AND (
  arguments ILIKE '%EventFilter%'
  OR arguments ILIKE '%EventConsumer%'
  OR arguments ILIKE '%FilterToConsumerBinding%'
)
ORDER BY timestamp DESC
```

#### Query 5 — PowerShell WMI subscription creation (Next-Gen SIEM)
```sql
FROM process
WHERE event_type = 'scriptBlock'
AND (
  scriptblock_text ILIKE '%Set-WMIInstance%'
  OR scriptblock_text ILIKE '%New-CimInstance%'
  OR scriptblock_text ILIKE '%__EventFilter%'
  OR scriptblock_text ILIKE '%__EventConsumer%'
  OR scriptblock_text ILIKE '%CommandLineEventConsumer%'
  OR scriptblock_text ILIKE '%ActiveScriptEventConsumer%'
)
ORDER BY timestamp DESC
```

#### Query 6 — Enumerate existing WMI subscriptions (run on endpoint or via RMM)
```powershell
# Run this on suspect endpoints or via mass deployment
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
  Select Name, Query, QueryLanguage | Format-List

Get-WMIObject -Namespace root\subscription -Class __EventConsumer |
  Select Name, CommandLineTemplate, ScriptText | Format-List

Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Select Filter, Consumer | Format-List
```

---

### Track C: COM Hijacking

#### Query 7 — HKCU COM registrations (user-writable, no admin required) (Next-Gen SIEM)
```sql
FROM registry
WHERE registry_path ILIKE '%\SOFTWARE\Classes\CLSID\%'
AND registry_path ILIKE '%\InprocServer32%'
AND (
  registry_hive = 'HKCU'   -- user-writable, no elevation needed
  OR registry_value_data ILIKE '%%TEMP%%'
  OR registry_value_data ILIKE '%%APPDATA%%'
  OR registry_value_data ILIKE '%\Users\%\AppData\%'
)
ORDER BY timestamp DESC
```

---

## Analysis Methodology

### Scheduled Tasks
1. Pull all tasks created in last 90 days via Query 1
2. Compare against known-good baseline:
   - GPO-deployed tasks (document from Group Policy)
   - SCCM/Intune tasks (document from deployment platform)
   - Vendor tasks (document from software inventory)
3. Flag tasks with:
   - Executable in user-writable path
   - PowerShell with encoded commands
   - Created by non-admin user
   - Run at logon/startup from `\Users\` path

### WMI Subscriptions
4. Run Query 6 on all endpoints via RMM tool
5. **Any result is suspicious** — permanent WMI subscriptions are nearly always malicious in standard enterprise environments
6. For any found: retrieve subscription content, determine what it executes

### COM Hijacking
7. Query 7 surfaces HKCU CLSID registrations pointing to user-writable paths
8. Cross-reference CLSID values against known-legitimate CLSIDs
9. Unknown CLSIDs in HKCU pointing to `%TEMP%` or `%APPDATA%` = immediate investigation

---

## Expected Findings

| Category | Example | Action |
|----------|---------|--------|
| **Legitimate** | SCCM maintenance task created last week | Document in baseline |
| **Legitimate** | Antivirus scheduled scan task | Document in baseline |
| **Suspicious** | User-created task running PS script from `%APPDATA%` | Investigate |
| **Malicious** | WMI event subscription executing any command | Incident response |
| **Malicious** | Unknown CLSID in HKCU pointing to temp executable | Incident response |

---

## Success Criteria

- [ ] Complete inventory of scheduled tasks beyond known-good baseline
- [ ] All WMI event subscriptions enumerated — any found triggers investigation
- [ ] COM HKCU registrations inventoried and mapped to known software
- [ ] At least one persistence mechanism found that isn't covered by existing detections
- [ ] Detection coverage extended for any novel persistence patterns found
