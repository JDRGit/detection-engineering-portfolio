# HUNT-005: Remote Access Tool Scope Creep

**Priority:** P2
**Effort:** Low
**Impact:** Medium
**Addresses Gap:** T1219
**Related Detection:** DET-006 (VS Code tunnel — complements this hunt)

---

## Hypothesis

Approved remote access tools (ScreenConnect, TeamViewer, AnyDesk, LogMeIn) may have been installed on endpoints outside their approved deployment scope. Attackers frequently abuse legitimate remote access tools for persistent C2 because they blend with normal traffic, are rarely blocked by network controls, and generate no alerts when the tool itself is whitelisted.

**Confidence basis:** The MDR evaluation period included at least one case of VS Code tunnel usage from a non-developer workstation. The broader question: are other remote access tools present on endpoints where they shouldn't be?

---

## Data Sources Required

| Source | Platform | Availability |
|--------|----------|-------------|
| Application inventory | SentinelOne / SCCM / Intune | High |
| Process execution history | SentinelOne / Next-Gen SIEM | High |
| Network connections to RAT infrastructure | Next-Gen SIEM / proxy logs | High |
| Endpoint group membership | Active Directory / Intune | High |

---

## Target Remote Access Tools

```
# Enterprise remote support (should only be on approved endpoints)
ScreenConnect (ConnectWise Control)   → connectwise.com infrastructure
TeamViewer                            → teamviewer.com
AnyDesk                               → anydesk.com
LogMeIn / GoToAssist                  → logmein.com, goto.com
BeyondTrust Remote Support            → bomgar.com

# Developer tools (should only be on developer endpoints)
VS Code Tunnel / devtunnels.ms        → DET-006
GitHub Codespaces                     → github.dev, vscode.dev
Tailscale                             → tailscale.com, controlplane.tailscale.com

# Consumer-grade (should not be on any corporate endpoint)
TeamViewer personal                   → Different port/infra from enterprise
AnyDesk personal
Chrome Remote Desktop                 → remotedesktop.google.com
RustDesk                              → rustdesk.com (open-source, often used in attacks)
Zoho Assist                           → assist.zoho.com
```

---

## Hunt Queries

### Query 1 — Remote access tool process execution in last 30 days (Next-Gen SIEM)
```sql
FROM process
WHERE process_name IN (
  'ScreenConnect.ClientService.exe',
  'ConnectWiseControl.ClientService.exe',
  'TeamViewer.exe', 'TeamViewer_Service.exe',
  'AnyDesk.exe',
  'LogMeIn.exe', 'LMIGuardianSvc.exe',
  'rustdesk.exe',
  'ZohoAssist.exe',
  'chrome_remote_desktop_host.exe'
)
GROUP BY process_name, host_name, user_name
ORDER BY count DESC
```

### Query 2 — Network connections to remote access infrastructure (Next-Gen SIEM)
```sql
FROM network
WHERE (
  destination_domain ILIKE '%screenconnect.com%'
  OR destination_domain ILIKE '%connectwise.com%'
  OR destination_domain ILIKE '%teamviewer.com%'
  OR destination_domain ILIKE '%anydesk.com%'
  OR destination_domain ILIKE '%logmein.com%'
  OR destination_domain ILIKE '%goto.com%'
  OR destination_domain ILIKE '%rustdesk.com%'
  OR destination_domain ILIKE '%tailscale.com%'
  OR destination_domain ILIKE '%devtunnels.ms%'
)
AND direction = 'outbound'
GROUP BY host_name, destination_domain, user_name
ORDER BY count DESC
```

### Query 3 — Remote access tools installed but not in approved deployment list (Next-Gen SIEM)
```sql
-- Requires integration with asset inventory
FROM software_inventory
WHERE software_name IN (
  'TeamViewer', 'AnyDesk', 'ScreenConnect', 'LogMeIn',
  'RustDesk', 'Zoho Assist', 'Chrome Remote Desktop Host'
)
AND host_name NOT IN (SELECT host_name FROM approved_rat_deployments)
ORDER BY host_name
```

### Query 4 — User-installed (non-admin) remote access tools (Next-Gen SIEM)
```sql
FROM process
WHERE process_name IN (known_rat_processes)
AND process_path ILIKE '%\Users\%\AppData\%'   -- user-writable path, no admin needed
AND NOT process_path ILIKE '%\Program Files%'  -- admin-installed path
ORDER BY timestamp DESC
```

---

## Analysis Methodology

1. Pull complete application inventory via SentinelOne or SCCM for known RAT executables
2. Cross-reference against IT/Help Desk's approved deployment list:
   - Which endpoints have ScreenConnect approved? (Help desk managed devices)
   - Which endpoints have TeamViewer approved? (Vendor remote support contracts)
   - Which endpoints have VS Code approved? (Developer group only)
3. **Flag any endpoint where:**
   - Tool is installed but not in approved scope
   - Tool version differs from the corporate-managed version (possible attacker-installed alternative)
   - Tool was installed by non-admin user (user-writable path installation)
   - Tool connects to infrastructure that doesn't match the corporate account ID
4. For VS Code tunnel: run Query from DET-006 to find devtunnels.ms connections from non-developer endpoints

---

## Infrastructure Fingerprinting

To distinguish corporate-managed vs. attacker-installed instances of the same tool:

```
ScreenConnect: Check server hostname in client config
  Corporate: controlled.yourcorp.com
  Attacker: instance.screenconnect.com (default cloud)

TeamViewer: Check TeamViewer ID and assigned account
  Corporate: assigned to corporate IT account
  Attacker: unassigned or assigned to personal account

AnyDesk: Check AnyDesk network setting
  Corporate: custom namespace (corp.anydesk.com)
  Attacker: public AnyDesk network
```

---

## Expected Findings

| Category | Example | Action |
|----------|---------|--------|
| **Expected** | ScreenConnect on help desk-managed endpoints | Document scope, confirm version |
| **Policy Issue** | TeamViewer on executive workstation (vendor support) | Verify approval, document |
| **Suspicious** | ScreenConnect installed from `%APPDATA%` | Investigate immediately |
| **Suspicious** | AnyDesk connecting to non-corporate namespace on server | Investigate — servers rarely need remote support tools |
| **Malicious** | RustDesk or unknown RAT on any endpoint | Incident response |

---

## Success Criteria

- [ ] Complete inventory of remote access tool installations mapped against approved scope
- [ ] All out-of-scope installations investigated and remediated or documented with exception
- [ ] Version check completed — all corporate tools running approved versions
- [ ] Infrastructure fingerprint check completed — all tools connecting to corporate infrastructure
- [ ] Detection rules updated to flag any new out-of-scope RAT installations going forward
- [ ] DET-006 (VS Code) confirmed effective; scope expanded to any new developer tool variants if needed
