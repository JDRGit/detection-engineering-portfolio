# Hunt Hypotheses 

Derived from blind spots and coverage gaps identified in the Detection Coverage Matrix. Each hypothesis targets detection weaknesses that cannot be fully addressed through automated rules alone.

---

## Hunt 1: Credential Store Access Without PowerShell

**Hypothesis:** Adversaries may be accessing credential stores (Windows Vault, browser credential databases) via compiled executables or .NET assemblies rather than PowerShell, bypassing current script block-based detections.

**Addresses Gap In:** T1555, T1552.001

**Data Sources:**
- File access events on known credential file paths
- Process creation events with file handle access to sensitive paths

**Target File Paths:**
```
# Chrome
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data

# Firefox
%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json
%APPDATA%\Mozilla\Firefox\Profiles\*\key4.db

# Edge
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

# Windows Vault
%APPDATA%\Microsoft\Vault\*
%LOCALAPPDATA%\Microsoft\Vault\*
```

**Hunt Method:**
1. Query for non-browser, non-security-tool processes accessing browser credential database files
2. Cross-reference with process reputation and code signing status
3. Flag unsigned executables or executables from user-writable paths accessing credential stores
4. Look for file copy operations targeting credential database files (the infostealer case showed Chrome's database being copied)

**Expected Findings:**
- Legitimate: Browser updates, credential migration tools, IT inventory scanners
- Suspicious: Unknown executables from Temp/Downloads accessing credential files
- Malicious: Processes spawned from document applications or email clients accessing credential stores

**Success Criteria:** Identify at least one credential access technique variant not caught by existing PowerShell-based detections.

---

## Hunt 2: LOLBin Payload Delivery Beyond Mshta

**Hypothesis:** While mshta.exe is well-detected, adversaries may be using other living-off-the-land binaries (certutil, bitsadmin, desktopimgdownldr, esentutl) for payload retrieval without triggering existing detections.

**Addresses Gap In:** T1105, T1218 (broader)

**Data Sources:**
- Process creation events for known LOLBins
- Network connection events from LOLBin processes

**Target LOLBins:**
```
certutil.exe        # -urlcache -split -f http://...
bitsadmin.exe       # /transfer http://...
desktopimgdownldr   # /lockscreenurl:http://...
esentutl.exe        # /y \\remote\share\payload /d local_copy
curl.exe            # Present on Windows 10+ by default
wget.exe            # If installed
msedge.exe          # --headless --dump-dom can fetch content
```

**Hunt Method:**
1. Build a 30-day baseline of LOLBin execution patterns
2. Identify instances where LOLBins are executed with arguments containing URLs, IP addresses, or UNC paths not in the corporate domain whitelist
3. Focus on LOLBins with network-related arguments executed from interactive user sessions (not SYSTEM/scheduled tasks)
4. Correlate with subsequent execution of newly-created files

**Expected Findings:**
- Legitimate: certutil for certificate management, BITS for Windows Update
- Suspicious: certutil with -urlcache to uncategorized domains
- Malicious: Any LOLBin fetching payload followed by execution of downloaded content

**Success Criteria:** Map all LOLBin usage in the environment; create new detection rules for any unmapped LOLBin-based payload delivery patterns.

---

## Hunt 3: Persistence via Non-Standard Startup Mechanisms

**Hypothesis:** Current persistence detection focuses on Startup folder shortcuts and Registry Run keys. Adversaries may be using scheduled tasks, WMI event subscriptions, or COM object hijacking for persistence without triggering existing rules.

**Addresses Gap In:** T1547 (broader), T1053, T1546

**Data Sources:**
- Scheduled task creation events (Microsoft-Windows-TaskScheduler/Operational)
- WMI event subscription creation (Microsoft-Windows-WMI-Activity/Operational)
- COM registration changes (Registry modifications under HKCR\CLSID)

**Hunt Method:**
1. Enumerate all scheduled tasks created in the past 90 days
2. Compare against known-good baseline (GPO-deployed tasks, SCCM tasks, Intune tasks)
3. Flag new scheduled tasks that:
   - Reference executables in user-writable paths (%TEMP%, %APPDATA%, %USERPROFILE%)
   - Were created by non-admin processes
   - Execute PowerShell with encoded commands
   - Run at logon or on a recurring schedule from non-standard locations
4. Enumerate WMI event subscriptions; any permanent event subscription warrants investigation
5. Review COM registrations for InprocServer32 values pointing to user-writable paths

**Expected Findings:**
- Legitimate: SCCM/Intune management tasks, IT automation, backup software
- Suspicious: User-created tasks referencing scripts in profile directories
- Malicious: WMI event subscriptions (very rarely legitimate in standard enterprise)

**Success Criteria:** Complete inventory of persistence mechanisms beyond Run keys and Startup shortcuts; identify at least one persistence mechanism not covered by existing detections.

---

## Hunt 4: Cloud Identity Infrastructure Manipulation via API

**Hypothesis:** AADInternals is detected via PowerShell, but adversaries may be performing similar Azure AD/Entra ID manipulation via direct REST API calls, Azure CLI, or Microsoft Graph PowerShell module without leaving AADInternals-specific artifacts.

**Addresses Gap In:** T1556, T1528 (API-based variants)

**Data Sources:**
- Azure AD audit logs (AuditLogs in Log Analytics)
- Microsoft Graph activity logs
- Entra ID sign-in logs with application context

**Hunt Method:**
1. Review Azure AD audit logs for the past 90 days focusing on:
   - PTA agent registration/modification
   - New device joins from unexpected sources
   - Authentication flow changes (federation settings, conditional access modifications)
   - Application consent grants with high-privilege Graph permissions
2. Look for API calls performing the same operations as AADInternals functions but from non-PowerShell clients
3. Check for new application registrations with Mail.ReadWrite, Directory.ReadWrite.All, or similar permissions
4. Review service principal credential additions/rotations

**Expected Findings:**
- Legitimate: IT-approved application registrations, automated provisioning tools
- Suspicious: Application registrations from personal accounts with broad permissions
- Malicious: PTA agent modifications, federation setting changes, or token issuance from unrecognized sources

**Success Criteria:** Verify that all Azure AD infrastructure changes in the audit period were authorized; identify any API-based manipulation patterns that need new detection rules.

---

## Hunt 5: Remote Access Tool Scope Creep

**Hypothesis:** Approved remote access tools (ScreenConnect, TeamViewer) may have been installed on endpoints outside their approved deployment scope, creating potential C2 channels that bypass detection because the tool itself is whitelisted.

**Addresses Gap In:** T1219

**Data Sources:**
- Application inventory (SentinelOne application inventory, SCCM software inventory)
- Network connections to remote access tool infrastructure
- Endpoint group membership vs. approved deployment scope

**Hunt Method:**
1. Pull complete list of endpoints with ScreenConnect, TeamViewer, AnyDesk, LogMeIn installed
2. Cross-reference against approved deployment list from IT/Help Desk
3. Flag any endpoint where:
   - Tool is installed but not in the approved scope
   - Tool version differs from the corporate-managed version
   - Tool was installed by a non-admin user
   - Tool connects to infrastructure not matching the corporate account
4. For VS Code specifically: identify all endpoints with devtunnels.ms connections that are not in developer groups

**Expected Findings:**
- Legitimate: Help desk tools on endpoints in support scope
- Suspicious: ScreenConnect on servers where no remote support should be needed
- Malicious: Unknown remote access tools or tools connecting to non-corporate infrastructure

**Success Criteria:** Complete inventory of remote access tool installations mapped against approved scope; remediate any out-of-scope installations; update detection rules to flag new out-of-scope installations automatically.

---

## Execution Priority

| Hunt | Effort | Impact | Priority |
|------|--------|--------|----------|
| Hunt 1: Credential Store Access | Medium | High | **P1** |
| Hunt 4: Cloud Identity API | Medium | High | **P1** |
| Hunt 5: Remote Access Scope | Low | Medium | **P2** |
| Hunt 3: Non-Standard Persistence | High | High | **P2** |
| Hunt 2: LOLBin Delivery | Medium | Medium | **P3** |

Hunts 1 and 4 are prioritized because they address the highest-impact blind spots identified in the coverage matrix: credential theft and identity infrastructure manipulation via methods that bypass current PowerShell-centric detections.
