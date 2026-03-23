# HUNT-004: Cloud Identity Infrastructure Manipulation via API

**Priority:** P1
**Effort:** Medium
**Impact:** High
**Addresses Gap:** T1556, T1528 (API-based variants)
**Related Detection:** DET-001 (PowerShell vector covered; REST API is this hunt's gap)

---

## Hypothesis

AADInternals is detected via PowerShell (DET-001), but adversaries performing identical Azure AD/Entra ID manipulation via direct REST API calls, Azure CLI, or Microsoft Graph PowerShell module would not trigger script block logging. An attacker with a stolen access token can replicate most AADInternals operations using standard HTTP requests — no suspicious PowerShell required.

**Confidence basis:** The AADInternals case (SIR-REDACT-01) used PowerShell and was caught. The open question is whether similar identity manipulation was occurring via API calls that weren't detected. This hunt validates coverage by auditing Azure AD changes for the evaluation period.

---

## Data Sources Required

| Source | Platform | Availability |
|--------|----------|-------------|
| Azure AD Audit Logs | Microsoft Entra / Log Analytics | High |
| Microsoft Graph activity logs | Microsoft Entra | Medium |
| Azure AD Sign-in logs with application context | Microsoft Entra | High |
| Conditional Access policy change logs | Microsoft Entra | High |

---

## Hunt Queries

### Query 1 — PTA Agent Registration / Modification (KQL - Log Analytics)
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in (
    "Add on-premises passthrough authentication agent",
    "Update on-premises passthrough agent",
    "Delete on-premises passthrough agent",
    "Update agent group"
)
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

### Query 2 — New Device Joins from Unexpected Sources (KQL)
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in ("Add device", "Register device")
| extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatingIP = tostring(InitiatedBy.user.ipAddress)
| extend DeviceName = tostring(TargetResources[0].displayName)
| where InitiatingIP !startswith "10."
    and InitiatingIP !startswith "172.16."
    and InitiatingIP !startswith "192.168."
| project TimeGenerated, InitiatingUser, InitiatingIP, DeviceName, Result
| order by TimeGenerated desc
```

### Query 3 — Federation / Trust Settings Changes (KQL)
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in (
    "Set federation settings on domain",
    "Set domain authentication",
    "Add unverified domain to company",
    "Update domain"
)
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

### Query 4 — High-Privilege Application Consent Grants (KQL)
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in (
    "Consent to application",
    "Add app role assignment to service principal"
)
| extend GrantedPermissions = tostring(TargetResources[0].modifiedProperties)
| where GrantedPermissions contains "Mail.ReadWrite"
    or GrantedPermissions contains "Directory.ReadWrite.All"
    or GrantedPermissions contains "RoleManagement.ReadWrite.Directory"
    or GrantedPermissions contains "Application.ReadWrite.All"
| project TimeGenerated, OperationName, InitiatedBy, GrantedPermissions
| order by TimeGenerated desc
```

### Query 5 — Service Principal Credential Additions (KQL)
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in (
    "Add service principal credentials",
    "Update service principal",
    "Add service principal"
)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend SP = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, SP, Result
| order by TimeGenerated desc
```

### Query 6 — Conditional Access Policy Modifications (KQL)
```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName in (
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy",
    "Disable conditional access policy"
)
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

### Query 7 — API Calls Mimicking AADInternals Functions (KQL)
```kql
// Look for Microsoft Graph calls matching AADInternals PRT / token operations
// These appear as application sign-ins with specific resource/scope combinations
SigninLogs
| where TimeGenerated > ago(90d)
| where AppId in (
    "1b730954-1685-4b74-9bfd-dac224a7b894",  // Azure Active Directory PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   // Azure CLI
)
| where ResourceDisplayName in (
    "Windows Azure Active Directory",
    "Microsoft Graph"
)
| extend Scopes = tostring(AuthenticationDetails)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResourceDisplayName, ResultType
| where ResultType == 0  // Successful only
| order by TimeGenerated desc
```

---

## Analysis Methodology

1. Run all queries against 90-day audit log window
2. **Query 1 (PTA):** Any PTA agent modification should match a change ticket. Zero unauthorized changes should exist.
3. **Query 2 (Device joins):** All device joins from external IPs warrant review — legitimate device joins typically originate from corporate IPs or known VPN egress
4. **Query 3 (Federation):** Federation changes are extremely rare and high-risk. ANY finding here is critical.
5. **Query 4 (App consent):** Map granted permissions to approved application registrations. Any high-privilege consent not in the approved registry is suspicious.
6. **Query 5 (SP credentials):** New credentials on service principals should map to rotation records in ITSM
7. **Query 6 (CA policies):** All CA changes should map to approved change requests. CA weakening (e.g., disabling a policy) is especially critical.

---

## Expected Findings

| Category | Example | Action |
|----------|---------|--------|
| **Authorized** | IT admin rotated SP credentials per quarterly schedule | Verify change ticket, document |
| **Authorized** | New device join from corporate VPN egress | Document as expected |
| **Suspicious** | App consent with Directory.ReadWrite.All from personal account | Investigate immediately |
| **Critical** | CA policy disabled with no change ticket | Treat as active incident |
| **Critical** | Federation settings changed | Treat as active incident; check for Golden SAML |

---

## Success Criteria

- [ ] All Azure AD infrastructure changes in 90-day window mapped to authorized change records
- [ ] No unexplained PTA agent modifications, federation changes, or CA policy disables
- [ ] Any API-based manipulation patterns identified that need new detection rules
- [ ] Decision documented: does current detection coverage need supplemental Azure AD audit log alerting?
