# Playbook: Identity & Cloud Incident Response

**Version:** 1.0
**Scope:** Azure AD / Microsoft Entra ID compromise — stolen credentials, token theft, MFA bypass, identity infrastructure manipulation
**Triggers:** DET-001, DET-002, DET-010 alerts; impossible travel; AADInternals activity; MFA push bombing
**Severity:** HIGH to CRITICAL

---

## Overview

Identity-based attacks are the highest-impact threat category in cloud-first environments. Unlike endpoint compromise, identity compromise gives an attacker persistent, geographically unconstrained access with minimal forensic footprint. Compromised credentials + token theft = attacker indistinguishable from a legitimate user.

This playbook covers the full response lifecycle from initial alert to recovery and hardening.

---

## Phase 1: Initial Triage (0–15 minutes)

### 1.1 Confirm the Alert

| Alert Source | Initial Validation Question |
|-------------|----------------------------|
| DET-002 (Impossible Travel) | Are both source IPs from the same user session or different sessions? |
| DET-001 (AADInternals) | Was this an authorized identity team assessment? Check change calendar. |
| DET-010 (MFA bombing) | Did the user themselves initiate repeated MFA? Contact user OOB immediately. |
| Manual report | Who reported it? What behavior prompted the report? |

### 1.2 Out-of-Band User Contact

**CRITICAL:** Contact the user via phone or Slack (not email — attacker may control email) to:
- Confirm whether they recognize the activity
- Ask if they received and approved any unexpected MFA push notifications
- Advise them NOT to take any account actions until instructed

**Do not notify via email** — if the attacker has mailbox access, this tips them off.

### 1.3 Initial Scope Assessment

```kql
// Get all authentication events for affected user in last 24h
SigninLogs
| where UserPrincipalName == "affected.user@corp.com"
| where TimeGenerated > ago(24h)
| project TimeGenerated, IPAddress, AppDisplayName, ResourceDisplayName,
          ResultType, AuthenticationRequirement, ConditionalAccessStatus,
          DeviceDetail, Location
| order by TimeGenerated desc
```

**Key questions to answer in triage:**
- [ ] Is the attacker still actively authenticated (live session)?
- [ ] Has the attacker accessed any sensitive resources (email, SharePoint, admin portals)?
- [ ] Are there signs of lateral movement (other accounts accessed, admin actions taken)?
- [ ] What is the attacker's entry point (phishing, password spray, token theft)?

---

## Phase 2: Containment (15–60 minutes)

### 2.1 Immediate Account Actions

**Severity: CRITICAL (confirmed active attacker)**
```
1. [ ] Disable affected user account in Azure AD
       Azure Portal → Users → [user] → Block sign-in: Yes
       OR: Set-MgUserBlockedSignin -UserId [UPN] -AccountEnabled $false

2. [ ] Revoke all active sessions and refresh tokens
       Azure Portal → Users → [user] → Revoke sessions
       OR: Invoke-MgInvalidateUserRefreshToken -UserId [UPN]

3. [ ] Force re-authentication for all applications
       This is automatic after token revocation

4. [ ] Reset user password (generates new credential hash)
       Force change on next sign-in = WRONG (attacker knows this)
       Generate random 32+ char password, deliver to user OOB
```

**Severity: HIGH (suspected compromise, not confirmed)**
```
1. [ ] Enforce step-up MFA for all user sessions
2. [ ] Revoke refresh tokens (keeps account active, kills stolen sessions)
3. [ ] Monitor actively before full account disable
```

### 2.2 Token Revocation Verification

Token revocation is not instantaneous. Verify effectiveness:

```kql
// Check for sign-ins AFTER revocation (should see 0 successful)
SigninLogs
| where UserPrincipalName == "affected.user@corp.com"
| where TimeGenerated > [revocation_timestamp]
| where ResultType == 0  // Successful
| project TimeGenerated, IPAddress, AppDisplayName, SessionId
```

**If successful sign-ins appear after revocation:** The attacker may have obtained a Primary Refresh Token (PRT) or device-bound token that survived revocation. Escalate to device isolation.

### 2.3 Conditional Access Emergency Controls

If the organization has a Conditional Access policy framework:

```
1. [ ] Block all sign-ins from attacker source IPs/ASN
       CA Policy → IP conditions → Named locations → Add attacker IPs as blocked

2. [ ] Require compliant device for all access (if not already enforced)
       Catches token theft from non-corporate devices

3. [ ] Enable "Require authentication strength" for privileged operations
       Blocks stolen tokens from performing admin actions
```

### 2.4 Privileged Access Review

If the compromised account has any admin roles:

```kql
// Check all admin actions taken by compromised account in last 72h
AuditLogs
| where InitiatedBy has "affected.user@corp.com"
| where TimeGenerated > ago(72h)
| where Category in ("RoleManagement", "ApplicationManagement",
                     "GroupManagement", "UserManagement",
                     "Policy", "Authentication")
| project TimeGenerated, OperationName, TargetResources, Result
| order by TimeGenerated desc
```

**For each admin action found:** Determine if it was attacker-initiated and if it needs to be reversed (role assignments, app consents, policy changes, new user accounts).

---

## Phase 3: Investigation (1–4 hours)

### 3.1 Establish Attack Timeline

Build a full timeline of attacker activity:

```kql
// Comprehensive activity timeline for affected user
let user = "affected.user@corp.com";
let start_time = datetime(YYYY-MM-DD);

union withsource=TableName
  (SigninLogs | where UserPrincipalName == user),
  (AuditLogs | where InitiatedBy has user),
  (OfficeActivity | where UserId == user),
  (CloudAppEvents | where AccountObjectId == user_object_id)
| where TimeGenerated between(start_time .. now())
| project TimeGenerated, TableName, OperationName, IPAddress,
          AppDisplayName, Result, AdditionalInfo=tostring(pack_all())
| order by TimeGenerated asc
```

### 3.2 Identify Initial Compromise Vector

| Evidence | Likely Vector |
|----------|--------------|
| Password spray patterns (many failed logins before success) | Credential stuffing / spray |
| Impossible travel immediately at first login | Session token theft (existing token reused) |
| MFA push bombing followed by successful MFA | MFA fatigue — user approved a push |
| AADInternals functions executed | Advanced token theft / PRT extraction |
| No prior failed logins + new location | Credential purchase (dark web) |

### 3.3 Mailbox and Data Access Review

```kql
// Review email access by attacker
OfficeActivity
| where UserId == "affected.user@corp.com"
| where TimeGenerated > [first_attacker_activity]
| where Operation in (
    "MailItemsAccessed", "Send", "SearchQueryPerformed",
    "Set-Mailbox", "New-InboxRule", "Set-InboxRule"
)
| project TimeGenerated, Operation, ClientIPAddress, ResultStatus, AffectedItems
| order by TimeGenerated asc
```

**High-risk findings to escalate:**
- Inbox rules created (especially forwarding rules → external address)
- Mass email access (MailItemsAccessed with large item count)
- Emails sent from compromised account
- SharePoint/OneDrive file access or downloads

### 3.4 Azure AD Infrastructure Integrity Check

Run HUNT-004 queries to verify no identity infrastructure was modified during the compromise window. Pay special attention to:
- CA policy changes
- New application registrations or consent grants
- PTA agent modifications
- New users created or roles assigned

---

## Phase 4: Eradication (2–8 hours)

### 4.1 Remove Attacker Persistence

Based on investigation findings, systematically remove any backdoors created:

```
1. [ ] Delete any inbox rules created by attacker
       Remove-InboxRule -Mailbox [user] -Identity [rule_name]

2. [ ] Revoke any application consents granted during compromise
       Azure Portal → Enterprise Applications → [app] → Permissions → Revoke

3. [ ] Remove any service principal credentials added by attacker
       Azure Portal → App Registrations → [app] → Certificates & secrets

4. [ ] Delete any accounts created by attacker
       Audit Log: AddUser operations during compromise window

5. [ ] Revert any role assignments added by attacker
       Audit Log: Add member to role operations during window

6. [ ] Review and revert CA policy changes if any were made

7. [ ] Remove any registered devices added by attacker
       Azure AD → Devices → filter by registration date during window
```

### 4.2 Credential Hygiene for Affected User

```
1. [ ] Reset password (already done in 2.1)
2. [ ] Re-register MFA methods (attacker may have registered their own authenticator)
       Azure AD → Users → [user] → Authentication methods → remove attacker methods
3. [ ] Issue hardware token (FIDO2 key) if user is high-value target
4. [ ] Review and re-confirm all trusted locations and remembered devices
```

---

## Phase 5: Recovery (4–24 hours)

### 5.1 Re-enable Account

```
1. [ ] Re-enable account after eradication is complete
2. [ ] Require fresh MFA registration (new methods, new device)
3. [ ] Enforce "Sign-in frequency: every session" for 30 days post-incident
4. [ ] Brief user on what happened and what to watch for
```

### 5.2 Business Impact Assessment

- [ ] Identify all resources accessed during compromise window
- [ ] Determine if any regulated data (PII, PHI, financial records) was accessed
- [ ] Notify Data Privacy team if regulatory reporting may be required
- [ ] Identify business partners/customers who may need notification

---

## Phase 6: Post-Incident Hardening

### 6.1 Detection Improvements

Based on how the attacker evaded or was detected:

| Gap Found | Improvement |
|-----------|-------------|
| Token theft not detected | Deploy Continuous Access Evaluation |
| MFA bombing bypassed | Enable number matching on MFA; consider FIDO2 for high-value users |
| API-based manipulation not detected | Implement HUNT-004 as recurring audit |
| Inbox rules not detected | Enable alert on new inbox forwarding rules |

### 6.2 Preventive Controls

```
Short-term (1 week):
[ ] Enable number matching for all Authenticator push approvals
[ ] Enable additional context (app name, geo) on push notifications
[ ] Verify Conditional Access: "Require compliant or hybrid-joined device"

Medium-term (1 month):
[ ] Evaluate FIDO2 hardware keys for privileged/high-value accounts
[ ] Deploy Microsoft Entra ID Protection (risk-based CA)
[ ] Enable Continuous Access Evaluation for M365 workloads

Long-term (1 quarter):
[ ] MFA-resistant authentication (Passkeys/FIDO2) for all users
[ ] Zero-trust network access review
[ ] Privileged Identity Management (PIM) for admin roles
```

---

## Escalation Matrix

| Condition | Escalate To | SLA |
|-----------|------------|-----|
| Active attacker with admin access | CISO + Legal | Immediate |
| Regulated data accessed (PII/PHI) | Legal + Privacy Officer | < 1 hour |
| Identity infrastructure modified (CA, federation) | CISO + Azure Admin | Immediate |
| Multiple accounts compromised | Incident Commander | < 30 min |
| C-suite / executive account | CISO + Executive Assistant | Immediate |

---

## Evidence Preservation

Before any remediation that might destroy evidence:

```
1. Export sign-in logs for affected user (90-day window)
2. Export audit logs for all changes made by or to affected account
3. Export email headers for suspicious emails during compromise window
4. Screenshot or export: all inbox rules, CA policy states, app consent grants
5. Document all actions taken during response with timestamps
```

---

*Related: HUNT-004 (Cloud Identity API), DET-001 (AADInternals), DET-002 (Impossible Travel), DET-010 (MFA Bombing)*
