# HUNT-002: LOLBin Payload Delivery Beyond Mshta

**Priority:** P3
**Effort:** Medium
**Impact:** Medium
**Addresses Gap:** T1105, T1218 (broader)
**Related Detection:** DET-003 (Mshta covered; other LOLBins are this hunt's scope)

---

## Hypothesis

While mshta.exe is detected by DET-003, adversaries may use other living-off-the-land binaries (certutil, bitsadmin, desktopimgdownldr, esentutl, curl) for payload retrieval. These LOLBins are signed Microsoft binaries with legitimate use cases, making them difficult to block outright and noisy to alert on broadly.

**Confidence basis:** LOLBin usage for payload delivery was a background theme across multiple MDR cases. The mshta case (SIR-REDACT-07) was the most prominent, but the broader LOLBin surface area wasn't systematically mapped.

---

## Data Sources Required

| Source | Platform | Availability |
|--------|----------|-------------|
| Process creation with full command line | SentinelOne / Next-Gen SIEM | High |
| Network connections with process attribution | SentinelOne / Next-Gen SIEM | High |
| DNS resolution with process attribution | SentinelOne / Next-Gen SIEM | Medium |
| File creation events | SentinelOne / Next-Gen SIEM | High |

---

## Target LOLBins

```
certutil.exe        # -urlcache -split -f http://...  OR  -decode base64
bitsadmin.exe       # /transfer JobName http://url local_path
desktopimgdownldr   # /lockscreenurl:http://...
esentutl.exe        # /y \\remote\share\payload /d local_path
curl.exe            # Present on Windows 10+ by default
wget.exe            # If installed (uncommon natively)
msedge.exe          # --headless --dump-dom http://... (unusual flag)
expand.exe          # Decompressing payloads
extrac32.exe        # CAB extraction
makecab.exe         # Payload packing/staging
```

---

## Hunt Queries

### Query 1 — Certutil with URL or decode arguments (Next-Gen SIEM)
```sql
FROM process
WHERE process_name ILIKE '%certutil.exe%'
AND (
  arguments ILIKE '%-urlcache%'
  OR arguments ILIKE '%-decode%'
  OR arguments ILIKE '%http://%'
  OR arguments ILIKE '%https://%'
  OR arguments ILIKE '%ftp://%'
)
ORDER BY timestamp DESC
LIMIT 200
```

### Query 2 — BITSAdmin job creation with external URLs (Next-Gen SIEM)
```sql
FROM process
WHERE process_name ILIKE '%bitsadmin.exe%'
AND arguments ILIKE '%/transfer%'
AND (
  arguments ILIKE '%http://%'
  OR arguments ILIKE '%https://%'
  OR arguments ILIKE '%ftp://%'
)
AND NOT arguments ILIKE '%windowsupdate.com%'
AND NOT arguments ILIKE '%microsoft.com%'
ORDER BY timestamp DESC
```

### Query 3 — Any LOLBin with network connection followed by file creation (Next-Gen SIEM)
```sql
-- Step 1: Find LOLBin network connections to external IPs
FROM network
WHERE process_name IN (
  'certutil.exe', 'bitsadmin.exe', 'desktopimgdownldr.exe',
  'esentutl.exe', 'curl.exe', 'expand.exe', 'extrac32.exe'
)
AND direction = 'outbound'
AND NOT (
  destination_ip ILIKE '10.%'
  OR destination_ip ILIKE '172.16.%'
  OR destination_ip ILIKE '192.168.%'
)
CORRELATE process_id, host_id
-- Step 2: Join to file creation by same process within 5 minutes
WITHIN 5m -> FROM file WHERE event_type = 'create'
ORDER BY timestamp DESC
```

### Query 4 — Sigma portable rule: certutil URL cache
```yaml
title: Certutil URL Cache Download
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '/urlcache'
  filter_legitimate:
    CommandLine|contains:
      - 'microsoft.com'
      - 'windowsupdate.com'
  condition: selection and not filter_legitimate
level: high
tags:
  - attack.t1105
  - attack.t1218
```

---

## Analysis Methodology

1. Build 30-day baseline of LOLBin execution patterns per host
2. Group by LOLBin, argument pattern, destination, and initiating user
3. **Priority triage:**
   - LOLBins with arguments containing uncategorized/unknown external URLs → immediate review
   - LOLBins run from interactive user sessions (not SYSTEM or scheduled tasks) → review
   - LOLBins followed within 5 minutes by a new file creation + execution → critical
4. Compare destination URLs/IPs against threat intelligence feeds
5. For any suspicious hits: trace the full execution chain backward (what spawned the LOLBin?) and forward (what ran after?)

---

## Baseline Building

```sql
-- Build LOLBin inventory for the last 30 days
FROM process
WHERE process_name IN (
  'certutil.exe', 'bitsadmin.exe', 'desktopimgdownldr.exe',
  'esentutl.exe', 'curl.exe', 'expand.exe', 'extrac32.exe', 'makecab.exe'
)
GROUP BY process_name, arguments_normalized, user_context, parent_process_name
ORDER BY count DESC
```

---

## Expected Findings

| Category | Example | Action |
|----------|---------|--------|
| **Legitimate** | certutil for certificate management via SCCM | Document as baseline |
| **Legitimate** | BITS for Windows Update (background) | Document as baseline |
| **Suspicious** | certutil -urlcache to uncategorized domain by user | Investigate URL, check file created |
| **Malicious** | certutil decode of base64 blob → execution | Incident response |

---

## Success Criteria

- [ ] Complete inventory of LOLBin usage in 30-day window
- [ ] All usage mapped to: authorized/expected, unexplained, or malicious
- [ ] Detection rules created for any unmapped LOLBin payload delivery patterns
- [ ] Baseline documented for ongoing anomaly detection (new LOLBin usage stands out)
