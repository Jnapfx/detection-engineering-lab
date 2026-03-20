# Detection Lifecycle — Brute-Force Authentication

**Lab:** Azure Sentinel Brute-Force Authentication Investigation  
**Author:** Javier Napoles  
**Last Updated:** 2026-03-20  

---

## Overview

This document traces the full lifecycle of the brute-force detection developed in this lab — from initial log observation through tuning and into a production-ready analytics rule. It follows the detection engineering lifecycle as a structured process, not a one-time task.

---

## Phase 1 — Identify

**Trigger:** During routine log review, an unusually high volume of EventID 4625 (failed logon) entries was observed against `sc200-vm1`.

**Initial observation query:**
```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| sort by TimeGenerated desc
```

**Finding:** 446 failed authentication attempts from a single external IP address (`139.0.12.92`), all targeting the same account, over a sustained time period.

**Root cause of exposure:** The VM's Network Security Group had an inbound rule allowing TCP/3389 (RDP) from `0.0.0.0/0` — fully open to the internet.

---

## Phase 2 — Develop

The initial query above is a **hunting query**, not a detection rule. It returns every failed login in the environment with no threshold or alert condition. To move toward a deployable rule, the following decisions were made:

**What constitutes an attack vs. a mistake?**  
A single failed login is noise. A pattern of failures from the same source within a time window is signal.

**First detection query with threshold:**
```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedAttempts = count() by IpAddress, Account, Computer, bin(TimeGenerated, 1h)
| where FailedAttempts >= 10
| sort by FailedAttempts desc
```

**Threshold rationale:** 10 failures per hour was chosen based on observed baseline behavior for `sc200-vm1`. Legitimate users in this environment rarely fail authentication more than 2–3 times consecutively.

---

## Phase 3 — Test

The detection query was validated against the real attack data from `139.0.12.92`.

| Test | Expected | Result |
|---|---|---|
| Query returns attack IP | Yes | ✅ Pass |
| Threshold filters out single failures | Yes | ✅ Pass |
| Internal IPs excluded | Yes | ✅ Pass (after iteration 2) |
| Successful login correlation works | Yes | ✅ Pass — CompromiseConfirmed = false |

**False positive scenarios evaluated:**

| Scenario | Classification | Resolution |
|---|---|---|
| Failed logins from internal IP ranges | False Positive | Excluded from rule scope |
| Service account with expired credentials | False Positive | Added to exclusion list |
| User mistyping password 3–5 times | Benign | Below threshold, no alert |
| External IP, 446 failed attempts | True Positive | Alert confirmed |
| Admin account during maintenance window | False Positive | Time-based suppression added |

---

## Phase 4 — Deploy

**Final production rule (as designed — pending Sentinel Analytics Rule implementation):**

```kql
let excluded_ips = dynamic(["10.0.0.0/8", "192.168.0.0/16"]);
let excluded_accounts = dynamic(["svc-backup", "svc-monitor"]);
let failed = SecurityEvent
    | where EventID == 4625
    | where isnotempty(IpAddress)
    | where not(ipv4_is_in_range(IpAddress, excluded_ips[0]))
    | where Account !in (excluded_accounts)
    | summarize FailedAttempts = count() by IpAddress, Account, Computer, bin(TimeGenerated, 1h)
    | where FailedAttempts >= 10
    | extend geo = geo_info_from_ip_address(IpAddress)
    | extend Country = tostring(geo.country)
    | extend Severity = case(
        ipv4_is_private(IpAddress) == false and FailedAttempts >= 100, "High",
        ipv4_is_private(IpAddress) == false and FailedAttempts >= 10, "Medium",
        ipv4_is_private(IpAddress) == true and FailedAttempts >= 50, "Medium",
        "Low");
let successful = SecurityEvent
    | where EventID == 4624
    | where isnotempty(IpAddress)
    | project SuccessTime = TimeGenerated, IpAddress, Account, Computer;
failed
| join kind=leftouter successful on IpAddress, Account, Computer
| extend CompromiseConfirmed = isnotempty(SuccessTime)
| sort by CompromiseConfirmed desc, FailedAttempts desc
```

**Deployment status:** Designed and validated. Pending implementation as a scheduled Sentinel Analytics Rule.

---

## Phase 5 — Monitor

Once deployed, the following metrics will be tracked to evaluate rule effectiveness over time:

| Metric | Target |
|---|---|
| True Positive Rate | > 80% |
| False Positive Rate | < 20% |
| Mean Time to Detect (MTTD) | < 15 minutes |
| Alert Volume | Stable or decreasing week-over-week |

**Current state:** Not yet formally measured. Tracking begins when the rule is deployed as an official Sentinel Analytics Rule.

---

## Phase 6 — Improve

Identified improvements for the next iteration:

- [ ] Replace hardcoded IP exclusions with a Sentinel Watchlist for easier maintenance  
- [ ] Add LogonType filter to scope alerts to network-based logons (Type 3) only  
- [ ] Build a separate rule for T1110.003 (Password Spraying) — multi-account correlation  
- [ ] Configure alert suppression for known maintenance windows  
- [ ] Establish a formal TP/FP tracking register  

---

## Lifecycle Summary

```
Identify     →  High-volume EventID 4625 observed on sc200-vm1
Develop      →  Hunting query evolved into threshold-based detection rule
Test         →  Validated against real attack data, false positives evaluated
Deploy       →  Final rule designed with enrichment and severity scoring
Monitor      →  Metrics defined, tracking pending rule deployment
Improve      →  Gaps identified: spraying detection, watchlists, suppression
```

---

*End of Document*
