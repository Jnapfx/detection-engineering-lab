# Detection Tuning Methodology — Authentication Brute-Force

Author: Javier Napoles
Lab: authentication-brute-force-investigation
Environment: Microsoft Sentinel / Azure

---

## Overview

This document describes the tuning methodology applied to the brute-force authentication detection developed in this lab. The goal of tuning is to maximize the signal-to-noise ratio of detection rules — reducing false positives while maintaining high fidelity for true positive alerts.

Tuning is not a one-time task. It is an iterative process that evolves as the environment changes and new attack patterns emerge.

---

## Baseline Established

Before tuning any rule, a baseline was established by observing normal authentication behavior in the environment.

Key baseline observations for `sc200-vm1`:

- Normal failed login rate: low volume, typically from known internal IP ranges
- Expected accounts: local administrator account, domain service accounts
- Expected logon types: Interactive (Type 2), Network (Type 3)
- No expected RDP connections from external or foreign IP addresses

This baseline was used to define what "normal" looks like, and therefore what constitutes anomalous behavior worth alerting on.

---

## Initial Detection Rule

The initial detection rule used to identify the brute-force attack was:

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| sort by TimeGenerated desc
```

**Problem:** This query returns every failed login in the environment, generating excessive noise and no actionable threshold. It is a hunting query, not an analytics rule.

---

## Tuning Iteration 1 — Applying a Threshold

The first tuning step was to define a meaningful threshold for alerting. A single failed login is not an attack. A pattern of failures within a time window is.

```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedAttempts = count() by IpAddress, Account, Computer, bin(TimeGenerated, 1h)
| where FailedAttempts >= 10
| sort by FailedAttempts desc
```

**Tuning rationale:** 10 failed attempts within a 1-hour window was chosen as the minimum threshold for this environment. This number was derived from the baseline — legitimate users rarely fail authentication more than 2–3 times consecutively.

**Threshold for this investigation:** The attacking IP `139.0.12.92` generated 423 failed attempts. This far exceeds the threshold and would have triggered an alert well before the attack concluded.

---

## Tuning Iteration 2 — Reducing False Positives

Certain IP addresses and accounts may legitimately generate failed logins at higher rates. These should be excluded to prevent alert fatigue.

**Common false positive sources in this environment:**

- Misconfigured service accounts attempting to authenticate with outdated credentials
- IT administrator accounts during password rotation windows
- Known internal IP ranges with legitimate retry behavior

**Exclusion approach:**

```kql
let excluded_ips = dynamic(["10.0.0.0/8", "192.168.0.0/16"]);
let excluded_accounts = dynamic(["svc-backup", "svc-monitor"]);
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| where not(ipv4_is_in_range(IpAddress, excluded_ips[0]))
| where Account !in (excluded_accounts)
| summarize FailedAttempts = count() by IpAddress, Account, Computer, bin(TimeGenerated, 1h)
| where FailedAttempts >= 10
| sort by FailedAttempts desc
```

**Note:** Exclusion lists should be reviewed periodically. An overly broad exclusion list is a detection gap waiting to be exploited.

---

## Tuning Iteration 3 — Enrichment for Prioritization

Not all brute-force alerts carry the same risk. An attack from a foreign IP targeting an admin account is higher priority than a failed login from a known office IP.

**Enrichment added:**

```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedAttempts = count() by IpAddress, Account, Computer, bin(TimeGenerated, 1h)
| where FailedAttempts >= 10
| extend geo = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(geo.country)
| extend IsPrivateIP = ipv4_is_private(IpAddress)
| extend Severity = case(
    IsPrivateIP == false and FailedAttempts >= 100, "High",
    IsPrivateIP == false and FailedAttempts >= 10, "Medium",
    IsPrivateIP == true and FailedAttempts >= 50, "Medium",
    "Low"
)
| sort by FailedAttempts desc
```

**Applied to this investigation:** `139.0.12.92` is a public IP from Indonesia with 423 failed attempts. This would be classified as **High** severity automatically.

---

## Tuning Iteration 4 — Correlating with Successful Logins

A brute-force attack that succeeds is a fundamentally different incident than one that fails. The final tuning step adds a cross-correlation to flag cases where a high-volume failure is followed by a successful login.

```kql
let failed = SecurityEvent
    | where EventID == 4625
    | where isnotempty(IpAddress)
    | summarize FailedAttempts = count() by IpAddress, Account, Computer
    | where FailedAttempts >= 10;
let successful = SecurityEvent
    | where EventID == 4624
    | where isnotempty(IpAddress)
    | project SuccessTime = TimeGenerated, IpAddress, Account, Computer;
failed
| join kind=leftouter successful on IpAddress, Account, Computer
| extend CompromiseConfirmed = isnotempty(SuccessTime)
| sort by CompromiseConfirmed desc, FailedAttempts desc
```

**Result for this investigation:** `CompromiseConfirmed = false` for IP `139.0.12.92`. The attack was not successful. This distinction changes the severity and response priority of the incident.

---

## False Positive Analysis

| Scenario | Classification | Action Taken |
|---|---|---|
| Failed logins from internal IP ranges | False Positive | Excluded from rule scope |
| Service account with expired credentials | False Positive | Added to exclusion list, remediated at source |
| Single user mistyping password 3–5 times | Benign | Below threshold, no alert generated |
| External IP with 423 failed attempts | True Positive | Alert triggered, confirmed as brute-force |
| Admin account with 15 failures during maintenance | False Positive | Added time-based suppression for maintenance windows |

---

## Detection Quality Metrics

The following metrics are tracked to evaluate detection rule effectiveness over time:

| Metric | Description | Target |
|---|---|---|
| True Positive Rate | Alerts that correspond to real attacks | > 80% |
| False Positive Rate | Alerts that are benign or expected | < 20% |
| Mean Time to Detect (MTTD) | Time from first malicious event to alert trigger | < 15 min |
| Alert Volume | Total alerts generated per week | Stable or decreasing |
| Threshold Breaches | Number of legitimate events hitting the threshold | 0 |

**Current state for this rule:** Not yet formally measured. Will be tracked as more data accumulates in the environment.

---

## MITRE ATT&CK Alignment

Tuning decisions were made with the following techniques in scope:

| Technique | ID | Tuning Impact |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Primary technique targeted by threshold rule |
| External Remote Services | T1133 | Scope limited to external IPs (non-RFC1918) |
| Valid Accounts | T1078 | Correlation query flags successful post-bruteforce logins |

Techniques explicitly **out of scope** for this rule (addressed separately):

- T1110.003 — Password Spraying (requires multi-account correlation)
- T1595.001 — Active Scanning (requires network flow data, not Security Events)

---

## Lessons Learned

1. **A detection without a threshold is a hunting query, not an analytics rule.** The initial EventID 4625 query needed significant tuning before it was suitable for alerting.

2. **Exclusion lists require maintenance.** Static exclusions become stale and can silently suppress real alerts over time. Review quarterly.

3. **Enrichment changes the response, not just the alert.** Knowing the attack originated from Indonesia at 3AM with 423 attempts changes how an analyst prioritizes and responds.

4. **Correlation is the difference between "attack detected" and "compromise confirmed."** The 4624 cross-correlation is the most operationally valuable tuning addition.

5. **Tuning is environment-specific.** The threshold of 10 failures per hour was appropriate for this lab. Production environments may require a different baseline.

---

## Next Steps

- [ ] Implement the final tuned rule as an official Sentinel Analytics Rule
- [ ] Configure alert suppression for maintenance windows
- [ ] Set up watchlist for known-good IPs to replace hardcoded exclusions
- [ ] Establish formal TP/FP tracking in a detection register
- [ ] Expand rule to cover T1110.003 (Password Spraying) as a separate detection

---

*End of Document*