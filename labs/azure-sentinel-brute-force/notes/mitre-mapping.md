# MITRE ATT&CK Mapping — Brute-Force Authentication Investigation

**Lab:** Azure Sentinel Brute-Force Authentication Investigation  
**Author:** Javier Napoles  
**ATT&CK Version:** v14  
**Last Updated:** 2026-03-20

---

## Overview

This document maps the observed attacker behavior from the brute-force investigation to the MITRE ATT&CK framework. Each technique is assessed based on the evidence collected from Microsoft Sentinel logs.

**Status definitions:**

| Status | Meaning |
|---|---|
| Confirmed | Directly observed in log data |
| Inferred | Strongly implied by evidence but not directly logged |
| Not Confirmed | Technique was considered but no supporting evidence found |
| Unsuccessful | Technique was attempted but did not achieve its objective |

---

## Technique Matrix

| Tactic | Technique | Sub-Technique | ID | Status |
|---|---|---|---|---|
| Reconnaissance | Active Scanning | Scanning IP Blocks | T1595.001 | Inferred |
| Initial Access | External Remote Services | — | T1133 | Confirmed |
| Credential Access | Brute Force | Password Guessing | T1110.001 | Confirmed |
| Credential Access | Brute Force | Password Spraying | T1110.003 | Not Confirmed |
| Credential Access | Valid Accounts | — | T1078 | Unsuccessful |

---

## Technique Detail

---

### T1595.001 — Active Scanning: Scanning IP Blocks

**Tactic:** Reconnaissance  
**Status:** Inferred  

**Description:**  
Adversaries scan IP ranges to identify internet-exposed hosts and open services before launching attacks. The rapid discovery of the exposed RDP port on `sc200-vm1` shortly after deployment suggests prior scanning activity.

**Evidence:**  
The virtual machine was exposed to the internet for a short period before brute-force attempts began. The speed at which attacks originated from multiple geographic locations is consistent with automated scanning infrastructure identifying the open port.

**Data Source:** Not directly observable via Windows Security Events. Would require network flow logs or Azure NSG flow logs to confirm.

**Detection Gap:** This technique is not currently covered by the KQL rules in this lab. Network-layer telemetry would be required.

---

### T1133 — External Remote Services

**Tactic:** Initial Access  
**Status:** Confirmed  

**Description:**  
Adversaries leverage internet-facing remote services such as RDP, VPN, or Citrix as an entry point. In this investigation, the Azure VM had port 3389 (RDP) exposed to the public internet via a permissive NSG rule (`0.0.0.0/0`).

**Evidence:**  
- NSG inbound rule allowed TCP/3389 from any source
- EventID 4625 records confirmed external IP addresses attempting RDP authentication
- Primary attacking IP: `139.0.12.92`

**Relevant KQL:**
```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| sort by TimeGenerated desc
```

**Remediation:** Restrict NSG inbound rules to trusted IP ranges. Disable RDP when not in use. Consider Azure Bastion as a replacement for direct RDP exposure.

---

### T1110.001 — Brute Force: Password Guessing

**Tactic:** Credential Access  
**Status:** Confirmed  

**Description:**  
Adversaries attempt to gain access by systematically guessing account credentials. This technique involves repeated authentication attempts against a single account using different passwords.

**Evidence:**  
- **446 failed authentication attempts** (EventID 4625) from IP `139.0.12.92`
- All attempts targeted the same account on `sc200-vm1`
- Attempts were sustained over time and consistent with automated tooling
- Geographic origin: Indonesia

**Relevant KQL:**
```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedAttempts = count() by IpAddress, Account, Computer, bin(TimeGenerated, 1h)
| where FailedAttempts >= 10
| sort by FailedAttempts desc
```

**Remediation:** Account lockout policy (threshold: 5 attempts), MFA enforcement, NSG restriction.

---

### T1110.003 — Brute Force: Password Spraying

**Tactic:** Credential Access  
**Status:** Not Confirmed  

**Description:**  
Password spraying involves attempting a small number of commonly used passwords against many accounts, rather than many passwords against one account. This avoids lockout policies.

**Evidence:**  
No evidence of multi-account targeting was observed. All 446 failed attempts were directed at the same account. The behavior is more consistent with T1110.001 (Password Guessing) than password spraying.

**Note:** Password spraying would require a separate detection rule correlating failures across multiple accounts within a time window. This is identified as a gap in the current detection coverage.

**Future Detection:**
```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize TargetedAccounts = dcount(Account), FailedAttempts = count()
    by IpAddress, bin(TimeGenerated, 1h)
| where TargetedAccounts >= 5 and FailedAttempts >= 20
| sort by TargetedAccounts desc
```

---

### T1078 — Valid Accounts

**Tactic:** Credential Access  
**Status:** Unsuccessful  

**Description:**  
Adversaries attempt to use legitimate credentials to authenticate and maintain access. A successful brute-force attack would result in the adversary obtaining valid account credentials.

**Evidence:**  
EventID 4624 (successful logon) was queried for the attacking IP `139.0.12.92`. No successful authentication events were found originating from that address.

```kql
SecurityEvent
| where EventID == 4624
| where IpAddress == "139.0.12.92"
| project TimeGenerated, Computer, Account, IpAddress, LogonType
```

**Result:** No records returned. The brute-force attack did not succeed. Compromise was not confirmed.

---

## Coverage Summary

```
Reconnaissance      [T1595.001]  ░░░░░░░░░░  Inferred — no telemetry coverage
Initial Access      [T1133]      ██████████  Confirmed — RDP exposure documented
Credential Access   [T1110.001]  ██████████  Confirmed — 446 failed attempts logged
Credential Access   [T1110.003]  ░░░░░░░░░░  Not confirmed — detection gap identified
Credential Access   [T1078]      ██████████  Monitored — no successful compromise
```

---

## Detection Gaps

| Gap | Technique | Action Required |
|---|---|---|
| No network-layer telemetry | T1595.001 | Enable NSG flow logs or Azure Network Watcher |
| No password spraying rule | T1110.003 | Build multi-account correlation query |
| No alerting on LogonType anomalies | T1078 | Add LogonType filter to detection rules |

---

## References

- [T1595.001 — Active Scanning](https://attack.mitre.org/techniques/T1595/001/)
- [T1133 — External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [T1110.003 — Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

*End of Document*