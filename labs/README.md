# Azure Sentinel Brute Force Attack Investigation

## Overview

This lab simulates and investigates a brute-force attack targeting a publicly exposed Azure virtual machine.

The objective is to detect, analyze, and understand the attack using Microsoft Sentinel and KQL queries.

---

## Lab Environment

* Azure Virtual Machine (Windows)
* Microsoft Sentinel (Log Analytics Workspace)
* Network Security Group (NSG)
* RDP (Port 3389 exposed)

---

## Incident Summary

During log analysis, multiple failed authentication attempts were detected against the virtual machine.

Further investigation revealed:

* 439 failed login attempts
* Originating from a single external IP address
* Targeting a specific user account
* Occurring over a sustained period of time

This behavior is consistent with an automated brute-force attack.

---

## Log Ingestion Validation

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize Count=count() by EventID
| sort by Count desc
```

![Log Ingestion](screenshots/log_ingestion_validation.png)

---

## Failed Login Analysis

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize FailedAttempts = count() by IpAddress
| sort by FailedAttempts desc
```

![Failed Logins](screenshots/failed_login_attempts.png)

---

## Infrastructure Exposure Analysis

The Network Security Group (NSG) allowed inbound RDP access from any external source.

![NSG Exposure](screenshots/nsg_rdp_exposed.png)

* Source: Any (0.0.0.0/0)
* Port: 3389 (RDP)
* Protocol: TCP
* Action: Allow

This misconfiguration exposed the system to the internet.

---

## Key Findings

* Public RDP exposure enabled external access attempts
* A single IP generated the majority of failed logins
* The attack pattern matches automated brute-force behavior
* No successful compromise was confirmed

---

## Mitigation Recommendations

* Restrict RDP access using NSG rules (IP allowlist)
* Implement Azure Bastion instead of public RDP
* Enable account lockout policies
* Deploy Microsoft Defender for Cloud alerts
* Monitor failed login thresholds with Sentinel alerts

---

## Skills Demonstrated

* Log Analysis (Windows Security Events)
* KQL Query Development
* Threat Detection
* Incident Investigation
* Cloud Security (Azure)
* NSG Misconfiguration Analysis

---

## End of Document
