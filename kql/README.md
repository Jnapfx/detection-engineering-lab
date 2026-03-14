# KQL Queries

This directory contains the Kusto Query Language (KQL) queries used throughout the Microsoft Sentinel SOC Lab.

These queries were developed during the investigation and analysis of authentication activity within the lab environment.

The queries focus primarily on Windows Security Events ingested into Microsoft Sentinel.

---

## Data Source

The queries in this directory analyze logs from:

* Windows Security Event Logs
* Table: `SecurityEvent`

Common Event IDs used:

* **4625** — Failed authentication attempt
* **4624** — Successful authentication

---

## Queries Included

### failed-authentication-events.kql

Displays failed login attempts in the environment.

Purpose:

* Identify authentication failures
* Observe patterns of failed logins
* Support brute force investigations

---

### brute-force-volume-by-ip.kql

Identifies IP addresses generating high volumes of failed login attempts.

Purpose:

* Detect potential brute force activity
* Highlight suspicious external IP addresses

---

### failed-login-timeline.kql

Displays failed login attempts across time.

Purpose:

* Identify spikes in authentication failures
* Visualize attack patterns

---

### successful-login-check.kql

Displays successful authentication events.

Purpose:

* Verify whether attackers successfully logged into the system

---

### geographic-distribution.kql

Aggregates failed login attempts by source IP address.

Purpose:

* Support geographic analysis in Microsoft Sentinel
* Identify attack origins

---

## Usage

These queries are used within the investigation labs located in:

`/labs/`

They can also be reused when building custom detection rules or performing additional security investigations in Microsoft Sentinel.

---

End of document
