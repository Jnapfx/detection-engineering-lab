# Detection Engineering Lab

**Author:** Javier Napoles  
**Focus:** SC-200 (Microsoft Security Operations Analyst) preparation through hands-on lab work  
**Environment:** Microsoft Azure — Sentinel, Log Analytics, Defender XDR  

---

## About This Repository

This repository documents my preparation for the SC-200 certification through practical, hands-on work in the Microsoft security stack.

It is organized into two sections:

- **`docs/`** — Study notes covering core concepts: SOC fundamentals, Azure architecture, Microsoft Sentinel, KQL, and Defender XDR. These serve as reference material alongside the labs.
- **`labs/`** — Hands-on investigations built in a live Azure environment. Each lab includes detection logic, KQL queries, MITRE ATT&CK mapping, and structured analysis.

Prior to this project, I built and operated a full SOC lab using Wazuh — implementing detection rules, simulating adversarial techniques, and tuning rules against real telemetry. This repo extends that work into the Microsoft security ecosystem.

---

## Labs

| Lab | Description | Status |
|---|---|---|
| [Azure Sentinel Brute-Force Investigation](labs/azure-sentinel-brute-force/README.md) | Detection and analysis of a real-world RDP brute-force attack using Microsoft Sentinel | Complete |
| Future Lab 2 | TBD | Planned |
| Future Lab 3 | TBD | Planned |

---

## Lab Architecture

All labs run on this cloud-based pipeline:

```
Azure Virtual Machine
→ Azure Monitor Agent
→ Log Analytics Workspace
→ Microsoft Sentinel
→ Analytics Rules (KQL)
→ Alerts and Incidents
→ Investigation and Classification
```

---

## Repository Structure

```
detection-engineering-lab/
│
├── docs/
│   ├── soc-fundamentals.md
│   ├── azure-core-concepts.md
│   ├── sentinel-architecture.md
│   ├── kql-fundamentals.md
│   ├── defender-overview.md
│   └── Microsoft_Sentinel_SOC_Lab_Setup_Guide/
│       └── README.md
│
└── labs/
    └── azure-sentinel-brute-force/
        ├── README.md
        ├── kql/
        ├── detection-notes/
        │   ├── mitre-mapping.md
        │   └── tuning-methodology.md
        ├── mitigations/
        └── screenshots/
```

---

## Each Lab Follows This Structure

1. Environment setup  
2. Detection logic and query development  
3. Investigation workflow  
4. MITRE ATT&CK mapping  
5. Detection tuning  
6. Mitigations  
7. Lessons learned  
