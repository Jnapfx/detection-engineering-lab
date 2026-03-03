# Detection Engineering Lab

## Overview

This repository documents the development of a cloud-native detection engineering lab built within the Microsoft security ecosystem (Azure, Microsoft Sentinel, and Defender XDR).

The purpose of this project is to design, implement, and document practical detection workflows in a structured and reproducible manner. While aligned with the SC-200 (Microsoft Security Operations Analyst) certification objectives, the primary focus is on hands-on detection engineering and threat investigation.

This is not a study repository. It is an implementation repository.

---

## Background

Prior to this project, I designed and operated a full SOC lab using Wazuh, where I:

- Implemented and tuned detection rules  
- Simulated adversarial techniques aligned with MITRE ATT&CK  
- Investigated endpoint and authentication telemetry  
- Performed rule optimization to reduce false positives  
- Documented detection logic and investigation workflows  

This lab extends those capabilities into the Microsoft security stack, with emphasis on Sentinel-based analytics, KQL detection logic, and XDR telemetry correlation.

---

## Objectives

The objectives of this repository are:

- Design and document end-to-end log ingestion architecture  
- Develop KQL-based detection rules  
- Map detections to MITRE ATT&CK techniques  
- Perform structured incident investigations  
- Apply detection tuning methodologies  
- Correlate identity, endpoint, and cloud telemetry  
- Maintain reproducible lab documentation  

---

## Architecture

The lab is fully cloud-based and follows this simplified architecture:

Azure Virtual Machine  
→ Azure Monitor Agent  
→ Log Analytics Workspace  
→ Microsoft Sentinel  
→ Analytics Rules (KQL)  
→ Alerts and Incidents  
→ Investigation and Classification  

All components are deployed in Azure to simulate a realistic enterprise monitoring environment.

---

## Repository Structure

```
detection-engineering-lab/
│
├── docs/
│   ├── soc-fundamentals.md
│   ├── azure-core-concepts.md
│   ├── sentinel-architecture.md
│   └── defender-overview.md
│
├── labs/
│   ├── lab-01-azure-foundation/
│   │   └── README.md
│   │
│   ├── lab-02-log-ingestion/
│   │   └── README.md
│   │
│   └── lab-03-basic-detection-rule/
│       └── README.md
│
├── kql/
│   ├── failed-logins.kql
│   ├── suspicious-powershell.kql
│   └── brute-force-detection.kql
│
├── detection-notes/
│   ├── mitre-mapping.md
│   ├── detection-lifecycle.md
│   └── tuning-methodology.md
│
└── README.md
```


---

## Core Focus Areas

- Microsoft Sentinel configuration and data connectors  
- Log Analytics workspace design  
- KQL query development and optimization  
- Analytics rule creation and tuning  
- Incident lifecycle management  
- MITRE ATT&CK mapping  
- Cross-platform detection methodology (Wazuh to Sentinel transition)  

---

## Methodology

Each lab implementation follows a consistent structure:

1. Objective  
2. Environment setup  
3. Detection logic  
4. Query design  
5. Incident generation  
6. Investigation workflow  
7. Tuning and improvement  
8. Lessons learned  

This ensures repeatability and measurable improvement over time.

---

## Long-Term Direction

This project supports continued growth toward:

- Detection Engineering  
- Threat Hunting  
- Cloud Security Engineering  
- Advanced Security Operations  

The repository will evolve as detection complexity increases and automation capabilities are integrated.