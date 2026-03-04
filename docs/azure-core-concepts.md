# Azure Core Concepts

Author: Javier Napoles  
Focus: SOC Analyst / SC-200 Preparation  
Environment: Microsoft Azure Security Ecosystem

---

# 1. Introduction to Microsoft Azure

Microsoft Azure is a cloud computing platform developed by Microsoft that provides a wide range of services including computing, storage, networking, databases, analytics, and security.

Organizations use Azure to build, deploy, and manage applications through Microsoft-managed data centers located around the world.

Cloud computing allows companies to access infrastructure and services without owning physical hardware.

## Benefits of Cloud Computing

- Scalability
- High availability
- Cost efficiency
- Global infrastructure
- Built-in security capabilities

---

# 2. Cloud Service Models

Cloud services are generally divided into three main models.

## Infrastructure as a Service (IaaS)

Provides virtualized computing resources over the internet.

Examples:
- Azure Virtual Machines
- Azure Virtual Networks
- Azure Storage

The customer manages:
- Operating system
- Applications
- Security configurations

Azure manages:
- Physical servers
- Networking hardware
- Data centers

## Platform as a Service (PaaS)

Provides a platform that allows developers to build, deploy, and manage applications without managing infrastructure.

Examples:
- Azure App Services
- Azure SQL Database
- Azure Functions

Azure manages:
- Infrastructure
- OS
- Runtime environment

## Software as a Service (SaaS)

Delivers software applications over the internet.

Examples:
- Microsoft 365
- Teams
- Outlook Online

The provider manages everything.

---

# 3. Azure Global Infrastructure

Microsoft Azure operates a global network of data centers.

Key components include:

## Regions

A region is a geographical area that contains one or more data centers.

Example regions:

- East US
- West Europe
- Central US

Organizations choose regions based on:

- Latency
- Compliance
- Disaster recovery strategy

## Availability Zones

Availability Zones are physically separate data centers within a region.

They provide redundancy and high availability.

Example architecture:

```
Application
     ↓
Zone 1 VM
Zone 2 VM
Zone 3 VM
```

If one zone fails, the others remain operational.

## Region Pairs

Each Azure region is paired with another region to support disaster recovery.

Example:

- East US → West US
- West Europe → North Europe

---

# 4. Azure Resource Organization

Azure resources are organized in a hierarchy to simplify management and access control.

## Hierarchy Structure

```
Management Group
└── Subscription
     └── Resource Group
          └── Resources
```

## Management Groups

Management groups allow administrators to organize multiple subscriptions.

Useful for:

- Large enterprises
- Policy management
- Governance

## Subscriptions

A subscription is a billing and access boundary.

Examples:

- Production subscription
- Development subscription
- Testing subscription

## Resource Groups

Resource groups contain related Azure resources.

Example:

```
Resource Group: SOC-Lab

Resources inside:
- Virtual Machine
- Storage Account
- Log Analytics Workspace
- Microsoft Sentinel
```

---

# 5. Azure Identity and Access Management

Identity management is a critical component of cloud security.

Azure uses **Microsoft Entra ID** (formerly Azure Active Directory) to manage identities.

## Authentication vs Authorization

Authentication  
Verifies a user's identity.

Example:
Logging into Azure Portal.

Authorization  
Determines what resources a user can access.

Example:
Allowing access to a virtual machine.

## Role-Based Access Control (RBAC)

RBAC controls access to Azure resources.

Examples of roles:

- Owner
- Contributor
- Reader
- Security Administrator

Example RBAC structure:

```
User
 ↓
Assigned Role
 ↓
Access to Resource
```

## Principle of Least Privilege

Users should only receive the minimum permissions necessary to perform their tasks.

This reduces the risk of compromise.

## Conditional Access

Conditional access policies enforce security controls based on conditions such as:

- Location
- Device compliance
- User risk level

Example:

```
User Login
     ↓
Conditional Access Policy
     ↓
Multi-Factor Authentication Required
```

---

# 6. Azure Networking Fundamentals

Networking in Azure allows resources to communicate securely.

## Virtual Network (VNet)

A Virtual Network is a private network inside Azure.

It enables communication between:

- Virtual machines
- Applications
- Azure services

## Subnets

Subnets divide a VNet into smaller segments.

Example:

```
Virtual Network
├── Subnet-Web
├── Subnet-Database
└── Subnet-Management
```

## Network Security Groups (NSG)

NSGs control inbound and outbound traffic.

Example rules:

Allow:

- HTTPS (443)
- SSH (22)

Deny:

- Unauthorized ports

## Public vs Private IP

Public IP  
Accessible from the internet.

Private IP  
Accessible only inside the Azure network.

---

# 7. Azure Compute Services

Compute services provide processing power to run applications.

## Azure Virtual Machines

Virtual machines allow users to run operating systems in the cloud.

Examples:

- Windows Server
- Linux

Security considerations:

- Patch management
- Endpoint protection
- Monitoring

## Virtual Machine Scale Sets

Automatically scale virtual machines based on demand.

Useful for high traffic applications.

## Azure App Services

Allows developers to deploy web applications without managing infrastructure.

---

# 8. Azure Storage Services

Azure storage provides scalable and durable data storage.

Types of storage include:

## Blob Storage

Stores large amounts of unstructured data such as:

- Images
- Videos
- Backup files

## File Storage

Provides managed file shares in the cloud.

## Queue Storage

Used for message-based communication between applications.

## Table Storage

Stores structured NoSQL data.

### Security Features

- Encryption at rest
- Shared Access Signatures (SAS)
- Storage firewall rules
- Access keys

---

# 9. Azure Monitoring and Logging

Monitoring and logging are essential for detecting security threats.

## Azure Monitor

Azure Monitor collects and analyzes telemetry data from resources.

Types of data:

- Metrics
- Logs

## Log Analytics

Log Analytics is used to query and analyze logs using **Kusto Query Language (KQL)**.

Example query:

```kql
SecurityEvent
| where EventID == 4625
| limit 10
```

This query retrieves failed login attempts.

## Activity Logs

Activity logs track operations performed on Azure resources.

Example events:

- Resource creation
- Resource deletion
- Permission changes

These logs are critical for security investigations.

---

# 10. Azure Security Concepts

## Shared Responsibility Model

Security responsibilities are shared between Microsoft and the customer.

Microsoft manages:

- Physical data centers
- Hardware
- Networking infrastructure

Customers manage:

- Identity access
- Operating systems
- Applications
- Data protection

## Zero Trust Model

Zero Trust assumes no user or system should be trusted automatically.

Principles include:

- Verify identity
- Use least privilege access
- Monitor continuously

## Defense in Depth

Defense in Depth uses multiple security layers.

Example layers:

```
Identity Security
Network Security
Application Security
Data Security
```

---

# 11. Azure Security Services Overview

Several Azure services support security monitoring.

## Microsoft Defender for Cloud

Provides security posture management and threat protection.

## Microsoft Sentinel

Cloud-native SIEM and SOAR platform.

Used for:

- Log analysis
- Threat detection
- Incident investigation

## Microsoft Defender XDR

Provides extended detection and response across multiple Microsoft services.

## Azure Policy

Used to enforce organizational standards and compliance rules.

---

# 12. Key Takeaways for Security Analysts

Understanding Azure fundamentals is essential for security operations.

Important concepts include:

- Identity as the primary security boundary
- Centralized logging for threat detection
- Monitoring cloud infrastructure
- Integrating logs into SIEM platforms

Security analysts rely on these components to detect, investigate, and respond to threats within cloud environments.

---

End of Document