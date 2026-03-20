# KQL Queries for Microsoft Sentinel

Author: Javier Napoles  
Focus: SOC Analyst / SC-200 Preparation  
Environment: Microsoft Sentinel + Log Analytics

---

# 1. What is KQL?

KQL (Kusto Query Language) is a powerful query language used to search, analyze, and visualize log data in Microsoft Sentinel and Azure Log Analytics.

Security analysts use KQL to:

- Investigate alerts
- Hunt for threats
- Analyze logs
- Detect suspicious behavior
- Build detection rules

KQL allows analysts to quickly search through large volumes of log data to identify potential security incidents.

---

# 2. KQL Learning Resource

The following video series is a useful reference for learning KQL and Microsoft Sentinel queries.

Study resource:

https://www.youtube.com/watch?v=4VezNFqMnpg&list=PLuIShsT8L3sCjndVr4iwT4Uyh6aquB3q2

This playlist covers:

- KQL basics
- Log analysis
- Threat hunting queries
- Microsoft Sentinel investigation techniques

---

# 3. Basic KQL Query Structure

Most KQL queries follow this structure:

```
TableName
| operator
| operator
| operator
```

Example:

```
SigninLogs
| limit 10
```

This retrieves the first 10 records from the SigninLogs table.

---

# 4. Filtering Data

The `where` operator filters records.

Example: Failed logins

```
SigninLogs
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress
| limit 10
```

This query returns login failures.

---

# 5. Selecting Specific Fields

The `project` operator selects specific columns.

Example:

```
SigninLogs
| project TimeGenerated, UserPrincipalName, IPAddress
| limit 10
```

This shows only the selected fields.

---

# 6. Sorting Data

The `order by` operator sorts results.

Example:

```
SigninLogs
| order by TimeGenerated desc
| limit 10
```

This shows the most recent logins.

---

# 7. Searching for Failed Login Attempts

Failed login attempts may indicate brute force attacks.

Example query:

```
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress
| limit 20
```

Event ID 4625 indicates failed login attempts in Windows systems.

---

# 8. Detecting Multiple Failed Logins

This query identifies accounts with multiple failed login attempts.

```
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account
| sort by FailedAttempts desc
```

High counts may indicate brute force activity.

---

# 9. Successful Login Monitoring

Monitor successful logins using Event ID 4624.

```
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, Computer
| limit 20
```

This helps analysts review login activity.

---

# 10. Detecting Suspicious IP Activity

This query identifies IP addresses with high login activity.

```
SigninLogs
| summarize LoginAttempts = count() by IPAddress
| where LoginAttempts > 20
| sort by LoginAttempts desc
```

High activity from a single IP may indicate attack attempts.

---

# 11. Detecting Logins from Multiple Locations

Unusual geographic login patterns may indicate compromised accounts.

```
SigninLogs
| summarize Locations = dcount(Location) by UserPrincipalName
| where Locations > 3
```

This shows users logging in from multiple locations.

---

# 12. Detecting Privileged Account Activity

Monitoring privileged accounts is critical for security.

Example:

```
SecurityEvent
| where EventID == 4672
| project TimeGenerated, Account, Computer
```

Event ID 4672 indicates special privileges assigned to a login.

---

# 13. Detecting Account Lockouts

Account lockouts may indicate brute force attempts.

```
SecurityEvent
| where EventID == 4740
| project TimeGenerated, Account, Computer
```

---

# 14. Investigating Suspicious Processes

This query looks for suspicious processes executed on endpoints.

```
DeviceProcessEvents
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| limit 20
```

This helps analysts detect suspicious commands.

---

# 15. Detecting Large Data Transfers

Large data transfers may indicate data exfiltration.

```
AzureActivity
| summarize DataTransfers = count() by CallerIPAddress
| where DataTransfers > 50
```

This identifies unusually high data activity.

---

# 16. Threat Hunting Example

Threat hunting queries help analysts proactively search for suspicious activity.

Example brute force detection:

```
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress
| where FailedAttempts > 10
```

This detects IP addresses with multiple failed login attempts.

---

# 17. Useful KQL Operators

Common operators used in KQL include:

| Operator | Purpose |
|--------|--------|
| where | Filters records |
| project | Selects columns |
| summarize | Aggregates data |
| order by | Sorts results |
| limit | Limits output |
| extend | Creates new columns |
| join | Combines tables |

These operators allow analysts to manipulate and analyze log data efficiently.

---

# 18. Key Takeaways for SOC Analysts

KQL is an essential skill for SOC analysts working with Microsoft Sentinel.

Security analysts use KQL to:

- Investigate alerts
- Perform threat hunting
- Analyze security logs
- Build detection rules
- Identify attack patterns

Strong KQL skills improve the speed and effectiveness of incident investigations.

---

End of Document