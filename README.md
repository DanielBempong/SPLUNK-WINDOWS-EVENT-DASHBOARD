# SPLUNK-WINDOWS-EVENT-DASHBOARD
Splunk SOC Analyst lab investigating Windows Security Events, successful logons, privileged account activity, suspicious account creation, and security dashboard development


# Splunk Windows Event Dashboard – SOC Analyst Lab

## Project Overview
This project demonstrates a hands-on SOC investigation using Splunk Enterprise to analyze Windows Security Event Logs, investigate successful authentication activity, identify privileged account activity, detect newly created user accounts, and build a Windows Activity dashboard.

The investigation focuses on Windows Event IDs 4624, 4672, and 4720 to identify authentication events, special privileges, and account creation activity.

## Tools & Technologies
- Splunk Enterprise 10.4.2
- Search Processing Language (SPL)
- Windows Security Event Logs
- Windows Authentication Analysis
- Privileged Account Monitoring
- Account Creation Detection
- SOC Investigation & Dashboarding

## Lab Environment
- Index: `mydfir-lab1`
- Host: `winvm`
- Analysis Period: January 7–9, 2024
- Platform: Splunk Enterprise

## Investigation Findings

| Finding | Result |
|---|---:|
| Initial events searched | 5,931 |
| Events associated with winvm | 993 |
| Successful logons (Event ID 4624) | 278 |
| Special-privilege events (Event ID 4672) | 22 |
| Relevant non-SYSTEM user | kporter |
| New account created (Event ID 4720) | evil |
| Account creator | kporter |

**Key observation:** The lab records show that kporter created a new account named evil on Desktop-IT. This activity warrants further investigation to determine whether the account creation was authorized.

## Windows Event IDs Investigated

| Event ID | Description | SOC Relevance |
|---|---|---|
| 4624 | Successful logon | Identify successful authentication |
| 4672 | Special privileges assigned to new logon | Investigate privileged activity |
| 4720 | User account created | Detect potentially unauthorized account creation |

## SPL Queries

### 1. Search Windows Security Events
```spl
index="mydfir-lab1"
```

### 2. Identify Windows Host
```spl
index="mydfir-lab1" host=winvm
```

### 3. Investigate Successful Logons
```spl
index="mydfir-lab1" host=winvm EventCode=4624
```

### 4. Analyze Logons by Computer, User, and Type
```spl
index="mydfir-lab1" host=winvm EventCode=4624
| stats count by ComputerName, user, Logon_Type
```

### 5. Exclude SYSTEM Accounts
```spl
index="mydfir-lab1" host=winvm EventCode=4624 user!=*$ user!=SYSTEM
| stats count by ComputerName, user, Logon_Type
```

### 6. Investigate Special-Privilege Activity
```spl
index="mydfir-lab1" host=winvm EventCode=4672 user!=*$ user!=SYSTEM
| stats count by user
```

### 7. Detect New Account Creation
```spl
index="mydfir-lab1" host=winvm EventCode=4720 user!=*$ user!=SYSTEM
| stats count by _time, ComputerName, Subject_Account_Name, New_Account_Account_Name
```

## Dashboard Components

The final Windows Activity dashboard includes three analyst-facing views:

1. Successful Logins by User
2. Users with Administrative Privileges
3. New User Account Created

## SOC Analyst Investigation Process

1. Search Windows Security Event Logs.
2. Identify relevant Windows hosts.
3. Investigate successful authentication events.
4. Separate SYSTEM activity from user-driven activity.
5. Review special-privilege assignments.
6. Detect newly created user accounts.
7. Correlate authentication and account-management activity.
8. Document findings and recommend follow-up actions.

## Recommended Follow-Up

- Review authentication sources and IP addresses associated with kporter.
- Validate whether the successful logons were expected.
- Investigate the creation of the evil account.
- Determine whether evil was added to privileged groups.
- Search for subsequent logons using the new account.
- Review process creation and PowerShell activity around the account creation timestamp.
- Document the investigation and remediation recommendations.

## Skills Demonstrated

Splunk Enterprise | SPL | Windows Security Event Analysis | Event IDs 4624, 4672, 4720 | Authentication Analysis | Privileged Activity Monitoring | Account Creation Detection | SOC Triage | Security Dashboarding | Incident Investigation

## Project Evidence

See `Splunk_Windows_Event_Dashboard_SOC_Report.pdf` for the complete investigation report, Splunk screenshots, SPL searches, dashboard visualizations, findings, and reconstructed lab timeline.

