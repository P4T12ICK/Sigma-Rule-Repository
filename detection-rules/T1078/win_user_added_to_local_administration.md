# Testing Documentation win_user_added_to_local_administration

## Detection Rule
```
title: User Added to Local Administrators
description: This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity 
status: stable
author: Florian Roth
tags:
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4732
        GroupName: Administrators
    filter:
        SubjectUserName: '*$'
    condition: selection and not filter
falsepositives: 
    - Legitimate administrative activity
level: low
```

## Attack Simulation
```
net localgroup Administrators ironman /add
```

## Result
Splunk

![](https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/detection-rules/T1078/win_user_added_to_local_administrators_test.png)

## Note
- Added field mapping GroupName: Group_Name for Splunk
- Successful tested

