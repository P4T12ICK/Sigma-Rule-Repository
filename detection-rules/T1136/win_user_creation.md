# Testing Documentation win_user_creation

## Detection Rule
```
title: Detects local user creation
description: Detects local user creation on windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs. 
status: experimental
tags:
    - attack.persistence
    - attack.t1136
references:
    - https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/ 
author: Patrick Bareiss
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
fields:
    - EventCode
    - AccountName
    - AccountDomain
falsepositives: 
    - Domain Controller Logs
    - Local accounts managed by privileged account management tools
level: low
```

## Attack Simulation
A local user account is created:
```
net user ironman test123!45 /add
```

## Result

Splunk

![](https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/detection-rules/T1136/win_user_creation_test.png)

## Note
- Detection rule was tested successfully.
- AccountName and AccountDomain is Account_Name and Account_Domain in Splunk.

