# Testing Documentation win_susp_commands_recon_activity

## Detection Rule
```
title: Reconnaissance Activity with Net Command
status: experimental
description: Detects a set of commands often used in recon stages by different attack groups
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
    - https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html
author: Florian Roth, Markus Neis
date: 2018/08/22
modified: 2018/12/11
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - tasklist
            - net time
            - systeminfo
            - whoami
            - nbtstat
            - net start
            - '*\net1 start'
            - qprocess
            - nslookup
            - hostname.exe
            - '*\net1 user /domain'
            - '*\net1 group /domain'
            - '*\net1 group "domain admins" /domain'
            - '*\net1 group "Exchange Trusted Subsystem" /domain'
            - '*\net1 accounts /domain'
            - '*\net1 user net localgroup administrators'
            - netstat -an
    timeframe: 15s
    condition: selection | count() by host > 4
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```

## Attack Simulation
Run multiple recon commands in a short time:
```
whoami
tasklist
net time
nslookup
nbstat
```

## Result

Splunk

![](https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/detection-rules/T1087/win_susp_commands_recon_activity_test.png)

## Note
- The detection rule was aggregated by CommandLine, which would detect an recon activity only if the same command was executed multiple times. That's why the aggregation condition was changed to by host.







