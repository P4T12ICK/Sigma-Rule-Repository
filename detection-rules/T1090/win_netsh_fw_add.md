# Testing Documentation win_netsh_fw_add

## Detection Rule
```
title: Netsh Firewall Rule Added 
description: Allow Incoming Connections by Port or Application on Windows Firewall
references:
    - https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
    - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.command_and_control
    - attack.t1090 
status: experimental
author: Markus Neis, Patrick Bareiss
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*netsh* firewall add*'
            - '*netsh* advfirewall* add*'
    condition: selection
falsepositives:
    - Legitimate administration
level: medium

```

## Attack Simulation
Add a new firewall rule on a Windows 10 machine:
```
netsh advfirewall firewall add rule name="Zoo TCP Port 80" dir=in action=allow protocol=TCP localport=80
```

## Result

Splunk

![](https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/detection-rules/T1090/win_netsh_fw_add_test.png)

## Note
- Added an additional * after netsh because in Splunk are two whitespaces after netsh.
- Added an additonal CommandLine for newer version of Windows.



