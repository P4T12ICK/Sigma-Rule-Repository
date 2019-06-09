# Testing Documentation sysmon_susp_run_key_img_folder

## Detection Rule
```
title: New RUN Key Pointing to Suspicious Folder
status: experimental
description: Detects suspicious new RUN key element pointing to an executable in a suspicious folder
references:
    - https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
author: Florian Roth, Markus Neis
tags:
    - attack.persistence
    - attack.t1060
date: 2018/25/08
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: 
          - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\*'
          - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\\*'
        Details:
          - 'C:\Windows\Temp\\*'
          - '*\AppData\\*'
          - 'C:\$Recycle.bin\\*'
          - 'C:\Temp\\*'
          - 'C:\Users\Public\\*'
          - 'C:\Users\Default\\*'
          - 'C:\Users\Desktop\\*'
    condition: selection
fields:
    - Image
    - TargetObject
    - Details
falsepositives:
    - Software with rare behaviour
level: medium
```

## Attack Simulation
Created a new Regsitry Run Key with the following command:
```
reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /v Test /t REG_SZ /d C:\Windows\Temp\evil.exe
```

## Result

Splunk

![](https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/detection-rules/T1060/sysmon_rundll32_net_connections.png)

## Note
- level was missing in the Sigma detection rule.
- The Detection Rule was tested successfully.






