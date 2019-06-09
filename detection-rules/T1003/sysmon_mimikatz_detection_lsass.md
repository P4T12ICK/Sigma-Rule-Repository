# Testing Documentation sysmon_mimikatz_detection_lsass

## Detection Rule
```
title: Mimikatz Detection LSASS Access
status: experimental
description: Detects process access to LSASS which is typical for Mimikatz (0x1000 PROCESS_QUERY_ LIMITED_INFORMATION, 0x0400 PROCESS_QUERY_ INFORMATION, 0x0010 PROCESS_VM_READ)
references:
    - https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow
tags:
    - attack.t1003
    - attack.s0002
    - attack.credential_access
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage: 'C:\windows\system32\lsass.exe'
        GrantedAccess: 
            - '0x1410'
            - '0x1010'
    condition: selection
falsepositives:
    - unknown
level: high
```

## Attack simulation
- download mimikatz from the [official repository](https://github.com/gentilkiwi/mimikatz)
- run mimikatz.exe
- Get debug privilege: privilege::debug
- Extract passwords: sekurlsa::logonpasswords

## Result

Splunk

![](https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/detection-rules/T1003/sysmon_mimikatz_detection_lsass_test.png)

## Note
- This detection rule need EventID 10 which can cause a high load (that's why it is disabled in swiftonsecurity's sysmon configuration)
- In my test, the GrantedAccess was 0x1010 instead of 0x1410, that's why I changed the rule.


