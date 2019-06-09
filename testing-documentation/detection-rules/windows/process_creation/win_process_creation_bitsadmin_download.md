# Testing Documentation win_process_creation_bitsadmin_download

## Rule
```
title: Bitsadmin Download
status: experimental
description: Detects usage of bitsadmin downloading a file
references:
        - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
        - https://isc.sans.edu/diary/22264
tags:
        - attack.defense_evasion
        - attack.persistence
        - attack.t1197
        - attack.s0190
author: Michael Haag
logsource:
        category: process_creation
        product: windows
detection:
        selection:
                Image:
                        - '*\bitsadmin.exe'
                CommandLine:
                        - '/transfer'
        condition: selection
fields:
        - CommandLine
        - ParentCommandLine
falsepositives:
        - Some legitimate apps use this, but limited.
level: medium
```

## Attack Simulation
The bitsadmin tool is used to download a file:
```
bitsadmin.exe  /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\Windows\Temp\bitsadmin_flag.ps1
```

## Results

Splunk



## Note
- The detection rule was tested successfully.





