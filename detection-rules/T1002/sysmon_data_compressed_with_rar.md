# Testing Documentation sysmon_data_compressed_with_rar

## Rule
```
title: Data compression with rar 
status: experimental
description: Detects the use of Winrar from the command line in order to compress data.
author: Patrick Bareiss
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.md
tags:
    - attack.t1002
    - attack.exfiltration
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine: 'rar* a -r *'
    condition: selection
falsepositives:
    - unknown
level: high

```

## Attack Simulation
Compress folder with rar command from the command line:
```
rar a -r test.rar test_folder
```

## Result

Splunk



## Note
- The detection rule was tested successfully.

