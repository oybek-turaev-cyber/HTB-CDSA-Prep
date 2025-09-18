- Search for process execution:
    - `index=sysmon EventCode=1 Image=*powershell.exe*`

- Detect lateral movement (PsExec):
    - `index=sysmon CommandLine=*psexec*`

- `rex` Command Usage for IPv4:
    - `| rex field=content "sender IP is (?<sender_ip>\d+.\d+.\d+.\d+)"`
    - `| search sender_ip=185.83.51.21`

- See available data:
    - `index=* | stats count by index`
    - `index=* | stats count by sourcetype`
    
    - `metadata` Command:
        - `| metadata type=hosts`
        - `| metadata type=indexes`
        - `| metadata type=sources`
        
        - `| eventcount summarize=false index=*` >> to show all indexes whether they have events or not
        
- Within specific Index:
        - Command To see sourtypes with nice time formatting:
            ```code
                    | metadata type=sourcetypes index=botsv2
                    | eval firstTime=strftime(firstTime, "%Y-%m-%d %H-%M-%S")
                    | eval lastTime=strftime(lastTime, "%Y-%m-%d %H-%M-%S")
                    | eval recentTime=strftime(recentTime, "%Y-%m-%d %H-%M-%S")
                    | sort - totalCount
            ```











