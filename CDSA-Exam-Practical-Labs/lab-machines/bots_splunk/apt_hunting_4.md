# BOTS Splunk

## APT Hunting #1 - Exfiltration By FTP
- Victim Info:
    - Frothly >> Beer Company >> USA
    - Notification from Law Enforcement FBI
    - Alice >> SOC Analyst

- APT:
    - TAFDOINGANG APT >> Eastern Asia-based

- Hypotheses #1: Exfiltration Over FTP >> Unencrypted/Obfuscated Non-C2 Protocol
    1. Hunt Direction:
        - What sourcetypes see or reference FTP?
        - What data flows look like between sources & dest
        - Can we see commands used in FTP?
        - What user accounts are used in FTP?
        - What time range is occured these events at?
        - Specific files are moved by FTP?

    2. Splunk Action:
        1. First >> let's check out what sourcetypes we have for `ftp` :
            ```code
                    index="botsv2" ftp
                    | stats count by sourcetype
                    | sort - count

                    index="botsv2" ftp sourcetype="suricata"
                    | stats count by dest_ip, src_ip
                    | sort - count

                    index="botsv2" ftp sourcetype="stream:ftp"
                    | stats count by dest_ip, src_ip
                    | sort - count

                    index="botsv2" ftp sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"
                    | stats count by host
                    | sort - count
            ```
            - I see two systems connected with external host `10.0.2.107` and `10.0.2.109` >>> `160.153.91.7`
                - `10.0.2.107` >> kelly >> admin
                - `10.0.2.109` >> belly tun >> user
                -
        2. Sourcetype:`pan:traffic` & `pan:threat` >> from palo alto
            - `71.39.18.125` >> is communicating with `160.153.91.7` >> 1450 times >> suspicious
            - hosts: (mercery >> server), (venus >> user)
            -
        3. Sysmon Logs >> as well
            - Hosts: wrk-btn, wrk-klagerf, venus
            - `commandline` fields shows suspicious command: `"C:\Windows\system32\ftp.exe" -i -s:winsys32.dll`
            -
        4. Time Series Analysis: with pan data & suricata data & stream:ftp
            ```code
                index="botsv2" ftp sourcetype="pan:*" src=* dest=*
                | eval uniq=src." ".dest
                | timechart count by uniq
            ```
            - It shows that  most traffic happened between 22 August and 26
            - Shows similar when `sourcetype=suricata` and `sourcetype=stream:ftp"`
            -
        5. Confirming Communicated Hosts:
            - `index="botsv2" sourcetype="stream:ftp" src=* dest=160.153.91.7` time range from 23 to 26 August
            - Only two src hosts communicated with external IP
            -
        6. Zoom Selection >> specific time interval >> then look for the
            - `filename` field
            - `reply_content`, `flow_id`, `method`, `method_parameter`
            -
        7. See the FTP Conversation Flow:
            ```code
                index="botsv2" ftp sourcetype="stream:ftp" src=* dest=160.153.91.7
                | table _time, filename, method, method_parameter, reply_content
                | sort + _time
            ```
            - Remove FTP methods that are not helpful
            - On both systems >> same actions happened
            - suspicious file extension found `hwp`
            -
        8. Examining Cluster >> Filter Histogram based on specific hours
            - In Histogram >> Press Mouse on each data >> explore specific files on this time
                - 4 Transmission times detected >> check of this >> see what files were transmissed by ftp
                - `frothly_passwords.kdbx` >> pdf files later >> `topsecretyeast.pdf`
                -
        9. Under the `reply_content` we found that `admin` related log in in ftp happened
            - Then need to search it for to see full FTP conversations (flow_id) associated with this string
                ```code
                        index="botsv2" sourcetype="stream:ftp" src=* dest=160.153.91.7 reply_content="*admin@hildegardsfarm.com*"
                        | sort + _time
                        | table _time, src, flow_id
                ```
            -
        10. Sysmon: explore (two specific files) >> see commandline args
                ```code
                    index="botsv2" (singlefile.dll OR winsys32.dll) sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
                    | table CommandLine, ParentCommandLine
                ```
                - it gives `powershell args` from ParentCommandLine
                - compare Sysmon Logs VS Win Event Logs >> to correlate events
                -
        11. `dns.py` was executed at Host: `Venus`
            - it is executed at each 10 min >> so some `cron` job is running
            -
        12. I found methods
            - `PORT` used to say server what port to use to connect active mode
            - `STOR` used to upload file to server

    3. Conclusion:
        - Two hosts communicated constantly with IP: 160.153.91.7
            - Two hosts use FTP to exfiltrate data to this IP
            - Script is obfuscated in .dll extension file since winsys32.dll is run by -s flag which is totally abnormal
        - FTP events:
            - shows both upload & download
            - 7 files are downloaded to 2 workstation on 23 August
            - traffice uploads seen >> directed to domain >> `hildegardsfarm.com`
        - Two Servers: Venus & Mercury only seen in Palo Alto Traffic
        -
        **Suggestions:**
            - Keep an eye on this IP
            - Monitor traffic baselines
            - Monitor odd arguments with .dll & ftp.exe
            - Monitor group of files of interest & their locations.
