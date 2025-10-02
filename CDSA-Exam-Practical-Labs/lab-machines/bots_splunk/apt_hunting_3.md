# BOTS Splunk

## APT Hunting #1 - Data Staging
- Victim Info:
    - Frothly >> Beer Company >> USA
    - Notification From Law Enforcement FBI
    - Alice >> SOC Analyst

- APT:
    - TAFDOINGANG APT >> Eastern Asia-based

- Hypotheses #1: Remote Data Staging
    1. What is Remote Data Staging?
        - Gathering Data in the central place in victim env prior to Exfiltration

    2. Hunt Direction:
        - What data types & sources help us to identify data being staged?
        - What traffic flow would like ? in case of staging data.
        - What can show where data is being stored?
        - What are some likely places ?
        - Any subsequent activity shows that staged data is being exfiltrated?
        - What user accounts might be used to stage data?
        - Time >> August 2017

    3. Splunk Action:
        - Never Ever Forget >> Hunt Direction
        1. Question First >> what sourtypes help you >> so then what certain files you have and how you can identify them?
            ```code
                index="botsv2" (.pdf OR .doc OR .tgz OR .xls)
                | stats count by sourcetype
                | sort - count
            ```
            - Found that that `stream:smb` got the lead with 7771 counts >> then go for it
            -
        2. Found that "stream:smb" has a nice field >> `flow_id` which identificator of each smb transaction
            - Also `filename` field >>
                ```code
                    index="botsv2" sourcetype="stream:smb"
                    | eval uniq=src_ip." ".dest_ip
                    | timechart count by uniq
                ```
            - Here `eval` combines two groups of src & dest IP >> then timechart graphically shows connections for each pair with specific time
            -
            - Found that pair `10.0.2.107   10.0.1.101` has higher number connections during August 23rd and 25th >> 23th is what we know attack started
            -
        3. Time range for >> `22 to 27 august` then look for `filenames` with certain pairs of `src & dest` IP
            ```code
                | stats count by filename, src_ip, dest_ip
                | sort - count
            ```
        4. Then just look for the one file from the found: `index="botsv2" 2322-pdf` >> check out sourcetypes >> where else they are appeared
            - Check the commands in that flow
                ```code
                    index="botsv2"  flow_id="d7370639-8ca9-40d3-a5f8-dd6547d4ff99" sourcetype="stream:smb"
                    | stats count by command
                    | sort - count
                ```
        5. Then to see how much data is being communicated: `smb2 read`
                ```code
                    index="botsv2"  flow_id="d7370639-8ca9-40d3-a5f8-dd6547d4ff99" sourcetype="stream:smb" command="smb2 read"
                    | stats count sum(bytes_in) AS b_in sum(bytes_out) AS b_out by src_ip, dest_ip
                    | eval mb_in=round((b_in/1024/1024), 2)
                    | eval mb_out=round((b_out/1024/1024), 2)
                    | fields - b_in b_out
                ```
            - Found that 1.29 GB is being sent from the servre
            -
        6. Then to see how much data is being communicated: `smb2 create`
                ```code
                    index="botsv2"  flow_id="d7370639-8ca9-40d3-a5f8-dd6547d4ff99" sourcetype="stream:smb" command="smb2 create"
                    | stats count sum(bytes_in) AS b_in sum(bytes_out) AS b_out by src_ip, dest_ip
                    | eval mb_in=round((b_in/1024/1024), 2)
                    | eval mb_out=round((b_out/1024/1024), 2)
                    | fields - b_in b_out
                ```
        7. Also check out `smb2 close` commands to see what it is doing and how is the situation
        8. We also checked out `http:ftp` traffic >> there src_ip `10.0.2.107` uploaded data to dest_ip `160.153.91.7`
            - That's file exfiltration

    4. Conclusion:
        - It is found out that smb is used in data staging >> found out IP addresses >> checked out communicated data size
        - A high volume of office files are copied from `10.0.2.107` to `10.0.1.101`
        -
        - Do outline analysis `stats, bytes_in/bytes_out, values(filename)`
