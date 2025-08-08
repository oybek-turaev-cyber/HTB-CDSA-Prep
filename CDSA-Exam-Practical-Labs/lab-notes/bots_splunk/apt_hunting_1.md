# BOTS Splunk
## APT Hunting #1
- Victim Info:
    - Frothly >> Beer Company >> USA
    - Notification from Law Enforcement FBI
    - Alice >> SOC Analyst
    
- APT:
    - TAFDOINGANG APT >> Eastern Asia-based
    

- Hypotheses:
    1. Spearphishing:
        - Hunting should not be tight with certain techniques >> but with your Company
        
        - Possible Scenario:
            - Possible initial foothold >> Spearphishing Attachement
            - Description: attachment via email >> user execution

        - Check This Out: 
        - related: sourcetypes >> 	
        - WebLogic_Access_Combined >> access_combined >> apache_error >> weblogic_stdout >> who
        
    2. Splunk Action:
        - Find attachments in emails
            - Using `selected fields` >> `host, src_ip, attach_filename`
        - Attack started around 23th August 2017 >> so that email delivery should have occurred before
        - Make choices between suspicious attachments >> `invoice.zip`
            - Now, need to check this filename info
            - Sender >> Recipients >> Size >> Subject >> Body >user001-splk> Attach_Name
            - Use Splunk `selected fields` for those attributes above
            - Found that sender is one person >> `Jim Smith <jsmith@urinalysis.com>`
            - But the recepients are 4 people 
            - Hash & Size of recevied messages are the same
            - Content Filed >> IP is found `185.83.51.41` >> original sender
            - We check the Mail Sender >> (Jim as well)
            - Take the hash of the file >> see with VirusTotal
        
    3. Conclusion:
        - Hypothesis is confirmed! Fishing; Sender(IP, Name); File; Recepients;
    
- User Execution:
    1. Hunt Direction:
        - What sourcetpyes we should check for this attachment?
        - What dates we should check after or before spearphishing file case?
        - Any other clues from these processes:
        - What user or username >> host >> process >> execute  >> or access to this file
        - Then what happened later after the execution;
    
    2. Splunk Action:
        - Neeed to check Sysmon File Acess (Sysmon ID 11)
        - Exclude certain sourcetypes to see what else data you can see
        - Check out the Sysmon as sourcetype for invoice.zip
        - There we see some powershell based commands & .exe runs >> `WINWORD.EXE` executed `invoice.doc` from `invoice.zip`
        - More clarification >> Check the first Sysmon Event
        - `CommandLine` part shows Powershell Ecnoded Code
    
    3. Conclusion?
        - Hypothesis is confirmed >> Done
        - Attack Vector >> Sender >> Recipient >> File Associated >> Later Actions >> Identified
        - Cycle >> `Email from btun@frothly.ly > Invoice.zip >> Invoice.doc >> Powershell CommandLine`
