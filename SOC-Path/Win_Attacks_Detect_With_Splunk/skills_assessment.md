# Skills Assessment
- Scenario:
    - Identifying malicious activity using Splunk and Zeek logs.

- Challenges:
    1. Use the "empire" index and the "bro:http:json" sourcetype.
       Identify beaconing activity by modifying the Splunk search of the "Detecting Beaconing Malware" section
       and enter the value of the "TimeInterval" field as your answer.

    **Resolu:**
        - J'ai utilise cette commande:
        - Le cle moment est que >> `prcnt` n'est pas 90 >> moins `le chiffre 86` donc `80` est bien
            ```code
                    index="cobaltstrike_beacon" sourcetype="bro:http:json"
                    | sort 0 _time
                    | streamstats current=f last(_time) as prevtime by src, dest, dest_port
                    | eval timedelta = _time - prevtime
                    | eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
                    | eval upper=avg*1.1
                    | eval lower=avg*0.9
                    | where timedelta > lower AND timedelta < upper
                    | stats count, values(avg) as TimeInterval by src, dest, dest_port, total
                    | eval prcnt = (count/total)*100
                    | where prcnt > 80 AND total > 10
            ```
        - Voila, c'est fini!


    2.  Use the "printnightmare" index and the "bro:dce_rpc:json" sourcetype to create a Splunk search
        that will detect possible exploitation of the PrintNightmare vulnerability.
        Enter the IP included in the "id.orig_h" field as your answer.

    **Resolu:**
        - J'ai utilise cette commande:
            ```code
                index="printnightmare" sourcetype="bro:dce_rpc:json"
                | bin _time span=5m
                | stats count by id.orig_h, id.resp_h
            ```
        - Apres, j'ai trouve la resultat! car il y moins de combination

    3. Use the "bloodhound_all_no_kerberos_sign" index and the "bro:dce_rpc:json" sourcetype to create a
       Splunk search that will detect possible BloodHound activity
       (https://www.lares.com/blog/active-directory-ad-attacks-enumeration-at-the-network-layer/).
       Enter the IP included in the "id.orig_h" field as your answer.

     **Resolu:**
        - J'ai utilise cette commande:
            ```code
                index="bloodhound_all_no_kerberos_sign" sourcetype="bro:dce_rpc:json"
                | bin _time span=5m
                | stats count by id.orig_h, id.resp_h
            ```
        - Apres, j'ai trouve la resultat! car il y moins de combination
        - Je sais que cette commande n'est pas ideal mais ca marche just pour trouver le drapeau!
































