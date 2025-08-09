# BOTS Splunk

## APT Hunting #1 - Reconnaissance
- Key Points:
    - Start Broadly and Go Narrow
    - Work with Time Ranges

- Victim Info:
    - Frothly >> Beer Company >> USA
    - Notification from Law Enforcement FBI
    - Alice >> SOC Analyst

- APT:
    - TAFDOINGANG APT >> Eastern Asia-based

- Hypotheses #1: >> User Agents Strings
    1. Hunt Direction:
        - What sourcetypes can be used for user agents strings
        - Some specific user agent strings
        - August 2017 timeline

    2. Splunk Action:
        - Found that >> `sourcetype="stream:http"` can provide User Agents Info
            - Set the timeline during August 2017
            - Found that the field >> `src_headers` contains `User-Agents` Info
            - Command: `rex field=src_headers "User-Agent: (?<user_agent_info>.*)` >> for the whole line
            - Anyway >> no need for regex: since we have a field `http_user_agent`
            - Command:
                ```code
                    index="botsv2" sourcetype="stream:http" site=www.froth.ly
                    | stats count by http_user_agent
                    | sort - count
                ```
            - I found the most User Agent >>
                - `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36`
            - For these, I used `whatismybrowser` user agents parser tool to get some nice data
            - But these are kinda expected User Agents, however, I found another one seems interesting
                - `Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4`
                    - What really suspicious here >> it's North Korean based web browser >> highly >> this could be the country of this traffic originator
                - The log is coming from the single host `eridanus` >> and src_mac address is also single >> `0A:96:DA:8D:C8:A1` >> `85.203.47.86`
                - All the packets are going to the single recepient >> dest_ip = `172.31.6.251` & dest_mac = `0A:5D:A3:E3:B9:92`
                - `ko-kp` >> web-browser language code for "north korean"
                -
            - Found out that from Asset Center `172.31.4.249` is the server for aws linux /web/mysql
            -
        - OSINT:
            - For IP `85.203.47.86`, ASN ( Autonomous System Number) assigned network number >> and
            - Express VPN are associated for this IP while bein in Hong Kong
            - apps.db.ripe.net >> europe ASN assigning database also checked out

    3. Conclusion:
        - Connection:
            - `Attacker IP `85.203.47.86` >> Using ASN 133752 & Express VPN >> www.froth.ly (172.31.6.251)`
            -
        - Idea Here >> it could be a trap by the adversary this type of reconnaisance
            - That's why it's good idea to give a try when it occurs, okay?
            -
        - Strategy:
            - Monitor certain IP >> may not be effictive since anytime attacker can change it
            - May be good to monitor block broader NetBlock
            - Monitor traffic from certain ASNs

- Hypotheses #2:
    1. Hunt Direction:
        - What Attacker can gain from our OSINT info about company
        - Pre Process of reconnaisance for attacker
        - Social Media/ website / others

    2. Splunk Action:
        - Idea is to use `http_content_typ` field to see http traffic content what MIME types are accesses
            - Found that `uri_path` >> `/files/company_contacts.xlsx` was accessed
            - `http://www.froth.ly/files/company_contacts.xlsx` >> downloaded from company website

    3. Conclusion:
        - This reconnaisance from the found IP >> started to navigate to website
        - Accessed to contacts.xlsx and then downlaoded 05/08/2017 11:49:00 am
        - User Agent Info Worked Out!
        -
        - Minimize OSINT of the company
        - Deploy some honeypots/files/workstation to make busy the attacker & monitor


