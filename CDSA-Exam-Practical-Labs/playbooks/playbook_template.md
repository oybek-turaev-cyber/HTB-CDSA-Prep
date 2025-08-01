# [Incident Type] Incident Response Playbook

## Purpose
Respond to and investigate [incident type, e.g., Phishing Email with Credential Harvesting].

## 1. Detection
- SIEM Alert: [Splunk/Sentinel/ELK Query here]
- Email received by user flagged as suspicious
- Triggered alert: `suspicious_email_received`

## 2. Investigation

### Artifact Collection
    Source          Artifact                        Tool/Command

- Email      >> Headers, URLs, attachments   >>  Outlook Message Header Analyzer
- Network    >> Domain/IP accessed           >>  Zeek, Suricata, Wireshark
- Host       >> Processes, browser history   >>  Sysmon logs, Kape, Velociraptor
- Logs       >> Login attempts, MFA status   >>  Auth logs, O365 logs, etc.

### Key Things to Check
- Was the URL visited? (Proxy/DNS logs)
- Were credentials entered? (POST requests)
- Did attacker gain access? (login logs)

## 3. MITRE ATT&CK Mapping
    Tactic         |  Technique ID   |    Name
- Initial Access    >>  T1566.001  >>  Spearphishing via Email
- Credential Access >>  T1110      >>  Brute Force / Harvesting
- Collection        >>  T1114      >>  Email Collection

## 4. Containment & Response

- Block malicious domain/IP at proxy/firewall
- Reset affected user's credentials
- Notify user of phishing and next steps
- Quarantine similar emails across org (search & destroy)

## 5. Post-Incident Actions

- Document IOCs in threat intel DB
- Review gaps in detection (did the SIEM catch it?)
- Update rules (e.g., YARA, Sigma, Splunk)
- Conduct awareness training if needed

## 6. Notes & References

- IOC: `hxxp://login-microsoft365[.]com`
- User: `jane.doe@org.com`
- [Link to similar Sigma rule](https://github.com/SigmaHQ/sigma)



