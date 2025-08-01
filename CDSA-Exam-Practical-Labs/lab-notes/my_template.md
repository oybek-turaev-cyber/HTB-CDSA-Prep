## Lab Title: Phishing Investigation – Office365 Credential Harvesting

### Date: 2025-08-01

### Duration: ~1.5h

### Platform: HTB Academy – Threat Hunting Lab 1

### 1. Scenario Summary
User reported a suspicious email. Initial signs of credential theft via a fake login page. Lab simulates O365 with email headers and network captures.

### 2. Steps Taken
- Checked email headers → found suspicious reply-to domain
- Investigated clicked link → IP, domain, SSL certificate mismatch
- Pulled proxy logs → user session, HTTP GET requests to `hxxp://office365-login[.]cc`
- Correlated with MITRE T1566 (Phishing), T1114 (Email Collection)

### 3. Findings
- Domain: `office365-login.cc` registered 2 days ago
- User entered credentials into fake form
- No MFA trigger detected → account at risk

### 4. Key Indicators
- Domain: `office365-login.cc`
- IP: `192.168.2.45`
- TTPs: T1566, T1114
- User: `john.smith@org.com`

### 5. What I Learned
- Importance of checking reply-to in phishing
- Learned to analyze proxy logs for GET/POST behavior
- Identified lack of MFA as critical risk---

### 6. What I Would Improve Next Time
- Start with proxy logs earlier
- Use VirusTotal quicker for domain check
- Document alert in standard SOC report format

## Questions:
- “What did I miss?”            >>   Identify blind spots
    - Answer:

- “What took too long?”         >>   Find inefficiencies
    - Answer:

- “What worked fast?”           >>   Build your playbook
    - Answer:

- “What were the key IOCs?"     >>   Build memory
    - Answer:

- “Which MITRE TTPs involved”   >>   Link to real-world patterns
    - Answer:


