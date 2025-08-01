# Incident Reporting Intro:
- Identify Security Incidents >> Sources:
    - Security Systems / Tooling in Place
    - Human Observations
    - Third Party Notifications

- Categorize Incidents:
    - Malware
    - Phishing
    - DDoS
    - Unauthorized Access
    - Data Leakage
    - Physical Breach

- Incident Severity Levels:
    - Critical >> threat to core business functionalities
    - High >> normal threat to business operations
    - Medium >> not immediate threat >> by time affects
    - Low >> Trivial incidents & routine anomalies

# Reporting Process
- Steps:
    - Initial Detection & Acknowledgement
    - Preliminary Analysis
    - Incident Logging >> `JIRA` or `TheHiveProject`
    - Notification of Relevant Parties
    - Detailed Investigation & Reporting
    - Final Report Creation
    - Feedback Loop

# Elements
- Executive Summary: broader audience/non-technical stakeholders
    - Parts:
        - Incident ID
        - Incident Overview
        - Key Findings
        - Immediate Actions Taken
        - Stakeholder Impact

- Technical Analysis:
    - Affected Systems & Data
    - Evidence Sources & Analysis
    - Indicators of Compromise (IoCs)
    - Root Cause Analysis
    - Technical Timeline
        - Reconnaissance
        - Initial Compromise
        - C2 Communications
        - Enumeration
        - Lateral Movement
        - Data Access & Exfiltration
        - Malware Deployment or Activity (including Process Injection and Persistence)
        - Containment Times
        - Eradication Times
        - Recovery Times
    - Nature of the Attack
    - Impact Analysis

- Response and Recovery Analysis
    - Immediate Response Actions
        - Revocation of Access
        - Containment Strategy

    - Eradication Measures
        - Malware Removal
        - System Patching

    - Recovery Steps
        - Data Restoration
        - System Validation

    - Post-Incident Actions
        - Monitoring
        - Lessons Learned

- Diagrams
    - Incident Flowchart
    - Affected Systems Map
    - Attack Vector Diagram

- Appendices
    - repository for supplementary material

- **Best Practices:**
    - `Root Cause Analysis`: Always aim to find the root cause of the incident to prevent future occurrences.
    - `Community Sharing`: Share non-sensitive details with a community of defenders to improve collective cybersecurity.
    - `Regular Updates`: Keep all stakeholders updated regularly throughout the incident response process.
    - `External Review`: Consider third-party cybersecurity specialists to validate findings.





























