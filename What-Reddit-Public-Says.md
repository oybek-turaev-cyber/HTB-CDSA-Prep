# Pre-Exam Thoughts:
    1. **Biggest thing to prep for:**
        - Log interpretation (you’ll get raw data, and you need to spot anomalies or indicators fast)
        - Correlation logic — not just “what happened,” but “what’s the root cause or next step?”
        - Understanding the investigative flow — think like a responder, not just a quiz-taker

    2. **You’ve got the background — now just drill the tools, know your logs cold, and go in calm**

    3. **Very good understanding of the Kill Chain**

    4. **I always ask myself as an attacker, what would I be doing next after achieving certain milestones?**

    5. **You must generate hypotheses and then investigate them**

# Pre-Exam Labs
    1. `"Academy X Labs"` >> Choose the modules from SOC Path >> it shows related Sherlocks

    2. **Is watching ippsec do Sherlock's or Malwarecube over at TCM do some investigations.**

    3. **Malwarecube has done a few of those livestreams, and tbh I prefer his style as he is constantly explaining rationale and
        attempts to put you in the investigative mindset.**

    4. *Redo SIEM labs blindly and attempting Splunk BOTS before the exam.* >> `bots.splunk.com`

    5. *Practice being overly detailed and focus on clearly connecting the dots in your report from the flags you capture in the BOTs challenges.*

# Exam-Content
    1.  *2 Incidents To investigate >> The first one you need to answer 20 question about it >> You use Elastic and Volatility*

    2.  *For the second incident you are free to explore to detect the attack origins, how the attacker move across endpoints,
        all the malicious activity associated, in this incident you use Splunk.*

    3. *You'll need Elastic, Splunk and Volatility*

    4. **Two Incidents >> 1st done in 8 hours >> 2nd another day >> report other days >> finish 2 days earlier**

# Exam-Time Reflections
    1. How did the attacker gain initial access? On which host? Why was the attacker able to gain access on this particular host?
       Were there reconnaissance activities?

    2. Did the attacker priv-esc? How did it do so? What did it do after priv-esc? Creds dumping? Lateral Movement? Info Exfiltration?

    3. Did the attacker conduct recon after initial access? Why did it do so? What did it do with that information?

    4. Did the attacker establish persistence? How? What were the evidence?

    5. Were there data Exfiltration? How do you prove that?

# Exam-Time Report
    1. *I recommend constantly taking notes of all the queries, commands and screenshots of all the SIEM results you find interesting*
      *that helped you either find a flag (in incident 1) or anything interesting or that could be malicious in both incidents in general.*

    2. *For the report, just follow the Sysreptor structure and the examples given on the sample report.*

    3. *I kept mine pretty concise and straight to the point with only 35 pages total and passed first try.*

    4. *I was overly detailed*

    5. *Try to frame it the way HTB does in the Security Incident Reporting module.*

    6. `Sysreptor` >> Look at the sample given `CDSA`

    7. Read about reports: `https://thedfirreport.com/`
