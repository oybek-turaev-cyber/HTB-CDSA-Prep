# Skills Assessment Challenges:
- Scenario:
    - the SOC manager tasked you with conducting a forensic investigation through `Velociraptor.`

1. Using VAD analysis, pinpoint the suspicious process and enter its name as your answer. Answer format: .exe

    **Solved:**
    - J'ai cree un artifact pour VAD dans le `Velociraptor`
    - J'ai trouve ce process quand j'ai analyse le `AppData` directory j0seph
    - Et Voila, c'est fini!

2. Determine the IP address of the C2 (Command and Control) server and enter it as your answer.

    **Solved:**
    - J'ai analyse le fichier `.netstat`
    - J'ai fait conversion au JSON: `$json = Get-Content -Raw -Path ".\Velociraptor_netstat.json" | ConvertFrom-Json`
    - Apres, j'ai analyse que le process `roundll32.exe` a communique avec cet IPv4: `3.**.***.*`
    - Et voila, c'est fini

3. Determine the registry key used for persistence and enter it as your answer.

    **Solved:**
    - Pour trouver la cle de registry, j'ai utilise l'outil `Autoruns`
    - Apres, j'ai cherche le process mefiant ici et j'ai trouve la cle correcte
    - Voila, ca y est! C'est fini!

4.  Determine the folder that contains all Mimikatz-related files and enter the full path as your answer.

    **Solved:**
    - Just j'ai utilise `Windows File Explorer` filter pour le mot "mimikatz"
    - Et apres, j'ai obtainu le drapeau

5. Determine the Microsoft Word document that j0seph recently accessed and enter its name as your answer. Answer format:

    **Solved:**
    - Pour trouver ca, j'ai utilise un artifack `Windows.RecentDocs` dans le Velociraptor
    - Et apres, j'ai trouve le fichier avec une extension .DOCX
    - Voila, c'est tout! Fini!
    - La vie est belle!


