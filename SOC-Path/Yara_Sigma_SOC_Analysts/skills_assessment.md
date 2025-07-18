# Skills Assessment

1.  The "C:\Rules\yara\seatbelt.yar" YARA rule aims to detect instances of the "Seatbelt.exe" .NET assembly on disk.
    Analyze both "C:\Rules\yara\seatbelt.yar" and "C:\Samples\Seatbelt.exe" and
    specify the appropriate string inside the "$class2" variable so that the rule successfully identifies
    "Seatbelt.exe". Answer format: L________r

    **Solved:**

    - J'ai connais que la reponse doit etre en ce format `L.......r`
    - Apres, j'ai utilise cette commande avec `strings`
        - `strings.exe .\Seatbelt.exe | Select-String '^L.*r$'`
    - J'ai trouve quelques options et j'ai choisi attentivement une option:
    - Apres, j'ai modifie le fichier `seatbelt.yar` pour ca
        - `yara64.exe -s C:\Rules\yara\seatbelt.yar C:\Samples\YARASigma\` >> fonctionne bien!
    - Et Voila, ca y est, c'est fini

2.  Use Chainsaw with the "C:\Tools\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml"
    Sigma rule to hunt for shadow volume deletion inside "C:\Events\YARASigma\lab_events_6.evtx".
    Enter the identified ScriptBlock ID as your answer.

    **Solved:**
    - J'ai utilise cette commande:
    ```code
    .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_6.evtx
    -s .\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml
    --mapping .\mappings\sigma-event-logs-all-new.yml
    ```
    - Apres, j'ai obtenu ca: `  faaeba08-***0******2-ba48-***********28`
    - Voila, ca y est! c'est fini! La vie est belle!

