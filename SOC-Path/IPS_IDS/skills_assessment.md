# Practical Challenges

1. Detecting WMI Execution (Through WMIExec)
    - WMI >> allows for `management tasks`, such as the `execution of code` or `management of devices` locally & remotely.
    - WMI execution happens over `SMB` and `DCOM` protocols

    - Patterns:
        - `Win32_Process via the WMI service.`
        - `Create` method to start a new process such as `cmd.exe` or `powershell.exe.`

    - Challenge:
        There is a file named pipekatposhc2.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to WMI execution.
        Add yet another content keyword right after the msg part of the rule with sid 2024233 within the local.rules file
        so that an alert is triggered and enter the specified payload as your answer.

    **Solved:**
    - J'ai utilise ce fichier >> local.rules
    - J'ai analyse la regle et apres j'ai compris que je dois faire un filter avec SMB protocol
    - J'ai trouve une requeste avec ces details >> J'ai besoin de certaine methode!
    - J'ai trouve le payload a debut de `__PARAMETERS..cmd /c powershell -v 2 -e ` mais avant,
    - J'ai trouve aussi ces informations: `.Win32API|Process and Thread Functions|CreateProcess|lpCurrentDirectory`
    - Voila, j'ai obtenu le drapeau > `C....e`


2.  Detecting Overpass-the-Hash
    - unauthorized access to resources by using a `stolen NTLM` (NT LAN Manager) `hash` or Kerberos key
    - goal >> use the hash to create a `Kerberos TGT` (Ticket-Granting Ticket) to `authenticate to Active Directory (AD).`

    - Patterns:
        - normal user uses >> `AES256 encryption`
        - attacker uses >> `RC4-HMAC`

    - Challenge:
        There is a file named wannamine.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the
        Overpass-the-hash technique which involves Kerberos encryption type downgrading.
        Replace XX with the appropriate value in the last content keyword of the rule with sid XXXXXXX within the
        local.rules file so that an alert is triggered as your answer.


    **Solved:**
    - J'ai compris que je dois trouver les patterns avec RC4-HMAC >>
    - Sur le web, j'ai trouve que le 23 decimal == RC4 ketype dans le Wireshark
    - J'ai analyse aussi le fichier local.rules pour comprende la regle
    - Apres, 23 == 0x17, voila, c'est comment j'ai obtenu le drapeau

3.  Detecting Gootkit's SSL Certificate
    - `Neutrino`, a `notorious exploit kit`, and `Gootkit`, `a potent banking trojan`
    - Gootkit begun to communicate over the network using `SSL/TLS encryption`


    - Patterns:
        - But, `(CN) "My Company Ltd.".` is not encrypted
        - Cybercriminals frequently `employ self-signed` or `non-trusted CA issued certificates` to foster encrypted communication

    - Challenge:
        There is a file named neutrinogootkit.pcap in the /home/htb-student/pcaps directory, which contains
        network traffic related to the Neutrino exploit kit sending Gootkit malware.
        Enter the x509.log field name that includes the "MyCompany Ltd." trace as your answer.

    **Solved:**
    - J'ai utilise Zeek pour ca
    - J'ai utilise Wireshark: c'est pour la requeste differente: `http.request.method == "POST" && frame contains "ddager"`
    - Zeek command: `/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/neutrinogootkit.pcap`
    - Apres, j'ai regarde au fichier >> x509.log >> ici, j'ai trouve ca:
        `CN=localhost,OU=IT,O=MyCompany`
    - Pour finir cette tache, regarde ci-dessus >> et voila, j'ai obtenu le drapeau!






