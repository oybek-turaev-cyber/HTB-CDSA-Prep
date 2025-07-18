# YARA
- Key Info:
    - identify & classify `files` based on certain patterns
    - YARA rules >> can recognize >> `textual & binary patterns`
        - can be applied to `memory forensics` as well
        - rules are in `.yara` or `.yar` files
    - can scan a set of files
    - you analyze the malware >> based on found unique features >> you customize the YARA rules then

- Usage:
    - Malware Detection & Classification
    - File Analysis
    - IoC detection
    - Community-rule sharing
    - Custom rules
    - IR & Proactive Threat Hunting

- Rule Structure:
    ```yara
    rule my_rule {

        meta:
            author = "Author Name"
            description = "example rule"
            hash = ""

        strings:
            $string1 = "test"
            $string2 = "rule"
            $string3 = "htb"

        condition:
            all of them
    }
    ```

- Condition:
    - `all of them` >> if all strings are found >> then it triggers
    - `filesize < 100KB and (uint16(0) == 0x5A4D or uint16(0) == 0x4D5A)`
        - Here >> `unint16(0) == 0x5A4D` >> the first 16 bites unsigned integer or 2 bytes starting from offset = 0,
            if these 2 bytes are equal to `0x5A4D` (hex of `MZ`)

## Developing YARA Rules
- Actions:
    - first need to find unique patterns of the malware:
        - `strings malware.exe`
            - based on findings, build a rule >> refer to `./upx_detector.yar`
            - it's a manual approach

- Developing a YARA Rule Through **yarGen**
    - `yarGen` is automatic YARA rule generator
    - comes with database of goodware strings >> so mostly knows what's normal & what's not normal

    - Command:
        - `./temp` folder >> malware.exe
        - `python3 yarGen.py -m /home/htb-student/temp -o htb_sample.yar`
            - It scans the malware from the given path >> then generates rules for this malware with given name
            - `-m` to specify the Path of the malware to be scanned, `-o` >> output file

    - Usage of Yara:
        - `yara htb_sample.yar /path_to/malwares`

- Example 1: ZoxPNG RAT Used by APT17
    - here use `strings malware.exe`
    - then customize the rule
    - refer to the `./example#1.yar`
    - possible to include `imphash` also via `PE Module` of python
    ```yara
    condition:
            ( uint16(0) == 0x5a4d and filesize < 200KB and (
                    pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9" or
                    1 of ($x*) or
                    6 of them`
    ```

    - In this example >> checking `executable magic word`, filesize, imphash,
    - `1 of ($x*)` At least one of the `$x` strings must be present in the file.
    - `6 of them` >> at least six of the strings (`from both $x and $s categories`) should be found within the scanned file.


- Example 2: Neuron Used by Turla
    - In this case, as the malware is written in .NET framework
    - better to use `monodis` tool rather than `strings`
        - `monodis --output=code Microsoft.Exchange.Service.exe`
    - ideal option would be to use `.NET debugger & assembly editor: dnSpy`

    - YARA rule:
        ```yara
        strings:
            $class1 = "StorageUtils" ascii fullword
            $class2 = "WebServer" ascii
            $class3 = "StorageFile" ascii
            $dotnetMagic = "BSJB" ascii

        condition:
            (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 6 of them`
        ```

    - Here, `ascii` and `fullword` are modifiers to tell YARA that strings should be ASCI chars & stand-alone full word
    - `BSJB` >> This signature is present in the CLI (Common Language Infrastructure) header of .NET binaries,
        and its presence can be used to indicate the file is a .NET assembly

- Example 3: Stonedrill Used in Shamoon 2.0 Attacks
    - this attack has a pattern: encrypted resource
    - so that we know that `encrypted/compressed/obfuscated files` have higher `entropy`
    - `max entropy` value is `8.0` >> need to calculate the entropy of the malware
    - this is gonna be a pattern for the rule then

    - refer to the `./example#3.yar`

- Idea: **combination of clever automatic preselection and a critical human analyst beats both the fully manual and fully automatic generation process.**


- Practical Challenge:
    1.  Perform string analysis on the "DirectX.dll" sample that resides in the "/home/htb-student/Samples/YARASigma" directory of this section's target.         Then, study the "apt_apt17_mal_sep17_1.yar" YARA rule that resides in the "/home/htb-student/Rules/yara" directory and
        replace "X.dll" with the correct DLL name to ensure the rule will identify "DirectX.dll". Enter the correct DLL name as your answer.

    **Solved:**
    - J'ai utilise cette command pour enqueter: `strings DirectX.dll`
    - Apres, j'ai analyse le `.yar` fichier
    - Je pense que cette commande m'a aide efficacement: `strings DirectX.dll | grep -e *.dll`
    - Voila, j'ai obtenu le drapeau

## Hunting Evil with YARA (Windows Edition)
- **Process:**
    - Tool: Hex Editor: `HxD` in Win >>
    - In Lin >> `hexdump malware.exe -C | grep crysis -n3`

- **Goal:**
    - is to identify the strings or patterns
    - then need to take `hex bytes` of those patterns to put in YARA rule
    - for example the pattern `sssssbsss` >> `73 73 73 73 73 62 73 73 73`
        - `$string_ssss = { 73 73 73 73 73 62 73 73 73 }` >> one case

- **YARA:** >>
    - `yara64.exe -s C:\Rules\yara\ransomware.yar C:\Samples\YARASigma\ -r 2>null`
        - `-s` to scan >> rule >> then malware
        - `-r` >> recursive scan for the directory/subdirs also
        - `2>null` >> stream 2 >> error output >> to a null device >> to hide any error messages

- **Hunting for Evil Within Running Processes with YARA:**
    - YARA rule targets >> Metasploit's meterpreter shellcode, believed to be lurking in a running process.

    - refer to `./meterpreter.yar`

    - Command:
        `Get-Process | ForEach-Object { "Scanning with Yara for meterpreter shellcode on PID "+$_.id;
        & "yara64.exe" "C:\Rules\yara\meterpreter_shellcode.yar" $_.id }`

    - Get-Process >> | >> {..} script
    - **ForEach-Object dissects each process, prompting yara64.exe to apply our YARA rule on each process's memory.**

    - YARA scanner with a specific PID a:
        - `yara64.exe C:\Rules\yara\meterpreter_shellcode.yar 9084 --print-strings`

- **Hunting for Evil Within ETW Data with YARA:**
    - ETW >> high-performance logging system used to monitor and debug Windows.
        - not running by default
        - started when triggered by apps or services

    - Core Components:
        - `providers` >>  Apps or system components that generate events (e.g., kernel, antivirus
        - `controllers` >> Start/stop tracing sessions and set what to collect
        - `consumers` >>  Tools or apps that read and process the events (e.g., Event Viewer, Sysmon, custom tools).

    - Flow: `Provider → Controller (enables) → Event data → Consumer (reads).`

    - SilkETW >> open-source tool >>  simplifies access to ETW
        -  easy logging of ETW providers
        -  via command line or JSON config
        -  It’s a consumer/controller built on ETW.
        -  **compatible to integrate YARA Rules**

    - Useful Providers:
        - *Ohh man, it's merveilleux d'avoir ces providers geniales:*
        - Some of them:

- **Example 1: YARA Rule Scanning on Microsoft-Windows-PowerShell ETW Data:**
    - Command:
        - ` .\SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -ot file -p ./etw_ps_logs.json -l verbose -y C:\Rules\yara  -yo Matches`
            - `-t user` >> tracing mode >> user >> only traces user-created, apps events
            - `-pn` >> specific provider name
            - `-ot file` >> saying it's file-format
            - `-p ./etw_ps_logs.json` >> output file name and path
            - `-y` >> to tell to integrate YARA rules
            - `-yo` >> specifies YARA output option >> set to "Matches,"
            -
    - YARA Rule:
    ```yara
    rule powershell_hello_world_yara {
	    strings:
		    $s0 = "Write-Host" ascii wide nocase
		    $s1 = "Hello" ascii wide nocase
		    $s2 = "from" ascii wide nocase
		    $s3 = "PowerShell" ascii wide nocase
	    condition:
		    3 of ($s*)
        }
    ```

    - Process: if we run this powershall command now, it triggers:
        - `Invoke-Command -ScriptBlock {Write-Host "Hello from PowerShell"}`
- **Example 2: DNS:**
    - Command:
        - ` .\SilkETW.exe -t user -pn Microsoft-Windows-DNS-Client -ot file -p ./etw_dns_logs.json -l verbose -y C:\Rules\yara  -yo Matches`

    - YARA Rule:
     ```yara
        rule dns_wannacry_domain {
	        strings:
		        $s1 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
	        condition:
		        $s1
        }
    ```
    - Trigger: `ping iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`

- **Practical Challenge:**
    1. Study the "C:\Rules\yara\shell_detector.yar" YARA rule that aims to detect "C:\Samples\MalwareAnalysis\shell.exe" inside process memory.
       Then, specify the appropriate hex values inside the "$sandbox" variable to ensure that the "Sandbox detected" message will also be detected.
       Enter the correct hex values as your answer. Answer format: Remove any spaces

    **Solved:**
    - J'ai utilise l'outil: `HxD` >> et j'ai cherche le mot `Sandbox Detected`
    - Apres, j'ai copie le hex bytes et j'ai modifie le fichier yar
    - Voila, ca y est, c'est fini!

## Hunting Evil with YARA (Linux Edition)
- Key Idea:
    - You got a memory dump >> need to analyse it
    - YARA-based scans directly on these memory images

- Process:
     1. Create YARA Rules
     2. Compiler YARA Rules: optional : yet effective
        - compile YARA rules into a `binary format`
        - `yarac` >> compiler >> creates a file with `.yrc` extension
        - harder to comprehend >> some protection
     3. Obtain Memory Images
     4. Run YARA

- Command:
    - `yara file.yar compromised_system.raw --print-strings`

- Tandem with Volatility
    - YARA can work with Volatility as a plugin
    - `yarascan` plugin

- Example: **Single Pattern YARA Scanning Against a Memory Image:**
    - Command:
        - `vol.py -f compromised_system.raw yarascan -U "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"`
            - volatility tool is running using specified yara rule
            - `yarascan -U` option >> for single pattern search

- Example: **Multiple YARA Rule Scanning Against a Memory Image:**
    - Command:
        - `vol.py -f compromised_system.raw yarascan -y wannacry_artifacts_memory.yar`
        - `yarascan -y` >> to specify a file or files

- Practical Challenge:
    1. Study the following resource https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html
       to learn how WannaCry performs shadow volume deletion. Then, use yarascan when analyzing
       "compromised_system.raw" to identify the process responsible for deleting shadows.
       Enter the name of the process as your answer.

    **Solved:**
    - J'ai compris que l'attaquant peut utiliser certains outils:
    - `vssadmin.exe` ou `wmic >> shadowcopy` ou `wbadmin.exe` ou `bcdedit`
    - Mais parmi ces, pour effacer/ supprimer, il doit utiliser `vssadmin.exe` ou `wmic >> shadowcopy` commande
    - Selon l'information, j'ai modifie mon fichier `.yar` pour chaque option:
    - Je n'ai pas trouve avec `vssadmin.exe` mais j'ai obtenu quelques informations avec `shadowcopy` suivante:
    ```code
        shadowcopy.delete.&.bcdedit./set  .{default}.boots  tatuspolicy.igno
        reallfailures.&.
        bcdedit./set.{de
        fault}.recoverye
        nabled.no.&.wbad
        min.delete.catal
        og.-quiet.vs..co fi.13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94
   ```

    - Voila, ca y est, c'est fini >> j'ai obtenu le drapeau

## Hunting Evil with YARA (Web Edition)
- Tool
    - `Unpack.Me`  >>  tailored for malware unpacking
    - possible to run YARA rules against their huge database of malware submissions
    - Work with Website >> Create & Put YARA Rule >> Validate  >> Run
    - Voila, c'est genial!


















