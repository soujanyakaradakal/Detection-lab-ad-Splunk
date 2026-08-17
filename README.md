# Detection Lab: Active Directory + Splunk SIEM with Simulated Password-Spray Attack

## Overview
This project is a hands-on home lab built to simulate a real-world SOC (Security Operations Center) workflow: **build → attack → detect**. I stood up a Windows Active Directory environment, configured a Splunk SIEM to monitor it, simulated a password-spray attack from a Kali Linux machine, and used Splunk to detect and analyze the attack.

## Objective
To gain hands-on experience with the core skills of an entry-level SOC Analyst:
- Configuring and administering Active Directory
- Deploying and configuring a SIEM (Splunk)
- Understanding a common attack technique (password spraying)
- Writing detection logic to identify malicious login activity from log data

## Environment

| Component | Details |
|---|---|
| Domain Controller | Windows Server 2022, promoted to AD DS, domain `lab.local` |
| SIEM | Splunk Enterprise, installed on the Domain Controller |
| Attacker Machine | Kali Linux |
| Virtualization | Oracle VirtualBox |
| Test Accounts | `jsmith`, `pnair` (created in Active Directory) |
| Network | Isolated internal network (`attacklab`) connecting DC01 and Kali, separate from internet-facing traffic |

## Build Steps

1. **Stood up the Domain Controller** — Installed Windows Server 2022 in a VM, promoted it to a Domain Controller for `lab.local` using PowerShell (`Install-ADDSForest`).
2. **Created test user accounts** — Added two Active Directory users (`jsmith`, `pnair`) via `New-ADUser` to simulate real employee accounts.
3. **Installed and configured Splunk** — Deployed Splunk Enterprise on the Domain Controller and configured a local Windows Event Log collection to ingest the **Security** event log, so all logon/logoff activity is captured and searchable.
4. **Set up an isolated attack network** — Configured a second network adapter on DC01 and connected it to an internal-only VirtualBox network (`attacklab`), with Kali Linux on the same network. This kept the simulated attack traffic isolated from the DC's internet-facing adapter.
5. **Simulated a password-spray attack** — From Kali, used `netexec` (`nxc`) to attempt SMB logins against both test accounts using an incorrect password:
   ```
   nxc smb 192.168.50.10 -u users.txt -p passwords.txt
   ```
   This is a **password-spray attack**: instead of guessing many passwords against one account (which risks account lockout), an attacker tries one password against many accounts — a stealthier, real-world technique.
6. **Detected the attack in Splunk** — Searched the Security event log for **EventCode 4625** (failed logon) and confirmed both attack attempts were captured, including the source IP of the attacking machine (Kali, `192.168.50.20`).
7. **Built a detection query** — Wrote a Splunk search to flag the password-spray pattern (multiple distinct accounts failing login on the same host):
   ```
   index=* EventCode=4625
   | stats count as failed_attempts, dc(Account_Name) as unique_accounts by host
   | where unique_accounts >= 2
   ```

## Key Windows Event Codes Used

| Event Code | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4672 | Special privileges assigned (e.g. admin logon) |

## Detection Logic Explained
A single failed login is usually just a typo. A **password spray attack** looks different: multiple *different* accounts failing login in a short window, often from the same source. My detection query flags any host where 2 or more distinct accounts have failed logons — surfacing exactly this pattern rather than relying on manually eyeballing logs.

## Skills Demonstrated
- Windows Server / Active Directory Domain Services administration
- SIEM deployment and log source configuration (Splunk)
- Understanding of MITRE ATT&CK-aligned attack techniques (Password Spraying — T1110.003)
- Windows Security Event Log analysis
- Basic network segmentation using VirtualBox internal networks
- Firewall and SMB protocol troubleshooting (Windows Defender Firewall, SMBv1 vs SMBv3)
- Splunk Search Processing Language (SPL) for detection engineering

## Challenges & Troubleshooting
Setting this up surfaced several real-world networking and Windows administration issues that had to be diagnosed and resolved:
- **Windows Firewall blocking SMB (port 445)** on the internal network adapter — required both a firewall rule and profile-level troubleshooting.
- **VirtualBox Promiscuous Mode** needed to be set to "Allow VMs" for inter-VM traffic to pass correctly on the internal network.
- **SMBv1 vs SMBv3** — modern netexec/SMB tooling defaults to attempting SMBv1 first, which Windows Server 2022 disables by default for security reasons (related to the EternalBlue/WannaCry legacy). Diagnosed via `nmap` port scanning and verbose tool output.

## What I'd Do Next
- Build a Splunk dashboard to visualize failed logon trends over time
- Add a saved alert that triggers automatically when the detection query matches
- Expand the lab to include a second Windows client machine for more realistic lateral movement scenarios
- Test detection against additional attack techniques (e.g. Kerberoasting, pass-the-hash)

---
*This lab was built entirely in a personal home environment using free/evaluation software (Windows Server 2022 Evaluation, Splunk Free, Kali Linux, VirtualBox) for educational purposes.*


## Screenshots

![Splunk Detection](screenshots/splunk-detection-4625.jpg)

![Active Directory Users](screenshots/active-directory-users.jpg)

![Kali Attack Command](screenshots/kali-attack-command.jpg)

![Detection Query](screenshots/detection-query-results.jpg)
