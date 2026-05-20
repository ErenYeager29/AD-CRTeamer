# Phase 06: Local Enumeration — What to Look For and Why

> **Why this phase exists**: Running winPEAS and being overwhelmed by output is useless. This phase teaches you to read a Windows host like a map — knowing what each finding means, why it's a vulnerability, and exactly which attack it enables. Enumeration is threat modelling, not data collection.

**Study time**: 1 week
**Difficulty**: Beginner–Intermediate

---

## Learning Objectives

- [ ] Explain what `whoami /priv` output tells you about available attack paths
- [ ] Identify an unquoted service path vulnerability from service enumeration output
- [ ] Identify a weak service binary permission from icacls output
- [ ] Find stored credentials in common locations
- [ ] Understand what AlwaysInstallElevated means and why it exists
- [ ] Prioritize findings by exploitability rather than just listing them

---

## 1. The Enumeration Mindset

Every item you discover in local enumeration should immediately trigger a question: **"What attack does this enable?"**

Don't collect data. Map trust relationships and attack surfaces:

| Finding | Question to ask |
|---------|----------------|
| SeImpersonatePrivilege enabled | Which Potato variant applies here? |
| Service running as SYSTEM with weak binary perms | Can I write to the binary path? |
| Unquoted path with spaces | Can I write to the intermediate directory? |
| AlwaysInstallElevated = 1 | Can I create a malicious MSI? |
| PowerShell history file | Does it contain credentials or interesting commands? |
| Scheduled task pointing to a user-writable script | Can I replace that script? |
| MSSQL running as a domain account | What rights does that account have in AD? |

---

## 2. Token Privileges — Reading `whoami /priv`

### Why privileges matter

Windows privileges are capabilities granted to a token. Some are extremely dangerous when enabled. Before doing anything else on a new host, run:

```cmd
whoami /priv
```

**Critical privileges to spot**:

| Privilege | Why it matters | Attack |
|-----------|---------------|--------|
| `SeImpersonatePrivilege` | Can impersonate any authenticating client | Potato attacks → SYSTEM |
| `SeAssignPrimaryTokenPrivilege` | Can assign tokens to processes | Same as above |
| `SeDebugPrivilege` | Can open any process with full access | Read LSASS directly |
| `SeTakeOwnershipPrivilege` | Can take ownership of any object | Take ownership of files/registry |
| `SeBackupPrivilege` | Can read any file regardless of ACL | Read SAM, NTDS.dit |
| `SeRestorePrivilege` | Can write any file regardless of ACL | Replace service binaries |
| `SeLoadDriverPrivilege` | Can load kernel drivers | Load malicious driver → kernel access |

**SeImpersonatePrivilege** is the one you'll see most on the exam. It's granted by default to:
- IIS application pool accounts
- SQL Server service accounts
- Network Service accounts
- Any service account that authenticates clients

The reason it exists: A service account needs to temporarily act as the user who is connecting to it. Kerberos uses this extensively.

**Why it leads to SYSTEM**: Potato attacks exploit the COM/DCOM or RPC activation path to get SYSTEM to authenticate to a service you control. When SYSTEM "connects" to your fake service, it creates an impersonation token for SYSTEM that you can steal and use to spawn a SYSTEM process.

---

## 3. Services — Three Ways They're Vulnerable

### Weak binary permissions

The service binary itself is writable by your user. Replace it with your beacon.

```powershell
# Find all services and their binary paths
Get-WmiObject Win32_Service | Select Name, PathName, StartName

# Check ACL on binary
icacls "C:\Program Files\SomeApp\service.exe"
# Look for: BUILTIN\Users:(F) or DOMAIN\Users:(W) or Everyone:(M)
# F = Full, W = Write, M = Modify — all exploitable
```

**Why this exists**: Poorly configured service installers sometimes set overly permissive ACLs. The developer or sysadmin didn't realize that "Everyone:Write" on a SYSTEM-run binary is catastrophic.

### Unquoted service path

Windows processes path names with spaces differently depending on quoting. The path:
```
C:\Program Files\My Application\service.exe
```

Without quotes, Windows **tries these paths in order**:
```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Application\service.exe
```

If you can write to `C:\` and create `Program.exe`, or write to `C:\Program Files\` and create `My.exe` — Windows executes your binary as the service's identity.

```powershell
# Find unquoted paths
Get-WmiObject Win32_Service | 
  Where-Object {$_.PathName -notmatch '^"' -and $_.PathName -match ' '} |
  Select Name, PathName, StartName
```

**Why this is so common**: Windows path parsing has worked this way for 30 years. Developers forget to quote paths. Microsoft's own application installer has had this bug.

### Weak service ACL

Not the binary, but the service object itself. If you have `SERVICE_CHANGE_CONFIG` on a service, you can change its `binPath` to anything.

```powershell
# AccessChk from Sysinternals
.\accesschk.exe -uwcqv "Domain Users" * /accepteula 2>nul
# Or: PowerUp
Invoke-AllChecks | Where-Object {$_.Check -eq "ModifiableServices"}
```

---

## 4. Privilege Escalation Shortcuts to Check First

### AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both must be `0x1`. If they are, any `.msi` file runs as SYSTEM. This policy exists to let non-admin users install approved software — but applying it globally means *any* MSI runs as SYSTEM.

### Stored credentials

```powershell
# Windows Credential Manager
cmdkey /list
# Look for generic or domain credentials stored

# Common file locations
Get-ChildItem C:\ -Recurse -Include *.xml,*.config,*.ini,*.txt -ErrorAction SilentlyContinue 2>$null |
  Select-String -Pattern "password|passwd|pwd|credential" -ErrorAction SilentlyContinue

# Unattended install files (common in enterprise deployments)
Get-Content C:\Windows\Panther\Unattend.xml -EA SilentlyContinue
Get-Content C:\Windows\System32\sysprep\unattend.xml -EA SilentlyContinue

# PowerShell history (every command ever typed interactively)
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -EA SilentlyContinue
```

**Why PowerShell history is valuable**: Admins type credentials into PowerShell constantly — `net use \\server\share /user:admin Password1`, `$cred = Get-Credential`, `Invoke-Command -Credential (...)`. All of this is logged to the history file.

---

## 5. Running Automated Enumeration Tools

### winPEAS

winPEAS automates everything above and more. Learn to read its output, not just collect it.

```bash
# Download (or via C2 execute-assembly — preferred)
# https://github.com/carlospolop/PEASS-ng/releases

# Run and pipe to file
.\winPEAS.exe > C:\Windows\Temp\peas_out.txt

# Key sections to read first (highest value):
# [+] Interesting registry keys (AlwaysInstallElevated, etc.)
# [+] Service binary permissions
# [+] Unquoted service paths
# [+] Token privileges
# [+] Stored credentials
# [!] = Red/Yellow items = potential vulnerabilities
```

### Seatbelt

More targeted, less noisy than winPEAS. Run specific checks:

```bash
.\Seatbelt.exe TokenPrivileges      # just privilege check
.\Seatbelt.exe Services             # service info
.\Seatbelt.exe WindowsCredentialFiles  # stored creds
.\Seatbelt.exe PowerShellHistory    # PS history for all users
.\Seatbelt.exe ScheduledTasks       # scheduled tasks
.\Seatbelt.exe -group=all > seat_out.txt  # everything
```

---

## 6. Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Windows PrivEsc Arena](https://tryhackme.com/room/windowsprivesc20) | THM (Free) | Multiple privesc scenarios guided |
| [THM: Steel Mountain](https://tryhackme.com/room/steelmountain) | THM (Sub) | Service vulnerability, manual exploit |
| [THM: Alfred](https://tryhackme.com/room/alfred) | THM (Sub) | Token impersonation (Juicy Potato style) |
| [VulnHub: Privesc Workshop](https://www.vulnhub.com/?q=privilege+escalation&sort=date-des) | Free | Various Windows privesc VMs |
| Manual: Windows lab | Your lab | Find all 5 privesc paths in a deliberately vulnerable VM |

---

## Phase 06 Mastery Checklist

- [ ] When you see `SeImpersonatePrivilege: Enabled` in `whoami /priv`, what's your next step?
- [ ] Can you identify an unquoted service path from `Get-WmiObject Win32_Service` output?
- [ ] Can you use `icacls` to find a writable service binary path?
- [ ] Can you explain why `AlwaysInstallElevated = 1` in both hives leads to SYSTEM?
- [ ] Can you find PowerShell history and explain why it often contains credentials?
- [ ] Can you triage winPEAS output and identify the 3 highest-value findings in under 5 minutes?

---

## Next Phase → **Phase 07: Windows Privilege Escalation**
