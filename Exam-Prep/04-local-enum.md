# Phase 04: Local Enumeration & Reconnaissance

> Speed is everything. You have 25 minutes budgeted for host recon. Run tools in parallel.

---

## Automated Enumeration — Run Immediately

```bash
# From C2 beacon (in-memory, no disk write):
sliver (beacon) > execute-assembly /tools/Seatbelt.exe -group=all
sliver (beacon) > execute-assembly /tools/winPEAS.exe log=true

# Or from an interactive shell:
.\winPEAS.exe > C:\Windows\Temp\peas.txt
.\Seatbelt.exe -group=all > C:\Windows\Temp\seat.txt
```

Run both simultaneously. While they run, do manual checks.

---

## Manual Quick Checks (Do While Tools Run)

```powershell
# Who am I? What privileges?
whoami /all

# OS + patch level
systeminfo | findstr /B /C:"OS" /C:"Hotfix"

# Local users + admins
net user
net localgroup administrators

# Running processes (look for AV/EDR)
tasklist /v
Get-Process | Select Name, Id, Path

# Network connections + listening ports
netstat -ano
# Cross-reference PIDs with tasklist to identify services

# Scheduled tasks (common privesc vector)
schtasks /query /fo LIST /v | findstr /i "task\|run\|status\|next"
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | Select TaskName,TaskPath

# Services (look for unquoted paths, weak permissions)
sc query type= all state= all
Get-WmiObject Win32_Service | Select Name,StartName,PathName | Where-Object {$_.StartName -notlike "Local*"}

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion

# Environment variables (may reveal creds/paths)
Get-ChildItem env:

# Check for interesting files
Get-ChildItem C:\Users -Recurse -Include *.txt,*.xml,*.config,*.ini,*.log,*.kdbx -ErrorAction SilentlyContinue
Get-ChildItem "C:\Program Files","C:\Program Files (x86)" -ErrorAction SilentlyContinue

# Writable directories in PATH (DLL hijack targets)
$env:PATH.Split(';') | ForEach-Object { if (Test-Path $_) { Get-Acl $_ | Select Path,AccessToString } }
```

---

## What to Look For

| Finding | Likely Privesc Path |
|---------|-------------------|
| Service running as SYSTEM with weak binary perms | Replace binary → SYSTEM |
| Unquoted service path with spaces | Drop binary in unquoted dir → SYSTEM |
| Scheduled task running as SYSTEM | Replace task binary / modify task |
| UAC enabled but user is local admin | UAC bypass → high integrity |
| AlwaysInstallElevated = 1 in registry | Malicious MSI → SYSTEM |
| Stored credentials in files/registry | Reuse creds for lateral move |
| Writable PATH dir | DLL hijack |
| SeImpersonatePrivilege / SeAssignPrimaryToken | Potato attacks → SYSTEM |

---

## Check SeImpersonatePrivilege (Very Common in Exam)

```powershell
whoami /priv
# Look for:
# SeImpersonatePrivilege    Impersonate a client after authentication  Enabled
# SeAssignPrimaryTokenPrivilege  Replace a process level token         Enabled
```

If either is enabled → **Potato attack** → SYSTEM (covered in Phase 05).

---

## Key Files to Search

```powershell
# Credentials in files
Get-ChildItem C:\ -Recurse -Include *credential*,*password*,*pass*,*secret*,*cred* -ErrorAction SilentlyContinue 2>$null
findstr /si "password" C:\*.xml C:\*.ini C:\*.txt C:\*.config 2>nul

# Unattend files (often contain admin creds)
Get-Content C:\Windows\Panther\Unattend.xml -ErrorAction SilentlyContinue
Get-Content C:\Windows\System32\sysprep\unattend.xml -ErrorAction SilentlyContinue

# SAM + SYSTEM backup (sometimes accessible)
Test-Path C:\Windows\Repair\SAM
Test-Path C:\Windows\System32\config\RegBack\SAM

# PowerShell history (often has credentials)
Get-Content (Get-PSReadlineOption).HistorySavePath
Get-Content C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue

# Registry-stored credentials
reg query HKLM /f "password" /t REG_SZ /s 2>nul
reg query HKCU /f "password" /t REG_SZ /s 2>nul

# VNC / RDP creds in registry
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul
```

---

## Prioritize Your Findings

After running tools, triage results in this order:

1. **SeImpersonatePrivilege** → instant SYSTEM path (Potato)
2. **Writable service binary / unquoted path** → reliable SYSTEM path
3. **AlwaysInstallElevated** → easy SYSTEM via MSI
4. **Stored credentials** → may skip privesc entirely
5. **UAC bypass** → needed if you're local admin but medium integrity
6. **Scheduled task weaknesses** → reliable but slower to exploit

---

## Exam Tip

winPEAS and Seatbelt both produce a lot of output. Don't read everything line by line — grep for the high-value sections:

```bash
# Seatbelt output — search for specific checks
.\Seatbelt.exe TokenPrivileges 2>$null
.\Seatbelt.exe Services 2>$null
.\Seatbelt.exe WindowsCredentialFiles 2>$null
.\Seatbelt.exe DotNet 2>$null

# winPEAS — most important sections are colored RED/YELLOW in terminal
# If redirected to file, grep for known patterns:
grep -i "FOUND\|YES\|Enabled\|vulnerable" peas_output.txt
```

---

## Next Step

Found SeImpersonatePrivilege or other privesc vector → **Phase 05: Windows Privilege Escalation** (`05-windows-privesc.md`)
