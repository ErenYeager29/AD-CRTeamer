# Phase 10: Active Directory Fundamentals

> **Why this phase exists**: Attacking AD without understanding it is guesswork. If you don't know what an SPN is, Kerberoasting is just a command. If you don't know what a TGT does, Pass-the-Ticket is magic. This phase builds the mental model that makes AD attacks make sense.

**Study time**: 1 week | **Difficulty**: Beginner–Intermediate

---

## Learning Objectives

- [ ] Explain what Active Directory is and why enterprises use it
- [ ] Explain what a SID is and why it's the real identity in AD
- [ ] Explain what a Service Principal Name (SPN) is and why Kerberoasting targets accounts with them
- [ ] Explain what an ACL is in AD context and give 3 examples of dangerous ACL entries
- [ ] Explain what a Group Policy Object does
- [ ] Draw the Kerberos authentication flow from memory

---

## 1. What Active Directory Is and Why It Exists

**The problem AD solves**: A company has 1,000 employees and 500 computers. Without AD, each computer has its own user database. User changes (new employees, password resets) must be made on every machine individually. Authentication doesn't work across machines — you can't log into computer B with your account from computer A.

**What AD provides**:
- **Centralized identity**: one user database (the domain) for all machines
- **Single sign-on**: authenticate once, access everything you're authorized for
- **Centralized policy**: GPOs push configuration to all machines simultaneously
- **Authorization**: ACLs on objects control who can do what, throughout the whole domain

### Key components

**Domain Controller (DC)**: The server that runs AD. Authenticates users, enforces policy, holds the NTDS.dit database (all user accounts + hashes). Compromising the DC = owning the entire domain.

**Domain**: An administrative boundary. All machines and users in `lab.local` share the same identity database.

**Forest**: A collection of one or more domains with a shared schema. The forest is the security boundary — trusts within a forest have no SID filtering.

**Organizational Units (OUs)**: Containers in AD used to organize objects and apply GPOs selectively.

---

## 2. SIDs — The Real Identity

Every user, group, and computer has a **Security Identifier (SID)** — a unique, immutable identifier.

```
S-1-5-21-1234567890-1234567890-1234567890-1001
```

Breaking it down:
- `S` = SID marker
- `1-5-21` = NT authority, domain SID pattern
- `1234567890-1234567890-1234567890` = domain identifier
- `1001` = Relative Identifier (RID) — unique within the domain

**Well-known RIDs**:
- `500` = Built-in Administrator
- `512` = Domain Admins group
- `519` = Enterprise Admins group

**Why SIDs matter for attacks**: When you forge Kerberos tickets (Golden Ticket), you specify which SID to embed in the ticket's PAC. The DC trusts the PAC — so by putting SID 512 in your ticket, you become Domain Admin. The username in the ticket is almost irrelevant; the SID is what the access check uses.

---

## 3. How Kerberos Works (The Protocol)

Understanding this makes every Kerberos attack obvious.

```
Step 1: AS-REQ
User → DC: "I'm jdoe, I want a TGT"
DC: encrypts a TGT with the krbtgt account's key
DC → User: here's your TGT (encrypted with krbtgt key)

Step 2: TGS-REQ
User → DC: "I want to access CIFS on FS01, here's my TGT"
DC: validates TGT (decrypts with krbtgt key), issues TGS
DC → User: here's a service ticket for CIFS/FS01 (encrypted with FS01's key)

Step 3: AP-REQ
User → FS01: "I want access, here's my ticket"
FS01: decrypts with its own key, extracts user identity from PAC
FS01 → User: access granted (if ACL permits)
```

**The attacks become obvious now**:

- **Kerberoasting**: You have step 1 (a TGT). Request a TGS in step 2 for a service account SPN. The TGS is encrypted with the service account's password hash. Take it offline and crack it.

- **AS-REP Roasting**: Normally, the AS-REQ includes a timestamp encrypted with your password (pre-authentication). Accounts with pre-auth disabled skip this check — the DC sends back the TGT component encrypted with the user's hash, which you crack.

- **Golden Ticket**: You have the krbtgt hash (from DCSync). Forge step 1's output yourself — create a TGT that says you're any user with any group membership. The DC in step 2 validates TGTs by decrypting with krbtgt — your forged ticket decrypts correctly.

- **Pass-the-Ticket**: Steal a user's TGT from LSASS. Use it in step 2 to get service tickets as them.

---

## 4. SPNs — What They Are and Why They Enable Kerberoasting

A **Service Principal Name** is a unique identifier for a service instance. It tells the KDC which account's key to use when encrypting service tickets.

```
MSSQLSvc/db01.lab.local:1433  ← SPN for SQL Server on db01
HTTP/web01.lab.local          ← SPN for IIS on web01
```

SPNs are registered on the account that runs the service. If a service account `svc_sql` runs MSSQL, `MSSQLSvc/db01.lab.local:1433` is registered on `svc_sql`.

**Why this enables Kerberoasting**:
1. Any authenticated domain user can request a TGS for any SPN
2. The TGS is encrypted with `svc_sql`'s password hash
3. You take it offline and crack it
4. No special privileges required — any domain user can do it

**Why service accounts are weak targets**: They often have long-lived, human-set passwords (humans choose memorable passwords). They have `PasswordNeverExpires = true`. They're set once and forgotten.

---

## 5. ACLs in Active Directory

Every AD object (users, groups, computers, OUs) has an **Access Control List** that defines who can do what with it. This is separate from filesystem ACLs.

**Common dangerous ACL entries**:

| Right | On object | What attacker can do |
|-------|-----------|---------------------|
| `GenericAll` | User | Reset password, set SPN for Kerberoasting, write any attribute |
| `GenericAll` | Group | Add yourself as member |
| `GenericAll` | Computer | Set RBCD, add SPNs |
| `WriteDACL` | Domain | Grant yourself DCSync rights |
| `GenericWrite` | User | Set SPN → targeted Kerberoasting |
| `ForceChangePassword` | User | Reset password without knowing current |
| `AllExtendedRights` | User | Reset password, read LAPS passwords |

**How ACL misconfigurations happen**: A sysadmin needs to give the helpdesk team the ability to reset user passwords. They add `ForceChangePassword` to the helpdesk group on all user objects — reasonable. But if the helpdesk group ever gets compromised, the attacker can reset any user's password, including Domain Admins.

**BloodHound maps all of this** — it ingests the AD object ACLs and draws them as graph edges, making attack chains visual.

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Active Directory Basics](https://tryhackme.com/room/winadbasics) | THM (Free) | AD concepts hands-on |
| [THM: Attacking Kerberos](https://tryhackme.com/room/attackingkerberos) | THM (Free) | Kerberos attacks explained + lab |
| [ired.team: Kerberos](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse) | Free | Deep reading |

---

## Phase 10 Mastery Checklist

- [ ] Can you draw the Kerberos AS-REQ / TGS-REQ / AP-REQ flow without notes?
- [ ] Can you explain what a SPN is and why it enables Kerberoasting?
- [ ] Can you explain why a Golden Ticket works even though you forged it?
- [ ] Can you explain what GenericAll on a user object lets you do?
- [ ] Can you explain the difference between a domain and a forest (security boundary)?

---

## Next Phase → **Phase 11: AD Enumeration**
