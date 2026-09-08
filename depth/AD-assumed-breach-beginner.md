# Active Directory — Assumed Breach
## From Low-Privilege Domain User to Enterprise Admin
### Zero to Solid Foundation — Concepts Before Commands

> **Teaching pattern used throughout:**
> 🔷 **WHAT** — What is this thing, defined simply
> 🔶 **WHY** — Why does it exist, what problem does it solve
> ⚔️ **HOW** — How it connects to your attack path
> 🧠 **LOCK IT IN** — An analogy or visual to make it permanent

---

## Before You Begin — The Most Important Sentence in This Document

> **You are not looking for vulnerabilities. You are mapping trust relationships.**

Vulnerabilities get patched. Trust relationships are architectural — they are baked into how Windows and Active Directory were designed. A domain user can request Kerberos tickets for any service. That is not a bug. A group member inherits every permission the group has. That is not a bug. An account with GenericAll on another account can reset its password. That is by design.

Your job in an assumed breach scenario is to walk a chain of legitimate trust relationships — ones that were misconfigured or over-permissioned — from where you are now to where you want to be.

Every section in this document answers one question:
**"What trust relationship does this give me, and where does it lead?"**

---

## PART 1 — Understanding the Environment Before You Look at Anything

---

## SECTION 1 — What Active Directory Is and Why It Exists

**🔷 WHAT**

Active Directory (AD) is a **centralised identity and policy management system** for Windows networks. It stores information about every user, computer, group, and policy in an organisation — and it enforces who can access what, across every machine in the network.

Before AD existed, each computer in a company kept its own list of user accounts. If you had 500 computers, you had 500 separate user databases. Adding a new employee meant creating an account on every machine they needed. Changing a password meant updating 500 machines. This was unmanageable.

AD solved this with a single, centralised directory. One user database. Every machine in the company trusts it. Authenticate once — access everything you are authorised to access, anywhere in the network.

```
Without AD (old model):
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ PC-01    │  │ PC-02    │  │ SERVER-1 │
  │ user DB  │  │ user DB  │  │ user DB  │
  │ (local)  │  │ (local)  │  │ (local)  │
  └──────────┘  └──────────┘  └──────────┘
  Each machine decides who can log in. No sharing.

With AD:
  ┌──────────────────────────────────────────────────┐
  │           DOMAIN CONTROLLER (DC)                 │
  │                                                  │
  │   One user database — NTDS.dit                  │
  │   All accounts, passwords, groups, policies      │
  │   for every user in the domain                  │
  └──────────────────────────────────────────────────┘
         ↕              ↕              ↕
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ PC-01    │  │ PC-02    │  │ SERVER-1 │
   │"trust DC │  │"trust DC │  │"trust DC │
   │ for auth"│  │ for auth"│  │ for auth"│
   └──────────┘  └──────────┘  └──────────┘
```

**🔶 WHY**

The Domain Controller (DC) is the most important machine in the entire network. It holds:

- Every user account and its password hash
- Every group and its membership
- Every policy applied to every machine
- The encryption keys for the Kerberos authentication system

Compromising the DC means compromising every machine in the domain — instantly, completely, and permanently (until the DC is rebuilt).

**⚔️ HOW**

Your assumed breach gives you a low-privilege domain user account. That account is stored on the DC. It has the minimum rights AD gives any user. But here is the critical fact:

**Any authenticated domain user can query the DC for information about the entire domain** — all users, all groups, all computers, all service accounts, and critically: all permissions granted between objects.

You start with credentials. That credential is your key to read the entire map of the organisation's infrastructure.

**🧠 LOCK IT IN**

AD is a city's registry office. It has records on every resident (user), every building (computer), every organisation (group), and every permit (permission). The registry is open to anyone who works in the city (domain users). You cannot change records without the right authority — but you can read almost everything. Your first job is to read the map before you move.

---

## SECTION 2 — The Three Boundaries: Domain, Tree, Forest

**🔷 WHAT**

AD is organised in a three-level hierarchy. Understanding these levels is not optional — they determine exactly how far your attack can reach and what techniques cross each boundary.

```
FOREST  (the security boundary)
│
├── TREE: corp.company.com
│   ├── DOMAIN: corp.company.com        ← root domain
│   ├── DOMAIN: us.corp.company.com     ← child domain
│   └── DOMAIN: eu.corp.company.com     ← child domain
│
└── TREE: subsidiary.com
    └── DOMAIN: subsidiary.com          ← separate tree, same forest
```

**Domain** — an administrative boundary. A collection of objects (users, computers, groups) that share the same AD database and policies. Each domain has its own Domain Controller.

**Tree** — a collection of domains that share a contiguous DNS namespace (e.g., `corp.com`, `us.corp.com`, `eu.corp.com`).

**Forest** — the highest level. A collection of trees that share a common schema (the definition of what AD objects look like) and a configuration partition. The forest root domain is the most powerful domain in the entire structure.

**🔶 WHY**

The security boundary distinction matters enormously for red teaming:

- **Within a forest**: domains automatically trust each other (parent-child trusts are created automatically). SID filtering is OFF between domains within the same forest. A compromised child domain can be leveraged to compromise the forest root.
- **Across forests**: trusts must be explicitly created. SID filtering is ON by default. Crossing a forest trust is significantly harder.

**⚔️ HOW**

As an assumed breach with low-priv user credentials:
- You can enumerate the **entire forest** structure from any domain-joined machine
- If your domain is a child domain and you reach Domain Admin in your domain → you have a path to Enterprise Admin in the forest root (the ultimate goal)
- Enterprise Admin (EA) is a member of the forest root domain only — it grants full control over every domain in the forest

The escalation goal for the exam:
```
Low-priv user in child domain
        ↓
Local Admin on a workstation
        ↓
SYSTEM on that workstation
        ↓
Domain Admin in current domain
        ↓
Enterprise Admin in forest root
        ↓ (if multiple forests with trust)
Domain Admin in trusted forest
```

**🧠 LOCK IT IN**

A forest is a country. Domains are states within that country. Domain Admin is a state governor — total control within their state, but authority stops at the state border. Enterprise Admin is the federal government — authority in every state simultaneously. The child→parent escalation technique exploits the fact that states in the same country automatically trust each other's residents.

---

## SECTION 3 — AD Objects: The Building Blocks

**🔷 WHAT**

Everything in AD is an **object** — a record with a type and a set of attributes. Understanding each object type tells you immediately what it might give you.

### User Objects

The most common object. Represents a person (or a service). Every user has:
- `sAMAccountName` — the logon name (`jdoe`)
- `userPrincipalName` — the email-format logon (`jdoe@corp.com`)
- `memberOf` — which groups this user belongs to
- `servicePrincipalName` (SPN) — if set, this account is Kerberoastable
- `userAccountControl` — flags that control logon behaviour (disabled, no pre-auth required, etc.)
- `adminCount` — if 1, this account was or is a member of a protected group (was once highly privileged)
- `description` — often contains passwords placed there by lazy admins

### Computer Objects

Every domain-joined machine has a computer object. Computers are accounts too — they have a password (a 120-character random string, auto-rotated every 30 days) and a SID. Computer accounts authenticate to the domain, not just humans.

Critically: a computer's password is known to the computer itself and stored on the DC. If you have SYSTEM on a machine, you can extract that machine account's credentials — and use them for further attacks (Kerberos attacks, LDAP queries authenticated as the machine account).

### Group Objects

Collections of users and/or computers. Members inherit all permissions the group has. Nested groups mean permissions chain: being a member of GroupA, which is a member of GroupB, gives you GroupB's permissions too.

High-value groups to know:

| Group | What membership gives you |
|---|---|
| `Domain Admins` | Full control over the entire domain |
| `Enterprise Admins` | Full control over the entire forest |
| `Schema Admins` | Can modify AD's schema — permanent architectural changes |
| `Group Policy Creator Owners` | Can create GPOs that apply to any machine |
| `Account Operators` | Can create and modify user accounts and groups (except protected ones) |
| `Backup Operators` | Can read any file on any domain computer, bypass file ACLs |
| `Server Operators` | Can log on to DCs, create/delete shares, stop/start services |
| `DNSAdmins` | Can load an arbitrary DLL into the DNS server (runs as SYSTEM on DC) |

### Organizational Units (OUs)

Containers used to organise objects and apply Group Policy selectively. OUs do not grant permissions by themselves — but GPOs applied to an OU affect every object inside it.

### Group Policy Objects (GPOs)

Policies that are automatically applied to machines and users in linked OUs. They control everything from password complexity to software installation to startup scripts.

**⚔️ HOW — what each object type means for your attack**

```
User with SPN set      → Kerberoastable → crack their password offline
User with no pre-auth  → AS-REP Roastable → get hash without credentials
User with adminCount=1 → was/is protected → likely has privileged path
User with "pass" in description → admin was lazy → test it as a password

Computer with unconstrained delegation → coerce DC auth → steal DC's TGT
Computer with constrained delegation   → S4U abuse → impersonate DA

Group with GenericAll on DA group → add yourself to Domain Admins
Group linked to a GPO             → if you can edit the GPO, code runs on every member
```

**🧠 LOCK IT IN**

AD objects are like employee badges. The badge says who you are (user account), which floors you can access (group memberships), which doors open automatically (permissions from groups), and what rules apply to you (GPO). Your job is to find badges with the wrong access level printed on them — service accounts that shouldn't have admin rights, groups that give too much permission to too many people.

---

## SECTION 4 — SIDs: The Real Identity in Active Directory

**🔷 WHAT**

Every object in AD — every user, every group, every computer — has a **Security Identifier (SID)**. The SID is the object's permanent, unique identity. Names can change. A user can be renamed. A group can be reorganised. The SID never changes.

```
S-1-5-21-1234567890-2345678901-3456789012-1001
│ │ │ │─────────────────────────────────────┤ └─ RID
│ │ │ └─────────────────────────────────────── Domain identifier
│ │ └─────────────────────────────────────────── NT authority
│ └───────────────────────────────────────────── Security authority
└─────────────────────────────────────────────── SID marker
```

The last number — the **Relative Identifier (RID)** — identifies the specific object within the domain. Important RIDs:

| RID | Object |
|---|---|
| 500 | Built-in Administrator (local and domain) |
| 501 | Built-in Guest |
| 512 | Domain Admins group |
| 513 | Domain Users group (every user is a member) |
| 514 | Domain Guests group |
| 519 | Enterprise Admins group |
| 520 | Group Policy Creator Owners |
| 544 | Built-in Administrators group |

**🔶 WHY**

When Windows makes an access decision — can this user open this file? can this account modify this AD object? — it compares SIDs, not names. Your access token (covered in Phase 00) contains your SID and the SIDs of every group you belong to. Windows checks the object's ACL against those SIDs.

**⚔️ HOW**

Two critical attack implications:

**Golden Ticket**: When you forge a Kerberos ticket, you embed SIDs into the ticket's PAC (Privilege Attribute Certificate). Put SID ending in `-512` (Domain Admins) in a forged ticket → Windows grants you Domain Admin rights. The Domain Controller validates the ticket by decrypting it — it trusts the SID claims inside.

**SID History injection**: AD objects can have a `SIDHistory` attribute — a list of SIDs from old domains (used when migrating users between domains). When Windows evaluates your access, it checks both your current SID AND every SID in your SIDHistory. If you can write a Domain Admin SID into your SIDHistory → you effectively become a DA without being in the DA group. This is the mechanism behind the child→parent domain escalation.

**🧠 LOCK IT IN**

Your SID is your social security number — it never changes even if everything else about you does. When you get access somewhere, the door doesn't check your name badge — it checks your social security number against a list. Golden Tickets are forged social security numbers with whatever benefits you want printed on them. SID History injection is adding extra social security numbers to your file that give you extra benefits.

---

## SECTION 5 — How Kerberos Authentication Works (The Full Picture)

**🔷 WHAT**

Kerberos is the authentication protocol Active Directory uses for everything. Understanding it is not optional — every major AD attack (Kerberoasting, AS-REP Roasting, Golden Ticket, Pass-the-Ticket, delegation abuse) is an exploitation of a specific step in this protocol.

Kerberos has three participants:

- **Client** — the user's machine wanting access to something
- **KDC (Key Distribution Center)** — the Domain Controller. Has two components: AS (Authentication Service) and TGS (Ticket Granting Service)
- **Service** — the server the user wants to access (file server, web server, etc.)

**The full flow, explained step by step:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  STEP 1: AS-REQ (Authentication Service Request)                   │
│  ─────────────────────────────────────────────────────────         │
│  Client → KDC (DC):                                                 │
│  "I am jdoe. I want to authenticate."                               │
│  Client sends: timestamp encrypted with jdoe's password hash       │
│  Purpose: proves the client knows the password without sending it   │
│                                                                     │
│  STEP 2: AS-REP (Authentication Service Reply)                     │
│  ─────────────────────────────────────────────────────────         │
│  KDC → Client:                                                       │
│  "Verified. Here is your TGT."                                       │
│  TGT (Ticket Granting Ticket) = a signed ticket encrypted with     │
│  the KRBTGT account's hash. Client cannot decrypt it.               │
│  The TGT says: "bearer is jdoe, valid until [timestamp]"            │
│  The client stores the TGT in memory (LSASS).                       │
│                                                                     │
│  STEP 3: TGS-REQ (Ticket Granting Service Request)                 │
│  ─────────────────────────────────────────────────────────         │
│  Client → KDC (DC):                                                  │
│  "I want to access \\FILESERVER\share. Here is my TGT."            │
│  The client presents the TGT to prove its identity.                 │
│                                                                     │
│  STEP 4: TGS-REP (Ticket Granting Service Reply)                   │
│  ─────────────────────────────────────────────────────────         │
│  KDC → Client:                                                       │
│  "Here is a Service Ticket for CIFS/FILESERVER."                    │
│  Service Ticket is encrypted with FILESERVER's machine account hash │
│  (the key FILESERVER and the KDC share — no one else has it)        │
│                                                                     │
│  STEP 5: AP-REQ (Application Request)                               │
│  ─────────────────────────────────────────────────────────         │
│  Client → FILESERVER:                                                │
│  "I want access. Here is my Service Ticket."                        │
│  FILESERVER decrypts the ticket with its own password hash.         │
│  Extracts: user identity, group memberships (from PAC)              │
│  Checks: does this user have permission to access the share?        │
│  Grants or denies access.                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**🔶 WHY**

The KDC (Domain Controller) is the trust anchor of the entire system. Every machine in the domain trusts the tickets the KDC issues. The KDC trusts the tickets because they are encrypted with keys only the KDC knows (the krbtgt account's hash for TGTs, service account hashes for service tickets).

If you compromise the krbtgt hash — you can forge TGTs that the KDC will accept as legitimate. That is a Golden Ticket.
If you compromise a service account hash — you can forge service tickets for that service. That is a Silver Ticket.
If you can get the KDC to issue a service ticket for you impersonating a different user — that is delegation abuse.

**⚔️ HOW**

Map each attack to the protocol step it exploits:

```
Kerberoasting:
  You have a TGT (Step 2 complete). Request a TGS-REP (Step 4) for a service.
  The Service Ticket is encrypted with the service account's password hash.
  Take the ticket offline → crack the hash → recover the password.
  No exploitation — just a protocol feature misused.

AS-REP Roasting:
  Some accounts do not require pre-auth (the timestamp in Step 1).
  Request AS-REP for such an account → KDC sends back Step 2 without verifying you.
  Part of the AS-REP is encrypted with the user's password hash.
  Crack it offline → no credentials required.

Golden Ticket:
  You have the krbtgt hash (from DCSync).
  Forge a TGT (Step 2's output) yourself.
  Embed any SIDs you want in the PAC.
  Present your forged TGT as Step 3's input → KDC validates it (decrypts with krbtgt key → matches).
  KDC issues real service tickets for your forged identity.

Pass-the-Ticket:
  Steal someone's TGT from LSASS memory.
  Use their TGT to request service tickets (Step 3) as them.
  No password needed — you have their ticket.

Delegation abuse:
  Constrained/unconstrained delegation allows services to obtain tickets on behalf of users.
  Abuse the S4U (Service-for-User) extensions to get tickets impersonating Domain Admins.
```

**🧠 LOCK IT IN**

Kerberos is a movie ticket system. The AS-REP (TGT) is your ticket stub — it proves you paid. The TGS-REP (Service Ticket) is your actual seat assignment for a specific movie (service). The movie theatre (service) only checks your seat assignment, not your ID.

A Golden Ticket is a fake ticket stub that the machine accepts as valid because you forged it with the same printing press (krbtgt key). The machine cannot tell the difference. It prints you a seat assignment for any movie, any seat you want.

---

## SECTION 6 — LDAP: The Query Language of Active Directory

**🔷 WHAT**

LDAP (Lightweight Directory Access Protocol) is the protocol used to query and modify Active Directory. Every tool that "enumerates AD" — PowerView, BloodHound, ldapdomaindump, nxc — is sending LDAP queries to the Domain Controller.

LDAP organises AD as a tree of entries, each with a **Distinguished Name (DN)**:

```
DC=corp,DC=company,DC=com           ← the root (the domain)
│
├── CN=Users,DC=corp,...             ← default Users container
│   ├── CN=John Doe,CN=Users,...     ← a user object
│   └── CN=Domain Admins,...         ← the Domain Admins group object
│
├── OU=Workstations,DC=corp,...      ← an Organizational Unit
│   ├── CN=PC-001,OU=Workstations,... ← a computer object
│   └── CN=PC-002,...
│
└── CN=Domain Controllers,...        ← DC container
    └── CN=DC01,...                  ← the DC itself
```

**🔶 WHY**

LDAP exists so applications can query directory information without knowing the internal structure of AD. It is a standard protocol — the same one used by Linux LDAP, OpenLDAP, and most enterprise directory systems.

The critical operational fact: **any authenticated domain user can query LDAP** for almost all objects in AD. There is no "privilege required" — reading the directory is a default right of domain membership.

**⚔️ HOW**

From a low-privilege domain user position, LDAP gives you:

```
All user accounts in the domain
All group memberships (recursive)
All computer accounts and their attributes
All service accounts and their SPNs (Kerberoasting targets)
All accounts with pre-auth disabled (AS-REP Roasting targets)
All accounts with delegation configured
All GPOs and what they apply to
All OUs and their structure
All trusts between domains
All ACLs on every object (who has what permissions on what)
```

This is essentially a complete map of the organisation's identity infrastructure — available to any domain user, by design.

**🧠 LOCK IT IN**

LDAP is a phone book — but for every employee, every server, every office, every security policy in the company. And it is open to anyone who works there. You are not breaking in to read it. You are a legitimate employee (domain user) consulting the phone book. The difference is you are reading it to plan an attack, not to make a call.

---

## SECTION 7 — ACLs on AD Objects: The Hidden Attack Surface

**🔷 WHAT**

Every AD object has an **Access Control List (ACL)** — a list of who can do what with that object. This is separate from file system ACLs. These are permissions on directory objects: user accounts, groups, GPOs, OUs, the domain object itself.

Each entry in an ACL is an ACE (Access Control Entry):

```
ACE structure:
  Who:    S-1-5-21-...-1105  (jdoe's SID)
  What:   GenericAll
  On:     CN=svc_sql,CN=Users,DC=corp,DC=com  (the svc_sql user object)

Translation: jdoe has full control over the svc_sql account
```

**🔶 WHY**

ACLs exist so administrators can delegate specific tasks without giving full admin rights. Example: "Give the helpdesk team the ability to reset user passwords" — the admin adds a `ResetPassword` ACE for the helpdesk group on all user objects in the Users OU.

The problem: these ACLs accumulate over years. Admins add permissions for projects and forget to remove them. Service accounts get over-privileged. Old ACEs from decommissioned projects remain. The result is a domain where low-privilege users or accounts have unexpected control over high-privilege objects.

**⚔️ HOW**

This is the most important attack surface in modern AD engagements. ACL misconfigurations are the primary path from "domain user" to "Domain Admin" in environments that are otherwise well-hardened against traditional attacks.

The rights that matter and what each one lets you do:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DANGEROUS ACL RIGHTS                             │
├─────────────────────┬───────────────────────────────────────────────┤
│ RIGHT               │ WHAT AN ATTACKER CAN DO                       │
├─────────────────────┼───────────────────────────────────────────────┤
│ GenericAll          │ Full control. Do anything to the object.      │
│                     │ On user → reset password, set SPN, anything   │
│                     │ On group → add yourself as member             │
│                     │ On computer → configure delegation, RBCD      │
├─────────────────────┼───────────────────────────────────────────────┤
│ GenericWrite        │ Write any property on the object              │
│                     │ On user → set SPN → Kerberoast them           │
│                     │ On computer → write RBCD attribute            │
├─────────────────────┼───────────────────────────────────────────────┤
│ WriteDACL           │ Modify the object's own ACL                   │
│                     │ Grant yourself GenericAll → do anything       │
│                     │ On domain object → grant DCSync rights        │
├─────────────────────┼───────────────────────────────────────────────┤
│ WriteOwner          │ Become the object's owner                     │
│                     │ Owner can modify the object's ACL             │
│                     │ → WriteDACL → GenericAll                      │
├─────────────────────┼───────────────────────────────────────────────┤
│ ForceChangePassword │ Reset user's password without knowing old one │
│                     │ Used to take over accounts in your ACL chain  │
├─────────────────────┼───────────────────────────────────────────────┤
│ AllExtendedRights   │ All extended rights on the object             │
│                     │ Includes ForceChangePassword                   │
│                     │ On domain object → includes DCSync rights     │
├─────────────────────┼───────────────────────────────────────────────┤
│ AddMember           │ Add members to a group                        │
│                     │ On Domain Admins → add yourself → DA           │
├─────────────────────┼───────────────────────────────────────────────┤
│ DCSync rights       │ Two specific extended rights on domain object  │
│ (DS-Replication-    │ Allow you to simulate DC replication          │
│  Get-Changes-All)   │ → dump all password hashes from the domain   │
└─────────────────────┴───────────────────────────────────────────────┘
```

**🧠 LOCK IT IN**

AD ACLs are like keys to rooms in a building. The building's security team hands out keys for legitimate reasons — helpdesk needs a key to reset the server room entry code (ResetPassword), the backup team needs a passkey to every room (Backup Operators). Over 10 years, keys pile up. Nobody audits who still has what. Your job as an attacker is to find the person who has a master key they forgot they had — and use it.

---

## SECTION 8 — Group Policy Objects: Code That Runs Everywhere

**🔷 WHAT**

A GPO (Group Policy Object) is a collection of settings that Windows automatically applies to machines and users in an OU. GPOs can configure:

- Password policies, lockout policies
- Software installation (push installers to machines)
- Startup/shutdown scripts (run as SYSTEM before logon)
- Logon/logoff scripts (run as the user at logon)
- Registry settings
- File system permissions
- Restricted groups (force specific accounts into local groups)
- Security settings

GPOs are linked to OUs. Every computer or user in that OU gets the GPO applied automatically, on a schedule (every 90 minutes by default), without any user interaction.

**🔶 WHY**

GPOs exist because configuring 500 machines individually is impractical. Push one GPO → all 500 machines apply the setting automatically. This is the mechanism that makes domain-wide policy enforcement possible.

**⚔️ HOW**

If you have write access to a GPO that is linked to an OU containing machines:

```
Your rights: GenericAll / WriteProperty on GPO "Workstation Policy"
GPO "Workstation Policy" linked to: OU=Workstations (contains 200 machines)

Attack:
1. Modify the GPO to add a Computer Startup Script
   Script content: add yourself to local Administrators group
   Script runs as: SYSTEM

2. Wait up to 90 minutes (or force: gpupdate /force on one machine)

3. Result: you are local admin on all 200 machines in the OU
           → dump LSASS on any of them
           → find a DA who logged in recently
           → use their hash/ticket
           → Domain Admin
```

One misconfigured GPO can give you code execution on hundreds of machines simultaneously.

**🧠 LOCK IT IN**

GPOs are a public announcement system. Management (admins) announce new policies over the PA system, and every department (OU) follows automatically. If you can get access to the PA system microphone (GPO write rights), every department follows your instructions — no individual persuasion needed.

---

## PART 2 — Your Starting Position and What You Can See

---

## SECTION 9 — What a Low-Privilege Domain User Can Do

**🔷 WHAT**

You are given domain credentials: `CORP\jdoe` / `Password1`. This account has:

- No local admin rights on any machine (initially)
- No AD group memberships beyond `Domain Users`
- No special permissions on any AD objects

This sounds like nothing. It is actually an enormous amount.

**🔶 WHY**

Microsoft designed AD so that any domain user can query the directory. The reasoning: you need to be able to look up a colleague's email address, find a shared printer, resolve a hostname. All of this requires LDAP access. Restricting LDAP to admins would break the entire system.

The unintended consequence: any domain user can also enumerate every service account with a Kerberoastable SPN, every account without pre-authentication, every ACL on every object, and every delegation configuration in the domain.

**⚔️ HOW**

From a domain user position, before touching any machine, you can:

```
1. Read all user accounts:
   → find accounts with SPNs (Kerberoasting)
   → find accounts without pre-auth (AS-REP Roasting)
   → find accounts with weak/guessable attributes
   → find accounts with interesting descriptions (passwords left there)
   → find accounts with adminCount=1 (was once privileged)

2. Read all groups and memberships:
   → find who is in Domain Admins
   → find who is in high-value groups
   → find nested group memberships that grant unexpected access

3. Read all computer accounts:
   → find computers with unconstrained delegation (non-DCs!)
   → find computers with constrained delegation
   → find computers that have specific service accounts running on them

4. Read all ACLs:
   → find misconfigurations that let domain users control privileged objects
   → find your own account in unexpected ACE entries
   → find groups you belong to that have unexpected rights

5. Request Kerberos tickets:
   → AS-REP Roast accounts with pre-auth disabled (no credentials beyond your domain user)
   → Kerberoast all SPN-bearing accounts (service ticket requests are normal and logged lightly)
```

**🧠 LOCK IT IN**

Being a domain user is like being a new employee on their first day with a valid ID badge. You cannot access the server room. You cannot approve payroll. But you CAN: read the company directory, see the org chart, look at every shared drive you were given access to, and notice that the unlocked door to the server room has a sticky note on it with the code.

---

## SECTION 10 — OPSEC: The Rules Before You Touch Anything

**🔷 WHAT**

OPSEC (Operational Security) is the discipline of not getting caught. Every action you take generates log entries somewhere. Your goal is to generate the minimum footprint necessary to accomplish your objective.

This section covers what to think about **before running a single tool**.

**🔶 WHY**

Blue teams detect attackers through anomaly — something happens that does not match the baseline. If you spray passwords against 500 accounts in 30 seconds, that anomaly is obvious. If you Kerberoast 50 accounts in one minute, that is anomalous. If you create 5 new scheduled tasks across 10 machines in 2 minutes, that is obvious.

Defenders are not watching for specific tool names. They are watching for patterns that deviate from normal behaviour. Understanding what "normal" looks like lets you blend into it.

**⚔️ HOW**

### What generates logs and what does not

```
┌─────────────────────────────────────────────────────────────────────┐
│  ACTION                              │ EVENT LOG ENTRY               │
├──────────────────────────────────────┼──────────────────────────────┤
│  LDAP query (reading AD objects)     │ Event 4662 — only if object  │
│                                      │ auditing is enabled (rare    │
│                                      │ default). Usually: nothing.  │
├──────────────────────────────────────┼──────────────────────────────┤
│  Kerberoasting (TGS-REQ for SPN)     │ Event 4769 — one entry per   │
│                                      │ ticket requested. RC4 type   │
│                                      │ 0x17 stands out on AES domain│
├──────────────────────────────────────┼──────────────────────────────┤
│  AS-REP Roasting                     │ Event 4768 — one per request │
│                                      │ Pre-auth type = 0 flagged    │
├──────────────────────────────────────┼──────────────────────────────┤
│  Password spray                      │ Event 4625 — one per FAILED  │
│                                      │ logon. Pattern: many users,  │
│                                      │ same source, same password   │
│                                      │ → immediate SIEM alert       │
├──────────────────────────────────────┼──────────────────────────────┤
│  SMB connection to a host            │ Event 5156 (network connect) │
│                                      │ Sysmon 3 (network connection)│
├──────────────────────────────────────┼──────────────────────────────┤
│  Logon to a remote host (WinRM/SMB)  │ Event 4624 LogonType 3       │
│                                      │ On target host's Security log│
├──────────────────────────────────────┼──────────────────────────────┤
│  LSASS memory read                   │ Sysmon Event 10 (ProcessAcce)│
│                                      │ Watching for VM_READ on LSASS│
│                                      │ Most EDRs alert immediately  │
├──────────────────────────────────────┼──────────────────────────────┤
│  DCSync (DRSUAPI replication call)   │ Event 4662 with replication  │
│                                      │ GUIDs — Defender for Identity│
│                                      │ alerts directly on this      │
├──────────────────────────────────────┼──────────────────────────────┤
│  New service created                 │ Event 7045 on target         │
│                                      │ PsExec creates a service     │
├──────────────────────────────────────┼──────────────────────────────┤
│  Scheduled task created              │ Event 4698                   │
└──────────────────────────────────────┴──────────────────────────────┘
```

### OPSEC tiers — apply this thinking to every action

Before doing anything, ask:

**"What event log entry does this create, and does that entry look anomalous?"**

```
🟢 Low noise  — LDAP queries, reading AD objects, requesting tickets for
                services you legitimately need. Normal user behaviour.

🟡 Medium     — SharpHound collection (many LDAP queries in short time),
                Kerberoasting (unusual number of TGS requests),
                WinRM connections (legitimate but watched).

🔴 High       — LSASS dump (immediate EDR alert), DCSync (Defender for
                Identity direct alert), PsExec (service creation events),
                password spraying (mass failed logon events).

💀 Avoid      — Mass account creation, GPO modification without careful
                timing, domain-wide actions that create hundreds of events
                simultaneously.
```

### Three OPSEC rules before touching tools

**Rule 1: Understand your target's baseline before deviating from it.**

What is normal in this environment? How many Kerberos TGS requests does a normal user generate per day? (Usually 10–50.) Requesting 200 TGS tickets in 5 minutes deviates from baseline. Request them slowly, spread over time.

**Rule 2: Prefer read operations over write operations.**

Reading AD (LDAP queries) leaves minimal traces. Writing to AD (modifying ACLs, creating accounts, changing passwords) is highly auditable. Exhaust read-only paths before touching write operations.

**Rule 3: Match your tooling to the environment.**

Running Mimikatz from disk as `mimikatz.exe` is immediately flagged by every EDR. Running SharpHound as `SharpHound.exe` from `C:\Windows\Temp\` is detected. Use in-memory execution (execute-assembly via C2) for all tools. The tool runs with no file on disk and no process name other than your beacon.

---

## PART 3 — The Escalation Ladder: Hop by Hop

---

## SECTION 11 — The Mental Map: How Low-Priv Becomes Enterprise Admin

**🔷 WHAT**

The escalation path is not one action. It is a chain of steps, each converting one type of access into a more powerful type of access. Here is the full ladder:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  STAGE 0: Low-privileged domain user                                │
│  CORP\jdoe — no local admin, no special AD rights                  │
│                     ↓                                               │
│  [Enumeration: find the weak point]                                 │
│                     ↓                                               │
│  STAGE 1: Foothold on a machine                                     │
│  Local user or service on a workstation, with a shell               │
│                     ↓                                               │
│  [Privilege escalation: become SYSTEM]                              │
│                     ↓                                               │
│  STAGE 2: SYSTEM on a workstation                                   │
│  Full control of one machine, access to its secrets                 │
│                     ↓                                               │
│  [Credential harvesting: what credentials live here?]               │
│                     ↓                                               │
│  STAGE 3: Privileged domain credentials                             │
│  A domain account with elevated rights — service account, DA        │
│  session, or local admin account reused elsewhere                   │
│                     ↓                                               │
│  [Lateral movement: reach a more valuable machine]                  │
│                     ↓                                               │
│  STAGE 4: SYSTEM on a high-value machine                            │
│  DC, jump server, server where DAs regularly log in                 │
│                     ↓                                               │
│  [Domain compromise: extract the crown jewels]                      │
│                     ↓                                               │
│  STAGE 5: Domain Admin                                              │
│  DCSync → all domain hashes → krbtgt → Golden Ticket               │
│                     ↓                                               │
│  [Forest escalation: parent domain via SID History]                 │
│                     ↓                                               │
│  STAGE 6: Enterprise Admin                                          │
│  Full control of the entire forest — every domain, every machine    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**🔶 WHY**

The path is sequential because each stage unlocks the capability for the next. You cannot DCSync without Domain Admin rights. You cannot get Domain Admin rights from LDAP alone — you need credential material. You cannot get credential material without a machine to dump it from. You cannot get a machine without a foothold.

Skipping stages does not work. The path is the path.

**⚔️ HOW — what you actually look for at each stage**

### Stage 0 → Stage 1: Finding your first foothold

You have domain credentials. You need a machine you can execute code on. Ask these questions:

```
Is WinRM (port 5985) open on any machine AND your credentials work?
→ YES: evil-winrm → interactive shell immediately. Stage 1 achieved.

Is SMB (port 445) accessible AND do you have write access to any share?
→ Can you write a file that will be executed? (Startup folder, writeable service path)

Does your domain user account have local admin on any machine?
→ netexec smb subnet/24 -u jdoe -p Password1 → look for "(Pwn3d!)"

Does any machine have a publicly-facing web interface or service?
→ Default credentials? Auth bypass? Known CVE?

Is there a MSSQL server (port 1433) where your domain creds have rights?
→ mssqlclient.py → check for xp_cmdshell → OS command execution
```

### Stage 1 → Stage 2: Becoming SYSTEM

You have a shell on a machine as a low-priv user. Before anything else:

```
Run: whoami /priv
     ↓
SeImpersonatePrivilege Enabled?
  → YES: Potato attack (GodPotato) → SYSTEM immediately. This is the most
         common scenario in exam environments. Service accounts and IIS
         accounts almost always have this.
  → NO: Continue checking...

Run: winPEAS or Seatbelt (via execute-assembly)
     ↓
Look for:
  - Unquoted service paths with spaces
  - Service binaries with weak permissions (you can write to them)
  - AlwaysInstallElevated = 1 in HKLM and HKCU
  - Scheduled tasks running as SYSTEM pointing to writable scripts
  - Stored credentials in files, registry, PowerShell history
  - User is already local admin but UAC is blocking → UAC bypass
```

### Stage 2 → Stage 3: Harvesting credentials

You are SYSTEM. This machine has secrets. Find them:

```
LSASS memory:
  → Who is logged in interactively right now?
  → Their NTLM hash and Kerberos TGT are in LSASS
  → Dump LSASS → parse → extract all hashes

Local SAM database:
  → Local Administrator account hash
  → This hash may be reused on many machines (common misconfiguration)
  → PtH with this hash to every other machine → find more (Pwn3d!)

LSA Secrets (SECURITY hive):
  → Service account credentials stored for services that run under domain accounts
  → These accounts often have elevated domain rights
  → secretsdump extracts these

DPAPI secrets:
  → Browser saved passwords
  → Windows Credential Manager
  → Potentially: Azure AD Connect MSOL account password (if on AAD Connect server)
     → MSOL account has DCSync rights → immediate Domain Admin

File system:
  → PowerShell history file: commands typed by admins, often with credentials
  → Config files: web.config, app.config, *.xml with passwords
  → Scripts in SYSVOL: Group Policy Preferences with cpassword (MS14-025)
  → Network drives mapped — what is accessible from here?
```

### Stage 3 → Stage 4: Moving to a better position

You have credentials. Where do you move?

```
What does BloodHound show? (You should have collected this already)
  → "Find where Domain Admins are logged in"
  → Shortest path from your owned accounts to Domain Admins

With domain credentials:
  → nxc smb subnet/24 -u svc_sql -H <hash> → where does this give you (Pwn3d!)?
  → Check if service accounts are local admins on relevant servers

Goal machines ranked by value:
  1. Domain Controllers → DCSync if you can get local admin or domain rights
  2. Jump servers / bastion hosts → DAs log in here daily
  3. Exchange / SharePoint → DAs run these → credentials in memory
  4. SCCM / deployment servers → can push code to every managed machine
  5. Any server where DAs have active sessions
```

### Stage 4 → Stage 5: Domain Admin

You are on a machine where a DA has a session, or you have rights to DCSync. The path forks:

**Path A: DA has an active session on a machine you own**
```
Dump LSASS on that machine
→ Extract DA's NTLM hash and/or Kerberos TGT
→ PtH or PtT as DA
→ DCSync as DA → get krbtgt hash
→ Golden Ticket → permanent DA access
```

**Path B: ACL chain to DA (BloodHound found a path)**
```
Example path:
  jdoe → [GenericAll] → svc_sql → [MemberOf] → Server Admins → [GenericAll] → Domain Admins
                                                                                     ↑
  Step 1: jdoe resets svc_sql's password (GenericAll allows this)
  Step 2: Authenticate as svc_sql
  Step 3: svc_sql is in Server Admins
  Step 4: Server Admins has GenericAll on Domain Admins group
  Step 5: Add jdoe to Domain Admins
  Step 6: jdoe is now Domain Admin
```

**Path C: Kerberoasting to DA**
```
svc_sql has an SPN and a weak password
→ Kerberoast → crack → svc_sql:SQLAdmin2023!
→ svc_sql has local admin on the DB server
→ DB server has DA sessions
→ Dump LSASS → DA hash → DCSync → krbtgt
```

**Path D: Delegation abuse**
```
Unconstrained delegation host found (non-DC)
→ Coerce DC to authenticate to that host
→ Capture DC's TGT
→ Inject TGT → DCSync as DC machine account
→ krbtgt extracted → Golden Ticket
```

### Stage 5 → Stage 6: Enterprise Admin

You are DA in a child domain. The parent domain (forest root) has different DA and EA accounts.

```
The SID History escalation (covered in Phase 09):
  DCSync child domain → get child domain's krbtgt hash
  → Get child domain SID and forest root domain SID
  → Forge Golden Ticket with /extra-sid = [FOREST_ROOT_SID]-519 (Enterprise Admins)
  → Forest root's DC validates the ticket (trusts child domain, no SID filtering intra-forest)
  → You are effectively Enterprise Admin in the forest root
  → DCSync forest root → all forest hashes → complete
```

---

## PART 4 — What to Look For: The Priority Checklist

---

## SECTION 12 — Enumeration Priority Order

This is the sequence of questions to answer, from highest to lowest value per time spent. Do not skip steps because later steps assume earlier ones are complete.

### Priority 1: Passive domain reconnaissance (no footprint)

These actions generate almost no logs. Do them first, completely, before anything noisier.

```
Questions to answer:
  What is the domain name and forest structure?
  Who are the Domain Admins and Enterprise Admins?
  What accounts have SPNs? (Kerberoasting targets)
  What accounts lack pre-authentication? (AS-REP Roasting targets)
  What computers have unconstrained delegation? (non-DCs only)
  What GPOs exist and what do they link to?
  What ACLs does my account (and its groups) have on AD objects?
  What trusts exist between domains?

How:
  LDAP queries via ldapdomaindump or windapsearch or bloodhound-python
  These are read-only, low-noise, and answer most of the important questions
  before you touch a single machine
```

### Priority 2: BloodHound collection and path analysis

```
Questions to answer:
  What is the shortest path from my account to Domain Admins?
  What accounts in my reach have privileged paths?
  What ACL misconfigurations exist in the domain?
  Where are Domain Admin sessions active right now?

Note: SharpHound with full collection is louder (SMB session enumeration).
      Use --stealth for LDAP-only collection first.
      Add session enumeration only if you need to find active DA sessions.
```

### Priority 3: Quick credential wins

```
Questions to answer:
  Are any AS-REP-roastable accounts crackable? (no credentials required)
  Are any Kerberoastable accounts crackable? (any domain user can request)
  Is GPP cpassword present in SYSVOL? (any domain user can read SYSVOL)
  Does LAPS expose any machine passwords? (if your account is in a LAPS reader group)
  Does any account have a password in its description field?

These attacks require minimal privileges and are low-noise.
A cracked service account password often gives you local admin on the servers it runs on.
```

### Priority 4: Local machine escalation

```
Once you have a shell on any machine:
  What privileges does the current user have? (whoami /priv)
  Is SeImpersonatePrivilege enabled? → Potato → SYSTEM
  What services have weak permissions?
  What is in the PowerShell history file?
  What credentials are cached in LSASS?
  What is in DPAPI stores?
```

### Priority 5: Lateral movement and hunting DA sessions

```
Once you have SYSTEM and credentials:
  Where can these credentials be reused? (netexec smb spray)
  Where are DA sessions active? (BloodHound, netexec --loggedon-users)
  What high-value machines are reachable from here?
```

---

## SECTION 13 — The BloodHound Mental Model

**🔷 WHAT**

BloodHound is not a scanner. It is a **graph database query engine**. It collects data about every AD object and the relationships between them, stores it as a graph (nodes connected by edges), and lets you query that graph for paths.

Every node is an AD object (user, group, computer, domain).
Every edge is a relationship (MemberOf, AdminTo, GenericAll, HasSession, etc.).

```
jdoe ──[MemberOf]──→ IT Support ──[GenericAll]──→ svc_sql ──[MemberOf]──→ Domain Admins
 └────────────────────────────────────────────────────────────────────────────────────┘
                            One connected path — BloodHound finds this in milliseconds
```

**🔶 WHY**

Without BloodHound, finding ACL chains and attack paths requires manually querying LDAP for every object's ACL, cross-referencing group memberships, and tracking chains by hand. For a domain with 10,000 users and 5,000 groups, this is effectively impossible manually. BloodHound reduces it to a query.

**⚔️ HOW**

The first five queries to run, in order, every time:

```
1. "Find Shortest Paths to Domain Admins"
   → Run this immediately after loading data. This is your primary attack path.
   → If the path is 2–3 edges, execute it immediately.
   → If the path is 8+ edges, look for shorter alternative paths.

2. "Find AS-REP Roastable Users"
   → No credentials needed to exploit these. Quick wins.

3. "Find Kerberoastable Users with Most Privileges"
   → Kerberoastable accounts on the path to DA are highest value.

4. "Find Computers with Unconstrained Delegation (non-DCs)"
   → These are coercion targets → DC TGT capture → DCSync

5. "Shortest Paths from Owned Principals"
   → After marking your account as Owned → shows paths from your position specifically
```

Reading a BloodHound edge means knowing what action it represents:

```
MemberOf       → you are in this group, you inherit its permissions
AdminTo        → you are local admin on this computer (can SYSTEM + dump LSASS)
HasSession     → a user has an active session on this computer (their creds in LSASS)
GenericAll     → you have full control over the target object
WriteDACL      → you can modify the target object's ACL
ForceChangePassword → you can reset the target user's password
AllExtendedRights → includes ForceChangePassword and more
AddMember      → you can add users to this group
CanPSRemote    → you can WinRM to this machine
CanRDP         → you can RDP to this machine
ExecuteDCOM    → you can execute via DCOM on this machine
SQLAdmin       → you are a SQL sysadmin on this SQL instance
```

---

## PART 5 — The Four Attack Path Categories

---

## SECTION 14 — Path Category 1: Credential-Based Attacks

**What these are:**  Getting password material from the domain without needing any machine access first.

**When to use:**  Always check these first. They require only your domain user account and generate moderate noise.

```
Attack          What you need       What you get
─────────────────────────────────────────────────────────────────────
Kerberoasting   Domain user creds   Offline crackable hash of service accounts
                                    → service account's password
                                    → their local admin access
                                    → possibly DA if they are privileged

AS-REP Roasting Just valid usernames Hash of accounts with pre-auth disabled
                                    → same as above

GPP cpassword   Domain user creds   Cleartext passwords from SYSVOL
                                    → often local admin or service account creds

LAPS reading    LAPS reader group   Local admin password for specific machines
                                    → immediate local admin on that machine

Password spray  Valid username list  A working credential if password policy is weak
                                    → ONLY as last resort, loudest technique
```

**The Kerberoasting decision framework:**

```
When you see a Kerberoastable account, ask:
  What groups is this account in?
    → Member of Server Admins / Domain Admins? → HIGH PRIORITY. Crack immediately.
    → Member of only Domain Users? → Lower priority. May still give local admin on services.

  What does its BloodHound path look like?
    → adminCount = 1? → Was once in a protected group → likely still privileged somewhere
    → Has a path to DA through ACLs? → Crack it, it is your key

  Is it using RC4 or AES encryption?
    → RC4 (hashcat mode 13100) → easier to crack, more common in older domains
    → AES (hashcat mode 19700) → harder, use better wordlists and rules
```

---

## SECTION 15 — Path Category 2: ACL Abuse Chains

**What these are:**  Misconfigurations where low-privilege accounts have unexpected control over higher-privilege objects.

**When to use:**  After BloodHound shows an ACL edge between your owned account and a path to DA.

**The execution pattern is always the same:**

```
Step 1: BloodHound shows edge [YOUR ACCOUNT] →[SOME_RIGHT]→ [TARGET OBJECT]
Step 2: Read the edge's "Abuse" tooltip in BloodHound (right-click the edge → Help)
Step 3: Execute the appropriate PowerView command
Step 4: Authenticate as the newly controlled account
Step 5: Repeat from Step 1 with the new account until DA
```

**The most common ACL chains you will encounter:**

```
CHAIN A: GenericAll on User
  → Reset target's password
  → Authenticate as target with new password
  → Check what target gives you → continue chain

CHAIN B: GenericAll on Group
  → Add yourself to the group
  → Log off and back on to refresh group membership token
  → Use new group permissions → continue chain

CHAIN C: WriteDACL on Domain Object → DCSync
  → Grant yourself DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
  → Run secretsdump as yourself → dumps all domain hashes
  → Extract krbtgt hash → Golden Ticket → EA

CHAIN D: GenericWrite on Computer
  → Write to msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD attribute)
  → Create/use a computer account
  → S4U2Self + S4U2Proxy → impersonate DA to that computer
  → Shell as DA on that computer → dump LSASS → real DA creds

CHAIN E: WriteOwner on Group
  → Take ownership of the group object
  → Grant yourself GenericAll on the group (you can modify your own object's ACL)
  → Add yourself to the group → continue
```

---

## SECTION 16 — Path Category 3: Delegation Abuse

**What these are:**  Kerberos delegation features that allow services to authenticate as users to other services. These are legitimate design features that become attack paths when misconfigured.

**The three types and what each gives you:**

```
UNCONSTRAINED DELEGATION
  What:    A computer or user with this flag receives a copy of the TGT of
           anyone who authenticates to it
  Find:    Computers with TrustedForDelegation=True that are NOT DCs
  Attack:  Get SYSTEM on that computer
           → Coerce the DC to authenticate to it (PetitPotam, PrinterBug)
           → DC's TGT is now in LSASS on that machine
           → Dump it → inject it → DCSync as the DC
  Result:  Full domain compromise from a non-DC machine

CONSTRAINED DELEGATION (S4U2Proxy)
  What:    A specific service account is allowed to impersonate users,
           but only to a specific list of services
  Find:    msDS-AllowedToDelegateTo attribute is populated on a user or computer
  Attack:  Compromise the delegating account (get its password/hash)
           → Use S4U2Self to get a ticket for a DA to this service
           → Use S4U2Proxy to convert it to a ticket for the allowed service
           → Authenticate as DA to the allowed service
  Trick:   The ticket's SPN can often be modified after issuance
           → cifs/target becomes ldap/target → different service, same rights

RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)
  What:    The TARGET resource decides who can delegate TO it
           (opposite of traditional constrained delegation)
  Find:    If you have GenericWrite/GenericAll/WriteProperty on a computer object
  Attack:  Write your controlled account's SID to the target's
           msDS-AllowedToActOnBehalfOfOtherIdentity attribute
           → S4U2Self: your account gets a ticket on behalf of a DA
           → S4U2Proxy: convert it to a service ticket for the target
           → Shell as DA on the target
  Why important: Works from a domain user with ANY write right on a computer
```

---

## SECTION 17 — Path Category 4: Local Admin Pivot Chain

**What these are:**  Finding machines where your credentials give you local admin → becoming SYSTEM → dumping credentials → using those credentials on the next machine.

**The pattern:**

```
Your domain creds → local admin on WS-01 (found via netexec spray)
         ↓
SYSTEM on WS-01 (SeImpersonatePrivilege → GodPotato)
         ↓
Dump LSASS on WS-01
         ↓
Find: svc_backup account hash (service runs on WS-01)
         ↓
svc_backup → local admin on BACKUP-SRV (found via netexec spray with svc_backup hash)
         ↓
SYSTEM on BACKUP-SRV
         ↓
Dump LSASS on BACKUP-SRV
         ↓
Find: DA account session (DA was logged in to BACKUP-SRV)
         ↓
DA's NTLM hash extracted
         ↓
PtH as DA → DCSync → krbtgt → Golden Ticket → Enterprise Admin
```

The chain continues until you find either:
1. A DA session on a machine you own
2. An account that has a direct privilege escalation to DA via ACLs
3. A machine where DCSync rights are granted to a non-DA account

---

## SECTION 18 — Final Mental Model: The Four Questions

Before running any tool, running any command, or taking any action — answer these four questions:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  QUESTION 1: Where am I?                                            │
│  What account do I control? What groups am I in? What machine am I  │
│  on (if any)? What privilege level do I have locally?               │
│                                                                     │
│  QUESTION 2: What can I see?                                        │
│  What does LDAP tell me about this domain? What does BloodHound     │
│  show as a path from my current position? What credentials have I   │
│  already harvested?                                                 │
│                                                                     │
│  QUESTION 3: What is the shortest path forward?                     │
│  From my current position, what is the minimum number of steps to   │
│  reach Domain Admin? Which of the four path categories does it      │
│  fall into? What is the most likely obstacle?                       │
│                                                                     │
│  QUESTION 4: What is the OPSEC cost?                                │
│  What events will my next action generate? Does that action deviate  │
│  from baseline? Is there a quieter way to achieve the same result?  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

These four questions drive every decision. The tools implement the decision — they do not make it.

---

## Mastery Checklist — AD Mental Model

You are ready to start using tools when you can answer every question below without notes:

**Domain structure:**
- [ ] What is the difference between a domain, tree, and forest?
- [ ] Why is the forest the security boundary and not the domain?
- [ ] What is an OU and how does it relate to GPO application?
- [ ] What does adminCount=1 on a user object tell you?

**Kerberos:**
- [ ] Draw the Kerberos AS-REQ/AS-REP/TGS-REQ/TGS-REP/AP-REQ flow without notes
- [ ] Why does Kerberoasting work? Map it to the specific protocol step.
- [ ] Why does AS-REP Roasting require no credentials?
- [ ] What is the krbtgt account and why does its hash enable Golden Tickets?
- [ ] What is a PAC and why do SIDs in the PAC determine your access?

**ACLs:**
- [ ] What does GenericAll on a user account let you do?
- [ ] What does WriteDACL on the domain object let you do?
- [ ] What does WriteOwner on a group let you do?
- [ ] Why is a nested group membership important for ACL chains?

**Delegation:**
- [ ] What is the difference between unconstrained, constrained, and RBCD?
- [ ] Why does unconstrained delegation combined with coercion give you DA?
- [ ] What AD attribute do you write for an RBCD attack?

**OPSEC:**
- [ ] Which actions generate Event 4769 and what flag makes it suspicious?
- [ ] Which action generates Event 4625 and why is volume the problem?
- [ ] Which action generates Event 4662 with replication GUIDs?
- [ ] What does "match your tooling to the environment" mean in practice?

**Escalation path:**
- [ ] What is the first thing you check when you get a shell on a new machine?
- [ ] What does a "(Pwn3d!)" response in netexec tell you?
- [ ] Where do you look for credentials after getting SYSTEM on a machine?
- [ ] How does a child domain DA become Enterprise Admin?
