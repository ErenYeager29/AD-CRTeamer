# C2-Driven Red Team Workflow & Pivoting

> **Exam Priority: ⭐⭐⭐⭐⭐ CRITICAL**
>
> **Purpose:** Understand **how to operate through a C2**, when to use **Kali tools**, when to execute **inside the Beacon**, and how **pivoting** actually works.
>
> **Key Concept:** The C2 is **not** your shell. It is your **operating platform inside the target environment**.

---

# Why Use a C2?

A common misconception is:

> **"I already have a shell. Why do I need a C2?"**

A shell only provides command execution.

A **C2 Framework** provides:

- Persistent access
- Multiple sessions
- Pivoting
- SOCKS proxy
- Port forwarding
- File transfer
- In-memory execution
- Session management
- Team collaboration
- OPSEC improvements

Think of it as your **command center**.

---

# The Red Team Mindset

Your objective is **NOT** to attack the network from Kali.

Your objective is to make it appear as though the **compromised workstation** is performing the activity.

Instead of thinking:

```
Kali → Domain Controller
```

Think:

```
Kali
   │
Sliver
   │
Beacon
   │
Internal Network
```

The Beacon becomes your **internal operator**.

---

# High-Level Architecture

```text
                     Internet / VPN
                           │
                     Kali Operator
                           │
                    Sliver Teamserver
                           │
                 Encrypted C2 Channel
                           │
                    Beacon on WS01
                ┌──────────┼──────────┐
                │          │          │
              LDAP       SMB     Kerberos
                │          │          │
                └──────────┼──────────┘
                     Internal Network
```

The workstation is now your gateway into the enterprise.

---

# Understanding the Roles

## Kali

### Purpose

Your operator workstation.

Use Kali for:

- Impacket
- NetExec
- Certipy
- BloodHound
- Hashcat
- Custom scripts
- Enumeration utilities

### Think

> **"I have the tools."**

---

## Sliver Teamserver

### Purpose

Your command infrastructure.

Responsible for:

- Managing Beacons
- Listeners
- Payload generation
- Session management
- SOCKS proxy
- Port forwarding
- Operator coordination

### Think

> **"I control the operation."**

---

## Beacon (Implant)

### Purpose

Your presence inside the victim environment.

Capabilities include:

- Execute PowerShell
- Execute C# assemblies
- Execute BOFs
- File upload/download
- Credential operations
- Pivoting
- SOCKS proxy
- Port forwarding

### Think

> **"I am the workstation."**

---

# Typical Red Team Workflow

```text
VPN Connection
      │
      ▼
Start Sliver
      │
      ▼
Obtain First Beacon
      │
      ▼
Enumerate Host
      │
      ▼
Enumerate Active Directory
      │
      ▼
Start SOCKS Proxy
      │
      ▼
Route Kali Tools Through SOCKS
      │
      ▼
Compromise Another Host
      │
      ▼
Deploy New Beacon
      │
      ▼
Repeat
```

---

# Two Types of Operations

## Type 1 — Execute Inside the Beacon

These commands execute **directly on the compromised workstation**.

Examples:

- PowerShell
- PowerView
- Seatbelt
- SharpHound
- Rubeus
- Execute Assembly
- BOFs
- Mimikatz (where appropriate)

Advantages

- No direct Kali connection
- In-memory execution
- Easier file management
- Better operational workflow

Traffic remains inside the C2 channel.

---

## Type 2 — Run Kali Tools Through the Beacon

Some tools are designed to run on Linux.

Examples

- NetExec
- Certipy
- BloodHound-python
- GetUserSPNs.py
- GetNPUsers.py
- secretsdump.py
- ntlmrelayx.py

These should generally be routed through the Beacon.

Example traffic flow

```text
Kali
   │
proxychains
   │
SOCKS5
   │
Beacon
   │
Domain Controller
```

The Beacon becomes the network pivot.

---

# Why Use a SOCKS Proxy?

Without SOCKS

```text
Kali
   │
   ▼
Domain Controller
```

The defender observes:

> Linux host communicating directly with the Domain Controller.

---

With SOCKS

```text
Kali
   │
SOCKS
   │
Beacon
   │
Domain Controller
```

The defender observes:

> Internal Windows workstation communicating with the Domain Controller.

This is a far more realistic communication path.

---

# Does SOCKS Improve OPSEC?

## YES

It improves **where traffic originates.**

Instead of:

```
Kali → DC
```

You have:

```
Workstation → DC
```

---

## NO

It does **NOT** reduce the amount of traffic generated.

The following remain noisy:

- BloodHound collection
- LDAP enumeration
- SMB scanning
- Password spraying
- DCSync
- LSASS dumping

SOCKS changes **origin**, not **behavior**.

---

# Understanding OPSEC

Always ask yourself:

> **"Would a normal employee workstation do this?"**

---

## Normal Activity

✅ LDAP queries

✅ Kerberos authentication

✅ SMB to file servers

✅ DNS lookups

✅ Web browsing

---

## Suspicious Activity

❌ Enumerating every computer

❌ Connecting to every admin share

❌ Thousands of LDAP requests

❌ Password spraying

❌ DCSync

❌ LSASS dumping

❌ Scanning an entire subnet

---

# When Should I Use Kali?

Use Kali when you need Linux-native tooling.

Recommended tools:

| Tool | Recommended? |
|-------|--------------|
| NetExec | ✅ |
| Impacket | ✅ |
| Certipy | ✅ |
| BloodHound-python | ✅ |
| Hashcat | ✅ |
| Custom Python Scripts | ✅ |

Always prefer routing them through SOCKS whenever possible.

---

# When Should I Stay Inside the Beacon?

Use the Beacon whenever possible for Windows-native tooling.

Examples

- PowerView
- Seatbelt
- SharpHound
- Rubeus
- PowerShell
- Execute Assembly
- BOFs
- File Transfers

Advantages

- Less operational overhead
- Better workflow
- Less file movement
- Better integration with Windows tooling

---

# Typical Enterprise Attack Chain

```text
Initial Access
      │
      ▼
Beacon on Workstation
      │
      ▼
Host Enumeration
      │
      ▼
Active Directory Enumeration
      │
      ▼
BloodHound
      │
      ▼
Identify Attack Path
      │
      ▼
Kerberoasting
      │
      ▼
Credential Access
      │
      ▼
Lateral Movement
      │
      ▼
Deploy New Beacon
      │
      ▼
Repeat Enumeration
      │
      ▼
Privilege Escalation
      │
      ▼
Domain Admin
```

Every newly compromised machine extends your operational capability.

---

# Pivoting

Never think:

> **"I have one shell."**

Think:

> **"I am building an internal operating infrastructure."**

Example

```text
Kali
   │
Beacon (WS01)
   │
Server01
   │
SQL01
   │
Management Server
   │
Domain Controller
```

Every Beacon becomes another pivot point.

---

# Decision Tree

## Need PowerShell?

➡ Use the Beacon

---

## Need PowerView?

➡ Use the Beacon

---

## Need Seatbelt?

➡ Use the Beacon

---

## Need Rubeus?

➡ Use the Beacon

---

## Need Execute Assembly?

➡ Use the Beacon

---

## Need BOFs?

➡ Use the Beacon

---

## Need NetExec?

➡ Kali → SOCKS

---

## Need BloodHound-python?

➡ Kali → SOCKS

---

## Need Certipy?

➡ Kali → SOCKS

---

## Need Impacket?

➡ Kali → SOCKS

---

# Golden Rule

The Beacon provides

> **ACCESS**

The SOCKS Proxy provides

> **NETWORK ROUTING**

Kali provides

> **TOOLS**

Together they become

> **YOUR RED TEAM OPERATING PLATFORM**

---

# Practical Exam Workflow (CRTeamer)

```text
Connect VPN
      │
      ▼
Start Sliver
      │
      ▼
Generate Payload
      │
      ▼
Obtain Initial Beacon
      │
      ▼
Host Enumeration
      │
      ▼
Active Directory Enumeration
      │
      ▼
Start SOCKS Proxy
      │
      ▼
Configure proxychains
      │
      ▼
Run Impacket / NetExec / Certipy / BloodHound
      │
      ▼
Find Attack Path
      │
      ▼
Lateral Movement
      │
      ▼
Deploy New Beacon
      │
      ▼
Repeat Until Objective Achieved
```

---

# Common Mistakes

❌ Running every tool directly from Kali

❌ Thinking SOCKS makes activity invisible

❌ Performing full BloodHound collection immediately

❌ Scanning entire subnets unnecessarily

❌ Dropping binaries when execute-assembly is sufficient

❌ Forgetting that every new Beacon becomes a new pivot point

---

# Key Takeaways

✅ C2 ≠ Reverse Shell

✅ Beacon = Internal Presence

✅ SOCKS = Network Pivot

✅ Kali = Toolbox

✅ OPSEC depends on **behavior**, not just routing

✅ Every Beacon extends your operational reach

✅ Route Linux-native tools through the Beacon whenever practical

✅ Execute Windows-native tooling directly inside the Beacon whenever practical

---

