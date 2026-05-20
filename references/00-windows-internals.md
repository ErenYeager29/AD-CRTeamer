# Phase 00: Windows Internals & Red Team Mindset

> **Why this phase exists**: Every red team technique exploits a Windows design decision. If you understand what Windows is doing and why, attacks stop being "magic commands" and start making logical sense. You'll debug failures faster, improvise when tools don't work, and understand detection.

**Study time**: 1 week
**Difficulty**: Beginner

---

## Learning Objectives

By the end of this phase you should be able to:
- [ ] Explain what a Windows process is and why process isolation matters for attacks
- [ ] Explain what an access token is and why it determines what you can do
- [ ] Explain what the Windows registry is and why it's a persistence target
- [ ] Explain what services are and why they're a privilege escalation surface
- [ ] Explain what LSASS is and why attackers want to read it
- [ ] Describe the red team mindset: thinking in trust relationships, not just vulnerabilities

---

## 1. What is Windows Architecture (and Why Should You Care)?

### The kernel / userland split

Windows is divided into two zones:

**Kernel mode** — the OS core. Has unrestricted access to hardware and memory. Drivers live here. If you crash kernel mode, the whole machine crashes (BSOD).

**User mode** — where all applications run, including LSASS, services, and your C2 beacon. Each process gets its own memory space isolated from other processes. You cannot read another process's memory without the OS granting you permission.

**Why this matters for red teaming**: LSASS (which holds credentials) runs in user mode. That means you *can* read it — but only if you have the right privileges. The entire game of privilege escalation is about acquiring those privileges.

### Processes and handles

A **process** is a running program with its own memory, threads, and handles. Every process runs under a **security context** — the identity it inherits from whoever started it.

A **handle** is a reference to a Windows object (file, process, registry key). When you dump LSASS, you open a handle to the LSASS process with read access, then copy its memory. EDRs watch for `OpenProcess` calls on LSASS with suspicious access rights.

```
Your beacon (process) 
  → calls OpenProcess(LSASS_PID, PROCESS_VM_READ)
  → Windows checks: does your process token have SeDebugPrivilege?
  → If yes: returns a handle you can read from
  → If no: Access Denied
```

**Mental model**: Think of processes as rooms with locked doors. Handles are keys. SeDebugPrivilege is a master key.

---

## 2. Access Tokens — The Heart of Windows Security

Every process in Windows carries an **access token**. This token tells Windows:
- Who you are (your SID — Security Identifier)
- What groups you belong to
- What privileges you have (SeImpersonatePrivilege, SeDebugPrivilege, etc.)

When you do *anything* — open a file, create a process, read a registry key — Windows checks your token against the object's access control list (ACL). Match = allowed. No match = denied.

### Token types

**Primary token**: The main identity of a process. Set when the process starts.

**Impersonation token**: A temporary token a thread can use to act as a different user. Services use this constantly — e.g., IIS impersonates the web request's identity.

### Why token impersonation is an attack

When a service runs as SYSTEM and creates an impersonation token for a connecting client (e.g., a named pipe), it briefly holds a token for that client identity. If you can get SYSTEM to connect to your named pipe, you steal that token and impersonate SYSTEM from a low-privilege process.

This is exactly how Potato attacks work. The mechanism is:
```
You (low-priv) → create a fake service that listens on a named pipe
Windows (SYSTEM) → connects to your pipe for legitimate reasons
You → steal the impersonation token → CreateProcessWithToken → SYSTEM shell
```

### SeImpersonatePrivilege

This privilege says: "this process is allowed to impersonate clients after authentication." It's granted to service accounts by default (IIS, MSSQL, network services). It's the reason most service account compromises lead straight to SYSTEM.

**Practice**: Run `whoami /priv` on a Windows machine. Note which privileges are listed as Enabled vs Disabled. Disabled doesn't mean useless — many can be re-enabled.

---

## 3. The Windows Registry

The registry is a hierarchical database that stores configuration for Windows and applications. Think of it as a filesystem for settings.

**Key hives relevant to red teaming**:

| Hive | Contains | Attack relevance |
|------|---------|-----------------|
| `HKLM\SYSTEM` | Service config, boot settings | Service binary paths (privesc) |
| `HKLM\SAM` | Local account password hashes | Credential dumping |
| `HKLM\SECURITY` | LSA secrets, service account creds | Credential dumping |
| `HKCU\Software\...\Run` | Current user autorun entries | Persistence (user-level) |
| `HKLM\Software\...\Run` | System-wide autorun entries | Persistence (system-level) |
| `HKLM\SOFTWARE\Policies\...` | Group Policy settings | AppLocker, AMSI config |

**Why persistence via registry works**: Windows reads Run keys at every logon and startup. You write your beacon path there; Windows executes it for you, as the user's identity, every time they log in.

---

## 4. Windows Services — The Privilege Escalation Surface

A **service** is a long-running background process managed by the Service Control Manager (SCM). Services are configured in the registry at `HKLM\SYSTEM\CurrentControlSet\Services\`.

Each service has:
- A **binary path** — what executable runs
- A **start type** — automatic, manual, disabled
- A **logon account** — what identity it runs as (SYSTEM, Network Service, a specific account)

**Why services are a privesc surface**:

1. **Weak binary permissions**: If the service's `.exe` is writable by you, replace it with your beacon. When the service starts (or restarts), your code runs as the service's identity — often SYSTEM.

2. **Unquoted paths with spaces**: If the path is `C:\Program Files\My App\service.exe` without quotes, Windows tries `C:\Program.exe` first, then `C:\Program Files\My.exe`, then the real path. If any of those intermediate directories is writable by you, drop a binary there — Windows runs it as the service's identity.

3. **Weak ACL on service object**: If you have `SERVICE_CHANGE_CONFIG` rights on a service object, you can change its binary path to anything you want.

**The mental model**: Services run as privileged identities. Misconfigured services let you substitute your code where Windows expects the service's code. Windows then runs your code with the service's privileges.

---

## 5. LSASS — Why Attackers Want It

**LSASS** (Local Security Authority Subsystem Service) is the process responsible for authenticating users. It validates passwords, creates access tokens, and manages security policies.

Because it handles authentication, LSASS caches:
- NTLM password hashes for logged-on users
- Kerberos tickets and session keys
- Sometimes cleartext passwords (via WDigest, which is disabled by default since Windows 8.1)

**Why reading LSASS = reading credentials**: Every user who has authenticated to this machine since last boot has left traces in LSASS memory. If a Domain Admin logged in recently, their hash is there.

**Why it's protected**:
- Requires `SeDebugPrivilege` to open with read access
- Modern Windows enables **PPL (Protected Process Light)** for LSASS, which prevents even SYSTEM from reading it without a signed kernel driver
- EDRs hook `OpenProcess` specifically for LSASS

**The attack chain**:
```
Escalate to SYSTEM (needed for SeDebugPrivilege)
→ Open LSASS with VM_READ access
→ Call MiniDumpWriteDump to create a memory dump
→ Transfer dump to Kali
→ Parse with pypykatz / Mimikatz offline
→ Extract NTLM hashes and Kerberos keys
```

---

## 6. The Red Team Mindset

Understanding techniques is not enough. You need to think differently.

### Think in trust relationships, not vulnerabilities

Vulnerabilities get patched. Trust relationships are architectural — they're designed in. Kerberoasting isn't a bug; it's a consequence of how Kerberos authentication works. ACL misconfigurations aren't bugs; they're administrative mistakes in a system that was designed to be flexible.

**Ask**: *Who does Windows trust to do X? Can I become that entity?*

### Think in chains, not single steps

No single technique goes from domain user to Domain Admin in one step (usually). You chain: foothold → local privesc → credential theft → lateral move → repeat → DA.

Every step should answer: "What new trust relationship does this give me access to?"

### Think about what leaves traces

Every action has a footprint:
- Creating a process = Event 4688
- Opening LSASS = Sysmon Event 10
- Modifying a service = Event 7040
- Kerberos ticket request = Event 4769

**Red teamers ask**: "What is the minimum footprint to achieve my objective?"

### The assumed breach model

The CRTeamer exam starts with low-priv domain credentials — this is called "assumed breach." It simulates a scenario where an attacker has already bypassed perimeter controls (phishing, stolen creds, etc.) and is now inside the network as a regular user.

Your job is to demonstrate what damage a real attacker could do from that position. This is why enumeration comes before exploitation — you need to understand the environment before you can pivot through it.

---

## 7. Build Your Lab (Do This Now)

You cannot learn red teaming without a lab. Here's the minimum viable setup:

### Option A: Fully local (16GB RAM recommended)

```
1. Download and install VirtualBox or VMware Workstation (free)
2. Create 3 VMs:
   - Kali Linux (attacker) — 4GB RAM, 2 CPUs
   - Windows Server 2019 (DC) — 4GB RAM, 2 CPUs
   - Windows 10 (victim workstation) — 4GB RAM, 2 CPUs
3. Network: Host-only adapter, 192.168.56.0/24
4. Promote Windows Server to Domain Controller (covered in crteamer-exam-prep Phase 00)
5. Add vulnerable accounts (covered in crteamer-exam-prep Phase 00)
```

### Option B: GOAD (most realistic, requires 16GB+ RAM)

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD
# Follow README for your chosen provider (VirtualBox, VMware, Proxmox)
# Use GOAD-Light (3 VMs) if RAM is limited
```

### Option C: TryHackMe subscription (~£14/month)

Best for beginners — no local setup needed. All labs are browser-based.
Start with: **TryHackMe Red Team Path** → free and guided.

---

## 8. Free Learning Resources

| Resource | What to study here | Time investment |
|---------|-------------------|----------------|
| [ired.team](https://www.ired.team) | Windows internals + attack techniques with deep explanations | High — core reference |
| [Windows Internals book](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) | The definitive reference (heavy reading) | Reference |
| [THM: Windows Fundamentals 1-3](https://tryhackme.com/room/windowsfundamentals1xbx) | Interactive Windows internals basics | 3 hours |
| [THM: Windows Internals](https://tryhackme.com/room/windowsinternals) | Processes, threads, handles, DLLs | 3 hours |
| [THM: Intro to C2](https://tryhackme.com/room/introtoc2) | How C2 frameworks work conceptually | 2 hours |
| [MITRE ATT&CK](https://attack.mitre.org) | Framework mapping all red team techniques | Ongoing reference |

---

## Phase 00 Mastery Checklist

Don't move to Phase 01 until you can answer all of these **without looking**:

- [ ] What is a process access token and what information does it contain?
- [ ] What is SeImpersonatePrivilege and why do service accounts have it?
- [ ] Why can SYSTEM read LSASS memory? What privilege enables this?
- [ ] Name three registry locations used for persistence and explain why each one works.
- [ ] What is an unquoted service path and why does it allow privilege escalation?
- [ ] What is LSASS and why does it cache credentials?
- [ ] What is the "assumed breach" model and why does the CRTeamer exam use it?
- [ ] What's the difference between a vulnerability and a trust relationship in red teaming?

**If you can't answer these**: go back to the THM rooms above. These concepts underpin every technique in the exam.

---

## Next Phase

→ **Phase 01: Red Team Infrastructure & OPSEC** — setting up the infrastructure that makes everything else possible
