# Windows Internals for Red Teamers
## Zero to Solid Foundation — Every Section Answers WHAT → WHY → HOW

> **Teaching pattern used throughout:**
> 🔷 **WHAT** — What is this thing, defined simply
> 🔶 **WHY** — Why does Windows have it, what problem does it solve
> ⚔️ **HOW** — How attackers exploit or interact with it
> 🧠 **LOCK IT IN** — An analogy or visual to make it permanent

---

## Before You Begin — Why Internals Matter for Red Teaming

Most red team resources teach you *what to run*. This document teaches you *why it works*.

When you understand why LSASS holds credentials, dumping it is not magic — it is a logical consequence of how authentication works. When you understand what a handle is, process injection is not a trick — it is a predictable abuse of a designed system. When you understand integrity levels, UAC bypass is not a mystery — it is exploiting a specific design decision Microsoft made in 2007.

**The rule**: if you cannot explain why a technique works to someone who has never heard of it, you do not understand it well enough to use it reliably.

Read every section fully. Later sections build on earlier ones — the order matters.

---

## SECTION 1 — The Two Zones: Kernel Mode vs User Mode

**🔷 WHAT**

Your CPU has two operating modes. Windows uses both, and the separation between them is the foundation of every other security mechanism in this document.

**User Mode** — where all applications run. Notepad, Chrome, LSASS, your C2 beacon. Every process runs here. Each process gets its own private virtual address space — a region of memory that belongs only to it. Process A cannot read Process B's memory. The OS enforces this isolation completely.

**Kernel Mode** — where Windows itself runs. The core OS, memory manager, scheduler, hardware drivers. Code running in kernel mode has *unrestricted access to everything* — every byte of RAM on the entire machine, every hardware device, all of it. There are no access checks here. If a driver crashes in kernel mode, the entire machine crashes — Blue Screen of Death (BSOD). The entire system dies because the kernel has no isolating layer beneath it.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          USER MODE                                  │
│                                                                     │
│   notepad.exe   chrome.exe   lsass.exe   svchost.exe   beacon.exe  │
│   ─────────     ─────────    ─────────   ──────────    ─────────   │
│   [isolated]    [isolated]   [isolated]  [isolated]    [isolated]  │
│                                                                     │
│   Each process has its own private virtual address space.           │
│   Process A cannot directly access Process B's memory.             │
│   Must ask the OS (via system calls) to cross boundaries.           │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                        KERNEL MODE                                  │
│                                                                     │
│   ntoskrnl.exe (OS core)  |  Win32k.sys  |  Hardware Drivers       │
│                                                                     │
│   No restrictions. Full access to all memory.                       │
│   A crash here = entire machine crashes (BSOD).                    │
│   EDRs run here. AV kernel components run here.                     │
└─────────────────────────────────────────────────────────────────────┘
                   ↕ crossing requires a system call ↕
```

The line between these two zones is called the **ring boundary** — CPU hardware enforces it. Crossing from user mode into kernel mode is a deliberate, controlled operation called a **system call (syscall)**. Your code does not jump directly into kernel mode. It asks the CPU to switch modes and execute a specific kernel function.

**🔶 WHY**

Without this separation, any running program could:
- Read your browser's memory and steal your banking password
- Overwrite OS code and take permanent control of the machine
- Crash the entire system by writing to the wrong memory address

The two-zone model makes isolation possible. Every other security feature — access tokens, ACLs, AMSI, integrity levels — only works because user-mode processes cannot bypass it without going through the OS.

**⚔️ HOW**

This boundary defines the entire attack surface:

**LSASS is in user mode.** It holds credentials. You can access it — but only if the OS grants you permission. The entire game of credential dumping is convincing the OS to give you the right access rights to LSASS's memory.

**EDR kernel components run in kernel mode.** They have a driver loaded into kernel mode that sees everything. To bypass a kernel-level EDR, you need a kernel-level attack — a malicious driver, or exploiting a vulnerable legitimate driver (BYOVD — Bring Your Own Vulnerable Driver). Kernel drivers are signed by Microsoft. Getting an unsigned driver loaded requires defeating Kernel Patch Protection (PatchGuard).

**Userland unhooking works because hooks are in user mode.** EDRs inject a DLL into your process and modify function code in user mode. You can overwrite those modifications from inside the same process — no kernel access needed. This is the fundamental reason userland unhooking (loading a clean copy of ntdll.dll) bypasses many EDR hooks.

**🧠 LOCK IT IN**

The kernel is the hotel manager with a master key to every room on every floor. User-mode processes are guests who each have a key to only their own room. Guest A cannot enter Guest B's room — the locks enforce it physically. To access a different room, you must ask the manager, who checks your identity before deciding.

Privilege escalation = convincing the manager you deserve access to rooms you should not have.
BYOVD = bribing the locksmith (a legitimate but vulnerable kernel driver) to modify the locks from inside the building management system.

---

## SECTION 2 — Virtual Memory: The Illusion Every Process Lives In

**🔷 WHAT**

Every process believes it has its own private, contiguous block of memory starting at address 0 and going up to the maximum address for the architecture. This belief is an illusion maintained by the CPU and Windows. It is called **virtual memory**.

On a 64-bit system, each process has a virtual address space of 128 TB — far more than any machine physically has. The CPU, with Windows' help, maps each virtual address to an actual physical address in RAM (or to a page file on disk if RAM is full).

```
Process A's view of memory:          Process B's view of memory:
  Virtual address 0x00001000           Virtual address 0x00001000
  → Physical address 0x48A2000         → Physical address 0x91C4000
                                         ↑ completely different physical page
  Same virtual address, different physical pages. Each process is isolated.
```

**Memory pages** are the unit of memory management. A page is typically 4KB. Each page has protection flags:

| Flag | Hex | Meaning |
|---|---|---|
| `PAGE_NOACCESS` | 0x01 | No access at all |
| `PAGE_READONLY` | 0x02 | Read only |
| `PAGE_READWRITE` | 0x04 | Read and write |
| `PAGE_EXECUTE` | 0x10 | Execute only |
| `PAGE_EXECUTE_READ` | 0x20 | Read and execute — normal for code |
| `PAGE_EXECUTE_READWRITE` | 0x40 | Read, write, and execute — suspicious |
| `PAGE_EXECUTE_WRITECOPY` | 0x80 | Copy-on-write + execute |

**🔶 WHY**

Virtual memory solves three problems simultaneously:

**Isolation** — each process has its own address space. Process A at virtual address 0x1000 is mapped to a completely different physical page than Process B at virtual address 0x1000. They literally cannot see each other's memory.

**More memory than physically exists** — a machine with 16GB RAM can run processes with a combined virtual footprint of much more, because pages are swapped to disk when not needed and loaded back when accessed.

**Simplicity** — every process is compiled and linked assuming it has a clean, consistent address space from 0 to maximum. The virtual memory layer handles the messy reality of sharing physical RAM.

**⚔️ HOW**

Virtual memory is central to every process injection technique. To inject code into another process:

```
1. OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, target_pid)
   → Get a handle to the target process's address space
   → Requires SeDebugPrivilege (need SYSTEM or admin)

2. VirtualAllocEx(handle, NULL, shellcode_size, MEM_COMMIT, PAGE_READWRITE)
   → Allocate a new page in the TARGET process's virtual address space
   → Returns a virtual address in the TARGET's space

3. WriteProcessMemory(handle, remote_address, shellcode, shellcode_size)
   → Write your shellcode into the allocated page
   → Now the target process's virtual address space contains your shellcode

4. VirtualProtectEx(handle, remote_address, shellcode_size, PAGE_EXECUTE_READ)
   → Change protection: READWRITE → READ+EXECUTE
   → The page can now be executed

5. CreateRemoteThread(handle, NULL, 0, remote_address, NULL, 0, NULL)
   → Create a new thread in the TARGET process starting at your shellcode
   → Thread executes inside the target process's context
```

**Why PAGE_EXECUTE_READWRITE is a detection signal:**
Steps 2-3 above allocate RW memory, write shellcode, then convert to RX. The intermediate state (allocating RWX directly — `PAGE_EXECUTE_READWRITE`) is extremely suspicious and flagged by modern EDRs. Legitimate code almost never needs memory that is simultaneously writable and executable. That combination strongly indicates shellcode staging.

**EDR detection of injection:**
- Hook `VirtualAllocEx` — flag allocations in remote processes
- Hook `WriteProcessMemory` — flag writes to executable pages
- Hook `CreateRemoteThread` — flag new threads with suspicious start addresses
- Scan all process memory periodically for known shellcode patterns (bypassed by sleep obfuscation)

**🧠 LOCK IT IN**

Virtual memory is like each person having their own map of a city where they are the only resident, and every building belongs to them. Two people can both say "I live at 123 Main Street" — they are not neighbours; they are in completely separate instances of the city that happen to have the same map coordinates. The postal service (CPU + Memory Management Unit) handles the translation between map-address and real physical location, completely transparently.

---

## SECTION 3 — Processes: What They Are and What They Contain

**🔷 WHAT**

A process is a running instance of a program. When Windows starts a process, it creates a container that holds:

```
┌──────────────────────────────────────────────────────────────────┐
│                         PROCESS                                  │
│                                                                  │
│  Virtual Address Space                                           │
│  ─────────────────────                                           │
│  Code (.text section) — read + execute                           │
│  Data (.data, .bss) — read + write                               │
│  Heap — dynamically allocated memory                             │
│  Stack — per-thread function call frames                         │
│  Mapped DLLs — shared libraries                                  │
│  ntdll.dll, kernel32.dll, amsi.dll, edrhook.dll, ...            │
│                                                                  │
│  Security Token                                                  │
│  ──────────────                                                  │
│  Identity: who is running this process?                          │
│  Groups: what groups does this identity belong to?               │
│  Privileges: what special capabilities does this process have?   │
│                                                                  │
│  Handle Table                                                    │
│  ────────────                                                    │
│  Handle #4  → C:\file.txt (GENERIC_READ)                        │
│  Handle #8  → lsass.exe process (PROCESS_VM_READ) — if granted  │
│  Handle #12 → HKCU\Software\... (KEY_READ | KEY_WRITE)          │
│                                                                  │
│  Threads                                                         │
│  ───────                                                         │
│  Thread 1: main loop                                             │
│  Thread 2: network communications                                │
│  Thread N: ...                                                   │
└──────────────────────────────────────────────────────────────────┘
```

**🔶 WHY**

Processes exist because isolation is essential for stability and security. A bug in Process A cannot corrupt Process B's memory — the virtual address space isolation prevents it. A crash in Process A does not take down Process B — each is independent.

Without process isolation, running two programs simultaneously would be impossible — they would overwrite each other's memory. Every multi-tasking OS uses process isolation. Windows, Linux, macOS — all of them.

**⚔️ HOW**

**Process listing is reconnaissance.** When you land on a machine, listing running processes tells you:

```
Processes that reveal the environment:
  MsMpEng.exe      → Windows Defender is running
  CylanceSvc.exe   → CylancePROTECT EDR is present
  CSFalconService  → CrowdStrike Falcon is present
  SentinelOne.exe  → SentinelOne EDR
  splunkd.exe      → Splunk is collecting logs — everything goes to SIEM
  lsass.exe        → Present (always). Target for credential dumping.
  w3wp.exe         → IIS worker process — web server, interesting permissions
  sqlservr.exe     → SQL Server — check for xp_cmdshell capability
  TeamViewer.exe   → Remote access tool — credentials stored?

Processes that help you:
  explorer.exe     → Stable, long-running, runs as current user — migration target
  svchost.exe      → Multiple instances, normal, blend in — migration target
  RuntimeBroker.exe → Windows Store broker — legitimate, quiet
```

**Process parent-child relationships reveal executions.** When you run something via a macro or script injection, the parent-child relationship can be suspicious:
```
Suspicious:    WINWORD.EXE → cmd.exe → powershell.exe
               (Office spawning command shell — common malware pattern)

Less suspicious: explorer.exe → powershell.exe
                 (User opened PowerShell from Explorer — normal)

Ideal: svchost.exe → your beacon
       (Looks like a Windows service — very hard to distinguish from legitimate)
```

**🧠 LOCK IT IN**

A process is like a worker in their own sealed office. They have their own desk (virtual memory), their own ID badge (security token), their own filing cabinet key (handle table), and they are working on their own tasks (threads). The building manager (OS) controls who can enter whose office and what they can do there. Breaking into someone else's office requires either a master key (SeDebugPrivilege) or finding an unlocked window (a vulnerability).

---

## SECTION 4 — Threads: The Workers Inside the Process

**🔷 WHAT**

A thread is the actual unit that executes code. A process is a container — threads are the workers inside it. Every process has at least one thread. Many processes have dozens.

Each thread has its own:
- **Stack** — a region of memory for its local variables and function call history (call stack)
- **Instruction Pointer (RIP on x64)** — points to the current instruction being executed
- **Register state** — all CPU registers (RAX, RBX, RSP, etc.) are saved and restored when threads are swapped in/out

The CPU switches between threads extremely rapidly (every few milliseconds), giving the illusion that all threads are running simultaneously. On a multi-core CPU, threads genuinely run in parallel — one per core.

**🔶 WHY**

Threads exist because a single sequential flow of execution cannot do multiple things concurrently. Without threads, Chrome could not render a page, play audio, download a file, and respond to your mouse clicks at the same time. Threads let one process do many things simultaneously.

**⚔️ HOW**

**Threads are injection targets.** Instead of creating a new thread (visible, suspicious), you can hijack an existing thread:

```
Thread hijacking:
1. OpenProcess + OpenThread on a target process/thread
2. SuspendThread(target_thread) — pause the thread
3. GetThreadContext(target_thread) — save its current state (registers, RIP)
4. Allocate memory, write shellcode (as in process injection)
5. SetThreadContext → change RIP to point at your shellcode
6. ResumeThread(target_thread) — thread resumes from your shellcode

Result: no new thread created — harder to detect
        your shellcode runs, completes, then jumps to original RIP
        thread continues normally afterward
```

**Thread suspension enables code injection:**
`SuspendThread` + `GetThreadContext` + `SetThreadContext` is a legitimate API combination for debuggers. EDRs watch for it on threads belonging to sensitive processes.

**🧠 LOCK IT IN**

Threads are workers on an assembly line. The factory (process) has the raw materials and tools (memory and handles). Workers (threads) do the actual tasks. If you want the factory to produce something it was not designed for, you can either hire a new worker (CreateThread — visible, new hire paperwork), or intercept an existing worker mid-task, give them new instructions, and have them complete the unauthorized work before resuming their normal job (thread hijacking — no new hire, harder to notice).

---

## SECTION 5 — Handles: The Controlled Reference System

**🔷 WHAT**

A handle is a numbered reference to a Windows object. When a process wants to interact with any kernel object — a file, another process, a registry key, a mutex, a named pipe, an event — it must first *ask the OS to open it*. The OS checks permissions, and if granted, returns a handle: an integer (like `0x0004`, `0x0008`, `0x000C`) that represents your access to that object.

```
Process wants to read lsass.exe memory:

Process calls: OpenProcess(
    PROCESS_VM_READ,         ← the access rights you want
    FALSE,
    lsass_pid                ← which process
)

OS checks: does the calling process's token have SeDebugPrivilege?
    YES → creates handle entry in process's handle table
          returns handle value (e.g., 0x0008)
    NO  → returns NULL + sets LastError = ACCESS_DENIED

Now the process uses handle 0x0008 in calls like ReadProcessMemory().
The handle is valid until CloseHandle() is called or the process exits.
```

The handle table is a per-process structure maintained in kernel memory. Every handle a process holds is listed there with the object it references and the access rights granted.

**🔶 WHY**

Handles exist because direct memory pointers to kernel objects would be dangerous. If you could hold a raw pointer to a kernel object, you could corrupt it — or any adjacent kernel memory — with a simple memory write. Handles are opaque integers. They only work through OS functions that validate them. The OS controls what you can do with a handle based on the access rights it was opened with.

Handles also enable resource tracking. When a process exits (even abnormally), Windows can look at that process's handle table and close every object it held. No resource leaks — the OS cleans up.

**⚔️ HOW**

**Handle duplication is a stealthy credential dumping technique.** If another process (e.g., a security product, or even the OS itself) already has an open handle to LSASS with sufficient access rights, you can duplicate that handle into your own process — without calling `OpenProcess` on LSASS directly.

```
Normal (detected):
  Your process → OpenProcess(PROCESS_VM_READ, lsass_pid)
  → Hook on OpenProcess fires → EDR sees LSASS targeted → ALERT

Handle duplication (stealthier):
  Find a process that ALREADY has a handle to LSASS open
  (e.g., Windows Defender's process has an open handle for monitoring)
  → DuplicateHandle(source_process, existing_handle, your_process, ...)
  → You now have a copy of that handle in your process
  → ReadProcessMemory with your duplicated handle
  → No OpenProcess on LSASS in your process → hook may not fire
```

**Why SeDebugPrivilege is the master key:**
With SeDebugPrivilege, `OpenProcess` with any access rights on any process is granted — regardless of that process's own permissions. It overrides normal access checks. SYSTEM always has it. Local administrators have it but UAC may prevent it being enabled in a medium-integrity context (hence the UAC bypass requirement before LSASS dumping from an admin account).

**🧠 LOCK IT IN**

A handle is a library card for a specific book. You do not get to touch the book directly — you give the library card to the librarian (OS), who retrieves the book and lets you do whatever your card says you are allowed to do (read, write, photocopy). The library keeps records of every card currently in use. When you return the card (CloseHandle) or leave the library (process exits), the book is returned. Handle duplication is finding someone else's card and making a photocopy of it — the book is the same, the permissions on the card are the same.

---

## SECTION 6 — Access Tokens: The Identity of a Process

**🔷 WHAT**

Every process in Windows carries an **access token** — a kernel object that represents the security identity of the process. When the process tries to do anything — open a file, read a registry key, create a new process — Windows checks the token against the object's permissions.

An access token contains:

```
ACCESS TOKEN
│
├── User SID         S-1-5-21-...-1001       (who you are)
│
├── Group SIDs       S-1-5-21-...-512  (Domain Admins)
│                    S-1-5-32-544      (Administrators)
│                    S-1-1-0           (Everyone)
│                    S-1-5-11          (Authenticated Users)
│                    ... (every group the user belongs to)
│
├── Privileges       SeDebugPrivilege         (Enabled/Disabled)
│                    SeImpersonatePrivilege   (Enabled)
│                    SeShutdownPrivilege      (Disabled)
│                    ... (special capabilities)
│
├── Integrity Level  Medium / High / System   (UAC-related)
│
└── Token Type       Primary (process) or Impersonation (thread)
```

**🔶 WHY**

The token is the single source of truth for "who is this process and what can it do?" Every access check in Windows ultimately comes down to: "does this token's SID list, privilege list, and integrity level allow this operation on this object?"

Tokens are created at logon — your credentials are verified by LSASS, and LSASS creates a token representing your identity. That token is inherited by every process you start from that logon session.

**⚔️ HOW**

**Token manipulation is the mechanism behind escalation.** Three techniques:

**Token impersonation:**
```
A service (running as SYSTEM) creates an impersonation token for a client
connecting to it. You get SYSTEM to connect to your service. You steal
the impersonation token it creates for itself.

ImpersonateNamedPipeClient()  → steal token from a named pipe connection
OpenProcessToken()            → get token from an already-running process
DuplicateToken()              → clone a token for your own use
SetThreadToken()              → apply the token to your thread
```

**Token elevation (UAC bypass):**
```
Your process runs at medium integrity as a local admin.
A UAC bypass tricks a trusted auto-elevating process to run your code.
That process runs at high integrity.
You steal its high-integrity token.
Your subsequent actions use the high-integrity token.
```

**Token creation via credentials:**
```
LogonUser(username, domain, password, ..., &token)
→ If credentials are valid, Windows creates a new token for that user
→ You now have a token you can use without that user being logged in
→ CreateProcessWithTokenW(token, ...) → process runs as that user

This is how PsExec works under the hood.
```

**🧠 LOCK IT IN**

A token is your wallet. It contains your ID (user SID), your membership cards for various clubs (group SIDs), and special passes to certain venues (privileges). When you try to do something, the bouncer (Windows access check) looks through your wallet rather than checking you yourself. If you steal someone else's wallet (token impersonation), you get past every bouncer they could. The bouncer never checks if the wallet actually belongs to you.

---

## SECTION 7 — Privileges: Special Capabilities Beyond Normal Access

**🔷 WHAT**

Privileges are special permissions that override normal object-level access checks. While ACLs on objects (files, registry keys) control *what you can access*, privileges control *what special things you are allowed to do* — things that go beyond normal object access.

Privileges are stored in the access token. Each privilege has two states: **Enabled** or **Disabled**. Having a privilege assigned does not mean it is active — a process must explicitly enable it with `AdjustTokenPrivileges` before it takes effect (with some exceptions).

**The privileges that matter for red teaming:**

```
┌──────────────────────────────────────────────────────────────────────────┐
│ PRIVILEGE                    │ WHAT IT ALLOWS                            │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SeDebugPrivilege             │ Open any process with any access rights,  │
│                              │ regardless of that process's own ACL.     │
│                              │ → Read LSASS memory directly.             │
│                              │ Who has it: Administrators (when enabled) │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SeImpersonatePrivilege       │ Impersonate any client that authenticates │
│                              │ to this process.                          │
│                              │ → Potato attacks → SYSTEM                 │
│                              │ Who: IIS, MSSQL, service accounts, Network│
│                              │ Service, Local Service                    │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SeAssignPrimaryTokenPrivilege│ Replace the primary token of a process.   │
│                              │ → Create processes as arbitrary users     │
│                              │ Who: Local Service, Network Service       │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SeBackupPrivilege            │ Read any file regardless of file ACL.     │
│                              │ → Read SAM, NTDS.dit, any file on system  │
│                              │ Who: Backup Operators group               │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SeRestorePrivilege           │ Write any file regardless of file ACL.    │
│                              │ → Replace service binaries, plant DLLs    │
│                              │ Who: Backup Operators group               │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SeTakeOwnershipPrivilege     │ Take ownership of any object regardless   │
│                              │ of permissions on the object.             │
│                              │ → Take ownership → grant yourself access  │
│                              │ Who: Administrators                       │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SeLoadDriverPrivilege        │ Load a kernel-mode driver.                │
│                              │ → Load malicious driver → kernel access   │
│                              │ → Disable PPL on LSASS from kernel        │
│                              │ Who: Administrators                       │
├──────────────────────────────┼───────────────────────────────────────────┤
│ SeTcbPrivilege               │ Act as part of the operating system.      │
│                              │ → Create tokens for any user              │
│                              │ Who: SYSTEM only                          │
└──────────────────────────────┴───────────────────────────────────────────┘
```

**🔶 WHY**

Certain operations are so powerful they should not be controlled by object-level ACLs alone. Reading any file on the system to do a backup should not require granting read access to every file — it is a categorical exception. `SeBackupPrivilege` provides that exception in a controlled way.

The same logic applies to `SeDebugPrivilege` — a developer needs to debug any process on the system, including protected OS processes. The privilege enables that without permanently lowering every process's security.

**⚔️ HOW**

**`SeImpersonatePrivilege` → SYSTEM is the most reliable exam path:**

```
Why IIS, MSSQL, and service accounts have SeImpersonatePrivilege:
  Services that authenticate clients need to temporarily act as those clients.
  IIS impersonates the user making the web request.
  MSSQL impersonates the user running a query.
  This requires SeImpersonatePrivilege.

  Consequence: any compromised service account running IIS or MSSQL
               has SeImpersonatePrivilege → Potato attack → SYSTEM.

The Potato attack mechanism (simplified):
  1. Your process creates a fake COM server / named pipe
  2. Triggers the OS (SYSTEM) to call into your fake server
     (via DCOM activation, EFS RPC, print spooler, etc.)
  3. SYSTEM connects → creates an impersonation token for SYSTEM
  4. ImpersonateNamedPipeClient() or CoImpersonateClient() → steal the token
  5. CreateProcessWithToken(SYSTEM_token, ...) → spawn cmd.exe as SYSTEM
```

**`SeDebugPrivilege` → LSASS read:**

```
Most LSASS dumping techniques need SeDebugPrivilege to call:
  OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, lsass_pid)

This is why you need SYSTEM (or admin with UAC bypassed) before dumping.
SYSTEM always has SeDebugPrivilege enabled.
Admin has it assigned but it may be disabled (medium integrity) or
  enabled (high integrity, after UAC bypass).
```

**Checking privileges in practice:**

```cmd
whoami /priv

Output:
Privilege Name                Description                          State
============================= ==================================== ========
SeDebugPrivilege              Debug programs                       Disabled
SeImpersonatePrivilege        Impersonate a client after auth      Enabled   ← POTATO
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled

Analysis:
  SeImpersonatePrivilege Enabled → GodPotato → SYSTEM
  SeDebugPrivilege Disabled → need to enable it (requires admin)
                            → or escalate to SYSTEM who has it enabled
```

**🧠 LOCK IT IN**

Privileges are VIP passes at a venue. Having the VIP pass (privilege assigned) does not mean you are in the VIP area — you have to present it at the door (enable it with `AdjustTokenPrivileges`). Some passes are automatically active when you enter (SeImpersonatePrivilege is always enabled for service accounts). Others you have to consciously activate (SeDebugPrivilege for administrators — a deliberate choice to reduce attack surface).

`SeImpersonatePrivilege` for service accounts is like giving every hotel concierge a master key so they can access any room on behalf of a guest. A concierge who gets compromised — suddenly the attacker has the master key.

---

## SECTION 8 — Integrity Levels: The Hidden Security Layer

**🔷 WHAT**

Windows Vista introduced **Mandatory Integrity Control** — a security layer that sits *above* normal ACL checks. Every process, file, registry key, and named object has an integrity level. A process can only write to objects at the same or lower integrity level than itself.

The four levels:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     INTEGRITY LEVELS                                │
│                                                                     │
│   SYSTEM (S-1-16-16384)   ← SYSTEM processes. ntoskrnl, lsass.exe │
│         ↑                                                           │
│   HIGH   (S-1-16-12288)   ← Elevated (admin) processes.            │
│         ↑                   After UAC elevation prompt accepted.    │
│   MEDIUM (S-1-16-8192)    ← Normal user processes. Default level.  │
│         ↑                   Your cmd.exe, browser, most things.     │
│   LOW    (S-1-16-4096)    ← Sandboxed processes. IE Enhanced       │
│                             Protected Mode. Renderer processes.     │
└─────────────────────────────────────────────────────────────────────┘
```

**The rule**: a medium-integrity process cannot write to a high-integrity process's memory, files marked for high integrity, or high-integrity registry keys — even if the user is an administrator.

**🔶 WHY**

Integrity levels exist because of drive-by malware. Suppose a malicious website exploits a browser vulnerability and gets code execution inside the browser process. Before integrity levels, that code ran with the same rights as the user — if the user was an admin, the malware was an admin.

With integrity levels, the browser renderer runs at LOW integrity. Exploiting it gives you low-integrity code execution. You cannot write to most files, cannot modify registry keys, cannot inject into higher-integrity processes. The damage is contained.

**⚔️ HOW**

**UAC is entirely built on integrity levels:**

```
You log in as a local administrator.
Windows creates TWO tokens for you:
  1. A filtered (medium integrity) token → used for all normal operations
  2. A full (high integrity) token → only used when UAC elevation is accepted

When you open cmd.exe normally: medium integrity token used
  → You CANNOT write to HKLM, cannot access other users' files
  → Even though you ARE an administrator

When you accept a UAC prompt: high integrity token used
  → Full admin access

This is why you can be "admin" and still get Access Denied.
```

**UAC bypass = getting high integrity without a UAC prompt:**

```
FodHelper bypass:
  fodhelper.exe is a Microsoft binary with autoElevate=true in its manifest
  → Windows trusts it to run elevated without showing a UAC prompt
  → fodhelper reads a registry key in HKCU before starting (user-writable)
  → Write your payload's path to that registry key
  → fodhelper runs your payload at HIGH INTEGRITY — no UAC prompt shown

The entire bypass exploits the autoElevate trust without defeating it:
  "I'm not going around UAC, I'm finding a trusted auto-elevating
   process and making it run my code instead of its intended code."
```

**Check your integrity level before doing anything sensitive:**

```cmd
whoami /groups | findstr "Mandatory Label"
Output:
  Mandatory Label\Medium Mandatory Level  Label S-1-16-8192

Interpretation: medium integrity — UAC applies even though you are admin
                LSASS dump will fail (SeDebugPrivilege not enabled)
                UAC bypass needed first → elevate to high → then dump
```

**🧠 LOCK IT IN**

Integrity levels are security clearance levels in a government building. A medium-clearance worker cannot access top-secret documents even if their boss (the token) says they have admin rights — there is a separate clearance system that overrides that. UAC bypass is not breaking into the vault. It is finding a senior official (autoElevate process) who can access the vault and tricking them into opening it for you.

---

## SECTION 9 — The Windows Registry: Persistence and Configuration

**🔷 WHAT**

The Windows Registry is a hierarchical database built into Windows that stores configuration for the OS, device drivers, services, and applications. It is organised as a tree of **keys** (like folders) containing **values** (like files with data).

The top-level keys are called **hives**. The critical ones for red teamers:

```
HKEY_LOCAL_MACHINE (HKLM) — machine-wide settings
│
├── HKLM\SYSTEM\CurrentControlSet\Services\
│   └── Configuration for every Windows service (binary path, start type, logon account)
│
├── HKLM\SAM\
│   └── Local account password hashes — LOCKED while Windows runs
│
├── HKLM\SECURITY\
│   └── LSA secrets — service account credentials, domain cache
│
├── HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
│   └── AutoAdminLogon, DefaultUserName, DefaultPassword — autologon creds
│
└── HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\
    └── ScriptBlockLogging, ModuleLogging settings

HKEY_CURRENT_USER (HKCU) — per-user settings, writable by the current user
│
├── HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
│   └── Programs that start at user logon — persistence location
│
├── HKCU\Software\Classes\
│   └── COM object registrations — UAC bypass target (HKCU is user-writable)
│
└── HKCU\Software\...
    └── Application settings, recently used files, saved credentials
```

**🔶 WHY**

Windows needed a centralised, structured place to store configuration. Before the registry, INI files (text files like `win.ini`, `system.ini`) held configuration. They were fragmented, unorganised, and had no access control. The registry replaced them with a unified, hierarchical, permission-controlled database.

The registry is also **transactional** — changes can be committed or rolled back atomically. This is why driver installation and Windows Update work reliably.

**⚔️ HOW**

**The registry is the most common persistence location:**

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  → Values here run at system startup for ALL users (requires admin to write)
  → Detection: standard baseline monitoring, Sysmon Event 13 (registry set)

HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  → Values here run at logon for the CURRENT user (writable by current user)
  → Detection: less monitored, but still Sysmon Event 13

HKLM\SYSTEM\CurrentControlSet\Services\<service_name>
  → The ImagePath value is the binary the service runs
  → Modify it → service starts your binary on next service start
  → Detection: service modification events, file write events
```

**Registry-based persistence that survives reboots:**

```
# Add a Run key for current user (no admin needed)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
    /v "WindowsUpdate" /t REG_SZ /d "C:\Windows\Temp\beacon.exe" /f

# Why this works:
# Every time this user logs in, Windows reads this key and executes all values
# "WindowsUpdate" is a plausible-looking value name
# The beacon restarts automatically even if terminated
```

**Registry stores credentials in cleartext in some configurations:**

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  AutoAdminLogon: 1
  DefaultUserName: Administrator
  DefaultPassword: SuperSecret123!   ← cleartext password for autologon

HKLM\SYSTEM\CurrentControlSet\Services\<service>\Parameters
  Sometimes stores passwords for services that need to authenticate elsewhere

HKCU\Software\ORL\WinVNC3\Password → VNC password (obfuscated, easily recovered)
HKCU\Software\TightVNC\Server → TightVNC password
HKCU\Software\SimonTatham\PuTTY\Sessions → SSH connection details
```

**The SAM and SECURITY hives store password hashes:**

```
HKLM\SAM → local account NTLM hashes (locked, requires SYSTEM)
HKLM\SECURITY → LSA secrets (service account creds, domain cache, locked)

To extract:
  reg save HKLM\SAM C:\Temp\sam.save
  reg save HKLM\SYSTEM C:\Temp\system.save
  reg save HKLM\SECURITY C:\Temp\security.save
  # Must be SYSTEM to save SAM and SECURITY hives
  # Transfer to Kali → secretsdump -sam sam.save -system system.save LOCAL
```

**🧠 LOCK IT IN**

The registry is a massive, organised filing cabinet built into Windows. Some drawers are locked to everyone except the OS (SAM, SECURITY hives). Some drawers belong to the machine and require admin keys (HKLM). Some drawers belong to you and you can write to them freely (HKCU). Persistence via registry is leaving a sticky note on Windows' to-do list — "run this program when I start up." Windows reads the list faithfully every boot, never questioning whether the item belongs there.

---

## SECTION 10 — Services and the Service Control Manager

**🔷 WHAT**

A Windows service is a long-running background process managed by the **Service Control Manager (SCM)** — a core Windows component (`services.exe`) that is responsible for starting, stopping, and monitoring services.

Services are configured in the registry at `HKLM\SYSTEM\CurrentControlSet\Services\<service_name>`. Each service entry has:

```
HKLM\SYSTEM\CurrentControlSet\Services\Spooler\
  ImagePath:    C:\Windows\System32\spoolsv.exe    ← the binary that runs
  Start:        2                                   ← 2=Auto, 3=Manual, 4=Disabled
  ObjectName:   LocalSystem                         ← runs as this account
  Type:         16                                  ← 16=Win32OwnProcess
  DisplayName:  Print Spooler
  Description:  Loads files to memory for later printing
```

Services start automatically at boot (if configured as Auto), run without a logged-in user, and survive user logoffs. They are the backbone of Windows background functionality.

**🔶 WHY**

Services exist because many critical functions must run regardless of whether anyone is logged in. Antivirus must scan files even before login. Network services must accept connections. The print spooler must queue jobs. None of these can wait for a user to open a window.

Services also run as specific accounts rather than inheriting a user's identity. A web server service runs as a limited "Network Service" account rather than as the logged-in admin — reducing the blast radius if the service is compromised.

**⚔️ HOW**

Services are the most common privilege escalation surface on Windows machines. Three distinct paths:

**Path 1: Weak binary permissions**
```
The service binary (ImagePath) is writable by a low-privileged account.
→ Replace the binary with your payload
→ Stop and start the service (or wait for reboot)
→ Your payload runs as the service's account (often SYSTEM or LocalService)

Detection:
  icacls "C:\path\to\service.exe"
  → Look for: BUILTIN\Users:(F), Everyone:(W), DOMAIN\Users:(M)
  → F=FullControl, W=Write, M=Modify — all exploitable
```

**Path 2: Unquoted service path**
```
ImagePath: C:\Program Files\My Application\service.exe   (NO QUOTES)

Windows tokenises the path at spaces and tries each combination:
  Attempt 1: C:\Program.exe                           ← tries this first
  Attempt 2: C:\Program Files\My.exe                  ← tries this second
  Attempt 3: C:\Program Files\My Application\service.exe ← actual file

If you can create C:\Program.exe or C:\Program Files\My.exe:
  Windows executes your file as the service's identity (SYSTEM)

Why this happens:
  The ImagePath value lacks quotes. If the path has spaces, Windows
  cannot tell where the executable name ends and arguments begin.
  The tokenisation vulnerability is decades old and still common.
```

**Path 3: Weak service object ACL**
```
The SERVICE OBJECT ITSELF (not the binary) has weak permissions.
→ You have SERVICE_CHANGE_CONFIG on the service object
→ sc config <service> binpath= "C:\Windows\Temp\beacon.exe"
→ sc stop <service> && sc start <service>
→ Your binary runs as the service's account

Detection:
  accesschk.exe -uwcqv "Domain Users" * /accepteula
  → Lists services where Domain Users have SERVICE_CHANGE_CONFIG
```

**Services as initial access:**
```
If a service is accessible over the network and has a known vulnerability:
  Print Spooler (Port 135/SMB): PrintNightmare (CVE-2021-1675) — remote code execution as SYSTEM
  RDP service: BlueKeep, EternalBlue (if unpatched)
  WinRM service: If credentials valid → evil-winrm → shell
  MSSQL service: If xp_cmdshell available → OS command execution
```

**🧠 LOCK IT IN**

Services are automated factory machines running 24/7 even when the factory is closed. Each machine has a maintenance manual stored in a cabinet (registry). If you can swap out the machine's core component (binary replacement), change what the machine does according to the manual (config change), or exploit the fact that the manual's directions are ambiguous (unquoted path), you control what the machine produces — and it runs with the factory's master key (SYSTEM account), not just the maintenance worker's badge.

---

## SECTION 11 — The Windows API Layers: From Win32 to Syscalls

**🔷 WHAT**

When your code needs the OS to do something — create a process, allocate memory, read a file — it calls a function. But there are multiple layers of functions between your code and the actual kernel:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      YOUR CODE                                      │
│            CreateProcess("notepad.exe", ...)                        │
└───────────────────────────┬─────────────────────────────────────────┘
                            ↓
┌───────────────────────────────────────────────────────────────────┐
│                   WIN32 API (kernel32.dll)                        │
│     High-level, easy-to-use functions. CreateProcess, ReadFile,   │
│     OpenProcess, CreateThread, etc.                               │
│     This layer does validation, parameter conversion, logging.    │
└───────────────────────────┬───────────────────────────────────────┘
                            ↓
┌───────────────────────────────────────────────────────────────────┐
│                    NATIVE API (ntdll.dll)                         │
│     Lower-level functions prefixed with Nt or Zw.                │
│     NtCreateProcess, NtReadVirtualMemory, NtAllocateVirtualMemory │
│     This is the LAST STOP before the kernel.                      │
│     ← EDRs hook functions here to intercept API calls            │
└───────────────────────────┬───────────────────────────────────────┘
                            ↓
┌───────────────────────────────────────────────────────────────────┐
│                    SYSTEM CALL (SYSCALL)                          │
│     The CPU switches from user mode to kernel mode.               │
│     A specific kernel function runs (e.g., NtCreateProcess in     │
│     ntoskrnl.exe).                                               │
│     This is the actual boundary crossing.                         │
└───────────────────────────────────────────────────────────────────┘
```

**🔶 WHY**

The layered API exists for several reasons:
- **Compatibility**: Win32 API provides a stable interface. Microsoft can change the underlying implementation without breaking applications.
- **Abstraction**: High-level functions (CreateProcess) hide dozens of lower-level operations. Developers work with simple functions.
- **Control points**: Each layer can perform validation, logging, or security checks.

**⚔️ HOW**

**EDR hooks live in ntdll.dll — and that is why userland unhooking works:**

```
When an EDR loads its agent into your process:
  It modifies the first bytes of key ntdll.dll functions (NtOpenProcess,
  NtWriteVirtualMemory, etc.)
  The modification is a JMP instruction → jumps to the EDR's own code
  The EDR examines the call, logs it, decides allow/block, then
  (if allowing) jumps back to continue the original function.

This is why these functions are called "hooked."

Userland unhooking removes the hooks by overwriting the modified bytes
with the original clean bytes from a fresh copy of ntdll.dll from disk.

Fresh copy loading:
  1. Open C:\Windows\System32\ntdll.dll (the file on disk — not in-memory)
  2. Map it into memory
  3. Copy the .text section (where code lives) over the hooked in-memory version
  4. EDR's JMP patches are now overwritten with original code
  5. All subsequent API calls go directly to the kernel without EDR interception
```

**Direct syscalls bypass ntdll.dll entirely:**

```
Normal call: your code → Win32 (kernel32.dll) → Native API (ntdll.dll) → SYSCALL
Direct syscall: your code → SYSCALL immediately

For a direct syscall, your code:
1. Puts the syscall number in the EAX register
   (syscall numbers are assigned by Windows version — not stable)
2. Sets up arguments in the correct registers
3. Executes the SYSCALL instruction directly

No ntdll.dll involved → no EDR hooks possible in userland
EDR cannot see the call unless it has a kernel driver watching for syscalls
```

**Indirect syscalls are even stealthier:**

```
EDRs can detect direct syscalls by watching for SYSCALL instructions
  in non-ntdll memory (your code should not be calling SYSCALL directly).

Indirect syscall: instead of executing SYSCALL in your code,
  jump to the SYSCALL instruction inside ntdll.dll itself,
  but with your own arguments.

Your code → (JMP to ntdll SYSCALL instruction) → kernel
  The SYSCALL is now executed FROM ntdll's address space
  EDR sees syscall from ntdll — looks legitimate
  EDR cannot inspect the arguments without kernel-level hook
```

**🧠 LOCK IT IN**

The API layers are like a government bureaucracy. You submit a request form (Win32 API). It goes to an intermediate department (ntdll.dll) that checks it and forwards it to the federal agency (kernel). EDRs are inspectors sitting in the intermediate department reading every form before it goes forward. Direct syscalls are bypassing the intermediate department entirely and going straight to the federal agency with your request. Indirect syscalls are using the intermediate department's internal mail room to forward your request, so the inspector only sees a request from the mail room — legitimate-looking.

---

## SECTION 12 — DLLs: Shared Code and the Injection Surface

**🔷 WHAT**

A **DLL** (Dynamic Link Library) is a compiled library of code that multiple processes can use simultaneously. Instead of each process having its own copy of common code (like networking functions, UI components, cryptography), they all reference the same DLL loaded into memory once.

When a process starts, Windows loads all the DLLs it depends on into the process's virtual address space. This happens automatically based on the Import Table in the executable — a list of every DLL and function the program needs.

```
notepad.exe starts:
  Windows reads Import Table:
    Imports from: kernel32.dll, ntdll.dll, user32.dll, gdi32.dll, ...
  Windows maps each DLL into notepad's address space:
    ntdll.dll      at 0x00007FF9A8000000
    kernel32.dll   at 0x00007FF9A5000000
    user32.dll     at 0x00007FF9A4000000
    amsi.dll       at 0x00007FF9A2000000   ← loaded because PS loads AMSI
    edrhook.dll    at 0x00007FF9A1000000   ← EDR injected this
```

**🔶 WHY**

DLLs exist to avoid duplicating code. If every process had its own copy of the Windows API functions, RAM would be wasted and updates would require recompiling every program. DLLs let Microsoft update `kernel32.dll` once and every application benefits immediately on the next run.

**⚔️ HOW**

**DLL injection is the basis of process injection:**

```
Method 1: LoadLibrary injection
  WriteProcessMemory → write DLL path string into target process
  CreateRemoteThread → start thread in target that calls LoadLibrary(your_dll_path)
  → Windows loads your DLL into the target process
  → Your DllMain() code executes inside the target

Method 2: Reflective DLL injection (stealthier)
  DLL contains its own loader — a function that maps the DLL into memory
  without calling Windows' LoadLibrary (which is logged and hookable)
  → No disk file needed — DLL bytes can come from a network download
  → No LoadLibrary call — EDR hooks on LoadLibrary don't fire

Method 3: DLL hijacking (persistence and initial access)
  Applications load DLLs from predictable locations.
  If a DLL does not exist in the application's directory, Windows
  searches: app directory → current directory → System32 → Windows → PATH
  
  If the app tries to load "missing_dll.dll" from its directory,
  and you can write to that directory:
  → Drop your malicious "missing_dll.dll" there
  → App starts and loads your DLL automatically
  → Your code runs in the context of the application
```

**DLL search order hijacking — the practical attack:**

```
Find: an application that loads a DLL that does not exist
Tool: Process Monitor (Procmon) with filter:
  Operation = CreateFile AND Path ends with .dll AND Result = NAME NOT FOUND

Example finding:
  "VulnApp.exe attempts to load 'missing.dll' from C:\Program Files\VulnApp\"
  "C:\Program Files\VulnApp\" is writable by current user"

Exploit:
  Drop malicious missing.dll in C:\Program Files\VulnApp\
  Next time VulnApp starts → loads your DLL → code executes as VulnApp's identity
```

**🧠 LOCK IT IN**

DLLs are like shared toolboxes in a workshop. Instead of every worker (process) having their own copy of every tool (code), they all borrow from shared toolboxes mounted on the wall (DLLs mapped into their address space). DLL injection is sneaking a tampered tool into the shared toolbox — when any worker reaches in and picks up that tool, they are using your modified version and do not notice. DLL hijacking is leaving a fake toolbox labelled with the same name as one the worker expects to find — they grab from yours instead of the real one.

---

## SECTION 13 — Named Pipes: The Potato Attack Foundation

**🔷 WHAT**

A named pipe is an inter-process communication (IPC) mechanism — a way for two processes to exchange data, even if they are running as different users. Named pipes appear as filesystem objects with paths like `\\.\pipe\mypipe`.

A **pipe server** creates the pipe and waits for connections. A **pipe client** connects to the pipe and sends/receives data.

```
Pipe server (your code):                Pipe client (could be SYSTEM):
  CreateNamedPipe("\\.\pipe\mypipe")
  ConnectNamedPipe() — wait for client
                          ←─────────── calls CreateFile("\\.\pipe\mypipe")
  Read/Write data         ←─────────── sends data
  ImpersonateNamedPipeClient() 
  → Windows gives you a SYSTEM impersonation token
  CreateProcessWithToken(SYSTEM_token)
```

**🔶 WHY**

Named pipes exist so services can communicate with each other and with client applications without using the network. A print server communicates with print clients via named pipes. Security subsystems communicate through named pipes. They are a standard, documented IPC mechanism.

The key design: when a client connects to a pipe, the server can *impersonate the client* — temporarily take on the client's identity. This is intentional and legitimate (a server needs to access resources on behalf of the client). `SeImpersonatePrivilege` authorises a process to do this impersonation.

**⚔️ HOW**

**Potato attacks exploit this mechanism:**

```
1. Your low-priv service process (has SeImpersonatePrivilege) creates a named pipe.

2. You trigger a mechanism that causes a SYSTEM-level process to connect to your pipe.
   This is the "coercion" step — different Potato variants use different coercion:
   
   JuicyPotato / RottenPotato: DCOM activation causes COM server (SYSTEM) to connect
   PrintSpoofer: abuses Print Spooler service's named pipe
   GodPotato: abuses EfsRpc (Encrypting File System RPC) → causes LSASS to connect
   SweetPotato: combines token stealing with DCOM activation

3. The SYSTEM process connects to your named pipe.
   Windows creates an impersonation token representing SYSTEM for this connection.

4. Your code calls ImpersonateNamedPipeClient().
   → You now have SYSTEM's impersonation token.

5. DuplicateTokenEx() → convert impersonation token to primary token.
   CreateProcessWithTokenW(primary_SYSTEM_token, ..., "cmd.exe")
   → A new cmd.exe runs as SYSTEM.

Why SeImpersonatePrivilege is the required privilege:
  ImpersonateNamedPipeClient requires SeImpersonatePrivilege.
  Without it, the impersonation call fails.
  With it, any connection from any user (including SYSTEM) can be impersonated.
```

**🧠 LOCK IT IN**

A named pipe is a drive-through window between processes. Your process opens the window (creates the pipe server). A higher-privileged process comes to the window (connects as a client). At that moment, because you are behind the window, you can legally wear the customer's jacket (impersonate their token) — you have permission to take their order under their name. The Potato attacks engineer which VIP customer shows up at your window.

---

## SECTION 14 — LSASS: Where Credentials Live

**🔷 WHAT**

**LSASS** (Local Security Authority Subsystem Service) is the Windows process responsible for authenticating users and enforcing security policy. Every time a user enters a password — at the lock screen, for a network share, for a web proxy — LSASS validates it.

Because LSASS handles authentication, it must maintain session keys and credentials in memory throughout each logon session. What it holds:

```
For each logged-on user:
  ├── NTLM hash         — the stored hash of their password
  ├── Kerberos TGT      — their current Ticket Granting Ticket
  ├── Kerberos session keys — AES128 and AES256 keys
  ├── Cached credentials  — encrypted domain password for offline logon
  └── Cleartext password  — ONLY if WDigest is enabled (disabled since Win 8.1)
```

The LSASS process (`lsass.exe`) runs as SYSTEM with special protection (PPL — Protected Process Light on modern Windows). Its PID is typically small (< 1000) and it appears in every running process list.

**🔶 WHY**

Windows uses several authentication protocols simultaneously (NTLM, Kerberos, CredSSP, etc.). For single sign-on to work — you log in once and access multiple resources without re-entering your password — LSASS must cache your credentials for the duration of your session.

If LSASS had to challenge you with your password for every file access, every printer use, every network resource, the experience would be unusable. The credential cache is a deliberate design decision that prioritises usability.

**⚔️ HOW**

**LSASS is the single highest-value target on any Windows machine:**

```
If you can read LSASS memory → you can extract:
  Every user's NTLM hash → Pass-the-Hash to any machine they have access to
  Domain user Kerberos TGT → Pass-the-Ticket as that user
  Service account credentials → access to the services they run
  If a DA is logged in → their hash → full domain compromise

Requirements to dump LSASS:
  SYSTEM or admin with SeDebugPrivilege (and UAC bypassed if medium integrity)

Methods ranked by stealth:
  Most visible: Mimikatz sekurlsa::logonpasswords — every EDR triggers
  Medium: comsvcs.dll MiniDump — uses signed MS binary, but still caught
  Stealthier: nanodump — forks the process, avoids OpenProcess on LSASS directly
  Stealthiest: handle duplication — reuse existing handle to LSASS from another process
```

**PPL (Protected Process Light) — the modern defense:**

```
Windows 8.1+ can mark LSASS as a Protected Process Light.
PPL processes cannot be opened with PROCESS_VM_READ by any non-PPL process,
  even SYSTEM.
  
Impact: Mimikatz, nanodump, and most standard dump techniques fail.

Bypass options:
  1. PPLBlade — uses a vulnerable driver to strip PPL protection from kernel level
  2. MimiDrivers — kernel-mode Mimikatz component
  3. Handle duplication from another PPL process that already has access
  4. BYOVD — Bring Your Own Vulnerable Driver → kernel access → strip PPL
```

**🧠 LOCK IT IN**

LSASS is a hotel concierge who holds the master key for every guest currently checked in. They need the keys to help guests access their rooms (authentication). If you can read the concierge's keyring (dump LSASS memory), you have a copy of every key for every currently checked-in guest. PPL is a bulletproof booth around the concierge — you can see them but you cannot reach in. Bypassing PPL is finding a vulnerability in the booth itself (the driver that enforces protection).

---

## SECTION 15 — The PE Format: What Executables Look Like Inside

**🔷 WHAT**

Every Windows executable (`.exe`, `.dll`) follows the **Portable Executable (PE)** format — a standardised structure that Windows' loader reads to understand how to set up the process. The PE format has evolved since the early 1990s but the core structure remains.

```
┌──────────────────────────────────────────────────────────┐
│  DOS Header                  ← "MZ" magic bytes (0x4D5A) │
│  (Compatibility stub)        ← "This program cannot..."  │
├──────────────────────────────────────────────────────────┤
│  PE Signature                ← "PE\0\0" (0x50450000)     │
├──────────────────────────────────────────────────────────┤
│  COFF File Header            ← Architecture, section count│
├──────────────────────────────────────────────────────────┤
│  Optional Header             ← Entry point, image base,  │
│                              ← subsystem, DLL flags       │
├──────────────────────────────────────────────────────────┤
│  Section Headers             ← Describes each section:   │
│                              ← name, size, permissions    │
├──────────────────────────────────────────────────────────┤
│  .text section               ← Executable code (RX)      │
├──────────────────────────────────────────────────────────┤
│  .data section               ← Initialized data (RW)     │
├──────────────────────────────────────────────────────────┤
│  .rdata section              ← Read-only data, strings   │
│                              ← Import Table is here       │
├──────────────────────────────────────────────────────────┤
│  Import Table                ← Every DLL and function     │
│                              ← this file needs            │
├──────────────────────────────────────────────────────────┤
│  Export Table (DLLs only)    ← Functions this DLL offers │
└──────────────────────────────────────────────────────────┘
```

**🔶 WHY**

Windows needs to know how to set up a process before the code even starts running. The PE format tells the loader:
- Where the entry point is (what instruction to execute first)
- What memory permissions each region needs (code is RX, data is RW)
- Which DLLs to load and which functions from each DLL to resolve
- Where to load the image in memory (preferred base address)

**⚔️ HOW**

**Signatures target PE structure:**

```
Static AV signatures often match:
  1. The "MZ" header + specific bytes at known offsets
  2. Strings in the .rdata section (function names, error messages, known tool strings)
  3. Import Table patterns (specific DLL + function combinations that only malware uses)
  4. Entry point code patterns

ThreatCheck works by finding which specific bytes in the PE are signatured.
Fixing them: rename strings, remove unused exports, change error messages.
```

**Donut defeats PE-based detection by eliminating the PE format:**

```
Donut converts a PE to shellcode:
  → Shellcode has no MZ header, no section table, no Import Table in the normal sense
  → The Donut-generated shellcode contains a mini-loader that handles the mapping
  → AV's PE parser cannot parse shellcode using PE rules
  → Shellcode-specific signatures must match instead (different detection path)
```

**Reflective DLL injection avoids the Windows loader:**

```
Standard DLL load:
  LoadLibrary("evil.dll") → Windows loader reads PE → maps sections → resolves imports
  Visible in module list, hookable via LoadLibrary hook

Reflective DLL load:
  The DLL contains its own loader function (ReflectiveDLLInject())
  This function maps the DLL's sections into memory manually
  Resolves its own imports by walking the Process Environment Block (PEB)
  No LoadLibrary call → no hook triggered → does not appear normally in module list
```

**🧠 LOCK IT IN**

The PE format is like a building's blueprint stapled to the front door. The construction crew (Windows loader) reads the blueprint to know where to put the walls (map sections), what utilities to connect (load DLLs), and where the main entrance is (entry point). AV is an inspector who memorises the appearance of blueprints from known bad buildings. Shellcode has no blueprint — it is raw material with no label. Reflective DLLs have a hidden extension to the blueprint that tells the structure how to build itself without calling the official construction crew.

---

## SECTION 16 — EDR Hooks: How Defenders See Into Your Process

**🔷 WHAT**

An EDR (Endpoint Detection and Response) agent typically injects a DLL into every process running on the machine. This DLL modifies the code of key functions in `ntdll.dll` and other Windows DLLs to redirect execution through the EDR's analysis code before the real function runs.

This modification is called a **hook**, and the modified function is a **hooked function**.

```
Before EDR hooks ntdll.dll in your process:
  NtOpenProcess:
    4C 8B D1     MOV R10, RCX     ← real function start
    B8 26 00 00  MOV EAX, 0x26    ← syscall number
    0F 05        SYSCALL           ← go to kernel
    C3           RET

After EDR injects hook:
  NtOpenProcess:
    E9 AB CD EF  JMP 0x7FF...A0000  ← JUMPS TO EDR DLL
    00 00
    ...
  
  At 0x7FF...A0000 (EDR's DLL):
    [EDR logs: NtOpenProcess called, target PID=X, access=Y]
    [EDR checks: is this suspicious?]
    [If allowed: jumps back to continue real NtOpenProcess]
    [If blocked: returns ACCESS_DENIED without calling the kernel]
```

**🔶 WHY**

EDRs hook functions because they need visibility into what processes are doing. The OS does not expose a built-in mechanism to intercept every API call in every process. Hooks are the practical solution — inject code that runs before every sensitive API call, log it, and block it if suspicious.

**⚔️ HOW**

**Userland unhooking removes the JMP redirections:**

```
Theory: EDR modified ntdll.dll bytes in YOUR process's memory.
        ntdll.dll on DISK is still clean (EDR cannot modify a system file).

Attack:
  1. Open the ntdll.dll file on disk: CreateFile("C:\Windows\System32\ntdll.dll")
  2. Map the file into memory: CreateFileMapping + MapViewOfFile
  3. Find the .text section in the disk version (clean, unhooked code)
  4. Overwrite the .text section in the in-memory version (hooked)
     with the bytes from the disk version
  5. The JMP redirections are now gone — replaced with original code
  6. All subsequent API calls go directly to kernel, bypassing EDR
```

**ETW-based detection still works even after unhooking:**

```
Userland unhooking removes userland API hooks.
But the .NET CLR and other components emit ETW events regardless of hooks.
Loading SharpHound via Assembly.Load emits an ETW event even if ntdll is unhooked.
→ ETW must be patched separately (Phase 04 covers this)

Modern EDRs use multiple detection layers:
  - API hooks (userland, bypassable via unhooking)
  - ETW subscriptions (.NET, PowerShell, process events)
  - Kernel callbacks (PPL-level, not bypassable from userland)
  - Cloud-based behavioral analysis (sees the aggregate pattern over time)

Bypassing one layer does not mean bypassing all layers.
```

**🧠 LOCK IT IN**

EDR hooks are like a post office interceptor who opens every letter that passes through, reads it, and either reseals and forwards it or returns it to sender. Userland unhooking is bribing the post office to use the original unstamped delivery route — bypassing the interceptor entirely. But there are also security cameras (ETW) and building access logs (kernel callbacks) that the interceptor does not control. Bypassing the interceptor does not make you invisible to everything.

---

## SECTION 17 — Credential Storage: The Full Map

**🔷 WHAT**

Windows stores credentials in multiple locations, each with different access requirements, each holding different types of credentials:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  LOCATION              │ CONTENTS                    │ ACCESS REQUIRED   │
├──────────────────────────────────────────────────────────────────────────┤
│  LSASS (memory)        │ NTLM hashes, Kerberos TGTs  │ SYSTEM            │
│                        │ AES keys, sometimes cleartext│ (SeDebugPriv)     │
├──────────────────────────────────────────────────────────────────────────┤
│  SAM hive              │ Local account NTLM hashes   │ SYSTEM            │
│  (registry, on disk)   │                             │                   │
├──────────────────────────────────────────────────────────────────────────┤
│  SECURITY hive         │ LSA secrets:                │ SYSTEM            │
│  (registry, on disk)   │ - Service account passwords │                   │
│                        │ - Domain cached credentials │                   │
│                        │ - NL$KM key for DCC2 hashes │                   │
├──────────────────────────────────────────────────────────────────────────┤
│  NTDS.dit              │ ALL domain account hashes   │ DC local admin    │
│  (AD database on DC)   │ krbtgt hash, all users      │ or DCSync rights  │
├──────────────────────────────────────────────────────────────────────────┤
│  DPAPI                 │ Browser passwords, cred mgr │ User context      │
│  (user's profile)      │ WiFi keys, certificates     │ or domain backup  │
│                        │                             │ key (DA)          │
├──────────────────────────────────────────────────────────────────────────┤
│  Credential Manager    │ Saved network passwords      │ User context      │
│  (%APPDATA%\Cred.)     │ Web credentials, RDP         │                   │
├──────────────────────────────────────────────────────────────────────────┤
│  Registry (misc)       │ VNC passwords, AutoLogon     │ Current user      │
│                        │ creds, app-specific secrets  │ (HKCU) or admin   │
└──────────────────────────────────────────────────────────────────────────┘
```

**🔶 WHY**

Windows must store credentials (or derivatives of them) persistently because:
- Users should not have to enter passwords repeatedly (credential caching)
- Services must authenticate to network resources without user interaction (LSA secrets)
- Offline logon must work when the DC is unavailable (cached domain credentials)
- Applications save credentials for convenience (browser password managers, Credential Manager)

**⚔️ HOW**

**The credential attack priority order:**

```
1. LSASS (immediate) — highest value, requires SYSTEM
   → Contains active session credentials for anyone currently logged in
   → A DA session = immediate DA compromise via PtH or PtT

2. SAM + SECURITY hive — fast, requires SYSTEM
   → Local admin hash (often reused across machines → lateral move)
   → LSA secrets (service account passwords → often privileged in AD)
   → Domain cached credentials (DCCache, hashcat mode 2100 — offline crack)

3. DPAPI — comprehensive, requires user context or domain backup key
   → Browser saved passwords (Chrome, Edge) — potentially admin credentials
   → Credential Manager (saved RDP, share, application passwords)
   → If DA: domain DPAPI backup key → decrypt ALL users' DPAPI secrets
              → every browser password in the domain

4. Registry — quick wins, no elevated access needed for HKCU
   → HKLM\Software\...\DefaultPassword — cleartext autologon password
   → VNC/RDP tool registry entries — stored passwords
   → Application-specific config in registry
```

**🧠 LOCK IT IN**

Credential storage locations are like different types of safes in a bank. LSASS is the teller's cash drawer — it has current transaction money (active session credentials) and is accessible to the teller on duty (SYSTEM). The SAM is the bank's vault — longer-term storage, higher access required. DPAPI is each employee's personal safe — accessible with their key (their password) or the master key held by management (domain backup key, requiring DA). The registry safe has a combination written on a sticky note inside the cabinet beside it.

---

## SECTION 18 — Putting It All Together: The Windows Attack Surface Map

Every attack in red teaming traces back to a mechanism covered in this document. Here is the map:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ATTACK ← MECHANISM                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  LSASS dump           ← Processes + Handles + SYSTEM privilege         │
│  Process injection    ← Virtual memory + Handles + SeDebugPrivilege    │
│  Potato attacks       ← Privileges (SeImpersonate) + Named Pipes       │
│  DLL hijacking        ← PE loader + DLL search order + file write      │
│  Service binary swap  ← Services + Registry + weak file permissions    │
│  Unquoted service path← Services + Registry + Windows path parsing     │
│  UAC bypass           ← Integrity levels + autoElevate + HKCU write    │
│  AMSI bypass          ← API layers + virtual memory + function patches │
│  ETW bypass           ← API layers + ntdll.dll + EtwEventWrite patch   │
│  EDR unhooking        ← API layers + ntdll.dll hooks + memory write    │
│  Credential dumping   ← LSASS architecture + Windows credential storage│
│  Registry persistence ← Registry autorun keys + HKCU write access      │
│  Token impersonation  ← Access tokens + SeImpersonatePrivilege         │
│  Thread hijacking     ← Threads + handles + register manipulation      │
│  Kernel bypass (BYOVD)← Kernel/user mode boundary + driver signing    │
└─────────────────────────────────────────────────────────────────────────┘
```

**The master diagnostic question**: when something is not working, ask:

```
What layer is blocking me?
  ↓
Is it an ACCESS issue?   → Token, privileges, integrity level, ACLs
Is it a DETECTION issue? → API hooks, ETW, behavioral rules, AMSI
Is it an OS DESIGN issue?→ Virtual memory isolation, PPL protection
Is it a CONFIGURATION issue? → Service permissions, registry ACLs

For each layer: what is the mechanism, and what is the bypass?
```

---

## Mastery Checklist — Windows Internals

You understand Windows Internals at the level needed for red teaming when you can answer all of these without notes:

**The Two Zones:**
- [ ] Why can process A not read process B's memory without OS permission?
- [ ] What happens to the entire machine if kernel-mode code crashes?
- [ ] Why does bypassing userland EDR hooks not bypass kernel-level detection?

**Virtual Memory:**
- [ ] Why does allocating PAGE_EXECUTE_READWRITE memory raise EDR alerts?
- [ ] What is the difference between virtual address 0x1000 in process A and process B?

**Processes and Handles:**
- [ ] What information does a running process list reveal about an environment?
- [ ] What does SeDebugPrivilege allow, and why does SYSTEM always have it?
- [ ] What is handle duplication and why is it stealthier than OpenProcess on LSASS?

**Tokens and Privileges:**
- [ ] What is the difference between a privilege being assigned and being enabled?
- [ ] Why do IIS and MSSQL service accounts have SeImpersonatePrivilege?
- [ ] What is the Potato attack mechanism at the token level?

**Integrity Levels:**
- [ ] Why can a local admin still get Access Denied without UAC bypass?
- [ ] What is autoElevate and which Windows binaries use it?
- [ ] Why does the FodHelper UAC bypass work without a prompt?

**Services:**
- [ ] How does an unquoted service path enable code execution?
- [ ] What are the three ways services are exploitable (binary perms, path, ACL)?
- [ ] Where in the registry is a service's binary path stored?

**API Layers:**
- [ ] Why do EDR hooks live in ntdll.dll rather than kernel32.dll?
- [ ] What does userland unhooking do, and what does it NOT protect against?
- [ ] What is the difference between a direct syscall and an indirect syscall?

**DLLs:**
- [ ] What is reflective DLL injection and why does it not appear in the module list?
- [ ] How does DLL search order enable hijacking?

**Credentials:**
- [ ] Name four places Windows stores credentials and the access level required for each
- [ ] What is DPAPI and what does the domain backup key unlock?
- [ ] Why does LSASS need to keep credentials in memory?

**EDR:**
- [ ] What is a function hook and where are they placed?
- [ ] What does userland unhooking replace and why does it work?
- [ ] Name two detection mechanisms that survive userland unhooking
