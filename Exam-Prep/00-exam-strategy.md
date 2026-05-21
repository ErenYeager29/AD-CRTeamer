# Phase 00: Exam Strategy & Time Plan

> Read this before anything else. The CRTeamer exam is won or lost in the first 30 minutes.

---

## The Core Problem

You get a **fresh Kali VM** with nothing configured. No C2, no payloads, no tools pre-staged. The clock starts immediately. Most candidates who fail do so because they spend 90+ minutes fumbling with C2 setup and payload evasion — leaving too little time for the AD chain.

**The fix**: practice your C2 setup until it takes under 20 minutes, every time, from a blank Kali.

---

## Pre-Exam Checklist (Do Before Exam Day)

### Build a Setup Script

Write a bash script you have memorized / can type from memory:

```bash
#!/bin/bash
# crteamer-setup.sh — run this on exam Kali immediately

# Update and install essentials
sudo apt update -q && sudo apt install -y golang python3-pip pipx bloodhound neo4j chisel

# Install Sliver C2
curl https://sliver.sh/install | sudo bash

# Install Impacket (latest)
pipx install impacket
pipx install bloodhound-python
pipx install netexec

# Install SharpHound collector
wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.zip
unzip SharpHound.zip -d ~/tools/sharphound/

# Prep a working directory
mkdir -p ~/exam/{loot,payloads,scans,bh-data}
echo "[+] Setup complete"
```

Practice running this until it completes in under 10 minutes including download time.

### Pre-Build Your Payload Templates

Before exam day, know exactly how to generate a working Defender-bypassing payload for each delivery method:
- Shellcode → stageless EXE loader
- PowerShell cradle → in-memory beacon
- HTA / LNK → dropper for initial access scenarios

→ See **Phase 02** for payload recipes.

### Know Your BloodHound Queries Cold

Have these memorized — you'll run them within 10 minutes of getting a foothold:
- Shortest Path to Domain Admins
- Find Kerberoastable users
- Find AS-REP Roastable users
- Find all owned-to-DA paths (after marking owned nodes)

---

## Exam-Day Execution Plan

### Minutes 0–20: Infrastructure Up

```
0:00  Start VPN → confirm connectivity to exam network
0:02  Run setup script (or manually: install Sliver/Havoc)
0:08  Start C2 listener, generate first payload
0:12  Confirm Defender bypass on test payload
0:15  Deliver payload via provided assumed-breach credentials
0:20  First beacon / shell → confirm C2 callback
```

If you don't have a beacon by minute 20, stop and troubleshoot evasion. Don't proceed without C2.

### Minutes 20–45: Host Recon

```
0:20  Run winPEAS or Seatbelt on foothold host
0:25  Note: OS version, AV/EDR, users, privileges, network
0:30  Look for quick wins: unquoted paths, weak service perms, stored creds
0:40  Note all interesting findings → prioritize privesc vectors
```

### Minutes 45–75: Privesc to SYSTEM

```
0:45  Execute best privesc vector from enum
0:55  Confirm SYSTEM shell via C2
1:00  Dump credentials (Mimikatz / nanodump → pypykatz offline)
1:10  Identify domain user creds / hashes for lateral move
```

### Minutes 75–105: AD Mapping

```
1:15  Run SharpHound with C2 execute-assembly (or -c All from SYSTEM)
1:25  Transfer zip → load into BloodHound
1:30  Run "Shortest Path to DA" query
1:35  Identify attack path (Kerberoast? ACL chain? Delegation?)
1:45  Begin executing AD attack chain
```

### Minutes 105–180: DA Path Execution

```
2:00  Kerberoast / AS-REP / ACL abuse → get privileged creds
2:30  PtH / PtT / evil-winrm to next hop
2:45  Repeat: enum → privesc → creds → move
3:00  Target DC or high-value system
3:15  DCSync / dump krbtgt
3:30  Collect flags from all compromised systems
```

### Minutes 180–300: Buffer + Polish

```
3:30  Set persistence on critical hosts (if required for flags)
3:45  Second-path exploration — missed flags?
4:00  Re-check all flag files, notes, screenshots
4:30  Final flag submission check
5:00  Exam ends
```

---

## Flag Collection Strategy

- **Take a screenshot of every step** — exam may ask you to prove compromise, not just submit a flag string
- Look for flags in:
  - Desktop (`C:\Users\*\Desktop\`)
  - SYSVOL / NETLOGON shares
  - Domain Admin home directories
  - DC root (`C:\`)
  - Common CTF locations: `C:\Flags\`, `C:\flag.txt`
- After each new shell: `dir C:\ /s /b | findstr -i flag`

---

## OPSEC During Exam

The exam may have detection mechanisms. Treat it like a real engagement:

- Don't run `winPEAS` in plaintext from disk — upload via C2 and execute in memory
- Use `--stealth` on SharpHound collector to reduce LDAP noise
- Prefer Kerberos auth over NTLM where possible
- Run credential dumping only when needed, not speculatively
- Clean up dropped files after use

---

## Common Failure Modes

| Problem | Cause | Fix |
|---------|-------|-----|
| No beacon after 45 min | Defender catching payload | Pre-test payload types; have 3 bypass methods ready |
| Stuck on privesc | Only tried one method | Have 5+ privesc techniques memorized; run multiple in parallel |
| BloodHound finds no path | Low-quality collection | Re-run with `--CollectionMethods All`; also enumerate manually with PowerView |
| Wrong flag format | Flag found but wrong hash | Read flag instructions carefully; some want full content, some want hash |
| Ran out of time | Spent too long on one path | Time-box each phase; move on and return |

---

## Practice Labs for Exam Simulation

Run these in order, timed, to simulate exam conditions:

1. **HTB Pro Lab: Offshore** — multi-host AD, 24h but practice completing it in 5h
2. **GOAD** — full AD lab with real vulns; set a 5h timer and see how far you get
3. **HTB boxes**: Forest → Sauna → Monteverde → Cascade (in that order)
4. **TryHackMe Red Team Path** — covers C2 setup and tradecraft with guided labs

For C2 speed practice: spin up a fresh Kali VM, start a timer, and race yourself to a working beacon. Target: under 20 minutes from blank machine.

---

## Next Step

→ Start building real skills: **Phase 01: C2 Setup & Infrastructure** (`01-c2-infrastructure.md`)
