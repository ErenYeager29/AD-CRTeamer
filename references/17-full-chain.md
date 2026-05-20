# Phase 17: Full Chain Simulation — Exam Readiness

> **This is the most important phase.** Everything you've learned must come together in a single timed run. This phase is the final exam simulation before the real exam.

**Study time**: 2 weeks (repeated simulations) | **Difficulty**: Advanced

---

## The Exam Simulation Protocol

### Setup

Use GOAD-Light or a custom 3-VM lab. Set a 5-hour countdown timer.

The rules:
- Fresh Kali VM (no pre-installed C2, no pre-built payloads)
- You receive: VPN credentials + domain user + password
- Goal: get SYSTEM on every host, reach Domain Admin, dump krbtgt

**No notes, no cheatsheets, no AI.** The exam prohibits AI tools — practice like the real thing.

---

## The Attack Chain You Must Be Able to Execute

```
00:00  VPN connected, timer started
       → Run setup script (apt install + Sliver)

00:15  Sliver server running, HTTPS listener up
       → Generate stageless beacon (with Defender bypass)

00:20  Verify exam credentials: nxc smb <dc> -u user -p pass
       → Find all hosts, check WinRM access

00:25  Deliver beacon to foothold host via evil-winrm cradle
       → Confirm C2 callback

00:35  Run Seatbelt + winPEAS via execute-assembly
       → Identify privesc vector (SeImpersonatePrivilege expected)

00:45  GodPotato → SYSTEM shell on foothold
       → Confirm whoami = NT AUTHORITY\SYSTEM

00:55  LSASS dump via comsvcs.dll → download → pypykatz
       → Extract NTLM hashes + any domain credentials

01:05  Run SharpHound via execute-assembly
       → Download zip → Load BloodHound

01:15  Mark owned nodes → "Shortest Path to DA"
       → Identify attack: Kerberoast / ACL chain / delegation

01:30  Execute attack chain:
       → Kerberoast → crack → lateral move
       OR → ACL abuse → DCSync

02:00  DA access confirmed → beacon on DC
       → whoami /all on DC

02:15  DCSync → dump krbtgt hash
       → Forge Golden Ticket (permanent access proof)

02:30  Collect all flags:
       → dir C:\ /s /b | findstr -i flag (on each host)

03:00  Set persistence (scheduled task SYSTEM)
       → Second pivot host (repeat privesc + dump)

04:00  All flags collected, documented
       → Review any missed objectives

05:00  Timer ends
```

---

## After Each Simulation — Debrief Questions

Answer these honestly after every run:

1. **C2 setup**: How long did it take? Was your beacon Defender-caught? What did you fix?
2. **Local privesc**: Did you find the right vector quickly? Did you waste time on wrong paths?
3. **Credential dump**: Did pypykatz parse correctly? Did you get useful hashes?
4. **AD path**: Was the BloodHound path clear? Did you need to do manual verification?
5. **Execution**: Did the ACL abuse / Kerberoast / delegation attack succeed first try?
6. **Time**: Which phase ran over budget? Why?

Repeat until you can complete the full chain consistently in under 3 hours — giving you 2 hours of buffer on the real exam.

---

## HTB Boxes — Exam-Equivalent Practice

Complete these in order, timed (target: each box in under 2 hours):

| Box | Focus | Difficulty |
|-----|-------|-----------|
| [Forest](https://app.hackthebox.com/machines/Forest) | AS-REP → DCSync | Easy AD |
| [Active](https://app.hackthebox.com/machines/Active) | Kerberoasting → DA | Easy AD |
| [Sauna](https://app.hackthebox.com/machines/Sauna) | AS-REP → BloodHound → DCSync | Easy AD |
| [Resolute](https://app.hackthebox.com/machines/Resolute) | DNS Admin → DA | Medium AD |
| [Monteverde](https://app.hackthebox.com/machines/Monteverde) | Azure Sync creds | Medium AD |
| [Cascade](https://app.hackthebox.com/machines/Cascade) | AD object abuse | Medium AD |
| [Mantis](https://app.hackthebox.com/machines/Mantis) | MSSQL → kerberos | Hard AD |

When you can do Forest, Active, and Sauna without any hints — you're ready for the CRTeamer exam.

---

## Final Exam Readiness Checklist

Complete every item before booking the exam:

**C2 & Infrastructure**
- [ ] Deploy Sliver from scratch in under 20 minutes
- [ ] Get a callback past Windows Defender using at least 2 methods
- [ ] Set up Chisel pivot and route Impacket through it

**Local Escalation**
- [ ] GodPotato → SYSTEM in under 5 minutes
- [ ] Exploit weak service binary permission end-to-end
- [ ] Bypass UAC with FodHelper

**Credential Access**
- [ ] Dump LSASS via comsvcs.dll + parse with pypykatz
- [ ] PtH to another host with extracted NTLM hash
- [ ] Explain NTLM hash vs NetNTLMv2 without notes

**AD Attacks**
- [ ] Kerberoast → crack → use cracked creds
- [ ] AS-REP roast without credentials
- [ ] Execute RBCD full chain (addcomputer → rbcd → getST → shell)
- [ ] DCSync the domain and dump krbtgt
- [ ] Forge a Golden Ticket and use it

**Evasion & Tradecraft**
- [ ] Run SharpHound via execute-assembly (no disk write)
- [ ] Load PowerView in-memory after AMSI bypass
- [ ] Download a file using certutil (no wget/curl)
- [ ] Deliver beacon via mshta.exe + HTA

**Simulation**
- [ ] Complete HTB Forest without hints
- [ ] Complete HTB Active without hints
- [ ] Complete GOAD-Light foothold → DA in under 3 hours

**When all boxes are checked → book the exam.**
