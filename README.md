# AD-CRTeamer Learning Path — Beginner to Exam-Ready

A structured, phase-by-phase learning skill for the **Certified Red Teamer (CRTeamer)** exam by [PentestingExams.com](https://pentestingexams.com/certifications/professional/certified-red-teamer/). Covers every exam domain from first principles — not just commands, but **why techniques work**, when to use them, and how to practice them.

**Scope**: Windows red teaming — C2 setup, payload evasion, Windows privilege escalation, credential access, lateral movement, Active Directory attacks, persistence, LOLBAS, PowerShell tradecraft.

[![Learning Path](https://img.shields.io/badge/learning--path-18%20phases-1f6feb?style=flat-square)](./cert-coverage.html)
[![Study Time](https://img.shields.io/badge/study--time-16--20%20weeks-d29922?style=flat-square)](./README.md)
[![Difficulty](https://img.shields.io/badge/difficulty-beginner%20→%20advanced-3fb950?style=flat-square)](./README.md)
[![Exam](https://img.shields.io/badge/exam-CRTeamer%205hr%20practical-f85149?style=flat-square)](https://pentestingexams.com/certifications/professional/certified-red-teamer/)

---

## This Skill vs The Cheatsheet Skill

There are two CRTeamer skills. Use them at different stages:

| | **crteamer-learn** (this skill) | **crteamer-exam-prep** |
|---|---|---|
| **Purpose** | Learn concepts deeply, build understanding | Quick reference on exam day |
| **Format** | Why → How → When → Lab → Checklist | Commands + time budget + failure modes |
| **When to use** | 16–20 weeks before exam | Final week / exam day |
| **Depth** | Full explanations, mental models, practice labs | Terse, fast lookup only |

---

## About the Exam

The CRTeamer is a **5-hour practical exam** by The SecOps Group / PentestingExams.com:

- Starts with a **fresh Kali VM** — no tools pre-installed, no C2 configured
- You receive **low-privileged domain user credentials** (assumed breach)
- Goal: vertical + lateral movement → full domain compromise
- **No AI tools** during the exam
- Pass at 60% · Merit at 75% · One free retake
- Equivalent difficulty to GRTP / Red Team Ops (Cobalt Strike course)

> *"The exam isn't difficult if you know what you're doing — but setting up C2 on a fresh Kali under time pressure is the hardest part if you've come unprepared."* — Viktor Bajraktar, CRTeamer

---

## How to Use This Skill

1. **Go in order** — each phase builds on the previous. Don't skip foundations.
2. **Understand before you run** — read the concept section first. Know WHY before typing commands.
3. **Do every practice lab** — reading is not learning. Hands-on is mandatory.
4. **Complete the mastery checklist** — each phase ends with questions you must answer without notes. Only move on when you can.
5. **Build a lab now** — Phase 00 helps you set one up. You need it from Phase 01 onward.
6. **Simulate the exam** — Phase 17 is a timed full-chain run. Do it repeatedly until your muscle memory is there.

---

## Full Learning Path — 18 Phases

| # | Phase | Syllabus Domain | Study Time | Level |
|---|-------|----------------|-----------|-------|
| 00 | [Windows Internals & Red Team Mindset] | Prerequisites | 1 week | Beginner |
| 01 | [Red Team Infrastructure & OPSEC](#phase-01) | Infrastructure & OPSEC | 1 week | Beginner |
| 02 | [C2 Frameworks Deep Dive](#phase-02) | Infrastructure & OPSEC | 1 week | Intermediate |
| 03 | [Payload Development — How Detection Works](#phase-03) | Payload Development | 1 week | Intermediate |
| 04 | [AMSI, ETW & AV Bypass](#phase-04) | Payload Development | 1 week | Intermediate |
| 05 | [Initial Access in Assumed Breach Scenarios](#phase-05) | Initial Access | 3 days | Beginner |
| 06 | [Local Enumeration — What to Look For and Why](#phase-06) | Local Enumeration | 1 week | Beginner |
| 07 | [Windows Privilege Escalation](#phase-07) | Windows PrivEsc | 2 weeks | Intermediate |
| 08 | [Credential Access — How Windows Stores Secrets](#phase-08) | Credential Access | 1 week | Intermediate |
| 09 | [Lateral Movement & Pivoting](#phase-09) | Lateral Movement | 1 week | Intermediate |
| 10 | [Active Directory Fundamentals](#phase-10) | AD prerequisite | 1 week | Beginner |
| 11 | [AD Enumeration — Reading the Attack Surface](#phase-11) | AD Enumeration | 1 week | Intermediate |
| 12 | [Kerberos — Protocol to Attacks](#phase-12) | Kerberos-Based Attacks | 2 weeks | Intermediate |
| 13 | [Domain Privilege Escalation — Thinking in Paths](#phase-13) | Domain PrivEsc | 1 week | Advanced |
| 14 | [AD Persistence — Durable Access](#phase-14) | AD Persistence | 1 week | Advanced |
| 15 | [LOLBAS & Red Team Tradecraft](#phase-15) | Living-off-the-Land | 3 days | Intermediate |
| 16 | [PowerShell & .NET Tradecraft](#phase-16) | PS & .NET + Offensive .NET | 1 week | Advanced |
| 17 | [Full Chain Simulation — Exam Readiness](#phase-17) | All domains | 2 weeks | Advanced |

**Total estimated study time**: 16–20 weeks part-time (1–2 hours/day)
**Accelerated**: 8–10 weeks full-time

---

## What Makes This Different

Most resources give you commands. This skill gives you **mental models**.

Each technique is taught as:

```
What is it?          → One clear sentence
Why does it exist?   → The underlying Windows design decision being exploited
Why does it work?    → The actual mechanism (tokens, protocol steps, API calls)
When do you use it?  → Exam context + real-world context
How to do it?        → Step-by-step with each step explained
What can go wrong?   → Common failures + defensive controls
Practice lab         → Specific THM room / HTB box / manual exercise
Mastery check        → Questions you answer without notes before moving on
```

**Example — Potato attacks**: Most cheatsheets say "run GodPotato if you have SeImpersonatePrivilege." This skill explains that Windows services create impersonation tokens for authenticating clients, that `SeImpersonatePrivilege` lets you *use* those tokens, and that Potato attacks trick SYSTEM into authenticating to your controlled endpoint so you can steal its token. You understand it — so when GodPotato fails, you know which variant to try next and why.

---

## Phase Summaries

<details>
<summary><strong>Phase 00 — Windows Internals & Red Team Mindset</strong></summary>

The foundation. Covers kernel vs userland, process access tokens, SeImpersonatePrivilege (why it leads to SYSTEM), the Windows registry as a persistence surface, services as a privilege escalation surface, and why LSASS holds credentials. Introduces the red team mindset: thinking in trust relationships, attack chains, and footprint. Includes lab setup guide (GOAD, manual 3-VM lab, or TryHackMe subscription).

**Mastery gate**: Can you explain why `SeImpersonatePrivilege` leads to SYSTEM without googling?

</details>

<details>
<summary><strong>Phase 01 — Red Team Infrastructure & OPSEC</strong></summary>

What C2 frameworks solve (vs raw shells), how beacons work (staged vs stageless, sleep intervals, jitter), what a redirector is and why it protects your real server, and OPSEC fundamentals. First hands-on lab: deploy Sliver, create an HTTPS listener, get a Windows callback. Target: under 20 minutes from a blank Kali.

**Mastery gate**: Can you deploy Sliver and get a callback in under 20 minutes?

</details>

<details>
<summary><strong>Phase 02 — C2 Frameworks Deep Dive</strong></summary>

Beyond basic setup. Execute-assembly (why in-memory matters), SOCKS5 pivoting via Sliver, Chisel tunnels, process migration, HTTP traffic profiles, and when to use Havoc or Mythic instead of Sliver. Multi-session management.

**Mastery gate**: Can you run SharpHound via execute-assembly, set up a SOCKS5 tunnel, and migrate a beacon?

</details>

<details>
<summary><strong>Phase 03 — Payload Development</strong></summary>

The three detection layers (static signatures, AMSI, behavioral/ETW) explained separately. ThreatCheck and AMSITrigger for finding what triggers detection. Shellcode loaders — why they're stealthier than raw PEs. Donut for .NET-to-shellcode conversion. PEzor for automated evasion. PowerShell obfuscation patterns.

**Mastery gate**: Can you use ThreatCheck to find the exact bytes triggering Defender and fix them?

</details>

<details>
<summary><strong>Phase 04 — AMSI, ETW & AV Bypass</strong></summary>

The actual bypasses. How `AmsiScanBuffer` patching works at the byte level. Why the bypass code itself needs obfuscation. Invisi-Shell as the reliable option. ETW `EtwEventWrite` patching and why it silences .NET telemetry. Sleep obfuscation concepts for memory scanning evasion.

**Mastery gate**: Can you get a PowerShell session past AMSI using 2 different methods?

</details>

<details>
<summary><strong>Phase 05 — Initial Access</strong></summary>

Assumed breach to first beacon. WinRM protocol explained, Evil-WinRM, credential verification workflow. Beacon delivery via PS cradle. Abusing misconfigured services (MSSQL, SMB shares, web portals). Weaponized LNK and HTA delivery explained.

**Mastery gate**: Can you verify domain creds and deliver a beacon via Evil-WinRM in under 5 minutes?

</details>

<details>
<summary><strong>Phase 06 — Local Enumeration</strong></summary>

Reading a Windows host as an attack surface. Triage mindset: every finding maps to an attack. `whoami /priv` analysis. Service vulnerability patterns. AlwaysInstallElevated. Credential hunting locations (PS history, unattend.xml, registry). Using winPEAS and Seatbelt via execute-assembly.

**Mastery gate**: Can you triage winPEAS output and identify the top 3 findings in under 5 minutes?

</details>

<details>
<summary><strong>Phase 07 — Windows Privilege Escalation</strong></summary>

The exam's most common phase. Potato attacks (GodPotato, SweetPotato, PrintSpoofer) with the mechanism explained. Weak service binary permissions — full exploitation flow. Unquoted service paths — why Windows parses them this way. UAC bypass (FodHelper) — why it auto-elevates. DLL hijacking — search order and how to find opportunities.

**Mastery gate**: Can you exploit a weak service binary and a Potato attack from scratch?

</details>

<details>
<summary><strong>Phase 08 — Credential Access</strong></summary>

Where Windows stores credentials and why. NTLM hash vs NetNTLMv2 — the distinction that trips up beginners. LSASS internals. Three dump methods (Mimikatz, comsvcs.dll, nanodump) with OPSEC comparison. SAM extraction. Pass-the-Hash — the protocol mechanism that makes it work. Kerberos ticket extraction and Pass-the-Ticket.

**Mastery gate**: Can you explain PtH without notes and dump LSASS via comsvcs.dll?

</details>

<details>
<summary><strong>Phase 09 — Lateral Movement & Pivoting</strong></summary>

Protocol comparison (WMI vs PsExec vs WinRM vs DCOM) — when each makes sense and what artifacts each leaves. Chisel tunnel setup step by step. Ligolo-ng for cleaner routing. Finding lateral move targets (NetExec, BloodHound AdminTo edges).

**Mastery gate**: Can you set up a Chisel tunnel and route evil-winrm through it?

</details>

<details>
<summary><strong>Phase 10 — Active Directory Fundamentals</strong></summary>

AD concepts before AD attacks. What AD solves and why DCs are crown jewels. SIDs as the real identity (why Golden Tickets put SIDs in tickets, not usernames). Kerberos AS-REQ/TGS-REQ/AP-REQ flow drawn and explained — every AD attack maps to a step in this flow. SPNs. ACLs on AD objects. GPOs.

**Mastery gate**: Can you draw the Kerberos flow and map each attack to its protocol step?

</details>

<details>
<summary><strong>Phase 11 — AD Enumeration</strong></summary>

How BloodHound's collector works (LDAP + NetSessionEnum + RPC), graph model explained. SharpHound and bloodhound-python collection. First queries to run (in priority order). Reading BloodHound paths as executable attack chains. 10 custom Cypher queries for specific scenarios. PowerView manual verification.

**Mastery gate**: Can you find a DA path in BloodHound in under 5 minutes and read the edges as attack steps?

</details>

<details>
<summary><strong>Phase 12 — Kerberos Attacks</strong></summary>

The most technique-dense phase. Each attack explained as a specific exploitation of the Kerberos protocol step from Phase 10. Kerberoasting (full step-by-step with each step explained). AS-REP roasting (with and without credentials). Unconstrained delegation with coercion. Constrained delegation S4U chain. RBCD full 4-step chain. Golden Ticket forging.

**Mastery gate**: Can you execute RBCD end-to-end from GenericWrite to a shell?

</details>

<details>
<summary><strong>Phase 13 — Domain Privilege Escalation</strong></summary>

Translating BloodHound edges into action. GenericAll/WriteDACL/WriteOwner chains. DCSync grant. Shadow Credentials (why stealthier than password reset). GPO write abuse for domain-wide code execution. AdminSDHolder.

**Mastery gate**: Can you execute WriteDACL → DCSync grant → DCSync the domain?

</details>

<details>
<summary><strong>Phase 14 — AD Persistence</strong></summary>

Why each persistence technique survives what it survives. Host-based: scheduled tasks, WMI event subscriptions, registry. Domain-level: DCSync ACL grant, AdminSDHolder (the 60-min SDProp re-application mechanism explained), Golden Ticket lifetime.

**Mastery gate**: Can you explain why AdminSDHolder persistence survives manual ACL cleanup?

</details>

<details>
<summary><strong>Phase 15 — LOLBAS & Red Team Tradecraft</strong></summary>

Why signed Microsoft binaries bypass AV. File download via certutil, bitsadmin, PowerShell. Execution via mshta, regsvr32/scrobj.dll (squiblydoo), rundll32. When LOLBAS is your fallback vs your primary approach.

**Mastery gate**: Can you download a file and execute a payload using only signed Microsoft binaries?

</details>

<details>
<summary><strong>Phase 16 — PowerShell & .NET Tradecraft</strong></summary>

Operating in restricted environments. CLM detection and bypass (PowerShell v2, execute-assembly, PowerShdll). AppLocker bypass via allowed paths and LOLBins. JEA escape techniques. .NET Assembly.Load in-memory. Disabling PowerShell transcription logging. Modifying open-source tools to defeat Defender signatures using ConfuserEx.

**Mastery gate**: Can you load PowerView in-memory in a CLM environment?

</details>

<details>
<summary><strong>Phase 17 — Full Chain Simulation</strong></summary>

Timed exam simulation runs against GOAD-Light. The complete attack chain: C2 setup → initial access → local privesc → credential dump → AD enumeration → DA path execution → persistence → flag collection. Debrief questions after each run. Exam readiness checklist. Required HTB boxes. Final gate: complete HTB Forest, Active, and Sauna without hints.

**Mastery gate**: All 30 items on the final readiness checklist checked.

</details>

---

## Exam Readiness Gates — You're Ready When

Before booking the exam, confirm you can do all of these **without notes**:

**Infrastructure**
- [ ] Deploy Sliver C2 and get a Defender-bypassing callback in under 20 minutes
- [ ] Set up Chisel pivot and route Impacket tools through it
- [ ] Run SharpHound via execute-assembly with no disk write

**Local escalation**
- [ ] GodPotato → SYSTEM in under 5 minutes
- [ ] Exploit a weak service binary end-to-end
- [ ] Bypass UAC with FodHelper

**Credential access**
- [ ] Dump LSASS via comsvcs.dll + parse with pypykatz
- [ ] PtH to another host with extracted NTLM hash
- [ ] Explain NTLM hash vs NetNTLMv2 out loud

**AD attacks**
- [ ] Kerberoast → crack → use cracked creds
- [ ] RBCD full chain (addcomputer → rbcd → getST → shell)
- [ ] DCSync the domain and dump krbtgt
- [ ] Forge a Golden Ticket and authenticate with it

**Tradecraft**
- [ ] Load PowerView in-memory after AMSI bypass
- [ ] Deliver beacon via mshta.exe HTA
- [ ] Modify a .NET tool to bypass a Defender signature

**Simulation**
- [ ] Complete HTB Forest without hints
- [ ] Complete HTB Active without hints
- [ ] Complete GOAD-Light foothold → DA in under 3 hours

---

## Practice Platform Reference

| Platform | Cost | Best for |
|----------|------|---------|
| [TryHackMe](https://tryhackme.com) | Free / £14/mo | Guided learning, beginner-friendly rooms per phase |
| [HackTheBox](https://hackthebox.com) | Free / €14/mo | Realistic boxes, exam-equivalent difficulty |
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) | Free (local VMs) | Full AD lab, most realistic, final simulation |
| [VulnHub](https://vulnhub.com) | Free | Offline VMs, Windows privesc practice |
| [ired.team](https://www.ired.team) | Free | Deep technique reference, mental models |

---

## Key Tools Covered

| Tool | Phase | What you learn |
|------|-------|---------------|
| Sliver | 01, 02 | Install, configure, operate, profile |
| Havoc / Mythic | 02 | When to use instead of Sliver |
| ThreatCheck / AMSITrigger | 03 | Find detection triggers precisely |
| Donut / PEzor | 03 | Shellcode and PE packing |
| Invisi-Shell | 04 | AMSI + logging bypass reliably |
| winPEAS / Seatbelt | 06 | Local enum via execute-assembly |
| GodPotato / SweetPotato | 07 | SYSTEM via SeImpersonatePrivilege |
| nanodump / comsvcs.dll | 08 | Stealthy LSASS dumping |
| pypykatz | 08 | Offline credential parsing |
| Chisel / Ligolo-ng | 09 | Network pivoting |
| BloodHound + SharpHound | 11 | AD path mapping and Cypher queries |
| PowerView | 11, 13 | Manual AD enumeration and ACL abuse |
| Rubeus | 12 | Kerberos ticket operations |
| Impacket suite | 12, 13 | GetUserSPNs, getST, secretsdump, rbcd |
| Certipy | 13 | AD CS / Shadow Credentials |
| SharpGPOAbuse | 13 | GPO-based code execution |
| ConfuserEx | 16 | .NET obfuscation |

---

## File Structure

```
crteamer-learn/
├── SKILL.md                             # Router: phase map, response template, mastery gates
├── README.md                            # This file
├── evals/
│   └── evals.json                       # 10 test prompts for skill validation
└── references/
    ├── 00-windows-internals.md          # Tokens, processes, registry, services, LSASS, mindset
    ├── 01-c2-infrastructure.md          # C2 concepts, staged/stageless, redirectors, OPSEC
    ├── 02-c2-deep-dive.md               # execute-assembly, SOCKS5, migration, profiles
    ├── 03-payload-development.md        # Detection layers, ThreatCheck, Donut, PEzor
    ├── 04-amsi-etw-bypass.md            # AMSI patch mechanism, Invisi-Shell, ETW, sleep obfusc.
    ├── 05-initial-access.md             # WinRM, Evil-WinRM, beacon delivery, LNK/HTA
    ├── 06-local-enum.md                 # Privilege analysis, service vulns, credential hunting
    ├── 07-windows-privesc.md            # Potato attacks, service perms, UAC bypass, DLL hijack
    ├── 08-credential-access.md          # LSASS internals, dump methods, NTLM vs NetNTLM, PtH
    ├── 09-lateral-movement.md           # WMI/PsExec/WinRM comparison, Chisel, Ligolo
    ├── 10-ad-fundamentals.md            # SIDs, Kerberos flow, SPNs, ACLs, GPOs
    ├── 11-ad-enumeration.md             # BloodHound internals, Cypher queries, PowerView
    ├── 12-kerberos-attacks.md           # Kerberoast, AS-REP, delegation, RBCD, Golden Ticket
    ├── 13-domain-privesc.md             # ACL chains, Shadow Credentials, GPO abuse
    ├── 14-ad-persistence.md             # Host + domain persistence, why each survives
    ├── 15-lolbas.md                     # Signed binary execution, download/exec techniques
    ├── 16-ps-dotnet.md                  # CLM/AppLocker bypass, in-memory .NET, tool modification
    └── 17-full-chain.md                 # Timed simulation, HTB boxes, final readiness checklist
```

---

## Recommended Study Order

```
Weeks 1–2   → Phase 00 (Windows Internals) + Phase 10 (AD Fundamentals)
              Read ired.team daily. Set up your lab.

Weeks 3–4   → Phase 01 + 02 (C2 Infrastructure + Deep Dive)
              Sliver setup drill every day until under 20 minutes.

Weeks 5–6   → Phase 03 + 04 (Payload Dev + AMSI/ETW Bypass)
              Get a beacon past Defender using 3 different methods.

Weeks 7–8   → Phase 05 + 06 + 07 (Initial Access + Enum + PrivEsc)
              Do THM Windows PrivEsc Arena + HTB Devel.

Weeks 9–10  → Phase 08 + 09 (Creds + Lateral Movement)
              Dump LSASS 4 ways. Set up a 3-VM pivot lab.

Weeks 11–12 → Phase 11 + 12 (AD Enum + Kerberos)
              Complete HTB Forest and Active. Load BloodHound on GOAD.

Weeks 13–14 → Phase 13 + 14 (Domain PrivEsc + Persistence)
              Execute 5 different ACL chains in GOAD.

Weeks 15–16 → Phase 15 + 16 (LOLBAS + PS Tradecraft)
              Operate in CLM. Modify a tool to bypass Defender.

Weeks 17–20 → Phase 17 (Full Chain Simulation)
              Timed GOAD runs. HTB Sauna, Resolute, Cascade.
              Repeat until foothold → DA in under 3 hours.

Week 20+    → Book the exam when all readiness gates are checked.
```

---

## Related Skills

- **`crteamer-exam-prep`** — exam-day cheatsheet (commands, time budget, failure modes)
- **`windows-ad-pentesting`** — deeper AD pentesting reference (17 phases, CRTE/OSCP level)
