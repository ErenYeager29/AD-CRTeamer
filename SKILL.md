---
name: crteamer-learn
description: >
  CRTeamer exam learning path — beginner to exam-ready. Deep conceptual teaching for the
  Certified Red Teamer (CRTeamer) exam by PentestingExams.com. Trigger on: learning red
  teaming from scratch, understanding why attacks work, Windows internals, how Kerberos
  works, why AMSI exists, how C2 frameworks work, how Windows stores credentials, why
  token impersonation works, how BloodHound maps attack paths, why delegation is
  exploitable, how .NET reflection loads assemblies, why LOLBins bypass AV, how service
  permissions lead to SYSTEM, what ACLs mean in AD, why Kerberoasting works, how NTLM
  relay happens, CRTeamer study plan, practice labs THM HTB GOAD, mastery checklist,
  red team beginner, Windows privilege escalation explained, AD explained for beginners,
  lateral movement concepts, C2 setup learning, payload evasion learning, phase by phase
  CRTeamer preparation, hands-on practice, what to study, learning order red team.
---

# CRTeamer Learning Path — Beginner to Exam-Ready

This skill teaches you **how and why** red team techniques work, not just the commands.
Every phase builds on the previous. Complete the mastery checklist before moving on.

---

## This Skill vs The Cheatsheet Skill

| | crteamer-learn (this skill) | crteamer-exam-prep |
|---|---|---|
| **Purpose** | Learn concepts deeply, build understanding | Quick reference on exam day |
| **Format** | Why → How → When → Lab → Checklist | Commands + time budget |
| **Use when** | Studying weeks/months before exam | Day before / during prep |
| **Depth** | Full explanations, mental models | Terse, fast lookup |

---

## How to Use This Skill

1. **Go in order** — each phase assumes the previous. Don't skip foundations.
2. **Read the concept section first** — understand WHY before running commands.
3. **Do the practice labs** — reading is not enough. Hands-on is mandatory.
4. **Complete the mastery checklist** — only move on when you can answer every item without looking.
5. **Build a lab** — Phase 00 helps you set one up. You need it from Phase 01 onward.

---

## Full Learning Path — 18 Phases

| # | Phase | Syllabus Domain | Study Time |
|---|-------|----------------|-----------|
| 00 | Windows Internals & Red Team Mindset | Prerequisites | 1 week |
| 01 | Red Team Infrastructure & OPSEC | Infrastructure & OPSEC | 1 week |
| 02 | C2 Frameworks Deep Dive | Infrastructure & OPSEC | 1 week |
| 03 | Payload Development — How Detection Works | Payload Development | 1 week |
| 04 | AMSI, ETW & AV Bypass | Payload Development | 1 week |
| 05 | Initial Access in Assumed Breach Scenarios | Initial Access | 3 days |
| 06 | Local Enumeration — What to Look For and Why | Local Enumeration | 1 week |
| 07 | Windows Privilege Escalation | Windows PrivEsc | 2 weeks |
| 08 | Credential Access — How Windows Stores Secrets | Credential Access | 1 week |
| 09 | Lateral Movement & Pivoting | Lateral Movement | 1 week |
| 10 | Active Directory Fundamentals | AD Enumeration prerequisite | 1 week |
| 11 | AD Enumeration — Reading the Attack Surface | AD Enumeration | 1 week |
| 12 | Kerberos — Protocol to Attacks | Kerberos-Based Attacks | 2 weeks |
| 13 | Domain Privilege Escalation — Thinking in Paths | Domain PrivEsc | 1 week |
| 14 | AD Persistence — Durable Access | AD Persistence | 1 week |
| 15 | LOLBAS & Red Team Tradecraft | Living-off-the-Land | 3 days |
| 16 | PowerShell & .NET Tradecraft | PS & .NET + Offensive .NET | 1 week |
| 17 | Full Chain Simulation — Exam Readiness | All domains | 2 weeks |

**Total estimated study time**: 16–20 weeks part-time (1–2 hours/day)
**Accelerated path**: 8–10 weeks full-time

---

## Response Template

For every learning question, structure the answer as:

1. **What is it** — one clear sentence
2. **Why it exists / why it works** — the mental model, the underlying mechanism
3. **When you'd use this** — exam context + real-world context
4. **How it works** — step-by-step with explanation at each step (not just commands)
5. **What can go wrong** — common mistakes, defensive controls that block it
6. **Practice lab** — specific THM room, HTB box, or manual exercise with difficulty rating
7. **Mastery check** — 2–3 questions the learner should be able to answer without notes

---

## Practice Platform Quick Reference

| Platform | Cost | Best for |
|----------|------|---------|
| TryHackMe (THM) | Free/£14mo | Guided learning, concepts, beginner-friendly |
| HackTheBox (HTB) | Free/€14mo | Realistic boxes, intermediate difficulty |
| GOAD (local) | Free | Full AD lab, most realistic, needs 16GB RAM |
| VulnHub | Free | Offline VMs, good for local practice |
| PentestingLabs | Free/paid | Specific Windows vulns |

---

## Prerequisites Before Starting

Before Phase 00, confirm you have:
- Basic Linux command line comfort (cd, ls, grep, pipes)
- Basic networking knowledge (what TCP/IP, DNS, ports are)
- A Kali Linux VM running (or Windows with WSL2)
- At least 8GB RAM available for labs

If you don't have these → start with TryHackMe's "Pre-Security" path first (2 weeks free).

---

## Mastery Gates — When Are You Exam-Ready?

You're ready to book the CRTeamer exam when you can:

- [ ] Deploy Sliver C2 and get a callback from a Windows VM in under 20 minutes from scratch
- [ ] Bypass Windows Defender with a custom payload using at least 2 different methods
- [ ] Escalate from domain user to SYSTEM using at least 3 different privesc techniques
- [ ] Run BloodHound and identify a DA path without guidance
- [ ] Execute a Kerberoasting → crack → lateral move chain end-to-end
- [ ] Abuse at least one ACL misconfiguration (GenericAll, WriteDACL, or AddMember) to reach DA
- [ ] Set up Chisel pivoting and route tools through it
- [ ] Complete GOAD from foothold to DA in under 3 hours
- [ ] Explain WHY each technique works (not just that it does)
