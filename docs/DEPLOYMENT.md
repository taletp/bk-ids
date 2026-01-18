# Production Deployment Guide

## Overview

Complete guide for deploying the IDS/IPS system in production environments.

---

## System Requirements

### Hardware
- **CPU**: 4+ cores recommended
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 10GB for system + logs
- **Network**: Dedicated monitoring interface

### Software
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Kali Linux)
- **Python**: 3.9 - 3.13
- **Kernel**: Support for packet capture (libpcap)

---

## Installation

### 1. System Packages

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv \
    libpcap-dev tcpdump iptables git
```

### 2. Clone Repository

```bash
cd /opt
sudo git clone <repository-url> ids-system
cd ids-system
sudo chown -R $USER:$USER .
```

### 3. Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Dashboard Setup

```bash
./setup_dashboard.sh
```

---

## Configuration

### Network Interface

```bash
# List available interfaces
ip a

# Edit config/config.py
SNIFFER_CONFIG = {
    'interface': 'eth0',  # Your monitoring interface
}
```

### Detection Threshold

```python
# config/config.py
DETECTOR_CONFIG = {
    'confidence_threshold': 0.95,  # Adjust based on false positive rate
}
```

### Whitelist Configuration

```python
# config/config.py
DETECTOR_CONFIG = {
    'whitelist': [
        '127.0.0.1',
        '10.0.1.50',  # Your trusted servers
    ],
    'whitelist_subnets': [
        '10.0.0.0/8',      # Internal network
        '172.16.0.0/12',   # Private network
    ],
}
```

### Auto-Blocking

```python
# config/config.py
PREVENTION_CONFIG = {
    'auto_block': True,      # Enable firewall blocking
    'block_duration': 3600,  # Block for 1 hour
}
```

---

## Running as Service

### 1. Create Systemd Service

```bash
sudo nano /etc/systemd/system/ids.service
```

```ini
[Unit]
Description=IDS/IPS Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ids-system
Environment="PATH=/opt/ids-system/venv/bin"
ExecStart=/opt/ids-system/venv/bin/python main.py --mode live --interface eth0 --threshold 0.95
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 2. Enable and Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable ids.service
sudo systemctl start ids.service
```

### 3. Check Status

```bash
sudo systemctl status ids.service
journalctl -u ids.service -f
```

---

## Dashboard Access

### Local Access

```
http://localhost:8050
```

### Remote Access (SSH Tunnel)

```bash
# On your laptop
ssh -L 8050:localhost:8050 user@ids-server

# Then access: http://localhost:8050
```

### Reverse Proxy (Nginx)

```nginx
server {
    listen 80;
    server_name ids.yourdomain.com;

    location / {
        proxy_pass http://localhost:8050;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

---

## Security Hardening

### 1. Dashboard Access Control

```python
# config/config.py
DASHBOARD_CONFIG = {
    'host': '127.0.0.1',  # Localhost only
}
```

### 2. Firewall Rules

```bash
# Allow dashboard only from specific IP
sudo ufw allow from 192.168.1.100 to any port 8050

# Or use VPN
sudo ufw allow from 10.8.0.0/24 to any port 8050
```

### 3. Log Rotation

```bash
sudo nano /etc/logrotate.d/ids
```

```
/opt/ids-system/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
```

---

## Monitoring

### Health Checks

```bash
# Check if service is running
sudo systemctl is-active ids.service

# View recent logs
sudo journalctl -u ids.service --since "1 hour ago"

# Check packet capture
sudo tcpdump -i eth0 -c 10
```

### Metrics

View in dashboard at `http://localhost:8050`:
- Total packets processed
- Detection rate
- False positive rate
- System performance (CPU, memory)

---

## Backup

### Configuration Backup

```bash
tar -czf ids-backup-$(date +%Y%m%d).tar.gz \
    config/ models/ logs/
```

### Automated Backup

```bash
# Add to crontab
crontab -e

# Daily backup at 2 AM
0 2 * * * cd /opt/ids-system && tar -czf /backup/ids-$(date +\%Y\%m\%d).tar.gz config/ models/ logs/
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u ids.service -n 50

# Test manually
cd /opt/ids-system
source venv/bin/activate
sudo venv/bin/python main.py --mode live --interface eth0
```

### High False Positives

1. Increase threshold: `--threshold 0.98`
2. Update whitelist in `config/config.py`
3. Review detection metrics in dashboard

### Performance Issues

```bash
# Check system resources
htop
iotop

# Reduce logging verbosity
# In config/config.py:
LOGGING_CONFIG['handlers']['console']['level'] = 'WARNING'
```

---

## Scaling

### Multiple Interfaces

Run separate instances for each interface:

```bash
# Terminal 1
sudo python main.py --mode live --interface eth0 --dashboard-port 8050

# Terminal 2
sudo python main.py --mode live --interface eth1 --dashboard-port 8051
```

### Load Balancing

Use multiple detection engines with load balancer for high-traffic environments.

---

## Updates

### Update System

```bash
cd /opt/ids-system
git pull
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart ids.service
```

### Update Models

1. Train new model on Kaggle
2. Download model files
3. Copy to `models/` directory
4. Restart service

---

## Support

For deployment issues:

1. Check logs: `journalctl -u ids.service`
2. Test manually: `sudo python main.py --mode live`
3. Review documentation
4. Check system resources

---

**Last Updated**: January 18, 2026
