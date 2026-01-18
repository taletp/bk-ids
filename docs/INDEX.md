# Documentation Index

Complete documentation for the Advanced IDS/IPS System.

---

## Getting Started

### Quick Start
- **[README.md](../README.md)** - Main project overview, installation, and quick start guide
- **[Dashboard Guide](DASHBOARD.md)** - Complete dashboard documentation

### Installation & Deployment
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide with systemd service setup
- **[KAGGLE_SETUP.md](KAGGLE_SETUP.md)** - Training models on Kaggle with CIC-IDS2018 dataset

---

## Dashboard

### Dashboard
- **[Dashboard Guide](DASHBOARD.md)** - Complete documentation with real-time monitoring, performance metrics, alerts, and interactive charts

---

## Detection & Training

### Attack Detection
- **[CIC-IDS2018 Guide](CIC-IDS2018-GUIDE.md)** - Dataset, feature engineering, and flow tracking
- **[Attack Testing Guide](ATTACK_TESTING_GUIDE.md)** - Testing attack detection

### Model Training
- **[KAGGLE_SETUP.md](KAGGLE_SETUP.md)** - Complete Kaggle training workflow
- Uses CIC-IDS2018 dataset (80GB)
- XGBoost classifier with 17 engineered features
- Supports 11+ attack types

---

## Performance & Tuning

### Optimization
- **[False Positive Mitigation](FALSE_POSITIVE_MITIGATION.md)** - Reducing false alarms and tuning thresholds

### Performance Metrics
| Metric | Value |
|--------|-------|
| Packet Processing | 1000-5000 pps |
| Detection Latency | 50-200ms |
| CPU Usage | 15-30% (4 cores) |
| Memory Usage | 800MB - 2GB |
| False Positive Rate | <1% (threshold 0.95) |

---

## Troubleshooting

### Common Issues

**Dashboard Won't Start**
```bash
# Check port availability
sudo lsof -i :8050

# Kill existing process
sudo kill $(sudo lsof -t -i:8050)

# Start dashboard
sudo venv/bin/python main.py --dashboard-only
```

**High False Positives**
- Increase threshold: `--threshold 0.97`
- Add trusted IPs to whitelist in [config/config.py](../config/config.py)
- Review [False Positive Mitigation](FALSE_POSITIVE_MITIGATION.md)

**No Packets Captured**
```bash
# Check interface is up
ip link show eth0

# Test packet capture
sudo tcpdump -i eth0 -c 10

# Run with sudo
sudo venv/bin/python main.py --mode live --interface eth0
```

**Permission Denied**
```bash
# Add user to necessary groups
sudo usermod -a -G wireshark $USER

# Or run with sudo
sudo venv/bin/python main.py
```

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                      Dashboard (Dash)                    │
│  http://localhost:8050 - Real-time monitoring & alerts   │
└─────────────────────────────────────────────────────────┘
                            ▲
                            │ Updates (1s intervals)
                            │
┌─────────────────────────────────────────────────────────┐
│                   IDS/IPS Main System                    │
│                                                           │
│  ┌──────────┐  ┌────────────┐  ┌───────────┐           │
│  │ Sniffer  │→ │Preprocessor│→ │ Detector  │           │
│  │ (Scapy)  │  │(Features)  │  │ (XGBoost) │           │
│  └──────────┘  └────────────┘  └───────────┘           │
│                                       │                  │
│                                       ▼                  │
│                              ┌─────────────────┐        │
│                              │ Prevention      │        │
│                              │ (iptables)      │        │
│                              └─────────────────┘        │
└─────────────────────────────────────────────────────────┘
                            ▲
                            │ Network Traffic
                            │
                      ┌──────────┐
                      │   eth0   │
                      └──────────┘
```

### Data Flow
1. **Sniffer**: Captures packets from network interface (eth0)
2. **Preprocessor**: Extracts 17 features per packet/flow
3. **Detector**: XGBoost model predicts attack type
4. **Prevention**: Blocks malicious IPs via iptables
5. **Dashboard**: Displays real-time metrics and alerts

---

## Supported Attack Types

The system can detect 11+ types of network attacks:

### DoS/DDoS Attacks
- **DoS Hulk** - HTTP flood attack
- **DoS Slowhttptest** - Slow HTTP headers
- **DoS Slowloris** - Slow HTTP connections
- **DoS GoldenEye** - HTTP flood with cached content
- **DDoS** - Distributed denial of service

### Reconnaissance
- **PortScan** - Port scanning activity
- **Bot** - Botnet communication patterns

### Web Attacks
- **Web Attack - Brute Force** - Login credential attacks
- **Web Attack - XSS** - Cross-site scripting
- **Web Attack - SQL Injection** - Database attacks

### Intrusion
- **Infiltration** - Network infiltration attempts

---

## Configuration

### Key Configuration Files

**[config/config.py](../config/config.py)**
```python
# Detection threshold (0.0-1.0)
DETECTOR_CONFIG = {
    'confidence_threshold': 0.95,
    'whitelist': ['127.0.0.1'],
}

# Dashboard settings
DASHBOARD_CONFIG = {
    'type': 'dash',
    'port': 8050,
    'enable_performance_monitoring': True,
}

# Prevention/blocking
PREVENTION_CONFIG = {
    'auto_block': False,
    'block_duration': 3600,
}
```

---

## Command Reference

### Basic Usage
```bash
# Live capture with dashboard
sudo venv/bin/python main.py --mode live --interface eth0

# Dashboard only (simulation mode)
python main.py --dashboard-only

# Custom threshold
sudo venv/bin/python main.py --mode live --threshold 0.97

# Enable auto-blocking
sudo venv/bin/python main.py --mode live --auto-block
```

### Testing
```bash
# Test dashboard installation
python test_dashboard.py

# Run attack tests
sudo venv/bin/python attack_testing/test_attacks.py

# View logs
tail -f logs/ids_system.log
```

---

## Development

### Project Structure
```
bk-ids/
├── main.py                  # Entry point
├── config/                  # Configuration files
│   └── config.py
├── src/                     # Core modules
│   ├── detector.py          # Detection engine
│   ├── preprocessor.py      # Feature extraction
│   ├── sniffer.py           # Packet capture
│   ├── prevention.py        # Blocking/mitigation
│   └── dashboard_dash.py    # Dash dashboard
├── models/                  # ML models
│   ├── ids_model_mlp.keras
│   └── scaler.joblib
├── logs/                    # Log files
└── docs/                    # Documentation
```

### Adding New Attack Types
1. Collect training data for new attack
2. Update feature extraction in [src/preprocessor.py](../src/preprocessor.py)
3. Retrain model on Kaggle (see [KAGGLE_SETUP.md](KAGGLE_SETUP.md))
4. Update label mapping in [src/detector.py](../src/detector.py)

---

## Additional Resources

### External Links
- [CIC-IDS2018 Dataset](https://www.unb.ca/cic/datasets/ids-2018.html) - Training dataset
- [Scapy Documentation](https://scapy.readthedocs.io/) - Packet manipulation
- [Dash Documentation](https://dash.plotly.com/) - Dashboard framework
- [XGBoost Documentation](https://xgboost.readthedocs.io/) - ML model

### Support
- Check logs: `tail -f logs/ids_system.log`
- Test manually: `sudo python main.py --mode live --interface eth0`
- Review error messages in dashboard
- Verify system requirements

---

## License & Credits

This IDS/IPS system uses:
- **CIC-IDS2018** dataset (UNB Canadian Institute for Cybersecurity)
- **XGBoost** for machine learning
- **Dash by Plotly** for visualization
- **Scapy** for packet processing

---

**Documentation Last Updated**: January 2026
