# IDS/IPS System - Advanced Intrusion Detection & Prevention

A production-ready **Deep Learning-based IDS/IPS** system with real-time monitoring, performance tracking, and intelligent alert notifications.

## 🎯 Key Features

- **ML-Powered Detection**: XGBoost, Random Forest, LightGBM, Neural Networks
- **CIC-IDS2018 Dataset**: Trained on 11+ attack types with 17 optimized features
- **Real-Time Dashboard**: Modern Dash-based UI with live metrics and alerts
- **Performance Monitoring**: CPU, memory, packet rate tracking
- **Smart Detection**: Streaming traffic heuristics to reduce false positives
- **Auto-Blocking**: Firewall integration with configurable IP blocking
- **Flexible Deployment**: Live capture, demo mode, or Kaggle training

## 📊 Supported Attack Types

| Category | Attack Types |
|----------|--------------|
| **DoS/DDoS** | SYN Flood, UDP Flood, LOIC-HTTP, LOIC-UDP, Slowloris, GoldenEye |
| **Reconnaissance** | Port Scan, SSH Brute Force |
| **Web Attacks** | SQL Injection, XSS |
| **Infiltration** | Bot attacks, backdoor connections |

---

## 🚀 Quick Start

### 1. Setup Environment

```bash
cd /path-to-folder/bk-ids
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Install Dashboard Dependencies

```bash
./setup_dashboard.sh
# Or manually:
pip install dash dash-bootstrap-components psutil
```

### 3. Test Installation

```bash
python test_dashboard.py
```

### 4. Run IDS with Dashboard

```bash
# Live capture mode (requires sudo)
sudo venv/bin/python main.py --mode live --interface eth0

# Dashboard automatically starts at http://localhost:8050
# Open in browser to view real-time monitoring
```

### 5. Dashboard Only (Testing)

```bash
python main.py --dashboard-only
```

---

## 📁 Project Structure

```
bk-ids/
├── src/                          # Core modules
│   ├── sniffer.py               # Packet capture (Scapy)
│   ├── preprocessor.py          # Feature extraction
│   ├── detector.py              # ML detection engine
│   ├── feature_adapter.py       # CIC-IDS2018 feature mapping
│   ├── prevention.py            # Firewall management
│   ├── dashboard_dash.py        # Modern Dash dashboard
│   └── dataset_loader.py        # CIC-IDS2018 data loader
├── config/
│   └── config.py                # System configuration
├── models/                       # Trained models
│   ├── ids_model_xgboost.joblib # XGBoost model (default)
│   ├── scaler.joblib            # Feature scaler
│   └── model_metadata.json      # Model info
├── data/                         # Training data
├── logs/                         # System logs
├── kaggle_train_ids.ipynb       # Kaggle training notebook
├── main.py                      # Main application
├── train.py                     # Local training script
└── docs/                        # Documentation
    ├── DEPLOYMENT.md            # Deployment guide
    └── API_REFERENCE.md         # API documentation
```

---

## 🎮 Usage Examples

### Live Capture with Custom Threshold

```bash
sudo venv/bin/python main.py --mode live --interface eth0 --threshold 0.95
```

### Enable Auto-Blocking

```bash
sudo venv/bin/python main.py --mode live --interface eth0 --auto-block
```

### Custom Dashboard Port

```bash
sudo venv/bin/python main.py --mode live --interface eth0 --dashboard-port 8888
```

### Demo Mode (No Root Required)

```bash
python main.py --mode demo
```

---

## 🔧 Configuration

Edit `config/config.py` to customize:

### Detection Settings
```python
DETECTOR_CONFIG = {
    'confidence_threshold': 0.95,  # Attack detection threshold
    'whitelist': ['127.0.0.1'],    # Trusted IPs
    'whitelist_subnets': [         # Trusted networks
        '10.0.0.0/8',
        '172.16.0.0/12',
    ],
}
```

### Dashboard Settings
```python
DASHBOARD_CONFIG = {
    'type': 'dash',
    'port': 8050,
    'host': '0.0.0.0',             # Use '127.0.0.1' for localhost only
    'enable_notifications': True,
    'enable_performance_monitoring': True,
}
```

### Firewall Settings
```python
PREVENTION_CONFIG = {
    'auto_block': False,           # Enable auto-blocking
    'block_duration': 3600,        # Seconds (1 hour)
}
```

---

## 📊 Dashboard Features

Access at **http://localhost:8050** after starting the system.

### Real-Time Monitoring
- **Live Statistics**: Total packets, attack rate, blocked IPs
- **Traffic Timeline**: Visual representation of normal vs attack traffic
- **Attack Distribution**: Breakdown by attack type

### Performance Monitoring
- **CPU Usage**: Real-time system CPU percentage
- **Memory Usage**: System memory tracking
- **Packet Rate**: Packets per second graph

### Alert System
- **Notification Badge**: Shows unread alert count
- **Alert Modal**: Detailed view of recent attacks
- **Recent Alerts Panel**: Last 10 attacks with full details

### Controls
- **Reset Button**: Clear all statistics
- **Live Status**: Connection status indicator
- **Auto-Refresh**: Updates every second

---

## 🎓 Training Models

The system uses pre-trained XGBoost models. To train new models, use the Kaggle notebook:

1. Open [Kaggle Notebooks](https://www.kaggle.com/code) and import `kaggle_train_ids.ipynb`
2. Add dataset: [CSE-CIC-IDS2018](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv)
3. Enable GPU (P100 or T4) and run all cells
4. Download trained models: `ids_model_xgboost.joblib`, `scaler.joblib`, `label_encoder.joblib`
5. Copy files to `models/` directory and restart the system

See [docs/KAGGLE_SETUP.md](docs/KAGGLE_SETUP.md) for detailed training instructions.

---

## 🐛 Troubleshooting

### Dashboard Won't Start

```bash
# Check dependencies
pip install dash dash-bootstrap-components psutil

# Check port availability
sudo lsof -i :8050
```

### False Positives on YouTube

The system includes streaming traffic detection heuristics. To further reduce false positives:

1. **Increase threshold**: Use `--threshold 0.98`
2. **Whitelist Google IPs**: Uncomment in `config/config.py`:
   ```python
   'whitelist_subnets': [
       '142.250.0.0/15',  # Google/YouTube
       '172.217.0.0/16',  # Google services
   ]
   ```

### Permission Errors

```bash
# Live capture requires sudo
sudo venv/bin/python main.py --mode live --interface eth0

# Or add user to pcap group
sudo usermod -a -G pcap $USER
```

### No Packets Captured

```bash
# Check interface name
ip a

# Verify interface is up
sudo ip link set eth0 up

# Check for other sniffers
sudo lsof -i | grep tcpdump
```

---

## 📚 Documentation

### 📖 Complete Documentation
👉 **[Documentation Index](docs/INDEX.md)** - Full documentation portal with all guides

### 🚀 Quick Links
| Document | Description |
|----------|-------------|
| [Dashboard Guide](docs/DASHBOARD.md) | Complete dashboard user guide |
| [Deployment Guide](docs/DEPLOYMENT.md) | Production deployment with systemd |
| [Attack Testing Guide](docs/ATTACK_TESTING_GUIDE.md) | Testing attack detection |
| [False Positive Mitigation](docs/FALSE_POSITIVE_MITIGATION.md) | Reduce false alarms |
| [Kaggle Training Guide](docs/KAGGLE_SETUP.md) | Model training workflow |
| [CIC-IDS2018 Guide](docs/CIC-IDS2018-GUIDE.md) | Dataset and features |

---

## 🔬 Testing

### Unit Tests
```bash
# Test dashboard
python test_dashboard.py

# Test false positive detection
python test_false_positives.py
```

### Attack Testing
Follow scenarios in [ATTACK_TESTING_GUIDE.md](ATTACK_TESTING_GUIDE.md):
- SYN Flood
- UDP Flood
- HTTP Flood
- Port Scan
- SSH Brute Force

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| **Detection Latency** | <10ms per packet |
| **CPU Overhead** | <2% (detection) + <1% (dashboard) |
| **Memory Usage** | ~100MB (model) + ~10MB (dashboard) |
| **Throughput** | 1000+ packets/second |
| **False Positive Rate** | <1% (with threshold 0.95) |

---

## 🛠️ Advanced Features

### Feature Adapter
Bridges live packet features with CIC-IDS2018 flow features:
- Flow tracking with 120s timeout
- Statistical aggregation
- Bidirectional flow analysis

### Smart Detection
- **Streaming Traffic Detection**: Reduces YouTube/Netflix false positives
- **Whitelist System**: Skip trusted IPs/subnets
- **Adaptive Thresholding**: Higher threshold for HTTPS streaming

### Metrics Logging
- Detection rate tracking
- Attack type distribution
- Performance monitoring
- Periodic summaries (every 1000 packets)

---

## 🤝 Contributing

This is an academic project. For improvements:

1. Test thoroughly with `test_dashboard.py`
2. Update documentation
3. Follow existing code style
4. Add comments for complex logic

---

## 📝 License

Academic project for educational purposes.

---

## 🏆 Credits

- **Dataset**: CIC-IDS2018 by Canadian Institute for Cybersecurity
- **ML Framework**: TensorFlow, scikit-learn, XGBoost, LightGBM
- **Dashboard**: Plotly Dash, Bootstrap
- **Packet Capture**: Scapy

---

## 📞 Support

### Quick Commands

```bash
# Setup
./setup_dashboard.sh

# Test
python test_dashboard.py

# Run
sudo venv/bin/python main.py --mode live --interface eth0

# Logs
tail -f logs/ids.log
```

### Common Issues

1. **Import errors**: Run `pip install -r requirements.txt`
2. **Port conflicts**: Use `--dashboard-port 8888`
3. **Permission denied**: Use `sudo` for live capture
4. **High false positives**: Increase `--threshold` to 0.98

---

**Version**: 2.0  
**Last Updated**: January 18, 2026  
**Status**: ✅ Production Ready  
**Dashboard**: http://localhost:8050

**Ví dụ:**
```python
from src.preprocessor import DataPreprocessor

preprocessor = DataPreprocessor(scaler_path='models/scaler.joblib')
processed = preprocessor.preprocess_packet(packet_info)
```

### 3. **Model Trainer** (`model_trainer.py`)
Tạo và huấn luyện các mô hình Deep Learning.

**Architectures:**
- **MLP**: Multilayer Perceptron (phổ biến, nhanh)
- **CNN**: Convolutional Neural Network (tốt cho pattern detection)
- **LSTM**: Long Short-Term Memory (tốt cho sequences)

**Ví dụ:**
```python
from src.model_trainer import AttackDetectionModel

model = AttackDetectionModel(input_dim=17, architecture='mlp')
history = model.train(X_train, y_train, epochs=50)
model.save('models/ids_model_mlp.keras')
```

### 4. **Detector** (`detector.py`)
Load mô hình và thực hiện phát hiện tấn công real-time.

**Classes:**
- 0: Normal
- 1: Teardrop
- 2: PingOfDeath
- 3: SynFlood
- 4: DNS_Amp

**Ví dụ:**
```python
from src.detector import DetectionEngine

detector = DetectionEngine(
    model_path='models/ids_model_mlp.keras',
    scaler_path='models/scaler.joblib',
    confidence_threshold=0.85
)

result = detector.detect(packet_info)
# Returns: {is_attack, attack_type, confidence, all_predictions}
```

### 5. **Prevention** (`prevention.py`)
Quản lý Firewall để chặn IPs tấn công.

**Hỗ trợ:**
- Linux: iptables
- Windows: netsh firewall

**Ví dụ:**
```python
from src.prevention import FirewallManager

firewall = FirewallManager(auto_block=True, block_duration=3600)
firewall.block_ip('192.168.1.100', reason='SYN Flood detected')
```

### 6. **Dashboard** (`dashboard.py`)
Giao diện Streamlit Dark Mode theo tiêu chuẩn SOC.

**Widgets:**
- 🟢/🔴 Status Indicator
- 📈 Live Traffic Graph (Normal vs Attack)
- 🎯 Attack Distribution (Donut chart)
- 🚨 Live Alerts Log
- ⚙️ Configuration Controls

---

## 📊 Configuration (`config/config.py`)

```python
# Sniffer
SNIFFER_CONFIG = {
    'interface': 'eth0',          # Interface name
    'packet_filter': None,        # BPF filter
    'use_mock': False,            # Testing mode
}

# Model
MODEL_CONFIG = {
    'architecture': 'mlp',        # mlp, cnn, lstm
    'epochs': 50,
    'batch_size': 32,
}

# Detection
DETECTOR_CONFIG = {
    'confidence_threshold': 0.85, # Alert threshold (0-1)
}

# Prevention
PREVENTION_CONFIG = {
    'auto_block': True,           # Auto-block attacks
    'block_duration': 3600,       # 1 hour
}
```

---

## 🔧 Command Line Options

```bash
python main.py [OPTIONS]

Options:
  --mode {live, demo, mock}     Operation mode (default: mock)
  --interface INTERFACE         Network interface (default: eth0)
  --auto-block                  Enable automatic IP blocking
  --threshold THRESHOLD         Confidence threshold (default: 0.85)
  --dashboard                   Launch Streamlit dashboard
```

---

## 📈 Demo Features

### Synthetic Data Generation
Script `train.py` sinh dữ liệu training giả lập theo loại tấn công:

```python
# Generate 2000 samples (400 per class)
X, y = generate_synthetic_data(n_samples=2000)
```

### Mock Components
Cho testing mà không cần:
- Root/Admin privileges
- Thực tế network interface
- TensorFlow/CUDA

---

## 🎯 Attack Detection Pipeline

```
[Network Packet] 
    ↓
[Sniffer] - Bắt gói tin từ interface
    ↓
[Preprocessor] - Extract 17 features + Scale
    ↓
[Deep Learning Model] - MLP/CNN/LSTM
    ↓
[Detector] - Phân loại (Normal/4 Attack types)
    ↓
[Prevention] - Auto-block IP nếu attack
    ↓
[Dashboard] - Real-time visualization
```

---

## 📋 Feature List

### Functional Requirements ✓

- ✓ FR-01: Real-time packet capture
- ✓ FR-02: Protocol filtering (ICMP, TCP, UDP)
- ✓ FR-03: Feature extraction (17 features)
- ✓ FR-04: Data scaling (StandardScaler)
- ✓ FR-05: Load Deep Learning model
- ✓ FR-06: Attack classification (5 classes)
- ✓ FR-07: Configurable confidence threshold
- ✓ FR-08: Firewall integration (iptables/netsh)
- ✓ FR-10: Real-time traffic metrics
- ✓ FR-11: Attack alerts
- ✓ FR-12: Auto-block toggle

### Non-Functional Requirements ✓

- ✓ Performance: <1s detection latency
- ✓ Compatibility: Linux + Windows (with fallback)
- ✓ Data Integrity: Same scaler for inference as training

---

## 🧪 Testing

### Unit Test Example
```python
# Test sniffer
from src.sniffer import MockPacketSniffer
sniffer = MockPacketSniffer(use_mock=True)

# Test detector
from src.detector import MockDetectionEngine
detector = MockDetectionEngine()
result = detector.detect({'src_ip': '192.168.1.1', ...})

# Test firewall
from src.prevention import MockFirewallManager
fw = MockFirewallManager(auto_block=True)
fw.block_ip('192.168.1.100')
```

---

## 📚 Dependencies

```
scapy>=2.5.0              # Packet sniffing
tensorflow>=2.12.0        # Deep Learning
scikit-learn>=1.3.0       # ML utilities
numpy>=1.23.0             # Numerical computing
pandas>=1.5.0             # Data manipulation
streamlit>=1.28.0         # Dashboard
plotly>=5.14.0            # Interactive charts
joblib>=1.3.0             # Model serialization
```

---

## 🚨 Important Notes

### Linux Setup
```bash
# Install dependencies
sudo apt-get install python3-pip python3-dev

# Run with sudo for real packet capture
sudo python main.py --mode live --interface eth0
```

### Windows Testing
```bash
# Use mock mode (no real interface needed)
python main.py --mode mock --dashboard
```

### Model Files
- Model sẽ được lưu tại: `models/ids_model_<arch>.keras`
- Scaler sẽ được lưu tại: `models/scaler.joblib`
- Đảm bảo sử dụng scaler giống như khi training!

---

## 📞 Troubleshooting

| Lỗi | Giải pháp |
|-----|----------|
| `Permission denied` on Linux | Chạy với `sudo` |
| `No module named 'tensorflow'` | `pip install tensorflow` |
| `Interface not found` | Check interface name: `ip link show` (Linux) |
| `Model not found` | Chạy `train.py` trước |

---

## 🎓 Educational Resources

- **Scapy**: https://scapy.readthedocs.io/
- **TensorFlow**: https://www.tensorflow.org/
- **Streamlit**: https://docs.streamlit.io/
- **Network Security**: https://owasp.org/

---

## 📝 License

Educational Project - BKHN

---

## 👨‍💻 Author

IDS/IPS Development Team

**Version**: 1.0  
**Last Updated**: 2024
