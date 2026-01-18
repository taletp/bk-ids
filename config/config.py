"""
Configuration file for IDS/IPS System
"""

import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
SRC_DIR = PROJECT_ROOT / "src"
DATA_DIR = PROJECT_ROOT / "data"
MODEL_DIR = PROJECT_ROOT / "models"
LOG_DIR = PROJECT_ROOT / "logs"
CONFIG_DIR = PROJECT_ROOT / "config"

# Ensure directories exist
for directory in [DATA_DIR, MODEL_DIR, LOG_DIR]:
    directory.mkdir(exist_ok=True)

# ========== SNIFFER CONFIGURATION ==========
SNIFFER_CONFIG = {
    'interface': 'eth0',  # Network interface to monitor (use 'ip a' to list)
    'packet_filter': None,  # BPF filter: 'tcp', 'icmp', 'udp', None for all
    'use_mock': False,  # Set True for testing without real interface
}

# ========== PREPROCESSING CONFIGURATION ==========
PREPROCESSING_CONFIG = {
    'window_size': 100,  # Sliding window for packet rate calculation
}

# ========== MODEL CONFIGURATION ==========
MODEL_CONFIG = {
    'input_dim': 17,  # Number of features
    'model_path': str(MODEL_DIR / "ids_model_xgboost.joblib"),
    'scaler_path': str(MODEL_DIR / "scaler.joblib"),
}

# ========== DETECTION ENGINE CONFIGURATION ==========
DETECTOR_CONFIG = {
    'model_path': MODEL_CONFIG['model_path'],
    'scaler_path': MODEL_CONFIG['scaler_path'],
    'confidence_threshold': 0.95,  # Only flag attacks if probability > 95%
    'use_mock': False,  # Set True for testing without real model
    
    # IP Whitelist - trusted IPs that should never be flagged as attacks
    'whitelist': [
        # '192.168.100.238',  # Host PC
        # '192.168.100.210',  # Guest VM Linux (Kali)
        '127.0.0.1',        # Localhost
        '::1',              # IPv6 localhost
    ],
    
    # Subnet whitelist (CIDR notation)
    'whitelist_subnets': [
        # '192.168.100.0/24',  # Local network
        '10.0.0.0/8',        # Private network
        '172.16.0.0/12',     # Private network
        # Uncomment below to whitelist Google/YouTube (reduces false positives for streaming)
        # '142.250.0.0/15',    # Google/YouTube primary range
        # '172.217.0.0/16',    # Google services
        # '216.58.0.0/16',     # YouTube CDN
    ],
}

# ========== PREVENTION CONFIGURATION ==========
PREVENTION_CONFIG = {
    'auto_block': True,  # Enable automatic IP blocking
    'block_duration': 3600,  # Block duration in seconds (1 hour)
    'use_mock': False,  # Set True for testing (no actual firewall changes)
}

# ========== DASHBOARD CONFIGURATION ==========
DASHBOARD_CONFIG = {
    'type': 'dash',  # 'dash' or 'streamlit'
    'port': 8050,  # Dash default port (Streamlit uses 8501)
    'host': '0.0.0.0',  # Listen on all interfaces
    'debug': False,
    'theme': 'dark',  # 'light' or 'dark'
    'refresh_interval': 1000,  # milliseconds
    'enable_notifications': True,
    'enable_performance_monitoring': True,
}

# ========== LOGGING CONFIGURATION ==========
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout',
        },
        'file': {
            'class': 'logging.FileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': str(LOG_DIR / 'ids_system.log'),
        },
    },
    'loggers': {
        '': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
        },
    },
}

# ========== ATTACK CLASSES ==========
# CIC-IDS2018 attack classes (full taxonomy)
ATTACK_CLASSES_CIC = {
    0: 'Benign',
    1: 'FTP-BruteForce',
    2: 'SSH-Bruteforce',
    3: 'DoS-GoldenEye',
    4: 'DoS-Slowloris',
    5: 'DoS-SlowHTTPTest',
    6: 'DoS-Hulk',
    7: 'Heartbleed',
    8: 'Web-BruteForce',
    9: 'Web-XSS',
    10: 'Infiltration',
    11: 'Botnet',
    12: 'DDoS-LOIC-HTTP',
    13: 'DDoS-HOIC',
}

# CIC-IDS2018 simplified (fewer categories)
ATTACK_CLASSES_SIMPLIFIED = {
    0: 'Normal',
    1: 'BruteForce',
    2: 'DoS',
    3: 'DDoS',
    4: 'Web',
    5: 'Exploit',
    6: 'Infiltration',
    7: 'Botnet',
}

# Active attack classes (configure which taxonomy to use)
ATTACK_CLASSES = ATTACK_CLASSES_SIMPLIFIED  # or ATTACK_CLASSES_CIC for full 14 classes

CLASS_TO_INDEX = {v: k for k, v in ATTACK_CLASSES.items()}

# ========== FEATURE NAMES ==========
FEATURE_NAMES = [
    'src_ip_numeric',
    'dst_ip_numeric',
    'total_length',
    'fragment_offset',
    'is_fragment',
    'payload_size',
    'ttl',
    'src_port',
    'dst_port',
    'tcp_syn_flag',
    'tcp_ack_flag',
    'tcp_fin_flag',
    'tcp_rst_flag',
    'window_size',
    'sequence_number',
    'udp_length',
    'packet_rate',
]

# ========== PERFORMANCE TUNING ==========
PERFORMANCE_CONFIG = {
    'max_packet_buffer': 10000,  # Maximum packets to keep in memory
    'detection_timeout': 1.0,  # Max seconds for detection per packet
    'batch_processing_size': 100,  # Process packets in batches
}

# ========== DEMO MODE CONFIGURATION ==========
# Set all use_mock flags to True for demo without real network interface
DEMO_MODE = False

if DEMO_MODE:
    SNIFFER_CONFIG['use_mock'] = True
    DETECTOR_CONFIG['use_mock'] = True
    PREVENTION_CONFIG['use_mock'] = True

print("Configuration loaded successfully")
