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
    'interface': 'eth0',  # Change to 'br0' for bridge, or your interface name
    'packet_filter': None,  # BPF filter: 'tcp', 'icmp', 'udp', None for all
    'use_mock': False,  # Set True for testing on Windows without real interface
}

# ========== PREPROCESSING CONFIGURATION ==========
PREPROCESSING_CONFIG = {
    'window_size': 100,  # Sliding window for packet rate calculation
    'scaler_type': 'StandardScaler',  # 'StandardScaler' or 'MinMaxScaler'
}

# ========== MODEL CONFIGURATION ==========
MODEL_CONFIG = {
    'architecture': 'mlp',  # 'mlp', 'cnn', or 'lstm'
    'input_dim': 17,  # Number of features
    'model_path': str(MODEL_DIR / "ids_model_mlp.keras"),
    'scaler_path': str(MODEL_DIR / "scaler.joblib"),
    
    # Training parameters
    'epochs': 50,
    'batch_size': 32,
    'validation_split': 0.2,
    'test_split': 0.1,
}

# ========== DETECTION ENGINE CONFIGURATION ==========
DETECTOR_CONFIG = {
    'model_path': MODEL_CONFIG['model_path'],
    'scaler_path': MODEL_CONFIG['scaler_path'],
    'confidence_threshold': 0.85,  # Only flag attacks if probability > 85%
    'architecture': MODEL_CONFIG['architecture'],
    'use_mock': False,  # Set True for testing
}

# ========== PREVENTION CONFIGURATION ==========
PREVENTION_CONFIG = {
    'auto_block': True,  # Enable automatic IP blocking
    'block_duration': 3600,  # Block duration in seconds (1 hour)
    'use_mock': False,  # Set True for testing (no actual firewall changes)
}

# ========== DASHBOARD CONFIGURATION ==========
DASHBOARD_CONFIG = {
    'port': 8501,
    'host': 'localhost',
    'debug': False,
    'theme': 'dark',  # 'light' or 'dark'
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
ATTACK_CLASSES = {
    0: 'Normal',
    1: 'Teardrop',
    2: 'PingOfDeath',
    3: 'SynFlood',
    4: 'DNS_Amp'
}

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
