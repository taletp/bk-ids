"""
__init__.py for IDS/IPS modules
"""

from .sniffer import PacketSniffer, MockPacketSniffer, get_sniffer
from .preprocessor import FeatureExtractor, DataPreprocessor
from .model_trainer import AttackDetectionModel
from .detector import DetectionEngine, MockDetectionEngine
from .prevention import FirewallManager, MockFirewallManager

__all__ = [
    'PacketSniffer',
    'MockPacketSniffer',
    'get_sniffer',
    'FeatureExtractor',
    'DataPreprocessor',
    'AttackDetectionModel',
    'DetectionEngine',
    'MockDetectionEngine',
    'FirewallManager',
    'MockFirewallManager',
]

__version__ = '1.0.0'
__author__ = 'IDS/IPS Team'
