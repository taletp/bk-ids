"""
Module Detection Engine: Load mô hình và thực hiện phát hiện tấn công real-time
"""

import logging
from typing import Dict, Tuple, Optional
import numpy as np
from datetime import datetime
from pathlib import Path
import joblib

try:
    from tensorflow import keras
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

from .preprocessor import DataPreprocessor

try:
    from .feature_adapter import FeatureAdapter
    FEATURE_ADAPTER_AVAILABLE = True
except ImportError:
    FEATURE_ADAPTER_AVAILABLE = False
    logging.warning("Feature adapter not available. CIC-IDS2018 models may not work correctly.")

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Engine phát hiện tấn công sử dụng mô hình Deep Learning
    
    Chịu trách nhiệm:
    1. Load mô hình đã train
    2. Load scaler
    3. Thực hiện inference trên packets
    4. Ra quyết định tấn công/bình thường
    """
    
    ATTACK_CLASSES = {
        0: 'Normal',
        1: 'Teardrop',
        2: 'PingOfDeath',
        3: 'SynFlood',
        4: 'DNS_Amp'
    }
    
    def __init__(self,
                 model_path: str,
                 scaler_path: str,
                 confidence_threshold: float = 0.85,
                 metadata_path: Optional[str] = None,
                 whitelist: Optional[list] = None,
                 whitelist_subnets: Optional[list] = None):
        """
        Khởi tạo Detection Engine
        
        Args:
            model_path: Đường dẫn tới file mô hình (.h5 hoặc .keras)
            scaler_path: Đường dẫn tới file scaler (.pkl hoặc .joblib)
            confidence_threshold: Ngưỡng confidence để báo tấn công (0.0-1.0)
            metadata_path: Path to model_metadata.json (for CIC-IDS2018 models)
            whitelist: List of trusted IP addresses
            whitelist_subnets: List of trusted subnets in CIDR notation
        """
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.confidence_threshold = confidence_threshold
        self.metadata_path = metadata_path
        self.whitelist = set(whitelist or [])
        self.whitelist_subnets = whitelist_subnets or []
        
        # Initialize components
        self.model = None
        self.preprocessor = None
        self.feature_adapter = None
        self.metadata = None
        
        # Load components
        self._load_metadata()
        self._load_model()
        self._load_preprocessor()
        self._initialize_feature_adapter()
        
        # Detection rate metrics
        self.metrics = {
            'total_packets': 0,
            'normal_packets': 0,
            'attack_packets': 0,
            'whitelisted_packets': 0,
            'errors': 0,
            'attack_types': {},
            'last_reset': datetime.now()
        }
        
        if self.whitelist:
            logger.info(f"IP whitelist enabled: {len(self.whitelist)} IPs")
        if self.whitelist_subnets:
            logger.info(f"Subnet whitelist enabled: {len(self.whitelist_subnets)} subnets")
        
        logger.info(f"DetectionEngine initialized. Confidence threshold: {confidence_threshold}")
    
    def _load_metadata(self):
        """Load model metadata if available"""
        if self.metadata_path and Path(self.metadata_path).exists():
            try:
                import json
                with open(self.metadata_path, 'r') as f:
                    self.metadata = json.load(f)
                logger.info(f"Metadata loaded from {self.metadata_path}")
                logger.info(f"Model type: {self.metadata.get('model_type')}")
                logger.info(f"Features: {self.metadata.get('n_features')}")
                logger.info(f"Classes: {self.metadata.get('n_classes')}")
                
                # Update ATTACK_CLASSES if metadata provides class names
                if 'class_names' in self.metadata:
                    self.ATTACK_CLASSES = {i: name for i, name in enumerate(self.metadata['class_names'])}
                    logger.info(f"Updated attack classes: {self.ATTACK_CLASSES}")
            except Exception as e:
                logger.warning(f"Could not load metadata: {e}")
                self.metadata = None
        else:
            # Try to auto-detect metadata file
            model_dir = Path(self.model_path).parent
            auto_metadata = model_dir / 'model_metadata.json'
            if auto_metadata.exists():
                self.metadata_path = str(auto_metadata)
                self._load_metadata()  # Recursive call with found path
    
    def _load_model(self):
        """Load mô hình (hỗ trợ cả Keras và scikit-learn models)"""
        try:
            model_path = Path(self.model_path)
            file_extension = model_path.suffix.lower()
            
            # Load scikit-learn models (.joblib, .pkl)
            if file_extension in ['.joblib', '.pkl']:
                self.model = joblib.load(self.model_path)
                self.model_type = 'sklearn'
                logger.info(f"Scikit-learn model loaded from {self.model_path}")
                logger.info(f"Model type: {type(self.model).__name__}")
            
            # Load Keras/TensorFlow models (.keras, .h5)
            elif file_extension in ['.keras', '.h5']:
                if not TF_AVAILABLE:
                    raise ImportError("TensorFlow is required for Keras models. Install with: pip install tensorflow")
                self.model = keras.models.load_model(self.model_path)
                self.model_type = 'keras'
                logger.info(f"Keras model loaded from {self.model_path}")
            
            else:
                raise ValueError(f"Unsupported model file format: {file_extension}. "
                               f"Supported formats: .joblib, .pkl (scikit-learn), .keras, .h5 (Keras)")
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
    
    def _load_preprocessor(self):
        """Load preprocessor với scaler"""
        try:
            self.preprocessor = DataPreprocessor(scaler_path=self.scaler_path)
            logger.info(f"Preprocessor loaded with scaler from {self.scaler_path}")
        except Exception as e:
            logger.error(f"Error loading preprocessor: {str(e)}")
            raise
    
    def _initialize_feature_adapter(self):
        """Initialize feature adapter for CIC-IDS2018 models"""
        if not FEATURE_ADAPTER_AVAILABLE:
            logger.warning("Feature adapter not available")
            return
        
        if self.metadata and 'feature_names' in self.metadata:
            try:
                feature_names = self.metadata['feature_names']
                self.feature_adapter = FeatureAdapter(
                    cic_feature_names=feature_names,
                    enable_flow_tracking=True
                )
                logger.info(f"Feature adapter initialized for {len(feature_names)} CIC features")
            except Exception as e:
                logger.warning(f"Could not initialize feature adapter: {e}")
                self.feature_adapter = None
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist"""
        if not ip:
            return False
        
        # Check direct IP whitelist
        if ip in self.whitelist:
            return True
        
        # Check subnet whitelist
        if self.whitelist_subnets:
            try:
                import ipaddress
                ip_obj = ipaddress.ip_address(ip)
                for subnet in self.whitelist_subnets:
                    if ip_obj in ipaddress.ip_network(subnet, strict=False):
                        return True
            except:
                pass
        
        return False
    
    def _is_streaming_traffic(self, packet_info: dict, flow_features: dict = None) -> bool:
        """Detect video streaming traffic patterns to reduce false positives
        
        Streaming characteristics:
        - HTTPS ports (443, 8443)
        - Large packets (near MTU ~1400-1500 bytes)
        - Sustained moderate packet rates (not flood-level)
        - Long-lived connections (>10 seconds)
        """
        if not flow_features:
            return False
        
        try:
            # Check for HTTPS
            dst_port = packet_info.get('dst_port', 0)
            is_https = dst_port in [443, 8443]
            
            # Check packet size (streaming uses large packets efficiently)
            avg_pkt_size = flow_features.get('fwd_pkt_len_mean', 0)
            is_large_packets = avg_pkt_size > 1200  # Near MTU size
            
            # Check flow duration (streaming = sustained connection)
            duration_us = flow_features.get('flow_duration', 0)
            is_sustained = duration_us > 10_000_000  # >10 seconds
            
            # Check packet rate (streaming = moderate, not flood-level)
            tot_pkts = flow_features.get('tot_fwd_pkts', 0)
            duration_s = duration_us / 1_000_000 if duration_us > 0 else 1
            pkt_rate = tot_pkts / duration_s
            is_moderate_rate = 10 < pkt_rate < 500  # Between normal and flood
            
            # Heuristic: likely streaming if all conditions met
            return is_https and is_large_packets and is_sustained and is_moderate_rate
            
        except Exception as e:
            logger.debug(f"Error checking streaming traffic: {e}")
            return False
    
    def detect(self, packet_info: Dict) -> Dict:
        """
        Phát hiện tấn công từ một gói tin
        
        Args:
            packet_info: Dictionary chứa thông tin gói tin từ Sniffer
            
        Returns:
            Dictionary chứa kết quả phát hiện:
            {
                'timestamp': str,
                'src_ip': str,
                'dst_ip': str,
                'protocol': str,
                'is_attack': bool,
                'attack_type': str,
                'confidence': float,
                'features': list (optional, cho debug)
            }
        """
        try:
            # Check whitelist first - skip detection for trusted IPs
            src_ip = packet_info.get('src_ip', '')
            dst_ip = packet_info.get('dst_ip', '')
            
            if self._is_whitelisted(src_ip) or self._is_whitelisted(dst_ip):
                self.metrics['total_packets'] += 1
                self.metrics['whitelisted_packets'] += 1
                self.metrics['normal_packets'] += 1
                return {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': packet_info.get('protocol', 'unknown'),
                    'src_port': packet_info.get('src_port'),
                    'dst_port': packet_info.get('dst_port'),
                    'is_attack': False,
                    'attack_type': 'Normal',
                    'confidence': 1.0,
                    'whitelisted': True
                }
            
            # Check if we need to use feature adapter for CIC-IDS2018 models
            flow_features = None
            if self.feature_adapter:
                # Use feature adapter to convert packet to CIC features
                processed_features = self.feature_adapter.adapt_packet_to_cic(packet_info)
                # Get flow features for streaming detection
                flow_key = self.feature_adapter.flow_tracker._get_flow_key(packet_info)
                if flow_key in self.feature_adapter.flow_tracker.flows:
                    flow_features = self.feature_adapter.flow_tracker.get_flow_features(packet_info)
            else:
                # Use standard preprocessor for packet-level features
                processed_features = self.preprocessor.preprocess_packet(packet_info)
            
            if processed_features is None:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': packet_info.get('src_ip', 'unknown'),
                    'dst_ip': packet_info.get('dst_ip', 'unknown'),
                    'protocol': packet_info.get('protocol', 'unknown'),
                    'is_attack': False,
                    'attack_type': 'Unknown',
                    'confidence': 0.0,
                    'error': 'Feature extraction failed'
                }
            
            # Reshape for model input
            X = processed_features.reshape(1, -1)
            
            # Predict based on model type
            if self.model_type == 'sklearn':
                # Scikit-learn models (Random Forest, XGBoost, etc.)
                predictions_proba = self.model.predict_proba(X)
                predictions = predictions_proba
                predicted_class = np.argmax(predictions[0])
                confidence = float(np.max(predictions[0]))
            else:
                # Keras/TensorFlow models
                predictions = self.model.predict(X, verbose=0)
                predicted_class = np.argmax(predictions[0])
                confidence = float(np.max(predictions[0]))
            
            # Determine if it's an attack
            threshold = self.confidence_threshold
            
            # Check for streaming traffic - use higher threshold to reduce false positives
            is_likely_streaming = self._is_streaming_traffic(packet_info, flow_features)
            if is_likely_streaming:
                threshold = min(0.98, threshold + 0.05)  # Increase threshold by 5% for streaming
                logger.debug(f"Streaming traffic detected, using higher threshold: {threshold:.2%}")
            
            is_attack = (predicted_class != 0) and (confidence >= threshold)
            
            attack_type = self.ATTACK_CLASSES.get(predicted_class, 'Unknown')
            
            # Final result
            if not is_attack and predicted_class != 0 and confidence < threshold:
                # Confidence too low, treat as Normal
                attack_type = 'Normal'
                if is_likely_streaming:
                    logger.debug(f"Streaming traffic classified as Normal (confidence: {confidence:.2%} < {threshold:.2%})")
            elif not is_attack:
                attack_type = 'Normal'
            
            # Update metrics
            self.metrics['total_packets'] += 1
            if is_attack:
                self.metrics['attack_packets'] += 1
                if attack_type not in self.metrics['attack_types']:
                    self.metrics['attack_types'][attack_type] = 0
                self.metrics['attack_types'][attack_type] += 1
                
                # Log attack with WARNING level
                logger.warning(
                    f"Attack detected: {attack_type} | {src_ip}:{packet_info.get('src_port', '?')} -> "
                    f"{packet_info.get('dst_ip', 'unknown')}:{packet_info.get('dst_port', '?')} | "
                    f"Confidence: {confidence:.2%} | Protocol: {packet_info.get('protocol', 'unknown')}"
                )
            else:
                self.metrics['normal_packets'] += 1
                # Log normal traffic at DEBUG level only
                logger.debug(
                    f"Normal traffic: {src_ip} -> {packet_info.get('dst_ip', 'unknown')} | "
                    f"Protocol: {packet_info.get('protocol', 'unknown')} | Confidence: {confidence:.2%}"
                )
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': packet_info.get('src_ip', 'unknown'),
                'dst_ip': packet_info.get('dst_ip', 'unknown'),
                'protocol': packet_info.get('protocol', 'unknown'),
                'src_port': packet_info.get('src_port'),
                'dst_port': packet_info.get('dst_port'),
                'is_attack': is_attack,
                'attack_type': attack_type,
                'confidence': confidence,
                'all_predictions': {
                    self.ATTACK_CLASSES[i]: float(predictions[0][i]) 
                    for i in range(len(self.ATTACK_CLASSES))
                }
            }
            
            return result
        
        except Exception as e:
            self.metrics['total_packets'] += 1
            self.metrics['errors'] += 1
            logger.error(f"Error during detection: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'src_ip': packet_info.get('src_ip', 'unknown'),
                'dst_ip': packet_info.get('dst_ip', 'unknown'),
                'protocol': packet_info.get('protocol', 'unknown'),
                'is_attack': False,
                'attack_type': 'Error',
                'confidence': 0.0,
                'error': str(e)
            }
    
    def detect_batch(self, packets: list) -> list:
        """
        Phát hiện tấn công từ batch gói tin
        
        Args:
            packets: List các packet_info dictionaries
            
        Returns:
            List các detection results
        """
        results = []
        for packet_info in packets:
            result = self.detect(packet_info)
            results.append(result)
        return results
    
    def update_threshold(self, new_threshold: float):
        """
        Cập nhật ngưỡng confidence
        
        Args:
            new_threshold: Giá trị threshold mới (0.0-1.0)
        """
        if 0.0 <= new_threshold <= 1.0:
            self.confidence_threshold = new_threshold
            logger.info(f"Confidence threshold updated to {new_threshold}")
        else:
            logger.warning(f"Invalid threshold value: {new_threshold}")
    
    def get_model_info(self) -> Dict:
        """Lấy thông tin mô hình"""
        try:
            return {
                'model_path': self.model_path,
                'scaler_path': self.scaler_path,
                'confidence_threshold': self.confidence_threshold,
                'input_shape': self.model.input_shape,
                'total_params': self.model.count_params()
            }
        except:
            return {
                'error': 'Could not retrieve model info'
            }
    
    def get_detection_metrics(self) -> Dict:
        """Get detection rate metrics"""
        total = self.metrics['total_packets']
        if total == 0:
            return {
                'total_packets': 0,
                'detection_rate': 0.0,
                'false_negative_rate': 0.0,
                'normal_rate': 0.0,
                'attack_rate': 0.0,
                'whitelist_rate': 0.0,
                'error_rate': 0.0,
                'attack_distribution': {},
                'uptime_seconds': (datetime.now() - self.metrics['last_reset']).total_seconds()
            }
        
        return {
            'total_packets': total,
            'normal_packets': self.metrics['normal_packets'],
            'attack_packets': self.metrics['attack_packets'],
            'whitelisted_packets': self.metrics['whitelisted_packets'],
            'errors': self.metrics['errors'],
            'normal_rate': self.metrics['normal_packets'] / total * 100,
            'attack_rate': self.metrics['attack_packets'] / total * 100,
            'whitelist_rate': self.metrics['whitelisted_packets'] / total * 100,
            'error_rate': self.metrics['errors'] / total * 100,
            'attack_distribution': dict(self.metrics['attack_types']),
            'uptime_seconds': (datetime.now() - self.metrics['last_reset']).total_seconds()
        }
    
    def reset_metrics(self):
        """Reset detection metrics"""
        self.metrics = {
            'total_packets': 0,
            'normal_packets': 0,
            'attack_packets': 0,
            'whitelisted_packets': 0,
            'errors': 0,
            'attack_types': {},
            'last_reset': datetime.now()
        }
        logger.info("Detection metrics reset")
    
    def log_metrics_summary(self):
        """Log a summary of detection metrics"""
        metrics = self.get_detection_metrics()
        uptime = metrics['uptime_seconds']
        
        logger.info("=" * 60)
        logger.info("Detection Metrics Summary")
        logger.info("=" * 60)
        logger.info(f"Uptime: {uptime:.1f}s ({uptime/60:.1f}m)")
        logger.info(f"Total Packets: {metrics['total_packets']:,}")
        logger.info(f"  Normal: {metrics['normal_packets']:,} ({metrics['normal_rate']:.1f}%)")
        logger.info(f"  Attacks: {metrics['attack_packets']:,} ({metrics['attack_rate']:.1f}%)")
        logger.info(f"  Whitelisted: {metrics['whitelisted_packets']:,} ({metrics['whitelist_rate']:.1f}%)")
        logger.info(f"  Errors: {metrics['errors']:,} ({metrics['error_rate']:.1f}%)")
        
        if metrics['attack_distribution']:
            logger.info("\nAttack Distribution:")
            for attack_type, count in sorted(metrics['attack_distribution'].items(), key=lambda x: x[1], reverse=True):
                percentage = count / metrics['attack_packets'] * 100 if metrics['attack_packets'] > 0 else 0
                logger.info(f"  {attack_type}: {count:,} ({percentage:.1f}% of attacks)")
        
        if uptime > 0:
            pps = metrics['total_packets'] / uptime
            logger.info(f"\nPackets per second: {pps:.2f}")
        
        logger.info("=" * 60)


# Mock Detection Engine cho testing
class MockDetectionEngine:
    """Mock Detection Engine cho testing trên Windows"""
    
    ATTACK_CLASSES = {
        0: 'Normal',
        1: 'Teardrop',
        2: 'PingOfDeath',
        3: 'SynFlood',
        4: 'DNS_Amp'
    }
    
    def __init__(self, model_path: str = None, scaler_path: str = None,
                 confidence_threshold: float = 0.85, architecture: str = 'mlp'):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.confidence_threshold = confidence_threshold
        self.architecture = architecture
        logger.warning("Using MockDetectionEngine (no model inference)")
    
    def detect(self, packet_info: Dict) -> Dict:
        """Simulate detection"""
        import random
        
        # Simulated detection logic
        is_normal = random.random() > 0.1  # 90% normal
        
        if is_normal:
            attack_type = 'Normal'
            confidence = random.uniform(0.85, 1.0)
            is_attack = False
        else:
            attack_types = list(range(1, 5))
            predicted_class = random.choice(attack_types)
            attack_type = self.ATTACK_CLASSES[predicted_class]
            confidence = random.uniform(self.confidence_threshold, 1.0)
            is_attack = True
        
        return {
            'timestamp': datetime.now().isoformat(),
            'src_ip': packet_info.get('src_ip', 'unknown'),
            'dst_ip': packet_info.get('dst_ip', 'unknown'),
            'protocol': packet_info.get('protocol', 'unknown'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'is_attack': is_attack,
            'attack_type': attack_type,
            'confidence': confidence,
            'all_predictions': {
                'Normal': random.uniform(0, 1),
                'Teardrop': random.uniform(0, 1),
                'PingOfDeath': random.uniform(0, 1),
                'SynFlood': random.uniform(0, 1),
                'DNS_Amp': random.uniform(0, 1)
            }
        }
    
    def detect_batch(self, packets: list) -> list:
        return [self.detect(p) for p in packets]
    
    def update_threshold(self, new_threshold: float):
        self.confidence_threshold = new_threshold


# No-op Detection Engine: used as a safe fallback in LIVE mode when TF is missing
class NoopDetectionEngine:
    """A safe detection engine that always reports 'Normal' (no attacks).

    Use this in LIVE deployments when the real model cannot be loaded to avoid
    generating noisy, randomized alerts from the mock engine.
    """

    def __init__(self, model_path: str = None, scaler_path: str = None,
                 confidence_threshold: float = 0.85, architecture: str = 'mlp'):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.confidence_threshold = confidence_threshold
        self.architecture = architecture
        logger.info("Using NoopDetectionEngine (always Normal)")

    def detect(self, packet_info: Dict) -> Dict:
        return {
            'timestamp': datetime.now().isoformat(),
            'src_ip': packet_info.get('src_ip', 'unknown'),
            'dst_ip': packet_info.get('dst_ip', 'unknown'),
            'protocol': packet_info.get('protocol', 'unknown'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'is_attack': False,
            'attack_type': 'Normal',
            'confidence': 1.0,
            'all_predictions': {k: 0.0 for k in MockDetectionEngine.ATTACK_CLASSES.values()}
        }

    def detect_batch(self, packets: list) -> list:
        return [self.detect(p) for p in packets]

    def update_threshold(self, new_threshold: float):
        self.confidence_threshold = new_threshold

    
    def log_metrics_summary(self):
        """Log a summary of metrics (noop mode - always normal)"""
        logger.info("=" * 60)
        logger.info("NoopDetectionEngine Metrics Summary (Safe Mode)")
        logger.info("=" * 60)
        logger.info("This engine always classifies packets as 'Normal'")
        logger.info("Use in production when model cannot be loaded")
        logger.info("No attacks will be reported (safe fallback mode)")
