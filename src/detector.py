"""
Module Detection Engine: Load mô hình và thực hiện phát hiện tấn công real-time
"""

import logging
from typing import Dict, Tuple, Optional
import numpy as np
from datetime import datetime

try:
    from tensorflow import keras
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

from .preprocessor import DataPreprocessor
from .model_trainer import AttackDetectionModel

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
                 architecture: str = 'mlp'):
        """
        Khởi tạo Detection Engine
        
        Args:
            model_path: Đường dẫn tới file mô hình (.h5 hoặc .keras)
            scaler_path: Đường dẫn tới file scaler (.pkl hoặc .joblib)
            confidence_threshold: Ngưỡng confidence để báo tấn công (0.0-1.0)
            architecture: Loại mô hình ('mlp', 'cnn', 'lstm')
        """
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.confidence_threshold = confidence_threshold
        self.architecture = architecture
        
        # Initialize components
        self.model = None
        self.preprocessor = None
        
        # Load components
        self._load_model()
        self._load_preprocessor()
        
        logger.info(f"DetectionEngine initialized. Confidence threshold: {confidence_threshold}")
    
    def _load_model(self):
        """Load mô hình Deep Learning"""
        try:
            if not TF_AVAILABLE:
                raise ImportError("TensorFlow is required. Install with: pip install tensorflow")
            
            self.model = keras.models.load_model(self.model_path)
            logger.info(f"Model loaded from {self.model_path}")
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
            # Preprocess packet
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
            
            # Reshape cho mô hình
            if self.architecture in ['cnn', 'lstm']:
                X = processed_features.reshape(1, len(processed_features), 1)
            else:
                X = processed_features.reshape(1, -1)
            
            # Predict
            predictions = self.model.predict(X, verbose=0)
            predicted_class = np.argmax(predictions[0])
            confidence = float(np.max(predictions[0]))
            
            # Determine if it's an attack
            is_attack = (predicted_class != 0) and (confidence >= self.confidence_threshold)
            
            attack_type = self.ATTACK_CLASSES.get(predicted_class, 'Unknown')
            
            # Final result
            if not is_attack and predicted_class != 0 and confidence < self.confidence_threshold:
                # Confidence too low, treat as Normal
                attack_type = 'Normal'
            elif not is_attack:
                attack_type = 'Normal'
            
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
                'architecture': self.architecture,
                'confidence_threshold': self.confidence_threshold,
                'input_shape': self.model.input_shape,
                'total_params': self.model.count_params()
            }
        except:
            return {
                'error': 'Could not retrieve model info'
            }


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
