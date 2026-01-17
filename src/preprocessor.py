"""
Module Preprocessing: Trích xuất đặc trưng (Feature Extraction) từ gói tin
và áp dụng Scaling sử dụng Scaler đã lưu từ quá trình training
"""

import logging
import joblib
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import deque

try:
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("Scikit-learn not installed. Scaling will be disabled.")

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Trích xuất đặc trưng từ gói tin theo 4 loại tấn công:
    1. Teardrop: Fragment Offset, IP Flags (MF), ID
    2. Ping of Death: Total Length, Data payload size
    3. SYN Flood: TCP Flags, Window Size, Sequence Number, Flag Count
    4. DNS Amplification: UDP Length, Source/Dest Port, Packet Rate
    """
    
    # Danh sách features cho mô hình
    FEATURE_NAMES = [
        'src_ip_numeric',      # Convert IP to numeric
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
        'packet_rate',  # Tính từ packet rate trong sliding window
    ]
    
    def __init__(self, window_size: int = 100):
        """
        Khởi tạo Feature Extractor
        
        Args:
            window_size: Kích thước cửa sổ trượt để tính packet rate
        """
        self.window_size = window_size
        self.packet_timestamps = deque(maxlen=window_size)
        
        logger.info(f"FeatureExtractor initialized with window_size={window_size}")
    
    @staticmethod
    def _ip_to_numeric(ip_str: str) -> float:
        """Chuyển IP string thành số"""
        try:
            parts = ip_str.split('.')
            return float(int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + 
                        int(parts[2]) * 256 + int(parts[3]))
        except:
            return 0.0
    
    def _calculate_packet_rate(self) -> float:
        """Tính packet rate (packets/second) từ sliding window"""
        if len(self.packet_timestamps) < 2:
            return 0.0
        
        time_diff = (self.packet_timestamps[-1] - self.packet_timestamps[0]).total_seconds()
        if time_diff == 0:
            return float(len(self.packet_timestamps))
        
        return len(self.packet_timestamps) / time_diff
    
    def _extract_tcp_flags(self, flags_str: str) -> Dict[str, int]:
        """
        Trích xuất cờ TCP từ string flags
        
        Args:
            flags_str: String flags từ gói tin (ví dụ: 'S', 'SA', 'A', etc.)
            
        Returns:
            Dict với các cờ TCP dưới dạng nhị phân
        """
        flags = {
            'syn': 0,
            'ack': 0,
            'fin': 0,
            'rst': 0,
        }
        
        if flags_str:
            flags_upper = flags_str.upper()
            flags['syn'] = 1 if 'S' in flags_upper else 0
            flags['ack'] = 1 if 'A' in flags_upper else 0
            flags['fin'] = 1 if 'F' in flags_upper else 0
            flags['rst'] = 1 if 'R' in flags_upper else 0
        
        return flags
    
    def extract_features(self, packet_info: Dict) -> Optional[np.ndarray]:
        """
        Trích xuất tất cả features từ gói tin
        
        Args:
            packet_info: Dictionary chứa thông tin gói tin từ Sniffer
            
        Returns:
            Numpy array chứa features, hoặc None nếu packet không hợp lệ
        """
        try:
            # Update packet timestamp để tính packet rate
            self.packet_timestamps.append(datetime.now())
            
            features = []
            
            # IP features
            src_ip_num = self._ip_to_numeric(packet_info.get('src_ip', '0.0.0.0'))
            dst_ip_num = self._ip_to_numeric(packet_info.get('dst_ip', '0.0.0.0'))
            features.append(src_ip_num)
            features.append(dst_ip_num)
            
            # IP layer features
            features.append(float(packet_info.get('total_length', 0)))
            features.append(float(packet_info.get('fragment_offset', 0)))
            features.append(float(packet_info.get('is_fragment', 0)))
            features.append(float(packet_info.get('payload_size', 0)))
            features.append(float(packet_info.get('ttl', 64)))
            
            # Port features
            features.append(float(packet_info.get('src_port', 0)))
            features.append(float(packet_info.get('dst_port', 0)))
            
            # TCP flags (nếu là TCP packet)
            tcp_flags = self._extract_tcp_flags(packet_info.get('flags', ''))
            features.append(float(tcp_flags['syn']))
            features.append(float(tcp_flags['ack']))
            features.append(float(tcp_flags['fin']))
            features.append(float(tcp_flags['rst']))
            
            # TCP additional features (từ raw packet nếu có)
            # Placeholder cho window_size và sequence_number
            features.append(65535.0)  # default window size
            features.append(0.0)       # default sequence number
            
            # UDP features
            features.append(float(packet_info.get('payload_size', 0)))
            
            # Packet rate
            packet_rate = self._calculate_packet_rate()
            features.append(packet_rate)
            
            return np.array(features, dtype=np.float32)
        
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            return None


class DataPreprocessor:
    """
    Tiền xử lý dữ liệu: Feature Extraction + Scaling
    """
    
    def __init__(self, scaler_path: Optional[str] = None):
        """
        Khởi tạo Preprocessor
        
        Args:
            scaler_path: Đường dẫn tới file scaler đã lưu (.pkl hoặc .joblib)
        """
        self.feature_extractor = FeatureExtractor()
        self.scaler = None
        self.is_fitted = False
        
        if scaler_path:
            self.load_scaler(scaler_path)
        else:
            # Tạo scaler mới (sẽ được fit sau khi huấn luyện)
            self.scaler = StandardScaler()
    
    def load_scaler(self, scaler_path: str):
        """Load scaler từ file"""
        try:
            self.scaler = joblib.load(scaler_path)
            self.is_fitted = True
            logger.info(f"Scaler loaded from {scaler_path}")
        except Exception as e:
            logger.error(f"Error loading scaler: {str(e)}")
            raise
    
    def save_scaler(self, scaler_path: str):
        """Lưu scaler vào file"""
        try:
            if self.scaler and self.is_fitted:
                joblib.dump(self.scaler, scaler_path)
                logger.info(f"Scaler saved to {scaler_path}")
            else:
                logger.warning("Scaler is not fitted yet")
        except Exception as e:
            logger.error(f"Error saving scaler: {str(e)}")
    
    def fit_scaler(self, X_train: np.ndarray):
        """
        Fit scaler trên training data
        
        Args:
            X_train: Training features (n_samples, n_features)
        """
        try:
            self.scaler.fit(X_train)
            self.is_fitted = True
            logger.info("Scaler fitted on training data")
        except Exception as e:
            logger.error(f"Error fitting scaler: {str(e)}")
    
    def preprocess_packet(self, packet_info: Dict) -> Optional[np.ndarray]:
        """
        Tiền xử lý một gói tin: extract features + scale
        
        Args:
            packet_info: Dictionary chứa thông tin gói tin
            
        Returns:
            Scaled features (1D array) hoặc None
        """
        # Extract features
        features = self.feature_extractor.extract_features(packet_info)
        
        if features is None:
            return None
        
        # Scale features
        if self.scaler and self.is_fitted:
            try:
                # Reshape để scale (scaler expects 2D input)
                features_reshaped = features.reshape(1, -1)
                scaled_features = self.scaler.transform(features_reshaped)
                return scaled_features[0]  # Return 1D array
            except Exception as e:
                logger.error(f"Error scaling features: {str(e)}")
                return None
        else:
            logger.warning("Scaler not fitted. Returning unscaled features.")
            return features
    
    def preprocess_batch(self, packets: List[Dict]) -> Optional[np.ndarray]:
        """
        Tiền xử lý batch gói tin
        
        Args:
            packets: List các packet_info dictionaries
            
        Returns:
            Scaled features (n_samples, n_features) hoặc None
        """
        features_list = []
        
        for packet_info in packets:
            features = self.feature_extractor.extract_features(packet_info)
            if features is not None:
                features_list.append(features)
        
        if not features_list:
            return None
        
        X = np.array(features_list, dtype=np.float32)
        
        # Scale features
        if self.scaler and self.is_fitted:
            try:
                X_scaled = self.scaler.transform(X)
                return X_scaled
            except Exception as e:
                logger.error(f"Error scaling batch: {str(e)}")
                return None
        else:
            logger.warning("Scaler not fitted. Returning unscaled features.")
            return X
    
    def get_feature_names(self) -> List[str]:
        """Lấy tên các features"""
        return FeatureExtractor.FEATURE_NAMES.copy()
    
    def get_feature_count(self) -> int:
        """Lấy số lượng features"""
        return len(FeatureExtractor.FEATURE_NAMES)
