"""
Feature Adapter: Maps live packet features to CIC-IDS2018 trained model features

This module bridges the gap between:
- Live packet capture (17 packet-level features from Scapy)
- CIC-IDS2018 trained models (17 flow-level statistical features)

The adapter approximates flow statistics using packet-level data.
"""

import numpy as np
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class FlowTracker:
    """
    Track flow statistics to approximate CIC-IDS2018 features
    """
    
    def __init__(self, timeout_seconds: int = 120):
        """
        Args:
            timeout_seconds: Flow timeout (default 120s for CIC-IDS2018)
        """
        self.flows = defaultdict(lambda: {
            'packets': deque(maxlen=1000),
            'timestamps': deque(maxlen=1000),
            'flags': defaultdict(int),
            'fwd_lengths': [],
            'bwd_lengths': [],
            'last_seen': datetime.now(),
        })
        self.timeout = timedelta(seconds=timeout_seconds)
        
    def _get_flow_key(self, packet_info: Dict) -> tuple:
        """Create flow key from packet"""
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol', 0)
        
        # Bidirectional flow key (sort IPs to match both directions)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            return (dst_ip, dst_port, src_ip, src_port, protocol)
    
    def update_flow(self, packet_info: Dict):
        """Update flow statistics with new packet"""
        flow_key = self._get_flow_key(packet_info)
        flow = self.flows[flow_key]
        
        now = datetime.now()
        flow['last_seen'] = now
        flow['timestamps'].append(now)
        
        # Track packet lengths
        length = packet_info.get('total_length', 0)
        flow['packets'].append(packet_info)
        
        # Determine direction (forward = src->dst in flow key)
        is_forward = (packet_info.get('src_ip'), packet_info.get('src_port')) == flow_key[:2]
        if is_forward:
            flow['fwd_lengths'].append(length)
        else:
            flow['bwd_lengths'].append(length)
        
        # Track TCP flags
        flags = packet_info.get('flags', '')
        if 'S' in str(flags):
            flow['flags']['syn'] += 1
        if 'A' in str(flags):
            flow['flags']['ack'] += 1
        if 'F' in str(flags):
            flow['flags']['fin'] += 1
        if 'R' in str(flags):
            flow['flags']['rst'] += 1
        if 'P' in str(flags):
            flow['flags']['psh'] += 1
        if 'U' in str(flags):
            flow['flags']['urg'] += 1
    
    def get_flow_features(self, packet_info: Dict) -> Dict:
        """Get flow statistics for packet"""
        flow_key = self._get_flow_key(packet_info)
        flow = self.flows[flow_key]
        
        # Calculate features
        timestamps = list(flow['timestamps'])
        fwd_lengths = flow['fwd_lengths']
        bwd_lengths = flow['bwd_lengths']
        
        # Flow duration
        if len(timestamps) > 1:
            duration = (timestamps[-1] - timestamps[0]).total_seconds() * 1000000  # microseconds
        else:
            duration = 0
        
        # Packet counts
        tot_fwd_pkts = len(fwd_lengths)
        tot_bwd_pkts = len(bwd_lengths)
        
        # Total lengths
        totlen_fwd = sum(fwd_lengths) if fwd_lengths else 0
        totlen_bwd = sum(bwd_lengths) if bwd_lengths else 0
        
        # Packet length statistics (forward)
        if fwd_lengths:
            fwd_len_max = max(fwd_lengths)
            fwd_len_min = min(fwd_lengths)
            fwd_len_mean = np.mean(fwd_lengths)
        else:
            fwd_len_max = fwd_len_min = fwd_len_mean = 0
        
        # Inter-arrival times (IAT)
        if len(timestamps) > 1:
            iats = [(timestamps[i+1] - timestamps[i]).total_seconds() * 1000000 
                    for i in range(len(timestamps)-1)]
            flow_iat_mean = np.mean(iats) if iats else 0
            fwd_iat_mean = flow_iat_mean  # Simplified approximation
        else:
            flow_iat_mean = fwd_iat_mean = 0
        
        return {
            'flow_duration': duration,
            'tot_fwd_pkts': tot_fwd_pkts,
            'tot_bwd_pkts': tot_bwd_pkts,
            'totlen_fwd_pkts': totlen_fwd,
            'totlen_bwd_pkts': totlen_bwd,
            'fwd_pkt_len_max': fwd_len_max,
            'fwd_pkt_len_min': fwd_len_min,
            'fwd_pkt_len_mean': fwd_len_mean,
            'flow_iat_mean': flow_iat_mean,
            'fwd_iat_mean': fwd_iat_mean,
            'psh_flag_cnt': flow['flags']['psh'],
            'urg_flag_cnt': flow['flags']['urg'],
            'fin_flag_cnt': flow['flags']['fin'],
            'syn_flag_cnt': flow['flags']['syn'],
            'rst_flag_cnt': flow['flags']['rst'],
            'ack_flag_cnt': flow['flags']['ack'],
        }
    
    def cleanup_old_flows(self):
        """Remove expired flows"""
        now = datetime.now()
        expired = [k for k, v in self.flows.items() 
                   if now - v['last_seen'] > self.timeout]
        for k in expired:
            del self.flows[k]


class FeatureAdapter:
    """
    Adapt live packet features to match CIC-IDS2018 training features
    """
    
    def __init__(self, cic_feature_names: List[str], enable_flow_tracking: bool = True):
        """
        Args:
            cic_feature_names: List of 17 feature names from CIC-IDS2018 model
            enable_flow_tracking: Enable flow tracking for better approximation
        """
        self.cic_features = cic_feature_names
        self.flow_tracker = FlowTracker() if enable_flow_tracking else None
        self.enable_flow_tracking = enable_flow_tracking
        
        logger.info(f"FeatureAdapter initialized with {len(cic_feature_names)} features")
        logger.info(f"Flow tracking: {'enabled' if enable_flow_tracking else 'disabled'}")
    
    def adapt_packet_to_cic(self, packet_info: Dict) -> Optional[np.ndarray]:
        """
        Convert live packet features to CIC-IDS2018 feature format
        
        Args:
            packet_info: Dict with live packet features
            
        Returns:
            numpy array with 17 features matching CIC-IDS2018 format
        """
        try:
            if self.enable_flow_tracking and self.flow_tracker:
                # Update flow tracker
                self.flow_tracker.update_flow(packet_info)
                flow_features = self.flow_tracker.get_flow_features(packet_info)
            else:
                flow_features = {}
            
            # Map features
            features = []
            
            for cic_feat in self.cic_features:
                value = self._map_feature(cic_feat, packet_info, flow_features)
                features.append(value)
            
            return np.array(features, dtype=np.float32)
            
        except Exception as e:
            logger.error(f"Error adapting features: {e}")
            return None
    
    def _map_feature(self, cic_feature: str, packet_info: Dict, flow_features: Dict) -> float:
        """Map a single CIC feature from packet info"""
        
        # Helper to safely convert to float
        def safe_float(val, default=0.0):
            if val is None:
                return default
            try:
                return float(val)
            except (ValueError, TypeError):
                return default
        
        # Direct mappings
        if cic_feature == 'Dst Port':
            return safe_float(packet_info.get('dst_port', 0))
        
        elif cic_feature == 'Protocol':
            # Convert protocol string to numeric code
            protocol = packet_info.get('protocol', 6)
            if isinstance(protocol, str):
                protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ICMPv6': 58}
                protocol = protocol_map.get(protocol.upper(), 6)
            return safe_float(protocol)
        
        elif cic_feature == 'Flow Duration':
            return safe_float(flow_features.get('flow_duration', 0))
        
        elif cic_feature == 'Tot Fwd Pkts':
            return safe_float(flow_features.get('tot_fwd_pkts', 1))
        
        elif cic_feature == 'Tot Bwd Pkts':
            return safe_float(flow_features.get('tot_bwd_pkts', 0))
        
        elif cic_feature == 'TotLen Fwd Pkts':
            return safe_float(flow_features.get('totlen_fwd_pkts', packet_info.get('total_length', 0)))
        
        elif cic_feature == 'TotLen Bwd Pkts':
            return safe_float(flow_features.get('totlen_bwd_pkts', 0))
        
        elif cic_feature == 'Fwd Pkt Len Max':
            return safe_float(flow_features.get('fwd_pkt_len_max', packet_info.get('total_length', 0)))
        
        elif cic_feature == 'Fwd Pkt Len Min':
            return safe_float(flow_features.get('fwd_pkt_len_min', packet_info.get('total_length', 0)))
        
        elif cic_feature == 'Fwd Pkt Len Mean':
            return safe_float(flow_features.get('fwd_pkt_len_mean', packet_info.get('total_length', 0)))
        
        elif cic_feature == 'Flow IAT Mean':
            return safe_float(flow_features.get('flow_iat_mean', 0))
        
        elif cic_feature == 'Fwd IAT Mean':
            return safe_float(flow_features.get('fwd_iat_mean', 0))
        
        elif cic_feature == 'PSH Flag Cnt':
            return safe_float(flow_features.get('psh_flag_cnt', 0))
        
        elif cic_feature == 'URG Flag Cnt':
            return safe_float(flow_features.get('urg_flag_cnt', 0))
        
        elif cic_feature == 'FIN Flag Cnt':
            return safe_float(flow_features.get('fin_flag_cnt', packet_info.get('tcp_fin_flag', 0)))
        
        elif cic_feature == 'SYN Flag Cnt':
            return safe_float(flow_features.get('syn_flag_cnt', packet_info.get('tcp_syn_flag', 0)))
        
        elif cic_feature == 'RST Flag Cnt':
            return safe_float(flow_features.get('rst_flag_cnt', packet_info.get('tcp_rst_flag', 0)))
        
        elif cic_feature == 'ACK Flag Cnt':
            return safe_float(flow_features.get('ack_flag_cnt', packet_info.get('tcp_ack_flag', 0)))
        
        # Additional flow statistics
        elif cic_feature == 'Flow Byts/s':
            # Bytes per second = total bytes / duration
            duration = safe_float(flow_features.get('flow_duration', 0))
            if duration > 0:
                total_bytes = safe_float(flow_features.get('totlen_fwd_pkts', 0)) + safe_float(flow_features.get('totlen_bwd_pkts', 0))
                return (total_bytes * 1000000.0) / duration  # Convert microseconds to seconds
            return 0.0
        
        elif cic_feature == 'Fwd Pkts/s':
            # Forward packets per second
            duration = safe_float(flow_features.get('flow_duration', 0))
            if duration > 0:
                fwd_pkts = safe_float(flow_features.get('tot_fwd_pkts', 1))
                return (fwd_pkts * 1000000.0) / duration  # Convert microseconds to seconds
            return 0.0
        
        elif cic_feature == 'Fwd Header Len':
            # Approximate header length (TCP/IP headers ~40-60 bytes)
            protocol = packet_info.get('protocol', 'TCP')
            if isinstance(protocol, str):
                protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
                protocol = protocol_map.get(protocol.upper(), 6)
            header_len = 40 if protocol == 6 else 28 if protocol == 17 else 20
            return float(header_len)
        
        elif cic_feature == 'Down/Up Ratio':
            # Download/Upload ratio (Bwd/Fwd)
            fwd_bytes = safe_float(flow_features.get('totlen_fwd_pkts', 1))
            bwd_bytes = safe_float(flow_features.get('totlen_bwd_pkts', 0))
            if fwd_bytes > 0:
                return bwd_bytes / fwd_bytes
            return 0.0
            return 0.0
        
        # Approximations for other features
        elif 'Pkt Len' in cic_feature:
            return float(packet_info.get('total_length', 0))
        
        elif 'Flag' in cic_feature:
            return 0.0  # Unknown flag
        
        else:
            # Default fallback (suppress warning for better performance)
            return 0.0
    
    def cleanup(self):
        """Cleanup old flow data"""
        if self.flow_tracker:
            self.flow_tracker.cleanup_old_flows()
