#!/usr/bin/env python3
"""
Main IDS/IPS System
Tích hợp tất cả modules: Sniffer, Preprocessor, Detector, Prevention, Dashboard
"""

import sys
import os
import logging
import logging.config
import argparse
import threading
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import config
sys.path.insert(0, str(PROJECT_ROOT / "config"))
import config

# Import modules
from src.sniffer import PacketSniffer, MockPacketSniffer, get_sniffer
from src.preprocessor import DataPreprocessor
from src.detector import DetectionEngine, MockDetectionEngine, NoopDetectionEngine
from src.prevention import FirewallManager, MockFirewallManager
from src.console_logger import setup_colored_logger

try:
    from src.dashboard_dash import dashboard_state as dash_state, start_dashboard_thread
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False
    logger.warning("Dash dashboard not available. Install: pip install dash dash-bootstrap-components")

# Setup logging
logging.config.dictConfig(config.LOGGING_CONFIG)
logger = logging.getLogger(__name__)
# Improve console output with colors
try:
    setup_colored_logger()
except Exception:
    # Fallback: continue without colored console
    pass


class IDSIPSSystem:
    """
    Hệ thống IDS/IPS chính
    Quản lý toàn bộ pipeline: Sniffing -> Preprocessing -> Detection -> Prevention
    """
    
    def __init__(self, use_mock: bool = False):
        """
        Khởi tạo hệ thống
        
        Args:
            use_mock: Nếu True, sử dụng mock components (để test trên Windows)
        """
        self.use_mock = use_mock or config.DEMO_MODE
        self.is_running = False
        self.dashboard_thread = None
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'attacks_detected': 0,
            'attacks_blocked': 0,
            'start_time': datetime.now(),
        }
        
        # Components
        self.sniffer = None
        self.detector = None
        self.firewall = None
        
        # Threads
        self.sniffer_thread = None
        self.detection_thread = None
        
        # Queues (for thread-safe communication)
        self.packet_queue = []
        self.detection_results = defaultdict(list)
        
        # Initialize components
        self._initialize_components()
        
        logger.info(f"IDS/IPS System initialized. Mode: {'MOCK' if self.use_mock else 'LIVE'}")
    
    def _initialize_components(self):
        """Khởi tạo các components"""
        try:
            # Initialize sniffer
            logger.info("Initializing sniffer...")
            if self.use_mock:
                self.sniffer = MockPacketSniffer(
                    interface=config.SNIFFER_CONFIG['interface']
                )
            else:
                self.sniffer = PacketSniffer(
                    interface=config.SNIFFER_CONFIG['interface'],
                    packet_filter=config.SNIFFER_CONFIG['packet_filter']
                )
            
            # Initialize detection engine
            logger.info("Initializing detection engine...")
            if self.use_mock:
                self.detector = MockDetectionEngine(
                    model_path=config.DETECTOR_CONFIG['model_path'],
                    scaler_path=config.DETECTOR_CONFIG['scaler_path'],
                    confidence_threshold=config.DETECTOR_CONFIG['confidence_threshold']
                )
            else:
                # Try to load real model, fall back to mock if not available
                try:
                    # Check for metadata file
                    model_dir = Path(config.MODEL_DIR)
                    metadata_path = model_dir / 'model_metadata.json'
                    
                    self.detector = DetectionEngine(
                        model_path=config.DETECTOR_CONFIG['model_path'],
                        scaler_path=config.DETECTOR_CONFIG['scaler_path'],
                        confidence_threshold=config.DETECTOR_CONFIG['confidence_threshold'],
                        architecture=config.DETECTOR_CONFIG['architecture'],
                        metadata_path=str(metadata_path) if metadata_path.exists() else None,
                        whitelist=config.DETECTOR_CONFIG.get('whitelist', []),
                        whitelist_subnets=config.DETECTOR_CONFIG.get('whitelist_subnets', [])
                    )
                except Exception as e:
                    logger.warning(f"Could not load model: {str(e)}")
                    # In LIVE mode prefer a safe noop detector (always Normal) to
                    # avoid noisy randomized alerts from the MockDetectionEngine.
                    if not config.DEMO_MODE:
                        logger.info("Falling back to NoopDetectionEngine (live safe mode)")
                        self.detector = NoopDetectionEngine(
                            confidence_threshold=config.DETECTOR_CONFIG['confidence_threshold']
                        )
                    else:
                        logger.info("Falling back to MockDetectionEngine (demo/mock mode)")
                        self.detector = MockDetectionEngine(
                            confidence_threshold=config.DETECTOR_CONFIG['confidence_threshold']
                        )
            
            # Initialize firewall manager
            logger.info("Initializing firewall manager...")
            if self.use_mock or config.PREVENTION_CONFIG['use_mock']:
                self.firewall = MockFirewallManager(
                    auto_block=config.PREVENTION_CONFIG['auto_block'],
                    block_duration=config.PREVENTION_CONFIG['block_duration']
                )
            else:
                self.firewall = FirewallManager(
                    auto_block=config.PREVENTION_CONFIG['auto_block'],
                    block_duration=config.PREVENTION_CONFIG['block_duration']
                )
            
            logger.info("All components initialized successfully")
        
        except Exception as e:
            logger.error(f"Error initializing components: {str(e)}")
            raise
    
    def _packet_callback(self, packet_info: dict):
        """Callback được gọi khi bắt được gói tin"""
        self.stats['packets_captured'] += 1
        self.packet_queue.append(packet_info)
        
        # Thực hiện detection
        try:
            detection_result = self.detector.detect(packet_info)
            self.stats['packets_processed'] += 1
            
            if detection_result.get('is_attack'):
                self.stats['attacks_detected'] += 1
                
                # Attack logging is now handled in detector.py
                
                # Try to block IP
                if self.firewall and self.firewall.auto_block:
                    src_ip = detection_result['src_ip']
                    reason = f"{detection_result['attack_type']} (Confidence: {detection_result['confidence']:.2%})"
                    
                    if self.firewall.block_ip(src_ip, reason):
                        self.stats['attacks_blocked'] += 1
                        logger.info(f"Blocked IP: {src_ip}")
            
            # Store detection result
            self.detection_results['all'].append(detection_result)
            self.detection_results[detection_result['attack_type']].append(detection_result)
            
            # Update dashboard if available
            if DASH_AVAILABLE:
                try:
                    dash_state.add_packet(packet_info, detection_result)
                    if detection_result.get('is_attack') and self.firewall:
                        dash_state.add_blocked_ip(detection_result['src_ip'])
                except Exception as e:
                    logger.debug(f"Error updating dashboard: {e}")
            
            # Log periodic metrics summary (every 1000 packets)
            if self.stats['packets_processed'] % 1000 == 0:
                self.detector.log_metrics_summary()
            
        except Exception as e:
            logger.error(f"Error during detection: {str(e)}")
    
    def start(self):
        """Bắt đầu hệ thống"""
        if self.is_running:
            logger.warning("System is already running")
            return
        
        logger.info("Starting IDS/IPS System...")
        self.is_running = True
        
        try:
            # Start sniffer
            logger.info(f"Starting packet capture on interface: {config.SNIFFER_CONFIG['interface']}")
            self.sniffer.start_sniffing(
                callback=self._packet_callback,
                timeout=None
            )
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
            self.stop()
        except Exception as e:
            logger.error(f"Error in sniffer: {str(e)}")
            self.stop()
    
    def stop(self):
        """Dừng hệ thống"""
        logger.info("Stopping IDS/IPS System...")
        self.is_running = False
        
        # Clear firewall blocks (optional)
        if self.firewall:
            logger.info("Clearing firewall blocks...")
            self.firewall.clear_all_blocks()
        
        self._print_summary()
    
    def _print_summary(self):
        """In ra tóm tắt thống kê"""
        uptime = datetime.now() - self.stats['start_time']
        
        logger.info("=" * 60)
        logger.info("IDS/IPS System Summary")
        logger.info("=" * 60)
        logger.info(f"Uptime: {uptime}")
        logger.info(f"Total Packets Captured: {self.stats['packets_captured']:,}")
        logger.info(f"Total Packets Processed: {self.stats['packets_processed']:,}")
        logger.info(f"Total Attacks Detected: {self.stats['attacks_detected']:,}")
        logger.info(f"Total Attacks Blocked: {self.stats['attacks_blocked']:,}")
        
        # Show detector metrics
        logger.info("")
        self.detector.log_metrics_summary()
        
        if self.stats['attacks_detected'] > 0:
            logger.info("\nAttack Distribution (from stored results):")
            for attack_type, count in sorted(
                self.detection_results.items(), 
                key=lambda x: len(x[1]), 
                reverse=True
            ):
                if attack_type != 'all':
                    logger.info(f"  {attack_type}: {len(count)}")
        
        if self.firewall:
            blocked_ips = self.firewall.get_blocked_ips()
            if blocked_ips:
                logger.info(f"\nCurrently Blocked IPs: {len(blocked_ips)}")
                for ip, info in list(blocked_ips.items())[:10]:  # Show first 10
                    logger.info(f"  {ip}: {info['remaining_seconds']}s remaining")
        
        logger.info("=" * 60)
    
    def get_stats(self) -> dict:
        """Lấy thống kê hiện tại"""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        return {
            'uptime_seconds': uptime,
            'packets_captured': self.stats['packets_captured'],
            'packets_per_second': self.stats['packets_captured'] / max(uptime, 1),
            'packets_processed': self.stats['packets_processed'],
            'attacks_detected': self.stats['attacks_detected'],
            'attacks_blocked': self.stats['attacks_blocked'],
            'blocked_ips': self.firewall.get_blocked_ips() if self.firewall else {},
        }
    
    def enable_auto_block(self, enable: bool = True):
        """Enable/disable auto-block"""
        if self.firewall:
            self.firewall.auto_block = enable
            logger.info(f"Auto-block {'enabled' if enable else 'disabled'}")
    
    def start_dashboard(self, host: str = None, port: int = None):
        """Start the Dash dashboard in a separate thread"""
        if not DASH_AVAILABLE:
            logger.error("Dash not available. Install: pip install dash dash-bootstrap-components psutil")
            return False
        
        host = host or config.DASHBOARD_CONFIG['host']
        port = port or config.DASHBOARD_CONFIG['port']
        
        try:
            self.dashboard_thread = start_dashboard_thread(host, port)
            logger.info(f"Dashboard started at http://{host}:{port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")
            return False
    
    def set_confidence_threshold(self, threshold: float):
        """Set confidence threshold"""
        if 0.0 <= threshold <= 1.0:
            if self.detector:
                self.detector.update_threshold(threshold)
                logger.info(f"Confidence threshold updated to {threshold:.2%}")
        else:
            logger.warning(f"Invalid threshold: {threshold}")


def create_demo_data():
    """Tạo dữ liệu demo (mock packets)"""
    import random
    import string
    
    def random_ip():
        return '.'.join(str(random.randint(0, 255)) for _ in range(4))
    
    demo_packets = []
    
    # Generate some normal packets
    for i in range(50):
        demo_packets.append({
            'timestamp': datetime.now().isoformat(),
            'src_ip': random_ip(),
            'dst_ip': random_ip(),
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 53, 22]),
            'total_length': random.randint(40, 1500),
            'payload_size': random.randint(0, 1460),
            'ttl': random.randint(64, 255),
            'is_fragment': 0,
            'fragment_offset': 0,
            'flags': 'A',
        })
    
    # Generate some attack-like packets
    for i in range(10):
        demo_packets.append({
            'timestamp': datetime.now().isoformat(),
            'src_ip': random_ip(),
            'dst_ip': random_ip(),
            'protocol': 'TCP',
            'src_port': random.randint(1024, 65535),
            'dst_port': 80,
            'total_length': 60,
            'payload_size': 0,
            'ttl': 64,
            'is_fragment': 0,
            'fragment_offset': 0,
            'flags': 'S',  # SYN flood indicator
        })
    
    return demo_packets


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='IDS/IPS System')
    parser.add_argument('--mode', choices=['live', 'demo', 'mock'], default='mock',
                       help='Operation mode (default: mock)')
    parser.add_argument('--interface', default='eth0',
                       help='Network interface to sniff on (default: eth0)')
    parser.add_argument('--auto-block', action='store_true',
                       help='Enable automatic IP blocking')
    parser.add_argument('--threshold', type=float, default=0.95,
                       help='Confidence threshold for attacks (default: 0.95)')
    parser.add_argument('--dashboard', action='store_true',
                       help='Launch web dashboard')
    parser.add_argument('--dashboard-only', action='store_true',
                       help='Launch dashboard only (no packet capture)')
    parser.add_argument('--dashboard-port', type=int, default=None,
                       help='Dashboard port (default: 8050 for Dash, 8501 for Streamlit)')
    
    args = parser.parse_args()
    
    # Update config based on arguments
    config.SNIFFER_CONFIG['interface'] = args.interface
    config.PREVENTION_CONFIG['auto_block'] = args.auto_block
    config.DETECTOR_CONFIG['confidence_threshold'] = args.threshold
    
    # Determine use_mock based on mode
    use_mock = args.mode in ['mock', 'demo']
    
    logger.info(f"Starting IDS/IPS System in {args.mode.upper()} mode")
    
    # Handle dashboard-only mode
    if args.dashboard_only:
        if not DASH_AVAILABLE:
            logger.error("Dash not available. Install: pip install dash dash-bootstrap-components psutil")
            sys.exit(1)
        
        logger.info("Launching dashboard in standalone mode...")
        from src.dashboard_dash import run_dashboard
        port = args.dashboard_port or config.DASHBOARD_CONFIG['port']
        host = config.DASHBOARD_CONFIG['host']
        run_dashboard(host=host, port=port, debug=config.DASHBOARD_CONFIG['debug'])
        
    elif args.dashboard:
        # Launch old Streamlit dashboard
        logger.info("Launching Streamlit dashboard...")
        os.system("streamlit run src/dashboard.py")
        
    else:
        # Start main system
        try:
            system = IDSIPSSystem(use_mock=use_mock)
            
            # Configure based on arguments
            if args.auto_block:
                system.enable_auto_block(True)
            
            system.set_confidence_threshold(args.threshold)
            
            # Start dashboard if Dash is available
            if DASH_AVAILABLE:
                port = args.dashboard_port or config.DASHBOARD_CONFIG['port']
                if system.start_dashboard(port=port):
                    logger.info(f"Dashboard accessible at http://localhost:{port}")
                    logger.info("Dashboard will update in real-time as packets are captured")
            
            # Start system
            system.start()
        
        except KeyboardInterrupt:
            logger.info("\nReceived interrupt signal")
        except Exception as e:
            logger.error(f"Fatal error: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main()
