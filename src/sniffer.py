"""
Module Sniffer: Bắt gói tin từ interface mạng sử dụng Scapy
Hỗ trợ lọc gói tin theo giao thức: ICMP, TCP, UDP
"""

import logging
from typing import List, Callable, Optional
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, ICMP, TCP, UDP, conf
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not installed. Some features will be disabled.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Lớp bắt gói tin từ interface mạng
    
    Hỗ trợ:
    - Bắt gói tin theo thời gian thực
    - Lọc theo giao thức (ICMP, TCP, UDP)
    - Callback để xử lý gói tin
    """
    
    def __init__(self, interface: str = None, packet_filter: str = None):
        """
        Khởi tạo Sniffer
        
        Args:
            interface: Tên interface mạng (ví dụ: 'eth0', 'br0')
            packet_filter: BPF filter (ví dụ: 'tcp port 80', 'icmp')
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet sniffing. Install with: pip install scapy")
        
        self.interface = interface
        self.packet_filter = packet_filter
        self.packet_count = 0
        self.is_running = False
        self.packet_stats = defaultdict(int)
        
        logger.info(f"Sniffer initialized on interface: {self.interface}")
    
    def _parse_packet(self, packet) -> dict:
        """
        Phân tích gói tin thô và trích xuất thông tin cơ bản
        
        Args:
            packet: Gói tin từ Scapy
            
        Returns:
            Dictionary chứa thông tin gói tin
        """
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'raw_packet': packet,
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'flags': None,
                'payload_size': 0,
                'total_length': 0,
                'fragment_offset': 0,
                'is_fragment': False,
                'ttl': 0,
            }
            
            # Parse IP layer
            if IP in packet:
                ip_layer = packet[IP]
                packet_info['src_ip'] = ip_layer.src
                packet_info['dst_ip'] = ip_layer.dst
                packet_info['ttl'] = ip_layer.ttl
                packet_info['total_length'] = ip_layer.len
                packet_info['fragment_offset'] = ip_layer.frag
                packet_info['is_fragment'] = ip_layer.flags & 0x1  # MF flag (More Fragments)
                
                # Parse ICMP
                if ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
                    icmp_layer = packet[ICMP]
                    packet_info['payload_size'] = len(icmp_layer.payload)
                    self.packet_stats['ICMP'] += 1
                
                # Parse TCP
                elif TCP in packet:
                    packet_info['protocol'] = 'TCP'
                    tcp_layer = packet[TCP]
                    packet_info['src_port'] = tcp_layer.sport
                    packet_info['dst_port'] = tcp_layer.dport
                    packet_info['flags'] = str(tcp_layer.flags)
                    packet_info['payload_size'] = len(tcp_layer.payload)
                    self.packet_stats['TCP'] += 1
                
                # Parse UDP
                elif UDP in packet:
                    packet_info['protocol'] = 'UDP'
                    udp_layer = packet[UDP]
                    packet_info['src_port'] = udp_layer.sport
                    packet_info['dst_port'] = udp_layer.dport
                    packet_info['payload_size'] = udp_layer.len
                    self.packet_stats['UDP'] += 1
                
                return packet_info
            
            return None
        
        except Exception as e:
            logger.error(f"Error parsing packet: {str(e)}")
            return None
    
    def start_sniffing(self, callback: Callable[[dict], None], 
                      packet_count: int = 0, timeout: int = None):
        """
        Bắt đầu bắt gói tin
        
        Args:
            callback: Hàm callback được gọi cho mỗi gói tin
            packet_count: Số gói tin muốn bắt (0 = vô hạn)
            timeout: Timeout theo giây (None = vô hạn)
        """
        def packet_callback(pkt):
            packet_info = self._parse_packet(pkt)
            if packet_info:
                self.packet_count += 1
                if self.packet_count % 100 == 0:
                    logger.info(f"Captured {self.packet_count} packets. Stats: {dict(self.packet_stats)}")
                callback(packet_info)
        
        try:
            self.is_running = True
            logger.info(f"Starting packet capture on {self.interface}")
            logger.info(f"Filter: {self.packet_filter if self.packet_filter else 'None'}")
            
            sniff(
                iface=self.interface,
                prn=packet_callback,
                filter=self.packet_filter,
                count=packet_count if packet_count > 0 else 0,
                timeout=timeout,
                store=False
            )
        except Scapy_Exception as e:
            err_msg = str(e)
            logger.error(f"Scapy error: {err_msg}")
            # Common Windows/driver problem: winpcap/npcap not installed -> layer 2 unavailable
            if 'winpcap' in err_msg.lower() or 'layer 2' in err_msg.lower():
                logger.error(
                    "WinPcap/Npcap appears to be missing or unavailable. "
                    "On Windows install Npcap (https://nmap.org/npcap/) and retry with administrator rights. "
                    "If you cannot install Npcap, you can: 1) run in L3-only mode using Scapy's L3 sockets, "
                    "or 2) use the MockPacketSniffer by creating the sniffer via get_sniffer(..., use_mock=True)."
                )
                logger.info("Falling back to mock mode (no real packet capture will occur).")
                # Stop running and return early to avoid repeated errors
                self.is_running = False
                return
        except PermissionError:
            logger.error("Permission denied. Run with administrator/root privileges.")
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
        finally:
            self.is_running = False
    
    def get_stats(self) -> dict:
        """Lấy thống kê gói tin đã bắt được"""
        return {
            'total_packets': self.packet_count,
            'protocol_stats': dict(self.packet_stats)
        }


# Hỗ trợ test trên Windows không có interface thực
class MockPacketSniffer:
    """Mock Sniffer cho mục đích test trên Windows"""
    
    def __init__(self, interface: str = None, packet_filter: str = None):
        self.interface = interface or "mock_br0"
        self.packet_filter = packet_filter
        self.packet_count = 0
        self.is_running = False
        self.packet_stats = defaultdict(int)
        logger.warning(f"Using MockPacketSniffer (no real packet capture)")
    
    def get_stats(self) -> dict:
        return {'total_packets': self.packet_count, 'protocol_stats': dict(self.packet_stats)}


# Factory function
def get_sniffer(interface: str = None, packet_filter: str = None, use_mock: bool = False):
    """Factory để tạo Sniffer hoặc MockSniffer"""
    if use_mock or not SCAPY_AVAILABLE:
        return MockPacketSniffer(interface, packet_filter)
    return PacketSniffer(interface, packet_filter)
