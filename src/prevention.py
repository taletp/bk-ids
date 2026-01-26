"""
Module Prevention: Tự động chặn IP tấn công
Hỗ trợ Linux (iptables), macOS (mock), và Windows (netsh/Windows Firewall) fallback
"""

import logging
import subprocess
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta

from src.platform_utils import get_os_type, command_exists

logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Quản lý firewall để chặn IP tấn công
    
    Hỗ trợ:
    - Linux: iptables
    - Windows: netsh firewall (fallback nếu không có iptables)
    """
    
    def __init__(self, auto_block: bool = False, block_duration: int = 3600):
        """
        Khởi tạo Firewall Manager
        
        Args:
            auto_block: Tự động chặn IP tấn công
            block_duration: Thời gian chặn (giây), default 1 giờ
        """
        self.auto_block = auto_block
        self.block_duration = block_duration
        self.os_type = get_os_type()
        
        # Track blocked IPs
        self.blocked_ips = {}  # {ip: blocked_time}
        
        # Check for macOS and use mock implementation
        self.use_mock = False
        self.iptables_available = False
        
        if self.os_type == 'darwin':
            logger.warning("Using mock firewall on macOS (pf/pfctl not implemented)")
            self.use_mock = True
        elif self.os_type == 'linux':
            self.iptables_available = self._check_iptables()
        
        logger.info(f"FirewallManager initialized on {self.os_type}")
        logger.info(f"Auto-block: {auto_block}, Block duration: {block_duration}s")
        logger.info(f"iptables available: {self.iptables_available}")
        if self.use_mock:
            logger.info("Using mock firewall manager")
    
    def _check_iptables(self) -> bool:
        """Kiểm tra xem iptables có sẵn không"""
        try:
            return command_exists('iptables')
        except Exception as e:
            logger.warning(f"Could not check iptables: {str(e)}")
            return False
    
    def block_ip(self, ip_address: str, reason: str = "Attack detected") -> bool:
        """
        Chặn một IP address
        
        Args:
            ip_address: IP cần chặn
            reason: Lý do chặn
            
        Returns:
            True nếu chặn thành công, False nếu thất bại
        """
        if not self.auto_block:
            logger.debug(f"Auto-block disabled. IP {ip_address} not blocked.")
            return False
        
        # Kiểm tra nếu IP đã bị chặn
        if ip_address in self.blocked_ips:
            logger.debug(f"IP {ip_address} already blocked")
            return False
        
        try:
            if self.use_mock:
                # Use mock implementation for macOS
                return self._block_ip_mock(ip_address, reason)
            elif self.os_type == 'linux' and self.iptables_available:
                return self._block_ip_iptables(ip_address, reason)
            else:
                return self._block_ip_netsh(ip_address, reason)
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {str(e)}")
            return False
    
    def _block_ip_iptables(self, ip_address: str, reason: str) -> bool:
        """Chặn IP sử dụng iptables (Linux)"""
        try:
            # Drop incoming packets from this IP
            cmd = ['sudo', 'iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                self.blocked_ips[ip_address] = datetime.now()
                logger.info(f"Blocked IP {ip_address} using iptables. Reason: {reason}")
                return True
            else:
                logger.error(f"iptables error: {result.stderr}")
                return False
        
        except subprocess.TimeoutExpired:
            logger.error(f"iptables command timed out for IP {ip_address}")
            return False
        except PermissionError:
            logger.error("Permission denied. Need sudo/root privileges for iptables")
            return False
        except Exception as e:
            logger.error(f"Error with iptables: {str(e)}")
            return False
    
    def _block_ip_netsh(self, ip_address: str, reason: str) -> bool:
        """Chặn IP sử dụng netsh (Windows)"""
        try:
            # Windows 10+ netsh syntax
            rule_name = f"Block_{ip_address.replace('.', '_')}"
            
            # Tạo rule chặn incoming
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                f'dir=in',
                'action=block',
                f'remoteip={ip_address}',
                f'description={reason}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                self.blocked_ips[ip_address] = datetime.now()
                logger.info(f"Blocked IP {ip_address} using netsh. Reason: {reason}")
                return True
            else:
                logger.error(f"netsh error: {result.stderr}")
                return False
        
        except subprocess.TimeoutExpired:
            logger.error(f"netsh command timed out for IP {ip_address}")
            return False
        except PermissionError:
            logger.error("Permission denied. Need admin privileges for netsh")
            return False
        except Exception as e:
            logger.error(f"Error with netsh: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Bỏ chặn một IP address
        
        Args:
            ip_address: IP cần bỏ chặn
            
        Returns:
            True nếu bỏ chặn thành công
        """
        if ip_address not in self.blocked_ips:
            logger.debug(f"IP {ip_address} is not blocked")
            return False
        
        try:
            if self.use_mock:
                # Use mock implementation for macOS
                return self._unblock_ip_mock(ip_address)
            elif self.os_type == 'linux' and self.iptables_available:
                return self._unblock_ip_iptables(ip_address)
            else:
                return self._unblock_ip_netsh(ip_address)
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {str(e)}")
            return False
    
    def _unblock_ip_iptables(self, ip_address: str) -> bool:
        """Bỏ chặn IP sử dụng iptables"""
        try:
            cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                del self.blocked_ips[ip_address]
                logger.info(f"Unblocked IP {ip_address} using iptables")
                return True
            else:
                logger.error(f"Error unblocking with iptables: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error in _unblock_ip_iptables: {str(e)}")
            return False
    
    def _unblock_ip_netsh(self, ip_address: str) -> bool:
        """Bỏ chặn IP sử dụng netsh"""
        try:
            rule_name = f"Block_{ip_address.replace('.', '_')}"
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                del self.blocked_ips[ip_address]
                logger.info(f"Unblocked IP {ip_address} using netsh")
                return True
            else:
                logger.error(f"Error unblocking with netsh: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error in _unblock_ip_netsh: {str(e)}")
            return False
    
    def _block_ip_mock(self, ip_address: str, reason: str) -> bool:
        """Mock block IP (for macOS)"""
        try:
            self.blocked_ips[ip_address] = datetime.now()
            logger.info(f"[MOCK] Blocked IP {ip_address}. Reason: {reason}")
            return True
        except Exception as e:
            logger.error(f"Error with mock block: {str(e)}")
            return False
    
    def _unblock_ip_mock(self, ip_address: str) -> bool:
        """Mock unblock IP (for macOS)"""
        try:
            del self.blocked_ips[ip_address]
            logger.info(f"[MOCK] Unblocked IP {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Error with mock unblock: {str(e)}")
            return False
    
    def check_expiry(self):
        """
        Kiểm tra và tự động bỏ chặn IPs hết hạn
        Thường được gọi định kỳ bởi scheduler
        """
        expired_ips = []
        current_time = datetime.now()
        
        for ip, block_time in self.blocked_ips.items():
            if current_time - block_time > timedelta(seconds=self.block_duration):
                expired_ips.append(ip)
        
        for ip in expired_ips:
            self.unblock_ip(ip)
            logger.info(f"Auto-unblocked IP {ip} (block duration expired)")
    
    def get_blocked_ips(self) -> Dict[str, str]:
        """Lấy danh sách IPs đang bị chặn"""
        result = {}
        for ip, block_time in self.blocked_ips.items():
            elapsed = (datetime.now() - block_time).total_seconds()
            result[ip] = {
                'blocked_at': block_time.isoformat(),
                'elapsed_seconds': int(elapsed),
                'remaining_seconds': max(0, int(self.block_duration - elapsed))
            }
        return result
    
    def clear_all_blocks(self):
        """Bỏ chặn tất cả IPs"""
        ips_to_unblock = list(self.blocked_ips.keys())
        for ip in ips_to_unblock:
            self.unblock_ip(ip)
        logger.info(f"Cleared {len(ips_to_unblock)} blocked IPs")


# Mock Firewall Manager cho testing
class MockFirewallManager:
    """Mock Firewall Manager cho testing"""
    
    def __init__(self, auto_block: bool = False, block_duration: int = 3600):
        self.auto_block = auto_block
        self.block_duration = block_duration
        self.blocked_ips = {}
        logger.warning("Using MockFirewallManager (no actual firewall rules)")
    
    def block_ip(self, ip_address: str, reason: str = "Attack detected") -> bool:
        if not self.auto_block:
            return False
        if ip_address not in self.blocked_ips:
            self.blocked_ips[ip_address] = datetime.now()
            logger.info(f"[MOCK] Blocked IP {ip_address}: {reason}")
            return True
        return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
            logger.info(f"[MOCK] Unblocked IP {ip_address}")
            return True
        return False
    
    def check_expiry(self):
        pass
    
    def get_blocked_ips(self) -> Dict[str, str]:
        return {ip: {'blocked_at': str(t), 'remaining_seconds': self.block_duration} 
                for ip, t in self.blocked_ips.items()}
    
    def clear_all_blocks(self):
        self.blocked_ips.clear()


def get_firewall_manager(auto_block: bool = False, block_duration: int = 3600) -> FirewallManager:
    """
    Factory function to instantiate the appropriate FirewallManager.
    
    On macOS, returns a MockFirewallManager.
    On Linux/Windows, returns a full FirewallManager.
    
    Args:
        auto_block: Enable automatic IP blocking
        block_duration: Duration in seconds to block IPs
    
    Returns:
        FirewallManager instance (or MockFirewallManager on macOS)
    """
    os_type = get_os_type()
    
    if os_type == 'darwin':
        logger.info("macOS detected, using MockFirewallManager")
        return MockFirewallManager(auto_block, block_duration)
    
    return FirewallManager(auto_block, block_duration)
