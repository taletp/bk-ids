"""
Cross-platform utilities module for OS detection and system checks.
Provides consistent interface for Linux, macOS, and Windows operations.
"""

import logging
import os
import platform
import shutil
import socket
import sys
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)


def get_os_type() -> str:
    """
    Detect the operating system type.
    
    Returns:
        str: One of 'linux', 'darwin', or 'windows' (normalized lowercase)
    
    Examples:
        >>> os_type = get_os_type()
        >>> assert os_type in ['linux', 'darwin', 'windows']
    """
    try:
        system = platform.system()
        os_type = system.lower()
        
        # Normalize platform names
        if os_type == 'darwin':
            # macOS always returns 'Darwin'
            normalized = 'darwin'
        elif os_type == 'linux':
            # Linux variants all return 'Linux'
            normalized = 'linux'
        elif os_type == 'windows':
            # Windows returns 'Windows'
            normalized = 'windows'
        else:
            # Fallback for unknown systems
            normalized = os_type
        
        logger.debug(f"Detected OS: {system} → {normalized}")
        return normalized
    
    except Exception as e:
        logger.error(f"Error detecting OS: {str(e)}")
        # Fallback to sys.platform if platform.system() fails
        fallback = sys.platform.split()[0].lower()
        logger.warning(f"Using fallback OS detection: {fallback}")
        return fallback


def is_admin() -> bool:
    """
    Check if the current process is running with elevated privileges (admin/root).
    
    Returns:
        bool: True if running as root/admin, False otherwise
    
    Platform-specific behavior:
        - Linux/macOS: Checks if effective UID is 0 (root)
        - Windows: Uses ctypes to check admin privileges
    
    Examples:
        >>> if is_admin():
        ...     print("Running with elevated privileges")
        ... else:
        ...     print("Running as regular user")
    """
    try:
        os_type = get_os_type()
        
        if os_type in ['linux', 'darwin']:
            # Unix-like systems: check effective UID
            try:
                uid = os.geteuid()
                is_root = (uid == 0)
                logger.debug(f"Unix privilege check: UID={uid}, is_root={is_root}")
                return is_root
            except AttributeError:
                logger.warning("os.geteuid() not available (not on Unix system)")
                return False
        
        elif os_type == 'windows':
            # Windows: use ctypes to check admin privileges
            try:
                import ctypes
                is_admin_windows = ctypes.windll.shell32.IsUserAnAdmin() != 0
                logger.debug(f"Windows privilege check: is_admin={is_admin_windows}")
                return is_admin_windows
            except Exception as e:
                logger.warning(f"Could not check Windows admin privileges: {str(e)}")
                return False
        
        else:
            logger.warning(f"Unknown OS type for privilege check: {os_type}")
            return False
    
    except Exception as e:
        logger.error(f"Error checking admin privileges: {str(e)}")
        return False


def command_exists(cmd: str) -> bool:
    """
    Check if a command exists in the system PATH (cross-platform).
    
    Uses shutil.which() which works on all platforms and properly handles
    Windows executable extensions (.exe, .bat, .cmd).
    
    Args:
        cmd (str): Command name to check (e.g., 'python', 'iptables', 'netsh')
    
    Returns:
        bool: True if command is available in PATH, False otherwise
    
    Examples:
        >>> assert command_exists('python') == True
        >>> assert command_exists('nonexistent_command_xyz_123') == False
        >>> if command_exists('iptables'):
        ...     print("iptables is available")
    """
    try:
        result = shutil.which(cmd)
        is_found = result is not None
        
        if is_found:
            logger.debug(f"Command '{cmd}' found at: {result}")
        else:
            logger.debug(f"Command '{cmd}' not found in PATH")
        
        return is_found
    
    except Exception as e:
        logger.error(f"Error checking for command '{cmd}': {str(e)}")
        return False


def get_default_interface() -> Optional[str]:
    """
    Detect the default/primary network interface across platforms.
    
    Uses a fallback chain:
    1. psutil: Find active interface with valid IP address (non-loopback)
    2. socket: Get interface for default route
    3. Return None if detection fails
    
    Returns:
        Optional[str]: Primary interface name (e.g., 'eth0', 'en0', 'Ethernet') or None
    
    Platform-specific behavior:
        - Windows: Returns friendly name like 'Ethernet', 'Wi-Fi'
        - Linux: Returns name like 'eth0', 'ens33', 'wlan0'
        - macOS: Returns name like 'en0', 'en1'
    
    Examples:
        >>> iface = get_default_interface()
        >>> if iface:
        ...     print(f"Using interface: {iface}")
        ... else:
        ...     print("Could not detect interface")
    """
    try:
        # Strategy 1: Use psutil to find active non-loopback interface
        if psutil is not None:
            try:
                stats = psutil.net_if_stats()
                addrs = psutil.net_if_addrs()
                
                # First pass: Look for UP interfaces with IP addresses
                for iface_name, stat in stats.items():
                    if stat.isup and iface_name in addrs:
                        # Skip loopback interfaces
                        if iface_name.lower() not in ['lo', 'lo0', 'loopback']:
                            # Check if it has IPv4 addresses
                            for addr in addrs[iface_name]:
                                if addr.family == socket.AF_INET:
                                    logger.info(f"Auto-detected interface via psutil: {iface_name}")
                                    return iface_name
                
                # Second pass: Any UP interface (loopback as last resort)
                for iface_name, stat in stats.items():
                    if stat.isup and iface_name in addrs:
                        logger.info(f"Auto-detected interface via psutil (no IPv4): {iface_name}")
                        return iface_name
            
            except Exception as e:
                logger.debug(f"psutil interface detection failed: {str(e)}")
        
        # Strategy 2: Use socket to find default route interface
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to Google DNS (not actually sending, just determining route)
            s.connect(("8.8.8.8", 80))
            interface_ip = s.getsockname()[0]
            s.close()
            
            # Try to find the interface name from the IP address
            if psutil is not None:
                addrs = psutil.net_if_addrs()
                for iface_name, addr_list in addrs.items():
                    for addr in addr_list:
                        if addr.family == socket.AF_INET and addr.address == interface_ip:
                            logger.info(f"Auto-detected interface via socket: {iface_name}")
                            return iface_name
        
        except Exception as e:
            logger.debug(f"socket interface detection failed: {str(e)}")
        
        # All strategies failed
        logger.warning("Could not auto-detect network interface")
        return None
    
    except Exception as e:
        logger.error(f"Unexpected error in get_default_interface(): {str(e)}")
        return None
