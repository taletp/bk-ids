"""
Unit tests for src/prevention.py - FirewallManager cross-platform support
Tests macOS detection, Linux iptables, Windows netsh, and factory function
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.prevention import FirewallManager, MockFirewallManager, get_firewall_manager


class TestMacOSDetection:
    """Test macOS detection and mock firewall routing"""
    
    def test_macos_detection_sets_use_mock_flag(self):
        """On macOS, use_mock should be True"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager()
            assert fw.use_mock is True
            assert fw.iptables_available is False
    
    def test_macos_logs_warning_message(self):
        """FirewallManager logs warning on macOS"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            with patch('src.prevention.logger') as mock_logger:
                fw = FirewallManager()
                # Should log warning about mock firewall
                calls = [str(call) for call in mock_logger.warning.call_args_list]
                assert any('mock' in str(call).lower() for call in calls), \
                    f"Expected mock warning in logs: {calls}"
    
    def test_macos_block_ip_uses_mock(self):
        """On macOS, block_ip should use mock implementation"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager(auto_block=True)
            result = fw.block_ip('192.168.1.100', 'test attack')
            assert result is True
            assert '192.168.1.100' in fw.blocked_ips
    
    def test_macos_unblock_ip_uses_mock(self):
        """On macOS, unblock_ip should use mock implementation"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager(auto_block=True)
            fw.block_ip('192.168.1.100', 'test')
            result = fw.unblock_ip('192.168.1.100')
            assert result is True
            assert '192.168.1.100' not in fw.blocked_ips
    
    def test_macos_os_type_normalized_lowercase(self):
        """os_type should be normalized to 'darwin' (lowercase)"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager()
            assert fw.os_type == 'darwin'


class TestLinuxDetection:
    """Test Linux detection and iptables integration"""
    
    def test_linux_detection_checks_iptables(self):
        """On Linux, should check if iptables is available"""
        with patch('src.prevention.get_os_type', return_value='linux'):
            with patch('src.prevention.command_exists', return_value=True):
                fw = FirewallManager()
                assert fw.os_type == 'linux'
                assert fw.iptables_available is True
                assert fw.use_mock is False
    
    def test_linux_without_iptables(self):
        """On Linux without iptables, should fallback to netsh"""
        with patch('src.prevention.get_os_type', return_value='linux'):
            with patch('src.prevention.command_exists', return_value=False):
                fw = FirewallManager()
                assert fw.iptables_available is False
                assert fw.use_mock is False
    
    def test_command_exists_replaces_which(self):
        """_check_iptables should use command_exists instead of which"""
        with patch('src.prevention.get_os_type', return_value='linux'):
            with patch('src.prevention.command_exists', return_value=True) as mock_cmd:
                fw = FirewallManager()
                # Check that command_exists was called
                assert mock_cmd.called


class TestWindowsDetection:
    """Test Windows detection and netsh integration"""
    
    def test_windows_detection_disables_iptables(self):
        """On Windows, iptables_available should be False"""
        with patch('src.prevention.get_os_type', return_value='windows'):
            fw = FirewallManager()
            assert fw.os_type == 'windows'
            assert fw.iptables_available is False
            assert fw.use_mock is False
    
    def test_windows_block_attempts_netsh(self):
        """On Windows, block_ip should attempt netsh (no mocking needed)"""
        with patch('src.prevention.get_os_type', return_value='windows'):
            fw = FirewallManager(auto_block=True)
            # Without mocking netsh, it should fail gracefully
            result = fw.block_ip('192.168.1.100', 'test')
            # Result depends on whether netsh succeeds, but should not raise


class TestFactoryFunction:
    """Test get_firewall_manager factory function"""
    
    def test_factory_returns_mock_on_macos(self):
        """Factory should return MockFirewallManager on macOS"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = get_firewall_manager()
            assert isinstance(fw, MockFirewallManager)
    
    def test_factory_returns_firewall_manager_on_linux(self):
        """Factory should return FirewallManager on Linux"""
        with patch('src.prevention.get_os_type', return_value='linux'):
            with patch('src.prevention.command_exists', return_value=False):
                fw = get_firewall_manager()
                assert isinstance(fw, FirewallManager)
                assert not isinstance(fw, MockFirewallManager)
    
    def test_factory_returns_firewall_manager_on_windows(self):
        """Factory should return FirewallManager on Windows"""
        with patch('src.prevention.get_os_type', return_value='windows'):
            fw = get_firewall_manager()
            assert isinstance(fw, FirewallManager)
            assert not isinstance(fw, MockFirewallManager)
    
    def test_factory_passes_auto_block_parameter(self):
        """Factory should pass auto_block to constructor"""
        with patch('src.prevention.get_os_type', return_value='windows'):
            fw = get_firewall_manager(auto_block=True)
            assert fw.auto_block is True
    
    def test_factory_passes_block_duration_parameter(self):
        """Factory should pass block_duration to constructor"""
        with patch('src.prevention.get_os_type', return_value='windows'):
            fw = get_firewall_manager(block_duration=7200)
            assert fw.block_duration == 7200
    
    def test_factory_logs_macos_detection(self):
        """Factory should log macOS detection"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            with patch('src.prevention.logger') as mock_logger:
                fw = get_firewall_manager()
                # Should log info about macOS detection
                calls = [str(call) for call in mock_logger.info.call_args_list]
                assert any('macos' in str(call).lower() for call in calls), \
                    f"Expected macOS log in: {calls}"


class TestBlockingBehavior:
    """Test blocking/unblocking behavior across platforms"""
    
    def test_auto_block_disabled_returns_false(self):
        """When auto_block=False, block_ip should return False"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager(auto_block=False)
            result = fw.block_ip('192.168.1.100')
            assert result is False
    
    def test_already_blocked_ip_returns_false(self):
        """Blocking same IP twice should return False on second call"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager(auto_block=True)
            fw.block_ip('192.168.1.100', 'first')
            result = fw.block_ip('192.168.1.100', 'second')
            assert result is False
    
    def test_unblock_nonexistent_ip_returns_false(self):
        """Unblocking non-existent IP should return False"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager()
            result = fw.unblock_ip('192.168.1.100')
            assert result is False
    
    def test_blocked_ip_stored_with_timestamp(self):
        """Blocked IP should be stored with timestamp"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager(auto_block=True)
            before = datetime.now()
            fw.block_ip('192.168.1.100')
            after = datetime.now()
            
            assert '192.168.1.100' in fw.blocked_ips
            timestamp = fw.blocked_ips['192.168.1.100']
            assert before <= timestamp <= after


class TestMockFirewallManager:
    """Test MockFirewallManager behavior (for macOS and testing)"""
    
    def test_mock_manager_logs_when_created(self):
        """MockFirewallManager should log warning on creation"""
        with patch('src.prevention.logger') as mock_logger:
            mock_fw = MockFirewallManager()
            assert mock_logger.warning.called
    
    def test_mock_blocks_ip(self):
        """Mock should track blocked IPs"""
        mock_fw = MockFirewallManager(auto_block=True)
        result = mock_fw.block_ip('192.168.1.100', 'test')
        assert result is True
        assert '192.168.1.100' in mock_fw.blocked_ips
    
    def test_mock_unblocks_ip(self):
        """Mock should unblock tracked IPs"""
        mock_fw = MockFirewallManager(auto_block=True)
        mock_fw.block_ip('192.168.1.100')
        result = mock_fw.unblock_ip('192.168.1.100')
        assert result is True
        assert '192.168.1.100' not in mock_fw.blocked_ips
    
    def test_mock_respects_auto_block_flag(self):
        """Mock should respect auto_block=False"""
        mock_fw = MockFirewallManager(auto_block=False)
        result = mock_fw.block_ip('192.168.1.100')
        assert result is False


class TestCrossPlatformCompatibility:
    """Integration tests for cross-platform behavior"""
    
    def test_os_type_comparison_uses_lowercase(self):
        """All OS type comparisons should use lowercase"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager()
            # Should not fail due to case mismatch
            assert fw.use_mock is True
    
    def test_factory_consistent_across_platforms(self):
        """Factory function behavior consistent for all platforms"""
        platforms = ['linux', 'darwin', 'windows']
        
        for platform_name in platforms:
            with patch('src.prevention.get_os_type', return_value=platform_name):
                with patch('src.prevention.command_exists', return_value=False):
                    fw = get_firewall_manager(auto_block=True, block_duration=5400)
                    assert fw.auto_block is True
                    assert fw.block_duration == 5400


class TestInitialization:
    """Test FirewallManager initialization"""
    
    def test_default_parameters(self):
        """FirewallManager should use correct defaults"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager()
            assert fw.auto_block is False
            assert fw.block_duration == 3600
            assert fw.blocked_ips == {}
    
    def test_custom_parameters(self):
        """FirewallManager should accept custom parameters"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager(auto_block=True, block_duration=7200)
            assert fw.auto_block is True
            assert fw.block_duration == 7200
    
    def test_initializes_blocked_ips_empty(self):
        """blocked_ips dict should start empty"""
        with patch('src.prevention.get_os_type', return_value='darwin'):
            fw = FirewallManager()
            assert fw.blocked_ips == {}
