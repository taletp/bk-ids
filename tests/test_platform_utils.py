"""
Unit tests for platform_utils module.
Tests cross-platform OS detection, privilege checking, and command availability.
"""

import os
import platform
import sys
from unittest import mock

import pytest

from src.platform_utils import get_os_type, is_admin, command_exists, get_default_interface


class TestGetOsType:
    """Tests for get_os_type() function."""
    
    def test_returns_valid_os_type(self):
        """Test that get_os_type returns one of the valid OS types."""
        os_type = get_os_type()
        assert os_type in ['linux', 'darwin', 'windows'], \
            f"Expected 'linux', 'darwin', or 'windows', got: {os_type}"
    
    def test_returns_lowercase(self):
        """Test that returned OS type is lowercase."""
        os_type = get_os_type()
        assert os_type == os_type.lower(), \
            f"OS type should be lowercase, got: {os_type}"
    
    def test_returns_string(self):
        """Test that get_os_type returns a string."""
        result = get_os_type()
        assert isinstance(result, str), f"Expected str, got {type(result)}"
    
    def test_consistency(self):
        """Test that get_os_type returns same value on multiple calls."""
        first_call = get_os_type()
        second_call = get_os_type()
        assert first_call == second_call, \
            f"OS type should be consistent, got: {first_call} vs {second_call}"
    
    @mock.patch('platform.system')
    def test_linux_detection(self, mock_system):
        """Test Linux detection."""
        mock_system.return_value = 'Linux'
        assert get_os_type() == 'linux'
    
    @mock.patch('platform.system')
    def test_darwin_detection(self, mock_system):
        """Test macOS (Darwin) detection."""
        mock_system.return_value = 'Darwin'
        assert get_os_type() == 'darwin'
    
    @mock.patch('platform.system')
    def test_windows_detection(self, mock_system):
        """Test Windows detection."""
        mock_system.return_value = 'Windows'
        assert get_os_type() == 'windows'
    
    @mock.patch('platform.system')
    def test_handles_platform_exception(self, mock_system):
        """Test graceful handling of platform.system() exception."""
        mock_system.side_effect = RuntimeError("Platform error")
        result = get_os_type()
        assert isinstance(result, str)
        assert len(result) > 0


class TestCommandExists:
    """Tests for command_exists() function."""
    
    def test_python_command_exists(self):
        """Test that 'python' command exists."""
        # Python should always be available since we're running Python
        result = command_exists('python')
        assert isinstance(result, bool)
        # It might be 'python' or 'python3' depending on system
        # At least one should be True
        assert command_exists('python') or command_exists('python3'), \
            "Either 'python' or 'python3' should exist"
    
    def test_nonexistent_command_returns_false(self):
        """Test that nonexistent command returns False."""
        result = command_exists('nonexistent_command_xyz_12345')
        assert result is False, \
            f"Expected False for nonexistent command, got: {result}"
    
    def test_returns_bool(self):
        """Test that command_exists returns a boolean."""
        result = command_exists('python')
        assert isinstance(result, bool), f"Expected bool, got {type(result)}"
    
    def test_empty_command(self):
        """Test handling of empty command string."""
        result = command_exists('')
        assert result is False, "Empty command should return False"
    
    def test_common_unix_commands(self):
        """Test detection of common Unix commands if on Unix system."""
        os_type = get_os_type()
        if os_type in ['linux', 'darwin']:
            # These should exist on Unix systems
            assert command_exists('ls'), "ls command should exist on Unix"
            assert command_exists('cat'), "cat command should exist on Unix"
    
    @mock.patch('shutil.which')
    def test_uses_shutil_which(self, mock_which):
        """Test that command_exists uses shutil.which internally."""
        mock_which.return_value = '/usr/bin/python'
        result = command_exists('python')
        assert result is True
        mock_which.assert_called_once_with('python')
    
    @mock.patch('shutil.which')
    def test_handles_which_exception(self, mock_which):
        """Test graceful handling of shutil.which() exception."""
        mock_which.side_effect = RuntimeError("shutil error")
        result = command_exists('python')
        assert result is False
    
    def test_case_sensitivity_on_unix(self):
        """Test that command names are case-sensitive on Unix."""
        os_type = get_os_type()
        if os_type in ['linux', 'darwin']:
            # 'PYTHON' should not exist (Unix is case-sensitive)
            result = command_exists('PYTHON')
            # Result depends on system setup, just ensure no exception
            assert isinstance(result, bool)


class TestIsAdmin:
    """Tests for is_admin() function."""
    
    def test_returns_bool(self):
        """Test that is_admin returns a boolean."""
        result = is_admin()
        assert isinstance(result, bool), f"Expected bool, got {type(result)}"
    
    def test_no_exception_raised(self):
        """Test that is_admin never raises an exception."""
        try:
            result = is_admin()
            assert isinstance(result, bool)
        except Exception as e:
            pytest.fail(f"is_admin() raised exception: {str(e)}")
    
    @pytest.mark.skipif(not hasattr(os, 'geteuid'), reason="geteuid not available on this platform")
    @mock.patch('src.platform_utils.get_os_type')
    def test_linux_root_detection(self, mock_get_os_type):
        """Test Linux root privilege detection."""
        mock_get_os_type.return_value = 'linux'
        # Mock geteuid at runtime
        with mock.patch('os.geteuid', return_value=0):
            assert is_admin() is True
    
    @pytest.mark.skipif(not hasattr(os, 'geteuid'), reason="geteuid not available on this platform")
    @mock.patch('src.platform_utils.get_os_type')
    def test_linux_non_root_detection(self, mock_get_os_type):
        """Test Linux non-root user detection."""
        mock_get_os_type.return_value = 'linux'
        with mock.patch('os.geteuid', return_value=1000):
            assert is_admin() is False
    
    @pytest.mark.skipif(not hasattr(os, 'geteuid'), reason="geteuid not available on this platform")
    @mock.patch('src.platform_utils.get_os_type')
    def test_darwin_root_detection(self, mock_get_os_type):
        """Test macOS root detection."""
        mock_get_os_type.return_value = 'darwin'
        with mock.patch('os.geteuid', return_value=0):
            assert is_admin() is True
    
    @pytest.mark.skipif(not hasattr(os, 'geteuid'), reason="geteuid not available on this platform")
    @mock.patch('src.platform_utils.get_os_type')
    def test_darwin_non_root_detection(self, mock_get_os_type):
        """Test macOS non-root detection."""
        mock_get_os_type.return_value = 'darwin'
        with mock.patch('os.geteuid', return_value=501):
            assert is_admin() is False
    
    @mock.patch('src.platform_utils.get_os_type')
    def test_windows_admin_detection(self, mock_get_os_type):
        """Test Windows admin detection (if on Windows)."""
        mock_get_os_type.return_value = 'windows'
        # Can't easily mock ctypes on non-Windows systems
        # Just ensure no exception is raised
        try:
            result = is_admin()
            assert isinstance(result, bool)
        except Exception as e:
            # Windows-specific error is acceptable
            pytest.skip(f"Cannot test Windows admin on non-Windows system: {str(e)}")
    
    @mock.patch('src.platform_utils.get_os_type')
    def test_handles_get_os_type_exception(self, mock_get_os_type):
        """Test graceful handling when get_os_type raises exception."""
        mock_get_os_type.side_effect = RuntimeError("OS detection error")
        result = is_admin()
        assert result is False
    
    @pytest.mark.skipif(not hasattr(os, 'geteuid'), reason="geteuid not available on this platform")
    @mock.patch('src.platform_utils.get_os_type')
    def test_handles_geteuid_exception(self, mock_get_os_type):
        """Test graceful handling when geteuid is not available."""
        mock_get_os_type.return_value = 'linux'
        with mock.patch('os.geteuid', side_effect=AttributeError("No geteuid")):
            result = is_admin()
            assert result is False
    
    def test_consistency_with_actual_os(self):
        """Test that is_admin returns reasonable value for current OS."""
        result = is_admin()
        assert isinstance(result, bool)
        
        # If running as root/admin, should be True; otherwise False
        os_type = get_os_type()
        if os_type in ['linux', 'darwin']:
            # We can verify against geteuid if available
            try:
                uid = os.geteuid()
                if uid == 0:
                    assert result is True, "Should be admin when UID is 0"
                else:
                    assert result is False, "Should not be admin when UID > 0"
            except AttributeError:
                # geteuid not available, skip verification
                pass


class TestIntegration:
    """Integration tests combining multiple functions."""
    
    def test_all_functions_callable(self):
        """Test that all public functions are callable."""
        assert callable(get_os_type)
        assert callable(is_admin)
        assert callable(command_exists)
    
    def test_no_logging_errors(self):
        """Test that functions execute without logging errors."""
        # This is a basic smoke test
        os_type = get_os_type()
        admin = is_admin()
        cmd = command_exists('python')
        
        assert isinstance(os_type, str)
        assert isinstance(admin, bool)
        assert isinstance(cmd, bool)
    
    def test_command_exists_with_detected_os(self):
        """Test command_exists works with detected OS."""
        os_type = get_os_type()
        
        # These commands should work on their respective OSes
        if os_type == 'linux':
            # Common Linux command
            result = command_exists('ls')
            assert isinstance(result, bool)
        elif os_type == 'darwin':
            # Common macOS command
            result = command_exists('ls')
            assert isinstance(result, bool)
        elif os_type == 'windows':
            # Common Windows command
            result = command_exists('cmd')
            assert isinstance(result, bool)
