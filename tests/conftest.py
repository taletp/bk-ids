"""
Pytest configuration and fixtures for bk-ids test suite.
"""

import pytest


@pytest.fixture
def mock_config():
    """Fixture providing basic mock configuration."""
    return {
        'mode': 'mock',
        'interface': 'eth0',
        'threshold': 0.85,
    }


@pytest.fixture
def mock_packet():
    """Fixture providing a mock packet dictionary."""
    return {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 443,
        'protocol': 'TCP',
        'timestamp': 1234567890,
    }
