"""
Smoke test to verify pytest infrastructure is working.
"""


def test_smoke():
    """Basic smoke test to verify pytest works."""
    assert 1 == 1


def test_fixture_availability(mock_config):
    """Test that mock_config fixture is available."""
    assert mock_config is not None
    assert mock_config['mode'] == 'mock'


def test_packet_fixture(mock_packet):
    """Test that mock_packet fixture is available."""
    assert mock_packet is not None
    assert mock_packet['src_ip'] == '192.168.1.100'
