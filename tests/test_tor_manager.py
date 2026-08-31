import pytest

from modules.proxy.tor_manager import AnonymityError, _ensure_host_ip_found


def test_unknown_host_ip_fails_anonymity_gate():
    with pytest.raises(AnonymityError, match="host IP"):
        _ensure_host_ip_found(None)
