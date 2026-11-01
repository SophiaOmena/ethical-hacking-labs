"""
Testes de QA para o Port Scanner e Banner Grabber.
"""

import socket
import pytest
from python_labs.src.port_scanner import scan_port, scan_host, grab_banner


class TestPortScanner:
    def test_scan_port_validation(self):
        with pytest.raises(ValueError, match="Porta inválida"):
            scan_port("127.0.0.1", 0)

        with pytest.raises(ValueError, match="Porta inválida"):
            scan_port("127.0.0.1", 70000)

    def test_scan_local_server(self):
        # Abre um socket local temporário em porta livre
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        try:
            result = scan_port("127.0.0.1", port, timeout=0.5)
            assert result["is_open"] is True
            assert result["port"] == port
        finally:
            server.close()

    def test_scan_closed_port(self):
        # Porta normalmente fechada (ex: porta 65000 na loopback)
        result = scan_port("127.0.0.1", 65000, timeout=0.2)
        assert result["is_open"] is False

    def test_scan_host_batch(self):
        results = scan_host("127.0.0.1", [65001, 65002], max_workers=2, timeout=0.2)
        assert len(results) == 2
        assert results[0]["port"] == 65001
        assert results[1]["port"] == 65002
