"""
Testes de QA para Análise de Pacotes e Detecção de Varreduras.
"""

import struct
from python_labs.src.packet_analyzer import (
    parse_ipv4_header,
    parse_tcp_header,
    detect_scan_signature,
)


class TestPacketAnalyzer:
    def test_parse_ipv4_header(self):
        # Constrói cabeçalho IPv4 sintético: 20 bytes
        # Versão 4, IHL 5 (0x45), TOS 0, TotalLen 60, ID 1234, Flags 0, TTL 64, Proto 6 (TCP), Checksum 0
        src_ip_bytes = bytes([192, 168, 1, 10])
        dst_ip_bytes = bytes([10, 0, 0, 1])

        raw_ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 60, 1234, 0, 64, 6, 0x1234, src_ip_bytes, dst_ip_bytes
        )

        res = parse_ipv4_header(raw_ip)
        assert res["version"] == 4
        assert res["header_length"] == 20
        assert res["ttl"] == 64
        assert res["protocol"] == "TCP"
        assert res["src_ip"] == "192.168.1.10"
        assert res["dst_ip"] == "10.0.0.1"

    def test_parse_tcp_header_and_flags(self):
        # Constrói cabeçalho TCP sintético: 20 bytes
        # SrcPort 443, DstPort 54321, Seq 100, Ack 200, Offset 5 (0x50), Flags SYN+ACK (0x12)
        raw_tcp = struct.pack(
            "!HHLLBBHHH",
            443, 54321, 100, 200, 0x50, 0x12, 65535, 0, 0
        )

        res = parse_tcp_header(raw_tcp)
        assert res["src_port"] == 443
        assert res["dst_port"] == 54321
        assert res["flags"]["SYN"] is True
        assert res["flags"]["ACK"] is True
        assert res["flags"]["FIN"] is False

    def test_detect_scan_signatures(self):
        # Teste 1: XMAS Scan (FIN + PSH + URG)
        xmas_flags = {"FIN": True, "PSH": True, "URG": True, "SYN": False, "ACK": False, "RST": False}
        assert detect_scan_signature(xmas_flags) == "VARREDURA_XMAS_SCAN"

        # Teste 2: NULL Scan
        null_flags = {f: False for f in ["FIN", "SYN", "RST", "PSH", "ACK", "URG"]}
        assert detect_scan_signature(null_flags) == "VARREDURA_NULL_SCAN"

        # Teste 3: SYN-FIN Scan
        syn_fin_flags = {"FIN": True, "SYN": True, "RST": False, "PSH": False, "ACK": False, "URG": False}
        assert detect_scan_signature(syn_fin_flags) == "VARREDURA_SYN_FIN_ANOMALA"
