"""
============================================================================
Exercício: Analisador de Cabeçalhos de Pacotes e Detecção de Varreduras Anômalas
Referência: Análise de Tráfego de Rede e Detecção de Intrusão (NIDS)
============================================================================

Descrição Teórica:
Técnicas avançadas de escaneamento de portas (como Nmap Stealth Scans) manipulam
diretamente as flags do cabeçalho TCP para evadir firewalls ou identificar pilhas de SO:
- XMAS Scan: Flags FIN, PSH e URG ativas simultaneamente (iluminado como árvore de natal).
- NULL Scan: Nenhuma flag TCP ativa (violação da RFC 793).
- SYN-FIN Scan: Combinação contraditória de inicialização (SYN) e encerramento (FIN).
"""

import socket
import struct
from typing import Dict


def parse_ipv4_header(raw_bytes: bytes) -> Dict[str, object]:
    """
    Decodifica os 20 bytes iniciais do cabeçalho IPv4 conforme a RFC 791.

    :param raw_bytes: Sequência binária com os bytes do pacote
    :return: Dicionário contendo os campos estruturados do cabeçalho
    """
    if len(raw_bytes) < 20:
        raise ValueError("O cabeçalho IPv4 requer no mínimo 20 bytes.")

    # Desempacota os campos principais do IPv4
    # ! = network byte order (big endian)
    # B = unsigned char (1 byte), H = unsigned short (2 bytes)
    v_ihl, tos, total_len, packet_id, flags_frag, ttl, proto, checksum, src_bytes, dst_bytes = (
        struct.unpack("!BBHHHBBH4s4s", raw_bytes[:20])
    )

    version = v_ihl >> 4
    ihl = (v_ihl & 0x0F) * 4  # Internet Header Length em bytes

    src_ip = socket.inet_ntoa(src_bytes)
    dst_ip = socket.inet_ntoa(dst_bytes)

    proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"OUTRO({proto})")

    return {
        "version": version,
        "header_length": ihl,
        "total_length": total_len,
        "ttl": ttl,
        "protocol": proto_name,
        "protocol_num": proto,
        "checksum": checksum,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }


def parse_tcp_header(raw_bytes: bytes) -> Dict[str, object]:
    """
    Decodifica os 20 bytes do cabeçalho TCP conforme a RFC 793.

    :param raw_bytes: Sequência binária do cabeçalho TCP
    :return: Dicionário com portas, números de sequência e mapa de flags ativas
    """
    if len(raw_bytes) < 20:
        raise ValueError("O cabeçalho TCP requer no mínimo 20 bytes.")

    src_port, dst_port, seq, ack, offset_reserved, flags_byte, window, checksum, urg_ptr = (
        struct.unpack("!HHLLBBHHH", raw_bytes[:20])
    )

    data_offset = (offset_reserved >> 4) * 4

    flags = {
        "FIN": bool(flags_byte & 0x01),
        "SYN": bool(flags_byte & 0x02),
        "RST": bool(flags_byte & 0x04),
        "PSH": bool(flags_byte & 0x08),
        "ACK": bool(flags_byte & 0x10),
        "URG": bool(flags_byte & 0x20),
    }

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "flags": flags,
        "window": window,
        "checksum": checksum,
    }


def detect_scan_signature(flags: Dict[str, bool]) -> str:
    """
    Analisa a combinação de flags TCP para identificar varreduras furtivas (stealth scans).

    :param flags: Dicionário de flags booleanas gerado por parse_tcp_header
    :return: Nome da assinatura detectada ou 'TRAFEGO_NORMAL'
    """
    is_fin = flags.get("FIN", False)
    is_syn = flags.get("SYN", False)
    is_rst = flags.get("RST", False)
    is_psh = flags.get("PSH", False)
    is_ack = flags.get("ACK", False)
    is_urg = flags.get("URG", False)

    # 1. NULL Scan: Nenhuma flag ativa
    if not any(flags.values()):
        return "VARREDURA_NULL_SCAN"

    # 2. XMAS Scan: FIN + PSH + URG ativos sem SYN/ACK
    if is_fin and is_psh and is_urg and not is_syn and not is_ack:
        return "VARREDURA_XMAS_SCAN"

    # 3. SYN-FIN Scan: Tentativa contraditória de abrir e fechar a conexão
    if is_syn and is_fin:
        return "VARREDURA_SYN_FIN_ANOMALA"

    # 4. Conexão TCP padrão
    if is_syn and not is_ack:
        return "TCP_SYN_INITIAL"
    if is_syn and is_ack:
        return "TCP_SYN_ACK_RESPONSE"
    if is_rst:
        return "TCP_RST_TERMINATION"

    return "TRAFEGO_NORMAL"
