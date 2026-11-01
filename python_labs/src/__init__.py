"""
Laboratório de Estudos de Hackerismo Ético em Python.
Módulos: Port Scanner, Auditoria Criptográfica, Análise de Pacotes e Esteganografia.
"""

from .port_scanner import scan_port, scan_host, grab_banner
from .crypto_auditor import (
    hash_password_sha256,
    hash_pbkdf2_hmac,
    calculate_shannon_entropy,
    audit_password_strength,
)
from .packet_analyzer import parse_ipv4_header, parse_tcp_header, detect_scan_signature
from .steganography import encode_message, decode_message

__all__ = [
    "scan_port",
    "scan_host",
    "grab_banner",
    "hash_password_sha256",
    "hash_pbkdf2_hmac",
    "calculate_shannon_entropy",
    "audit_password_strength",
    "parse_ipv4_header",
    "parse_tcp_header",
    "detect_scan_signature",
    "encode_message",
    "decode_message",
]
