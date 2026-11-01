"""
============================================================================
Exercício: Esteganografia LSB (Least Significant Bit) em Sequências de Bytes
Referência: Ocultação de Informação e Comunicação Secreta (Covert Channels)
============================================================================

Descrição Teórica:
A esteganografia consiste na arte e ciência de ocultar a própria existência
de uma mensagem dentro de um arquivo carreador (imagem, áudio ou vetor de bytes),
diferentemente da criptografia, que oculta apenas o significado.

Na técnica LSB (Least Significant Bit), o bit menos significativo de cada byte
carreador é substituído por um bit da mensagem secreta.
Como o bit menos significativo altera o valor numérico em no máximo ±1 (ex: de 200 para 201),
a variação é imperceptível para os sentidos humanos e para a maioria dos visualizadores.
"""

import struct

MAGIC_HEADER = b"STEG"


def encode_message(cover_bytes: bytes, secret_text: str) -> bytes:
    """
    Insere uma mensagem de texto em um vetor de bytes utilizando LSB.

    :param cover_bytes: Bytes do arquivo carreador original
    :param secret_text: Mensagem secreta a ser escondida
    :return: Novo vetor de bytes (stego_bytes) contendo a mensagem embutida
    """
    secret_payload = MAGIC_HEADER + struct.pack("!I", len(secret_text)) + secret_text.encode("utf-8")
    total_bits_needed = len(secret_payload) * 8

    if len(cover_bytes) < total_bits_needed:
        raise ValueError(
            f"Carreador insuficiente: possui {len(cover_bytes)} bytes, "
            f"mas necessita de pelo menos {total_bits_needed} bytes."
        )

    # Converte o payload secreto em uma sequência de bits (0 ou 1)
    bits = []
    for byte in secret_payload:
        for bit_idx in range(7, -1, -1):
            bits.append((byte >> bit_idx) & 1)

    byte_array = bytearray(cover_bytes)

    # Substitui o LSB de cada byte carreador pelo respectivo bit da mensagem
    for i, bit in enumerate(bits):
        byte_array[i] = (byte_array[i] & ~1) | bit

    return bytes(byte_array)


def decode_message(stego_bytes: bytes) -> str:
    """
    Extrai e recupera uma mensagem oculta via LSB em um vetor de bytes.

    :param stego_bytes: Bytes contendo a mensagem oculta
    :return: Texto secreto decodificado
    :raises ValueError: Se não houver cabeçalho esteganográfico válido
    """
    header_bits_needed = (len(MAGIC_HEADER) + 4) * 8
    if len(stego_bytes) < header_bits_needed:
        raise ValueError("Dados insuficientes para conter o cabeçalho esteganográfico.")

    # Extrai os bits dos bytes do carreador
    extracted_bytes = bytearray()
    current_byte = 0
    bit_count = 0

    for b in stego_bytes:
        current_byte = (current_byte << 1) | (b & 1)
        bit_count += 1
        if bit_count == 8:
            extracted_bytes.append(current_byte)
            current_byte = 0
            bit_count = 0

    # Valida o cabeçalho mágico
    if not extracted_bytes.startswith(MAGIC_HEADER):
        raise ValueError("Nenhuma mensagem esteganográfica válida encontrada (Magic Header ausente).")

    # Lê o tamanho do payload em bytes
    length_bytes = extracted_bytes[len(MAGIC_HEADER) : len(MAGIC_HEADER) + 4]
    payload_len = struct.unpack("!I", length_bytes)[0]

    start_idx = len(MAGIC_HEADER) + 4
    end_idx = start_idx + payload_len

    if len(extracted_bytes) < end_idx:
        raise ValueError("Dados corrompidos ou payload truncado.")

    payload = extracted_bytes[start_idx:end_idx]
    return payload.decode("utf-8", errors="replace")
