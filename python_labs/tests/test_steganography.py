"""
Testes de QA para Esteganografia LSB.
"""

import pytest
from python_labs.src.steganography import encode_message, decode_message


class TestSteganography:
    def test_encode_and_decode_message(self):
        # Cria um carreador fictício de 1024 bytes
        cover = bytes([i % 256 for i in range(1024)])
        secret = "FLAG{h4ck1ng_3t1c0_2026}"

        stego = encode_message(cover, secret)
        assert len(stego) == len(cover)
        # O arquivo modificado não deve ser idêntico ao original, mas sim sutilmente alterado
        assert stego != cover

        # Decodifica a mensagem
        recovered = decode_message(stego)
        assert recovered == secret

    def test_insufficient_cover_size(self):
        # Carreador com apenas 10 bytes não comporta payload + header
        tiny_cover = b"1234567890"
        with pytest.raises(ValueError, match="Carreador insuficiente"):
            encode_message(tiny_cover, "Texto muito longo para 10 bytes")

    def test_decode_invalid_header(self):
        # Dados aleatórios sem o cabeçalho 'STEG'
        random_bytes = bytes([128] * 100)
        with pytest.raises(ValueError, match="Magic Header ausente"):
            decode_message(random_bytes)
