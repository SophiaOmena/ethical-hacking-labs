"""
Testes de QA para Auditoria Criptográfica e Entropia.
"""

from python_labs.src.crypto_auditor import (
    calculate_shannon_entropy,
    hash_password_sha256,
    hash_pbkdf2_hmac,
    audit_password_strength,
)


class TestCryptoAuditor:
    def test_shannon_entropy(self):
        # String repetitiva deve ter entropia muito baixa por caractere
        entropy_low = calculate_shannon_entropy("aaaaaaaa")
        # String de alta diversidade
        entropy_high = calculate_shannon_entropy("aB3!zQ9#")

        assert entropy_low == 0.0
        assert entropy_high > 20.0

    def test_salted_hash_sha256(self):
        h1, s1 = hash_password_sha256("segredo123")
        h2, s2 = hash_password_sha256("segredo123")

        # Mesmo com senhas idênticas, sais diferentes produzem hashes diferentes
        assert s1 != s2
        assert h1 != h2

        # Reutilizando o mesmo sal, a saída deve coincidir
        salt_bytes = bytes.fromhex(s1)
        h3, _ = hash_password_sha256("segredo123", salt=salt_bytes)
        assert h3 == h1

    def test_pbkdf2_key_derivation(self):
        salt = b"1234567812345678"
        k1, _ = hash_pbkdf2_hmac("minha_senha", salt=salt, iterations=1000)
        k2, _ = hash_pbkdf2_hmac("minha_senha", salt=salt, iterations=1000)
        assert k1 == k2
        assert len(k1) == 64  # SHA-256 gera chave de 32 bytes = 64 hex chars

    def test_password_strength_auditing(self):
        # Caso 1: Senha em blacklist
        r1 = audit_password_strength("123456")
        assert r1["strength"] == "MUITO_FRACA"
        assert r1["score"] == 0

        # Caso 2: Senha fraca
        r2 = audit_password_strength("abcdef")
        assert r2["strength"] == "FRACA"

        # Caso 3: Senha robusta e completa
        r3 = audit_password_strength("C0mpl3x#P@ssw0rd!2026")
        assert r3["strength"] == "FORTE"
        assert r3["score"] >= 80
