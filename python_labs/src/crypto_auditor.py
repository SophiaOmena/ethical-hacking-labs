"""
============================================================================
Exercício: Auditoria Criptográfica e Análise de Entropia de Senhas
Referência: CWE-328 (Use of Weak Hash) e CWE-521 (Weak Password Requirements)
============================================================================

Descrição Teórica:
O armazenamento e auditoria segura de credenciais exige o entendimento de:
1. Funções de Hash Criptográfico: SHA-256 vs KDFs modernos (PBKDF2/bcrypt/Argon2).
2. Salting: Geração de sais aleatórios criptograficamente seguros para mitigar
   ataques pré-computados com Rainbow Tables.
3. Entropia de Shannon: Medição matemática de aleatoriedade e imprevisibilidade
   da informação contida em uma senha (bits de entropia).
"""

from collections import Counter
import hashlib
import math
import os
import re
from typing import Dict, Optional, Tuple


def calculate_shannon_entropy(text: str) -> float:
    """
    Calcula a Entropia de Shannon (em bits por caractere * comprimento) de uma string.
    H = - sum(p(x) * log2(p(x)))

    :param text: String a ser avaliada
    :return: Total de bits de entropia estimados
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy_per_char = -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )

    # Entropia total considerando tamanho da string
    return round(entropy_per_char * length, 2)


def hash_password_sha256(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Gera o hash SHA-256 de uma senha utilizando salt criptográfico.

    :param password: Senha em texto claro
    :param salt: Sal fornecido ou None para gerar 16 bytes aleatórios
    :return: Tupla (hex_hash, hex_salt)
    """
    if salt is None:
        salt = os.urandom(16)

    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(password.encode("utf-8"))

    return hasher.hexdigest(), salt.hex()


def hash_pbkdf2_hmac(
    password: str,
    salt: Optional[bytes] = None,
    iterations: int = 100_000,
) -> Tuple[str, str]:
    """
    Aplica PBKDF2 (Password-Based Key Derivation Function 2) com HMAC-SHA256,
    recomendado para desacelerar intencionalmente tentativas de força bruta (Brute-force).

    :param password: Senha
    :param salt: Sal (ou None para gerar 16 bytes aleatórios)
    :param iterations: Fator de custo (número de iterações, ex: 100.000)
    :return: Tupla (hex_derived_key, hex_salt)
    """
    if salt is None:
        salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return key.hex(), salt.hex()


def audit_password_strength(
    password: str,
    blacklist: Optional[set] = None,
) -> Dict[str, object]:
    """
    Audita a robustez de uma senha, verificando entropia, dicionário de senhas
    comuns e conformidade com critérios de segurança da informação.

    :param password: Senha sob análise
    :param blacklist: Conjunto de senhas comuns/vazadas para checagem
    :return: Dicionário com pontuação (0 a 100), nível de risco e recomendações
    """
    if blacklist is None:
        blacklist = {"123456", "password", "senha123", "admin", "qwerty"}

    warnings = []
    entropy = calculate_shannon_entropy(password)

    if password.lower() in blacklist:
        warnings.append("Senha extremamente comum encontrada na lista de bloqueio.")
        return {
            "score": 0,
            "strength": "MUITO_FRACA",
            "entropy_bits": entropy,
            "warnings": warnings,
        }

    score = 0

    # Comprimento
    length = len(password)
    if length >= 14:
        score += 35
    elif length >= 10:
        score += 25
    elif length >= 8:
        score += 15
    else:
        warnings.append("Senha curta (menos de 8 caracteres).")

    # Variedade de caracteres
    if re.search(r"[a-z]", password):
        score += 15
    else:
        warnings.append("Faltam letras minúsculas.")

    if re.search(r"[A-Z]", password):
        score += 15
    else:
        warnings.append("Faltam letras maiúsculas.")

    if re.search(r"[0-9]", password):
        score += 15
    else:
        warnings.append("Faltam números.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 20
    else:
        warnings.append("Faltam símbolos especiais.")

    # Avaliação final
    score = min(100, score)
    if score >= 80:
        strength = "FORTE"
    elif score >= 50:
        strength = "MEDIA"
    else:
        strength = "FRACA"

    return {
        "score": score,
        "strength": strength,
        "entropy_bits": entropy,
        "warnings": warnings,
    }
