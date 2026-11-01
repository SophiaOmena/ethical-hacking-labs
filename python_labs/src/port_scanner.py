"""
============================================================================
Exercício: Scanner de Portas e Capturador de Banners (Port Scanner)
Referência: Reconhecimento e Mapeamento de Superfície de Ataque
============================================================================

Descrição Teórica:
O escaneamento de portas é uma das primeiras etapas do reconhecimento ativo
em auditorias de segurança e testes de intrusão autorizados (Pentest).
O objetivo é identificar portas de comunicação TCP/UDP abertas em um alvo,
revelando quais serviços de rede estão ativos e vulneráveis a exploração.

Princípios Éticos e de Implementação:
1. Deve ser utilizado exclusivamente em redes/sistemas com consentimento explícito.
2. Uso de sockets não bloqueantes com timeouts estritos para evitar travamento.
3. Banner grabbing passivo para identificar versões de serviços expostos.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import Dict, List, Optional


def scan_port(host: str, port: int, timeout: float = 0.5) -> Dict[str, object]:
    """
    Testa se uma porta TCP específica está aberta em um determinado host.

    :param host: Endereço IP ou hostname do alvo
    :param port: Número da porta (1 a 65535)
    :param timeout: Tempo limite em segundos para aguardar a resposta
    :return: Dicionário com informações do status da porta
    """
    if not (1 <= port <= 65535):
        raise ValueError(f"Porta inválida: {port}. Deve estar entre 1 e 65535.")

    result = {
        "port": port,
        "is_open": False,
        "banner": None,
        "service": socket.getservbyport(port, "tcp") if _has_service(port) else "unknown",
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            ret = s.connect_ex((host, port))
            if ret == 0:
                result["is_open"] = True
                result["banner"] = _grab_banner_socket(s)
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        pass
    except Exception:
        pass

    return result


def scan_host(host: str, ports: List[int], max_workers: int = 20, timeout: float = 0.5) -> List[Dict[str, object]]:
    """
    Realiza o escaneamento multithreaded de uma lista de portas em um host.

    :param host: Endereço IP ou hostname do alvo
    :param ports: Lista de números de portas a verificar
    :param max_workers: Quantidade máxima de threads concorrentes
    :param timeout: Tempo limite por conexão
    :return: Lista ordenada de dicionários com os resultados de cada porta
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda item: int(item["port"]))
    return results


def grab_banner(host: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """
    Tenta capturar o banner do serviço em uma porta já conhecida como aberta.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return _grab_banner_socket(s)
    except Exception:
        return None


def _grab_banner_socket(s: socket.socket) -> Optional[str]:
    try:
        # Envia solicitação genérica para provocar resposta do daemon
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = s.recv(1024)
        if data:
            return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    return None


def _has_service(port: int) -> bool:
    try:
        socket.getservbyport(port, "tcp")
        return True
    except OSError:
        return False
