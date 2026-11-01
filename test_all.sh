#!/usr/bin/env bash
set -e

# ==============================================================================
# Master QA Test Runner - Ethical Hacking Labs (C, Python, Java)
# ==============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "========================================================================"
echo "  INICIANDO SUITE GLOBAL DE TESTES DE QA - HACKERISMO ÉTICO            "
echo "========================================================================"

echo ""
echo ">>> [1/3] EXECUTANDO TESTES EM C (Memory Safety, Format String, Overflow)..."
cd "$ROOT_DIR/c_labs"
make clean
make test

echo ""
echo ">>> [2/3] EXECUTANDO TESTES EM PYTHON (Port Scanner, Crypto, Packets, LSB)..."
cd "$ROOT_DIR"
PYTHONPATH=. python3 -m pytest python_labs/tests -v

echo ""
echo ">>> [3/3] EXECUTANDO TESTES EM JAVA (SQLi, JWT Security, XSS, Rate Limiter)..."
cd "$ROOT_DIR/java_labs"
./run_tests.sh

echo ""
echo "========================================================================"
echo "  ✓ TODOS OS TESTES (C, PYTHON E JAVA) FORAM EXECUTADOS COM SUCESSO!   "
echo "========================================================================"
