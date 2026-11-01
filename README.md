# Ethical Hacking Labs - Estudos Práticos em C, Python e Java

Repositório dedicado ao estudo prático de **Hackerismo Ético**, **Segurança Ofensiva/Defensiva** e **Engenharia de Software Segura**. O projeto reúne exercícios clássicos de cibersegurança implementados em três linguagens fundamentais da computação:

- **C:** Segurança de baixo nível, integridade de memória, buffer overflow e exploração de ponteiros.
- **Python:** Varredura e reconhecimento de redes, auditoria criptográfica de senhas, análise binária de pacotes e esteganografia.
- **Java:** Segurança de aplicações web (OWASP Top 10), mitigação de SQLi e XSS, validação criptográfica de tokens JWT e blindagem contra força bruta (Rate Limiting).

---

## 🛡️ Matriz de Exercícios e Vulnerabilidades

| Linguagem | Exercício | Referência / CWE | Descrição do Ataque | Solução Defensiva Implementada |
| :--- | :--- | :--- | :--- | :--- |
| **C** | `buffer_overflow` | **CWE-120** | Sobrescrita de endereços na pilha (Stack) e ponteiros de instrução ($RIP). | Bounded copy (`safe_string_copy`) com terminação nula garantida e validação de sentinelas (*Stack Canaries*). |
| **C** | `format_string` | **CWE-134** | Vazamento de pilha (`%x`, `%p`) e gravação arbitrária de memória (`%n`). | Scanner estrito de especificadores maliciosos e aplicação forçada de literais de formatação. |
| **C** | `integer_overflow` | **CWE-190** | Wrap-around aritmético induzindo alocação de buffer insuficiente no heap. | Operações seguras com checagem de limites (`SIZE_MAX` / `UINT_MAX`) antes da chamada ao `calloc`. |
| **Python** | `port_scanner` | **Reconhecimento** | Mapeamento de superfície de ataque e identificação de serviços expostos. | Scanner multithreaded assíncrono com timeouts e capturador passivo de banners. |
| **Python** | `crypto_auditor` | **CWE-328 / CWE-521** | Quebra de hashes fracos e senhas previsíveis via dicionário / rainbow tables. | Hashing salgado, derivação PBKDF2-HMAC (100k iterações) e cálculo de Entropia de Shannon. |
| **Python** | `packet_analyzer` | **NIDS / Análise** | Varreduras furtivas manipulando flags TCP (XMAS Scan, NULL Scan, SYN-FIN). | Desempacotamento binário de cabeçalhos IPv4/TCP (RFC 791/793) e classificador de assinaturas anômalas. |
| **Python** | `steganography` | **Canais Ocultos** | Comunicação disfarçada através de canais secretos. | Inserção/extração LSB (Least Significant Bit) com cabeçalho mágico e prefixo de tamanho de payload. |
| **Java** | `sqli` | **CWE-89 / OWASP A03** | Bypass de autenticação (`' OR '1'='1`) via concatenação direta de consultas. | Consultas parametrizadas que forçam a interpretação estrita dos dados como literais. |
| **Java** | `jwt` | **CWE-347** | Ataque "alg: none", falsificação de assinatura e adulteração de permissões (`role`). | Validador HMAC-SHA256 em tempo constante (`MessageDigest.isEqual`), rejeição de `none` e validação de `exp`. |
| **Java** | `xss` | **CWE-79 / OWASP A03** | Injeção e execução de scripts maliciosos no navegador de usuários. | Escape HTML contextual estrito e remoção ativa de tags executáveis e manipuladores de evento inline. |
| **Java** | `ratelimit` | **CWE-307** | Ataques de força bruta e credential stuffing sobre rotas de login. | Algoritmo *Token Bucket* (Balde de Fichas) concorrente por IP com recarga contínua. |

---

## 🧪 Bateria de Testes de Qualidade (QA)

Todos os módulos contam com baterias de testes automatizados que comprovam o funcionamento das técnicas defensivas:

- **C (23 Testes):** Testes unitários com compilação rigorosa (`-Wall -Wextra -pedantic -Werror`).
- **Python (14 Testes):** Testes via `pytest` cobrindo sockets locais, entropia, decodificação de pacotes e integridade esteganográfica.
- **Java (11 Testes):** Testes em `JUnit 5` validando bypass vs mitigação de SQLi, adulteração de JWT, encoding XSS e limites do Token Bucket.
- **Total: 48 Testes Automatizados** executando em menos de 2 segundos.

---

## 🚀 Como Executar os Testes

### Execução Completa (Todas as Linguagens)

Para rodar todos os testes de uma só vez:

```bash
./test_all.sh
```

Ou utilizando o Makefile:

```bash
make test
```

### Execução Individual por Linguagem

- **Apenas C:**
  ```bash
  make test-c
  ```
- **Apenas Python:**
  ```bash
  make test-python
  ```
- **Apenas Java:**
  ```bash
  make test-java
  ```

---

## 📁 Estrutura de Diretórios

```
ethical-hacking-labs/
├── c_labs/                              # Laboratório de Baixo Nível em C
│   ├── include/                         # Headers (.h) com Javadoc/Doxygen
│   │   ├── buffer_overflow.h
│   │   ├── format_string.h
│   │   └── integer_overflow.h
│   ├── src/                             # Implementações defensivas (.c)
│   ├── tests/                           # Suíte de testes em C
│   └── Makefile                         # Build com flags de segurança
├── python_labs/                         # Laboratório de Redes e Cripto em Python
│   ├── src/
│   │   ├── port_scanner.py              # Scanner de portas e banners
│   │   ├── crypto_auditor.py            # Entropia de Shannon e PBKDF2
│   │   ├── packet_analyzer.py           # Análise de cabeçalhos IPv4/TCP
│   │   └── steganography.py             # Esteganografia LSB
│   ├── tests/                           # Testes unitários em pytest
│   └── requirements.txt
├── java_labs/                           # Laboratório de Aplicações Web em Java
│   ├── src/main/java/br/com/security/
│   │   ├── sqli/                        # Defesa contra SQL Injection
│   │   ├── jwt/                         # Validação e defesa de JWT
│   │   ├── xss/                         # Sanitização e escape contra XSS
│   │   └── ratelimit/                   # Algoritmo Token Bucket
│   ├── src/test/java/                   # Testes de unidade em JUnit 5
│   ├── pom.xml
│   └── run_tests.sh
├── Makefile                             # Orquestrador global de testes
├── test_all.sh                          # Script principal de QA
├── .gitignore
└── README.md
```

---

## ⚖️ Termo de Responsabilidade e Ética

Este repositório foi desenvolvido estritamente para **fins educacionais e de pesquisa em segurança da informação**. As técnicas e defesas aqui apresentadas devem ser utilizadas apenas em ambientes controlados, redes locais autorizadas e aplicações próprias. O uso não autorizado contra sistemas de terceiros é ilegal e antiético.
