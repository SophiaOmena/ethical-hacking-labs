#ifndef FORMAT_STRING_H
#define FORMAT_STRING_H

#include <stddef.h>
#include <stdbool.h>

/**
 * ============================================================================
 * Exercício: Defesa contra Format String Vulnerabilities
 * Referência: CWE-134 (Use of Externally-Controlled Format String)
 * ============================================================================
 *
 * Descrição Teórica:
 * Ocorre quando uma entrada fornecida pelo usuário é repassada diretamente
 * como argumento de formato em funções da família printf (ex: printf(user_input)).
 * Atacantes podem usar:
 * - '%x' ou '%p' para vazar valores confidenciais da pilha (Information Disclosure).
 * - '%s' para ler ponteiros arbitrários.
 * - '%n' para gravar bytes na memória apontada pela pilha (Arbitrary Memory Write).
 *
 * Princípios Defensivos:
 * 1. Nunca usar entrada de usuário como string de formatação: printf("%s", user_input).
 * 2. Analisador sintático estrito de especificadores de conversão não autorizados.
 */

typedef enum {
    FORMAT_SAFE = 0,
    FORMAT_DETECTED_PERCENT_N = 1,
    FORMAT_DETECTED_LEAK_ATTEMPT = 2,
    FORMAT_ERROR_NULL_POINTER = -1
} FormatScanResult;

/**
 * Inspeciona uma string fornecida por usuário em busca de tokens maliciosos
 * de format string (%n, %x, %p).
 *
 * @param input String a ser auditada
 * @return FORMAT_SAFE se não houver tentativas de injeção de especificador,
 *         ou código do tipo de ameaça detectada.
 */
FormatScanResult scan_format_string(const char *input);

/**
 * Gera um log formatado de forma imune a ataques de format string,
 * fixando a string de formato no código compilado.
 *
 * @param buffer       Buffer de saída
 * @param buffer_size  Tamanho do buffer
 * @param prefix       Prefixo do log (ex: "[INFO]")
 * @param user_message Mensagem de entrada arbitrária
 * @return Número de caracteres gravados ou negativo em caso de erro.
 */
int safe_format_log(char *buffer, size_t buffer_size, const char *prefix, const char *user_message);

#endif /* FORMAT_STRING_H */
