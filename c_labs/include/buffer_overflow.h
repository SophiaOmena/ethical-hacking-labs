#ifndef BUFFER_OVERFLOW_H
#define BUFFER_OVERFLOW_H

#include <stddef.h>
#include <stdbool.h>

/**
 * ============================================================================
 * Exercício: Defesa contra Buffer Overflow (Estouro de Buffer)
 * Referência: CWE-120 (Buffer Copy without Checking Size of Input)
 * ============================================================================
 *
 * Descrição Teórica:
 * O estouro de buffer ocorre quando dados gravados em um array excedem a
 * memória alocada, sobrescrevendo endereços adjacentes na pilha (Stack)
 * ou na memória dinâmica (Heap), incluindo o endereço de retorno da função ($EIP/$RIP).
 *
 * Princípios Defensivos:
 * 1. Proibição de funções inseguras da libc clássica (gets, strcpy, strcat, sprintf).
 * 2. Uso estrito de cópia delimitada por tamanho (bounded copy) garantindo terminador nulo '\0'.
 * 3. Simulação de sentinelas de pilha (Stack Canaries) para integridade de frames.
 */

typedef enum {
    BUFFER_SUCCESS = 0,
    BUFFER_TRUNCATED = 1,
    BUFFER_ERROR_NULL_POINTER = -1,
    BUFFER_ERROR_ZERO_CAPACITY = -2
} BufferStatus;

/**
 * Copia uma string de origem para destino de forma segura, garantindo que o
 * buffer de destino nunca transborde e sempre termine com caractere nulo.
 *
 * @param dest      Buffer de destino
 * @param dest_size Capacidade total em bytes do buffer de destino
 * @param src       String de origem (terminada em nulo)
 * @return BUFFER_SUCCESS se copiado sem cortes,
 *         BUFFER_TRUNCATED se a origem era maior que o espaço disponível,
 *         ou código de erro negativo em caso de argumentos inválidos.
 */
BufferStatus safe_string_copy(char *dest, size_t dest_size, const char *src);

/**
 * Simula a verificação de integridade de um Stack Canary (valor sentinela).
 *
 * @param canary_guard   Valor da sentinela posicionado antes do frame
 * @param expected_canary Valor original esperado da sentinela
 * @return true se o canário estiver íntegro, false se houve corrupção de memória.
 */
bool verify_stack_canary(unsigned int canary_guard, unsigned int expected_canary);

#endif /* BUFFER_OVERFLOW_H */
