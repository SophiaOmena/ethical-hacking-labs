#ifndef INTEGER_OVERFLOW_H
#define INTEGER_OVERFLOW_H

#include <stddef.h>
#include <stdbool.h>
#include <limits.h>

/**
 * ============================================================================
 * Exercício: Defesa contra Integer Overflow e Wrap-around
 * Referência: CWE-190 (Integer Overflow or Wraparound)
 * ============================================================================
 *
 * Descrição Teórica:
 * Quando o resultado de uma operação aritmética excede o valor máximo
 * representável pelo tipo de dado, ocorre um estouro/wrap-around.
 * Em C, isso é frequentemente explorado para contornar verificações de alocação:
 * Exemplo clássico:
 *   size_t total = num_elements * sizeof(Element); // Transborda para valor pequeno!
 *   void *buffer = malloc(total);                  // Aloca menos do que o necessário
 *   memcpy(buffer, data, num_elements * sizeof(Element)); // Heap Buffer Overflow!
 */

/**
 * Soma segura de inteiros sem sinal (unsigned int) prevenindo wrap-around.
 *
 * @param a       Primeiro operando
 * @param b       Segundo operando
 * @param result  Ponteiro para armazenar a soma caso não haja estouro
 * @return true se a operação foi segura, false em caso de overflow.
 */
bool safe_add_uint(unsigned int a, unsigned int b, unsigned int *result);

/**
 * Multiplicação segura de size_t para alocação de buffers prevenindo integer overflow.
 *
 * @param a       Quantidade de elementos
 * @param b       Tamanho unitário de cada elemento
 * @param result  Ponteiro para armazenar o produto
 * @return true se o produto couber no tipo size_t, false se houver overflow.
 */
bool safe_multiply_size_t(size_t a, size_t b, size_t *result);

/**
 * Aloca memória dinamicamente de forma segura, garantindo que nmemb * size
 * não sofra integer overflow antes de repassar para o alocador do sistema.
 *
 * @param nmemb Quantidade de itens
 * @param size  Tamanho de cada item em bytes
 * @return Ponteiro para a memória alocada ou NULL se houver overflow ou falta de memória.
 */
void* safe_calloc_guard(size_t nmemb, size_t size);

#endif /* INTEGER_OVERFLOW_H */
