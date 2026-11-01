#include "buffer_overflow.h"
#include <string.h>

BufferStatus safe_string_copy(char *dest, size_t dest_size, const char *src) {
    if (dest == NULL || src == NULL) {
        return BUFFER_ERROR_NULL_POINTER;
    }

    if (dest_size == 0) {
        return BUFFER_ERROR_ZERO_CAPACITY;
    }

    size_t i = 0;
    // Copia no máximo (dest_size - 1) bytes para garantir espaço ao terminador nulo
    while (i < dest_size - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }

    // Garante sempre o caractere nulo finalizador
    dest[i] = '\0';

    // Se ainda restaram caracteres na origem, houve truncamento
    if (src[i] != '\0') {
        return BUFFER_TRUNCATED;
    }

    return BUFFER_SUCCESS;
}

bool verify_stack_canary(unsigned int canary_guard, unsigned int expected_canary) {
    return (canary_guard == expected_canary);
}
