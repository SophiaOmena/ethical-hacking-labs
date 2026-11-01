#include "integer_overflow.h"
#include <stdlib.h>
#include <stdint.h>

bool safe_add_uint(unsigned int a, unsigned int b, unsigned int *result) {
    if (result == NULL) {
        return false;
    }

    // Se UINT_MAX - a < b, somar 'a' e 'b' certamente causará wrap-around
    if (UINT_MAX - a < b) {
        return false; // Overflow detectado e impedido
    }

    *result = a + b;
    return true;
}

bool safe_multiply_size_t(size_t a, size_t b, size_t *result) {
    if (result == NULL) {
        return false;
    }

    if (a == 0 || b == 0) {
        *result = 0;
        return true;
    }

    // Verificação estrita de divisão prévia
    if (SIZE_MAX / a < b) {
        return false; // Multiplicação excederia SIZE_MAX!
    }

    *result = a * b;
    return true;
}

void* safe_calloc_guard(size_t nmemb, size_t size) {
    size_t total_bytes = 0;

    // Impede o clássico exploit de alocação de buffer reduzido
    if (!safe_multiply_size_t(nmemb, size, &total_bytes)) {
        return NULL; // Rejeição de alocação insegura
    }

    if (total_bytes == 0) {
        return NULL;
    }

    return calloc(1, total_bytes);
}
