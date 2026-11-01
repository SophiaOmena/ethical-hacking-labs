#include "format_string.h"
#include <stdio.h>
#include <string.h>

FormatScanResult scan_format_string(const char *input) {
    if (input == NULL) {
        return FORMAT_ERROR_NULL_POINTER;
    }

    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        if (input[i] == '%') {
            // Se for '%%' é apenas o escape literal para '%'
            if (i + 1 < len && input[i + 1] == '%') {
                i++;
                continue;
            }

            // Inspeciona os próximos caracteres
            for (size_t j = i + 1; j < len && j <= i + 5; j++) {
                char ch = input[j];
                if (ch == 'n') {
                    // Detecção de tentativa crítica de escrita de memória (%n)
                    return FORMAT_DETECTED_PERCENT_N;
                }
                if (ch == 'x' || ch == 'p' || ch == 's') {
                    // Detecção de vazamento de ponteiros/pilha
                    return FORMAT_DETECTED_LEAK_ATTEMPT;
                }
                // Se encontrar um delimitador de fim de token de formato
                if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
                    break;
                }
            }
        }
    }

    return FORMAT_SAFE;
}

int safe_format_log(char *buffer, size_t buffer_size, const char *prefix, const char *user_message) {
    if (buffer == NULL || buffer_size == 0 || prefix == NULL || user_message == NULL) {
        return -1;
    }

    // Boa prática: a string de formatação é um literal estático ("%s: %s"),
    // portanto argumentos do usuário nunca são interpretados como especificadores!
    return snprintf(buffer, buffer_size, "%s: %s", prefix, user_message);
}
