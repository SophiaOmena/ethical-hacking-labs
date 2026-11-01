#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "buffer_overflow.h"
#include "format_string.h"
#include "integer_overflow.h"

static int g_tests_passed = 0;
static int g_tests_total = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_total++; \
    if (cond) { \
        printf("  [PASS] %s\n", msg); \
        g_tests_passed++; \
    } else { \
        printf("  [FAIL] %s (linha %d)\n", msg, __LINE__); \
    } \
} while(0)

static void test_buffer_overflow(void) {
    printf("=== Testes de QA: Defesa de Buffer Overflow ===\n");
    char dest[16];

    // Caso 1: Cópia padrão dentro dos limites
    BufferStatus status = safe_string_copy(dest, sizeof(dest), "admin_user");
    TEST_ASSERT(status == BUFFER_SUCCESS, "Cópia normal dentro do limite");
    TEST_ASSERT(strcmp(dest, "admin_user") == 0, "Conteúdo gravado corretamente");

    // Caso 2: Tentativa de estouro de buffer (truncamento seguro)
    const char *payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    status = safe_string_copy(dest, sizeof(dest), payload);
    TEST_ASSERT(status == BUFFER_TRUNCATED, "Detectou e impediu estouro de buffer com truncamento");
    TEST_ASSERT(strlen(dest) == sizeof(dest) - 1, "Tamanho máximo respeitado com terminação nula");
    TEST_ASSERT(dest[sizeof(dest) - 1] == '\0', "Último byte obrigatoriamente nulo");

    // Caso 3: Ponteiros inválidos
    TEST_ASSERT(safe_string_copy(NULL, 10, "teste") == BUFFER_ERROR_NULL_POINTER, "Rejeitou ponteiro nulo");
    TEST_ASSERT(safe_string_copy(dest, 0, "teste") == BUFFER_ERROR_ZERO_CAPACITY, "Rejeitou capacidade zero");

    // Caso 4: Verificação de Stack Canary
    unsigned int original_canary = 0xDEADBEEF;
    unsigned int intact_canary = 0xDEADBEEF;
    unsigned int corrupted_canary = 0x41414141; // Sobrescrito com 'AAAA'

    TEST_ASSERT(verify_stack_canary(intact_canary, original_canary) == true, "Canário íntegro validado");
    TEST_ASSERT(verify_stack_canary(corrupted_canary, original_canary) == false, "Canário corrompido detectado com sucesso");
}

static void test_format_string(void) {
    printf("\n=== Testes de QA: Defesa contra Format String ===\n");

    // Caso 1: String comum e segura
    TEST_ASSERT(scan_format_string("Usuario logado com sucesso") == FORMAT_SAFE, "Texto normal é seguro");
    TEST_ASSERT(scan_format_string("Desconto de 50%% aplicado") == FORMAT_SAFE, "Escape literal '%%%%' é seguro");

    // Caso 2: Tentativa de vazamento de memória (%x / %p)
    TEST_ASSERT(scan_format_string("DEBUG: %x %x %x %x") == FORMAT_DETECTED_LEAK_ATTEMPT, "Detectou tentativa de leak com %%x");
    TEST_ASSERT(scan_format_string("Ponteiro: %p") == FORMAT_DETECTED_LEAK_ATTEMPT, "Detectou tentativa de leak com %%p");

    // Caso 3: Tentativa de escrita de memória (%n)
    TEST_ASSERT(scan_format_string("Nome: Alice%n") == FORMAT_DETECTED_PERCENT_N, "Detectou exploit de escrita arbitraria %%n");

    // Caso 4: Geração de log seguro
    char log_buf[64];
    int bytes = safe_format_log(log_buf, sizeof(log_buf), "[SEC_LOG]", "%x %n tentativa de payload");
    TEST_ASSERT(bytes > 0, "Log formatado com sucesso");
    TEST_ASSERT(strstr(log_buf, "%x %n") != NULL, "Especificadores maliciosos tratados como texto puro e inofensivo");
}

static void test_integer_overflow(void) {
    printf("\n=== Testes de QA: Proteção contra Integer Overflow ===\n");

    unsigned int sum = 0;
    // Caso 1: Soma unsigned comum
    TEST_ASSERT(safe_add_uint(100, 200, &sum) == true && sum == 300, "Soma normal segura");

    // Caso 2: Estouro de unsigned int
    TEST_ASSERT(safe_add_uint(UINT_MAX, 1, &sum) == false, "Detectou overflow em UINT_MAX + 1");
    TEST_ASSERT(safe_add_uint(UINT_MAX - 10, 15, &sum) == false, "Detectou wrap-around iminente");

    // Caso 3: Multiplicação segura de size_t
    size_t prod = 0;
    TEST_ASSERT(safe_multiply_size_t(10, 20, &prod) == true && prod == 200, "Multiplicação segura");
    TEST_ASSERT(safe_multiply_size_t(SIZE_MAX / 2, 3, &prod) == false, "Detectou overflow na alocação de buffer");

    // Caso 4: Alocação com guarda de overflow
    void *ptr_valido = safe_calloc_guard(10, sizeof(int));
    TEST_ASSERT(ptr_valido != NULL, "Alocação legítima concedida");
    free(ptr_valido);

    void *ptr_invalido = safe_calloc_guard(SIZE_MAX / 2, 4);
    TEST_ASSERT(ptr_invalido == NULL, "Alocação com parâmetros maliciosos de overflow bloqueada");
}

int main(void) {
    printf("====================================================\n");
    printf("  SUITE DE TESTES DE QA - C HACKING DEFENSE LABS   \n");
    printf("====================================================\n\n");

    test_buffer_overflow();
    test_format_string();
    test_integer_overflow();

    printf("\n----------------------------------------------------\n");
    printf("Total de testes: %d | Aprovados: %d | Falhas: %d\n",
           g_tests_total, g_tests_passed, g_tests_total - g_tests_passed);
    printf("----------------------------------------------------\n");

    return (g_tests_passed == g_tests_total) ? 0 : 1;
}
