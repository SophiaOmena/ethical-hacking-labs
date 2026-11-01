package br.com.security.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Testes de QA: Rate Limiter")
class RateLimiterTest {

    @Test
    @DisplayName("Deve permitir requisições dentro da capacidade e bloquear excedentes")
    void deveBloquearTentativasExcessivas() {
        // Capacidade máxima de 3 fichas, recarga de 1 ficha a cada segundo
        RateLimiter limiter = new RateLimiter(3, 1.0);
        String ip = "192.168.1.100";

        assertTrue(limiter.permitirRequisicao(ip), "1ª tentativa permitida");
        assertTrue(limiter.permitirRequisicao(ip), "2ª tentativa permitida");
        assertTrue(limiter.permitirRequisicao(ip), "3ª tentativa permitida");

        // 4ª tentativa consecutiva imediata deve ser bloqueada
        assertFalse(limiter.permitirRequisicao(ip), "4ª tentativa bloqueada por rate limiting!");
    }

    @Test
    @DisplayName("Clientes distintos devem possuir cotas de requisições isoladas")
    void deveIsolarCotasPorCliente() {
        RateLimiter limiter = new RateLimiter(1, 1.0);

        assertTrue(limiter.permitirRequisicao("cliente_A"));
        assertFalse(limiter.permitirRequisicao("cliente_A"));

        // Cliente B ainda tem sua cota intacta
        assertTrue(limiter.permitirRequisicao("cliente_B"));
    }
}
