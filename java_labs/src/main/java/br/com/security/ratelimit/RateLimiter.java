package br.com.security.ratelimit;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================================
 * Exercício: Limitador de Taxa (Rate Limiter) contra Ataques de Força Bruta
 * Referência: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
 * Paradigma: Algoritmo Token Bucket (Balde de Fichas)
 * ============================================================================
 *
 * Descrição Teórica:
 * Ataques de Força Bruta (Brute-Force), Credential Stuffing e DoS na camada de
 * aplicação tentam sobrecarregar rotas críticas (como endpoints de login).
 * O algoritmo Token Bucket mantém uma cota máxima de requisições que se regenera
 * a uma taxa fixa por segundo, bloqueando requisições excessivas.
 */
public class RateLimiter {

    private static class Balde {
        final double capacidadeMaxima;
        final double taxaRecargaPorSegundo;
        double fichasAtuais;
        long ultimoReabastecimentoEpoch;

        Balde(double capacidade, double taxaPorSegundo) {
            this.capacidadeMaxima = capacidade;
            this.taxaRecargaPorSegundo = taxaPorSegundo;
            this.fichasAtuais = capacidade;
            this.ultimoReabastecimentoEpoch = Instant.now().getEpochSecond();
        }

        synchronized boolean consumirFicha() {
            reabastecer();
            if (fichasAtuais >= 1.0) {
                fichasAtuais -= 1.0;
                return true; // Requisição permitida
            }
            return false; // Cota esgotada! Bloqueio por rate limiting
        }

        private void reabastecer() {
            long agora = Instant.now().getEpochSecond();
            long deltaSegundos = Math.max(0, agora - ultimoReabastecimentoEpoch);
            if (deltaSegundos > 0) {
                fichasAtuais = Math.min(capacidadeMaxima, fichasAtuais + (deltaSegundos * taxaRecargaPorSegundo));
                ultimoReabastecimentoEpoch = agora;
            }
        }
    }

    private final double capacidade;
    private final double taxaRecargaPorSegundo;
    private final Map<String, Balde> baldesPorCliente;

    public RateLimiter(int capacidade, double taxaRecargaPorSegundo) {
        if (capacidade <= 0 || taxaRecargaPorSegundo <= 0) {
            throw new IllegalArgumentException("Capacidade e taxa de recarga devem ser positivas.");
        }
        this.capacidade = capacidade;
        this.taxaRecargaPorSegundo = taxaRecargaPorSegundo;
        this.baldesPorCliente = new ConcurrentHashMap<>();
    }

    /**
     * Tenta processar uma requisição para a chave informada (ex: IP ou usuário).
     *
     * @param chave Identificador único do cliente
     * @return true se a requisição estiver dentro do limite permitido, false se for bloqueada
     */
    public boolean permitirRequisicao(String chave) {
        Objects.requireNonNull(chave, "A chave do cliente não pode ser nula.");
        Balde balde = baldesPorCliente.computeIfAbsent(
                chave,
                k -> new Balde(capacidade, taxaRecargaPorSegundo)
        );
        return balde.consumirFicha();
    }
}
