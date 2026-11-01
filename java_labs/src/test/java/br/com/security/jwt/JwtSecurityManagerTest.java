package br.com.security.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Testes de QA: Segurança de JWT")
class JwtSecurityManagerTest {

    private JwtSecurityManager jwtManager;

    @BeforeEach
    void setUp() {
        jwtManager = new JwtSecurityManager("super_secret_signing_key_2026_!@#");
    }

    @Test
    @DisplayName("Token legítimo recém-gerado deve ser validado com sucesso")
    void deveValidarTokenLegitimo() {
        String token = jwtManager.gerarToken("alice", "USER", 3600);
        assertTrue(jwtManager.validarTokenSeguro(token));
    }

    @Test
    @DisplayName("Deve rejeitar token com payload adulterado (escalonamento de privilégio)")
    void deveRejeitarTokenAdulterado() {
        String token = jwtManager.gerarToken("bob", "USER", 3600);
        String[] partes = token.split("\\.");

        // Atacante altera role de USER para ADMIN
        String payloadOriginal = new String(Base64.getUrlDecoder().decode(partes[1]), StandardCharsets.UTF_8);
        String payloadAdulterado = payloadOriginal.replace("\"USER\"", "\"ADMIN\"");
        String novoPayloadEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadAdulterado.getBytes(StandardCharsets.UTF_8));

        String tokenFalso = partes[0] + "." + novoPayloadEncoded + "." + partes[2];
        assertFalse(jwtManager.validarTokenSeguro(tokenFalso), "Token com assinatura inconsistente deve ser recusado");
    }

    @Test
    @DisplayName("Deve rejeitar ataque de algoritmo 'none' (alg: none)")
    void deveRejeitarAtaqueAlgoritmoNone() {
        String headerNone = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"hacker\",\"role\":\"ADMIN\"}".getBytes(StandardCharsets.UTF_8));

        // Token sem assinatura com algoritmo none
        String tokenExploit = headerNone + "." + payload + ".";
        assertFalse(jwtManager.validarTokenSeguro(tokenExploit), "Bypass com alg: none deve ser bloqueado");
    }

    @Test
    @DisplayName("Deve rejeitar token expirado")
    void deveRejeitarTokenExpirado() {
        // Token com TTL negativo (-10s)
        String tokenExpirado = jwtManager.gerarToken("alice", "USER", -10);
        assertFalse(jwtManager.validarTokenSeguro(tokenExpirado));
    }
}
