package br.com.security.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

/**
 * ============================================================================
 * Exercício: Segurança de Tokens JWT (JSON Web Tokens) e Detecção de Adulteração
 * Referência: CWE-347 (Improper Verification of Cryptographic Signature)
 * ============================================================================
 *
 * Descrição Teórica:
 * JWTs são tokens compactos compostos por Header, Payload e Signature:
 *   Base64Url(Header) . Base64Url(Payload) . Base64Url(Signature)
 *
 * Principais Falhas de Segurança em JWT:
 * 1. Ataque "alg: none": O atacante altera o cabeçalho para "alg": "none"
 *    e remove a assinatura, tentando fazer a aplicação aceitar o token sem validação.
 * 2. Adulteração de Payload: Modificação de privilégios (ex: "role": "admin") sem
 *    recalcular ou ter acesso à chave secreta de assinatura.
 * 3. Falta de verificação de expiração ("exp").
 */
public class JwtSecurityManager {

    private final byte[] secretKey;

    public JwtSecurityManager(String secret) {
        Objects.requireNonNull(secret, "A chave secreta não pode ser nula.");
        this.secretKey = secret.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Cria um JWT assinado com HMAC-SHA256 (HS256).
     *
     * @param subject Identificador do usuário (sub)
     * @param role    Perfil de acesso (role)
     * @param ttlSeconds Tempo de vida em segundos
     * @return String JWT formatada
     */
    public String gerarToken(String subject, String role, long ttlSeconds) {
        long exp = Instant.now().getEpochSecond() + ttlSeconds;

        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = String.format("{\"sub\":\"%s\",\"role\":\"%s\",\"exp\":%d}", subject, role, exp);

        String encodedHeader = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

        String contentToSign = encodedHeader + "." + encodedPayload;
        byte[] signature = calcularHmacSha256(contentToSign, secretKey);
        String encodedSignature = base64UrlEncode(signature);

        return contentToSign + "." + encodedSignature;
    }

    /**
     * Valida estritamente a autenticidade e integridade de um JWT.
     * Defende contra:
     * - Ataque de algoritmo "none"
     * - Modificação de payload / falsificação de assinatura
     * - Tokens expirados
     *
     * @param token String JWT a ser verificada
     * @return true se o token for autêntico, válido e não expirado
     */
    public boolean validarTokenSeguro(String token) {
        if (token == null) return false;
        String[] partes = token.split("\\.");
        if (partes.length != 3) {
            return false;
        }

        String encodedHeader = partes[0];
        String encodedPayload = partes[1];
        String encodedSignature = partes[2];

        // 1. Defesa contra ataque "alg: none"
        String headerJson = new String(base64UrlDecode(encodedHeader), StandardCharsets.UTF_8);
        if (headerJson.toLowerCase().contains("\"alg\":\"none\"") || encodedSignature.isEmpty()) {
            return false; // Rejeição de tentativa de bypass de assinatura!
        }

        // 2. Validação da assinatura criptográfica usando chave secreta
        String contentToSign = encodedHeader + "." + encodedPayload;
        byte[] assinaturaEsperada = calcularHmacSha256(contentToSign, secretKey);
        byte[] assinaturaRecebida = base64UrlDecode(encodedSignature);

        // Uso de MessageDigest.isEqual para prevenção de Timing Attacks
        if (!MessageDigest.isEqual(assinaturaEsperada, assinaturaRecebida)) {
            return false; // Assinatura inválida (token adulterado)
        }

        // 3. Validação de expiração (exp)
        String payloadJson = new String(base64UrlDecode(encodedPayload), StandardCharsets.UTF_8);
        return !isExpirado(payloadJson);
    }

    private boolean isExpirado(String payloadJson) {
        int expIndex = payloadJson.indexOf("\"exp\":");
        if (expIndex != -1) {
            int start = expIndex + 6;
            int end = payloadJson.indexOf("}", start);
            if (end != -1) {
                try {
                    long exp = Long.parseLong(payloadJson.substring(start, end).trim());
                    return Instant.now().getEpochSecond() > exp;
                } catch (NumberFormatException ignored) {}
            }
        }
        return false;
    }

    private static byte[] calcularHmacSha256(String data, byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Falha ao calcular HMAC-SHA256", e);
        }
    }

    private static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] base64UrlDecode(String str) {
        return Base64.getUrlDecoder().decode(str);
    }
}
