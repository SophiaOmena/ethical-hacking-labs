package br.com.security.xss;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Testes de QA: Sanitização contra XSS")
class XssSanitizerTest {

    @Test
    @DisplayName("Deve escapar tags HTML perigosas para entidades seguras")
    void deveEscaparCaracteresHtml() {
        String payload = "<script>alert('XSS & Hack');</script>";
        String seguro = XssSanitizer.escaparHtml(payload);

        assertEquals("&lt;script&gt;alert(&#x27;XSS &amp; Hack&#x27;);&lt;&#x2F;script&gt;", seguro);
        assertFalse(seguro.contains("<"));
        assertFalse(seguro.contains(">"));
    }

    @Test
    @DisplayName("Deve neutralizar tags de script e manipuladores de eventos embutidos")
    void deveRemoverScriptsEEventHandlers() {
        String payload = "Olá <script>alert(1)</script><img src='x' onerror='alert(2)'>mundo!";
        String neutralizado = XssSanitizer.neutralizarScripts(payload);

        assertFalse(neutralizado.contains("<script>"));
        assertFalse(neutralizado.contains("onerror="));
        assertTrue(neutralizado.contains("Olá "));
        assertTrue(neutralizado.contains("mundo!"));
    }
}
