package br.com.security.xss;

import java.util.regex.Pattern;

/**
 * ============================================================================
 * Exercício: Higienização e Sanitização contra Cross-Site Scripting (XSS)
 * Referência: OWASP Top 10 (A03:2021) e CWE-79 (Improper Neutralization of Input)
 * ============================================================================
 *
 * Descrição Teórica:
 * XSS ocorre quando uma aplicação web inclui dados não confiáveis em uma página
 * sem validação ou escape contextual adequado, permitindo que scripts maliciosos
 * (JavaScript) sejam executados no navegador de outros usuários.
 *
 * Princípios Defensivos:
 * 1. Escape HTML Contextual: conversão de caracteres com significado sintático
 *    para suas respectivas entidades HTML seguras.
 * 2. Remoção de vetores ativos (scripts, iframes, handlers de eventos).
 */
public final class XssSanitizer {

    private static final Pattern SCRIPT_TAG_PATTERN = Pattern.compile("<script.*?>.*?</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern EVENT_HANDLER_PATTERN = Pattern.compile("on\\w+\\s*=\\s*['\"].*?['\"]", Pattern.CASE_INSENSITIVE);
    private static final Pattern JAVASCRIPT_URI_PATTERN = Pattern.compile("javascript:\\s*", Pattern.CASE_INSENSITIVE);

    private XssSanitizer() {
        // Construtor privado para utilitário
    }

    /**
     * Aplica escape contextual estrito em caracteres HTML perigosos.
     * Converte:
     *   & -> &amp;
     *   < -> &lt;
     *   > -> &gt;
     *   " -> &quot;
     *   ' -> &#x27;
     *   / -> &#x2F;
     *
     * @param input Texto do usuário não sanitizado
     * @return Texto seguro para renderização no corpo de páginas HTML
     */
    public static String escaparHtml(String input) {
        if (input == null) return null;

        StringBuilder sb = new StringBuilder(input.length() + 16);
        for (char c : input.toCharArray()) {
            switch (c) {
                case '&':  sb.append("&amp;"); break;
                case '<':  sb.append("&lt;"); break;
                case '>':  sb.append("&gt;"); break;
                case '"':  sb.append("&quot;"); break;
                case '\'': sb.append("&#x27;"); break;
                case '/':  sb.append("&#x2F;"); break;
                default:   sb.append(c); break;
            }
        }
        return sb.toString();
    }

    /**
     * Remove ativamente tags de script e manipuladores de eventos embutidos.
     *
     * @param html Conteúdo HTML
     * @return HTML desprovido de scripts executáveis
     */
    public static String neutralizarScripts(String html) {
        if (html == null) return null;

        String limpo = SCRIPT_TAG_PATTERN.matcher(html).replaceAll("");
        limpo = EVENT_HANDLER_PATTERN.matcher(limpo).replaceAll("");
        limpo = JAVASCRIPT_URI_PATTERN.matcher(limpo).replaceAll("");
        return limpo;
    }
}
