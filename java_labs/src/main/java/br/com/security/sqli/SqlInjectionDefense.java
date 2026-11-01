package br.com.security.sqli;

import java.util.*;

/**
 * ============================================================================
 * Exercício: Defesa contra SQL Injection (SQLi)
 * Referência: OWASP Top 10 (A03:2021 - Injection) e CWE-89
 * ============================================================================
 *
 * Descrição Teórica:
 * SQL Injection ocorre quando dados não confiáveis inseridos pelo usuário
 * são concatenados diretamente na estrutura de comandos SQL, permitindo
 * que um atacante altere a lógica da consulta (ex: bypass de autenticação
 * com "' OR '1'='1" ou extração de dados com UNION SELECT).
 *
 * Solução Defensiva:
 * O uso de Consultas Parametrizadas (Prepared Statements). Com parâmetros,
 * o banco de dados trata a entrada do usuário estritamente como dado literal,
 * nunca como instrução executável.
 */
public class SqlInjectionDefense {

    public static class Usuario {
        private final String login;
        private final String senhaHash;
        private final String perfil;

        public Usuario(String login, String senhaHash, String perfil) {
            this.login = login;
            this.senhaHash = senhaHash;
            this.perfil = perfil;
        }

        public String getLogin() { return login; }
        public String getPerfil() { return perfil; }
    }

    private final Map<String, Usuario> tabelaUsuarios;

    public SqlInjectionDefense() {
        // LinkedHashMap preserva a ordem de inserção do banco de dados simulado
        tabelaUsuarios = new LinkedHashMap<>();
        tabelaUsuarios.put("admin", new Usuario("admin", "admin_hash_secret", "ADMINISTRADOR"));
        tabelaUsuarios.put("joao", new Usuario("joao", "joao_hash_123", "USUARIO_PADRAO"));
    }

    /**
     * VULNERÁVEL: Simula autenticação via concatenação direta de strings.
     * Exemplo de ataque: se o usuário passar "' OR '1'='1" no campo login,
     * a condição se torna verdadeira para qualquer registro.
     */
    public Optional<Usuario> autenticarInseguro(String loginInput, String senhaHashInput) {
        String consultaSimulada = "SELECT * FROM usuarios WHERE login = '" + loginInput + "' AND senha = '" + senhaHashInput + "'";

        // Simula o interpretador SQL ingênuo avaliando a cláusula "' OR '1'='1"
        if (consultaSimulada.contains("' OR '1'='1") || consultaSimulada.contains("' or '1'='1")) {
            // Exploit bem-sucedido: retorna o primeiro usuário da base (admin)
            return tabelaUsuarios.values().stream().findFirst();
        }

        Usuario u = tabelaUsuarios.get(loginInput);
        if (u != null && u.senhaHash.equals(senhaHashInput)) {
            return Optional.of(u);
        }
        return Optional.empty();
    }

    /**
     * SEGURO: Utiliza parametrização estrita. Os valores de entrada são
     * tratados puramente como literais de busca, anulando qualquer sintaxe SQL injetada.
     */
    public Optional<Usuario> autenticarSeguro(String loginParam, String senhaHashParam) {
        Objects.requireNonNull(loginParam, "Login não pode ser nulo.");
        Objects.requireNonNull(senhaHashParam, "Senha não pode ser nula.");

        // O valor loginParam é comparado literalmente por igualdade exata
        Usuario u = tabelaUsuarios.get(loginParam);
        if (u != null && u.senhaHash.equals(senhaHashParam)) {
            return Optional.of(u);
        }
        return Optional.empty();
    }
}
