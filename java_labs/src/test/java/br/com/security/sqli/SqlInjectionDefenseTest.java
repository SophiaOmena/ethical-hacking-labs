package br.com.security.sqli;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Testes de QA: Defesa contra SQL Injection")
class SqlInjectionDefenseTest {

    private SqlInjectionDefense dao;

    @BeforeEach
    void setUp() {
        dao = new SqlInjectionDefense();
    }

    @Test
    @DisplayName("Autenticação insegura deve ser vulnerável a bypass com ' OR '1'='1")
    void deveDemonstrarVulnerabilidadeEmConsultaConcatenada() {
        String payload = "' OR '1'='1";
        Optional<SqlInjectionDefense.Usuario> usuario = dao.autenticarInseguro(payload, "qualquer_coisa");

        assertTrue(usuario.isPresent(), "O exploit de SQLi deveria obter acesso indevido na consulta vulnerável");
        assertEquals("admin", usuario.get().getLogin());
    }

    @Test
    @DisplayName("Autenticação segura deve neutralizar tentativa de injeção de SQL")
    void deveNeutralizarSQLiEmConsultaParametrizada() {
        String payload = "' OR '1'='1";
        Optional<SqlInjectionDefense.Usuario> usuario = dao.autenticarSeguro(payload, "qualquer_coisa");

        assertFalse(usuario.isPresent(), "A consulta parametrizada deve bloquear o bypass de SQLi");
    }

    @Test
    @DisplayName("Autenticação segura com credenciais corretas deve autenticar com sucesso")
    void deveAutenticarCredenciaisValidas() {
        Optional<SqlInjectionDefense.Usuario> usuario = dao.autenticarSeguro("admin", "admin_hash_secret");
        assertTrue(usuario.isPresent());
        assertEquals("ADMINISTRADOR", usuario.get().getPerfil());
    }
}
