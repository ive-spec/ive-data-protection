package ar.ive.spec.protection;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * EL VERIFICADOR: encontrar los agujeros de la tabla SIN datos.
 *
 * <p>Lo que se prueba acá no es que la librería niegue —eso ya está
 * probado— sino que los mismos casos se puedan ENCONTRAR RECORRIENDO,
 * antes de que llegue ninguna petición.</p>
 *
 * <p>SON LOS MISMOS CASOS QUE LA SUITE DE PYTHON, uno por uno. Si acá
 * faltara uno, el mismo sistema pasaría o no según en qué lenguaje esté
 * escrito el servicio que arrancó — y la tabla es una sola.</p>
 */
class VerificacionTest {

    private static final Classification TARJETA =
            Classification.of("cardholderData", Sensitivity.RESTRICTED, "pci-dss");

    private static PrecedenceTable.Builder tabla() {
        return PrecedenceTable.builder();
    }

    /** Las clases de hallazgo encontradas, ordenadas para poder compararlas. */
    private static Set<String> clases(List<Finding> hallazgos) {
        return new TreeSet<>(hallazgos.stream().map(Finding::kind).toList());
    }

    // ------------------------------------------------------------------
    // Lo que encuentra
    // ------------------------------------------------------------------

    @Test
    void una_tabla_completa_no_tiene_nada_que_decir() {
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "externo", new TechniqueSpec(Technique.MASKED, Map.of("keep", "4")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(List.of(), TableVerification.verify(p, List.of(TARJETA)));
    }

    @Test
    void el_invocador_desconocido_se_recorre_siempre() {
        // Es el caso más fácil de olvidar: la regla para "cualquier otro
        // nivel" NO lo cubre, porque esa red sólo se tira cuando hay nivel.
        var t = tabla()
                .trustLevel("interno")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", PrecedenceTable.ANY_LEVEL, TechniqueSpec.of(Technique.REDACTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        var hallazgos = TableVerification.verify(p, List.of(TARJETA));
        assertEquals(Set.of(Finding.SIN_RESPUESTA), clases(hallazgos));
        assertNull(hallazgos.get(0).trustLevel());
    }

    @Test
    void y_deja_de_aparecer_cuando_alguien_lo_decide() {
        // Una fila explícita dice "esto lo decidí yo"; una que falta no
        // dice nada.
        var t = tabla()
                .trustLevel("interno")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", PrecedenceTable.ANY_LEVEL, TechniqueSpec.of(Technique.REDACTED))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(List.of(), TableVerification.verify(p, List.of(TARJETA)));
    }

    @Test
    void encuentra_un_techo_que_la_tabla_se_pasa_a_si_misma() {
        var t = tabla()
                .trustLevel("externo")
                .forClass("cardholderData", "externo", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .ceilingForClass("cardholderData", "externo", Technique.MASKED)
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertTrue(clases(TableVerification.verify(p, List.of(TARJETA))).contains(Finding.SOBRE_EL_TECHO));
    }

    @Test
    void encuentra_un_parametro_mal_escrito() {
        var t = tabla()
                .trustLevel("externo")
                .forClass("cardholderData", "externo", new TechniqueSpec(Technique.MASKED, Map.of("keep", "cuatro")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(Set.of(Finding.PARAMETRO_INVALIDO), clases(TableVerification.verify(p, List.of(TARJETA))));
    }

    @Test
    void encuentra_un_lado_que_no_existe() {
        var t = tabla()
                .trustLevel("externo")
                .forClass("cardholderData", "externo",
                        new TechniqueSpec(Technique.MASKED, Map.of("keep", "4", "side", "arriba")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(Set.of(Finding.PARAMETRO_INVALIDO), clases(TableVerification.verify(p, List.of(TARJETA))));
    }

    @Test
    void encuentra_un_algoritmo_que_no_existe() {
        var t = tabla()
                .trustLevel("externo")
                .forClass("cardholderData", "externo",
                        new TechniqueSpec(Technique.HASHED, Map.of("algorithm", "SHA-999")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(Set.of(Finding.PARAMETRO_INVALIDO), clases(TableVerification.verify(p, List.of(TARJETA))));
    }

    @Test
    void encuentra_que_falta_el_servicio_de_tokens() {
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.TOKENIZED))
                .forClass("cardholderData", "externo", TechniqueSpec.of(Technique.TOKENIZED))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertTrue(clases(TableVerification.verify(p, List.of(TARJETA))).contains(Finding.FALTA_IMPLEMENTACION));
    }

    @Test
    void encuentra_que_falta_el_generalizador_de_una_regla_propia() {
        var t = tabla()
                .trustLevel("externo")
                .forClass("cardholderData", "externo",
                        new TechniqueSpec(Technique.GENERALIZED, Map.of("rule", "tramoEtario")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(Set.of(Finding.FALTA_IMPLEMENTACION), clases(TableVerification.verify(p, List.of(TARJETA))));
    }

    @Test
    void las_reglas_de_la_libreria_no_piden_generalizador() {
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "externo",
                        new TechniqueSpec(Technique.GENERALIZED, Map.of("rule", "prefix:6")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(List.of(), TableVerification.verify(p, List.of(TARJETA)));
    }

    @Test
    void encuentra_que_falta_el_gestor_de_claves() {
        // Se guarda entero, la sensibilidad está en el nivel que se cifra,
        // y no hay con qué. La ausencia no es una decisión.
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "externo", new TechniqueSpec(Technique.MASKED, Map.of("keep", "4")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).build();

        assertTrue(clases(TableVerification.verify(p, List.of(TARJETA))).contains(Finding.FALTA_IMPLEMENTACION));
    }

    @Test
    void y_deja_de_aparecer_si_se_declara_que_no_se_cifra() {
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "externo", new TechniqueSpec(Technique.MASKED, Map.of("keep", "4")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(List.of(), TableVerification.verify(p, List.of(TARJETA)));
    }

    // ------------------------------------------------------------------
    // El tipo del campo: el chequeo que parece de ejecución y no lo es
    // ------------------------------------------------------------------

    @Test
    void un_enmascarado_no_entra_en_un_numero() {
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "externo", new TechniqueSpec(Technique.MASKED, Map.of("keep", "4")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        var hallazgos = TableVerification.verify(p, List.of(TARJETA),
                Map.of("cardholderData", Long.class), Set.of());
        assertEquals(Set.of(Finding.TIPO_INCOMPATIBLE), clases(hallazgos));
    }

    @Test
    void en_un_campo_de_texto_no_hay_nada_que_decir() {
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "externo", new TechniqueSpec(Technique.MASKED, Map.of("keep", "4")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(List.of(), TableVerification.verify(p, List.of(TARJETA),
                Map.of("cardholderData", String.class), Set.of()));
    }

    @Test
    void generalizar_al_anio_si_entra_en_un_entero() {
        // "1980" es un número. El resto de las reglas no.
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "externo",
                        new TechniqueSpec(Technique.GENERALIZED, Map.of("rule", "year")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertEquals(List.of(), TableVerification.verify(p, List.of(TARJETA),
                Map.of("cardholderData", Integer.class), Set.of()));
    }

    @Test
    void un_token_no_se_supone_no_numerico() {
        // Qué forma tiene un token lo decide el servicio de cada
        // organización: suponerlo sería inventar.
        TokenService tokens = new TokenService() {
            @Override
            public String tokenize(String value, Classification classification) {
                return value;
            }

            @Override
            public String detokenize(String token, Classification classification) {
                return token;
            }
        };
        var t = tabla()
                .trustLevel("interno").trustLevel("externo")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.TOKENIZED))
                .forClass("cardholderData", "externo", TechniqueSpec.of(Technique.TOKENIZED))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).tokens(tokens).withoutEncryptionAtRest().build();

        assertEquals(List.of(), TableVerification.verify(p, List.of(TARJETA),
                Map.of("cardholderData", BigDecimal.class), Set.of()));
    }

    // ------------------------------------------------------------------
    // La tabla misma
    // ------------------------------------------------------------------

    @Test
    void una_tabla_que_no_expone_sus_niveles_se_verifica_igual() {
        // Un conjunto vacío es una respuesta válida; los niveles se pasan.
        DecisionTable reservada = new DecisionTable() {
            @Override
            public TechniqueSpec techniqueFor(Classification classification, String trustLevel) {
                return TechniqueSpec.of(Technique.REDACTED);
            }

            @Override
            public Set<String> trustLevels() {
                return Set.of();
            }
        };
        var p = DataProtection.with(reservada).withoutEncryptionAtRest().build();

        assertEquals(List.of(), TableVerification.verify(p, List.of(TARJETA),
                Map.of(), Set.of("interno", "externo")));
    }

    @Test
    void una_tabla_que_devuelve_null_en_vez_de_un_conjunto_no_contesto() {
        DecisionTable sinContestar = new DecisionTable() {
            @Override
            public TechniqueSpec techniqueFor(Classification classification, String trustLevel) {
                return TechniqueSpec.of(Technique.REDACTED);
            }

            @Override
            public Set<String> trustLevels() {
                return null;
            }
        };
        var p = DataProtection.with(sinContestar).withoutEncryptionAtRest().build();

        assertEquals(Set.of(Finding.TABLA_SIN_CONTESTAR),
                clases(TableVerification.verify(p, List.of(TARJETA))));
    }

    // ------------------------------------------------------------------
    // Requiring a complete table
    // ------------------------------------------------------------------

    @Test
    void require_complete_is_silent_on_a_complete_table() {
        var t = tabla()
                .trustLevel("interno")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertDoesNotThrow(() -> TableVerification.requireComplete(p, List.of(TARJETA)));
    }

    @Test
    void require_complete_throws_one_exception_with_every_finding() {
        // Nobody wrote a row for the unknown caller: that is a finding, and
        // the table does not start.
        var t = tabla()
                .trustLevel("interno")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        var e = assertThrows(IncompleteTableException.class,
                () -> TableVerification.requireComplete(p, List.of(TARJETA), Map.of(), Set.of()));
        assertEquals(TableVerification.verify(p, List.of(TARJETA)), e.findings());
        assertInstanceOf(IllegalStateException.class, e);
        assertTrue(e.getMessage().contains(e.findings().get(0).toString()));
        assertTrue(e.getMessage().contains("1 caso(s)"));
    }

    @Test
    void require_complete_uses_the_field_types() {
        var t = tabla()
                .trustLevel("externo")
                .forClass("cardholderData", "externo", new TechniqueSpec(Technique.MASKED, Map.of("keep", "4")))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(t).withoutEncryptionAtRest().build();

        assertDoesNotThrow(() -> TableVerification.requireComplete(p, List.of(TARJETA)));
        var e = assertThrows(IncompleteTableException.class,
                () -> TableVerification.requireComplete(p, List.of(TARJETA),
                        Map.of("cardholderData", BigDecimal.class), Set.of()));
        assertEquals(Set.of(Finding.TIPO_INCOMPATIBLE), clases(e.findings()));
    }
}
