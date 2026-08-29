package ar.ive.spec.protection;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Lo que el modelo permite decir, comprobado contra la librería —no
 * contra los ejemplos que hay a mano—. Cada prueba de acá sale de una
 * frase de {@code 02-structure.md}, sección "Clasificación de datos".
 */
class ModeloTest {

    private static final TechniqueSpec VALOR_REAL = TechniqueSpec.of(Technique.FULL);

    private static final Classification TARJETA =
            Classification.of("cardholderData", Sensitivity.RESTRICTED, "pci-dss");
    private static final Classification SALUD =
            Classification.of("healthData", Sensitivity.RESTRICTED, "gdpr-art9", "hipaa");

    // ------------------------------------------------------------------
    // El techo: la tabla no puede contradecirse a sí misma
    // ------------------------------------------------------------------

    @Test
    void una_regla_que_pasa_el_techo_de_la_propia_tabla_se_niega() {
        // "Declarar valor completo para un destinatario de poca
        // confianza sobre un dato restringido no es una decisión
        // legítima sino un error de especificación."
        var tabla = PrecedenceTable.builder()
                .forClass("cardholderData", "anonymous", TechniqueSpec.of(Technique.FULL))
                .ceilingForSensitivity(Sensitivity.RESTRICTED, "anonymous", Technique.MASKED)
                .build();
        var p = DataProtection.with(tabla).build();

        var e = assertThrows(AboveCeilingException.class,
                () -> p.toRecipient("4111111111111111", String.class, TARJETA, "anonymous"));
        assertEquals(Technique.FULL, e.technique());
        assertEquals(Technique.MASKED, e.ceiling());
        assertTrue(e.getMessage().contains("cardholderData"));
    }

    @Test
    void por_debajo_del_techo_la_regla_manda() {
        // El techo dice hasta dónde, no qué: la regla elige dentro.
        var tabla = PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "internal", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "partner",
                        new TechniqueSpec(Technique.HASHED, Map.of()))
                .ceilingForSensitivity(Sensitivity.RESTRICTED, "partner", Technique.MASKED)
                .build();
        var p = DataProtection.with(tabla).build();
        assertEquals(64, String.valueOf(
                p.toRecipient("4111111111111111", String.class, TARJETA, "partner")).length());
    }

    @Test
    void sin_techo_declarado_la_tabla_queda_como_estaba() {
        var tabla = PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "internal", TechniqueSpec.of(Technique.FULL))
                .build();
        var p = DataProtection.with(tabla).build();
        assertEquals("4111111111111111",
                p.toRecipient("4111111111111111", String.class, TARJETA, "internal"));
    }

    @Test
    void el_techo_tambien_vale_para_decidir_como_se_guarda() {
        // Si solo se comprobara en la salida, una forma de guardado
        // podría quedar fijada por una regla que el techo no admite, y
        // eso se descubriría con el dato ya escrito.
        var tabla = PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "internal", TechniqueSpec.of(Technique.FULL))
                .ceilingForSensitivity(Sensitivity.RESTRICTED, "internal", Technique.TOKENIZED)
                .build();
        var p = DataProtection.with(tabla).build();
        assertThrows(AboveCeilingException.class, () -> p.storageFormFor(TARJETA));
    }

    // ------------------------------------------------------------------
    // La forma desconocida: cuando el otro lado no usa IVE
    // ------------------------------------------------------------------

    @Test
    void de_una_fuente_que_no_declara_la_forma_no_se_supone_que_esta_en_claro() {
        // "Un token que conserva el formato del original es
        // indistinguible del valor real por inspección."
        var tabla = PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "partner", TechniqueSpec.of(Technique.TOKENIZED))
                .build();
        var p = DataProtection.with(tabla).tokens(new Tokens()).build();

        var e = assertThrows(UnknownFormException.class,
                () -> p.toRecipientOfUnknownForm("4111111111111111", String.class,
                        TARJETA, "partner"));
        assertEquals(Technique.TOKENIZED, e.technique());
    }

    @Test
    void lo_que_no_mira_el_dato_se_puede_dar_sin_saber_la_forma() {
        // Adivinar de más es aceptable; adivinar de menos, no.
        var tabla = PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "anonymous", TechniqueSpec.of(Technique.REDACTED))
                .forSensitivity(Sensitivity.RESTRICTED, "nadie", TechniqueSpec.of(Technique.OMITTED))
                .build();
        var p = DataProtection.with(tabla).build();
        assertEquals("[REDACTED]", p.toRecipientOfUnknownForm(
                "4111111111111111", String.class, TARJETA, "anonymous"));
        assertNull(p.toRecipientOfUnknownForm(
                "4111111111111111", String.class, TARJETA, "nadie"));
    }

    // ------------------------------------------------------------------
    // La entrada: tratarlo como sensible desde que llega
    // ------------------------------------------------------------------

    @Test
    void un_dato_clasificado_no_aparece_en_un_registro() {
        var p = DataProtection.with(PrecedenceTable.builder().build()).build();
        assertEquals("[REDACTED]", p.forLogging("4111111111111111", TARJETA));
    }

    @Test
    void una_organizacion_puede_querer_seguir_el_mismo_dato_entre_dos_lineas() {
        // Un hash con sal de sistema permite correlacionar sin revelar.
        // Es una decisión, y se toma en un solo lugar.
        var tabla = PrecedenceTable.builder()
                .logging(new TechniqueSpec(Technique.HASHED, Map.of(TechniqueSpec.SALT, "sistema")))
                .build();
        var p = DataProtection.with(tabla).build();
        String una = p.forLogging("4111111111111111", TARJETA);
        String otra = p.forLogging("4111111111111111", TARJETA);
        assertEquals(una, otra);
        assertFalse(una.contains("4111"));
    }

    @Test
    void un_registro_no_tiene_destinatario_y_por_eso_no_lleva_nivel() {
        // Si llevara nivel, cada línea de log tendría que resolver a
        // quién le habla, y no le habla a nadie.
        var p = DataProtection.with(PrecedenceTable.builder().build()).build();
        assertNull(p.forLogging(null, TARJETA));
    }

    // ------------------------------------------------------------------
    // La sal: las dos decisiones del modelo, las dos expresables
    // ------------------------------------------------------------------

    @Test
    void la_sal_de_sistema_deja_el_hash_estable_y_comparable() {
        var p = conRegla(new TechniqueSpec(Technique.HASHED,
                Map.of(TechniqueSpec.SALT, "abc", TechniqueSpec.SALT_SCOPE, TechniqueSpec.SALT_SYSTEM)));
        assertEquals(hash(p), hash(p));
    }

    @Test
    void la_sal_por_valor_rompe_la_correlacion_y_tambien_la_comparacion() {
        var p = conRegla(new TechniqueSpec(Technique.HASHED,
                Map.of(TechniqueSpec.SALT_SCOPE, TechniqueSpec.SALT_VALUE)));
        assertNotEquals(hash(p), hash(p));
    }

    @Test
    void un_alcance_de_sal_que_no_existe_es_un_error_de_la_tabla() {
        var p = conRegla(new TechniqueSpec(Technique.HASHED,
                Map.of(TechniqueSpec.SALT_SCOPE, "por-usuario")));
        assertThrows(UnsupportedTechniqueSpecException.class, () -> hash(p));
    }

    /**
     * El nivel que ve el valor entero no está de adorno: sin él la forma
     * de guardado sería el hash, el valor ya estaría hasheado, y no
     * habría ningún hash que hacer.
     */
    private static DataProtection conRegla(TechniqueSpec spec) {
        return DataProtection.with(PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "internal", TechniqueSpec.of(Technique.FULL))
                .forSensitivity(Sensitivity.RESTRICTED, "partner", spec)
                .build()).build();
    }

    private static String hash(DataProtection p) {
        return String.valueOf(
                p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
    }

    // ------------------------------------------------------------------
    // La precedencia, escrita una sola vez
    // ------------------------------------------------------------------

    @Test
    void lo_particular_gana_sobre_lo_generico() {
        // "cardholderData es restringido, pero qué se puede mostrar de
        // una tarjeta lo dice PCI DSS y no se deduce de restringido."
        var tabla = PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "partner", TechniqueSpec.of(Technique.REDACTED))
                .forClass("cardholderData", "partner",
                        new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "4")))
                .build();
        assertEquals(Technique.MASKED, tabla.techniqueFor(TARJETA, "partner").technique());
        // Y el mismo nivel, sobre otro dato restringido, sigue con la genérica.
        assertEquals(Technique.REDACTED, tabla.techniqueFor(SALUD, "partner").technique());
    }

    @Test
    void una_regla_por_cumplimiento_no_tiene_que_enumerar_las_clases() {
        // "Todo lo que caiga bajo gdpr-art9 sale enmascarado", sin
        // saber qué clases lo declaran hoy.
        var tabla = PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "partner", TechniqueSpec.of(Technique.FULL))
                .forCompliance("gdpr-art9", "partner", TechniqueSpec.of(Technique.REDACTED))
                .build();
        assertEquals(Technique.REDACTED, tabla.techniqueFor(SALUD, "partner").technique());
        assertEquals(Technique.FULL, tabla.techniqueFor(TARJETA, "partner").technique());
    }

    @Test
    void la_clase_gana_sobre_el_cumplimiento_y_el_cumplimiento_sobre_la_sensibilidad() {
        var tabla = PrecedenceTable.builder()
                .forSensitivity(Sensitivity.RESTRICTED, "partner", TechniqueSpec.of(Technique.FULL))
                .forCompliance("hipaa", "partner", TechniqueSpec.of(Technique.HASHED))
                .forClass("healthData", "partner", TechniqueSpec.of(Technique.TOKENIZED))
                .build();
        assertEquals(Technique.TOKENIZED, tabla.techniqueFor(SALUD, "partner").technique());
    }

    @Test
    void una_regla_para_un_nivel_puntual_gana_sobre_la_que_vale_para_todos() {
        var tabla = PrecedenceTable.builder()
                .forClass("cardholderData", PrecedenceTable.ANY_LEVEL, TechniqueSpec.of(Technique.REDACTED))
                .forClass("cardholderData", "internal", TechniqueSpec.of(Technique.FULL))
                .build();
        assertEquals(Technique.FULL, tabla.techniqueFor(TARJETA, "internal").technique());
        assertEquals(Technique.REDACTED, tabla.techniqueFor(TARJETA, "partner").technique());
    }

    @Test
    void el_eje_de_la_clasificacion_manda_sobre_el_del_nivel() {
        // Lo que el modelo llama particular es la clase, no el nivel.
        var tabla = PrecedenceTable.builder()
                .forClass("cardholderData", PrecedenceTable.ANY_LEVEL, TechniqueSpec.of(Technique.REDACTED))
                .forSensitivity(Sensitivity.RESTRICTED, "partner", TechniqueSpec.of(Technique.FULL))
                .build();
        assertEquals(Technique.REDACTED, tabla.techniqueFor(TARJETA, "partner").technique());
    }

    @Test
    void con_varias_clases_gana_la_mas_protectora() {
        // No hay forma de que exponer de más sea la respuesta correcta a
        // una ambigüedad, y elegir por orden de declaración haría que
        // mover una línea del catálogo cambiara lo que se ve.
        var dosClases = new Classification(
                List.of("personalIdentifier", "fiscalData"), Sensitivity.CONFIDENTIAL);
        var tabla = PrecedenceTable.builder()
                .forClass("personalIdentifier", "partner", TechniqueSpec.of(Technique.FULL))
                .forClass("fiscalData", "partner", TechniqueSpec.of(Technique.HASHED))
                .build();
        assertEquals(Technique.HASHED, tabla.techniqueFor(dosClases, "partner").technique());
    }

    @Test
    void una_regla_para_todos_los_niveles_no_alcanza_al_invocador_desconocido() {
        // "Un Intent sin trustLevel no tiene ninguna proteccion por
        // nivel de confianza aplicada -- no hay ningun valor por defecto
        // implicito." "Para todos mis niveles" habla de los niveles que
        // la organizacion declaro; el que llama sin que se sepa quien es
        // no es uno de ellos.
        var tabla = PrecedenceTable.builder()
                .forClass("cardholderData", PrecedenceTable.ANY_LEVEL, VALOR_REAL)
                .build();
        assertEquals(Technique.FULL, tabla.techniqueFor(TARJETA, "partner").technique());
        assertNull(tabla.techniqueFor(TARJETA, null));

        var p = DataProtection.with(tabla).withoutEncryptionAtRest().build();
        assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.toRecipient("4111111111111111", String.class, TARJETA, null));
    }

    @Test
    void al_desconocido_se_le_contesta_si_alguien_escribio_su_regla() {
        var tabla = PrecedenceTable.builder()
                .forClass("cardholderData", PrecedenceTable.ANY_LEVEL, VALOR_REAL)
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER,
                        TechniqueSpec.of(Technique.REDACTED))
                .build();
        var p = DataProtection.with(tabla).withoutEncryptionAtRest().build();
        assertEquals("[REDACTED]",
                p.toRecipient("4111111111111111", String.class, TARJETA, null));
    }

    @Test
    void ni_el_comodin_ni_el_desconocido_son_niveles_de_confianza() {
        // Si entraran a la lista, la forma de guardado se decidiria
        // contra ellos.
        var tabla = PrecedenceTable.builder()
                .forClass("cardholderData", PrecedenceTable.ANY_LEVEL, VALOR_REAL)
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER,
                        TechniqueSpec.of(Technique.REDACTED))
                .forClass("cardholderData", "partner", TechniqueSpec.of(Technique.HASHED))
                .build();
        assertEquals(Set.of("partner"), tabla.trustLevels());
    }

    @Test
    void sin_ninguna_regla_la_tabla_no_contesta_y_la_libreria_se_niega() {
        var tabla = PrecedenceTable.builder().build();
        assertNull(tabla.techniqueFor(TARJETA, "partner"));
        var p = DataProtection.with(tabla).build();
        assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
    }

    @Test
    void los_niveles_salen_de_las_reglas_para_que_no_falte_ninguno() {
        // Si la lista quedara a mano, olvidarse uno se descubriría en
        // producción: el dato guardado en una forma que no lo sirve.
        var tabla = PrecedenceTable.builder()
                .forClass("cardholderData", "internal", TechniqueSpec.of(Technique.FULL))
                .forSensitivity(Sensitivity.RESTRICTED, "partner", TechniqueSpec.of(Technique.REDACTED))
                .forClass("cardholderData", PrecedenceTable.ANY_LEVEL, TechniqueSpec.of(Technique.REDACTED))
                .trustLevel("todavia-sin-reglas")
                .build();
        assertEquals(Set.of("internal", "partner", "todavia-sin-reglas"), tabla.trustLevels());
    }

    // ------------------------------------------------------------------
    // El cumplimiento viaja
    // ------------------------------------------------------------------

    @Test
    void la_clasificacion_dice_de_donde_sale_la_obligacion() {
        assertTrue(SALUD.under("gdpr-art9"));
        assertFalse(SALUD.under("pci-dss"));
        // Y aparece en el mensaje: sin eso no se puede volver a la
        // especificación desde un stack trace.
        assertEquals("healthData (RESTRICTED) [gdpr-art9, hipaa]", SALUD.toString());
    }

    @Test
    void sin_cumplimiento_declarado_ese_eje_no_se_usa_y_nada_cambia() {
        var sinNorma = Classification.of("strategicPricing", Sensitivity.RESTRICTED);
        assertEquals(List.of(), sinNorma.compliance());
        assertEquals("strategicPricing (RESTRICTED)", sinNorma.toString());
        var tabla = PrecedenceTable.builder()
                .forCompliance("gdpr", "partner", TechniqueSpec.of(Technique.REDACTED))
                .forSensitivity(Sensitivity.RESTRICTED, "partner", TechniqueSpec.of(Technique.HASHED))
                .build();
        assertEquals(Technique.HASHED, tabla.techniqueFor(sinNorma, "partner").technique());
    }

    /** Tokenización de mentira, reversible y estable. */
    private static final class Tokens implements TokenService {

        @Override
        public String tokenize(String value, Classification classification) {
            return "tok_" + value;
        }

        @Override
        public String detokenize(String token, Classification classification) {
            return token.startsWith("tok_") ? token.substring(4) : token;
        }
    }
}
