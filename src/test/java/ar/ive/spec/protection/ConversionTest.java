package ar.ive.spec.protection;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * La conversión: resolver contra la tabla, deshacer lo que el valor
 * tenga puesto, volver a hacer lo que haga falta, y negarse cuando no
 * se puede.
 */
class ConversionTest {

    private static final Classification TARJETA =
            Classification.of("cardholderData", Sensitivity.RESTRICTED);
    /**
     * En estas tablas hay siempre un nivel que ve el valor entero: sin
     * eso, la forma de guardado sería la técnica del único nivel que
     * hay, el valor ya estaría guardado así, y no habría ninguna
     * conversión que mirar.
     */
    private static final TechniqueSpec VALOR_REAL = TechniqueSpec.of(Technique.FULL);

    private static final Classification CLAVE =
            Classification.of("credential", Sensitivity.RESTRICTED);

    /** Una tabla de mentira: lo que devuelve está fijado por nivel. */
    private static final class Tabla implements DecisionTable {

        private final Map<String, TechniqueSpec> porNivel = new LinkedHashMap<>();

        Tabla con(String trustLevel, TechniqueSpec spec) {
            porNivel.put(trustLevel, spec);
            return this;
        }

        @Override
        public TechniqueSpec techniqueFor(Classification classification, String trustLevel) {
            return porNivel.get(trustLevel);
        }

        @Override
        public Set<String> trustLevels() {
            return porNivel.keySet();
        }
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

    /** Cifrado de mentira, reversible y a la vista. */
    private static final class Claves implements KeyProvider {

        @Override
        public byte[] encrypt(byte[] plain, Classification classification) {
            return ("cif:" + new String(plain, java.nio.charset.StandardCharsets.UTF_8))
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

        @Override
        public byte[] decrypt(byte[] encrypted, Classification classification) {
            String texto = new String(encrypted, java.nio.charset.StandardCharsets.UTF_8);
            return texto.substring("cif:".length()).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private static DataProtection sin(Tabla tabla) {
        return DataProtection.with(tabla).build();
    }

    private static DataProtection con(Tabla tabla) {
        return DataProtection.with(tabla).tokens(new Tokens()).build();
    }

    // --- La forma de guardado ---

    @Test
    void si_todos_reciben_lo_mismo_se_guarda_esa_forma() {
        // El caso de la contraseña: nadie la ve nunca, así que guardar
        // el hash no le cierra la puerta a nadie.
        var hash = new TechniqueSpec(Technique.HASHED, Map.of(TechniqueSpec.ALGORITHM, "SHA-256"));
        var p = sin(new Tabla().con("internal", hash).con("partner", hash));
        assertEquals(hash, p.storageFormFor(CLAVE));
    }

    @Test
    void si_las_salidas_diferen_hay_que_guardar_el_valor_real() {
        var p = sin(new Tabla()
                .con("internal", TechniqueSpec.of(Technique.FULL))
                .con("partner", new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "4"))));
        assertEquals(Technique.FULL, p.storageFormFor(TARJETA).technique());
    }

    @Test
    void la_misma_tecnica_con_otros_parametros_ya_son_dos_formas() {
        // Un enmascarado dejando cuatro no permite producir uno dejando
        // dos: no es el mismo dato con menos, es otro valor.
        var p = sin(new Tabla()
                .con("internal", new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "4")))
                .con("partner", new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "2"))));
        assertEquals(Technique.FULL, p.storageFormFor(TARJETA).technique());
    }

    @Test
    void quien_no_ve_nada_no_obliga_a_guardar_de_ninguna_forma() {
        var hash = TechniqueSpec.of(Technique.HASHED);
        var p = sin(new Tabla()
                .con("internal", hash)
                .con("anonymous", TechniqueSpec.of(Technique.OMITTED))
                .con("public", TechniqueSpec.of(Technique.REDACTED)));
        assertEquals(hash, p.storageFormFor(CLAVE));
    }

    @Test
    void sin_niveles_declarados_se_guarda_el_valor_real() {
        // Es lo único que no cierra puertas que todavía no se sabe si
        // alguien va a necesitar.
        assertEquals(Technique.FULL, sin(new Tabla()).storageFormFor(TARJETA).technique());
    }

    @Test
    void un_token_igual_para_todos_alcanza_como_forma_de_guardado() {
        var token = TechniqueSpec.of(Technique.TOKENIZED);
        var p = con(new Tabla().con("internal", token).con("partner", token));
        assertEquals(token, p.storageFormFor(TARJETA));
        // Y el valor real se recupera al leer, porque el token vuelve.
        assertEquals("4111111111111111",
                p.fromStorage("tok_4111111111111111", String.class, TARJETA));
    }

    // --- La bajada y la subida ---

    @Test
    void hacia_el_almacenamiento_se_aplica_la_forma_de_guardado() {
        var p = sin(new Tabla().con("internal", TechniqueSpec.of(Technique.HASHED)));
        Object guardado = p.toStorage("hunter2", String.class, CLAVE);
        assertNotEquals("hunter2", guardado);
        assertEquals(64, String.valueOf(guardado).length()); // SHA-256 en hexa
        // Y al leer no hay vuelta que dar: el hash es el dato.
        assertEquals(guardado, p.fromStorage(guardado, String.class, CLAVE));
    }

    @Test
    void la_sal_sale_de_la_tabla_y_cambia_el_hash() {
        var conSal = sin(new Tabla().con("internal",
                new TechniqueSpec(Technique.HASHED, Map.of(TechniqueSpec.SALT, "abc"))));
        var sinSal = sin(new Tabla().con("internal", TechniqueSpec.of(Technique.HASHED)));
        assertNotEquals(sinSal.toStorage("hunter2", String.class, CLAVE),
                conSal.toStorage("hunter2", String.class, CLAVE));
    }

    // --- Hacia un destinatario ---

    @Test
    void desde_el_valor_real_se_produce_lo_que_le_toca_a_cada_uno() {
        var p = sin(new Tabla()
                .con("internal", TechniqueSpec.of(Technique.FULL))
                .con("partner", new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "4"))));

        assertEquals("4111111111111111",
                p.toRecipient("4111111111111111", String.class, TARJETA, "internal"));
        assertEquals("************1111",
                p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
    }

    @Test
    void lo_que_ya_esta_en_la_forma_pedida_no_se_toca() {
        // La contraseña se guarda hasheada y sale hasheada: si esto
        // deshiciera para rehacer, pediría una vuelta que no existe.
        var hash = TechniqueSpec.of(Technique.HASHED);
        var p = sin(new Tabla().con("internal", hash));
        String guardado = String.valueOf(p.toStorage("hunter2", String.class, CLAVE));
        assertEquals(guardado,
                p.toRecipient(guardado, String.class, CLAVE, "internal"));
    }

    @Test
    void la_regla_de_guardado_hace_que_nunca_falte_la_vuelta() {
        // Si un nivel necesita el valor real, la forma de guardado ya
        // es el valor real: la negativa por falta de vuelta no puede
        // aparecer sola, y eso es justamente lo que la regla compra.
        var p = con(new Tabla()
                .con("internal", TechniqueSpec.of(Technique.FULL))
                .con("partner", TechniqueSpec.of(Technique.TOKENIZED)));
        assertEquals(Technique.FULL, p.storageFormFor(TARJETA).technique());
        assertEquals("tok_4111111111111111",
                p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
    }

    @Test
    void un_valor_que_llega_ya_protegido_de_afuera_y_no_vuelve_se_niega() {
        var p = sin(new Tabla().con("internal", TechniqueSpec.of(Technique.FULL)));
        var e = assertThrows(IrreversibleTechniqueException.class,
                () -> p.toRecipient("a1b2c3", String.class,
                        TARJETA, "internal", Technique.HASHED));
        assertTrue(e.getMessage().contains("HASHED"));
        assertTrue(e.getMessage().contains("cardholderData"));
    }

    @Test
    void un_token_que_llega_de_afuera_se_deshace_para_darle_al_que_puede_verlo() {
        var p = con(new Tabla().con("internal", TechniqueSpec.of(Technique.FULL)));
        assertEquals("4111111111111111",
                p.toRecipient("tok_4111111111111111", String.class,
                        TARJETA, "internal", Technique.TOKENIZED));
    }

    @Test
    void tapar_no_necesita_ver_el_dato_y_se_puede_sobre_lo_que_no_vuelve() {
        var p = sin(new Tabla()
                .con("internal", TechniqueSpec.of(Technique.HASHED))
                .con("anonymous", TechniqueSpec.of(Technique.REDACTED)));
        assertEquals("[REDACTED]",
                p.toRecipient("a1b2c3", String.class, CLAVE, "anonymous"));
    }

    @Test
    void omitido_devuelve_nulo_porque_la_ausencia_la_resuelve_el_serializador() {
        var p = sin(new Tabla().con("anonymous", TechniqueSpec.of(Technique.OMITTED)));
        assertNull(p.toRecipient("4111111111111111", String.class, TARJETA, "anonymous"));
    }

    @Test
    void un_valor_que_no_esta_no_se_protege() {
        var p = sin(new Tabla().con("partner", new TechniqueSpec(Technique.MASKED, Map.of())));
        assertNull(p.toRecipient(null, String.class, TARJETA, "partner"));
    }

    // --- Se niega ---

    @Test
    void sin_el_servicio_de_tokenizacion_se_niega_y_dice_cual_falta() {
        var p = sin(new Tabla().con("partner", TechniqueSpec.of(Technique.TOKENIZED)));
        var e = assertThrows(MissingImplementationException.class,
                () -> p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
        assertEquals(Technique.Requirement.TOKENS, e.requirement());
    }

    @Test
    void una_tabla_que_no_contesta_no_autoriza_nada() {
        // La falta de respuesta no puede leerse como "mostralo entero".
        var p = sin(new Tabla().con("internal", TechniqueSpec.of(Technique.FULL)));
        assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.toRecipient("4111111111111111", String.class,
                        TARJETA, "un-nivel-que-la-tabla-no-conoce"));
    }

    @Test
    void lo_que_la_tecnica_produce_tiene_que_entrar_donde_va() {
        // Un número de tarjeta enmascarado ya no es un número.
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner",
                new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "4"))));
        var e = assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.toRecipient(4111111111111111L, Long.class, TARJETA, "partner"));
        assertTrue(e.getMessage().contains("MASKED"));
        assertTrue(e.getMessage().contains("Long"));
    }

    // --- Enmascarado ---

    @Test
    void enmascarar_dejando_mas_de_lo_que_hay_tapa_todo() {
        // Un parámetro pensado para un valor largo no puede dejar en
        // claro uno corto.
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner",
                new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "8"))));
        assertEquals("*****",
                p.toRecipient("12345", String.class, TARJETA, "partner"));
    }

    @Test
    void se_puede_dejar_a_la_vista_el_lado_izquierdo_y_elegir_con_que_se_tapa() {
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner", new TechniqueSpec(Technique.MASKED,
                Map.of(TechniqueSpec.KEEP, "3", TechniqueSpec.SIDE, "left", "mask", "#"))));
        assertEquals("411#############",
                p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
    }

    @Test
    void un_keep_que_no_es_un_numero_es_un_error_de_la_tabla() {
        // No declararlo es una decisión --tapar todo--; declararlo mal
        // no lo es. Que la respuesta protectora fuera la misma no
        // alcanza: nadie iba a arreglar esa fila nunca.
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner",
                new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "cuatro"))));
        var e = assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
        assertTrue(e.getMessage().contains("cuatro"));
    }

    @Test
    void un_lado_que_no_existe_es_un_error_de_la_tabla() {
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner", new TechniqueSpec(Technique.MASKED,
                Map.of(TechniqueSpec.KEEP, "3", TechniqueSpec.SIDE, "arriba"))));
        assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
    }

    // --- Generalización ---

    @Test
    void generalizar_una_fecha_al_anio_funciona_tipada_y_como_texto() {
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner",
                new TechniqueSpec(Technique.GENERALIZED, Map.of(TechniqueSpec.RULE, "year"))));
        var nacimiento = Classification.of("personalData", Sensitivity.CONFIDENTIAL);
        assertEquals("1980",
                p.toRecipient(LocalDate.of(1980, 5, 17), String.class, nacimiento, "partner"));
        assertEquals("1980",
                p.toRecipient("1980-05-17", String.class, nacimiento, "partner"));
    }

    @Test
    void generalizar_un_numero_lo_deja_en_un_rango() {
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner",
                new TechniqueSpec(Technique.GENERALIZED, Map.of(TechniqueSpec.RULE, "range:10"))));
        var ingreso = Classification.of("financialData", Sensitivity.CONFIDENTIAL);
        assertEquals("40-49", p.toRecipient(47, String.class, ingreso, "partner"));
    }

    @Test
    void una_regla_de_generalizacion_del_dominio_no_se_adivina() {
        // Un código postal a una región es conocimiento del negocio. No
        // es un error de la tabla —una regla propia es lo esperable—:
        // lo que falta es que este sistema la implemente, y de eso se
        // entera acá, no devolviendo el dato sin generalizar.
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner",
                new TechniqueSpec(Technique.GENERALIZED, Map.of(TechniqueSpec.RULE, "region"))));
        var e = assertThrows(MissingImplementationException.class,
                () -> p.toRecipient("1425", String.class, TARJETA, "partner"));
        assertEquals(Technique.Requirement.RULES, e.requirement());
        assertTrue(e.getMessage().contains(Generalizer.class.getName()));
    }

    @Test
    void generalizar_a_un_prefijo_que_no_reduce_nada_es_un_error_de_la_tabla() {
        var p = sin(new Tabla().con("internal", VALOR_REAL).con("partner",
                new TechniqueSpec(Technique.GENERALIZED, Map.of(TechniqueSpec.RULE, "prefix:16"))));
        assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.toRecipient("4111111111111111", String.class, TARJETA, "partner"));
    }

    // --- El cifrado en reposo ---

    @Test
    void lo_que_se_guarda_entero_se_guarda_cifrado() {
        var p = DataProtection.with(new Tabla()
                        .con("internal", VALOR_REAL)
                        .con("partner", new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "4"))))
                .keys(new Claves())
                .build();

        Object columna = p.toStorage("4111111111111111", byte[].class, TARJETA);
        assertInstanceOf(byte[].class, columna);
        assertEquals("cif:4111111111111111",
                new String((byte[]) columna, java.nio.charset.StandardCharsets.UTF_8));
        // Y al leer vuelve el valor real: nadie ve un dato cifrado.
        assertEquals("4111111111111111",
                p.fromStorage(columna, String.class, TARJETA));
    }

    @Test
    void sin_gestor_de_claves_y_sin_decir_nada_se_niega() {
        // LA AUSENCIA NO ES UNA DECISION: que no haya gestor de claves
        // no puede querer decir "entonces guardalo en claro". Es lo
        // mismo que tokenizar sin servicio de tokenización.
        var p = sin(new Tabla()
                .con("internal", VALOR_REAL)
                .con("partner", new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "4"))));
        var e = assertThrows(MissingImplementationException.class,
                () -> p.toStorage("4111111111111111", String.class, TARJETA));
        assertEquals(Technique.Requirement.KEYS, e.requirement());
        assertTrue(e.getMessage().contains(KeyProvider.class.getName()));
    }

    @Test
    void no_cifrar_en_reposo_se_puede_decidir_pero_hay_que_decirlo() {
        // Puede estar bien --cifrado de disco, de tablespace-- y es una
        // decisión de quien opera. Lo que no puede es deducirse de que
        // falte una implementación.
        var p = DataProtection.with(new Tabla()
                        .con("internal", VALOR_REAL)
                        .con("partner", new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "4"))))
                .withoutEncryptionAtRest()
                .build();
        assertEquals("4111111111111111",
                p.toStorage("4111111111111111", String.class, TARJETA));
    }

    @Test
    void decir_que_no_se_cifra_y_pasar_las_claves_es_una_contradiccion() {
        var b = DataProtection.with(new Tabla()).withoutEncryptionAtRest().keys(new Claves());
        assertThrows(IllegalStateException.class, b::build);
    }

    @Test
    void por_debajo_del_piso_no_hace_falta_gestor_de_claves() {
        // Cifrar lo público no protege nada, así que tampoco se exige
        // con qué: la negativa aparece solo donde el cifrado hacía falta.
        var publico = Classification.of("catalogData", Sensitivity.PUBLIC);
        var p = sin(new Tabla().con("internal", VALOR_REAL));
        assertEquals("gato", p.toStorage("gato", String.class, publico));
    }

    @Test
    void una_tabla_que_devuelve_null_en_vez_de_un_conjunto_de_niveles_no_contesto() {
        // Un conjunto vacío es una respuesta y está documentada; un null
        // no es ninguna, y leerlo como vacío decidiría la forma de
        // guardado a partir de algo que nadie dijo.
        var p = DataProtection.with(new DecisionTable() {
            @Override
            public TechniqueSpec techniqueFor(Classification classification, String trustLevel) {
                return VALOR_REAL;
            }

            @Override
            public Set<String> trustLevels() {
                return null;
            }
        }).withoutEncryptionAtRest().build();
        assertThrows(IllegalStateException.class, () -> p.storageFormFor(TARJETA));
    }

    @Test
    void declarar_desde_donde_se_cifra_sin_decir_con_que_no_se_construye() {
        // La peor de las fallas sería la callada: no cifrar nada.
        var b = DataProtection.with(new Tabla()).encryptAtRestFrom(Sensitivity.INTERNAL);
        assertThrows(IllegalStateException.class, b::build);
    }

    @Test
    void por_debajo_del_piso_de_sensibilidad_no_se_cifra() {
        // Cifrar lo público no protege nada y rompe las consultas.
        var publico = Classification.of("catalogData", Sensitivity.PUBLIC);
        var p = DataProtection.with(new Tabla().con("internal", VALOR_REAL))
                .keys(new Claves())
                .build();
        assertEquals("gato", p.toStorage("gato", String.class, publico));
    }

    @Test
    void lo_que_se_guarda_hasheado_no_se_cifra() {
        // No hay nada que recuperar, y cifrarlo lo dejaría inservible
        // hasta para comparar, que es lo único que un hash permite.
        var hash = TechniqueSpec.of(Technique.HASHED);
        var p = DataProtection.with(new Tabla().con("internal", hash)).keys(new Claves()).build();
        Object guardado = p.toStorage("hunter2", String.class, CLAVE);
        assertInstanceOf(String.class, guardado);
        assertEquals(64, String.valueOf(guardado).length());
    }

    @Test
    void un_numero_cifrado_vuelve_siendo_un_numero() {
        // Lo que se descifra son bytes, y el campo puede no ser texto.
        var cuenta = Classification.of("financialData", Sensitivity.RESTRICTED);
        var p = DataProtection.with(new Tabla()
                        .con("internal", VALOR_REAL)
                        .con("partner", TechniqueSpec.of(Technique.REDACTED)))
                .keys(new Claves())
                .build();
        Object columna = p.toStorage(123456789L, byte[].class, cuenta);
        assertEquals(123456789L, p.fromStorage(columna, Long.class, cuenta));
    }

    @Test
    void el_tipo_de_la_columna_lo_elige_quien_llama_no_la_tabla() {
        // El conversor NO SABE si se va a cifrar --lo decide la tabla, en
        // runtime-- y no tiene por que saberlo: pide el tipo que tiene la
        // columna. Si el tipo dependiera de esa decision, una base habria
        // que re-migrarla porque alguien agrego un gestor de claves.
        var p = DataProtection.with(new Tabla().con("internal", VALOR_REAL))
                .keys(new Claves())
                .build();

        Object enTexto = p.toStorage("4111111111111111", String.class, TARJETA);
        assertInstanceOf(String.class, enTexto);
        assertEquals("cif:4111111111111111", new String(
                java.util.Base64.getDecoder().decode((String) enTexto),
                java.nio.charset.StandardCharsets.UTF_8));
        assertEquals("4111111111111111", p.fromStorage(enTexto, String.class, TARJETA));

        Object enBytes = p.toStorage("4111111111111111", byte[].class, TARJETA);
        assertInstanceOf(byte[].class, enBytes);
        assertEquals("4111111111111111", p.fromStorage(enBytes, String.class, TARJETA));
    }

    @Test
    void una_columna_que_no_puede_aguantar_un_cifrado_se_niega() {
        var p = DataProtection.with(new Tabla().con("internal", VALOR_REAL))
                .keys(new Claves())
                .build();
        var e = assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.toStorage("4111111111111111", Long.class, TARJETA));
        assertTrue(e.getMessage().contains("Base64"));
    }

    @Test
    void si_el_dato_se_guarda_cifrado_lo_que_haya_en_la_columna_tiene_que_serlo() {
        // Devolver tal cual lo que no es un cifrado seria devolver
        // basura y llamarla dato.
        var p = DataProtection.with(new Tabla().con("internal", VALOR_REAL))
                .keys(new Claves())
                .build();
        assertThrows(UnsupportedTechniqueSpecException.class,
                () -> p.fromStorage("esto no es base64 %%%", String.class, TARJETA));
    }

    // --- La generalización del dominio ---

    @Test
    void una_regla_propia_la_resuelve_el_dominio() {
        var p = DataProtection.with(new Tabla().con("internal", VALOR_REAL).con("partner",
                        new TechniqueSpec(Technique.GENERALIZED, Map.of(TechniqueSpec.RULE, "region"))))
                .generalizer((value, rule, classification) -> "AMBA")
                .build();
        assertEquals("AMBA",
                p.toRecipient("1425", String.class, TARJETA, "partner"));
    }

    @Test
    void las_cuatro_reglas_propias_de_la_libreria_no_las_pisa_el_dominio() {
        // La misma tabla tiene que proteger igual en dos sistemas.
        var p = DataProtection.with(new Tabla().con("internal", VALOR_REAL).con("partner",
                        new TechniqueSpec(Technique.GENERALIZED, Map.of(TechniqueSpec.RULE, "year"))))
                .generalizer((value, rule, classification) -> "lo que se le cante")
                .build();
        assertEquals("1980",
                p.toRecipient("1980-05-17", String.class, TARJETA, "partner"));
    }
}
