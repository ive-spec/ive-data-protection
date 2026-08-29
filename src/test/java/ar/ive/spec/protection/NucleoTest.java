package ar.ive.spec.protection;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Lo que el núcleo decide, fijado.
 *
 * <p>Casi todo acá son declaraciones —qué técnica tiene vuelta, qué
 * necesita cada una—, y justamente por eso conviene tenerlas escritas
 * también como prueba: si alguien marca el hash como reversible, no
 * rompe ninguna compilación, y lo que pasa después es que un dato sale
 * en claro.</p>
 */
class NucleoTest {

    // --- El techo, que es la única comparación que se puede hacer ---

    @Test
    void la_sensibilidad_es_el_unico_eje_ordenado() {
        assertTrue(Sensitivity.RESTRICTED.atLeast(Sensitivity.CONFIDENTIAL));
        assertFalse(Sensitivity.INTERNAL.atLeast(Sensitivity.CONFIDENTIAL));
        // Contra un nivel que no está, nada es "al menos tan sensible":
        // no saber no puede leerse como saber que alcanza.
        assertFalse(Sensitivity.RESTRICTED.atLeast(null));
    }

    @Test
    void la_escala_de_tecnicas_esta_ordenada_de_mas_a_menos_reveladora() {
        // ES EL ORDEN DE DECLARACION DEL ENUM, y de él depende que se
        // pueda comprobar un techo. Reordenarlo no rompe ninguna
        // compilación, y lo que pasa después es que una técnica pasa un
        // techo sin que nadie lo vea. Por eso está escrito acá.
        Technique[] deMasAMenos = {
                Technique.FULL, Technique.GENERALIZED, Technique.MASKED, Technique.TOKENIZED,
                Technique.HASHED, Technique.REDACTED, Technique.OMITTED
        };
        assertArrayEquals(deMasAMenos, Technique.values());
        for (int i = 0; i < deMasAMenos.length; i++) {
            for (int j = i + 1; j < deMasAMenos.length; j++) {
                assertTrue(deMasAMenos[i].revealsMoreThan(deMasAMenos[j]),
                        deMasAMenos[i] + " tiene que revelar más que " + deMasAMenos[j]);
                assertFalse(deMasAMenos[j].revealsMoreThan(deMasAMenos[i]));
            }
        }
        // Ninguna revela más que sí misma, y contra nada no se compara.
        assertFalse(Technique.MASKED.revealsMoreThan(Technique.MASKED));
        assertFalse(Technique.FULL.revealsMoreThan(null));
    }

    // --- Qué es el dato ---

    @Test
    void una_clasificacion_es_una_lista_y_necesita_al_menos_una_clase() {
        var c = new Classification(List.of("cardholderData", "fiscalData"), Sensitivity.RESTRICTED);
        assertTrue(c.has("fiscalData"));
        assertFalse(c.has("healthData"));
        // Sin ninguna clase no hay nada sobre lo que la tabla decida.
        assertThrows(IllegalArgumentException.class,
                () -> new Classification(List.of(), Sensitivity.PUBLIC));
    }

    @Test
    void la_clasificacion_se_dice_entera_en_una_linea() {
        // Es lo que va a aparecer en el mensaje de una excepción: sin
        // esto, un stack trace no permite volver a la especificación.
        assertEquals("cardholderData (RESTRICTED)",
                Classification.of("cardholderData", Sensitivity.RESTRICTED).toString());
    }

    // --- Las técnicas ---

    @Test
    void solo_el_valor_completo_y_el_token_tienen_vuelta() {
        assertTrue(Technique.FULL.isReversible());
        assertTrue(Technique.TOKENIZED.isReversible());

        // De un hash no se vuelve al valor real; de un enmascarado y de
        // una generalización tampoco: lo que se tapó no está en ningún
        // lado. Redactado y omitido, menos todavía.
        assertFalse(Technique.HASHED.isReversible());
        assertFalse(Technique.MASKED.isReversible());
        assertFalse(Technique.GENERALIZED.isReversible());
        assertFalse(Technique.REDACTED.isReversible());
        assertFalse(Technique.OMITTED.isReversible());
    }

    @Test
    void dos_tecnicas_necesitan_algo_de_la_organizacion_y_el_resto_no() {
        // El token, porque el sustituto lo da un servicio de afuera. La
        // generalización, porque agrupar es conocimiento del dominio y
        // las cuatro reglas que la librería resuelve sola no lo cubren.
        assertEquals(Technique.Requirement.TOKENS, Technique.TOKENIZED.requirement());
        assertEquals(Technique.Requirement.RULES, Technique.GENERALIZED.requirement());
        for (Technique t : Technique.values()) {
            if (t != Technique.TOKENIZED && t != Technique.GENERALIZED) {
                assertEquals(Technique.Requirement.NONE, t.requirement(), t.name());
            }
        }
    }

    @Test
    void omitido_no_produce_un_valor_y_redactado_si() {
        // No es lo mismo: un nulo dice "hay un campo que no te muestro",
        // la ausencia no dice nada.
        assertFalse(Technique.OMITTED.producesValue());
        assertTrue(Technique.REDACTED.producesValue());
    }

    // --- Lo que la tabla devuelve ---

    @Test
    void los_parametros_son_de_la_tabla_y_viajan_tal_cual() {
        var spec = new TechniqueSpec(Technique.MASKED,
                Map.of(TechniqueSpec.KEEP, "4", TechniqueSpec.SIDE, "right", "propio", "algo"));
        assertEquals(4, spec.intParam(TechniqueSpec.KEEP).orElseThrow());
        assertEquals("right", spec.param(TechniqueSpec.SIDE).orElseThrow());
        // Un parámetro que la librería no conoce viaja igual: la tabla
        // es de cada organización.
        assertEquals("algo", spec.param("propio").orElseThrow());
        assertTrue(spec.param("noEsta").isEmpty());
    }

    @Test
    void un_parametro_numerico_mal_escrito_no_revienta_la_llamada() {
        // Es un error de la tabla. Quien aplique la técnica decide si
        // puede seguir sin él o si tiene que negarse; leerlo no es el
        // lugar para decidir eso.
        var spec = new TechniqueSpec(Technique.MASKED, Map.of(TechniqueSpec.KEEP, "cuatro"));
        assertTrue(spec.intParam(TechniqueSpec.KEEP).isEmpty());
    }

    @Test
    void una_tecnica_sin_parametros_no_necesita_mapa() {
        assertEquals(Map.of(), TechniqueSpec.of(Technique.REDACTED).params());
        assertEquals(Map.of(), new TechniqueSpec(Technique.FULL, null).params());
    }

    // --- Falla cerrado ---

    @Test
    void deshacer_lo_que_no_tiene_vuelta_dice_que_pasó_y_de_qué_dato() {
        var c = Classification.of("healthData", Sensitivity.RESTRICTED);
        var e = new IrreversibleTechniqueException(c, Technique.HASHED, Technique.FULL, "internal");
        assertSame(c, e.classification());
        assertEquals(Technique.FULL, e.technique());
        assertEquals("internal", e.trustLevel());
        assertTrue(e.getMessage().contains("HASHED"));
        assertTrue(e.getMessage().contains("healthData"));
        assertTrue(e.getMessage().contains("internal"));
    }

    @Test
    void sin_implementacion_se_niega_y_dice_cual_falta() {
        var c = Classification.of("cardholderData", Sensitivity.RESTRICTED);
        var e = new MissingImplementationException(c, Technique.TOKENIZED, null);
        assertEquals(Technique.Requirement.TOKENS, e.requirement());
        assertTrue(e.getMessage().contains(TokenService.class.getName()));
        // Sin nivel de confianza el mensaje no queda con un "null".
        assertTrue(e.getMessage().contains("indeterminado"));
    }

    @Test
    void las_dos_son_la_misma_familia_y_se_pueden_atrapar_juntas() {
        var c = Classification.of("fiscalData", Sensitivity.CONFIDENTIAL);
        assertInstanceOf(ProtectionException.class,
                new IrreversibleTechniqueException(c, Technique.MASKED, Technique.FULL, "partner"));
        assertInstanceOf(ProtectionException.class,
                new MissingImplementationException(c, Technique.TOKENIZED, "partner"));
    }
}
