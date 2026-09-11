package ar.ive.spec.protection;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * THE PROTECTED-OUTPUT WALKER: every classified value of an output, by path.
 *
 * <p>The same cases as the Python and TypeScript suites: the walker is one
 * decision in three languages.</p>
 */
class ProtectedOutputTest {

    private static final Classification TARJETA =
            Classification.of("cardholderData", Sensitivity.RESTRICTED, "pci-dss");

    /** "interno" sees it whole, "externo" masked, "nadie" does not see it. */
    private static DataProtection protection() {
        var t = PrecedenceTable.builder()
                .trustLevel("interno").trustLevel("externo").trustLevel("nadie")
                .forClass("cardholderData", "interno", TechniqueSpec.of(Technique.FULL))
                .forClass("cardholderData", "externo", new TechniqueSpec(Technique.MASKED, Map.of("keep", "4")))
                .forClass("cardholderData", "nadie", TechniqueSpec.of(Technique.OMITTED))
                .forClass("cardholderData", PrecedenceTable.UNKNOWN_CALLER, TechniqueSpec.of(Technique.OMITTED))
                .build();
        return DataProtection.with(t).withoutEncryptionAtRest().build();
    }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    private static ProtectedField field(boolean required, String... path) {
        return new ProtectedField(List.of(path), TARJETA, String.class, required);
    }

    @Test
    void protects_a_nested_value_and_leaves_the_rest() {
        var output = map("cuenta", map("numero", "4507990000001234", "titular", "Ana"));
        var result = ProtectedOutput.protect(output, List.of(field(true, "cuenta", "numero")),
                protection(), "externo");

        assertEquals(map("cuenta", map("numero", "************1234", "titular", "Ana")), result);
    }

    @Test
    void works_on_a_copy() {
        var output = map("numero", "4507990000001234");
        ProtectedOutput.protect(output, List.of(field(true, "numero")), protection(), "externo");

        assertEquals("4507990000001234", output.get("numero"));
    }

    @Test
    void enters_every_element_of_a_list() {
        var lista = new ArrayList<Object>(List.of(map("numero", "1111222233334444"), map("numero", "5555666677778888")));
        var output = map("tarjetas", lista);
        var result = ProtectedOutput.protect(output, List.of(field(true, "tarjetas[]", "numero")),
                protection(), "externo");

        assertEquals(map("tarjetas", List.of(map("numero", "************4444"), map("numero", "************8888"))),
                result);
    }

    @Test
    void an_element_of_a_list_is_never_taken_out() {
        var output = map("numeros", new ArrayList<Object>(List.of("1111222233334444", "5555666677778888")));
        var result = ProtectedOutput.protect(output, List.of(field(false, "numeros[]")), protection(), "nadie");

        assertEquals(map("numeros", java.util.Arrays.asList(null, null)), result);
    }

    @Test
    void an_omitted_optional_field_is_taken_out() {
        var result = ProtectedOutput.protect(map("numero", "1111222233334444", "titular", "Ana"),
                List.of(field(false, "numero")), protection(), null);

        assertEquals(map("titular", "Ana"), result);
    }

    @Test
    void an_omitted_required_field_stays_as_null() {
        var result = ProtectedOutput.protect(map("numero", "1111222233334444"),
                List.of(field(true, "numero")), protection(), "nadie");

        assertTrue(((Map<?, ?>) result).containsKey("numero"));
        assertNull(((Map<?, ?>) result).get("numero"));
    }

    @Test
    void a_field_that_already_was_null_stays_null() {
        // "There is no value" and "I will not show it to you" are two
        // different answers.
        var result = ProtectedOutput.protect(map("numero", null), List.of(field(false, "numero")),
                protection(), "nadie");

        assertTrue(((Map<?, ?>) result).containsKey("numero"));
    }

    @Test
    void what_is_not_there_is_not_invented() {
        var result = ProtectedOutput.protect(map("titular", "Ana"), List.of(field(true, "cuenta", "numero")),
                protection(), "externo");

        assertEquals(map("titular", "Ana"), result);
    }

    @Test
    void without_fields_the_output_is_returned_as_is() {
        var output = map("numero", "1111222233334444");

        assertSame(output, ProtectedOutput.protect(output, List.of(), protection(), "externo"));
    }

    @Test
    void protection_not_wired_is_an_illegal_state() {
        assertInstanceOf(IllegalStateException.class, new ProtectionNotWiredException("x"));
    }
}
