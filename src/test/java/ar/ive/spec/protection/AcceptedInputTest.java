package ar.ive.spec.protection;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * WHAT COMES IN: who may set a datum, and the walker that takes out what
 * the sender may not.
 *
 * <p>The same cases as the Python and TypeScript suites.</p>
 */
class AcceptedInputTest {

    private static final Classification ESTADO =
            new Classification(List.of("businessState"), Sensitivity.PUBLIC, List.of(), Integrity.HIGH);
    private static final Classification NOTA =
            new Classification(List.of("internalNote"), Sensitivity.INTERNAL, List.of(), Integrity.MODERATE);
    private static final Classification APODO =
            new Classification(List.of("nickname"), Sensitivity.PUBLIC, List.of(), Integrity.LOW);
    private static final Classification SIN_EVALUAR = Classification.of("whatever", Sensitivity.RESTRICTED);
    private static final List<TrustLevel> NIVELES = List.of(
            new TrustLevel("externo", 1), new TrustLevel("socio", 2), new TrustLevel("interno", 3));

    private static DataProtection conNiveles(DecisionTable table) {
        return DataProtection.with(table).withoutEncryptionAtRest().trustLevels(NIVELES).build();
    }

    private static DataProtection conNiveles() {
        return conNiveles(PrecedenceTable.builder().build());
    }

    @Test
    void theMatrixFailsClosed() {
        for (Integrity integrity : Integrity.values()) {
            for (int clearance = 1; clearance <= 5; clearance++) {
                Boolean higher = InputBaseline.CONSERVATIVE.forPair(integrity, clearance + 1);
                Boolean lower = InputBaseline.CONSERVATIVE.forPair(integrity, clearance);
                assertFalse(Boolean.TRUE.equals(lower) && !Boolean.TRUE.equals(higher), integrity + " at " + clearance);
            }
            Boolean unknown = InputBaseline.CONSERVATIVE.forPair(integrity, null);
            assertFalse(Boolean.TRUE.equals(unknown) && !Boolean.TRUE.equals(InputBaseline.CONSERVATIVE.forPair(integrity, 1)));
        }
    }

    @Test
    void theMatrixNeverAcceptsAHighDatum() {
        for (Integer clearance : new Integer[] { null, 1, 2, 3, 10, 1000 }) {
            assertEquals(Boolean.FALSE, InputBaseline.CONSERVATIVE.forPair(Integrity.HIGH, clearance));
        }
    }

    @Test
    void lowIsAcceptedFromAnyone() {
        assertTrue(conNiveles().acceptsFrom(APODO, null));
        assertTrue(conNiveles().acceptsFrom(APODO, "externo"));
    }

    @Test
    void moderateOnlyFromClearance3Up() {
        DataProtection p = conNiveles();
        assertFalse(p.acceptsFrom(NOTA, "externo"));
        assertFalse(p.acceptsFrom(NOTA, "socio"));
        assertTrue(p.acceptsFrom(NOTA, "interno"));
        assertFalse(p.acceptsFrom(NOTA, null));
    }

    @Test
    void withoutIntegrityItWasNotEvaluated() {
        assertTrue(conNiveles().acceptsFrom(SIN_EVALUAR, null));
    }

    @Test
    void aWrittenRowOpensWhatTheMatrixCloses() {
        DataProtection p = conNiveles(PrecedenceTable.builder().acceptForClass("businessState", "interno", true).build());
        assertTrue(p.acceptsFrom(ESTADO, "interno"));
        assertFalse(p.acceptsFrom(ESTADO, "socio"));
    }

    @Test
    void withinAnAxisTheMostProtectiveWins() {
        Classification dos = new Classification(List.of("businessState", "nickname"), Sensitivity.PUBLIC, List.of(), Integrity.LOW);
        DataProtection p = conNiveles(PrecedenceTable.builder()
                .acceptForClass("nickname", PrecedenceTable.ANY_LEVEL, true)
                .acceptForClass("businessState", PrecedenceTable.ANY_LEVEL, false)
                .build());
        assertFalse(p.acceptsFrom(dos, "interno"));
    }

    @Test
    void withNoInputBaselineOnlyWhatTheTableAcceptsIsTaken() {
        DataProtection p = DataProtection.with(PrecedenceTable.builder().build())
                .withoutEncryptionAtRest().trustLevels(NIVELES).inputBaseline(InputBaseline.NONE).build();
        assertFalse(p.acceptsFrom(APODO, "interno"));
    }

    @Test
    void aLevelNobodyDeclaredIsRefused() {
        assertThrows(UnknownTrustLevelException.class, () -> conNiveles().acceptsFrom(NOTA, "extreno"));
    }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    @Test
    void onMapsWhatIsNotAcceptedGoesAwayAndThePathIsReported() {
        Map<String, Object> body = map("estado", "aprobada", "apodo", "Pepa",
                "items", new ArrayList<>(List.of(map("nota", "a"), map("nota", "b"))));
        List<String> ignored = new ArrayList<>();
        AcceptedInput.filter(body, List.of(
                new GuardedField(List.of("estado"), ESTADO),
                new GuardedField(List.of("apodo"), APODO),
                new GuardedField(List.of("items[]", "nota"), NOTA)), conNiveles(), "socio", ignored::add);
        assertEquals(map("apodo", "Pepa", "items", List.of(map(), map())), body);
        assertEquals(List.of("estado", "items[].nota"), ignored);
    }

    /** A View as the backend builds it: a bean with setters. */
    public static class Reclamo {
        private String estado = "cerrado";
        private String texto = "sin luz";

        public String getEstado() { return estado; }
        public void setEstado(String estado) { this.estado = estado; }
        public String getTexto() { return texto; }
        public void setTexto(String texto) { this.texto = texto; }
    }

    @Test
    void onABeanThePropertyBecomesNull() {
        Reclamo r = AcceptedInput.filter(new Reclamo(),
                List.of(new GuardedField(List.of("estado"), ESTADO)), conNiveles(), "externo", null);
        assertNull(r.getEstado());
        assertEquals("sin luz", r.getTexto());
    }

    /** A View that keeps what arrived, as the backend's do. */
    public static class ReclamoQueRecuerda extends Reclamo {
        private final java.util.Set<String> arrived = new java.util.LinkedHashSet<>(List.of("estado", "texto"));

        public java.util.Set<String> arrived() { return arrived; }
    }

    @Test
    void onABeanThatKeepsWhatArrivedItIsForgotten() {
        ReclamoQueRecuerda r = new ReclamoQueRecuerda();
        List<String> ignored = new ArrayList<>();
        AcceptedInput.filter(r, List.of(new GuardedField(List.of("estado"), ESTADO)), conNiveles(), "externo", ignored::add);
        assertNull(r.getEstado());
        assertEquals(java.util.Set.of("texto"), r.arrived());
        assertEquals(List.of("estado"), ignored);
    }

    @Test
    void aNullThatCameIsTakenOutAndReported() {
        ReclamoQueRecuerda r = new ReclamoQueRecuerda();
        r.setEstado(null);
        List<String> ignored = new ArrayList<>();
        AcceptedInput.filter(r, List.of(new GuardedField(List.of("estado"), ESTADO)), conNiveles(), "externo", ignored::add);
        assertEquals(java.util.Set.of("texto"), r.arrived());
        assertEquals(List.of("estado"), ignored);

        Map<String, Object> body = map("estado", null);
        ignored.clear();
        AcceptedInput.filter(body, List.of(new GuardedField(List.of("estado"), ESTADO)), conNiveles(), "externo", ignored::add);
        assertEquals(map(), body);
        assertEquals(List.of("estado"), ignored);
    }

    @Test
    void whenEverythingIsAcceptedNothingChanges() {
        Map<String, Object> body = map("apodo", "Pepa");
        AcceptedInput.filter(body, List.of(new GuardedField(List.of("apodo"), APODO)), conNiveles(), "externo", null);
        assertEquals(map("apodo", "Pepa"), body);
    }
}
