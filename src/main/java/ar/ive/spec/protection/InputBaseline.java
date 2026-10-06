package ar.ive.spec.protection;

/**
 * WHAT IS ACCEPTED WHEN THE TABLE WROTE NOTHING FOR THAT PAIR: the
 * integrity of the datum and the clearance of whoever sends it.
 *
 * <p>The mirror of {@link Baseline}. {@code true} accepts, {@code false}
 * ignores, {@code null} does not cover the pair -- and then it is ignored
 * too: a missing answer never authorizes a write.</p>
 */
@FunctionalInterface
public interface InputBaseline {

    /**
     * @param integrity the integrity of the datum
     * @param clearance how much trust whoever sends it has, or {@code null}
     *                  for the unknown caller and a level declared without
     *                  a quantity
     */
    Boolean forPair(Integrity integrity, Integer clearance);

    /**
     * THE MATRIX THE LIBRARY BRINGS FOR WHAT COMES IN.
     *
     * <pre>
     *                c1       c2       c3+      unknown
     *   HIGH         ignore   ignore   ignore   ignore
     *   MODERATE     ignore   ignore   accept   ignore
     *   LOW          accept   accept   accept   accept
     * </pre>
     *
     * <p>It keeps the same two properties as {@link Baseline#CONSERVATIVE}:
     * IT FAILS CLOSED -- the lower the clearance, the less it accepts -- and
     * IT NEVER ACCEPTS A {@code HIGH} DATUM FROM OUTSIDE, not even from the
     * highest clearance: for that the row is written. And {@code LOW} is
     * accepted from anyone, as {@code PUBLIC} is shown to anyone.</p>
     */
    InputBaseline CONSERVATIVE = (integrity, clearance) -> {
        if (integrity == null) {
            return null;
        }
        return switch (integrity) {
            case LOW -> true;
            case MODERATE -> clearance != null && clearance >= 3;
            case HIGH -> false;
        };
    };

    /** NO DEFAULT FOR WHAT COMES IN: the table answers, or nothing is accepted. */
    InputBaseline NONE = (integrity, clearance) -> null;
}
