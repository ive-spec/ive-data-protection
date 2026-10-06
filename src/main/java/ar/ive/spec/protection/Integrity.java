package ar.ive.spec.protection;

/**
 * HOW MUCH HARM THE DATUM DOES IF SOMEONE WHO SHOULD NOT CHANGES IT. The
 * order IS the scale.
 *
 * <p>The other axis of NIST FIPS 199 -- {@link Sensitivity} is the
 * confidentiality one -- and what Biba's integrity model orders: nobody
 * writes a datum whose integrity is above their own level. It decides what
 * is ACCEPTED when the datum comes in ({@link DataProtection#acceptsFrom}),
 * never what is shown.</p>
 */
public enum Integrity {
    LOW,
    MODERATE,
    HIGH
}
