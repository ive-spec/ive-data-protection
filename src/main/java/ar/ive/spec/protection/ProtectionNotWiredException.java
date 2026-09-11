package ar.ive.spec.protection;

/**
 * SOMETHING DELIVERS CLASSIFIED DATA AND NOBODY WIRED HOW TO PROTECT IT.
 *
 * <p>Thrown when a component that hands out classified data (an MCP
 * server, for instance) is built without a {@link DataProtection}. It is
 * thrown WHEN BUILDING, not on the first call: the alternative is failing
 * on somebody's request -- or worse, not failing and handing over the
 * whole row -- and that would show up months later.</p>
 *
 * <p>The message is the caller's: it knows what it is and what it
 * delivers.</p>
 */
public class ProtectionNotWiredException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    public ProtectionNotWiredException(String message) {
        super(message);
    }
}
