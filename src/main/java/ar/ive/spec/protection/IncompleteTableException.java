package ar.ive.spec.protection;

import java.util.List;

/**
 * THE DECISION TABLE LEAVES CASES UNRESOLVED, so the system does not start.
 *
 * <p>Thrown by {@link TableVerification#requireComplete}. It is the ONE
 * exception every consumer throws for this: the generated Spring
 * verification, the MCP servers, anything that checks the table at
 * startup. It extends {@link IllegalStateException} because that is what
 * it is: the system is not in a state in which it can serve.</p>
 *
 * <p>It is not a {@link ProtectionException}: that one says a VALUE could
 * not be protected, during a call. This one says the TABLE is incomplete,
 * before any call.</p>
 *
 * <p>The message lists every finding, one per line, and says how each one
 * is fixed: with an explicit row. There is no switch to silence it on
 * purpose -- a row that says {@code OMITTED} or {@code REDACTED} is a
 * decision; a missing row is not.</p>
 */
public class IncompleteTableException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    private final transient List<Finding> findings;

    public IncompleteTableException(List<Finding> findings) {
        super(messageFor(findings));
        this.findings = List.copyOf(findings);
    }

    /** What the table does not resolve. Never empty. */
    public List<Finding> findings() {
        return findings;
    }

    private static String messageFor(List<Finding> findings) {
        StringBuilder detail = new StringBuilder();
        for (Finding finding : findings) {
            if (detail.length() > 0) {
                detail.append("\n  ");
            }
            detail.append(finding);
        }
        return "La tabla de decisión de la protección de datos no resuelve " + findings.size()
                + " caso(s):\n  " + detail
                + "\nCada uno se arregla con una fila explícita en la tabla. Si la intención"
                + " es negar el dato, la fila igual va: OMITTED o REDACTED lo dicen, y una"
                + " fila que falta no dice nada.";
    }
}
