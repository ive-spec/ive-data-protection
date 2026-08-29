package ar.ive.spec.protection;

/**
 * NO SE PUDO PROTEGER, ASI QUE NO SE DEVUELVE NADA.
 *
 * <p>Esta librería <b>falla cerrado</b>: si no puede aplicar lo que la
 * tabla decidió, se niega en vez de devolver el valor en claro. Es el
 * mismo criterio que el generador con un helper que no carga — seguir
 * como si nada es lo único que no se puede hacer, porque el resultado
 * sería exponer justamente el dato que había que proteger.</p>
 *
 * <p>Las dos derivadas separan dos problemas que se arreglan en manos
 * distintas: {@link IrreversibleTechniqueException} es un error de
 * diseño de la tabla, y {@link MissingImplementationException} es un
 * hueco de despliegue. Una por técnica no tendría sentido: quien llama
 * es código generado y no puede hacer nada distinto según cuál sea.</p>
 *
 * <p>El mensaje nombra siempre la técnica, la clasificación y hacia
 * dónde iba el valor: sin eso queda un stack trace del que no se puede
 * volver a la especificación.</p>
 */
public class ProtectionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient Classification classification;
    private final Technique technique;
    private final String trustLevel;

    protected ProtectionException(String message,
                                  Classification classification,
                                  Technique technique,
                                  String trustLevel) {
        super(message);
        this.classification = classification;
        this.technique = technique;
        this.trustLevel = trustLevel;
    }

    /** Qué era el dato. Puede ser null si falló antes de saberlo. */
    public Classification classification() {
        return classification;
    }

    /** Qué había que aplicar. */
    public Technique technique() {
        return technique;
    }

    /** Para quién era. Null cuando no se pudo determinar. */
    public String trustLevel() {
        return trustLevel;
    }

    /** El destinatario, dicho para un mensaje. */
    static String forWhom(String trustLevel) {
        return trustLevel == null ? "un destinatario de nivel indeterminado" : "trustLevel '" + trustLevel + "'";
    }
}
