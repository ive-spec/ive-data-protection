package ar.ive.spec.protection;

import java.util.List;
import java.util.Objects;

/**
 * QUE ES EL DATO: sus clases, su techo de sensibilidad y de dónde sale
 * la obligación de protegerlo.
 *
 * <p>Los tres los resolvió el generador contra el catálogo de la
 * organización; acá llegan resueltos. Esta librería no sabe qué
 * significa {@code cardholderData} ni de qué catálogo salió.</p>
 *
 * <p>NO HAY UNA LISTA UNIVERSAL DE CLASES: cada organización arma la
 * suya. Por eso son textos y no un enum.</p>
 *
 * @param classes    una o más clases del catálogo
 * @param sensitivity el techo: la sensibilidad más alta de sus clases
 * @param compliance de dónde sale la obligación —una ley, una norma de
 *                   industria, un contrato, una decisión propia—.
 *                   <b>Es un eje de decisión, no una etiqueta</b>: una
 *                   tabla puede querer decir "todo lo que caiga bajo
 *                   {@code gdpr-art9} sale enmascarado" sin enumerar las
 *                   clases que hoy lo declaran. Puede venir vacío, y
 *                   entonces ese eje simplemente no se usa.
 */
public record Classification(List<String> classes, Sensitivity sensitivity, List<String> compliance,
                             Integrity integrity) {

    public Classification {
        Objects.requireNonNull(classes, "classes");
        Objects.requireNonNull(sensitivity, "sensitivity");
        if (classes.isEmpty()) {
            throw new IllegalArgumentException("Una clasificación necesita al menos una clase.");
        }
        classes = List.copyOf(classes);
        compliance = compliance == null ? List.of() : List.copyOf(compliance);
    }

    /** Sin cumplimiento declarado: la tabla decide por clase y por sensibilidad. */
    /**
     * Without integrity: NOT EVALUATED. Null is not {@link Integrity#LOW} --
     * nobody said it is harmless -- and the library does not decide on it:
     * what comes in is accepted, as before.
     */
    public Classification(List<String> classes, Sensitivity sensitivity, List<String> compliance) {
        this(classes, sensitivity, compliance, null);
    }

    public Classification(List<String> classes, Sensitivity sensitivity) {
        this(classes, sensitivity, List.of());
    }

    public static Classification of(String clazz, Sensitivity sensitivity) {
        return new Classification(List.of(clazz), sensitivity, List.of());
    }

    public static Classification of(String clazz, Sensitivity sensitivity, String... compliance) {
        return new Classification(List.of(clazz), sensitivity, List.of(compliance));
    }

    public boolean has(String clazz) {
        return classes.contains(clazz);
    }

    /** Si esta obligación alcanza al dato. */
    public boolean under(String norm) {
        return compliance.contains(norm);
    }

    /**
     * Todo el dato en una línea. Es lo que va a aparecer en el mensaje
     * de una excepción: sin esto, un stack trace no permite volver a la
     * especificación.
     */
    @Override
    public String toString() {
        String base = String.join(", ", classes) + " (" + sensitivity + ")";
        return compliance.isEmpty() ? base : base + " [" + String.join(", ", compliance) + "]";
    }
}
