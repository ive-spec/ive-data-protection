package ar.ive.spec.protection;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.HexFormat;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * Aplica UNA técnica a UN valor real. No decide nada: la decisión ya la
 * tomó la tabla y llega en el {@link TechniqueSpec}.
 *
 * <p>Es lo único de la librería que produce valores nuevos, y por eso
 * concentra todo lo que puede salir mal por un parámetro mal escrito.
 * Cuando algo no se puede hacer se niega: nunca devuelve el valor sin
 * tocar como salida de emergencia.</p>
 *
 * <p>EL VALOR QUE ENTRA ACÁ ES SIEMPRE EL REAL. Deshacer lo que el valor
 * tenga puesto es cosa de {@link DataProtection}; esta clase empieza
 * donde eso terminó.</p>
 */
final class Techniques {

    /** Lo que ve quien recibe un valor redactado, si la tabla no dice otra cosa. */
    static final String REDACTED_TEXT = "[REDACTED]";

    /** Parámetro abierto: con qué se tapa lo enmascarado. */
    static final String MASK = "mask";

    /** Parámetro abierto: con qué texto se reemplaza lo redactado. */
    static final String TEXT = "text";

    /** Para la sal por valor. Es seguro compartirlo entre hilos. */
    private static final SecureRandom SALT_SOURCE = new SecureRandom();

    private Techniques() {
    }

    static Object apply(TechniqueSpec spec,
                        Object real,
                        Classification classification,
                        String trustLevel,
                        TokenService tokens,
                        Generalizer generalizer) {
        Technique technique = spec.technique();
        // Un valor que no está no se protege: no hay nada que tapar, y
        // fabricar un enmascarado de la nada diría que hay un dato.
        if (real == null) {
            return null;
        }
        return switch (technique) {
            case FULL -> real;
            case OMITTED -> null;
            case REDACTED -> spec.param(TEXT).orElse(REDACTED_TEXT);
            case MASKED -> mask(String.valueOf(real), spec, classification, trustLevel);
            case HASHED -> hash(String.valueOf(real), spec, classification, trustLevel);
            case GENERALIZED -> generalize(real, spec, classification, trustLevel, generalizer);
            case TOKENIZED -> {
                if (tokens == null) {
                    throw new MissingImplementationException(classification, technique, trustLevel);
                }
                yield tokens.tokenize(String.valueOf(real), classification);
            }
        };
    }

    // --- Enmascarado ---

    /**
     * Deja a la vista {@code keep} caracteres de un lado y tapa el
     * resto. Si {@code keep} llega o pasa el largo del valor, TAPA
     * TODO: enmascarar dejando todo a la vista no es enmascarar, y un
     * valor corto no puede quedar en claro por un parámetro pensado
     * para uno largo.
     */
    private static String mask(String value, TechniqueSpec spec,
                               Classification classification, String trustLevel) {
        // NO DECLARAR `keep` ES UNA DECISION --tapar todo-- y declararlo
        // mal es un error de la tabla. Antes eran lo mismo: un
        // `keep: "cuatro"` se leia como cero y tapaba todo sin que nadie
        // se enterara de que la tabla decia otra cosa. Que la respuesta
        // haya sido la protectora no lo vuelve correcto: nadie iba a
        // arreglar esa fila nunca.
        if (spec.param(TechniqueSpec.KEEP).isPresent()
                && spec.intParam(TechniqueSpec.KEEP).isEmpty()) {
            throw new UnsupportedTechniqueSpecException(
                    "La tabla pide enmascarar dejando '" + spec.param(TechniqueSpec.KEEP).orElse("")
                            + "' caracteres a la vista, y eso tiene que ser un numero.",
                    classification, Technique.MASKED, trustLevel);
        }
        int keep = spec.intParam(TechniqueSpec.KEEP).orElse(0);
        if (keep < 0) {
            throw new UnsupportedTechniqueSpecException(
                    "La tabla pide enmascarar dejando " + keep + " caracteres a la vista.",
                    classification, Technique.MASKED, trustLevel);
        }
        String side = spec.param(TechniqueSpec.SIDE).orElse("right").toLowerCase(Locale.ROOT);
        if (!side.equals("right") && !side.equals("left")) {
            throw new UnsupportedTechniqueSpecException(
                    "La tabla pide enmascarar del lado '" + side + "', y los lados son 'left' y 'right'.",
                    classification, Technique.MASKED, trustLevel);
        }
        char maskChar = spec.param(MASK).filter(s -> !s.isEmpty()).orElse("*").charAt(0);

        int visible = Math.min(keep, value.length());
        if (visible >= value.length()) {
            visible = 0;
        }
        String hidden = String.valueOf(maskChar).repeat(value.length() - visible);
        return side.equals("right")
                ? hidden + value.substring(value.length() - visible)
                : value.substring(0, visible) + hidden;
    }

    // --- Hash ---

    private static String hash(String value, TechniqueSpec spec,
                               Classification classification, String trustLevel) {
        String algorithm = spec.param(TechniqueSpec.ALGORITHM).orElse("SHA-256");
        String scope = spec.param(TechniqueSpec.SALT_SCOPE).orElse(TechniqueSpec.SALT_SYSTEM);
        String salt;
        if (scope.equals(TechniqueSpec.SALT_VALUE)) {
            // Una sal por valor rompe la correlación, y también la
            // comparación: no se guarda ni se devuelve, porque el hash
            // no está para poder compararlo.
            byte[] fresh = new byte[16];
            SALT_SOURCE.nextBytes(fresh);
            salt = HexFormat.of().formatHex(fresh);
        } else if (scope.equals(TechniqueSpec.SALT_SYSTEM)) {
            // La sal de sistema es de la tabla, no de la librería:
            // inventar una por arranque daría un hash distinto en cada
            // despliegue y el dato dejaría de servir hasta para comparar.
            salt = spec.param(TechniqueSpec.SALT).orElse("");
        } else {
            throw new UnsupportedTechniqueSpecException(
                    "La tabla pide una sal de alcance '" + scope + "', y los alcances son '"
                            + TechniqueSpec.SALT_SYSTEM + "' y '" + TechniqueSpec.SALT_VALUE + "'.",
                    classification, Technique.HASHED, trustLevel);
        }
        String salted = salt + value;
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            return HexFormat.of().formatHex(digest.digest(salted.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedTechniqueSpecException(
                    "La tabla pide hashear con '" + algorithm + "', que esta JVM no tiene.",
                    classification, Technique.HASHED, trustLevel);
        }
    }

    // --- Generalización ---

    /**
     * Baja la precisión del dato. Las reglas que la librería resuelve
     * sola son cuatro, y son las que no necesitan saber qué significa
     * el dato: {@code year}, {@code month}, {@code range:N} y
     * {@code prefix:N}. Cualquier otra es conocimiento del negocio, y
     * va al {@link Generalizer} de la organización.
     *
     * <p>Las cuatro propias van PRIMERO: una tabla que escribe
     * {@code year} está pidiendo el año, y que eso cambie de
     * significado según qué implementó cada sistema haría que la misma
     * tabla protegiera distinto en dos lados.</p>
     */
    private static Object generalize(Object real, TechniqueSpec spec,
                                     Classification classification, String trustLevel,
                                     Generalizer generalizer) {
        String rule = spec.param(TechniqueSpec.RULE)
                .orElseThrow(() -> new UnsupportedTechniqueSpecException(
                        "La tabla pide generalizar pero no dice con qué regla (parámetro '"
                                + TechniqueSpec.RULE + "').",
                        classification, Technique.GENERALIZED, trustLevel));

        if (rule.equals("year")) {
            return String.valueOf(field(real, ChronoField.YEAR, rule, classification, trustLevel));
        }
        if (rule.equals("month")) {
            return "%04d-%02d".formatted(
                    field(real, ChronoField.YEAR, rule, classification, trustLevel),
                    field(real, ChronoField.MONTH_OF_YEAR, rule, classification, trustLevel));
        }
        if (rule.startsWith("range:")) {
            long size = number(rule.substring("range:".length()), rule, classification, trustLevel);
            if (size <= 0) {
                throw new UnsupportedTechniqueSpecException(
                        "La tabla pide agrupar de a " + size + ", y un rango tiene que ser positivo.",
                        classification, Technique.GENERALIZED, trustLevel);
            }
            long value = number(String.valueOf(real), rule, classification, trustLevel);
            long floor = Math.floorDiv(value, size) * size;
            return floor + "-" + (floor + size - 1);
        }
        if (rule.startsWith("prefix:")) {
            int n = (int) number(rule.substring("prefix:".length()), rule, classification, trustLevel);
            String value = String.valueOf(real);
            if (n <= 0 || n >= value.length()) {
                // Un prefijo del valor entero no generaliza nada: sería
                // devolverlo tal cual creyendo que se lo protegió.
                throw new UnsupportedTechniqueSpecException(
                        "La tabla pide generalizar a los primeros " + n + " caracteres de un valor de "
                                + value.length() + ": no reduce nada.",
                        classification, Technique.GENERALIZED, trustLevel);
            }
            return value.substring(0, n);
        }
        // No es un error de la tabla: una regla propia es lo esperable.
        // Lo que falta es que este sistema la implemente, y de eso se
        // entera acá —no devolviendo el dato sin generalizar—.
        if (generalizer == null) {
            throw new MissingImplementationException(
                    classification, Technique.GENERALIZED, trustLevel);
        }
        return generalizer.generalize(real, rule, classification);
    }

    private static int field(Object real, ChronoField wanted, String rule,
                             Classification classification, String trustLevel) {
        if (real instanceof TemporalAccessor temporal && temporal.isSupported(wanted)) {
            return temporal.get(wanted);
        }
        // Una fecha que viaja como texto ISO es lo más común de todo:
        // se la lee sin exigir que el campo esté tipado.
        String text = String.valueOf(real);
        if (wanted == ChronoField.YEAR && text.length() >= 4) {
            return (int) number(text.substring(0, 4), rule, classification, trustLevel);
        }
        if (wanted == ChronoField.MONTH_OF_YEAR && text.length() >= 7 && text.charAt(4) == '-') {
            return (int) number(text.substring(5, 7), rule, classification, trustLevel);
        }
        throw new UnsupportedTechniqueSpecException(
                "La tabla pide generalizar con '" + rule + "' un valor que no tiene una fecha adentro ("
                        + real.getClass().getSimpleName() + ").",
                classification, Technique.GENERALIZED, trustLevel);
    }

    private static long number(String text, String rule,
                               Classification classification, String trustLevel) {
        try {
            return Long.parseLong(text.trim());
        } catch (NumberFormatException e) {
            throw new UnsupportedTechniqueSpecException(
                    "La regla de generalización '" + rule + "' necesita un número y encontró '"
                            + text + "'.",
                    classification, Technique.GENERALIZED, trustLevel);
        }
    }
}
