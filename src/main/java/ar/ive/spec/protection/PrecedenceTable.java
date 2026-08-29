package ar.ive.spec.protection;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Una {@link DecisionTable} armada con reglas, que aplica la precedencia
 * del modelo de una sola vez y para todos.
 *
 * <p>POR QUE EXISTE: la precedencia —lo particular gana sobre lo
 * genérico— es una regla de seguridad, no una comodidad. Si cada
 * organización la implementa a mano en su propia tabla, cada una se
 * puede equivocar distinto, y equivocarse ahí significa exponer un dato
 * de más sin que nada avise. Acá está escrita una vez.</p>
 *
 * <p>NO LEE NINGUN ARCHIVO, y eso no cambia: la tabla es propia de cada
 * organización y puede vivir donde quiera. Esto es dónde ponerla, no de
 * dónde sacarla.</p>
 *
 * <h2>Los tres ejes, de más particular a más genérico</h2>
 * <ol>
 *   <li><b>Por clase</b> — {@code cardholderData} es restringido, pero
 *       qué se puede mostrar de una tarjeta lo dice PCI DSS y no se
 *       deduce de "restringido".</li>
 *   <li><b>Por cumplimiento</b> — "todo lo que caiga bajo
 *       {@code gdpr-art9} sale enmascarado", sin enumerar qué clases lo
 *       declaran hoy.</li>
 *   <li><b>Por sensibilidad</b> — la regla de fondo, la que hace que un
 *       dato nuevo esté protegido desde el día uno sin que nadie escriba
 *       una regla para él.</li>
 * </ol>
 *
 * <p>Dentro de un mismo eje, una regla para un nivel de confianza
 * puntual le gana a una que vale para todos. El eje de la clasificación
 * manda sobre el del nivel: una regla por clase para todos los niveles
 * le gana a una por sensibilidad para un nivel puntual, porque lo que el
 * modelo llama particular es la clase.</p>
 *
 * <h2>Cuando un dato tiene varias clases</h2>
 * <p>Una propiedad puede declarar más de una —{@code [personalIdentifier,
 * fiscalData]}— y las dos pueden tener regla. <b>GANA LA MAS
 * PROTECTORA</b>: no hay forma de que exponer de más sea la respuesta
 * correcta a una ambigüedad, y elegir por orden de declaración haría que
 * mover una línea en el catálogo cambiara lo que se ve.</p>
 */
public final class PrecedenceTable implements DecisionTable {

    /**
     * Una regla escrita para TODOS LOS NIVELES CONOCIDOS.
     *
     * <p><b>No incluye al invocador desconocido</b>, y esa distinción es
     * el modelo, no una sutileza: un Intent sin {@code trustLevel} "no
     * tiene ninguna protección por nivel de confianza aplicada, y no hay
     * ningún valor por defecto implícito". "Para todos mis niveles" es
     * una frase sobre los niveles que la organización declaró; quien
     * llama sin que se sepa quién es no es uno de ellos —es el que menos
     * se conoce— y darle lo que se les da a todos seria adivinar de
     * menos.</p>
     *
     * <p>Para escribir la regla del desconocido está
     * {@link #UNKNOWN_CALLER}. Si no hay ninguna, la tabla no contesta y
     * la librería se niega: es la misma regla de siempre, lo que falta
     * no es permiso.</p>
     */
    public static final String ANY_LEVEL = "ive:any-trust-level";

    /**
     * El nivel al que aplica una regla para cuando NO SE SABE QUIEN
     * INVOCA. Es {@code null} porque es lo que llega en ese caso.
     */
    public static final String UNKNOWN_CALLER = null;

    private enum Axis { CLASS, COMPLIANCE, SENSITIVITY }

    private record Rule(Axis axis, String key, String trustLevel, TechniqueSpec spec) {

        boolean matches(Classification classification, String level) {
            return Objects.equals(trustLevel, level) && appliesTo(classification);
        }

        boolean appliesTo(Classification classification) {
            return switch (axis) {
                case CLASS -> classification.has(key);
                case COMPLIANCE -> classification.under(key);
                case SENSITIVITY -> classification.sensitivity().name().equals(key);
            };
        }
    }

    private final List<Rule> rules;
    private final List<Rule> ceilings;
    private final Set<String> trustLevels;
    private final TechniqueSpec logging;

    private PrecedenceTable(Builder builder) {
        this.rules = List.copyOf(builder.rules);
        this.ceilings = List.copyOf(builder.ceilings);
        this.logging = builder.logging;

        // Los niveles salen de las reglas: que la lista quede completa no
        // puede depender de que alguien se acuerde de escribirla dos veces.
        Set<String> levels = new LinkedHashSet<>(builder.trustLevels);
        for (Rule rule : builder.rules) {
            // Ni el comodin ni el desconocido son niveles de confianza:
            // uno es una forma de escribir una regla y el otro es la
            // ausencia de un invocador identificado. Si entraran a esta
            // lista, la forma de guardado se decidiria contra ellos.
            if (rule.trustLevel() != null && !ANY_LEVEL.equals(rule.trustLevel())) {
                levels.add(rule.trustLevel());
            }
        }
        this.trustLevels = Set.copyOf(levels);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public TechniqueSpec techniqueFor(Classification classification, String trustLevel) {
        Objects.requireNonNull(classification, "classification");
        for (Axis axis : Axis.values()) {
            TechniqueSpec found = mostProtective(rules, axis, classification, trustLevel);
            if (found != null) {
                return found;
            }
        }
        // Ninguna regla: la tabla no contesta, y la librería se niega.
        // No inventar una respuesta acá es parte del contrato.
        return null;
    }

    @Override
    public Technique ceilingFor(Classification classification, String trustLevel) {
        Objects.requireNonNull(classification, "classification");
        for (Axis axis : Axis.values()) {
            TechniqueSpec found = mostProtective(ceilings, axis, classification, trustLevel);
            if (found != null) {
                return found.technique();
            }
        }
        return Technique.FULL;
    }

    @Override
    public Set<String> trustLevels() {
        return trustLevels;
    }

    @Override
    public TechniqueSpec forLogging(Classification classification) {
        return logging;
    }

    /**
     * La regla de este eje: primero las escritas para este nivel, y solo
     * si no hay ninguna, las que valen para todos. Entre varias, la que
     * revela menos.
     */
    private static TechniqueSpec mostProtective(List<Rule> from, Axis axis,
                                                Classification classification, String trustLevel) {
        TechniqueSpec best = pick(from, axis, classification, trustLevel);
        // El respaldo "para todos" vale para un nivel CONOCIDO que no
        // tiene regla propia. Para el desconocido no hay respaldo: o
        // alguien escribió su regla, o la tabla no contesta.
        if (best == null && trustLevel != null) {
            best = pick(from, axis, classification, ANY_LEVEL);
        }
        return best;
    }

    private static TechniqueSpec pick(List<Rule> from, Axis axis,
                                      Classification classification, String trustLevel) {
        TechniqueSpec best = null;
        for (Rule rule : from) {
            if (rule.axis() != axis || !rule.matches(classification, trustLevel)) {
                continue;
            }
            if (best == null || best.technique().revealsMoreThan(rule.spec().technique())) {
                best = rule.spec();
            }
        }
        return best;
    }

    /** Se escriben las reglas en cualquier orden: la precedencia no depende de él. */
    public static final class Builder {

        private final List<Rule> rules = new ArrayList<>();
        private final List<Rule> ceilings = new ArrayList<>();
        private final Set<String> trustLevels = new LinkedHashSet<>();
        private TechniqueSpec logging = TechniqueSpec.of(Technique.REDACTED);

        private Builder() {
        }

        public Builder forClass(String clazz, String trustLevel, TechniqueSpec spec) {
            return rule(Axis.CLASS, clazz, trustLevel, spec);
        }

        public Builder forCompliance(String norm, String trustLevel, TechniqueSpec spec) {
            return rule(Axis.COMPLIANCE, norm, trustLevel, spec);
        }

        public Builder forSensitivity(Sensitivity sensitivity, String trustLevel, TechniqueSpec spec) {
            return rule(Axis.SENSITIVITY, sensitivity.name(), trustLevel, spec);
        }

        public Builder ceilingForClass(String clazz, String trustLevel, Technique ceiling) {
            return ceiling(Axis.CLASS, clazz, trustLevel, ceiling);
        }

        public Builder ceilingForCompliance(String norm, String trustLevel, Technique ceiling) {
            return ceiling(Axis.COMPLIANCE, norm, trustLevel, ceiling);
        }

        public Builder ceilingForSensitivity(Sensitivity sensitivity, String trustLevel, Technique ceiling) {
            return ceiling(Axis.SENSITIVITY, sensitivity.name(), trustLevel, ceiling);
        }

        /**
         * Un nivel de confianza que existe aunque todavía no tenga
         * ninguna regla propia. Los que aparecen en una regla se agregan
         * solos.
         */
        public Builder trustLevel(String trustLevel) {
            trustLevels.add(Objects.requireNonNull(trustLevel, "trustLevel"));
            return this;
        }

        /** En qué forma puede aparecer un dato clasificado en un registro. */
        public Builder logging(TechniqueSpec spec) {
            this.logging = Objects.requireNonNull(spec, "spec");
            return this;
        }

        public PrecedenceTable build() {
            return new PrecedenceTable(this);
        }

        private Builder rule(Axis axis, String key, String trustLevel, TechniqueSpec spec) {
            rules.add(new Rule(axis, Objects.requireNonNull(key, "key"), trustLevel,
                    Objects.requireNonNull(spec, "spec")));
            return this;
        }

        private Builder ceiling(Axis axis, String key, String trustLevel, Technique ceiling) {
            ceilings.add(new Rule(axis, Objects.requireNonNull(key, "key"), trustLevel,
                    TechniqueSpec.of(Objects.requireNonNull(ceiling, "ceiling"))));
            return this;
        }
    }
}
