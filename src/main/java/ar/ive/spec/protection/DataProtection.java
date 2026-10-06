package ar.ive.spec.protection;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * La conversión: dado un valor, qué es ese dato y a dónde va, lo
 * devuelve en la forma que corresponde.
 *
 * <p>EL DESTINO NO ES UN PARÁMETRO QUE ALGUIEN PUEDA EQUIVOCAR: es cuál
 * de los métodos se llama, y cada uno lo llama un sitio distinto del
 * código generado.</p>
 *
 * <ul>
 *   <li>{@link #toStorage} y {@link #fromStorage} — los llama el
 *       conversor de persistencia ({@code AttributeConverter} en JPA),
 *       que es el único que ve el viaje del valor a la base y de vuelta.
 *       No hay nivel de confianza: no hay destinatario.</li>
 *   <li>{@link #toRecipient} — lo llama el servicio, antes de devolver.
 *       Ahí sí hay destinatario, y su nivel de confianza es lo que la
 *       tabla necesita para contestar.</li>
 * </ul>
 *
 * <p>EL CIFRADO EN REPOSO LO HACE ESTA CLASE, en {@link #toStorage}, y
 * no por eso es una de las siete técnicas: ninguna de las siete
 * describe lo que ve alguien de un valor cifrado, porque nadie lo ve
 * cifrado —se descifra al leer—. Es la otra mitad de la misma decisión:
 * cuando la forma de guardado es el valor real, guardarlo en claro es
 * la única alternativa, y no es una alternativa. Quien decide que este
 * sistema puede cifrar es quien le pasa un {@link KeyProvider}; desde
 * qué sensibilidad, {@code encryptAtRestFrom}.</p>
 *
 * <p>Tampoco recorre objetos ni lee catálogos: ve un valor por vez, con
 * su clasificación ya resuelta por el generador.</p>
 *
 * <p>Es inmutable y se puede compartir entre hilos.</p>
 */
public final class DataProtection {

    private final DecisionTable table;
    private final TokenService tokens;
    private final Generalizer generalizer;
    private final KeyProvider keys;
    private final Sensitivity encryptFrom;
    private final boolean sinCifradoEnReposo;

    /**
     * WHICH CLASSES OF DATA THIS SYSTEM USES, and why -- by class name,
     * the reason as the value. The generator brings it from the
     * specification ({@code usedInLogic} on a View property); the library
     * cannot know it, because the logic lives in hand-written code.
     *
     * <p>Empty means nothing was declared, which is the ordinary case:
     * most classified data is only ever shown.</p>
     */
    private final Map<String, String> usedInLogic;

    /**
     * LOS NIVELES DE CONFIANZA DECLARADOS, por nombre.
     *
     * <p>Sale del catálogo de la organización y de lo que el proyecto dice
     * que usa; el generador lo baja acá. <b>Vacío quiere decir "nadie
     * declaró nada", y entonces esto se comporta exactamente como antes de
     * que existiera</b>: ni se rechaza un nivel desconocido ni se consulta
     * la matriz por omisión. Un sistema que no declara nada no cambia.</p>
     */
    private final Map<String, TrustLevel> trustLevels;

    /**
     * LO QUE CORRESPONDE CUANDO LA TABLA NO ESCRIBIÓ NADA PARA ESE PAR.
     * Se consulta ÚLTIMA, debajo de todo lo escrito, y sólo si hay niveles
     * declarados — sin cantidades no hay con qué entrar a la matriz.
     */
    private final Baseline baseline;
    private final InputBaseline inputBaseline;

    /**
     * La forma de guardado no cambia entre llamadas —sale de la tabla y
     * de la lista de niveles, no del valor— y se resuelve una vez por
     * clasificación: si no, cada valor de cada fila recorrería todos
     * los niveles de confianza otra vez.
     */
    private final Map<Classification, TechniqueSpec> storageForms = new ConcurrentHashMap<>();

    private DataProtection(Builder builder) {
        this.table = Objects.requireNonNull(builder.table, "table");
        this.tokens = builder.tokens;
        this.generalizer = builder.generalizer;
        this.keys = builder.keys;
        this.encryptFrom = builder.encryptFrom;
        this.sinCifradoEnReposo = builder.sinCifradoEnReposo;
        this.usedInLogic = Map.copyOf(builder.usedInLogic);
        this.trustLevels = Map.copyOf(builder.trustLevels);
        this.baseline = builder.baseline;
        this.inputBaseline = builder.inputBaseline;
    }

    public static Builder with(DecisionTable table) {
        return new Builder(table);
    }

    /**
     * Lo que la organización pone, y todo es opcional a propósito: un
     * sistema cuya tabla no pide tokens no tiene por qué implementar
     * la tokenización. Si la tabla lo pide y no está, la llamada se
     * niega con {@link MissingImplementationException} —eso es un
     * problema de quien opera el sistema, tiene que verse cuando pasa,
     * y no puede impedir que la librería se construya—.
     */
    public static final class Builder {

        private final DecisionTable table;
        private TokenService tokens;
        private Generalizer generalizer;
        private KeyProvider keys;
        private Sensitivity encryptFrom = Sensitivity.CONFIDENTIAL;
        private boolean encryptFromDeclarado;
        private boolean sinCifradoEnReposo;
        private Map<String, String> usedInLogic = Map.of();
        private Map<String, TrustLevel> trustLevels = Map.of();
        private Baseline baseline = Baseline.CONSERVATIVE;
        private InputBaseline inputBaseline = InputBaseline.CONSERVATIVE;

        private Builder(DecisionTable table) {
            this.table = table;
        }

        public Builder tokens(TokenService tokens) {
            this.tokens = tokens;
            return this;
        }

        public Builder generalizer(Generalizer generalizer) {
            this.generalizer = generalizer;
            return this;
        }

        /** El gestor de claves con el que este sistema cifra en reposo. */
        public Builder keys(KeyProvider keys) {
            this.keys = keys;
            return this;
        }

        /**
         * ESTE SISTEMA NO CIFRA EN REPOSO, Y ES UNA DECISION TOMADA.
         *
         * <p>Puede estar bien —cifrado de disco, de tablespace, una base
         * que ya cifra— pero <b>hay que decirlo</b>. Antes alcanzaba con
         * no pasar el gestor de claves, y eso era lo peor de los dos
         * mundos: la ausencia de una implementación decidía por su
         * cuenta que un dato confidencial se guardara en claro, en
         * silencio, que es exactamente lo que esta librería no hace con
         * ninguna otra implementación ausente.</p>
         *
         * <p>Sin esto y sin gestor de claves, guardar un dato que llega
         * al piso de sensibilidad se niega con
         * {@link MissingImplementationException}, igual que tokenizar
         * sin servicio de tokenización.</p>
         */
        public Builder withoutEncryptionAtRest() {
            this.sinCifradoEnReposo = true;
            return this;
        }

        /**
         * Desde qué sensibilidad se cifra en reposo. Por defecto,
         * {@code CONFIDENTIAL}: cifrar lo público no protege nada y
         * rompe las consultas por ese campo.
         */
        public Builder encryptAtRestFrom(Sensitivity floor) {
            this.encryptFrom = Objects.requireNonNull(floor, "floor");
            this.encryptFromDeclarado = true;
            return this;
        }

        /**
         * THE CLASSES OF DATA THIS SYSTEM USES, not only shows, with the
         * reason for each one. The generator brings it from the
         * specification; nobody is expected to write it by hand.
         *
         * <p>What it changes is the STORAGE FORM, and only that: a class
         * declared here is never stored in a form with no way back, because
         * from a hash or a mask the value cannot be operated on -- only
         * displayed. <b>It changes nothing about who sees what.</b></p>
         *
         * <p>The reason is carried so the startup report can say it. A line
         * stating that a value is kept whole is worth little without the
         * sentence explaining why.</p>
         */
        public Builder usedInLogic(Map<String, String> reasonByClass) {
            this.usedInLogic = reasonByClass == null ? Map.of() : Map.copyOf(reasonByClass);
            return this;
        }

        /**
         * LOS NIVELES DE CONFIANZA QUE ESTE SISTEMA CONOCE, con su
         * clearance cuando lo tienen.
         *
         * <p>Declararlos cambia DOS cosas, y las dos para el mismo lado:
         * un nivel que no esté acá se NIEGA en vez de caer en la regla de
         * "para todos" —ver {@link UnknownTrustLevelException}— y los
         * pares que la tabla no escribió pasan a resolverse con la matriz
         * por omisión en vez de negarse.</p>
         *
         * <p><b>Sin declarar nada, nada de eso pasa</b> y la librería se
         * comporta como siempre: exige que la tabla conteste todo.</p>
         */
        public Builder trustLevels(Collection<TrustLevel> levels) {
            Map<String, TrustLevel> porNombre = new LinkedHashMap<>();
            if (levels != null) {
                for (TrustLevel nivel : levels) {
                    TrustLevel previo = porNombre.put(nivel.name(), nivel);
                    // DOS FUENTES QUE LE PONEN CANTIDAD DISTINTA AL MISMO
                    // NOMBRE no están afinando nada: están en desacuerdo
                    // sobre cuánto se confía en alguien, y eso resuelto a
                    // escondidas es como un agujero se vuelve permanente.
                    if (previo != null && !Objects.equals(previo.clearance(), nivel.clearance())) {
                        throw new IllegalStateException(
                                "El nivel de confianza \"" + nivel.name() + "\" se declaró dos veces con"
                                        + " clearance distinto (" + previo.clearance() + " y "
                                        + nivel.clearance() + "). No es un refinamiento: son dos"
                                        + " afirmaciones opuestas sobre cuánto se le confía.");
                    }
                }
            }
            this.trustLevels = porNombre;
            return this;
        }

        /**
         * LA MATRIZ POR OMISIÓN DE ESTE SISTEMA, en vez de la de la
         * librería. Es un piso, no un veredicto: se puede reemplazar
         * entera, y {@link Baseline#NONE} la apaga —ahí la tabla vuelve a
         * tener que contestar todo—.
         */
        public Builder baseline(Baseline baseline) {
            this.baseline = baseline == null ? Baseline.NONE : baseline;
            return this;
        }

        /**
         * THE DEFAULT FOR WHAT COMES IN, instead of the library's. Replaced
         * whole; {@link InputBaseline#NONE} turns it off, and then only what
         * the table accepts is taken.
         */
        public Builder inputBaseline(InputBaseline inputBaseline) {
            this.inputBaseline = inputBaseline == null ? InputBaseline.NONE : inputBaseline;
            return this;
        }

        public DataProtection build() {
            if (encryptFromDeclarado && keys == null) {
                // Decir desde dónde se cifra y no decir con qué es una
                // contradicción, y la que falla callada sería la peor:
                // no se cifraría nada.
                throw new IllegalStateException(
                        "Se declaró desde qué sensibilidad cifrar en reposo (" + encryptFrom
                                + ") pero no se pasó ningún " + KeyProvider.class.getSimpleName() + ".");
            }
            if (sinCifradoEnReposo && keys != null) {
                throw new IllegalStateException(
                        "Se declaró que este sistema no cifra en reposo y a la vez se pasó un "
                                + KeyProvider.class.getSimpleName() + ": son dos decisiones opuestas.");
            }
            return new DataProtection(this);
        }
    }

    // ------------------------------------------------------------------
    // LO QUE ESTE EVALUADOR TIENE, para quien lo verifica
    //
    // De paquete y no publico: lo unico que necesita mirar adentro es
    // `TableVerification`, que vive aca al lado. Abrirlo del todo dejaria
    // que cualquiera pregunte por la tabla y decida por su cuenta, que es
    // exactamente lo que esta clase existe para centralizar.
    // ------------------------------------------------------------------

    DecisionTable table() {
        return table;
    }

    TokenService tokens() {
        return tokens;
    }

    Generalizer generalizer() {
        return generalizer;
    }

    KeyProvider keys() {
        return keys;
    }

    Sensitivity encryptFrom() {
        return encryptFrom;
    }

    boolean withoutEncryptionAtRest() {
        return sinCifradoEnReposo;
    }

    /**
     * QUÉ CLASES DE DATO USA ESTE SISTEMA, y por qué.
     *
     * <p>PÚBLICO, a diferencia de los accesores de arriba, y por un motivo:
     * hay cadenas que NO arman este objeto —lo reciben ya armado— y lo único
     * que les queda es COMPROBAR que lo declarado llegó. Sin poder
     * preguntarlo, una declaración que no se pasó no se nota, y ése es
     * exactamente el error que esto existe para sacar.</p>
     */
    public Map<String, String> usedInLogic() {
        return usedInLogic;
    }

    /**
     * Why this system needs the real value of this data, or {@code null}
     * when nothing was declared for any of its classes.
     */
    String reasonForUse(Classification classification) {
        for (String clazz : classification.classes()) {
            String reason = usedInLogic.get(clazz);
            if (reason != null) {
                return reason;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // La forma de guardado
    // ------------------------------------------------------------------

    /**
     * En qué forma hay que guardar este dato.
     *
     * <p>LA REGLA: la forma de guardado tiene que poder llegar a la
     * salida MÁS EXIGENTE de todas las que usan el dato. Guardar el
     * valor real no cierra ninguna puerta; guardar un hash las cierra
     * casi todas.</p>
     *
     * <p>De ahí salen los tres casos:</p>
     * <ol>
     *   <li>Si todos los niveles reciben EXACTAMENTE LA MISMA forma
     *       —la misma técnica con los mismos parámetros—, se guarda esa:
     *       es la más cerrada que sigue sirviendo a todos. Es el caso de
     *       la contraseña, que nadie ve nunca y se guarda hasheada.</li>
     *   <li>Si las formas difieren, hay que guardar el valor real: es lo
     *       único desde donde se puede producir cualquiera de ellas.</li>
     *   <li>Redactado y omitido no miran el dato, así que no cuentan
     *       para decidir: un nivel que no ve nada no obliga a guardar
     *       nada en particular.</li>
     * </ol>
     *
     * <p>Un token cuenta como forma cerrada válida aunque tenga vuelta:
     * si todos reciben el mismo token, guardar el token alcanza, y el
     * valor real se recupera destokenizando cuando haga falta.</p>
     *
     * <p>Y HAY UN CASO ANTES QUE LOS TRES, que no sale de las salidas
     * porque no puede: un dato que este sistema USA y no le muestra a
     * nadie en claro no tiene destinatario, así que ningún nivel lo pide
     * y ninguna salida lo cuenta. Lo declara la especificación
     * ({@code usedInLogic}), y lo que exige es que la forma de guardado
     * TENGA VUELTA — de un hash o de un enmascarado el valor no se puede
     * operar, sólo mostrar. Si la forma que sale de las salidas ya es
     * reversible ({@link Technique#FULL} o {@link Technique#TOKENIZED}),
     * SE RESPETA: la elección de la tabla no se pisa por gusto.</p>
     */
    public TechniqueSpec storageFormFor(Classification classification) {
        Objects.requireNonNull(classification, "classification");
        return storageForms.computeIfAbsent(classification, this::resolveStorageForm);
    }

    private TechniqueSpec resolveStorageForm(Classification classification) {
        Set<TechniqueSpec> forms = new LinkedHashSet<>();
        for (String trustLevel : trustLevels()) {
            TechniqueSpec spec = required(classification, trustLevel);
            Technique technique = spec.technique();
            if (technique == Technique.REDACTED || technique == Technique.OMITTED) {
                continue;
            }
            forms.add(spec);
        }
        // Sin niveles declarados, o con ninguna salida que mire el dato,
        // se guarda el valor real: es lo único que no cierra puertas que
        // todavía no se sabe si alguien va a necesitar.
        TechniqueSpec form = forms.size() == 1
                ? forms.iterator().next()
                : TechniqueSpec.of(Technique.FULL);

        // ESTE SISTEMA LO USA: la forma tiene que tener vuelta. Una que ya
        // la tiene se respeta —un token guardado se destokeniza y el valor
        // real vuelve— y sólo una sin vuelta se cambia por el valor real.
        if (!form.technique().isReversible() && reasonForUse(classification) != null) {
            return TechniqueSpec.of(Technique.FULL);
        }
        return form;
    }

    private Set<String> trustLevels() {
        Set<String> levels = table.trustLevels();
        if (levels == null) {
            // UN CONJUNTO VACIO ES UNA RESPUESTA —"no expongo mi lista"—
            // y esta documentada. UN NULO NO ES NINGUNA: es la tabla sin
            // contestar, y leerlo como vacio decidiria la forma de
            // guardado a partir de una respuesta que nadie dio.
            throw new IllegalStateException(
                    table.getClass().getName() + ".trustLevels() devolvió null."
                            + " Para no exponer la lista, devolvé un conjunto vacío: eso es una"
                            + " decisión, y un null no lo es.");
        }
        return levels;
    }

    /**
     * En qué forma está el valor cuando ya está en memoria, del otro
     * lado del conversor de persistencia. Es la forma de guardado si no
     * tiene vuelta, y el valor real si la tiene —porque en ese caso el
     * conversor ya la deshizo al leer—.
     */
    private TechniqueSpec formInMemory(Classification classification) {
        TechniqueSpec stored = storageFormFor(classification);
        return stored.technique().isReversible() ? TechniqueSpec.of(Technique.FULL) : stored;
    }

    // ------------------------------------------------------------------
    // Hacia el almacenamiento y de vuelta — lo llama el conversor
    // ------------------------------------------------------------------

    /**
     * Bajada: del valor real a lo que va a la columna.
     *
     * <p>Son dos cosas, y en este orden: la TÉCNICA de almacenamiento
     * —que puede no ser ninguna, si lo que hay que guardar es el valor
     * real— y después el CIFRADO EN REPOSO, si este sistema cifra y el
     * dato llega al piso de sensibilidad.</p>
     *
     * <p><b>EL TIPO DE LA COLUMNA NO PUEDE DEPENDER DE UNA DECISION DE
     * RUNTIME, y por eso lo elige quien llama y no esta librería.</b>
     * Si dependiera, una base habría que re-migrarla porque alguien
     * agregó un gestor de claves, y dos despliegues de la misma
     * especificación tendrían esquemas distintos. Quien llama —el
     * conversor de persistencia— no sabe si se va a cifrar, y no tiene
     * por qué saberlo: pide el tipo que tiene la columna y esta
     * librería se arregla.</p>
     *
     * <p>Con {@code String.class}, un valor cifrado vuelve en Base64.
     * Con {@code byte[].class}, en crudo, para quien quiera una columna
     * binaria a propósito. {@link #fromStorage} acepta las dos.</p>
     */
    public Object toStorage(Object value, Class<?> to, Classification classification) {
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(to, "to");
        TechniqueSpec form = storageFormFor(classification);
        Object stored = Techniques.apply(form, value, classification, null, tokens, generalizer);
        if (encryptsAtRest(form, classification)) {
            if (stored == null) {
                return null;
            }
            byte[] cifrado = keys.encrypt(
                    String.valueOf(stored).getBytes(StandardCharsets.UTF_8), classification);
            return asColumn(cifrado, to, classification);
        }
        return coerce(stored, to, form.technique(), classification, null);
    }

    /**
     * Lo cifrado, en el tipo que tiene la columna. Son los dos únicos
     * que puede haber: bytes, o texto —y ahí Base64, que es lo que se
     * usa siempre para meter un cifrado en una columna de texto—.
     */
    private Object asColumn(byte[] cifrado, Class<?> to, Classification classification) {
        if (to == byte[].class) {
            return cifrado;
        }
        if (to == String.class) {
            return Base64.getEncoder().encodeToString(cifrado);
        }
        throw new UnsupportedTechniqueSpecException(
                "Este dato se guarda cifrado, y una columna que lo aguante es byte[] o String"
                        + " (en Base64), no " + to.getSimpleName() + ".",
                classification, Technique.FULL, null);
    }

    /**
     * Subida: de la forma guardada al valor real.
     *
     * <p>Cuando la forma de guardado NO TIENE VUELTA, devuelve lo que
     * hay —el hash es el dato, no una versión estropeada de otro—. Que
     * eso alcance o no para lo que cada quien tiene que recibir lo
     * decide {@link #toRecipient}, que es el que sabe hacia dónde va.</p>
     */
    public Object fromStorage(Object stored, Class<?> to, Classification classification) {
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(to, "to");
        TechniqueSpec form = storageFormFor(classification);
        if (encryptsAtRest(form, classification)) {
            if (stored == null) {
                return null;
            }
            byte[] cifrado = fromColumn(stored, classification);
            return coerce(new String(keys.decrypt(cifrado, classification), StandardCharsets.UTF_8),
                    to, form.technique(), classification, null);
        }
        Object real = undo(stored, form, classification, null);
        // Sin vuelta, lo guardado ES el dato: no hay nada que deshacer
        // y tampoco nada de qué quejarse todavía. La negativa aparece
        // recién si alguien pide más de lo que esa forma puede dar, y
        // eso lo sabe `toRecipient`.
        return coerce(real == UNREACHABLE ? stored : real,
                to, form.technique(), classification, null);
    }

    /**
     * Se cifra en reposo cuando hay con qué, cuando el dato llega al
     * piso de sensibilidad, y SOLO cuando lo que se guarda es el valor
     * real: un hash no se cifra —dejaría de servir para comparar y no
     * hay nada que recuperar— y un token tampoco —afuera del servicio
     * de tokenización no dice nada—.
     */
    private boolean encryptsAtRest(TechniqueSpec form, Classification classification) {
        if (form.technique() != Technique.FULL
                || !classification.sensitivity().atLeast(encryptFrom)) {
            return false;
        }
        if (keys == null) {
            // LA AUSENCIA NO ES UNA DECISION. Que no haya gestor de
            // claves no puede querer decir "entonces guardalo en claro":
            // es lo mismo que tokenizar sin servicio de tokenización, y
            // se niega igual. Para no cifrar hay una forma de decirlo.
            if (sinCifradoEnReposo) {
                return false;
            }
            throw new MissingImplementationException(
                    classification, Technique.FULL, null, Technique.Requirement.KEYS);
        }
        return true;
    }

    /** Lo que la columna tenga, de vuelta a los bytes que se cifraron. */
    private byte[] fromColumn(Object stored, Classification classification) {
        if (stored instanceof byte[] bytes) {
            return bytes;
        }
        if (stored instanceof CharSequence texto) {
            try {
                return Base64.getDecoder().decode(texto.toString());
            } catch (IllegalArgumentException e) {
                // No es "entonces devolvelo tal cual": si este dato se
                // guarda cifrado, lo que hay en esa columna tiene que
                // ser un cifrado. Devolverlo como si fuera el valor
                // sería devolver basura y llamarla dato.
                throw new UnsupportedTechniqueSpecException(
                        "Este dato se guarda cifrado y lo que hay en la columna no es Base64.",
                        classification, Technique.FULL, null);
            }
        }
        throw new UnsupportedTechniqueSpecException(
                "Este dato se guarda cifrado, así que en la columna tiene que haber byte[] o texto"
                        + " en Base64, y llegó " + stored.getClass().getSimpleName() + ".",
                classification, Technique.FULL, null);
    }

    // ------------------------------------------------------------------
    // Hacia un destinatario — lo llama el servicio, antes del return
    // ------------------------------------------------------------------

    /**
     * Devuelve el valor en la forma que le corresponde a un
     * destinatario de este nivel de confianza.
     *
     * <p>NO HACE FALTA DECIRLE EN QUÉ FORMA ESTÁ EL VALOR: si viene de
     * la base, la forma sale de la misma regla que decidió cómo
     * guardarlo, y así no hay dos fuentes que puedan desincronizarse.
     * Para un valor que llega ya protegido desde otro sistema está la
     * sobrecarga que lo recibe explícito.</p>
     *
     * <p>Con la técnica {@code OMITTED} devuelve {@code null}: que el
     * campo no aparezca no es un valor que se pueda devolver, y lo
     * resuelve el serializador de cada framework.</p>
     */
    public Object toRecipient(Object value, Class<?> to,
                              Classification classification, String trustLevel) {
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(to, "to");
        return toRecipient(value, to, classification, trustLevel, formInMemory(classification));
    }

    /** La misma conversión, para un valor que ya viene en una forma conocida. */
    public Object toRecipient(Object value, Class<?> to,
                              Classification classification, String trustLevel,
                              Technique currentForm) {
        return toRecipient(value, to, classification, trustLevel,
                TechniqueSpec.of(Objects.requireNonNull(currentForm, "currentForm")));
    }

    private Object toRecipient(Object value, Class<?> to,
                               Classification classification, String trustLevel,
                               TechniqueSpec currentForm) {
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(to, "to");
        TechniqueSpec target = required(classification, trustLevel);

        // Lo que ya está en la forma pedida no se toca: deshacer para
        // volver a hacer lo mismo pediría una vuelta que puede no haber.
        if (currentForm.equals(target)) {
            return coerce(value, to, target.technique(), classification, trustLevel);
        }
        // Redactado y omitido no miran el dato: se pueden dar sobre
        // cualquier forma, incluso sobre una que no tiene vuelta.
        if (!target.technique().producesValue()) {
            return null;
        }
        if (target.technique() == Technique.REDACTED) {
            return coerce(Techniques.apply(target, value, classification, trustLevel, tokens, generalizer),
                    to, target.technique(), classification, trustLevel);
        }
        Object real = undo(value, currentForm, classification, trustLevel);
        if (real == UNREACHABLE) {
            throw new IrreversibleTechniqueException(
                    classification, currentForm.technique(), target.technique(), trustLevel);
        }
        return coerce(Techniques.apply(target, real, classification, trustLevel, tokens, generalizer),
                to, target.technique(), classification, trustLevel);
    }

    /**
     * Lo mismo, para un valor que llegó de una fuente que NO DECLARA en
     * qué forma lo manda —un sistema que no usa IVE: no hay tabla
     * compartida, y un token que conserva el formato del original es
     * indistinguible del valor real por inspección—.
     *
     * <p>No se supone nada. Lo que no mira el dato —redactado, omitido—
     * se da igual; cualquier cosa que necesite el valor real se niega
     * con {@link UnknownFormException}. Es la regla del modelo: adivinar
     * de más es aceptable, adivinar de menos no.</p>
     */
    public Object toRecipientOfUnknownForm(Object value, Class<?> to,
                                           Classification classification, String trustLevel) {
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(to, "to");
        if (value == null) {
            return null;
        }
        TechniqueSpec target = required(classification, trustLevel);
        if (!target.technique().producesValue()) {
            return null;
        }
        if (target.technique() == Technique.REDACTED) {
            return coerce(Techniques.apply(target, value, classification, trustLevel, tokens, generalizer),
                    to, target.technique(), classification, trustLevel);
        }
        throw new UnknownFormException(classification, target.technique(), trustLevel);
    }

    // ------------------------------------------------------------------
    // Hacia un registro — no hay destinatario, y por eso no hay nivel
    // ------------------------------------------------------------------

    /**
     * En qué forma este dato puede aparecer en un registro, una traza o
     * un mensaje de error.
     *
     * <p>Es la primera de las dos cosas que el modelo pide con un dato
     * clasificado que entra: <b>tratarlo como sensible desde que
     * llega</b>. No depende de la forma en que vino ni de a dónde va
     * —vale mientras el dato exista en el proceso— y por eso no lleva
     * nivel de confianza: un registro no tiene destinatario.</p>
     *
     * <p>De omisión no aparece. Que exista este método y no una constante
     * suelta es lo que permite que una organización decida otra cosa
     * —un hash con sal de sistema, para poder seguir un mismo dato entre
     * dos líneas— en un solo lugar, y no en cada punto donde se escribe
     * una línea de registro.</p>
     *
     * <p>LA OTRA MITAD NO ES DE ACA: que el {@code toString} de un objeto
     * generado, los mensajes de error y las trazas llamen a esto en vez
     * de imprimir el campo es cosa de las plantillas.</p>
     */
    public String forLogging(Object value, Classification classification) {
        Objects.requireNonNull(classification, "classification");
        if (value == null) {
            return null;
        }
        TechniqueSpec spec = table.forLogging(classification);
        if (spec == null) {
            // No es "entonces no muestres nada": es la tabla sin
            // contestar. Se trata igual que en cualquier otra consulta.
            throw new UnsupportedTechniqueSpecException(
                    "La tabla no dice en qué forma este dato puede aparecer en un registro.",
                    classification, null, null);
        }
        if (!spec.technique().producesValue()) {
            return null;
        }
        Object shown = Techniques.apply(spec, value, classification, null, tokens, generalizer);
        return shown == null ? null : String.valueOf(shown);
    }

    // ------------------------------------------------------------------
    // Deshacer
    // ------------------------------------------------------------------

    /** Marca "de acá no se vuelve", para no confundirlo con un valor nulo. */
    private static final Object UNREACHABLE = new Object();

    private Object undo(Object value, TechniqueSpec currentForm,
                        Classification classification, String trustLevel) {
        if (value == null) {
            return null;
        }
        return switch (currentForm.technique()) {
            case FULL -> value;
            case TOKENIZED -> {
                if (tokens == null) {
                    throw new MissingImplementationException(
                            classification, Technique.TOKENIZED, trustLevel);
                }
                yield tokens.detokenize(String.valueOf(value), classification);
            }
            // De un hash, de un enmascarado y de una generalización no
            // se vuelve; de un redactado y de un omitido, menos.
            default -> UNREACHABLE;
        };
    }

    // ------------------------------------------------------------------
    // La tabla y los tipos
    // ------------------------------------------------------------------

    /**
     * La técnica que la tabla resolvió, comprobada contra el techo que
     * la misma tabla declara. Todo lo que consulta la tabla pasa por
     * acá: si el techo se comprobara solo en la salida, una forma de
     * guardado podría quedar fijada por una regla que el techo no
     * admite, y eso se descubriría cuando ya está el dato escrito.
     */
    private TechniqueSpec required(Classification classification, String trustLevel) {
        TechniqueSpec spec = resolved(classification, trustLevel);
        Technique ceiling = table.ceilingFor(classification, trustLevel);
        if (spec.technique().revealsMoreThan(ceiling)) {
            throw new AboveCeilingException(
                    classification, spec.technique(), ceiling, trustLevel);
        }
        return spec;
    }

    private TechniqueSpec resolved(Classification classification, String trustLevel) {
        // UN NIVEL QUE NADIE DECLARÓ SE NIEGA, ANTES DE PREGUNTARLE A LA
        // TABLA. No es "no sé" --eso es `null`, y tiene su propia fila--:
        // es un nombre que alguien creyó que existía. Antes caía en la
        // regla de "para todos mis niveles", y quien llega con un nombre
        // inexistente no es uno de ellos: no fallaba, contestaba distinto
        // y en silencio.
        //
        // SÓLO SI HAY NIVELES DECLARADOS. Sin declaración no hay contra
        // qué comparar, y un sistema que no declara nada se comporta como
        // siempre.
        if (trustLevel != null && !trustLevels.isEmpty() && !trustLevels.containsKey(trustLevel)) {
            throw new UnknownTrustLevelException(classification, trustLevel, trustLevels.keySet());
        }

        TechniqueSpec spec = table.techniqueFor(classification, trustLevel);
        if (spec == null) {
            // LA MATRIZ POR OMISIÓN, que es lo último y lo más genérico:
            // debajo de la fila de ese nivel, de la banda y del comodín.
            // Existe para que un despliegue no tenga que escribir la tabla
            // ENTERA antes de arrancar -- arranca protegiendo y escribe
            // sólo las excepciones.
            spec = porOmision(classification, trustLevel);
        }
        if (spec == null) {
            // Una tabla que no contesta no autoriza nada: la falta de
            // respuesta no puede leerse como "mostralo entero".
            throw new UnsupportedTechniqueSpecException(
                    "La tabla no dice qué forma le corresponde a este dato.",
                    classification, null, trustLevel);
        }
        return spec;
    }

    /**
     * La matriz, entrada con la sensibilidad del dato y el clearance de
     * quien pide.
     *
     * <p>SIN NIVELES DECLARADOS NO SE CONSULTA: la matriz necesita una
     * cantidad para ubicar a quien llama, y sin declaración no hay
     * ninguna. Ahí todo sigue dependiendo de que la tabla conteste.</p>
     *
     * <p>Un nivel declarado SIN clearance entra como el desconocido —lo
     * más protector—: no hay cantidad con la cual ubicarlo, y suponerle
     * una sería inventarla.</p>
     */
    /**
     * WHETHER A DATUM THAT COMES IN IS TAKEN from whoever sends it. The
     * other direction of {@code toRecipient}: there the question is what
     * the caller may SEE, here what the caller may SET.
     *
     * <p>The table answers first; where it wrote nothing, the input
     * matrix, with the integrity of the datum and the clearance of the
     * level. A missing answer never authorizes: null from both is false.</p>
     *
     * <p>A CLASSIFICATION WITHOUT INTEGRITY WAS NOT EVALUATED, and what
     * comes in is taken, as it always was. A level nobody declared is
     * refused, as on the way out.</p>
     */
    public boolean acceptsFrom(Classification classification, String trustLevel) {
        Objects.requireNonNull(classification, "classification");
        if (classification.integrity() == null) {
            return true;
        }
        if (trustLevel != null && !trustLevels.isEmpty() && !trustLevels.containsKey(trustLevel)) {
            throw new UnknownTrustLevelException(classification, trustLevel, trustLevels.keySet());
        }
        Boolean written = table.acceptsFrom(classification, trustLevel);
        if (written != null) {
            return written;
        }
        TrustLevel nivel = trustLevel == null ? null : trustLevels.get(trustLevel);
        return Boolean.TRUE.equals(inputBaseline.forPair(classification.integrity(), nivel == null ? null : nivel.clearance()));
    }

    private TechniqueSpec porOmision(Classification classification, String trustLevel) {
        if (trustLevels.isEmpty()) {
            return null;
        }
        TrustLevel nivel = trustLevel == null ? null : trustLevels.get(trustLevel);
        return baseline.forPair(classification.sensitivity(), nivel == null ? null : nivel.clearance());
    }

    /**
     * LA FORMA CAMBIA EL TIPO, y por eso el tipo de destino no es
     * decorativo: un número de tarjeta enmascarado ya no es un número,
     * y una fecha generalizada a un año ya no es una fecha. Cuando lo
     * que la técnica produce no entra donde tiene que ir, se niega
     * —devolverlo igual sería un {@code ClassCastException} más lejos,
     * o peor, un valor sin proteger porque alguien tipó el campo de
     * otra manera—.
     */
    private Object coerce(Object produced, Class<?> to, Technique technique,
                          Classification classification, String trustLevel) {
        if (produced == null) {
            return produced;
        }
        Class<?> target = to.isPrimitive() ? boxed(to) : to;
        if (target.isInstance(produced)) {
            return produced;
        }
        if (target == String.class) {
            return String.valueOf(produced);
        }
        // De vuelta del almacenamiento el valor viaja como texto —lo
        // que se descifra son bytes— y el campo puede ser un número.
        if (produced instanceof String text) {
            Object parsed = parse(text, target);
            if (parsed != null) {
                return parsed;
            }
        }
        throw new UnsupportedTechniqueSpecException(
                "La técnica " + technique + " produce " + produced.getClass().getSimpleName()
                        + " y el destino es " + to.getSimpleName() + ".",
                classification, technique, trustLevel);
    }

    /** {@code null} si no es un tipo al que se pueda volver desde texto, o si el texto no es ese valor. */
    private static Object parse(String text, Class<?> target) {
        try {
            if (target == Long.class) return Long.valueOf(text);
            if (target == Integer.class) return Integer.valueOf(text);
            if (target == Short.class) return Short.valueOf(text);
            if (target == Byte.class) return Byte.valueOf(text);
            if (target == Double.class) return Double.valueOf(text);
            if (target == Float.class) return Float.valueOf(text);
            if (target == java.math.BigDecimal.class) return new java.math.BigDecimal(text);
            if (target == java.math.BigInteger.class) return new java.math.BigInteger(text);
        } catch (NumberFormatException e) {
            // No es que el tipo no sirva: es que ESTE valor no entra.
            // Un enmascarado nunca va a ser un número, y eso lo tiene
            // que decir el mensaje de arriba, no un NumberFormatException.
            return null;
        }
        if (target == Boolean.class) {
            if (text.equalsIgnoreCase("true")) return Boolean.TRUE;
            if (text.equalsIgnoreCase("false")) return Boolean.FALSE;
        }
        if (target == Character.class && text.length() == 1) {
            return text.charAt(0);
        }
        return null;
    }

    private static Class<?> boxed(Class<?> primitive) {
        if (primitive == int.class) return Integer.class;
        if (primitive == long.class) return Long.class;
        if (primitive == double.class) return Double.class;
        if (primitive == float.class) return Float.class;
        if (primitive == boolean.class) return Boolean.class;
        if (primitive == short.class) return Short.class;
        if (primitive == byte.class) return Byte.class;
        if (primitive == char.class) return Character.class;
        return primitive;
    }
}
