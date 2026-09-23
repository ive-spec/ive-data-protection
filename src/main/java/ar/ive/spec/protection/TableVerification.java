package ar.ive.spec.protection;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * RECORRER LA TABLA ENTERA Y DECIR QUÉ LE FALTA, ANTES DE USARLA.
 *
 * <p>POR QUÉ EXISTE. Casi todo lo que esta librería puede negar no es un
 * error de ejecución: es una PROPIEDAD DE LA TABLA.
 * {@link DecisionTable#techniqueFor} y {@link DecisionTable#ceilingFor}
 * dependen sólo de la clasificación y del nivel de confianza —ninguna de
 * las dos mira el dato— así que una fila mal escrita, un techo que la
 * propia tabla se pasa o un par sin respuesta se pueden encontrar
 * RECORRIENDO: sin datos, sin peticiones y sin tener que provocarlos con
 * un caso de prueba.</p>
 *
 * <p>Y LA DIFERENCIA NO ES DE PROLIJIDAD. Sin esto, una fila mal escrita
 * se descubre cuando alguien pide ESE dato con ESE nivel: si es un nivel
 * poco frecuente, pueden pasar meses.</p>
 *
 * <p>QUÉ NO SE PUEDE VERIFICAR ASÍ, y por eso queda para ejecución: que el
 * dato que llega DE OTRO SISTEMA alcance para lo que hay que dar
 * ({@link IrreversibleTechniqueException}, {@link UnknownFormException}).
 * Depende de lo que mande ese sistema, no de la tabla. Sobre la base
 * propia no puede pasar: la forma de guardado siempre puede llegar a la
 * salida más exigente, y eso es lo que compra esa regla.</p>
 *
 * <p>CUÁNDO CORRERLO: lo más temprano que se pueda. El generador NO puede
 * —la tabla es código que escribe la organización y sólo existe en
 * ejecución— así que el momento más temprano posible es AL ARRANCAR.</p>
 *
 * <p>ES EL MISMO VERIFICADOR QUE EL DE PYTHON, hallazgo por hallazgo y con
 * las mismas claves. La tabla de una organización es una sola aunque haya
 * dos backends leyéndola: si acá faltara un chequeo que allá está, el
 * mismo sistema pasaría o no según en qué lenguaje esté escrito el
 * servicio que arrancó.</p>
 */
public final class TableVerification {

    /**
     * Las técnicas que SIEMPRE producen texto que no es un número. Es lo
     * que hace comprobable el tipo de destino sin mirar ningún dato.
     *
     * <p>{@code TOKENIZED} no está: qué forma tiene un token lo decide el
     * servicio de tokenización de cada organización, y suponer que no es
     * numérico sería inventar. {@code GENERALIZED} depende de la regla y
     * se mira aparte: {@code year} produce "1980", que sí entra en un
     * entero.</p>
     */
    private static final Set<Technique> TEXTO_SEGURO =
            Set.of(Technique.MASKED, Technique.HASHED, Technique.REDACTED);

    /** Los tipos que no aguantan un texto arbitrario. */
    private static final Set<Class<?>> NUMERICOS = Set.of(
            int.class, long.class, short.class, byte.class, double.class, float.class,
            Integer.class, Long.class, Short.class, Byte.class, Double.class, Float.class,
            BigDecimal.class, BigInteger.class);

    private TableVerification() {
    }

    /**
     * Todo lo que la tabla no resuelve, recorriendo lo que el sistema tiene.
     *
     * @param protection      el {@link DataProtection} ya construido: de ahí
     *                        sale la tabla Y el cableado, que es la mitad de
     *                        lo que hay que comprobar.
     * @param classifications las que ESTA especificación declara. El código
     *                        generado las tiene en una constante.
     * @param fieldTypes      de qué tipo es el campo donde va cada
     *                        clasificación, por nombre de clase. Sin esto no
     *                        se puede comprobar que lo que la técnica produce
     *                        entre donde va, y ese chequeo se saltea en vez
     *                        de inventarse.
     * @param extraLevels     niveles que la tabla no expone en
     *                        {@code trustLevels()} pero este sistema usa
     *                        igual. Una tabla puede devolver un conjunto
     *                        vacío a propósito —"no expongo mi lista"— y ahí
     *                        hay que decirle cuáles mirar.
     *
     * <p>SE RECORRE TAMBIÉN EL INVOCADOR DESCONOCIDO ({@code null}), y no es
     * un agregado: es el caso más fácil de olvidar y el más caro. La regla
     * para "cualquier otro nivel" NO lo cubre —esa red sólo se tira cuando
     * hay un nivel— así que si nadie le escribió una fila, la tabla no
     * contesta. Que se le niegue el dato puede ser exactamente lo que la
     * organización quiso; lo que no puede ser es que nadie lo haya
     * decidido. Por eso se exige una respuesta EXPLÍCITA: una fila que diga
     * {@code OMITTED} o {@code REDACTED} dice "esto lo decidí yo", y una
     * fila que falta no dice nada.</p>
     */
    public static List<Finding> verify(DataProtection protection,
                                       Collection<Classification> classifications,
                                       Map<String, Class<?>> fieldTypes,
                                       Set<String> extraLevels) {
        List<Finding> hallazgos = new ArrayList<>();
        DecisionTable tabla = protection.table();
        Map<String, Class<?>> tipos = fieldTypes == null ? Map.of() : fieldTypes;

        Set<String> declarados;
        try {
            declarados = tabla.trustLevels();
        } catch (RuntimeException falla) {
            return List.of(new Finding(Finding.TABLA_SIN_CONTESTAR, null, null,
                    "trustLevels() falló: " + falla.getMessage()));
        }

        if (declarados == null) {
            // Un conjunto vacío es una respuesta —"no expongo mi lista"— y
            // `null` no es ninguna.
            return List.of(new Finding(Finding.TABLA_SIN_CONTESTAR, null, null,
                    "trustLevels() devolvió null. Para no exponer la lista, devolvé un conjunto"
                            + " vacío: eso es una decisión, y un null no lo es."));
        }

        List<String> niveles = new ArrayList<>(new LinkedHashSet<>(declarados));
        if (extraLevels != null) {
            for (String nivel : extraLevels) {
                // LA TABLA QUE EXPONE SU LISTA AFIRMA QUE ESTA COMPLETA
                // --`trustLevels()` lo dice con todas las letras-- asi que
                // un nivel que este proyecto declara y ella no tiene es una
                // de dos: el nombre esta mal escrito de un lado, o a la
                // tabla le falta. Las dos se arreglan mirando, y las dos
                // cuestan caro sin avisar: lo que falta termina decidiendo
                // en que forma se GUARDA el dato.
                //
                // Con la lista VACIA no se dice nada: eso es "no expongo mi
                // lista", que es una respuesta legitima y documentada, y
                // ahi `extraLevels` es justamente para lo que existe.
                if (!declarados.isEmpty() && !declarados.contains(nivel)) {
                    hallazgos.add(new Finding(Finding.NIVEL_QUE_LA_TABLA_NO_LISTA, null, nivel,
                            "este sistema declara que lo atiende y la tabla no lo lista."
                                    + " Los que la tabla lista son: " + String.join(", ", declarados)
                                    + ". O el nombre está mal escrito de un lado, o a la tabla le"
                                    + " falta: sin resolverlo, lo que decide en qué forma se guarda"
                                    + " el dato queda a medias."));
                }
                if (!niveles.contains(nivel)) {
                    niveles.add(nivel);
                }
            }
        }
        niveles.add(null); // el invocador desconocido, siempre

        for (Classification classification : classifications) {
            for (String nivel : niveles) {
                hallazgos.addAll(verificarPar(protection, tabla, classification, nivel, tipos));
            }
            hallazgos.addAll(verificarGuardado(protection, classification));
        }
        return List.copyOf(hallazgos);
    }

    /** Sin tipos de campo y sin niveles extra: lo mínimo. */
    public static List<Finding> verify(DataProtection protection,
                                       Collection<Classification> classifications) {
        return verify(protection, classifications, Map.of(), Set.of());
    }

    /**
     * REQUIRES A COMPLETE TABLE: {@link #verify} and, if anything is found,
     * {@link IncompleteTableException} with every finding.
     *
     * <p>IT IS NOT A WARNING. The alternative to failing here is failing on
     * somebody's request, when that value is asked for with that level --
     * which may be months later. And there is no way to switch it off on
     * purpose: a pair left unanswered may be exactly what the organization
     * wanted, and for saying so there is the explicit row
     * ({@code OMITTED} or {@code REDACTED} for that level, the unknown
     * caller included).</p>
     *
     * <p>Same parameters as {@link #verify}.</p>
     */
    public static void requireComplete(DataProtection protection,
                                       Collection<Classification> classifications,
                                       Map<String, Class<?>> fieldTypes,
                                       Set<String> extraLevels) {
        List<Finding> findings = verify(protection, classifications, fieldTypes, extraLevels);
        if (!findings.isEmpty()) {
            throw new IncompleteTableException(findings);
        }
    }

    /** {@link #requireComplete} without field types and without extra levels. */
    public static void requireComplete(DataProtection protection,
                                       Collection<Classification> classifications) {
        requireComplete(protection, classifications, Map.of(), Set.of());
    }

    private static List<Finding> verificarPar(DataProtection protection, DecisionTable tabla,
                                              Classification classification, String nivel,
                                              Map<String, Class<?>> tipos) {
        List<Finding> hallazgos = new ArrayList<>();
        TechniqueSpec spec;
        try {
            spec = tabla.techniqueFor(classification, nivel);
        } catch (RuntimeException falla) {
            return List.of(new Finding(Finding.TABLA_SIN_CONTESTAR, classification, nivel,
                    "la tabla falló: " + falla.getMessage()));
        }

        if (spec == null) {
            hallazgos.add(new Finding(Finding.SIN_RESPUESTA, classification, nivel,
                    "la tabla no dice qué forma le corresponde. Si la intención es negarle el dato,"
                            + " escribí la fila con OMITTED o REDACTED: una fila que falta no dice"
                            + " nada, y en ejecución esto sale como un error del servidor."));
            return hallazgos;
        }

        // EL TECHO. Es la misma decisión dicha dos veces, y acá es donde se
        // ve si se contradicen — en ejecución aparece recién cuando alguien
        // pide ese dato con ese nivel.
        Technique techo;
        try {
            techo = tabla.ceilingFor(classification, nivel);
        } catch (RuntimeException falla) {
            techo = Technique.FULL;
            hallazgos.add(new Finding(Finding.TABLA_SIN_CONTESTAR, classification, nivel,
                    "ceilingFor falló: " + falla.getMessage()));
        }
        if (techo != null && spec.technique().revealsMoreThan(techo)) {
            hallazgos.add(new Finding(Finding.SOBRE_EL_TECHO, classification, nivel,
                    "la tabla resuelve " + spec.technique() + " y su propio techo para este caso es "
                            + techo + ": revela más de lo que ella misma admite."));
        }

        hallazgos.addAll(verificarSpec(protection, classification, nivel, spec));
        hallazgos.addAll(verificarTipo(classification, nivel, spec, tipos));
        return hallazgos;
    }

    /**
     * Los parámetros de la técnica, y si lo que necesita está cableado.
     *
     * <p>NO SE APLICA LA TÉCNICA A UN VALOR DE PRUEBA. Un valor inventado
     * responde por sí mismo y no por la tabla: generalizar al año falla
     * sobre un valor que no es una fecha, y eso no diría nada sobre si la
     * regla está bien escrita. Se miran los parámetros.</p>
     */
    private static List<Finding> verificarSpec(DataProtection protection, Classification classification,
                                               String nivel, TechniqueSpec spec) {
        List<Finding> hallazgos = new ArrayList<>();

        switch (spec.technique()) {
            case MASKED -> {
                if (spec.param(TechniqueSpec.KEEP).isPresent()
                        && spec.intParam(TechniqueSpec.KEEP).isEmpty()) {
                    hallazgos.add(new Finding(Finding.PARAMETRO_INVALIDO, classification, nivel,
                            "'" + TechniqueSpec.KEEP + "' tiene que ser un número y dice '"
                                    + spec.param(TechniqueSpec.KEEP).orElse("") + "'."));
                } else if (spec.intParam(TechniqueSpec.KEEP).orElse(0) < 0) {
                    hallazgos.add(new Finding(Finding.PARAMETRO_INVALIDO, classification, nivel,
                            "'" + TechniqueSpec.KEEP + "' no puede ser negativo."));
                }
                String lado = spec.param(TechniqueSpec.SIDE).orElse("right").toLowerCase();
                if (!lado.equals("right") && !lado.equals("left")) {
                    hallazgos.add(new Finding(Finding.PARAMETRO_INVALIDO, classification, nivel,
                            "'" + TechniqueSpec.SIDE + "' es '" + lado + "' y los lados son 'left' y 'right'."));
                }
            }
            case HASHED -> {
                String alcance = spec.param(TechniqueSpec.SALT_SCOPE).orElse(TechniqueSpec.SALT_SYSTEM);
                if (!alcance.equals(TechniqueSpec.SALT_SYSTEM) && !alcance.equals(TechniqueSpec.SALT_VALUE)) {
                    hallazgos.add(new Finding(Finding.PARAMETRO_INVALIDO, classification, nivel,
                            "'" + TechniqueSpec.SALT_SCOPE + "' es '" + alcance + "' y los alcances son '"
                                    + TechniqueSpec.SALT_SYSTEM + "' y '" + TechniqueSpec.SALT_VALUE + "'."));
                }
                String algoritmo = spec.param(TechniqueSpec.ALGORITHM).orElse("SHA-256");
                try {
                    MessageDigest.getInstance(algoritmo);
                } catch (NoSuchAlgorithmException e) {
                    hallazgos.add(new Finding(Finding.PARAMETRO_INVALIDO, classification, nivel,
                            "el algoritmo '" + algoritmo + "' no existe en esta JVM."));
                }
            }
            case GENERALIZED -> {
                String regla = spec.param(TechniqueSpec.RULE).orElse(null);
                if (regla == null) {
                    hallazgos.add(new Finding(Finding.PARAMETRO_INVALIDO, classification, nivel,
                            "generaliza y no dice con qué regla ('" + TechniqueSpec.RULE + "')."));
                } else if (!reglaConocida(regla) && protection.generalizer() == null) {
                    hallazgos.add(new Finding(Finding.FALTA_IMPLEMENTACION, classification, nivel,
                            "la regla '" + regla + "' no es de las que resuelve la librería"
                                    + " (year, month, range:N, prefix:N) y no hay Generalizer."));
                } else if (regla.startsWith("range:") || regla.startsWith("prefix:")) {
                    String crudo = regla.substring(regla.indexOf(':') + 1).trim();
                    try {
                        if (Long.parseLong(crudo) <= 0) {
                            throw new NumberFormatException();
                        }
                    } catch (NumberFormatException e) {
                        hallazgos.add(new Finding(Finding.PARAMETRO_INVALIDO, classification, nivel,
                                "la regla '" + regla + "' necesita un número positivo."));
                    }
                }
            }
            case TOKENIZED -> {
                if (protection.tokens() == null) {
                    hallazgos.add(new Finding(Finding.FALTA_IMPLEMENTACION, classification, nivel,
                            "tokeniza y este sistema no tiene TokenService."));
                }
            }
            default -> {
                // FULL, REDACTED y OMITTED no llevan parámetros que puedan
                // estar mal: no hay nada que mirar, y decirlo es mejor que
                // un `default` vacío que parezca un olvido.
            }
        }
        return hallazgos;
    }

    private static boolean reglaConocida(String regla) {
        return regla.equals("year") || regla.equals("month")
                || regla.startsWith("range:") || regla.startsWith("prefix:");
    }

    /**
     * Que lo que la técnica produce ENTRE donde va.
     *
     * <p>Es el chequeo que parece de ejecución y no lo es: la técnica sale
     * de la tabla y el tipo del campo sale de la View, y los dos se conocen
     * sin mirar ningún dato.</p>
     *
     * <p>SE INFORMA SÓLO LO QUE ES SEGURO. Un enmascarado nunca va a ser un
     * número; un token, en cambio, tiene la forma que le dé el servicio de
     * tokenización de cada organización.</p>
     */
    private static List<Finding> verificarTipo(Classification classification, String nivel,
                                               TechniqueSpec spec, Map<String, Class<?>> tipos) {
        Class<?> destino = null;
        for (String clase : classification.classes()) {
            if (tipos.containsKey(clase)) {
                destino = tipos.get(clase);
                break;
            }
        }
        if (destino == null || !NUMERICOS.contains(destino)) {
            return List.of();
        }

        boolean produceTexto = TEXTO_SEGURO.contains(spec.technique());
        if (spec.technique() == Technique.GENERALIZED) {
            // `year` produce "1980", que entra en un entero. El resto no.
            produceTexto = !"year".equals(spec.param(TechniqueSpec.RULE).orElse(""));
        }
        if (!produceTexto) {
            return List.of();
        }
        return List.of(new Finding(Finding.TIPO_INCOMPATIBLE, classification, nivel,
                spec.technique() + " produce texto y el campo es " + destino.getSimpleName()
                        + ": en ejecución la conversión se niega. O el campo es texto, o la técnica"
                        + " para este nivel es otra."));
    }

    /**
     * Que la forma de guardado se pueda resolver, y aplicar.
     *
     * <p>Depende de TODOS los niveles a la vez —la forma tiene que poder
     * llegar a la salida más exigente— así que se mira una vez por
     * clasificación y no una por nivel.</p>
     */
    private static List<Finding> verificarGuardado(DataProtection protection, Classification classification) {
        TechniqueSpec forma;
        try {
            forma = protection.storageFormFor(classification);
        } catch (AboveCeilingException falla) {
            return List.of(new Finding(Finding.SOBRE_EL_TECHO, classification, null,
                    "al decidir cómo se guarda: " + falla.getMessage()));
        } catch (ProtectionException falla) {
            return List.of(new Finding(Finding.SIN_RESPUESTA, classification, null,
                    "no se puede decidir cómo se guarda: " + falla.getMessage()));
        }

        // EL CIFRADO EN REPOSO TAMBIÉN ES CABLEADO. Que falte el gestor de
        // claves no quiere decir "entonces guardalo en claro": si esta
        // sensibilidad se cifra y no hay con qué, la primera escritura se
        // niega. Mejor saberlo ahora.
        if (forma.technique() == Technique.FULL
                && classification.sensitivity().atLeast(protection.encryptFrom())
                && protection.keys() == null
                && !protection.withoutEncryptionAtRest()) {
            return List.of(new Finding(Finding.FALTA_IMPLEMENTACION, classification, null,
                    "se guarda entero y su sensibilidad (" + classification.sensitivity()
                            + ") está en el nivel que se cifra en reposo, pero no hay KeyProvider."
                            + " Si este sistema no cifra, declaralo con withoutEncryptionAtRest():"
                            + " la ausencia no es una decisión."));
        }
        return List.of();
    }

    // ------------------------------------------------------------------
    // SAYING HOW EACH THING ENDED UP STORED
    //
    // This is NOT a check: it finds nothing and it fails at nothing. It
    // ANSWERS a question that is resolved here and nowhere else.
    //
    // `storageFormFor` is already resolved at startup, once per
    // classification, and until now the answer was thrown away -- only the
    // findings came out. Whoever tests the system had no way of knowing
    // whether a value is kept whole, tokenized or hashed, and that decides
    // what they should expect to see in the database.
    //
    // AND THIS IS THE ONLY MOMENT IT CAN BE KNOWN. The generator cannot:
    // the table is written by the organization and only exists at runtime.
    // So it is not, and cannot be, in any generated artifact.
    // ------------------------------------------------------------------

    /**
     * How one class of data ends up stored, and why, if a reason was given.
     *
     * @param classification  what the data is
     * @param form            the form it is stored in
     * @param encryptedAtRest whether this library encrypts it on the way to
     *                        the column. Storage-level encryption —disk, a
     *                        tablespace, a database that already encrypts—
     *                        is outside this library and does not show here
     * @param reasonForUse    why this system needs the real value, or
     *                        {@code null} when nothing was declared
     * @param warning         what deserves a second look, or {@code null}.
     *                        It is not an error: nothing here can be proven
     *                        wrong from the inside
     */
    public record StorageNote(Classification classification,
                              TechniqueSpec form,
                              boolean encryptedAtRest,
                              String reasonForUse,
                              String warning) {

        @Override
        public String toString() {
            StringBuilder linea = new StringBuilder();
            linea.append(classification).append(" -> ").append(form.technique());
            if (encryptedAtRest) {
                linea.append(" + encrypted at rest");
            }
            if (reasonForUse != null) {
                linea.append(" (kept whole: ").append(reasonForUse).append(')');
            }
            if (warning != null) {
                linea.append("\n    ! ").append(warning);
            }
            return linea.toString();
        }
    }

    /**
     * HOW EACH CLASSIFICATION ENDS UP STORED, for whoever has to know what
     * to expect. One line per classification, in the order given.
     *
     * <p>A classification whose storage form cannot even be resolved is
     * left out: that is a finding, and {@link #verify} is what reports
     * it.</p>
     */
    public static List<StorageNote> describeStorage(DataProtection protection,
                                                    Collection<Classification> classifications) {
        List<StorageNote> notas = new ArrayList<>();
        for (Classification classification : classifications) {
            TechniqueSpec forma;
            try {
                forma = protection.storageFormFor(classification);
            } catch (ProtectionException falla) {
                continue;
            }
            boolean sobreElPiso = classification.sensitivity().atLeast(protection.encryptFrom());
            boolean cifrado = forma.technique() == Technique.FULL
                    && sobreElPiso
                    && protection.keys() != null;
            String razon = protection.reasonForUse(classification);

            // THE ONE WORTH SEEING AT A GLANCE. Two decisions that are each
            // reasonable on their own —"I need to use this value" and "the
            // storage already encrypts"— leave the real value in clear in
            // the database. Neither of them is wrong, and nobody is in a
            // position to notice the combination except right here.
            String aviso = null;
            if (razon != null
                    && forma.technique() == Technique.FULL
                    && sobreElPiso
                    && protection.keys() == null
                    && protection.withoutEncryptionAtRest()) {
                aviso = "the real value is kept in clear: it is needed whole, its sensitivity ("
                        + classification.sensitivity() + ") is at the level that gets encrypted,"
                        + " and this system declared it does not encrypt at rest."
                        + " Check that the storage does encrypt it.";
            }
            notas.add(new StorageNote(classification, forma, cifrado, razon, aviso));
        }
        return List.copyOf(notas);
    }
}
