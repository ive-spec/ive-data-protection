package ar.ive.spec.protection;

/**
 * Algo que la tabla de decisión no resuelve, con dónde y por qué.
 *
 * <p>LAS CLAVES DE {@code kind} SON LAS MISMAS QUE EN PYTHON, letra por
 * letra. No es un detalle de estilo: una organización que corre un backend
 * en cada lenguaje va a leer las dos salidas, y la misma falta tiene que
 * llamarse igual en las dos o no se pueden comparar. Por eso son cadenas y
 * no un {@code enum}: el enum sería más lindo acá y menos comparable
 * allá.</p>
 */
public record Finding(String kind, Classification classification, String trustLevel, String message) {

    /** La tabla no dice qué forma le corresponde a ese par. */
    public static final String SIN_RESPUESTA = "sin-respuesta";

    /** La regla revela más de lo que el techo de la propia tabla admite. */
    public static final String SOBRE_EL_TECHO = "sobre-el-techo";

    /** Un parámetro de la técnica que no se puede aplicar. */
    public static final String PARAMETRO_INVALIDO = "parametro-invalido";

    /** Falta cableado: el servicio de tokens, el generalizador, las claves. */
    public static final String FALTA_IMPLEMENTACION = "falta-implementacion";

    /** Lo que la técnica produce no entra en el tipo del campo. */
    public static final String TIPO_INCOMPATIBLE = "tipo-incompatible";

    /** La tabla no contestó, o falló al preguntarle. */
    public static final String TABLA_SIN_CONTESTAR = "tabla-sin-contestar";

    /**
     * Este sistema dice atender a alguien que la tabla no lista.
     *
     * <p>La tabla que expone su lista está afirmando que está COMPLETA
     * —{@code trustLevels()} lo dice con todas las letras—, así que un
     * nivel que este proyecto declara y ella no tiene es una de dos: o el
     * nombre está mal escrito de un lado, o a la tabla le falta.</p>
     */
    public static final String NIVEL_QUE_LA_TABLA_NO_LISTA = "nivel-que-la-tabla-no-lista";

    @Override
    public String toString() {
        String donde = trustLevel == null ? "el invocador desconocido" : "'" + trustLevel + "'";
        return "[" + kind + "] " + classification + " / " + donde + ": " + message;
    }
}
