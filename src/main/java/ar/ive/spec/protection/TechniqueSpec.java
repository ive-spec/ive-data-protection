package ar.ive.spec.protection;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * LO QUE LA TABLA DEVUELVE: una técnica y con qué parámetros.
 *
 * <p>Los parámetros son de cada técnica y los declara la tabla, no esta
 * librería: cuánto se conserva y de qué lado en un enmascarado, la regla
 * de agrupamiento de una generalización, el algoritmo y la sal de un
 * hash. Van como mapa y no como campos con nombre a propósito — la tabla
 * es de cada organización, y una técnica puede necesitar un parámetro
 * que hoy no existe sin que haya que cambiar esta clase.</p>
 *
 * <p>Los nombres de los parámetros que la librería sí entiende están
 * declarados como constantes acá: es el contrato entre la tabla y quien
 * aplica la técnica. Un parámetro que no esté acá viaja igual y lo puede
 * leer una implementación propia.</p>
 */
public record TechniqueSpec(Technique technique, Map<String, String> params) {

    /** Cuántos caracteres del valor real quedan a la vista. Enmascarado. */
    public static final String KEEP = "keep";

    /** De qué lado quedan: {@code left} o {@code right}. Enmascarado. */
    public static final String SIDE = "side";

    /** La regla de agrupamiento. Generalización. */
    public static final String RULE = "rule";

    /** El algoritmo. Hash. */
    public static final String ALGORITHM = "algorithm";

    /**
     * De dónde sale la sal: {@code system} —estable, comparable entre
     * respuestas, y por eso correlacionable— o {@code value} —rompe la
     * correlación y también la comparación—. Hash.
     */
    public static final String SALT = "salt";

    /**
     * De qué alcance es la sal del hash, y no es una decisión menor.
     *
     * <p>{@link #SALT_SYSTEM} —una sal para todo el sistema, la de
     * omisión— mantiene el hash <b>estable</b>: el mismo valor da
     * siempre el mismo resultado, se puede comparar entre respuestas, y
     * por eso mismo <b>se puede correlacionar</b>.</p>
     *
     * <p>{@link #SALT_VALUE} —una sal por valor— rompe la correlación, y
     * también la comparación: dos hashes del mismo dato no se parecen.
     * Es lo que corresponde cuando el hash está para no mostrar el dato,
     * no para poder compararlo.</p>
     */
    public static final String SALT_SCOPE = "saltScope";

    /** Sal para todo el sistema: hash estable y comparable. */
    public static final String SALT_SYSTEM = "system";

    /** Sal por valor: no se puede comparar ni correlacionar. */
    public static final String SALT_VALUE = "value";

    public TechniqueSpec {
        Objects.requireNonNull(technique, "technique");
        params = params == null ? Map.of() : Map.copyOf(params);
    }

    /** La técnica sin parámetros. Es lo normal para las que no llevan. */
    public static TechniqueSpec of(Technique technique) {
        return new TechniqueSpec(technique, Map.of());
    }

    public Optional<String> param(String name) {
        return Optional.ofNullable(params.get(name));
    }

    /**
     * Un parámetro numérico. Devuelve vacío si no está o si la tabla
     * puso algo que no es un número — que es un error de la tabla, no un
     * caso a resolver acá: quien aplique la técnica decide si puede
     * seguir sin él o si tiene que negarse.
     */
    public Optional<Integer> intParam(String name) {
        try {
            return param(name).map(Integer::parseInt);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    @Override
    public String toString() {
        return params.isEmpty() ? technique.toString() : technique + " " + params;
    }
}
