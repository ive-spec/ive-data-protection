package ar.ive.spec.protection;

/**
 * Baja la precisión de un valor según una regla que es del dominio.
 *
 * <p>La librería resuelve sola las reglas que no necesitan saber qué
 * significa el dato —{@code year}, {@code month}, {@code range:N},
 * {@code prefix:N}—. Todo lo demás es conocimiento del negocio: un
 * código postal a una región, un diagnóstico a un capítulo, un cargo a
 * una categoría. Eso no se adivina, y tampoco se declara en la
 * especificación: lo implementa la organización, una vez, y sirve para
 * todas las reglas propias que su tabla use.</p>
 *
 * <p>Es opcional, como {@link TokenService}: si la tabla no pide ninguna
 * regla propia, no hace falta. Si la pide y no está, la llamada se niega
 * con {@link MissingImplementationException} — que es la forma en que el
 * sistema se entera de que le falta implementar esto, en vez de devolver
 * un dato sin generalizar.</p>
 */
public interface Generalizer {

    /**
     * @param value          el valor real
     * @param rule           la regla, tal cual la escribió la tabla
     * @param classification qué es el dato
     * @return el valor generalizado — puede ser de otro tipo que el que entró
     */
    Object generalize(Object value, String rule, Classification classification);
}
