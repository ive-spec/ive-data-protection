package ar.ive.spec.protection;

/**
 * DADA UNA INVOCACION, CUAL ES EL NIVEL DE CONFIANZA. La implementa cada
 * organización, contra su esquema de seguridad.
 *
 * <p><b>Esta librería no la llama.</b> El nivel de confianza le llega ya
 * resuelto, como un valor más de la llamada: quien la usa es el código
 * generado, que lo pide acá y lo pasa. La interfaz vive igual en esta
 * librería porque el contrato tiene que ser uno solo — si cada paquete
 * de plantillas inventara el suyo, un sistema tendría que implementar
 * uno distinto por tecnología.</p>
 *
 * <p>El nivel <b>no viene en la petición</b>: eso sería dejar que quien
 * llama declare cuánto se confía en él. Lo resuelve el sistema receptor
 * a partir de lo que sí llega —credencial, alcances, origen— y de lo que
 * cada organización quiera mirar. Cómo llega a ese valor no es asunto de
 * la especificación ni de esta librería: por eso es una caja negra con
 * una interfaz, y no una regla escrita acá.</p>
 *
 * @param <C> lo que en esta tecnología representa una invocación: un
 *            request HTTP, un mensaje, lo que corresponda. La librería
 *            no lo mira.
 */
public interface TrustResolver<C> {

    /**
     * El nivel de confianza de quien está invocando.
     *
     * <p>Puede devolver {@code null} cuando no se pudo determinar. No es
     * un error: es una respuesta, y la tabla tiene que contestar lo más
     * protector que corresponda — no saber quién llama es más razón para
     * proteger, no menos.</p>
     */
    String trustLevelOf(C invocation);
}
