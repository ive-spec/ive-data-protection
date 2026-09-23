package ar.ive.spec.protection;

import java.util.Collection;
import java.util.List;
import java.util.TreeSet;

/**
 * EL RESOLUTOR DEVOLVIÓ UN NIVEL QUE NADIE DECLARÓ.
 *
 * <p><b>No es "no se pudo determinar".</b> Para eso está {@code null}, que
 * está documentado, tiene su fila explícita y es lo que hay que devolver
 * cuando no se sabe quién llama. Un nombre que nadie declaró no es una
 * duda: es alguien que creyó que ese nivel existía.</p>
 *
 * <h2>Por qué se niega en vez de tratarlo como uno más</h2>
 * <p>Antes caía en la regla de "para todos mis niveles" —y quien llega con
 * un nombre que no existe NO es uno de ellos—. Eso no fallaba: contestaba
 * distinto, en silencio. Y si el nombre mal escrito es el del nivel más
 * alto, el resultado es que quien más tenía que ver DEJA DE VER, sin que
 * nada lo diga y sin que nadie lo pueda diagnosticar.</p>
 *
 * <p>Tampoco se puede encontrar antes: el resolutor es una caja negra
 * —un mapa, una consulta, lo que cada sistema quiera— y esta librería no
 * puede enumerar lo que va a devolver. El verificador de arranque recorre
 * los niveles DECLARADOS, así que un nombre que no está entre ellos no se
 * recorre nunca.</p>
 *
 * <p>Por eso el mensaje trae el nombre recibido Y la lista de los
 * declarados: es lo que convierte esto en un diagnóstico de treinta
 * segundos en vez de una búsqueda.</p>
 */
public class UnknownTrustLevelException extends ProtectionException {

    private static final long serialVersionUID = 1L;

    public UnknownTrustLevelException(Classification classification,
                                      String trustLevel,
                                      Collection<String> declarados) {
        super("El nivel de confianza \"" + trustLevel + "\" no está declarado."
                        + " Los declarados son: " + String.join(", ", new TreeSet<>(declarados)) + "."
                        + " Si lo que pasó es que no se pudo determinar quién llama, eso se dice"
                        + " devolviendo null: tiene su propia fila y es lo más protector."
                        + " El dato es " + classification + ".",
                classification, null, trustLevel);
    }

    /** Los declarados, para quien quiera mostrarlos sin parsear el mensaje. */
    public static List<String> ordenados(Collection<String> declarados) {
        return List.copyOf(new TreeSet<>(declarados));
    }
}
