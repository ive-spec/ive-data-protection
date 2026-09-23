package ar.ive.spec.protection;

import java.util.Objects;

/**
 * UN NIVEL DE CONFIANZA DECLARADO: un nombre, y cuánta confianza es.
 *
 * <p><b>EL NOMBRE ES LA IDENTIDAD.</b> Es lo que devuelve el resolutor de
 * cada sistema, lo que la tabla indexa, lo que aparece en el mensaje de
 * una negativa y lo que queda en una auditoría. Todo lo que esta librería
 * recibe y devuelve sigue siendo el nombre.</p>
 *
 * <h2>Y el {@code clearance} es una CANTIDAD, no una posición</h2>
 * <p>Más alto es más confianza. No es un puesto en un ranking —donde el 1
 * sería el mejor— sino cuánto se le confía a quien llama: el dato tiene su
 * {@link Classification} y quien lo pide tiene su clearance.</p>
 *
 * <p><b>DOS NOMBRES PUEDEN COMPARTIR CLEARANCE, y es el caso normal.</b>
 * Si ninguna regla corta entre el profesional tratante y el equipo de
 * enfermería, entonces no son dos niveles de confianza: son dos nombres
 * del mismo, y siguen siendo distinguibles para escribirle una fila a uno
 * solo, para auditar y para leer un error. Ponerles cantidades distintas
 * afirmaría un corte que ninguna regla usa.</p>
 *
 * <h2>Es OPCIONAL, y eso es lo que mantiene honesto al modelo</h2>
 * <p>Un nivel puede declararse SIN clearance. Dos clases de confianza que
 * no se comparan —un socio comercial y un empleado de mesa— no tienen por
 * qué ponerse en la misma línea, y esta librería no obliga a inventar esa
 * comparación. Lo que no tiene cantidad no entra a ninguna banda ni a la
 * matriz por omisión: necesita filas escritas, como siempre.</p>
 *
 * <p>EL INVOCADOR DESCONOCIDO NO ES UN NIVEL Y NO TIENE CANTIDAD. No es
 * cero: si lo fuera, una banda "de cero para arriba" se lo llevaría puesto
 * en silencio, que es el agujero más caro y el más fácil de olvidar. Es
 * {@code null}, y tiene su propia respuesta.</p>
 *
 * @param name      el nombre, que es la identidad
 * @param clearance cuánta confianza, o {@code null} si no se declara
 */
public record TrustLevel(String name, Integer clearance) {

    public TrustLevel {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("Un nivel de confianza necesita un nombre.");
        }
    }

    /** Sin cantidad: sólo se puede usar con reglas escritas. */
    public static TrustLevel of(String name) {
        return new TrustLevel(name, null);
    }

    public static TrustLevel of(String name, int clearance) {
        return new TrustLevel(name, clearance);
    }

    /** Si entra en una banda que empieza en {@code desde}. */
    public boolean atLeast(int desde) {
        return clearance != null && clearance >= desde;
    }

    @Override
    public String toString() {
        return clearance == null ? name : name + " (clearance " + clearance + ")";
    }
}
