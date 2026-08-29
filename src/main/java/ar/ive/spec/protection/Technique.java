package ar.ive.spec.protection;

/**
 * QUE SE DEVUELVE DE UN VALOR PROTEGIDO. Es una escala, de más a menos
 * revelador, y esta librería no elige: la elige la tabla.
 *
 * <p>Cada una declara dos cosas que el resto de la librería necesita
 * saber sin conocer los detalles de ninguna: <b>si tiene vuelta</b> y
 * <b>qué hace falta para aplicarla</b>.</p>
 *
 * <p><b>La vuelta importa porque el valor casi nunca está en claro.</b>
 * Un dato que llega de otro sistema puede venir ya tokenizado, y uno que
 * sale de la base puede venir cifrado: para llevarlo a la forma que
 * corresponde hay que deshacer primero lo que tenga puesto. Lo que no
 * tiene vuelta no se puede deshacer —de un hash no se vuelve al valor
 * real, y de un enmascarado tampoco—, y ahí la librería se niega en vez
 * de devolver algo que no es el dato.</p>
 *
 * <p>Quedan fuera privacidad diferencial, k-anonimato, datos sintéticos
 * y barajado: son técnicas sobre conjuntos de datos, no sobre un valor
 * en una respuesta.</p>
 */
public enum Technique {

    /** El dato, tal cual. No necesita nada. */
    FULL(true, Requirement.NONE),

    /**
     * El valor real, con menos precisión: una fecha de nacimiento como
     * rango de edad, una ciudad como provincia. Necesita la regla de
     * agrupamiento, que declara la tabla.
     *
     * <p>No tiene vuelta: de un rango no se recupera la fecha.</p>
     */
    GENERALIZED(false, Requirement.RULES),

    /**
     * Un fragmento del valor real. Necesita cuánto se conserva y de qué
     * lado, que declara la tabla.
     *
     * <p>No tiene vuelta: lo que se tapó no está en ningún lado.</p>
     */
    MASKED(false, Requirement.NONE),

    /**
     * Un sustituto estable. Necesita el servicio de tokenización, que
     * implementa la organización.
     *
     * <p><b>Tiene vuelta</b> —el servicio sabe volver— y por eso un
     * token sigue siendo un dato sensible: es reversible por quien lo
     * tenga, así que no es anónimo y se protege igual que el valor
     * real.</p>
     *
     * <p>Y el token tiene que ser <b>el mismo siempre</b>: si cada
     * llamada devolviera uno distinto, quien lo recibe no podría
     * correlacionar nada y el token no serviría para nada.</p>
     */
    TOKENIZED(true, Requirement.TOKENS),

    /**
     * Un sustituto estable e irreversible: permite comparar igualdad sin
     * revelar. Necesita algoritmo y sal, que declara la tabla.
     *
     * <p>Sobre la sal hay una decisión que no es menor y que la tabla
     * toma, no esta librería: una sal por sistema mantiene el hash
     * estable —el mismo valor da siempre el mismo resultado, y se puede
     * comparar entre respuestas— pero eso también permite correlacionar;
     * una sal por valor rompe la correlación y también la comparación.</p>
     */
    HASHED(false, Requirement.NONE),

    /**
     * El campo, sin valor.
     *
     * <p>No es lo mismo que {@link #OMITTED}: <b>un nulo dice "hay un
     * campo que no te muestro", la ausencia no dice nada.</b></p>
     */
    REDACTED(false, Requirement.NONE),

    /**
     * Nada: el campo no aparece.
     *
     * <p>Esto NO es un valor, y por eso esta librería no lo puede
     * aplicar sola: que un campo no aparezca es una decisión de quien
     * serializa. Acá se puede decidir y devolver como técnica, para que
     * el enganche de cada framework la ejecute.</p>
     */
    OMITTED(false, Requirement.NONE);

    /** Qué hace falta, además de la tabla, para poder aplicarla. */
    public enum Requirement {
        /** Nada que la librería no tenga. */
        NONE,
        /** El servicio de tokenización de la organización. */
        TOKENS,
        /**
         * El gestor de claves de la organización.
         *
         * <p>NINGUNA TECNICA DE LA ESCALA LA PIDE, y no es un olvido: el
         * cifrado no es una forma de exponer un dato, es una forma de
         * GUARDARLO. Hace falta para deshacer lo que la base tiene
         * puesto —descifrar antes de llevar el valor a la forma que
         * corresponde a quien lo recibe— y para dejarlo en esa forma al
         * guardarlo.</p>
         */
        KEYS,
        /**
         * El generalizador del dominio.
         *
         * <p>La librería resuelve sola las reglas de agrupamiento que no
         * necesitan saber qué significa el dato —el año de una fecha, un
         * rango numérico, un prefijo—. Un código postal a una región o un
         * diagnóstico a un capítulo no salen de ahí: eso lo sabe el
         * negocio, y lo implementa la organización.</p>
         */
        RULES
    }

    private final boolean reversible;
    private final Requirement requirement;

    Technique(boolean reversible, Requirement requirement) {
        this.reversible = reversible;
        this.requirement = requirement;
    }

    /**
     * Si de la forma que produce se puede volver al valor real.
     *
     * <p>Es lo que decide si un valor que YA está en esta forma se puede
     * llevar a otra. Un valor cifrado se descifra y se tokeniza; uno
     * hasheado no se puede llevar a ningún lado.</p>
     */
    public boolean isReversible() {
        return reversible;
    }

    /** Qué implementación de la organización hace falta para aplicarla. */
    public Requirement requirement() {
        return requirement;
    }

    /**
     * Si esta técnica revela más del dato que la otra.
     *
     * <p>ES EL ORDEN EN QUE ESTAN DECLARADAS, y no es casual: la escala
     * va de más a menos reveladora, igual que la tabla del modelo. De
     * este orden depende que se pueda comprobar un techo, así que
     * agregar una técnica en el medio no es un cambio cosmético.</p>
     */
    public boolean revealsMoreThan(Technique other) {
        return other != null && this.ordinal() < other.ordinal();
    }

    /**
     * Si produce un valor que se pueda asignar a un campo.
     *
     * <p>{@link #OMITTED} no: no hay valor que poner, hay que no poner
     * el campo, y eso lo resuelve quien serializa.</p>
     */
    public boolean producesValue() {
        return this != OMITTED;
    }
}
