package ar.ive.spec.protection;

/**
 * Cuánto daño hace que este dato se exponga.
 *
 * <p>Son los cuatro niveles de uso extendido, que se corresponden con el
 * nivel de impacto de confidencialidad de NIST. <b>Es el único eje
 * ordenado de todo esto</b>: las clases de datos son propias de cada
 * organización —no existe una taxonomía universal— y los niveles de
 * confianza tampoco tienen orden entre sí. Por eso una regla del tipo
 * "de acá para arriba, protegido" solo se puede escribir sobre esto.</p>
 *
 * <p>El valor NO lo decide esta librería: sale del catálogo de la
 * organización, donde cada clase de dato declara el suyo, y llega
 * resuelto en la llamada. Cuando un dato tiene varias clases, el que
 * llega es <b>el más alto</b> de todas: una propiedad que es a la vez
 * identificador personal y dato de salud se trata como dato de salud.
 * Elegir el más bajo sería declarar un techo más flojo del que
 * corresponde.</p>
 */
public enum Sensitivity {

    /** Divulgación amplia, riesgo mínimo. */
    PUBLIC,

    /** Uso interno, riesgo limitado si se expone. */
    INTERNAL,

    /** Daño concreto si se expone. */
    CONFIDENTIAL,

    /** El nivel más alto; suele implicar acceso auditado. */
    RESTRICTED;

    /** Si este nivel es al menos tan sensible como el otro. */
    public boolean atLeast(Sensitivity other) {
        return other != null && this.ordinal() >= other.ordinal();
    }
}
