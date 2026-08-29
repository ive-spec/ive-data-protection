package ar.ive.spec.protection;

import java.util.Set;

/**
 * LA TABLA DE DECISION: qué técnica corresponde, y para quién.
 *
 * <p>Entradas: la sensibilidad, la clasificación y el nivel de confianza
 * de quien recibe. Salida: la técnica. <b>Y precedencia</b>, porque lo
 * particular gana sobre lo genérico: las reglas genéricas van por nivel
 * de sensibilidad, y las particulares por clase puntual —
 * {@code cardholderData} es restringido, pero qué se puede mostrar de
 * una tarjeta lo dice PCI DSS y no se deduce de "restringido"—.</p>
 *
 * <p><b>La tabla es propia de cada organización</b>, igual que las clases
 * de datos y que los niveles de confianza. Esta librería define qué
 * preguntas se le hacen y las evalúa; qué contesta, no. Por eso es una
 * interfaz y no un archivo con un formato impuesto: quien la implemente
 * puede leerla de donde quiera.</p>
 *
 * <p><b>La clasificación fija el techo.</b> Una tabla que le devuelva
 * {@link Technique#FULL} a un destinatario de poca confianza sobre un
 * dato restringido no está tomando una decisión legítima: está mal
 * escrita. Esta librería no puede DEDUCIR ese techo —no sabe qué nivel
 * de confianza es "poco" para una organización, porque los niveles no
 * tienen orden entre sí— pero sí puede HACERLO CUMPLIR si se lo
 * declaran: para eso está {@link #ceilingFor}.</p>
 */
public interface DecisionTable {

    /**
     * La técnica con la que este dato le llega a quien tiene ese nivel
     * de confianza.
     *
     * @param classification qué es el dato: sus clases y su techo de
     *                       sensibilidad, resueltos por quien generó el
     *                       código contra el catálogo de la organización
     * @param trustLevel     quién recibe. Es un valor propio de cada
     *                       organización y lo resuelve el sistema
     *                       receptor, no viaja en la invocación. Puede
     *                       ser {@code null} cuando no se pudo
     *                       determinar, y ahí la tabla tiene que
     *                       contestar lo más protector que corresponda:
     *                       no saber quién llama es más razón para
     *                       proteger, no menos.
     * @return la técnica y sus parámetros. Nunca {@code null}: si la
     *         tabla no tiene una regla para este caso, tiene que
     *         devolver la que aplique por omisión, y si su omisión es
     *         "no exponer", devolver {@link Technique#REDACTED} u
     *         {@link Technique#OMITTED} — un {@code null} sería "no sé",
     *         que acá se lee como "mostralo entero".
     */
    TechniqueSpec techniqueFor(Classification classification, String trustLevel);

    /**
     * Todos los niveles de confianza que esta tabla conoce.
     *
     * <p>Hace falta para una pregunta que no se puede contestar mirando
     * un nivel solo: <b>en qué forma hay que guardar un dato</b>. La
     * respuesta sale de la salida más exigente de todas las que usan ese
     * dato —guardar cifrado no cierra ninguna puerta; guardar hasheado
     * cierra casi todas— así que hay que poder recorrer los niveles.</p>
     *
     * <p><b>TIENEN QUE ESTAR TODOS.</b> Toda la regla de la forma de
     * guardado se apoya en esta lista: si falta un nivel, el dato se
     * guarda en una forma desde la que a ese nivel no se lo puede
     * servir, y eso no se descubre al generar ni al arrancar — se
     * descubre la primera vez que alguien de ese nivel pide el dato, en
     * producción.</p>
     *
     * <p>Una tabla que no quiera exponer su lista puede devolver un
     * conjunto vacío: ahí la forma de almacenamiento la decide quien
     * implemente, no esta librería.</p>
     */
    Set<String> trustLevels();

    /**
     * LO MAS REVELADOR QUE ESTE DATO PUEDE SALIR PARA ESE NIVEL, sea
     * cual sea la regla que después lo resuelva.
     *
     * <p>Es la misma decisión dicha dos veces, y ahí está su valor: la
     * regla puntual dice qué sale, el techo dice hasta dónde se puede
     * llegar, y si la regla lo pasa, <b>la tabla se contradice a sí
     * misma</b>. Esa contradicción no la puede ver el generador —desde
     * la vuelta en que la exposición salió del modelo no hay nada
     * declarado en la propiedad que pueda contradecir a la tabla— así
     * que este es el último lugar donde se puede ver, y por eso la
     * librería la comprueba en cada llamada.</p>
     *
     * <p><b>De omisión no hay techo</b> ({@link Technique#FULL}, que es
     * lo más revelador de la escala): una tabla que no declara techo
     * queda como estaba. Declararlo es lo que convierte un error de la
     * tabla en una negativa.</p>
     *
     * <p>Se le pasa la clasificación entera y no solo la sensibilidad
     * porque el techo también puede ser puntual: el modelo dice que lo
     * genérico va por nivel de sensibilidad y lo particular por clase, y
     * eso vale igual para el techo que para la regla.</p>
     */
    default Technique ceilingFor(Classification classification, String trustLevel) {
        return Technique.FULL;
    }

    /**
     * EN QUE FORMA PUEDE APARECER ESTE DATO EN UN REGISTRO, una traza o
     * un mensaje de error.
     *
     * <p>El modelo pide dos cosas con un dato clasificado que entra, y
     * esta es la primera: <b>tratarlo como sensible desde que llega</b>,
     * fuera de registros, de trazas y de mensajes de error. No depende
     * de la forma en que vino ni de a dónde va —vale mientras el dato
     * exista en el proceso— y por eso no lleva nivel de confianza: un
     * registro no tiene destinatario.</p>
     *
     * <p>De omisión, {@link Technique#REDACTED}: no aparece. Una
     * organización que necesite poder seguir un mismo dato entre dos
     * líneas de registro puede devolver {@link Technique#HASHED} con
     * sal de sistema, y eso ya es una decisión que se toma una vez y en
     * un solo lugar en vez de en cada punto donde se escribe una línea.</p>
     */
    default TechniqueSpec forLogging(Classification classification) {
        return TechniqueSpec.of(Technique.REDACTED);
    }
}
