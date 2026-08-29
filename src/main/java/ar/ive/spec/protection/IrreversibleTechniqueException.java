package ar.ive.spec.protection;

/**
 * SE PIDIO DESHACER ALGO QUE NO TIENE VUELTA.
 *
 * <p>De un hash no se vuelve al valor real, y de un enmascarado ni de
 * una generalización tampoco: lo que se tapó no está en ningún lado. Si
 * un dato está guardado en una de esas formas y la salida necesita otra,
 * <b>alguien pidió algo imposible</b>.</p>
 *
 * <p>No es un problema de ejecución: es un error de diseño de la tabla,
 * y lo arregla quien la escribió. La regla que lo evita está dicha desde
 * el principio — la forma de almacenamiento queda determinada por la
 * salida más exigente de todas las que usan ese dato: guardar cifrado no
 * cierra ninguna puerta, guardar hasheado cierra casi todas.</p>
 */
public class IrreversibleTechniqueException extends ProtectionException {

    private static final long serialVersionUID = 1L;

    public IrreversibleTechniqueException(Classification classification,
                                          Technique stored,
                                          Technique wanted,
                                          String trustLevel) {
        super("El valor está en forma " + stored + ", que no tiene vuelta, y para "
                        + forWhom(trustLevel) + " hace falta " + wanted
                        + ". El dato es " + classification
                        + ". La forma en que se guarda tiene que poder llegar a la salida más exigente"
                        + " de todas las que usan este dato.",
                classification, wanted, trustLevel);
    }
}
