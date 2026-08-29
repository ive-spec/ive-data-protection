package ar.ive.spec.protection;

/**
 * La tabla pidió algo que la librería no puede hacer: una regla de
 * generalización que no conoce, un parámetro que falta, o una técnica
 * cuyo resultado no entra en el tipo de destino.
 *
 * <p>Es la MISMA MANO que {@link IrreversibleTechniqueException} —quien
 * escribió la tabla— y por eso no es una excepción por técnica, que no
 * aportaría nada. Lo que la separa de aquella es de qué se queja: allá
 * la tabla pide algo imposible por la forma en que el dato está
 * guardado; acá pide algo que está mal escrito o que no se puede
 * expresar.</p>
 */
public class UnsupportedTechniqueSpecException extends ProtectionException {

    private static final long serialVersionUID = 1L;

    public UnsupportedTechniqueSpecException(String what,
                                             Classification classification,
                                             Technique technique,
                                             String trustLevel) {
        super(what + " El dato es " + classification + ", y esto es para "
                        + forWhom(trustLevel) + ". No se devuelve el valor sin proteger.",
                classification, technique, trustLevel);
    }
}
