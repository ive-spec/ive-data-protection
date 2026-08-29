package ar.ive.spec.protection;

/**
 * La tabla se contradice a sí misma: la regla que resolvió este caso
 * devuelve una técnica que revela más de lo que su propio techo admite.
 *
 * <p>No es un error de forma —la técnica se podría aplicar sin
 * problemas— sino de fondo, y por eso vale una excepción propia: lo que
 * hay que corregir no es un parámetro, es una regla que no debería
 * existir. Se arregla en la misma mano que
 * {@link IrreversibleTechniqueException}, la de quien es dueño de la
 * tabla.</p>
 *
 * <p>Que llegue hasta acá quiere decir que nadie lo vio antes, y no por
 * descuido: desde que la exposición salió del modelo no hay nada
 * declarado en la propiedad que el generador pueda contrastar contra la
 * tabla. Este es el último lugar donde se puede ver.</p>
 */
public class AboveCeilingException extends ProtectionException {

    private static final long serialVersionUID = 1L;

    private final Technique ceiling;

    public AboveCeilingException(Classification classification,
                                 Technique resolved,
                                 Technique ceiling,
                                 String trustLevel) {
        super("La tabla resolvió " + resolved + " para " + forWhom(trustLevel)
                        + ", y su propio techo para este dato es " + ceiling
                        + ", que revela menos. El dato es " + classification
                        + ". No se devuelve el valor: una regla no puede pasar el techo"
                        + " que la misma tabla declara.",
                classification, resolved, trustLevel);
        this.ceiling = ceiling;
    }

    /** Lo más revelador que la tabla admitía para este caso. */
    public Technique ceiling() {
        return ceiling;
    }
}
