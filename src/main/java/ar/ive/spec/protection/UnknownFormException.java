package ar.ive.spec.protection;

/**
 * No se sabe en qué forma llegó el valor, y para darle a este
 * destinatario lo que le toca habría que saberlo.
 *
 * <p>Pasa cuando el dato viene de un sistema que no usa IVE: no hay
 * tabla compartida, así que la forma no se puede determinar, y un token
 * que conserva el formato del original —lo habitual con tarjetas, para
 * no romper los sistemas que ya existen— es indistinguible del valor
 * real por inspección: mismo largo, mismo dígito verificador.</p>
 *
 * <p>Por eso la librería no adivina. La regla del modelo es que
 * <b>adivinar de más es aceptable y adivinar de menos no</b>: suponer
 * que el valor está en claro sería lo segundo —tokenizaría un valor que
 * ya era un token, hashearía un token creyendo que hashea el dato— y lo
 * que sale de ahí no es lo que quien recibe cree que es.</p>
 *
 * <p>Lo que sí se puede dar sin saber la forma es lo que no mira el
 * dato: redactado y omitido. Eso no se niega.</p>
 *
 * <p>Se arregla del lado de la integración: o el valor se lleva a una
 * forma conocida cuando entra al sistema —que es lo que hace el conversor
 * de persistencia con todo lo que se guarda—, o ese destinatario no
 * puede recibir ese dato de esa fuente.</p>
 */
public class UnknownFormException extends ProtectionException {

    private static final long serialVersionUID = 1L;

    public UnknownFormException(Classification classification,
                                Technique wanted,
                                String trustLevel) {
        super("Este valor llegó de una fuente que no declara en qué forma lo manda, y para "
                        + forWhom(trustLevel) + " hace falta " + wanted
                        + ", que necesita el valor real. El dato es " + classification
                        + ". No se supone que está en claro: si ya viniera protegido,"
                        + " lo que saldría de acá no sería el dato.",
                classification, wanted, trustLevel);
    }
}
