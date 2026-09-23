package ar.ive.spec.protection;

/**
 * LO QUE CORRESPONDE CUANDO LA TABLA NO ESCRIBIÓ NADA PARA ESE PAR.
 *
 * <p>Es una matriz de dos entradas ORDENADAS —la sensibilidad del dato y
 * el clearance de quien lo pide— y ésa es la razón por la que se puede
 * escribir de una vez para todos: son los dos únicos ejes del modelo que
 * tienen orden. Las clases de datos no lo tienen (cada organización arma
 * la suya) y por eso nunca va a haber una omisión por clase.</p>
 *
 * <h2>Por qué esto existe, si la librería no toma decisiones</h2>
 * <p>Hasta acá no había ninguna omisión, y eso tenía un costo concreto:
 * <b>un despliegue tenía que escribir la tabla entera antes de que el
 * sistema arrancara</b> —una fila por clasificación y por nivel, y la que
 * falta impide arrancar—. Con esto arranca PROTEGIENDO, y se escriben
 * sólo las excepciones.</p>
 *
 * <p>Y sigue sin tomar la decisión que la librería evita, por dos
 * propiedades que esta matriz tiene que conservar:</p>
 * <ol>
 *   <li><b>Falla cerrado.</b> Cuanto más baja la confianza, menos revela;
 *       al invocador desconocido no le muestra nada.</li>
 *   <li><b>NUNCA ENTREGA ENTERO UN DATO RESTRINGIDO.</b> Ni el clearance
 *       más alto: para eso hay que escribir la fila. Así la omisión no
 *       regala nunca lo más caro, y quien decide entregarlo lo decide.</li>
 * </ol>
 *
 * <p>UN SISTEMA PUEDE PONER LA SUYA. Esto es un piso, no un veredicto:
 * {@code DataProtection.Builder.baseline(...)} la reemplaza entera.</p>
 */
@FunctionalInterface
public interface Baseline {

    /**
     * La forma que corresponde por omisión, o {@code null} si esta matriz
     * tampoco cubre el par —y ahí la librería se niega, como siempre—.
     *
     * @param sensitivity el techo de sensibilidad del dato
     * @param clearance   cuánta confianza tiene quien pide, o {@code null}
     *                    para el invocador desconocido y para un nivel
     *                    declarado sin cantidad
     */
    TechniqueSpec forPair(Sensitivity sensitivity, Integer clearance);

    /**
     * LA MATRIZ QUE TRAE LA LIBRERÍA.
     *
     * <pre>
     *                  c1         c2         c3+       desconocido
     *   RESTRICTED   REDACTED   REDACTED   MASKED       REDACTED
     *   CONFIDENTIAL REDACTED   MASKED     FULL         REDACTED
     *   INTERNAL     MASKED     FULL       FULL         REDACTED
     *   PUBLIC       FULL       FULL       FULL         FULL
     * </pre>
     *
     * <p>Lo público se muestra siempre, incluso a quien no se identificó:
     * es lo que "público" quiere decir, y taparlo no protege a nadie.</p>
     *
     * <p>UN NIVEL SIN CLEARANCE NO ENTRA. Se lo trata como al desconocido
     * —lo más protector— porque no hay cantidad con la cual ubicarlo, y
     * suponerle una sería inventarla.</p>
     */
    Baseline CONSERVATIVE = (sensitivity, clearance) -> {
        if (sensitivity == null) {
            return null;
        }
        if (sensitivity == Sensitivity.PUBLIC) {
            return TechniqueSpec.of(Technique.FULL);
        }
        if (clearance == null) {
            // El desconocido, y el declarado sin cantidad: no ve nada.
            return TechniqueSpec.of(Technique.REDACTED);
        }
        return switch (sensitivity) {
            // LO RESTRINGIDO ENTERO NO SALE DE ACÁ, NUNCA. Ésa es la
            // propiedad que hace que esta omisión sea aceptable.
            case RESTRICTED -> clearance >= 3
                    ? TechniqueSpec.of(Technique.MASKED)
                    : TechniqueSpec.of(Technique.REDACTED);
            case CONFIDENTIAL -> clearance >= 3
                    ? TechniqueSpec.of(Technique.FULL)
                    : clearance >= 2
                            ? TechniqueSpec.of(Technique.MASKED)
                            : TechniqueSpec.of(Technique.REDACTED);
            case INTERNAL -> clearance >= 2
                    ? TechniqueSpec.of(Technique.FULL)
                    : TechniqueSpec.of(Technique.MASKED);
            default -> TechniqueSpec.of(Technique.FULL);
        };
    };

    /**
     * NINGUNA OMISIÓN: la tabla contesta todo o la librería se niega.
     *
     * <p>Es como se comportaba antes de que la matriz existiera, y sigue
     * disponible para quien quiera que nada se resuelva sin una fila
     * escrita.</p>
     */
    Baseline NONE = (sensitivity, clearance) -> null;
}
