package ar.ive.spec.protection;

/**
 * HACE FALTA ALGO QUE ESTE SISTEMA NO IMPLEMENTO.
 *
 * <p>Tokenizar necesita el servicio de tokenización; generalizar con una
 * regla del dominio, el generalizador; guardar un dato entero, el gestor
 * de claves para dejarlo cifrado en reposo. Son interfaces que implementa
 * cada organización, y si la que hace falta no está, esta librería <b>no
 * devuelve el valor sin proteger: se niega</b>.</p>
 *
 * <p><b>LA AUSENCIA NUNCA ES UNA DECISION.</b> Que no esté una
 * implementación no se lee como "entonces no lo protejas": se lee como
 * que falta. Lo que sí es una decisión es declararla —y para no cifrar
 * en reposo hay una forma explícita de decirlo, que deja constancia de
 * quién lo decidió.</p>
 *
 * <p>Es un hueco de despliegue, no de diseño, y se arregla del lado de
 * quien opera el sistema. Y se puede anticipar: el generador sabe, al
 * generar, qué técnicas declara la especificación, así que qué interfaz
 * hace falta implementar deja de ser un error que aparece en producción
 * y pasa a ser un pendiente con nombre propio.</p>
 */
public class MissingImplementationException extends ProtectionException {

    private static final long serialVersionUID = 1L;

    private final Technique.Requirement requirement;

    public MissingImplementationException(Classification classification,
                                          Technique technique,
                                          String trustLevel) {
        this(classification, technique, trustLevel, technique.requirement());
    }

    /**
     * Con el requisito dicho aparte, para lo que hace falta sin ser parte
     * de la escala: el CIFRADO EN REPOSO no es una de las siete técnicas
     * —nadie ve un valor cifrado— pero necesita el gestor de claves
     * igual, y que falte se niega como cualquier otra implementación
     * ausente.
     */
    public MissingImplementationException(Classification classification,
                                          Technique technique,
                                          String trustLevel,
                                          Technique.Requirement requirement) {
        super(message(classification, technique, trustLevel, requirement),
                classification, technique, trustLevel);
        this.requirement = requirement;
    }

    /** Qué implementación falta. */
    public Technique.Requirement requirement() {
        return requirement;
    }

    private static String message(Classification classification,
                                  Technique technique,
                                  String trustLevel,
                                  Technique.Requirement requirement) {
        String queria = requirement == Technique.Requirement.KEYS
                ? "Este dato se guarda entero y tiene que quedar cifrado en reposo"
                : "Para " + forWhom(trustLevel) + " este dato tiene que salir con " + technique;
        return queria + ", que necesita " + describe(requirement)
                + ", y este sistema no lo implementó. El dato es " + classification
                + ". No se devuelve el valor sin proteger.";
    }

    private static String describe(Technique.Requirement requirement) {
        return switch (requirement) {
            case TOKENS -> "el servicio de tokenización (" + TokenService.class.getName() + ")";
            case KEYS -> "el gestor de claves (" + KeyProvider.class.getName() + ")";
            case RULES -> "el generalizador del dominio (" + Generalizer.class.getName() + ")";
            case NONE -> "algo que la librería no tiene";
        };
    }
}
