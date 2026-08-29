package ar.ive.spec.protection;

/**
 * CONVERTIR UN VALOR EN SU SUSTITUTO ESTABLE, Y VOLVER. La implementa
 * cada organización, contra su servicio.
 *
 * <p><b>El token tiene que ser el mismo siempre.</b> Si cada llamada
 * devolviera uno distinto, quien lo recibe no podría correlacionar nada
 * y el token no serviría para nada. Eso no es algo que esta librería
 * pueda garantizar: necesita el mismo mapeo estable que tokenizar al
 * entrar, y ese mapeo es del servicio.</p>
 *
 * <p>Un token es reversible por quien tenga el servicio, así que
 * <b>sigue siendo un dato sensible</b>: no es anónimo, y se protege
 * igual que el valor real — fuera de registros, fuera de mensajes de
 * error.</p>
 */
public interface TokenService {

    /** El sustituto estable de este valor. */
    String tokenize(String value, Classification classification);

    /** El valor real que le corresponde a ese token. */
    String detokenize(String token, Classification classification);
}
