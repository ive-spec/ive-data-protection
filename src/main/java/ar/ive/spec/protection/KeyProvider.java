package ar.ive.spec.protection;

/**
 * CIFRAR Y DESCIFRAR. La implementa cada organización, contra su gestor
 * de claves.
 *
 * <p>Va aparte de las otras dos y no en una interfaz sola a propósito:
 * quien solo usa enmascarado y omisión no implementa ninguna, y quien
 * agrega tokenización implementa esa y nada más. Con una interfaz única
 * habría que escribir métodos que nunca se llaman.</p>
 *
 * <p>El cifrado no es una técnica de exposición: es una forma de
 * GUARDAR. Esto hace falta para deshacer lo que la base tiene puesto
 * antes de llevar el valor a la forma que corresponde a quien lo recibe,
 * y para dejarlo cifrado al guardarlo.</p>
 *
 * <p>Las claves no salen de acá: quien implemente resuelve contra su
 * gestor, y esta librería nunca las ve.</p>
 */
public interface KeyProvider {

    /** El valor, cifrado. */
    byte[] encrypt(byte[] plain, Classification classification);

    /** El valor real, a partir de lo cifrado. */
    byte[] decrypt(byte[] encrypted, Classification classification);
}
