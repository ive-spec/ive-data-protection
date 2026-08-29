# ive-data-protection

Dado un valor, **qué es** ese dato y **quién lo va a recibir**, devuelve el
valor en la forma que corresponde. La decisión sale de una **tabla** que es
propia de cada organización; esta librería la evalúa y la aplica.

`ar.ive.spec:ive-data-protection`, Java 21, sin dependencias de runtime.

## Cómo se construye

`JAVA_HOME` en esta máquina apunta a un JDK 8, así que Maven corre sobre Java 8
y falla con *invalid flag: --release*. Hay que apuntarlo al 21:

```
JAVA_HOME="C:\Program Files\Java\jdk-21" mvn test
```

## Por qué es una librería y no código generado

La técnica puede depender de quién invoca, y eso se resuelve en cada llamada.
Generar la decisión la fijaría al momento de generar, que es justamente cuando
no se sabe. Es el mismo criterio que el motor que ejecuta un Flow.

Es **por lenguaje, no por framework**: acá no hay Spring ni Jackson. Lo que
varía por framework es cómo se engancha —en uno puede ser el serializador, en
otro un interceptor— y eso va en otro artefacto.

## Qué sabe y qué no

**No lee especificaciones ni catálogos.** Qué significa `cardholderData`, qué
sensibilidad tiene y de qué norma sale la obligación es cosa del catálogo de
cada organización, y lo resuelve el generador. Lo que llega en la llamada son
nombres de clase y un techo de sensibilidad ya calculado.

**No recorre objetos.** Una librería genérica no conoce las formas del dominio.
El que las conoce es el generador, que las sacó de la especificación: la
plantilla desciende por el grafo y emite una llamada por cada valor sensible.
Esta librería ve **un valor**, nunca un objeto de dominio.

**No decide sola qué es más protector que qué en un caso concreto.** La escala de
técnicas sí está ordenada, y por eso puede comparar contra un techo; pero cuál es
el techo, y qué nivel de confianza es "poco", lo declara la organización.

**No resuelve el nivel de confianza.** Le llega como un valor más. `TrustResolver`
vive acá para que el contrato sea uno solo —si cada paquete de plantillas
inventara el suyo, un sistema tendría que implementar uno por tecnología— pero
quien la llama es el código generado.

## La forma de la llamada

Una por cada valor sensible, emitida en el servicio del backend generado
(`{Grupo}ServiceBase.java`, que se regenera siempre), con:

- el valor;
- **el tipo que hay que devolver, y es obligatorio** — la forma cambia el tipo:
  un número de tarjeta puede salir como `String` tokenizado o como `byte[]`
  cifrado, y una fecha de nacimiento generalizada no es una fecha. Quien no
  quiera comprometerse con un tipo lo dice con `Object.class`, que es una
  respuesta; omitirlo no lo era;
- la clasificación, con su techo de sensibilidad;
- el nivel de confianza de quien recibe.

## No es una conversión inversa

El valor casi nunca está en claro. Uno que llega de otro sistema puede venir ya
tokenizado; uno que sale de la base puede venir cifrado. Llevarlo a la forma que
corresponde es **deshacer lo que tenga puesto y volver a hacer lo que haga
falta**, con el valor real como punto de paso, no como destino.

Y no es simétrico: **hay técnicas que no tienen vuelta**. De un hash no se
recupera el valor real, y de un enmascarado o una generalización tampoco. Ahí la
librería **se niega** — `IrreversibleTechniqueException` — en vez de devolver
algo que no es el dato.

## Falla cerrado, y la ausencia no es una decisión

Si no puede aplicar lo que la tabla decidió, no devuelve el valor sin proteger.
Y **una regla sola**, sin excepciones: nada que falte se lee como permiso. Que
no haya una implementación no quiere decir "entonces protegé menos"; que la
tabla no conteste no quiere decir "entonces mostralo entero"; que un parámetro
esté mal escrito no quiere decir "entonces usá el que te parezca" —aunque el que
parezca sea el más protector: si nadie se entera, esa fila no se arregla nunca—.

Lo único que sí decide es lo que alguien declaró: la tabla, o el que construye
la librería. Por eso no cifrar en reposo se dice con `withoutEncryptionAtRest()`
en vez de deducirse de que falte el gestor de claves, y por eso un conjunto
vacío de niveles de confianza es una respuesta válida y un `null` no lo es.

| Excepción | Qué pasó | Quién lo arregla |
| :--- | :--- | :--- |
| `IrreversibleTechniqueException` | La tabla pide algo imposible por la forma en que el dato está guardado | Quien escribió la tabla |
| `UnsupportedTechniqueSpecException` | La tabla pide algo que no se puede expresar: una regla de generalización que la librería no conoce, un parámetro que falta, o un resultado que no entra en el tipo de destino | Quien escribió la tabla |
| `AboveCeilingException` | La regla que resolvió el caso revela más de lo que el techo de la propia tabla admite: la tabla se contradice | Quien escribió la tabla |
| `UnknownFormException` | El valor vino de una fuente que no declara en qué forma lo manda, y lo que hay que darle a este destinatario necesita el valor real | Quien integró esa fuente |
| `MissingImplementationException` | Falta implementar `TokenService`, `Generalizer` o `KeyProvider` | Quien opera el sistema |

Una excepción por técnica no aportaría nada: quien llama es código generado y no
puede hacer nada distinto según cuál sea. Estas dos separan dos problemas que se
arreglan en manos distintas. En los dos casos el mensaje nombra la técnica, la
clasificación y hacia dónde iba el valor — sin eso queda un stack trace del que
no se puede volver a la especificación.

## A dónde va el valor: lo dice el sitio, no un parámetro

Hay dos bordes, y el destino no es un dato que alguien pueda equivocar al
llamar: es **cuál de los métodos se llama**, y cada uno lo llama un sitio
distinto del código generado.

| Método | Quién lo llama | Nivel de confianza |
| :--- | :--- | :--- |
| `toStorage` / `fromStorage` | El conversor de persistencia (`AttributeConverter` en JPA) | No hay: no hay destinatario |
| `toRecipient` | El servicio, justo antes de devolver | Sí, resuelto en esa llamada |

`toRecipient` **no necesita que le digan en qué forma está el valor**: si viene
de la base, la forma sale de la misma regla que decidió cómo guardarlo, y así no
hay dos fuentes que puedan desincronizarse. Para un valor que llega ya protegido
desde otro sistema —un token de un tercero— hay una sobrecarga que lo recibe
explícito.

Con `OMITTED` devuelve `null`: que el campo no aparezca no es un valor que se
pueda devolver, y lo resuelve el serializador de cada framework.

## La forma de guardado

La regla es una: **la forma de guardado tiene que poder llegar a la salida más
exigente de todas las que usan el dato**. De ahí salen tres casos y no hay un
cuarto:

- Si todos los niveles reciben **exactamente la misma forma** —la misma técnica
  con los mismos parámetros—, se guarda esa: es la más cerrada que sigue
  sirviendo a todos. Es el caso de la contraseña.
- Si las formas difieren, se guarda el valor real: es lo único desde donde se
  pueden producir todas.
- Redactado y omitido no miran el dato, así que no cuentan para decidir.

Un token cuenta como forma cerrada válida aunque tenga vuelta: si todos reciben
el mismo token, guardar el token alcanza.

Esta regla **compra una propiedad**: si algún nivel necesita el valor real, la
forma de guardado ya es el valor real. La negativa por falta de vuelta no puede
aparecer por sí sola en una tabla coherente —solo con un valor que llega ya
protegido desde afuera—.

## El techo, que la librería hace cumplir

**La clasificación fija el techo**: la sensibilidad determina cuál es la técnica
más reveladora admisible, y la regla elige dentro de ese margen. Una tabla que le
devuelva valor completo a un destinatario de poca confianza sobre un dato
restringido no está tomando una decisión legítima: está mal escrita.

La librería **no puede deducir** ese techo —no sabe qué nivel de confianza es
"poco" para una organización, porque los niveles no tienen orden entre sí— pero
**sí lo hace cumplir** si se lo declaran, con `DecisionTable.ceilingFor`. Es la
misma decisión dicha dos veces, y ahí está su valor: si la regla puntual pasa el
techo, la tabla se contradice a sí misma, y eso ya no lo puede ver nadie más —
desde que la exposición salió del modelo no hay nada declarado en la propiedad
que el generador pueda contrastar—. De omisión no hay techo: una tabla que no lo
declara queda como estaba.

Se comprueba en **toda** consulta a la tabla, no solo en la salida: si no, una
forma de guardado podría quedar fijada por una regla que el techo no admite, y
eso se descubriría con el dato ya escrito.

## Cuando el otro lado no usa IVE

No hay tabla compartida, así que **la forma en que llegó el valor no se puede
determinar**: un token que conserva el formato del original es indistinguible del
valor real por inspección. Para eso está `toRecipientOfUnknownForm`, que no
supone nada. Lo que no mira el dato —redactado, omitido— se da igual; cualquier
cosa que necesite el valor real se niega.

Es la regla del modelo: **adivinar de más es aceptable, adivinar de menos no**.
Suponer que el valor está en claro sería lo segundo — tokenizaría un valor que ya
era un token.

## La entrada: tratarlo como sensible desde que llega

Con un dato clasificado que entra hay dos cosas que hacer, y la exposición no es
ninguna de las dos: llevarlo a la forma en que se guarda (`toStorage`) y
**tratarlo como sensible mientras exista en el proceso** — fuera de registros, de
trazas y de mensajes de error. Para lo segundo está `forLogging`, que no lleva
nivel de confianza porque un registro no tiene destinatario.

De omisión el dato no aparece. Una organización que necesite seguir un mismo dato
entre dos líneas de registro puede devolver un hash con sal de sistema desde
`DecisionTable.forLogging`, y esa decisión queda en un solo lugar en vez de en
cada punto donde se escribe una línea.

**La otra mitad no es de esta librería, y ya está hecha del lado del generador**:
toda clase de modelo de Java sale con un `toString()` que **omite** los campos
clasificados y con un `redacted()` que devuelve **una copia del mismo tipo** con
esos campos en null —que es exactamente `REDACTED`: "el campo, sin valor"—.
Ninguna de las dos cosas necesita esta librería: omitir y anular no resuelven
ninguna tabla ni conocen ningún `trustLevel`, y un modelo que dependiera de un
artefacto de runtime para poder imprimirse sería un mal negocio.

Así que `forLogging` es la **salida deliberada**, no el camino por omisión: está
para quien necesite en el registro algo más que un nulo —un hash con sal de
sistema, para poder seguir un mismo dato entre dos líneas— y quiera esa decisión
en un solo lugar.

Falta que las trazas y los mensajes de error pasen por ahí, como ya pasa el
`toString`.

## La precedencia, escrita una sola vez

`PrecedenceTable` es una `DecisionTable` armada con reglas que aplica la
precedencia del modelo. Existe porque **la precedencia es una regla de seguridad,
no una comodidad**: si cada organización la implementa a mano, cada una se puede
equivocar distinto, y equivocarse ahí expone un dato de más sin que nada avise.

Tres ejes, de más particular a más genérico:

1. **Por clase** — `cardholderData` es restringido, pero qué se puede mostrar de
   una tarjeta lo dice PCI DSS.
2. **Por cumplimiento** — "todo lo que caiga bajo `gdpr-art9` sale enmascarado",
   sin enumerar qué clases lo declaran hoy.
3. **Por sensibilidad** — la regla de fondo, la que hace que un dato nuevo esté
   protegido desde el día uno sin que nadie escriba una regla para él.

Dentro de un eje, una regla para un nivel puntual le gana a una que vale para
todos; el eje de la clasificación manda sobre el del nivel, porque lo que el
modelo llama particular es la clase.

**"Para todos los niveles" no incluye al invocador desconocido.** Un Intent sin
`trustLevel` "no tiene ninguna protección por nivel de confianza aplicada, y no
hay ningún valor por defecto implícito": `ANY_LEVEL` habla de los niveles que la
organización declaró, y quien llama sin que se sepa quién es no es uno de ellos
—es el que menos se conoce—. Su regla se escribe con `UNKNOWN_CALLER`; si no
hay ninguna, la tabla no contesta y la librería se niega.

**Cuando un dato tiene varias clases y las dos tienen regla, gana la más
protectora.** No hay forma de que exponer de más sea la respuesta correcta a una
ambigüedad, y elegir por orden de declaración haría que mover una línea del
catálogo cambiara lo que se ve.

Los niveles de confianza salen de las propias reglas: que `trustLevels()` quede
completa no puede depender de que alguien se acuerde de escribirla dos veces —si
falta uno, el dato se guarda en una forma desde la que a ese nivel no se lo puede
servir, y eso se descubre en producción.

No lee ningún archivo, y eso no cambia: es **dónde poner la tabla, no de dónde
sacarla**.

## Qué generaliza y qué no

`GENERALIZED` necesita el parámetro `rule`. La librería resuelve sola cuatro
reglas, que son las que no necesitan saber qué significa el dato: `year`,
`month`, `range:N` y `prefix:N`. Van **primero**: una tabla que escribe `year`
está pidiendo el año, y que eso cambiara de significado según qué implementó
cada sistema haría que la misma tabla protegiera distinto en dos lados.

Cualquier otra regla —un código postal a una región, un diagnóstico a un
capítulo, un cargo a una categoría— es conocimiento del negocio y va al
`Generalizer` de la organización, que se implementa **una vez** y sirve para
todas las reglas propias que su tabla use. Si la tabla pide una y no está, la
llamada se niega con `MissingImplementationException` nombrando la interfaz:
eso es lo que le avisa al sistema que le falta implementarla, en vez de devolver
un dato sin generalizar.

## El cifrado no es una técnica de exposición

La escala tiene siete: valor completo, generalización, enmascarado, token, hash,
redactado, omitido. El cifrado no está: es una forma de **guardar**. Por eso
`Requirement.KEYS` existe y hoy no lo pide ninguna técnica.

Pero **guardar sí es asunto de esta librería**, y por eso `toStorage` cifra. No
hay contradicción: ninguna de las siete describe lo que ve alguien de un valor
cifrado, porque nadie lo ve cifrado —se descifra al leer—. Es la otra mitad de
la misma decisión: si la forma de guardado es el valor real, la única
alternativa a cifrarlo es dejarlo en claro, y eso no es una alternativa.

Quien decide que este sistema puede cifrar es **quien le pasa un `KeyProvider`**;
desde qué sensibilidad, `encryptAtRestFrom` (por defecto `CONFIDENTIAL`: cifrar
lo público no protege nada y rompe las consultas por ese campo).

**La ausencia no es una decisión.** Que no haya gestor de claves no quiere decir
"entonces guardalo en claro" — es lo mismo que tokenizar sin servicio de
tokenización, y se niega igual, con `MissingImplementationException`. No cifrar
en reposo puede estar bien —cifrado de disco, de tablespace, una base que ya
cifra— pero **hay que decirlo**: `withoutEncryptionAtRest()`. Así queda
constancia de que alguien lo decidió, en vez de que lo decida un hueco de
despliegue. Declarar el piso sin pasar las claves, o declarar las dos cosas a la
vez, no construye.

Se cifra **solo lo que se guarda entero**. Un hash no —no hay nada que
recuperar, y cifrarlo lo dejaría inservible hasta para comparar— y un token
tampoco —afuera del servicio de tokenización no dice nada—.

**El tipo de la columna no puede depender de una decisión de runtime**, así que
lo elige quien llama y no esta librería: si dependiera, una base habría que
re-migrarla porque alguien agregó un gestor de claves, y dos despliegues de la
misma especificación tendrían esquemas distintos. Quien llama —el conversor de
persistencia— no sabe si se va a cifrar y no tiene por qué saberlo: pide el tipo
que tiene la columna. Con `String.class` un valor cifrado vuelve en Base64; con
`byte[].class`, en crudo. `fromStorage` acepta las dos.

## Estado

Hecho y probado contra el modelo —`02-structure.md`, sección "Clasificación de
datos"—, no contra los ejemplos del repo: el núcleo, la conversión en las dos
direcciones, la forma de guardado, el cifrado en reposo, el techo, la forma
desconocida, la protección en registros, la sal en sus dos alcances, y la
precedencia con sus tres ejes. **80 tests.**

Falta, y no es deuda de acá sino lo que sigue: el enganche por framework —el
`AttributeConverter` de JPA, la resolución del `trustLevel` del lado del
servicio, y que `toString`, trazas y mensajes de error pasen por `forLogging`— y
del lado del generador, la plantilla que emite la llamada.
