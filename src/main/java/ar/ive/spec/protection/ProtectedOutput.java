package ar.ive.spec.protection;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * BRINGS EVERY CLASSIFIED VALUE OF AN OUTPUT TO THE FORM ITS RECIPIENT GETS.
 *
 * <p>The output is a tree of {@link Map}s and {@link List}s (a parsed JSON
 * document, a structured tool result); the {@link ProtectedField}s say
 * where the classified values are. It goes RIGHT BEFORE RETURNING: until
 * then the service works with the real value.</p>
 *
 * <p>IT WORKS ON A COPY. What the service returned may be the very object
 * it keeps -- a cached row, an in-memory record -- and overwriting its
 * fields there would leave the protected value inside the system. That is
 * not a matter of style: it is losing the data.</p>
 *
 * <p>AND THIS IS WHERE {@code required} DECIDES SOMETHING. With
 * {@code OMITTED}, {@link DataProtection#toRecipient} returns null and
 * leaves "the field does not appear" to the serializer of each framework:
 * this is that serializer. An OPTIONAL field that the technique removed is
 * TAKEN OUT -- its absence is exactly what the table asked for --; a
 * REQUIRED one cannot be taken out, because the schema the receiver
 * validates would stop holding, so it stays as null.</p>
 */
public final class ProtectedOutput {

    private ProtectedOutput() {
    }

    /**
     * A protected deep copy of {@code output}.
     *
     * @param output     what the service returned. Not modified.
     * @param fields     where the classified values are.
     * @param protection the organization's {@link DataProtection}.
     * @param trustLevel of whom receives it; {@code null} is the unknown
     *                   caller, and the table has its own row for it.
     */
    public static Object protect(Object output, List<ProtectedField> fields,
                                 DataProtection protection, String trustLevel) {
        if (fields.isEmpty()) {
            return output;
        }
        Object copy = copy(output);
        for (ProtectedField field : fields) {
            visit(copy, field.path(), 0,
                    v -> protection.toRecipient(v, field.type(), field.classification(), trustLevel),
                    field.required());
        }
        return copy;
    }

    /** A mutable deep copy of maps and lists; anything else is kept as is. */
    private static Object copy(Object value) {
        if (value instanceof Map<?, ?> m) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                copy.put(String.valueOf(e.getKey()), copy(e.getValue()));
            }
            return copy;
        }
        if (value instanceof List<?> l) {
            List<Object> copy = new ArrayList<>(l.size());
            for (Object x : l) {
                copy.add(copy(x));
            }
            return copy;
        }
        return value;
    }

    /**
     * Reaches every value the path names and replaces it.
     *
     * <p>WHAT IS NOT THERE IS NOT INVENTED: an optional field the service
     * did not return is not added as null. Its absence is a valid
     * answer.</p>
     */
    @SuppressWarnings("unchecked")
    private static void visit(Object node, List<String> path, int i,
                              UnaryOperator<Object> replace, boolean required) {
        if (i >= path.size()) {
            return;
        }
        String step = path.get(i);
        boolean isList = step.endsWith("[]");
        String name = isList ? step.substring(0, step.length() - 2) : step;
        boolean last = i == path.size() - 1;

        Map<String, Object> container = null;
        Object child;
        if (!name.isEmpty()) {
            if (!(node instanceof Map<?, ?> m) || !m.containsKey(name)) {
                return;
            }
            container = (Map<String, Object>) m;
            child = container.get(name);
        } else {
            child = node;
        }

        if (isList) {
            if (!(child instanceof List<?>)) {
                return;
            }
            List<Object> list = (List<Object>) child;
            for (int k = 0; k < list.size(); k++) {
                // AN ELEMENT OF A LIST IS NOT TAKEN OUT. Removing it would
                // shorten the list, and that is not "this field does not
                // appear": it is saying there are fewer than there are.
                if (last) {
                    list.set(k, replace.apply(list.get(k)));
                } else {
                    visit(list.get(k), path, i + 1, replace, required);
                }
            }
            return;
        }

        if (!last) {
            visit(child, path, i + 1, replace, required);
        } else if (container != null) {
            Object protectedValue = replace.apply(child);
            // TAKEN OUT ONLY IF THE TECHNIQUE TOOK IT OUT, which is why the
            // value before is looked at: a field that ALREADY came as null
            // stays null. "There is no value" and "I will not show it to
            // you" are two different answers, and removing the first would
            // turn it into the second.
            if (child != null && protectedValue == null && !required) {
                container.remove(name);
            } else {
                container.put(name, protectedValue);
            }
        }
    }
}
