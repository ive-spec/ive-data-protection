package ar.ive.spec.protection;

import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * TAKES OUT OF AN INPUT WHAT ITS SENDER HAS NO AUTHORITY TO SET.
 *
 * <p>The input is what the framework built from the request: a bean with
 * getters and setters (a View), or plain maps and lists. Each
 * {@link GuardedField} says where a classified value is. It goes RIGHT
 * AFTER THE INPUT IS VALIDATED and before the service logic: the contract
 * is checked on what came, and the service only sees what it may use. The
 * mirror of {@link ProtectedOutput}, which goes right before answering.</p>
 *
 * <p>WHAT IS NOT ACCEPTED IS REMOVED, as if it had not come -- not
 * rejected. The contract says the field exists; whether this sender may
 * set it is decided here, and every party knows it will not change. In a
 * map the key goes away; in a bean the property becomes null and, when the
 * bean keeps what arrived ({@code arrived()}), it is forgotten there too --
 * otherwise an Update would read it as "came null" and empty the stored
 * value. A null that came is a value as well, so taking it out is reported.
 * The caller gets no error; the removal is reported to {@code onIgnored},
 * so it can be logged.</p>
 *
 * <p>IT CHANGES THE INPUT IN PLACE: it is the object the framework built
 * for this request, and nobody else holds it. Same walker as the Python
 * and TypeScript libraries.</p>
 */
public final class AcceptedInput {

    private AcceptedInput() {
    }

    /**
     * Removes from {@code input} what {@code trustLevel} may not set, and
     * returns it. {@code onIgnored} gets the path of each removed value --
     * never the value --; it may be null.
     */
    public static <T> T filter(T input, List<GuardedField> fields, DataProtection protection,
                               String trustLevel, Consumer<String> onIgnored) {
        if (input == null || fields == null || fields.isEmpty()) {
            return input;
        }
        for (GuardedField field : fields) {
            if (protection.acceptsFrom(field.classification(), trustLevel)) {
                continue;
            }
            if (remove(input, field.path(), 0) && onIgnored != null) {
                onIgnored.accept(String.join(".", field.path()));
            }
        }
        return input;
    }

    /** Removes every value the path names. True if something was there. */
    @SuppressWarnings("unchecked")
    private static boolean remove(Object node, List<String> path, int at) {
        if (node == null || at >= path.size()) {
            return false;
        }
        String step = path.get(at);
        boolean isList = step.endsWith("[]");
        String name = isList ? step.substring(0, step.length() - 2) : step;
        boolean last = at == path.size() - 1;

        Object child;
        if (name.isEmpty()) {
            child = node;
        } else if (node instanceof Map<?, ?> map) {
            if (!map.containsKey(name)) {
                return false;
            }
            child = map.get(name);
        } else {
            PropertyDescriptor property = property(node, name);
            if (property == null || property.getReadMethod() == null) {
                return false;
            }
            child = read(node, property);
        }

        if (last) {
            if (name.isEmpty()) {
                return false;
            }
            if (node instanceof Map<?, ?> map) {
                // The key was there: it came, even with a null -- a null
                // that comes is a value too ("make it empty").
                ((Map<String, Object>) map).remove(name);
                return true;
            }
            Set<String> arrived = arrivedOf(node);
            boolean was = arrived != null ? arrived.contains(name) : child != null;
            write(node, property(node, name), null);
            if (arrived != null) {
                arrived.remove(name);
            }
            return was;
        }
        if (isList) {
            if (!(child instanceof List<?> list)) {
                return false;
            }
            boolean removed = false;
            for (Object element : list) {
                removed = remove(element, path, at + 1) || removed;
            }
            return removed;
        }
        return remove(child, path, at + 1);
    }

    /**
     * What a bean says arrived, or null when it does not keep track. A bean
     * that does exposes {@code Set<String> arrived()} -- the properties the
     * message carried, by bean name, null ones included -- so that "absent"
     * and "null" are not the same value. Asked by name, like a getter: this
     * library does not know the classes it walks.
     */
    @SuppressWarnings("unchecked")
    private static Set<String> arrivedOf(Object bean) {
        try {
            Object found = bean.getClass().getMethod("arrived").invoke(bean);
            return found instanceof Set<?> set ? (Set<String>) set : null;
        } catch (NoSuchMethodException none) {
            return null;
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException("Cannot read what arrived in " + bean.getClass().getName(), e);
        }
    }

    private static PropertyDescriptor property(Object bean, String name) {
        try {
            for (PropertyDescriptor d : Introspector.getBeanInfo(bean.getClass()).getPropertyDescriptors()) {
                if (d.getName().equals(name)) {
                    return d;
                }
            }
            return null;
        } catch (IntrospectionException e) {
            throw new IllegalStateException("Cannot read the properties of " + bean.getClass().getName(), e);
        }
    }

    private static Object read(Object bean, PropertyDescriptor property) {
        try {
            return property.getReadMethod().invoke(bean);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException("Cannot read " + property.getName() + " of " + bean.getClass().getName(), e);
        }
    }

    private static void write(Object bean, PropertyDescriptor property, Object value) {
        if (property == null || property.getWriteMethod() == null) {
            // A read-only property (a record component) cannot be emptied
            // in place: saying so beats leaving the value in without a word.
            throw new IllegalStateException("Cannot empty `" + (property == null ? "?" : property.getName())
                    + "` of " + bean.getClass().getName() + ": it has no setter.");
        }
        try {
            property.getWriteMethod().invoke(bean, value);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException("Cannot write " + property.getName() + " of " + bean.getClass().getName(), e);
        }
    }
}
