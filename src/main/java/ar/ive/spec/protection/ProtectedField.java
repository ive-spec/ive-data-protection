package ar.ive.spec.protection;

import java.util.List;
import java.util.Objects;

/**
 * A CLASSIFIED VALUE INSIDE AN OUTPUT, and how to reach it.
 *
 * <p>{@code path} says where it is, one step per property. A step that
 * ends in {@code []} is a list: EVERY element is visited, not one. A step
 * that is only {@code []} is the node itself being a list.</p>
 *
 * <p>{@code type} is the type of the field the value goes into (what
 * {@link DataProtection#toRecipient} converts to), and
 * {@code required} says whether the schema the receiver validates demands
 * the field: a required field cannot be omitted, so there the only way
 * out is covering it.</p>
 *
 * <p>The generated code builds these from the spec; the library walks
 * them ({@link ProtectedOutput#protect}).</p>
 */
public record ProtectedField(List<String> path, Classification classification, Class<?> type,
                             boolean required) {

    public ProtectedField {
        path = List.copyOf(Objects.requireNonNull(path, "path"));
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(type, "type");
    }
}
