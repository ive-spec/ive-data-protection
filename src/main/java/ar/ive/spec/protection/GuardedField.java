package ar.ive.spec.protection;

import java.util.List;
import java.util.Objects;

/**
 * A CLASSIFIED VALUE INSIDE AN INPUT, and how to reach it.
 *
 * <p>{@code path} says where it is, one step per property. A step that
 * ends in {@code []} is a list: EVERY element is visited. A path whose LAST
 * step is a list removes the whole list: its elements are the datum.</p>
 *
 * <p>The generated code builds these from the spec; the library walks them
 * ({@link AcceptedInput#filter}).</p>
 */
public record GuardedField(List<String> path, Classification classification) {

    public GuardedField {
        path = List.copyOf(Objects.requireNonNull(path, "path"));
        Objects.requireNonNull(classification, "classification");
    }
}
