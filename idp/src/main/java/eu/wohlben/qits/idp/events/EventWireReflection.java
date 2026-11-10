package eu.wohlben.qits.idp.events;

import eu.wohlben.qits.eventstream.control.EventEnvelope;
import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * What {@code QitsEventBus.publish} binds to JSON here, told to native-image (qits-1977, the same
 * registration qits-system-service and qits-workspaces-service carry for their own events). No code,
 * no bean: the annotation is the entire content.
 *
 * <p>{@code CanonicalJson} builds its own {@code ObjectMapper} by hand, so the build step that
 * decides what needs reflection never sees what it serializes. Left unregistered, the native binary
 * publishes {@link UserDeleted} as {@code {}} and serializes the {@link EventEnvelope} — the PUT body
 * — empty, which qits-events refuses with a 400; the JVM suite stays green throughout. The mix-in is
 * named as a string because it is private: it keeps {@code QitsEvent}'s own accessors, {@code
 * eventId} above all, out of the payload, and Jackson finds its {@code @JsonIgnore}s by reflection.
 *
 * <p>Nothing that READS the bus is here, because this service consumes no event. A new {@code
 * QitsEvent} record in this package joins the list in the commit that adds it.
 */
@RegisterForReflection(
    targets = {UserDeleted.class, EventEnvelope.class},
    classNames = {"eu.wohlben.qits.eventstream.control.CanonicalJson$QitsEventMixin"})
public final class EventWireReflection {

  private EventWireReflection() {}
}
