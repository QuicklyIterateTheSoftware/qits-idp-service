package eu.wohlben.qits.idp.events;

import eu.wohlben.qits.eventstream.QitsEvent;
import java.time.Instant;
import java.util.UUID;

/**
 * An account is gone (qits-1977): {@code Users.delete} removed the row and everything keyed to it,
 * in the transaction that publishes this. {@code userId} is the {@code sub} of every token the
 * person was ever minted, so it is what a consumer revoking that person's access keys on; {@code
 * username} travels beside it for the log and for a consumer that only ever saw the name.
 *
 * <p>{@code username}, never {@code name}: {@link QitsEvent#name()} defaults to the signature — the
 * simple class name, which is what a subscriber selects on — and a record component called {@code
 * name} would shadow it and put the person's name on the wire where the event's belongs.
 *
 * <p>A record the bus serializes must also be named in {@code EventWireReflection}, or a native
 * binary publishes it as {@code {}} while the JVM suite stays green.
 */
public record UserDeleted(UUID eventId, UUID userId, String username, Instant occurredAt)
    implements QitsEvent {

  public UserDeleted {
    if (eventId == null) {
      eventId = UUID.randomUUID();
    }
  }

  public UserDeleted(UUID userId, String username, Instant occurredAt) {
    this(null, userId, username, occurredAt);
  }
}
