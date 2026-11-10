package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.wohlben.qits.eventstream.control.EventEnvelope;
import eu.wohlben.qits.idp.events.EventWireReflection;
import eu.wohlben.qits.idp.events.UserDeleted;
import io.quarkus.runtime.annotations.RegisterForReflection;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@link EventWireReflection} is what lets a native binary serialize {@link UserDeleted} and the
 * envelope around it (qits-1977). On a JVM every class reflects whether registered or not, so this
 * cannot prove the binary publishes; what it can pin is that the list still names every type that
 * crosses the wire and that the mix-in's string still resolves — so the next event record joins it
 * in the commit that adds it.
 */
class UserDeletedReflectionTest {

  private static final String MIXIN =
      "eu.wohlben.qits.eventstream.control.CanonicalJson$QitsEventMixin";

  @Test
  void theRegisteredTargetsAreTheTypesThatCrossTheWire() throws Exception {
    RegisterForReflection registration =
        EventWireReflection.class.getAnnotation(RegisterForReflection.class);
    assertNotNull(registration, "the annotation IS the class");
    assertEquals(Set.of(UserDeleted.class, EventEnvelope.class), Set.of(registration.targets()));
    assertEquals(Set.of(MIXIN), Set.of(registration.classNames()));
    Class.forName(MIXIN, false, getClass().getClassLoader());
  }
}
