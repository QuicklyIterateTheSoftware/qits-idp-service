package eu.wohlben.qits.idp.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.error.OAuthException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@link BasicCaller#requireAnyRole}, the check a read route uses to accept {@code qits:agent} beside
 * its old role. Plain unit tests: the method reads only the caller's roles.
 */
public class BasicCallerTest {

  private final BasicCaller caller = new BasicCaller();

  @Test
  public void aReadAcceptsThePlatformRoleOrTheAgentRole() {
    IdpClient service = client("qits:system", BasicCaller.PLATFORM_SYSTEM);
    IdpClient agent = client(BasicCaller.AGENT);

    assertSame(
        service, caller.requireAnyRole(service, BasicCaller.PLATFORM_SYSTEM, BasicCaller.AGENT));
    assertSame(agent, caller.requireAnyRole(agent, BasicCaller.PLATFORM_SYSTEM, BasicCaller.AGENT));
  }

  @Test
  public void aCallerWithNeitherRoleIsRefused() {
    OAuthException refused =
        assertThrows(
            OAuthException.class,
            () ->
                caller.requireAnyRole(
                    client("qits:admin"), BasicCaller.PLATFORM_SYSTEM, BasicCaller.AGENT));

    assertEquals(403, refused.statusCode());
    assertEquals("access_denied", refused.error());
  }

  @Test
  public void aWriteStillRequiresThePlatformRole() {
    // requireRole is what the write routes call, and it does not know the agent role.
    assertThrows(
        OAuthException.class,
        () -> caller.requireRole(client(BasicCaller.AGENT), BasicCaller.PLATFORM_SYSTEM));
  }

  private static IdpClient client(String... roles) {
    return new IdpClient("some-client", null, List.of(roles), Map.of(), null, null);
  }
}
