package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The self-role rule itself, without a process around it: what a token's {@code groups} is built
 * from.
 *
 * <p>A plain unit test rather than a {@code @QuarkusTest}, because one case here is unreachable
 * over HTTP on purpose — no source of roles can produce a duplicate self-role, and the
 * deduplication that would absorb it still has to be true.
 */
public class ClientRolesTest {

  @Test
  public void aMintedTokenCarriesTheClientsRolesThenItsOwnSelfRole() {
    assertEquals(
        List.of("qits:system", "qits:admin", "clients/prod-qits-projects"),
        List.copyOf(ClientRoles.mintedFor(client("prod-qits-projects", "qits:system", "qits:admin"))));
  }

  @Test
  public void aClientWithNoRolesStillNamesItself() {
    assertEquals(List.of("clients/dyn-ci-run-4711-abc"), List.copyOf(ClientRoles.mintedFor(client("dyn-ci-run-4711-abc"))));
  }

  @Test
  public void theSelfRoleAppearsOnceHoweverTheRolesWereAssembled() {
    assertEquals(
        List.of("qits:system", "clients/prod-qits-projects"),
        List.copyOf(
            ClientRoles.mintedFor(
                client("prod-qits-projects", "qits:system", "clients/prod-qits-projects"))),
        "a claim's shape must not depend on how its input was built");
  }

  private static IdpClient client(String clientId, String... roles) {
    return new IdpClient(clientId, null, List.of(roles), Map.of(), null, null);
  }
}
