package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.error.OAuthException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The rule a commission's claims are held to, and the column they survive in.
 *
 * <p>Plain unit tests: this class is static, has no CDI and decides the whole of what a caller may
 * ask for, so the refusals are worth stating one per line rather than through the endpoint. {@code
 * CommissionedClientsTest} is where the same rule is checked as a status code and a minted token.
 */
public class CommissionedClaimsTest {

  private static final String PROJECT = "b03b84b1-1875-4071-9dbf-854550156258";

  @Test
  public void aStatedClaimIsKeptAndTrimmed() {
    Map<String, String> stated =
        CommissionedClaims.stated(Map.of(ClaimNames.PROJECT, "  " + PROJECT + " "));

    assertEquals(Map.of(ClaimNames.PROJECT, PROJECT), stated);
  }

  @Test
  public void statingNothingIsTheOrdinaryCaseAndNoFailure() {
    assertEquals(Map.of(), CommissionedClaims.stated(null));
    assertEquals(Map.of(), CommissionedClaims.stated(Map.of()));
    assertNull(CommissionedClaims.format(Map.of()), "and the column stays null");
    assertNull(CommissionedClaims.format(null));
  }

  @Test
  public void theWildcardIsTheOneValueACommissionMayNotState() {
    OAuthException refused =
        assertThrows(
            OAuthException.class,
            () -> CommissionedClaims.stated(Map.of(ClaimNames.PROJECT, "*")));

    assertEquals("invalid_request", refused.error());
    assertTrue(
        refused.getMessage().contains("narrow"),
        "the caller is told which direction it may go: " + refused.getMessage());
  }

  @Test
  public void theWildcardIsRefusedForEveryName() {
    // agent included: a token belongs to one agent, never to every agent.
    for (String name : ClaimNames.GRANTABLE) {
      OAuthException refused =
          assertThrows(OAuthException.class, () -> CommissionedClaims.stated(Map.of(name, "*")));
      assertEquals("invalid_request", refused.error(), name);
    }
  }

  @Test
  public void anAgentIdIsAccepted() {
    String agentId = "07a79d74-b3ff-40a3-9b66-bceda7435a37";
    assertEquals(
        Map.of(ClaimNames.AGENT, agentId),
        CommissionedClaims.stated(Map.of(ClaimNames.AGENT, agentId)));
  }

  /** A refinement session's token names its work item (qits-1482). */
  @Test
  public void anEntityIdIsAccepted() {
    String entityId = "520a4917-dbd7-49d1-9001-4bd82fa378c5";
    assertEquals(
        Map.of(ClaimNames.PROJECT, "p-1", ClaimNames.ENTITY, entityId),
        CommissionedClaims.stated(Map.of(ClaimNames.ENTITY, entityId, ClaimNames.PROJECT, "p-1")));
  }

  @Test
  public void onlyTheGrantableNamesAreAccepted() {
    // Every name the vocabulary has, at once, so this test fails the day one is added without a
    // decision about whether a commission may state it.
    Map<String, String> everyName = new LinkedHashMap<>();
    for (String name : ClaimNames.GRANTABLE) {
      everyName.put(name, "value-" + name);
    }
    assertEquals(everyName, CommissionedClaims.stated(everyName));

    assertThrows(
        OAuthException.class, () -> CommissionedClaims.stated(Map.of("region", "eu-central")));
    assertThrows(OAuthException.class, () -> CommissionedClaims.stated(Map.of("groups", "qits:admin")));
    // The name a claim would have to carry to impersonate a client, refused as any other unknown.
    assertThrows(OAuthException.class, () -> CommissionedClaims.stated(Map.of("sub", "prod-qits-ci")));
  }

  @Test
  public void aValueMustBeOneThingAndNotAnInjection() {
    assertThrows(OAuthException.class, () -> CommissionedClaims.stated(Map.of(ClaimNames.PROJECT, "")));
    assertThrows(
        OAuthException.class, () -> CommissionedClaims.stated(Map.of(ClaimNames.PROJECT, "   ")));
    // The stored form's own separators. Neither is in the accepted charset, which is what makes the
    // column parseable without escaping — so a value carrying one is refused rather than written.
    assertThrows(
        OAuthException.class,
        () -> CommissionedClaims.stated(Map.of(ClaimNames.PROJECT, "a\nworkspace=b")));
    assertThrows(
        OAuthException.class, () -> CommissionedClaims.stated(Map.of(ClaimNames.PROJECT, "a=b")));
    assertThrows(
        OAuthException.class,
        () ->
            CommissionedClaims.stated(
                Map.of(ClaimNames.PROJECT, "x".repeat(CommissionedClaims.MAX_VALUE_LENGTH + 1))));
  }

  @Test
  public void theStoredFormRoundTripsInGrantableOrder() {
    // Handed in the reverse of the vocabulary's order, to show the answer follows GRANTABLE and not
    // the caller — the token's claim order is a property of this service, not of who asked.
    Map<String, String> reversed = new LinkedHashMap<>();
    reversed.put(ClaimNames.BRANCH, "main");
    reversed.put(ClaimNames.PROJECT, PROJECT);

    String stored = CommissionedClaims.format(CommissionedClaims.stated(reversed));
    assertEquals("project=" + PROJECT + "\nbranch=main", stored);
    assertEquals(
        List.of(ClaimNames.PROJECT, ClaimNames.BRANCH),
        List.copyOf(CommissionedClaims.parse(stored).keySet()));
    assertEquals(PROJECT, CommissionedClaims.parse(stored).get(ClaimNames.PROJECT));
  }

  @Test
  public void anUnreadableColumnCostsAClaimAndNeverTheIssuer() {
    // This runs on the token path for every commissioned credential. A row somebody edited by hand,
    // or one written by a version that spelled something differently, must drop what it cannot read
    // and answer with the rest — throwing here would take token issuance down with it.
    assertEquals(Map.of(), CommissionedClaims.parse(null));
    assertEquals(Map.of(), CommissionedClaims.parse("   "));
    assertEquals(Map.of(), CommissionedClaims.parse("nonsense"));
    assertEquals(Map.of(), CommissionedClaims.parse("=orphan"));
    assertEquals(Map.of(), CommissionedClaims.parse("region=eu"), "an unknown name is dropped");
    assertEquals(Map.of(), CommissionedClaims.parse("project=*"), "and so is a wildcard");
    assertEquals(
        Map.of(ClaimNames.PROJECT, PROJECT),
        CommissionedClaims.parse("region=eu\nproject=" + PROJECT + "\nbroken"),
        "the readable lines still answer");
  }
}
