package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * The rotation rule itself, deterministically — {@link ServiceClients} and {@code
 * IdpServiceClientsControllerTest} exercise it through a live rotation, which cannot wait out the
 * fifteen-minute grace (D4 of epic qits-540, dossier page "Plan (as of 2026-09-13)") inside a test. This pins the
 * expiry check {@link ClientSecret#matches} makes at authentication time, with a clock a test
 * controls.
 */
public class ClientSecretTest {

  @Test
  public void aDatabaseServiceClientAcceptsItsCurrentHash() {
    ClientSecret secret =
        ClientSecret.serviceClient(ClientSecret.hash("current"), null, null);
    assertTrue(secret.matches("current"));
    assertFalse(secret.matches("wrong"));
  }

  @Test
  public void aPreviousHashAuthenticatesWhileItIsStillLive() {
    ClientSecret secret =
        ClientSecret.serviceClient(
            ClientSecret.hash("current"),
            ClientSecret.hash("previous"),
            Instant.now().plus(15, ChronoUnit.MINUTES));

    assertTrue(secret.matches("current"), "the fresh secret");
    assertTrue(secret.matches("previous"), "the rotated-out one, still inside its grace");
  }

  @Test
  public void aPreviousHashStopsAuthenticatingOnceItsGraceHasPassed() {
    ClientSecret secret =
        ClientSecret.serviceClient(
            ClientSecret.hash("current"),
            ClientSecret.hash("previous"),
            Instant.now().minus(1, ChronoUnit.SECONDS));

    assertTrue(secret.matches("current"));
    assertFalse(secret.matches("previous"), "the grace window (D4) has closed");
  }

  @Test
  public void aNullCandidateNeverMatches() {
    ClientSecret secret = ClientSecret.serviceClient(ClientSecret.hash("only"), null, null);
    assertFalse(secret.matches(null), "a null candidate never matches");
    assertTrue(secret.usable());
  }

  @Test
  public void matchNamesWhichSourceAcceptedEachHash() {
    ClientSecret secret =
        ClientSecret.serviceClient(
            ClientSecret.hash("current"),
            ClientSecret.hash("previous"),
            Instant.now().plus(15, ChronoUnit.MINUTES));

    assertEquals(Optional.of(ClientSecret.Source.CURRENT), secret.match("current"));
    assertEquals(Optional.of(ClientSecret.Source.PREVIOUS), secret.match("previous"));
    assertEquals(Optional.empty(), secret.match("wrong"), "no hash accepts this");
  }

  @Test
  public void matchIsEmptyOnceThePreviousHashHasExpired() {
    ClientSecret secret =
        ClientSecret.serviceClient(
            ClientSecret.hash("current"),
            ClientSecret.hash("previous"),
            Instant.now().minus(1, ChronoUnit.SECONDS));

    assertEquals(Optional.of(ClientSecret.Source.CURRENT), secret.match("current"));
    assertEquals(
        Optional.empty(), secret.match("previous"), "the grace window (D4) has closed");
  }
}
