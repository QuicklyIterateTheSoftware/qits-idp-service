package eu.wohlben.qits.idp.control;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.idp.persistence.IdpServiceClientSeedRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Seeding the first service client, once (epic qits-540 dossier, "Plan (as of 2026-09-13)", "seed
 * once"). Its own
 * application start, the way {@code EnvironmentAudiencesTest} costs one to pin
 * {@code QITS_ENVIRONMENT}: seeding happens at {@code StartupEvent}, so it has to have already run
 * by the time any test method sees it.
 *
 * <p><b>A second real boot is not something one test run can do</b>, so a later boot with the
 * variables changed or blanked is simulated by calling {@link ServiceClients#seedOnce()} again —
 * package-visible for exactly this — after swapping the injected config fields, which are
 * package-private for the same reason. What that proves is the part a real second boot cannot prove
 * any more cheaply: the {@code idp_seed} marker row, not the variables, is what "once" checks.
 */
@QuarkusTest
@TestProfile(ServiceClientSeedTest.SeedConfigured.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ServiceClientSeedTest {

  static final String SEED_ID = "seed-test-once";
  static final String SEED_SECRET = "seed-test-secret-1";

  public static class SeedConfigured implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      // The dotted key, like every other @TestProfile override in this suite (StoryProfile's
      // qits.idp.client.<id>.secret is the same idiom) — a profile override is a plain config
      // source keyed by the property name @ConfigProperty asks for, not by the env var mangling
      // real deployments use.
      return Map.of(
          "qits.idp.seed-client.id", SEED_ID,
          "qits.idp.seed-client.secret", SEED_SECRET);
    }
  }

  @Inject ServiceClients serviceClients;

  @Inject IdpServiceClientSeedRepository seedRepository;

  @Test
  @Order(1)
  public void theSeedClientMintsFromTheFirstBoot() {
    given()
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials&client_id=" + SEED_ID + "&client_secret=" + SEED_SECRET)
        .when()
        .post("/idp/token")
        .then()
        .statusCode(200);

    String markedId =
        QuarkusTransaction.requiringNew()
            .call(() -> seedRepository.findById(IdpServiceClientSeedRepository.ID).clientId);
    assertEquals(SEED_ID, markedId, "the marker names the seeded id");
  }

  @Test
  @Order(2)
  public void aLaterCallWithTheSameVariablesStillSetDoesNothingTwice() {
    serviceClients.seedOnce();

    // Still exactly the one marker row, still naming the same id.
    long rows =
        QuarkusTransaction.requiringNew()
            .call(() -> seedRepository.count());
    assertEquals(1L, rows);
  }

  @Test
  @Order(3)
  public void aLaterCallWithAChangedVariableIsIgnored() {
    serviceClients.seedClientId = Optional.of("seed-test-should-not-exist");
    serviceClients.seedClientSecret = Optional.of("seed-test-should-not-exist-secret");
    try {
      serviceClients.seedOnce();
    } finally {
      serviceClients.seedClientId = Optional.of(SEED_ID);
      serviceClients.seedClientSecret = Optional.of(SEED_SECRET);
    }

    String stillMarkedId =
        QuarkusTransaction.requiringNew()
            .call(() -> seedRepository.findById(IdpServiceClientSeedRepository.ID).clientId);
    assertEquals(SEED_ID, stillMarkedId, "a deleted seed client does not come back, and neither"
        + " does a different one: the marker row decides, not the variable");
    given()
        .contentType(ContentType.URLENC)
        .body(
            "grant_type=client_credentials&client_id=seed-test-should-not-exist&client_secret=seed-test-should-not-exist-secret")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401);
  }

  @Test
  @Order(4)
  public void aLaterCallWithBlankVariablesDoesNothing() {
    serviceClients.seedClientId = Optional.empty();
    serviceClients.seedClientSecret = Optional.empty();
    try {
      serviceClients.seedOnce();
    } finally {
      serviceClients.seedClientId = Optional.of(SEED_ID);
      serviceClients.seedClientSecret = Optional.of(SEED_SECRET);
    }

    long rows = QuarkusTransaction.requiringNew().call(() -> seedRepository.count());
    assertEquals(1L, rows, "blank seeds nothing, even with a marker row already present");
  }
}
