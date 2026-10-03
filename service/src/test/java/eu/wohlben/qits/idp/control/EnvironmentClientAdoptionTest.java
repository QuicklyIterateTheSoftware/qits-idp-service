package eu.wohlben.qits.idp.control;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.api.PublishedJwks;
import eu.wohlben.qits.idp.entity.IdpServiceClient;
import eu.wohlben.qits.idp.persistence.IdpAdoptionRepository;
import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * The one-time move of the environment service clients into the database (qits-163).
 *
 * <p>The first case is the real start: the application booted against a freshly cleaned schema with
 * {@code qits.idp.clients} and the secrets in {@code src/test/resources/application.properties}, so
 * by the time a test runs the adoption has happened exactly as it would on a live installation's
 * first start of this version.
 *
 * <p><b>A second real boot is not something one test run can do</b>, so the later cases call
 * {@link EnvironmentClientAdoption#adopt} directly — package-visible for exactly this — with ids of
 * their own, after deleting the marker row to stand for "the first boot". That proves the part a
 * reboot would: which ids get a row, which are left alone, and that the marker, not the variables,
 * decides "once". The suite shares one store, so every id here is this class's own.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class EnvironmentClientAdoptionTest {

  @Inject EnvironmentClientAdoption adoption;

  @Inject ServiceClients serviceClients;

  @Inject IdpServiceClientRepository rows;

  @Inject IdpAdoptionRepository marker;

  @Test
  @Order(1)
  public void theFirstStartAdoptedEveryConfiguredClientWithASecret() throws Exception {
    for (String id : List.of("test-broad", "test-narrow", "test-audienceless", "test-role-thief")) {
      IdpServiceClient row = row(id);
      assertNotNull(row, id + " has a row");
      assertEquals(EnvironmentClientAdoption.ADOPTED_BY, row.createdBy, id);
      assertEquals(ClientSecret.hash(id + "-secret"), row.secretHash, id + ": the same hash a"
          + " database client uses, of the secret it already had");
      assertNull(row.rotatedAt, id);
    }
    assertNull(row("prod-qits-workspaces"), "listed with no secret, so skipped");
    assertTrue(adopted(), "the marker is set in the same transaction");

    // An adopted client authenticates with its old secret and is an ordinary service client.
    JwtClaims claims = PublishedJwks.verify(mint("test-broad", "test-broad-secret", "&audience=prod-qits-ci")
        .statusCode(200)
        .extract()
        .path("access_token"), "qits-platform");
    assertEquals("test-broad", claims.getSubject());
    assertEquals(
        List.of("qits:system", "clients/test-broad"), claims.getStringListClaimValue("groups"));
    assertEquals(List.of("qits-platform"), PublishedJwks.audienceOf(claims));
  }

  @Test
  @Order(2)
  public void aFirstAdoptionAddsMissingRowsSkipsBlankSecretsAndLeavesExistingRowsAlone()
      throws Exception {
    String existingHash = ClientSecret.hash("adopt-existing-original");
    Instant existingAt = Instant.parse("2026-09-01T00:00:00Z");
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              marker.deleteById(IdpAdoptionRepository.ID);
              IdpServiceClient existing = new IdpServiceClient();
              existing.clientId = "adopt-existing";
              existing.secretHash = existingHash;
              existing.createdBy = "svc-someone";
              existing.createdAt = existingAt;
              rows.persist(existing);
            });

    Map<String, String> configured = new LinkedHashMap<>();
    configured.put("adopt-new", "adopt-new-secret");
    configured.put("adopt-blank", "   ");
    configured.put("adopt-absent", null);
    configured.put("adopt-existing", "adopt-existing-environment-secret");
    configured.put("Adopt_Malformed", "adopt-malformed-secret");
    configured.put("adopt-second-new", "adopt-second-new-secret");

    assertEquals(List.of("adopt-new", "adopt-second-new"), adoption.adopt(configured));

    IdpServiceClient adopted = row("adopt-new");
    assertEquals(ClientSecret.hash("adopt-new-secret"), adopted.secretHash);
    assertEquals(EnvironmentClientAdoption.ADOPTED_BY, adopted.createdBy);
    assertNull(row("adopt-blank"), "a blank secret could never authenticate, so nothing moves");
    assertNull(row("adopt-absent"), "nor an absent one");
    assertNull(row("Adopt_Malformed"), "nor an id no service client may have");

    IdpServiceClient untouched = row("adopt-existing");
    assertEquals(existingHash, untouched.secretHash, "an existing row keeps its own secret");
    assertEquals("svc-someone", untouched.createdBy);
    assertEquals(existingAt, untouched.createdAt);
    assertTrue(adopted(), "and the marker is back");

    // Through the token endpoint, once the cache has the rows (the real start loads after adopting).
    serviceClients.load();
    mint("adopt-new", "adopt-new-secret", "").statusCode(200);
    mint("adopt-existing", "adopt-existing-environment-secret", "").statusCode(401);
    mint("adopt-existing", "adopt-existing-original", "").statusCode(200);
    mint("adopt-blank", "   ", "").statusCode(401);
  }

  @Test
  @Order(3)
  public void onceTheMarkerExistsNothingIsReadOrWrittenAgain() {
    assertTrue(adopted());

    assertEquals(List.of(), adoption.adopt(Map.of("adopt-too-late", "adopt-too-late-secret")));
    assertNull(row("adopt-too-late"), "the marker, not the variables, decides once");

    // The start-time entry point too: it does not get as far as reading the configuration.
    adoption.adoptOnce();
    assertEquals(1L, QuarkusTransaction.requiringNew().call(() -> marker.count()));
  }

  private IdpServiceClient row(String clientId) {
    return QuarkusTransaction.requiringNew().call(() -> rows.findById(clientId));
  }

  private boolean adopted() {
    return QuarkusTransaction.requiringNew().call(() -> marker.adopted());
  }

  private static ValidatableResponse mint(String clientId, String secret, String extraForm) {
    return given()
        .contentType(ContentType.URLENC)
        .body(
            "grant_type=client_credentials&client_id="
                + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret="
                + URLEncoder.encode(secret, StandardCharsets.UTF_8)
                + extraForm)
        .when()
        .post("/idp/token")
        .then();
  }
}
