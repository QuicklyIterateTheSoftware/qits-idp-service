package eu.wohlben.qits.idp.control;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.api.PublishedJwks;
import eu.wohlben.qits.idp.entity.IdpServiceClient;
import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * {@code POST /idp/api/gc/service-clients} end to end (qits-878): service clients no deployment
 * claims are deleted, through the cache, and nothing else is.
 *
 * <p>In this package rather than {@code api} for one reason: {@link ServiceClients#load()} is
 * package-visible, and a client has to be made <i>older</i> than the grace to be collectable at all —
 * every row in this suite was written moments ago. {@link #backdate} rewrites {@code created_at}
 * and reloads the cache, the same move {@code EnvironmentClientAdoptionTest} makes.
 *
 * <p><b>The suite shares one store</b>, so every collection here claims every client except the
 * ones the test is about ({@link #claimsAllBut}): {@code test-broad} and every other test's clients
 * survive as {@code claimed}, whatever order the classes run in.
 */
@QuarkusTest
public class ServiceClientGcTest {

  private static final String ADMIN = "test-broad";
  private static final String ADMIN_SECRET = "test-broad-secret";
  private static final String DOOR = "/idp/api/gc/service-clients";

  @Inject ServiceClients serviceClients;

  @Inject IdpServiceClientRepository repository;

  @Inject SigningKeys signingKeys;

  // --- the rule -------------------------------------------------------------------------------

  @Test
  public void anUnclaimedClientPastItsGraceIsDeletedAndCanNoLongerAuthenticate() {
    String id = "svc-gc-unclaimed";
    String secret = create(id);
    backdate(id);

    String body =
        gc(basic(ADMIN, ADMIN_SECRET), claimsAllBut(false, id))
            .statusCode(200)
            .body("dryRun", equalTo(false))
            .body("removed.size()", equalTo(1))
            .body("removed[0].clientId", equalTo(id))
            .body("removed[0].reason", equalTo("unclaimed"))
            .body("removed[0].createdBy", equalTo(ADMIN))
            .body("removed[0].createdAt", notNullValue())
            .body("kept.find { it.clientId == '" + id + "' }", nullValue())
            .body("kept.find { it.clientId == 'test-broad' }.reason", equalTo("claimed"))
            .body("keptCounts.claimed", greaterThanOrEqualTo(1))
            .extract()
            .asString();
    assertFalse(
        body.contains("\"secret") || body.contains("Hash"),
        "a report never carries a secret or its hash: " + body);

    assertTrue(serviceClients.find(id).isEmpty(), "the cache forgot it");
    assertNull(row(id), "the row is gone");
    token(id, secret).statusCode(401).body("error", equalTo("invalid_client"));
  }

  @Test
  public void aDryRunJudgesTheSameAndDeletesNothing() {
    String id = "svc-gc-dry-run";
    String secret = create(id);
    backdate(id);

    gc(basic(ADMIN, ADMIN_SECRET), claimsAllBut(true, id))
        .statusCode(200)
        .body("dryRun", equalTo(true))
        .body("removed.size()", equalTo(1))
        .body("removed[0].clientId", equalTo(id))
        .body("removed[0].reason", equalTo("unclaimed"));

    assertTrue(serviceClients.find(id).isPresent());
    assertNotNull(row(id));
    token(id, secret).statusCode(200);
  }

  @Test
  public void aClaimedClientIsKeptHoweverOld() {
    String id = "svc-gc-claimed";
    create(id);
    backdate(id);

    gc(basic(ADMIN, ADMIN_SECRET), claimsAllBut(false))
        .statusCode(200)
        .body("removed.size()", equalTo(0))
        .body("kept.find { it.clientId == '" + id + "' }.reason", equalTo("claimed"));
    assertTrue(serviceClients.find(id).isPresent());
  }

  @Test
  public void aYoungClientIsKeptForItsGrace() {
    // Not backdated: created moments ago, and not claimed — the deployer has not written its claim
    // row yet, or a bootstrap is still on its seed client.
    String id = "svc-gc-young";
    String secret = create(id);

    gc(basic(ADMIN, ADMIN_SECRET), claimsAllBut(false, id))
        .statusCode(200)
        .body("removed.size()", equalTo(0))
        .body("kept.find { it.clientId == '" + id + "' }.reason", equalTo("grace"))
        .body("keptCounts.grace", greaterThanOrEqualTo(1));
    token(id, secret).statusCode(200);
  }

  @Test
  public void theBasicCallersOwnClientIsKept() {
    String id = "svc-gc-basic-caller";
    String secret = create(id);
    backdate(id);

    gc(basic(id, secret), claimsAllBut(false, id))
        .statusCode(200)
        .body("removed.size()", equalTo(0))
        .body("kept.find { it.clientId == '" + id + "' }.reason", equalTo("caller"))
        .body("keptCounts.caller", equalTo(1));
    token(id, secret).statusCode(200);
  }

  @Test
  public void aSystemBearerOfAServiceClientIsAcceptedAndItsClientKept() {
    String id = "svc-gc-bearer-caller";
    String secret = create(id);
    String token = token(id, secret).statusCode(200).extract().path("access_token");
    backdate(id);
    String target = "svc-gc-bearer-target";
    create(target);
    backdate(target);

    gc(bearer(token), claimsAllBut(false, id, target))
        .statusCode(200)
        .body("removed.size()", equalTo(1))
        .body("removed[0].clientId", equalTo(target))
        .body("kept.find { it.clientId == '" + id + "' }.reason", equalTo("caller"))
        .body("keptCounts.caller", equalTo(1));
    assertTrue(serviceClients.find(target).isEmpty());
    assertTrue(serviceClients.find(id).isPresent());
  }

  @Test
  public void commissionedClientsAreNeverJudged() {
    var pair =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic(ADMIN, ADMIN_SECRET))
            .body("{\"contextKind\":\"svc-gc\",\"contextId\":\"untouched\"}")
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract();
    String dyn = pair.path("clientId");
    String secret = pair.path("secret");
    assertTrue(dyn.startsWith("dyn-"));

    // A real collection, with the commission in no claim.
    gc(basic(ADMIN, ADMIN_SECRET), claimsAllBut(false))
        .statusCode(200)
        .body("removed.find { it.clientId == '" + dyn + "' }", nullValue())
        .body("kept.find { it.clientId == '" + dyn + "' }", nullValue());
    token(dyn, secret).statusCode(200);
  }

  // --- fail closed ----------------------------------------------------------------------------

  @Test
  public void missingOrEmptyClaimsAre400AndDeleteNothing() {
    String id = "svc-gc-fail-closed";
    create(id);
    backdate(id);

    for (String body :
        List.of(
            "{\"dryRun\":false,\"claims\":[]}",
            "{\"dryRun\":false}",
            "{\"dryRun\":false,\"claims\":null}",
            "{\"dryRun\":false,\"claims\":[{\"applicationName\":\"no-client-id\"}]}")) {
      gc(basic(ADMIN, ADMIN_SECRET), body)
          .statusCode(400)
          .body("error", equalTo("invalid_request"));
    }
    // No body at all.
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(ADMIN, ADMIN_SECRET))
        .when()
        .post(DOOR)
        .then()
        .statusCode(400);

    assertTrue(serviceClients.find(id).isPresent());
    assertNotNull(row(id));
  }

  // --- auth -----------------------------------------------------------------------------------

  @Test
  public void everyoneElseIsRefusedAndNothingIsDeleted() {
    String id = "svc-gc-refusals";
    create(id);
    backdate(id);
    String body = claimsAllBut(false, id);

    // Unauthenticated.
    gc(null, body).statusCode(401);
    gc(basic("svc-gc-nobody", "wrong"), body).statusCode(401);
    gc(bearer("not-a-jwt"), body).statusCode(401).body("error", equalTo("invalid_token"));

    // An agent: a workspace commission's own bearer (qits:agent), and its Basic pair.
    var workspace = commission("workspace", "gc-agent");
    String agentToken =
        token(workspace.get(0), workspace.get(1)).statusCode(200).extract().path("access_token");
    gc(bearer(agentToken), body).statusCode(403).body("error", equalTo("access_denied"));
    gc(basic(workspace.get(0), workspace.get(1)), body)
        .statusCode(403)
        .body("error", equalTo("access_denied"));

    // qits:system, signed by this idp, but the sub is a commissioned client or a person.
    var other = commission("ci-run", "gc-dyn-sub");
    for (String subject : List.of(other.get(0), "dyn-not-a-row", "a-person")) {
      gc(bearer(signed(subject, "qits:system")), body)
          .statusCode(403)
          .body("error", equalTo("access_denied"));
    }
    // A service client's id as sub, but without qits:system.
    gc(bearer(signed(ADMIN, "qits:agent")), body).statusCode(403);

    assertTrue(serviceClients.find(id).isPresent(), "no refused call deleted anything");
    assertNotNull(row(id));
  }

  // --- helpers --------------------------------------------------------------------------------

  /** A service client created through the API by test-broad. @return its secret */
  private static String create(String clientId) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(ADMIN, ADMIN_SECRET))
        .body("{\"clientId\":\"" + clientId + "\"}")
        .when()
        .post("/idp/api/service-clients")
        .then()
        .statusCode(201)
        .extract()
        .path("secret");
  }

  /** Move the row's {@code created_at} past the grace, and reload the cache to see it. */
  private void backdate(String clientId) {
    Instant old = Instant.now().minus(UnclaimedServiceClientCollector.GRACE).minusSeconds(3600);
    QuarkusTransaction.requiringNew()
        .run(() -> repository.findById(clientId).createdAt = old);
    serviceClients.load();
  }

  /**
   * A request body claiming every service client there is except {@code excluded}, in the shape
   * qits-deployments answers — with an unknown field at both levels, which must be tolerated.
   */
  private String claimsAllBut(boolean dryRun, String... excluded) {
    Set<String> skip = Set.of(excluded);
    String claims =
        serviceClients.list().stream()
            .map(ServiceClients.StoredServiceClient::clientId)
            .filter(clientId -> !skip.contains(clientId))
            .map(
                clientId ->
                    "{\"clientId\":\"" + clientId + "\",\"applicationName\":\"" + clientId
                        + "\",\"environmentName\":\"dev\",\"createdAt\":\"2026-10-01T00:00:00Z\","
                        + "\"unknown\":1}")
            .collect(Collectors.joining(","));
    return "{\"dryRun\":" + dryRun + ",\"claims\":[" + claims + "],\"alsoUnknown\":true}";
  }

  private static ValidatableResponse gc(String authorization, String body) {
    var spec = given().contentType(ContentType.JSON).body(body);
    if (authorization != null) {
      spec = spec.header("Authorization", authorization);
    }
    return spec.when().post(DOOR).then();
  }

  private IdpServiceClient row(String clientId) {
    return QuarkusTransaction.requiringNew().call(() -> repository.findById(clientId));
  }

  /** A commission of test-broad's. @return [clientId, secret] */
  private static List<String> commission(String kind, String contextId) {
    var pair =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic(ADMIN, ADMIN_SECRET))
            .body("{\"contextKind\":\"" + kind + "\",\"contextId\":\"" + contextId + "\"}")
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract();
    return List.of(pair.path("clientId"), pair.path("secret"));
  }

  private static ValidatableResponse token(String clientId, String secret) {
    return given()
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + secret)
        .when()
        .post("/idp/token")
        .then();
  }

  /** A bearer this idp would verify, with a chosen sub and role — what no mint here produces. */
  private String signed(String subject, String role) {
    SigningKeys.SigningKey key = signingKeys.signing();
    Instant now = Instant.now();
    return Jwt.claims()
        .issuer(PublishedJwks.ISSUER)
        .subject(subject)
        .audience(TokenService.PLATFORM_AUDIENCE)
        .groups(role)
        .issuedAt(now)
        .expiresAt(now.plusSeconds(300))
        .jws()
        .keyId(key.kid())
        .sign(key.privateKey());
  }

  private static String bearer(String token) {
    return "Bearer " + token;
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
