package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.SigningKeys;
import eu.wohlben.qits.idp.entity.IdpServiceClient;
import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * {@code /idp/api/service-clients} end to end (epic qits-540, dossier page "Plan (as of
 * 2026-09-13)", contract C2): the service-client registry, managed rather than configured.
 *
 * <p>{@code test-broad} is the calling admin throughout — a service client the application adopted
 * at start (qits-163), holding {@code qits:system} like every service client, and the same fixture
 * {@code CommissionedClientsTest} uses as an owner. Every test names its own client id, because the
 * suite shares one store.
 */
@QuarkusTest
public class IdpServiceClientsControllerTest {

  private static final String ADMIN = "test-broad";
  private static final String ADMIN_SECRET = "test-broad-secret";

  @Inject IdpServiceClientRepository repository;

  @Inject SigningKeys signingKeys;

  @Test
  public void createAnswersOnceAndTheRowHoldsOnlyAHash() {
    String id = "svc-create-once";
    var answer =
        create(id).statusCode(201).header("Cache-Control", "no-store").extract();
    String secret = answer.path("secret");
    assertEquals(id, answer.path("clientId"));
    assertEquals(ADMIN, answer.path("createdBy"));
    assertNotNull(answer.path("createdAt"));
    assertNotNull(secret);

    IdpServiceClient row = QuarkusTransaction.requiringNew().call(() -> repository.findById(id));
    assertNotNull(row, "the create is a row");
    assertNotEquals(secret, row.secretHash, "the plaintext must not be stored");
    assertTrue(row.secretHash.startsWith("sha-256:"), "the scheme is named in the stored value");
    assertFalse(row.secretHash.contains(secret), "nor any part of it");

    // And the secret actually authenticates.
    token(id, secret, "&audience=qits-deployments").statusCode(200);
  }

  @Test
  public void createTwiceIsAConflict() {
    String id = "svc-conflict";
    create(id).statusCode(201);

    create(id).statusCode(409).body("error", equalTo("conflict"));
  }

  @Test
  public void anAdoptedClientIsAnOrdinaryRow() {
    // test-narrow was adopted at start: it has a row, so creating it again is the same 409 any row
    // answers, and a read reports it like any other — source "database", never "environment".
    create("test-narrow").statusCode(409).body("error", equalTo("conflict"));
    get("test-narrow")
        .statusCode(200)
        .body("source", equalTo("database"))
        .body("createdAt", notNullValue());
  }

  @Test
  public void aDatabaseOnlyServiceClientMayCommissionAndReplaceGitRefs() {
    // BasicCaller.staticOnly asks "is this a service client", and the answer is "has a row". A
    // client created here, never configured anywhere, must therefore pass every commission door.
    String id = "svc-commissioner";
    String secret = create(id).statusCode(201).extract().path("secret");

    String commissioned =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic(id, secret))
            .body(
                "{\"contextKind\":\"svc-commissioner\",\"contextId\":\"ctx\","
                    + "\"gitRefs\":[\"refs/heads/epic/e-1\"]}")
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .body("owner", equalTo(id))
            .extract()
            .path("clientId");

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(id, secret))
        .body("{\"gitRefs\":[\"refs/heads/epic/e-2\"]}")
        .when()
        .put("/idp/api/clients/" + commissioned + "/git-refs")
        .then()
        .statusCode(200)
        .body("gitRefs", equalTo(List.of("refs/heads/epic/e-2")));

    given()
        .header("Authorization", basic(id, secret))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .body("find { it.clientId == '" + commissioned + "' }.owner", equalTo(id));
  }

  @Test
  public void badIdsAreRefused() {
    for (String bad :
        List.of(
            "Upper-Case",
            "-leading-dash",
            "dyn-looks-commissioned",
            "qits-git-workstation",
            "qits-cli",
            "")) {
      createRaw("{\"clientId\":\"" + bad + "\"}")
          .statusCode(400)
          .body("error", equalTo("invalid_request"));
    }
    createRaw("{}").statusCode(400);
    createRaw(null).statusCode(400);
  }

  @Test
  public void rotateKeepsThePreviousSecretLiveAndAnswersOnce() {
    String id = "svc-rotate";
    String original = create(id).statusCode(201).extract().path("secret");

    var rotated =
        given()
            .header("Authorization", basic(ADMIN, ADMIN_SECRET))
            .when()
            .post("/idp/api/service-clients/" + id + "/secret")
            .then()
            .statusCode(200)
            .header("Cache-Control", "no-store")
            .body("clientId", equalTo(id))
            .extract();
    String rotatedSecret = rotated.path("secret");
    assertNotNull(rotated.path("rotatedAt"));
    assertNotEquals(original, rotatedSecret);

    // Both still work: the new one, and the old one within its grace window (D4).
    token(id, rotatedSecret, "&audience=qits-deployments").statusCode(200);
    token(id, original, "&audience=qits-deployments").statusCode(200);
  }

  @Test
  public void rotatingAnUnknownIdIs404() {
    given()
        .header("Authorization", basic(ADMIN, ADMIN_SECRET))
        .when()
        .post("/idp/api/service-clients/svc-never-created/secret")
        .then()
        .statusCode(404)
        .body("error", equalTo("not_found"));
  }

  @Test
  public void getAndListReportTheSourceOfEachId() {
    String id = "svc-source";
    create(id).statusCode(201);

    get(id).statusCode(200).body("source", equalTo("database")).body("clientId", equalTo(id));
    // prod-qits-workspaces is listed for adoption with no secret, so it never became a row: there
    // is no other registry for it to be found in.
    get("prod-qits-workspaces").statusCode(404).body("error", equalTo("not_found"));
    get("svc-does-not-exist").statusCode(404).body("error", equalTo("not_found"));

    String document =
        given()
            .header("Authorization", basic(ADMIN, ADMIN_SECRET))
            .when()
            .get("/idp/api/service-clients")
            .then()
            .statusCode(200)
            .body("find { it.clientId == '" + id + "' }.source", equalTo("database"))
            .body("findAll { it.source != 'database' }", org.hamcrest.Matchers.empty())
            .body("find { it.clientId == 'prod-qits-workspaces' }", org.hamcrest.Matchers.nullValue())
            .extract()
            .asString();
    assertFalse(document.contains("secretHash"), "a listing must never carry a secret or its hash");
  }

  @Test
  public void deleteRemovesTheRowAnd404sTwice() {
    String id = "svc-delete";
    create(id).statusCode(201);

    delete(id).statusCode(204);
    delete(id).statusCode(404).body("error", equalTo("not_found"));
    get(id).statusCode(404);
  }

  @Test
  public void aServiceClientMayNotDeleteItsOwnRow() {
    String id = "svc-self-delete";
    String secret = create(id).statusCode(201).extract().path("secret");

    given()
        .header("Authorization", basic(id, secret))
        .when()
        .delete("/idp/api/service-clients/" + id)
        .then()
        .statusCode(409)
        .body("error", equalTo("conflict"));

    // It still exists, and it may delete something else.
    get(id).statusCode(200);
    String other = "svc-self-delete-other";
    create(other).statusCode(201);
    given()
        .header("Authorization", basic(id, secret))
        .when()
        .delete("/idp/api/service-clients/" + other)
        .then()
        .statusCode(204);
  }

  @Test
  public void aCommissionedCallerIsRefused() {
    // A commissioned credential of test-broad's, via the existing commission API.
    var pair =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic(ADMIN, ADMIN_SECRET))
            .body("{\"contextKind\":\"svc-mgmt-refusal\",\"contextId\":\"ctx\"}")
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract();
    String clientId = pair.path("clientId");
    String secret = pair.path("secret");

    createRaw(clientId, secret, "{\"clientId\":\"svc-from-commission\"}")
        .statusCode(403)
        .body("error", equalTo("access_denied"));
    given()
        .header("Authorization", basic(clientId, secret))
        .when()
        .get("/idp/api/service-clients")
        .then()
        .statusCode(403);
  }

  @Test
  public void everyVerbNeedsCredentials() {
    given().when().get("/idp/api/service-clients").then().statusCode(401);
    createRaw("wrong-caller", "wrong", "{\"clientId\":\"svc-anon\"}").statusCode(401);
  }

  @Test
  public void aDatabaseOnlyTokenCarriesTheCodeShapeExactly() throws Exception {
    String id = "svc-token-shape";
    String secret = create(id).statusCode(201).extract().path("secret");

    JwtClaims claims =
        PublishedJwks.verify(
            token(id, secret, "&audience=some-service").statusCode(200).extract().path("access_token"),
            "qits-platform");

    assertEquals(id, claims.getSubject());
    // The one audience, whatever was asked for (qits-163, C7).
    assertEquals(List.of("qits-platform"), claims.getAudience());
    assertEquals(
        List.of("qits:system", "clients/" + id),
        claims.getStringListClaimValue("groups"));
    assertEquals("*", claims.getClaimValueAsString("project"), "D3: every project, in code");
    assertFalse(claims.hasClaim("workspace"));
    assertFalse(claims.hasClaim("branch"));
  }

  // --- bearer reads (qits-162): an agent keeps every read and gains no write ------------------

  @Test
  public void anAgentBearerReadsBothRoutesAndNoSecret() {
    String id = "svc-bearer-read";
    create(id).statusCode(201);
    String agent = bearer(commissionedToken("workspace", "bearer-read"));

    String one =
        given()
            .header("Authorization", agent)
            .when()
            .get("/idp/api/service-clients/" + id)
            .then()
            .statusCode(200)
            .body("clientId", equalTo(id))
            .body("source", equalTo("database"))
            .extract()
            .asString();
    String all =
        given()
            .header("Authorization", agent)
            .when()
            .get("/idp/api/service-clients")
            .then()
            .statusCode(200)
            .body("find { it.clientId == '" + id + "' }.source", equalTo("database"))
            .extract()
            .asString();
    for (String body : List.of(one, all)) {
      assertFalse(body.toLowerCase().contains("secret"), "a read never carries a secret: " + body);
    }
  }

  @Test
  public void aSystemOrAdminBearerReadsToo() {
    // qits:system: a service client's own token. qits:admin: no client holds it any more, so the
    // bearer is signed here with the idp's own key — what a person's CLI token would carry.
    String system =
        token(ADMIN, ADMIN_SECRET, "").statusCode(200).extract().path("access_token");
    for (String token : List.of(system, signedWithRole("qits:admin"))) {
      given()
          .header("Authorization", bearer(token))
          .when()
          .get("/idp/api/service-clients")
          .then()
          .statusCode(200);
    }
  }

  @Test
  public void aBearerWithoutAReadRoleIsForbidden() {
    // A ci-run commission carries qits:ci-run and its own clients/<id> — none of the three.
    String ciRun = bearer(commissionedToken("ci-run", "bearer-no-role"));
    given()
        .header("Authorization", ciRun)
        .when()
        .get("/idp/api/service-clients")
        .then()
        .statusCode(403)
        .body("error", equalTo("access_denied"));
    given()
        .header("Authorization", ciRun)
        .when()
        .get("/idp/api/service-clients/prod-qits-ci")
        .then()
        .statusCode(403)
        .body("error", equalTo("access_denied"));
  }

  @Test
  public void aBearerThatDoesNotVerifyIsUnauthenticated() {
    String good = commissionedToken("workspace", "bearer-tampered");
    String[] parts = good.split("\\.");
    // Same header and claims, someone else's signature: the last character flipped.
    String sig = parts[2];
    String forged =
        parts[0] + "." + parts[1] + "." + sig.substring(0, sig.length() - 2)
            + (sig.charAt(sig.length() - 2) == 'A' ? 'B' : 'A') + sig.charAt(sig.length() - 1);
    for (String header : List.of(bearer(forged), bearer("not-a-jwt"), "Bearer ")) {
      given()
          .header("Authorization", header)
          .when()
          .get("/idp/api/service-clients")
          .then()
          .statusCode(401)
          .body("error", equalTo("invalid_token"));
    }
  }

  @Test
  public void anAgentBearerIsRefusedOnEveryWrite() {
    String id = "svc-bearer-write";
    String secret = create(id).statusCode(201).extract().path("secret");
    String agent = bearer(commissionedToken("workspace", "bearer-write"));

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", agent)
        .body("{\"clientId\":\"svc-bearer-created\"}")
        .when()
        .post("/idp/api/service-clients")
        .then()
        .statusCode(401);
    given()
        .header("Authorization", agent)
        .when()
        .post("/idp/api/service-clients/" + id + "/secret")
        .then()
        .statusCode(401);
    given()
        .header("Authorization", agent)
        .when()
        .delete("/idp/api/service-clients/" + id)
        .then()
        .statusCode(401);

    // Nothing moved: no row was created, the row was neither rotated nor deleted.
    get("svc-bearer-created").statusCode(404);
    get(id).statusCode(200).body("rotatedAt", org.hamcrest.Matchers.nullValue());
    token(id, secret, "&audience=qits-deployments").statusCode(200);
  }

  // --- helpers --------------------------------------------------------------------------------

  private static ValidatableResponse create(String clientId) {
    return createRaw(ADMIN, ADMIN_SECRET, "{\"clientId\":\"" + clientId + "\"}");
  }

  private static ValidatableResponse createRaw(String body) {
    return createRaw(ADMIN, ADMIN_SECRET, body);
  }

  private static ValidatableResponse createRaw(String caller, String secret, String body) {
    var spec =
        given().contentType(ContentType.JSON).header("Authorization", basic(caller, secret));
    if (body != null) {
      spec = spec.body(body);
    }
    return spec.when().post("/idp/api/service-clients").then();
  }

  private static ValidatableResponse get(String clientId) {
    return given()
        .header("Authorization", basic(ADMIN, ADMIN_SECRET))
        .when()
        .get("/idp/api/service-clients/" + clientId)
        .then();
  }

  private static ValidatableResponse delete(String clientId) {
    return given()
        .header("Authorization", basic(ADMIN, ADMIN_SECRET))
        .when()
        .delete("/idp/api/service-clients/" + clientId)
        .then();
  }

  private static ValidatableResponse token(String clientId, String secret, String extraForm) {
    return given()
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + secret + extraForm)
        .when()
        .post("/idp/token")
        .then();
  }

  /** A commission of test-broad's of this kind, and the token it mints for {@code qits-platform}. */
  private static String commissionedToken(String kind, String contextId) {
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
    return token(pair.path("clientId"), pair.path("secret"), "&audience=qits-platform")
        .statusCode(200)
        .extract()
        .path("access_token");
  }

  private String signedWithRole(String role) {
    SigningKeys.SigningKey key = signingKeys.signing();
    java.time.Instant now = java.time.Instant.now();
    return io.smallrye.jwt.build.Jwt.claims()
        .issuer(PublishedJwks.ISSUER)
        .subject("service-clients-reader")
        .audience(eu.wohlben.qits.idp.control.TokenService.PLATFORM_AUDIENCE)
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
