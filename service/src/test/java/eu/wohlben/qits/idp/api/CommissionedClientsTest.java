package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.entity.IdpDynamicClient;
import eu.wohlben.qits.idp.persistence.IdpDynamicClientRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The commission API end to end: a service asks for a credential for a context, the credential
 * mints tokens exactly like the service client that asked, and deleting it stops that at once.
 *
 * <p>The owners are service clients the application adopted at start from {@code
 * src/test/resources/application.properties} — {@code test-broad} and {@code test-narrow}, each
 * holding {@code qits:system} and {@code project=*} in code. <b>A commission inherits nothing from
 * its owner</b> (D3/D12 of epic qits-540, dossier page "Plan (as of 2026-09-13)"): only its own
 * stated claims reach the token, its roles are its context kind's fixed ones ({@code
 * CommissionRoles}) or none, and its audience is {@code qits-platform} like every token's.
 *
 * <p>Every test names its own {@code contextKind}, because the suite shares one application and
 * therefore one store: the listing case filters on it rather than assuming an empty table.
 */
@QuarkusTest
public class CommissionedClientsTest {

  private static final String OWNER = "test-broad";
  private static final String OWNER_SECRET = "test-broad-secret";
  private static final String OTHER_OWNER = "test-narrow";
  private static final String OTHER_OWNER_SECRET = "test-narrow-secret";

  /** A project id in the shape the platform actually mints them, so the value charset is exercised. */
  private static final String A_PROJECT = "b03b84b1-1875-4071-9dbf-854550156258";

  @jakarta.inject.Inject IdpDynamicClientRepository repository;

  @Test
  public void aCommissionedClientMintsExactlyLikeTheServiceClientThatCommissionedIt()
      throws Exception {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "mint-kind", "run/4711");

    String token =
        token(pair.get("clientId"), pair.get("secret"), "&audience=qits-deployments")
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-platform");
    assertEquals(pair.get("clientId"), claims.getSubject(), "the commissioned id is the sub");
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer());
    assertNotNull(PublishedJwks.kidOf(token), "signed by the same key as everything else");

    // The one audience, whatever was asked for — with and without an audience parameter.
    assertEquals(List.of("qits-platform"), PublishedJwks.audienceOf(claims));
    String all =
        token(pair.get("clientId"), pair.get("secret"), "").statusCode(200).extract()
            .path("access_token");
    JwtClaims allClaims = PublishedJwks.verify(all, "qits-platform");
    assertEquals(List.of("qits-platform"), PublishedJwks.audienceOf(allClaims));
    assertNull(
        allClaims.getClaimValueAsString("project"),
        "a commission does not inherit its owner's project=* (D3)");

    // An audience the owner was never allowed is ignored too, never invalid_target.
    String other =
        token(pair.get("clientId"), pair.get("secret"), "&audience=qits-platform-artifacts")
            .statusCode(200)
            .extract()
            .path("access_token");
    assertEquals(
        List.of("qits-platform"),
        PublishedJwks.audienceOf(PublishedJwks.verify(other, "qits-platform")));
  }

  @Test
  public void aCommissionedTokenNamesItselfAndNotTheOwnerThatCommissionedIt() throws Exception {
    // The commission body has no roles member, and one written anyway changes nothing: roles are
    // not a thing a caller asks for here. This is the second half of "no client may hold another
    // client's self-role" — the first is that no client's roles are configurable at all.
    Map<String, String> pair =
        pairOf(
            commissionRaw(
                    OWNER,
                    OWNER_SECRET,
                    "{\"contextKind\":\"self-role-kind\",\"contextId\":\"ctx-self-role\","
                        + "\"roles\":[\"clients/test-narrow\",\"clients/test-broad\"]}")
                .statusCode(201));

    String token =
        token(pair.get("clientId"), pair.get("secret"), "&audience=qits-deployments")
            .statusCode(200)
            .extract()
            .path("access_token");
    List<String> groups =
        PublishedJwks.verify(token, "qits-platform").getStringListClaimValue("groups");

    assertEquals(
        List.of("clients/" + pair.get("clientId")),
        groups,
        "self-role-kind has no fixed role (D12), and roles are never a thing a caller asks for —"
            + " the credential's OWN self-role only");
    assertFalse(
        groups.contains("clients/" + OWNER),
        "a commissioned credential must not reach a door held open for the client that made it");
    assertFalse(groups.contains("clients/" + OTHER_OWNER), "nor anyone else's");
  }

  @Test
  public void theSecretIsReturnedOnceAndTheRowHoldsOnlyAHash() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "hash-kind", "ctx-1");

    IdpDynamicClient row =
        QuarkusTransaction.requiringNew().call(() -> repository.findById(pair.get("clientId")));
    assertNotNull(row, "the commission is a row");
    assertNotEquals(pair.get("secret"), row.secretHash, "the plaintext must not be stored");
    assertTrue(row.secretHash.startsWith("sha-256:"), "the scheme is named in the stored value");
    assertFalse(row.secretHash.contains(pair.get("secret")), "nor any part of it");
    assertEquals(OWNER, row.owner);
    assertEquals("hash-kind", row.contextKind);
    assertEquals("ctx-1", row.contextId);
    assertNotNull(row.createdAt);
  }

  @Test
  public void theClientIdIsReadableAndIsNoServiceClientsName() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "ci-run", "Project/Build #918");
    String clientId = pair.get("clientId");

    assertTrue(clientId.startsWith(DynamicClients.ID_PREFIX + "ci-run-"), clientId);
    assertTrue(
        clientId.contains("project-build-918"), "the context is legible in a listing: " + clientId);
    // A service client's id may not start with dyn-, so none of them can be produced here.
    assertFalse(List.of(OWNER, OTHER_OWNER).contains(clientId));
    assertTrue(clientId.length() <= 128, "the column is varchar(128)");
  }

  @Test
  public void decommissioningStopsTheMintingImmediately() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "revoke-kind", "ctx-2");
    token(pair.get("clientId"), pair.get("secret"), "").statusCode(200);

    decommission(OWNER, OWNER_SECRET, pair.get("clientId")).statusCode(204);

    // The very next request, with no cache to wait out. Tokens already minted live out their exp;
    // that grace is the accepted cost and is not what this asserts.
    token(pair.get("clientId"), pair.get("secret"), "")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
    long rows =
        QuarkusTransaction.requiringNew()
            .call(() -> repository.count("clientId = ?1", pair.get("clientId")));
    assertEquals(0L, rows, "decommissioning is deleting the row");
  }

  @Test
  public void onlyTheOwnerMayDecommission() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "owner-kind", "ctx-3");

    // Another service client is told what a caller naming a nonexistent id is told.
    decommission(OTHER_OWNER, OTHER_OWNER_SECRET, pair.get("clientId"))
        .statusCode(404)
        .body("error", equalTo("not_found"));
    token(pair.get("clientId"), pair.get("secret"), "").statusCode(200);

    decommission(OWNER, OWNER_SECRET, pair.get("clientId")).statusCode(204);
  }

  @Test
  public void aContextMayHandItsOwnCredentialBack() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "self-kind", "ctx-4");

    decommission(pair.get("clientId"), pair.get("secret"), pair.get("clientId")).statusCode(204);

    token(pair.get("clientId"), pair.get("secret"), "").statusCode(401);
  }

  @Test
  public void aCommissionedClientMayNotCommissionAnother() {
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "spread-kind", "ctx-5");

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(pair.get("clientId"), pair.get("secret")))
        .body("{\"contextKind\":\"spread-kind\",\"contextId\":\"ctx-5-child\"}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(403)
        .body("error", equalTo("access_denied"));

    // It authenticates fine. spread-kind has no fixed role (D12), so the listing — which still
    // needs SYSTEM or AGENT — is 403 rather than the empty 200 an owner-inherited role
    // used to answer with; POST is refused for the separate reason above regardless.
    given()
        .header("Authorization", basic(pair.get("clientId"), pair.get("secret")))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(403);
  }

  @Test
  public void theListingShowsTheCallersOwnCommissionsAndNoOthers() {
    String kind = "listing-kind";
    Map<String, String> mine = commission(OWNER, OWNER_SECRET, kind, "ctx-mine");
    Map<String, String> alsoMine = commission(OWNER, OWNER_SECRET, kind, "ctx-mine-2");
    Map<String, String> theirs = commission(OTHER_OWNER, OTHER_OWNER_SECRET, kind, "ctx-theirs");

    List<String> ownersOwn = listedIds(OWNER, OWNER_SECRET, kind);
    assertTrue(ownersOwn.contains(mine.get("clientId")));
    assertTrue(ownersOwn.contains(alsoMine.get("clientId")));
    assertFalse(ownersOwn.contains(theirs.get("clientId")), "no cross-owner listing");

    List<String> othersOwn = listedIds(OTHER_OWNER, OTHER_OWNER_SECRET, kind);
    assertEquals(List.of(theirs.get("clientId")), othersOwn);

    // What a reconcile reads on each row.
    String row = "find { it.clientId == '" + theirs.get("clientId") + "' }.";
    given()
        .header("Authorization", basic(OTHER_OWNER, OTHER_OWNER_SECRET))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .body(row + "owner", equalTo(OTHER_OWNER))
        .body(row + "contextKind", equalTo(kind))
        .body(row + "contextId", equalTo("ctx-theirs"))
        .body(row + "createdAt", org.hamcrest.Matchers.notNullValue());

    // A listing never carries a secret, in either spelling.
    String document =
        given()
            .header("Authorization", basic(OWNER, OWNER_SECRET))
            .when()
            .get("/idp/api/clients")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    assertFalse(document.contains(mine.get("secret")), "a listing must not carry a secret");
    assertFalse(document.contains("secretHash"), "nor the hash of one");
  }

  @Test
  public void aCommissionNeedsAContextItCanNameInAClientId() {
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextId\":\"ctx\"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"ci-run\"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"ci-run\",\"contextId\":\"  \"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    // A kind goes into a client id, so it is a lowercase slug and nothing else.
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"CI Run\",\"contextId\":\"ctx\"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"ci/../run\",\"contextId\":\"ctx\"}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void everyVerbNeedsTheCallersOwnCredentials() {
    // No header at all.
    given()
        .contentType(ContentType.JSON)
        .body("{\"contextKind\":\"anon-kind\",\"contextId\":\"ctx\"}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .header("WWW-Authenticate", "Basic realm=\"qits-platform-idp\"");
    given().when().get("/idp/api/clients").then().statusCode(401);
    given().when().delete("/idp/api/clients/dyn-anon-ctx-abc").then().statusCode(401);

    // The wrong secret.
    commissionRaw(OWNER, "wrong", "{\"contextKind\":\"anon-kind\",\"contextId\":\"ctx\"}")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));

    // An id listed for adoption with no secret was never adopted, so it is unknown here too — the
    // same reading as at the token endpoint, so there is no door this API opens that that one does
    // not.
    commissionRaw(
            "prod-qits-workspaces", "", "{\"contextKind\":\"anon-kind\",\"contextId\":\"ctx\"}")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void decommissioningSomethingThatIsNotThereIsNotAnError() {
    decommission(OWNER, OWNER_SECRET, "dyn-nothing-here-Aaaaaaaaaaaaaaaaaaaaaa")
        .statusCode(404)
        .body("error", equalTo("not_found"));
    // A service client id is not a commission and cannot be deleted through this door either.
    decommission(OWNER, OWNER_SECRET, OTHER_OWNER).statusCode(404);
  }

  // --- per-context scoping ------------------------------------------------------------------

  @Test
  public void aCommissionStatesWhatItsContextIsAboutAndTheTokenCarriesIt() throws Exception {
    // The owner holds project=* and the commission inherits none of it: the scope comes from the
    // commission, not from the client making it.
    io.restassured.response.ExtractableResponse<?> answer =
        commissionRaw(
                OTHER_OWNER,
                OTHER_OWNER_SECRET,
                "{\"contextKind\":\"workspace\",\"contextId\":\"1101\","
                    + "\"claims\":{\"project\":\"" + A_PROJECT + "\"}}")
            .statusCode(201)
            .body("claims.project", equalTo(A_PROJECT))
            .extract();
    String clientId = answer.path("clientId");
    String secret = answer.path("secret");

    JwtClaims claims =
        PublishedJwks.verify(
            token(clientId, secret, "").statusCode(200).extract().path("access_token"),
            "qits-platform");

    assertEquals(
        A_PROJECT,
        claims.getClaimValueAsString("project"),
        "the claim a resource service scopes this credential by");
    assertNull(claims.getClaimValueAsString("workspace"), "and nothing it did not state");
    assertNull(claims.getClaimValueAsString("branch"));

    // On the row, in the column V2 dropped and V5 brought back together with this reader.
    IdpDynamicClient row = QuarkusTransaction.requiringNew().call(() -> repository.findById(clientId));
    assertEquals("project=" + A_PROJECT, row.claims);
  }

  @Test
  public void aStatedClaimReachesTheTokenAloneWithNoOwnerMerge() throws Exception {
    // D3: a commission no longer inherits its owner's claims. test-broad holds project=*, but this
    // commission states only workspace, so the token carries workspace and nothing else —
    // there is no owner grant left to merge it with.
    io.restassured.response.ExtractableResponse<?> added =
        commissionRaw(
                OWNER,
                OWNER_SECRET,
                "{\"contextKind\":\"merge-kind\",\"contextId\":\"ctx-merge\","
                    + "\"claims\":{\"workspace\":\"ws-77\"}}")
            .statusCode(201)
            .extract();
    JwtClaims claims =
        PublishedJwks.verify(
            token(
                    added.path("clientId"),
                    added.path("secret"),
                    "&audience=qits-deployments")
                .statusCode(200)
                .extract()
                .path("access_token"),
            "qits-platform");

    assertNull(claims.getClaimValueAsString("project"), "the owner's grant is not inherited (D3)");
    assertEquals("ws-77", claims.getClaimValueAsString("workspace"), "the commission's own claim");
  }

  @Test
  public void aCommissionMayNotWidenItselfToTheWildcard() {
    // The whole security argument as one status code: a commission narrows. `*` is granted to a
    // service client in configuration, by an operator, and cannot be asked for over the wire.
    commissionRaw(
            OTHER_OWNER,
            OTHER_OWNER_SECRET,
            "{\"contextKind\":\"widen-kind\",\"contextId\":\"ctx-widen\","
                + "\"claims\":{\"project\":\"*\"}}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));

    assertEquals(
        List.of(),
        listedIds(OTHER_OWNER, OTHER_OWNER_SECRET, "widen-kind"),
        "a refused claim leaves no row and no secret behind");
  }

  @Test
  public void aCommissionMayNotInventAClaimName() {
    commissionRaw(
            OTHER_OWNER,
            OTHER_OWNER_SECRET,
            "{\"contextKind\":\"invent-kind\",\"contextId\":\"ctx-invent\","
                + "\"claims\":{\"groups\":\"qits:admin\"}}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));

    assertEquals(List.of(), listedIds(OTHER_OWNER, OTHER_OWNER_SECRET, "invent-kind"));
  }

  @Test
  public void aCommissionThatStatesNothingCarriesNoClaimsAtAll() throws Exception {
    // D3: there is no owner grant left to fall back to. A null column, and a token with no claims.
    Map<String, String> pair = commission(OWNER, OWNER_SECRET, "unstated-kind", "ctx-unstated");

    IdpDynamicClient row =
        QuarkusTransaction.requiringNew().call(() -> repository.findById(pair.get("clientId")));
    assertNull(row.claims, "nothing stated is nothing stored");

    assertNull(
        PublishedJwks.verify(
                token(pair.get("clientId"), pair.get("secret"), "&audience=qits-deployments")
                    .statusCode(200)
                    .extract()
                    .path("access_token"),
                "qits-platform")
            .getClaimValueAsString("project"),
        "no owner claim to inherit any more (D3)");
  }

  @Test
  public void theListingShowsHowEachCommissionIsScoped() {
    // The reconcile read doubles as the operator's answer to "why can this credential not do that".
    commissionRaw(
            OTHER_OWNER,
            OTHER_OWNER_SECRET,
            "{\"contextKind\":\"scoped-listing\",\"contextId\":\"ctx-listed\","
                + "\"claims\":{\"project\":\"" + A_PROJECT + "\"}}")
        .statusCode(201);

    given()
        .header("Authorization", basic(OTHER_OWNER, OTHER_OWNER_SECRET))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .body("find { it.contextKind == 'scoped-listing' }.claims.project", equalTo(A_PROJECT));
  }

  // --- helpers ------------------------------------------------------------------------------

  /**
   * The pair, by path rather than by binding the whole body to a {@code Map<String, String>}. The
   * response has not been flat since commissions could state their claims — {@code claims} is a
   * nested object — and a helper that binds every member would make an unrelated test fail the next
   * time a member is added.
   */
  private static Map<String, String> commission(
      String owner, String secret, String contextKind, String contextId) {
    return pairOf(
        commissionRaw(
                owner,
                secret,
                "{\"contextKind\":\"" + contextKind + "\",\"contextId\":\"" + contextId + "\"}")
            .statusCode(201)
            .header("Cache-Control", "no-store")
            .body("owner", equalTo(owner))
            .body("contextKind", equalTo(contextKind))
            .body("contextId", equalTo(contextId)));
  }

  /** The two members every caller of a commission actually uses. */
  private static Map<String, String> pairOf(ValidatableResponse answer) {
    io.restassured.response.ExtractableResponse<?> body = answer.extract();
    return Map.of("clientId", body.path("clientId"), "secret", body.path("secret"));
  }

  private static ValidatableResponse commissionRaw(String owner, String secret, String body) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(owner, secret))
        .body(body)
        .when()
        .post("/idp/api/clients")
        .then();
  }

  private static ValidatableResponse decommission(String caller, String secret, String clientId) {
    return given()
        .header("Authorization", basic(caller, secret))
        .when()
        .delete("/idp/api/clients/" + clientId)
        .then();
  }

  private static List<String> listedIds(String caller, String secret, String contextKind) {
    return given()
        .header("Authorization", basic(caller, secret))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .extract()
        .path("findAll { it.contextKind == '" + contextKind + "' }.clientId");
  }

  private static ValidatableResponse token(String clientId, String secret, String extraForm) {
    return given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic(clientId, secret))
        .body("grant_type=client_credentials" + extraForm)
        .when()
        .post("/idp/token")
        .then();
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
