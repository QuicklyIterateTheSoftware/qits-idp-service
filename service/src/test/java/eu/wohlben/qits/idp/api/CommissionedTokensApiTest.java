package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.CommissionedTokens;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The commissioned-token API end to end (qits-449): a service client commissions an opaque token
 * for a context, lists its own, and deletes one — or the token deletes itself — after which the
 * very next introspection refuses it. And introspection itself (qits-450): a service client turns a
 * value into the identity behind it and a short JWT minted as for a commissioned client of that
 * kind, verified here against the published JWKS like any other token.
 *
 * <p>The owners are the suite's adopted service clients, {@code test-broad} and {@code test-narrow}, as in
 * {@link CommissionedClientsTest}. Every test names its own {@code contextKind}, because the suite
 * shares one store and a listing check filters on it.
 */
@QuarkusTest
public class CommissionedTokensApiTest {

  private static final String OWNER = "test-broad";
  private static final String OWNER_SECRET = "test-broad-secret";
  private static final String OTHER_OWNER = "test-narrow";
  private static final String OTHER_OWNER_SECRET = "test-narrow-secret";

  @Inject CommissionedTokens tokens;

  @Test
  public void theValueIsAPrefixedOpaqueTokenAndTheSubjectReadsLikeAClientId() {
    ExtractableResponse<?> issued =
        commissionRaw(
                OWNER,
                OWNER_SECRET,
                "{\"contextKind\":\"tok-shape\",\"contextId\":\"Run/4711\","
                    + "\"claims\":{\"project\":\"qits\"},\"gitRefs\":[\"refs/heads/a\"]}")
            .statusCode(201)
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .body("owner", equalTo(OWNER))
            .body("contextKind", equalTo("tok-shape"))
            .body("contextId", equalTo("Run/4711"))
            .body("claims.project", equalTo("qits"))
            .body("gitRefs", equalTo(List.of("refs/heads/a")))
            .extract();

    String token = issued.path("token");
    assertTrue(
        token.matches("qits_tok_[A-Za-z0-9_-]{43}"),
        "the prefix, then 32 random bytes base64url unpadded: " + token);
    String subject = issued.path("subject");
    assertTrue(
        subject.matches("tok-tok-shape-run-4711-[A-Za-z0-9_-]{22}"),
        "tok-<kind>-<context slug>-<random>: " + subject);
    UUID.fromString(issued.path("tokenId"));
  }

  @Test
  public void aCommissionedClientMayNotCommissionAToken() {
    ExtractableResponse<?> client =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic(OWNER, OWNER_SECRET))
            .body("{\"contextKind\":\"tok-spread\",\"contextId\":\"ctx\"}")
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract();

    commissionRaw(
            client.path("clientId"),
            client.path("secret"),
            "{\"contextKind\":\"tok-spread\",\"contextId\":\"ctx-child\"}")
        .statusCode(403)
        .body("error", equalTo("access_denied"));
    assertEquals(List.of(), listedIds(OWNER, OWNER_SECRET, "tok-spread"));
  }

  @Test
  public void aTokenCannotAuthenticateToCommission() {
    String token = commission(OWNER, OWNER_SECRET, "tok-bearer-post", "ctx").path("token");

    given()
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + token)
        .body("{\"contextKind\":\"tok-bearer-post\",\"contextId\":\"ctx-child\"}")
        .when()
        .post("/idp/api/tokens")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void theListingAcceptsTheAgentRoleAndRefusesACallerWithNeither() {
    // A commissioned client of an agent kind holds qits:agent: 200, and its own (empty) listing.
    ExtractableResponse<?> agent = commissionClient("workspace", "tok-list-agent");
    given()
        .header("Authorization", basic(agent.path("clientId"), agent.path("secret")))
        .when()
        .get("/idp/api/tokens")
        .then()
        .statusCode(200)
        .body("size()", equalTo(0));

    // A kind with no role at all: 403, as on the clients door.
    ExtractableResponse<?> none = commissionClient("tok-list-none", "tok-list-none");
    given()
        .header("Authorization", basic(none.path("clientId"), none.path("secret")))
        .when()
        .get("/idp/api/tokens")
        .then()
        .statusCode(403);

    given().when().get("/idp/api/tokens").then().statusCode(401);
  }

  @Test
  public void theListingIsTheOwnersOwnAndNeverCarriesAValue() {
    String kind = "tok-api-listing";
    ExtractableResponse<?> mine = commission(OWNER, OWNER_SECRET, kind, "ctx-mine");
    ExtractableResponse<?> theirs = commission(OTHER_OWNER, OTHER_OWNER_SECRET, kind, "ctx-theirs");

    List<String> ownersOwn = listedIds(OWNER, OWNER_SECRET, kind);
    assertEquals(List.of(mine.<String>path("tokenId")), ownersOwn);
    assertEquals(
        List.of(theirs.<String>path("tokenId")), listedIds(OTHER_OWNER, OTHER_OWNER_SECRET, kind));

    String row = "find { it.tokenId == '" + mine.path("tokenId") + "' }.";
    String document =
        given()
            .header("Authorization", basic(OWNER, OWNER_SECRET))
            .when()
            .get("/idp/api/tokens")
            .then()
            .statusCode(200)
            .body(row + "subject", equalTo(mine.path("subject")))
            .body(row + "owner", equalTo(OWNER))
            .body(row + "contextId", equalTo("ctx-mine"))
            .body(row + "createdAt", org.hamcrest.Matchers.notNullValue())
            .extract()
            .asString();
    assertFalse(document.contains(mine.<String>path("token")), "a listing must not carry a value");
    assertFalse(document.contains("qits_tok_"), "nor any value at all");
    assertFalse(document.contains("tokenHash"), "nor the hash of one");
  }

  @Test
  public void onlyTheOwnerDeletesAndTheNextIntrospectionRefusesIt() {
    ExtractableResponse<?> issued = commission(OWNER, OWNER_SECRET, "tok-api-delete", "ctx");
    String id = issued.path("tokenId");
    String value = issued.path("token");

    delete(basic(OTHER_OWNER, OTHER_OWNER_SECRET), id)
        .statusCode(404)
        .body("error", equalTo("not_found"));
    assertTrue(tokens.introspect(value).isPresent(), "another owner changed nothing");

    delete(basic(OWNER, OWNER_SECRET), id).statusCode(204);

    assertTrue(tokens.introspect(value).isEmpty(), "gone on the very next introspection");
    assertEquals(List.of(), listedIds(OWNER, OWNER_SECRET, "tok-api-delete"));
    delete(basic(OWNER, OWNER_SECRET), id).statusCode(404);
  }

  @Test
  public void anUnknownIdAndAMalformedIdAreTheSame404() {
    delete(basic(OWNER, OWNER_SECRET), UUID.randomUUID().toString())
        .statusCode(404)
        .body("error", equalTo("not_found"));
    delete(basic(OWNER, OWNER_SECRET), "not-a-uuid")
        .statusCode(404)
        .body("error", equalTo("not_found"));
  }

  @Test
  public void aTokenMayHandItselfBackAndNothingElse() {
    ExtractableResponse<?> own = commission(OWNER, OWNER_SECRET, "tok-self", "ctx-own");
    ExtractableResponse<?> sibling = commission(OWNER, OWNER_SECRET, "tok-self", "ctx-sibling");

    // A live token naming a different id is told what an unknown id is told.
    delete("Bearer " + own.path("token"), sibling.path("tokenId")).statusCode(404);
    assertTrue(tokens.introspect(sibling.<String>path("token")).isPresent());

    delete("Bearer " + own.path("token"), own.path("tokenId")).statusCode(204);
    assertTrue(tokens.introspect(own.<String>path("token")).isEmpty());

    // And once gone it authenticates nothing.
    delete("Bearer " + own.path("token"), own.path("tokenId"))
        .statusCode(401)
        .body("error", equalTo("invalid_client"));

    delete(basic(OWNER, OWNER_SECRET), sibling.path("tokenId")).statusCode(204);
  }

  @Test
  public void aRefusedClaimOrRefIsA400WithNothingWritten() {
    commissionRaw(
            OWNER,
            OWNER_SECRET,
            "{\"contextKind\":\"tok-bad-claim\",\"contextId\":\"ctx\","
                + "\"claims\":{\"project\":\"*\"}}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    commissionRaw(
            OWNER,
            OWNER_SECRET,
            "{\"contextKind\":\"tok-bad-claim\",\"contextId\":\"ctx\","
                + "\"gitRefs\":[\"refs/tags/v1\"]}")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    commissionRaw(OWNER, OWNER_SECRET, "{\"contextKind\":\"CI Run\",\"contextId\":\"ctx\"}")
        .statusCode(400);

    assertEquals(List.of(), listedIds(OWNER, OWNER_SECRET, "tok-bad-claim"));
  }

  // --- introspection (qits-450) -----------------------------------------------------------------

  @Test
  public void introspectionAnswersTheTokenAndAJwtMintedAsForACommissionedClient() throws Exception {
    ExtractableResponse<?> issued =
        commissionRaw(
                OWNER,
                OWNER_SECRET,
                "{\"contextKind\":\"ci-run\",\"contextId\":\"tok-introspect\","
                    + "\"claims\":{\"project\":\"qits\"},\"gitRefs\":[\"refs/heads/a\"]}")
            .statusCode(201)
            .extract();
    String subject = issued.path("subject");

    ExtractableResponse<?> answer =
        introspect(basic(OWNER, OWNER_SECRET), issued.path("token"))
            .statusCode(200)
            .header("Cache-Control", "no-store")
            .body("tokenId", equalTo(issued.path("tokenId")))
            .body("subject", equalTo(subject))
            .body("roles", equalTo(List.of("qits:ci-run", "clients/" + subject)))
            .body("claims.project", equalTo("qits"))
            .body("gitRefs", equalTo(List.of("refs/heads/a")))
            .body("contextKind", equalTo("ci-run"))
            .body("contextId", equalTo("tok-introspect"))
            .body("expiresIn", equalTo(300))
            .extract();

    JwtClaims claims = PublishedJwks.verify(answer.path("accessToken"), "qits-platform");
    assertEquals(subject, claims.getSubject());
    assertEquals(
        List.of("qits:ci-run", "clients/" + subject),
        claims.getStringListClaimValue("groups"),
        "the kind's role and the token's own self-role; never the owner's");
    assertEquals(
        List.of("qits-platform"),
        PublishedJwks.audienceOf(claims),
        "the one audience, like every token's — nothing is read from the owner");
    assertEquals("ci-run", claims.getClaimValueAsString("context_kind"));
    assertEquals(List.of("refs/heads/a"), claims.getStringListClaimValue("git_refs"));
    assertEquals("qits", claims.getClaimValueAsString("project"), "the stated claim, verbatim");
    assertEquals(
        300L,
        claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue(),
        "qits.idp.token-introspection-jwt-ttl-seconds, not the client token's hour");
  }

  @Test
  public void aTokenThatStatedNoRefsCarriesNoGitRefsClaim() throws Exception {
    String token = commission(OWNER, OWNER_SECRET, "tok-introspect-bare", "ctx").path("token");

    JwtClaims claims =
        PublishedJwks.verify(
            introspect(basic(OWNER, OWNER_SECRET), token)
                .statusCode(200)
                .extract()
                .path("accessToken"),
            "qits-platform");
    assertFalse(claims.hasClaim("git_refs"), "no list stated, no claim — as for a client");
    assertFalse(claims.hasClaim("project"), "and no owner claim inherited");
  }

  @Test
  public void aDeletedTokenIsA404OnTheVeryNextIntrospection() {
    ExtractableResponse<?> issued = commission(OWNER, OWNER_SECRET, "tok-introspect-gone", "ctx");
    introspect(basic(OWNER, OWNER_SECRET), issued.path("token")).statusCode(200);

    delete(basic(OWNER, OWNER_SECRET), issued.path("tokenId")).statusCode(204);

    introspect(basic(OWNER, OWNER_SECRET), issued.path("token"))
        .statusCode(404)
        .body("error", equalTo("not_found"));
  }

  @Test
  public void onlyAServiceClientIntrospects() {
    String token = commission(OWNER, OWNER_SECRET, "tok-introspect-who", "ctx").path("token");
    ExtractableResponse<?> client = commissionClient("tok-introspect-who", "ctx-client");

    introspect(basic(client.path("clientId"), client.path("secret")), token)
        .statusCode(403)
        .body("error", equalTo("access_denied"));
    introspect("Bearer " + token, token).statusCode(401);
    given()
        .contentType(ContentType.JSON)
        .body("{\"token\":\"" + token + "\"}")
        .when()
        .post("/idp/api/tokens/introspect")
        .then()
        .statusCode(401);
  }

  @Test
  public void garbageAndJwtsAre404AndABlankValueIs400() {
    introspect(basic(OWNER, OWNER_SECRET), "qits_tok_" + "A".repeat(43))
        .statusCode(404)
        .body("error", equalTo("not_found"));
    introspect(basic(OWNER, OWNER_SECRET), "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln")
        .statusCode(404)
        .body("error", equalTo("not_found"));
    introspect(basic(OWNER, OWNER_SECRET), "   ")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(OWNER, OWNER_SECRET))
        .body("{}")
        .when()
        .post("/idp/api/tokens/introspect")
        .then()
        .statusCode(400);
  }

  // --- helpers ------------------------------------------------------------------------------

  private static ValidatableResponse introspect(String authorization, String token) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", authorization)
        .body("{\"token\":\"" + token + "\"}")
        .when()
        .post("/idp/api/tokens/introspect")
        .then();
  }

  static ExtractableResponse<?> commission(
      String owner, String secret, String contextKind, String contextId) {
    return commissionRaw(
            owner,
            secret,
            "{\"contextKind\":\"" + contextKind + "\",\"contextId\":\"" + contextId + "\"}")
        .statusCode(201)
        .extract();
  }

  static ValidatableResponse commissionRaw(String owner, String secret, String body) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(owner, secret))
        .body(body)
        .when()
        .post("/idp/api/tokens")
        .then();
  }

  /** A commissioned CLIENT of this kind, owned by {@link #OWNER} — a caller that is no service. */
  static ExtractableResponse<?> commissionClient(String contextKind, String contextId) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(OWNER, OWNER_SECRET))
        .body("{\"contextKind\":\"" + contextKind + "\",\"contextId\":\"" + contextId + "\"}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(201)
        .extract();
  }

  private static ValidatableResponse delete(String authorization, String tokenId) {
    return given()
        .header("Authorization", authorization)
        .when()
        .delete("/idp/api/tokens/" + tokenId)
        .then();
  }

  private static List<String> listedIds(String caller, String secret, String contextKind) {
    return given()
        .header("Authorization", basic(caller, secret))
        .when()
        .get("/idp/api/tokens")
        .then()
        .statusCode(200)
        .extract()
        .path("findAll { it.contextKind == '" + contextKind + "' }.tokenId");
  }

  static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
