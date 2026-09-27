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
import org.junit.jupiter.api.Test;

/**
 * The commissioned-token API end to end (qits-449): a service client commissions an opaque token
 * for a context, lists its own, and deletes one — or the token deletes itself — after which the
 * very next introspection refuses it.
 *
 * <p>The owners are the suite's static clients, {@code test-broad} and {@code test-narrow}, as in
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

  // --- helpers ------------------------------------------------------------------------------

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
