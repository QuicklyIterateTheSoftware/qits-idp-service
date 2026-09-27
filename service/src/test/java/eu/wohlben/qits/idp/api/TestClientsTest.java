package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.ValidatableResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * Test clients end to end (qits-439): an agent commissions a {@code test-client} for itself, the
 * test client commissions a {@code ci-run} or {@code ci-runner-registration} token and nothing
 * else, and the agent deletes the test client when it is done — after which that client's tokens
 * are refused at introspection. It exists so an agent can prove commissioned tokens live without
 * ever holding {@code qits:system}.
 *
 * <p><b>The "agent" is a {@code workspace} commission of the suite's {@code test-broad}</b>, which
 * is what an agent is on the platform: a commissioned client whose kind gives it {@code
 * qits:agent}. Every test makes its own agents and its own context ids, because the suite shares
 * one store.
 */
@QuarkusTest
public class TestClientsTest {

  private static final String SERVICE = "test-broad";
  private static final String SERVICE_SECRET = "test-broad-secret";

  /** Both refusals, verbatim: the commissioned-client one is today's and must stay today's. */
  private static final String NOT_ANOTHER = "a commissioned client may not commission another";

  private static final String TEST_KINDS_ONLY =
      "a test client may commission only ci-run and ci-runner-registration tokens";

  /** A commission answer's id and secret. */
  private record Pair(String clientId, String secret) {
    String basic() {
      return TestClientsTest.basic(clientId, secret);
    }
  }

  // --- who may commission a test client ---------------------------------------------------------

  @Test
  public void anAgentCommissionsATestClientThatHoldsOnlyTheTokenTestRole() throws Exception {
    Pair agent = agent("tc-shape");

    ExtractableResponse<?> issued =
        commissionClient(agent.basic(), "test-client", "tc-shape")
            .statusCode(201)
            .body("owner", equalTo(agent.clientId()))
            .body("contextKind", equalTo("test-client"))
            .extract();
    Pair testClient = new Pair(issued.path("clientId"), issued.path("secret"));
    assertTrue(
        testClient.clientId().startsWith("dyn-test-client-tc-shape-"),
        "an ordinary commissioned id: " + testClient.clientId());

    JwtClaims claims = clientToken(testClient);
    assertEquals(
        List.of("qits:token-test", "clients/" + testClient.clientId()),
        claims.getStringListClaimValue("groups"),
        "the kind's one role and its self-role; never qits:agent, never qits:system");

    // The agent sees what it commissioned on the listing it already reads.
    List<String> listed =
        given()
            .header("Authorization", agent.basic())
            .when()
            .get("/idp/api/clients")
            .then()
            .statusCode(200)
            .extract()
            .path("clientId");
    assertEquals(List.of(testClient.clientId()), listed);
  }

  @Test
  public void anAgentMayCommissionNoOtherKind() {
    Pair agent = agent("tc-agent-other");
    for (String kind : List.of("ci-run", "workspace", "ci-runner", "some-unknown-kind")) {
      commissionClient(agent.basic(), kind, "tc-agent-other")
          .statusCode(403)
          .body("error", equalTo("access_denied"))
          .body("error_description", equalTo(NOT_ANOTHER));
    }
    // A body with no kind at all is today's 403 too, not a 400 that would say more.
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", agent.basic())
        .body("{\"contextId\":\"tc-agent-other\"}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(403);
  }

  @Test
  public void aCommissionedClientWithoutTheAgentRoleMayNotCommissionATestClient() {
    Pair ciRun = created(basic(SERVICE, SERVICE_SECRET), "ci-run", "tc-not-agent");
    commissionClient(ciRun.basic(), "test-client", "tc-not-agent")
        .statusCode(403)
        .body("error_description", equalTo(NOT_ANOTHER));
  }

  @Test
  public void aTestClientMayCommissionNoClientOfAnyKind() {
    Pair testClient = testClient(agent("tc-no-chain"), "tc-no-chain");
    for (String kind : List.of("test-client", "workspace", "ci-run", "some-unknown-kind")) {
      commissionClient(testClient.basic(), kind, "tc-no-chain-child")
          .statusCode(403)
          .body("error_description", equalTo(NOT_ANOTHER));
    }
  }

  @Test
  public void anAgentsTestClientStillValidatesItsClaimsAndRefs() {
    Pair agent = agent("tc-validate");
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", agent.basic())
        .body(
            "{\"contextKind\":\"test-client\",\"contextId\":\"tc-validate\","
                + "\"claims\":{\"project\":\"*\"}}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", agent.basic())
        .body(
            "{\"contextKind\":\"test-client\",\"contextId\":\"tc-validate\","
                + "\"gitRefs\":[\"refs/tags/v1\"]}")
        .when()
        .post("/idp/api/clients")
        .then()
        .statusCode(400);
  }

  // --- what a test client may do on /idp/api/tokens ---------------------------------------------

  @Test
  public void aTestClientCommissionsCiRunAndRegistrationTokensAndNothingElse() {
    Pair testClient = testClient(agent("tc-kinds"), "tc-kinds");

    commissionToken(
            testClient.basic(),
            "{\"contextKind\":\"ci-run\",\"contextId\":\"tc-kinds\","
                + "\"gitRefs\":[\"refs/heads/ticket/tc-kinds\"]}")
        .statusCode(201)
        .body("owner", equalTo(testClient.clientId()))
        .body("contextKind", equalTo("ci-run"))
        .body("gitRefs", equalTo(List.of("refs/heads/ticket/tc-kinds")));
    commissionToken(testClient.basic(), tokenBody("ci-runner-registration", "tc-kinds"))
        .statusCode(201)
        .body("owner", equalTo(testClient.clientId()));

    for (String kind : List.of("workspace", "ci-runner", "test-client", "some-unknown-kind")) {
      commissionToken(testClient.basic(), tokenBody(kind, "tc-kinds"))
          .statusCode(403)
          .body("error", equalTo("access_denied"))
          .body("error_description", equalTo(TEST_KINDS_ONLY));
    }
  }

  @Test
  public void anAgentStillMayNotCommissionAToken() {
    commissionToken(agent("tc-agent-token").basic(), tokenBody("ci-run", "tc-agent-token"))
        .statusCode(403)
        .body("error_description", equalTo("a commissioned client may not commission a token"));
  }

  @Test
  public void aTestClientMayNotIntrospect() {
    Pair testClient = testClient(agent("tc-introspect-who"), "tc-introspect-who");
    String token = testToken(testClient, "tc-introspect-who").path("token");

    introspect(testClient.basic(), token).statusCode(403).body("error", equalTo("access_denied"));
  }

  @Test
  public void aTestTokenIsIssuedItsAgentsAudiencesAndNeverMore() throws Exception {
    Pair agent = agent("tc-aud");
    Pair testClient = testClient(agent, "tc-aud");
    String subject = testToken(testClient, "tc-aud").path("subject");
    String token = testToken(testClient, "tc-aud-2").path("token");

    List<String> agentsAud = PublishedJwks.audienceOf(clientToken(agent));
    JwtClaims introspected =
        PublishedJwks.verify(
            introspect(basic(SERVICE, SERVICE_SECRET), token)
                .statusCode(200)
                .body("roles[0]", equalTo("qits:ci-run"))
                .extract()
                .path("accessToken"),
            "qits-platform");
    List<String> aud = PublishedJwks.audienceOf(introspected);

    assertTrue(aud.contains("qits-platform"), "always qits-platform: " + aud);
    assertTrue(agentsAud.containsAll(aud), "never wider than the agent: " + aud + " " + agentsAud);
    // Two hops: test client -> agent -> test-broad. The agent's own owner's list, plus qits-platform.
    assertEquals(List.of("prod-qits-ci", "qits-deployments", "qits-platform"), aud);
    assertEquals(agentsAud, PublishedJwks.audienceOf(clientToken(testClient)));
    assertTrue(subject.startsWith("tok-ci-run-tc-aud-"), subject);
  }

  @Test
  public void aTestClientWhoseAgentIsGoneGetsQitsPlatformAlone() throws Exception {
    Pair agent = agent("tc-orphan");
    Pair testClient = testClient(agent, "tc-orphan");
    String token = testToken(testClient, "tc-orphan").path("token");

    // The agent's own owner decommissions it; the test client it made is still there.
    decommission(basic(SERVICE, SERVICE_SECRET), agent.clientId()).statusCode(204);

    assertEquals(
        List.of("qits-platform"),
        PublishedJwks.audienceOf(clientToken(testClient)),
        "an unresolvable chain is qits-platform, never an error and never wider");
    assertEquals(
        List.of("qits-platform"),
        PublishedJwks.audienceOf(
            PublishedJwks.verify(
                introspect(basic(SERVICE, SERVICE_SECRET), token)
                    .statusCode(200)
                    .extract()
                    .path("accessToken"),
                "qits-platform")));
    // And asking for anything more is refused, not granted.
    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", testClient.basic())
        .body("grant_type=client_credentials&audience=prod-qits-ci")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_target"));
  }

  @Test
  public void aTestClientListsOnlyItsOwnTokensAndDeletesOne() {
    Pair agent = agent("tc-list");
    Pair mine = testClient(agent, "tc-list-mine");
    Pair theirs = testClient(agent, "tc-list-theirs");
    String own = testToken(mine, "tc-list").path("tokenId");
    String other = testToken(theirs, "tc-list").path("tokenId");

    assertEquals(List.of(own), listedTokens(mine));
    assertEquals(List.of(other), listedTokens(theirs));
    // The agent owns neither token, so its listing (it may read) holds none of them.
    assertEquals(List.of(), listedTokens(agent));

    deleteToken(mine.basic(), other).statusCode(404);
    deleteToken(mine.basic(), own).statusCode(204);
    assertEquals(List.of(), listedTokens(mine));
    assertEquals(List.of(other), listedTokens(theirs));
  }

  // --- cleanup ----------------------------------------------------------------------------------

  @Test
  public void theAgentDeletesItsTestClientAndItsTokensAreRefused() {
    Pair agent = agent("tc-cleanup");
    Pair testClient = testClient(agent, "tc-cleanup");
    String token = testToken(testClient, "tc-cleanup").path("token");
    introspect(basic(SERVICE, SERVICE_SECRET), token).statusCode(200);

    decommission(agent.basic(), testClient.clientId()).statusCode(204);

    introspect(basic(SERVICE, SERVICE_SECRET), token)
        .statusCode(404)
        .body("error", equalTo("not_found"));
    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", testClient.basic())
        .body("grant_type=client_credentials")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401);
  }

  @Test
  public void anotherAgentDeletingATestClientIsA404() throws Exception {
    Pair agent = agent("tc-foreign");
    Pair stranger = agent("tc-foreign-stranger");
    Pair testClient = testClient(agent, "tc-foreign");

    decommission(stranger.basic(), testClient.clientId())
        .statusCode(404)
        .body("error", equalTo("not_found"));
    clientToken(testClient);

    decommission(agent.basic(), testClient.clientId()).statusCode(204);
  }

  @Test
  public void anAgentStillMayNotDeleteAnythingButItsTestClients() {
    Pair agent = agent("tc-delete-scope");
    Pair sibling = agent("tc-delete-scope-sibling");
    Pair testClient = testClient(agent, "tc-delete-scope");

    // Another agent's own credential: today's 403, the widening is for test-client rows alone.
    decommission(agent.basic(), sibling.clientId()).statusCode(403);
    // A test client may delete nothing but itself — not its sibling, not its agent.
    Pair sibling2 = testClient(agent, "tc-delete-scope-2");
    decommission(testClient.basic(), sibling2.clientId()).statusCode(403);
    decommission(testClient.basic(), agent.clientId()).statusCode(403);
    decommission(testClient.basic(), testClient.clientId()).statusCode(204);
  }

  // --- helpers ----------------------------------------------------------------------------------

  /** An agent: a {@code workspace} commission of a service client, which holds {@code qits:agent}. */
  private static Pair agent(String contextId) {
    return created(basic(SERVICE, SERVICE_SECRET), "workspace", contextId);
  }

  private static Pair testClient(Pair agent, String contextId) {
    return created(agent.basic(), "test-client", contextId);
  }

  private static Pair created(String authorization, String kind, String contextId) {
    ExtractableResponse<?> answer =
        commissionClient(authorization, kind, contextId).statusCode(201).extract();
    return new Pair(answer.path("clientId"), answer.path("secret"));
  }

  private static ExtractableResponse<?> testToken(Pair testClient, String contextId) {
    return commissionToken(testClient.basic(), tokenBody("ci-run", contextId))
        .statusCode(201)
        .extract();
  }

  private static ValidatableResponse commissionClient(
      String authorization, String kind, String contextId) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", authorization)
        .body(tokenBody(kind, contextId))
        .when()
        .post("/idp/api/clients")
        .then();
  }

  private static String tokenBody(String kind, String contextId) {
    return "{\"contextKind\":\"" + kind + "\",\"contextId\":\"" + contextId + "\"}";
  }

  private static ValidatableResponse commissionToken(String authorization, String body) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", authorization)
        .body(body)
        .when()
        .post("/idp/api/tokens")
        .then();
  }

  private static ValidatableResponse introspect(String authorization, String token) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", authorization)
        .body("{\"token\":\"" + token + "\"}")
        .when()
        .post("/idp/api/tokens/introspect")
        .then();
  }

  private static List<String> listedTokens(Pair caller) {
    return given()
        .header("Authorization", caller.basic())
        .when()
        .get("/idp/api/tokens")
        .then()
        .statusCode(200)
        .extract()
        .path("tokenId");
  }

  private static ValidatableResponse deleteToken(String authorization, String tokenId) {
    return given()
        .header("Authorization", authorization)
        .when()
        .delete("/idp/api/tokens/" + tokenId)
        .then();
  }

  private static ValidatableResponse decommission(String authorization, String clientId) {
    return given()
        .header("Authorization", authorization)
        .when()
        .delete("/idp/api/clients/" + clientId)
        .then();
  }

  /** A {@code client_credentials} token for this pair, asking for nothing, verified. */
  private static JwtClaims clientToken(Pair client) throws Exception {
    String jwt =
        given()
            .contentType(ContentType.URLENC)
            .header("Authorization", client.basic())
            .body("grant_type=client_credentials")
            .when()
            .post("/idp/token")
            .then()
            .statusCode(200)
            .extract()
            .path("access_token");
    return PublishedJwks.verify(jwt, "qits-platform");
  }

  static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
