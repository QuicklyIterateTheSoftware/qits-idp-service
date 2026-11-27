package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.CommissionedTokens;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.SigningKeys;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.Test;

/**
 * {@code GET /idp/api/user-subjects} (qits-2725): every account's subject and username, for the
 * callers that may change a toggle's rules — a {@code qits:admin} person (bearer or session), the
 * delivery desk ({@code qits:desk-admin}) and a static {@code qits:system} client over Basic — and
 * refused to every other.
 *
 * <p>The suite shares one store, so each case invents its own usernames and asserts on its own rows
 * and on order rather than on a count.
 */
@QuarkusTest
public class UserSubjectsTest {

  private static final String DOOR = "/idp/api/user-subjects";
  private static final String SYSTEM = "test-broad";
  private static final String SYSTEM_SECRET = "test-broad-secret";

  @Inject TokenService tokenService;

  @Inject Sessions sessions;

  @Inject SigningKeys signingKeys;

  @Inject CommissionedTokens commissionedTokens;

  /**
   * THE SUBJECT IS THE TOKEN'S SUB. What a toggles USER rule matches is the bearer's {@code sub};
   * the listing's {@code subject} for a person must be exactly the {@code sub} of the token that
   * person is minted, or a picked person would never match.
   */
  @Test
  public void anAdminBearerListsEachAccountsSubjectAsItsTokensSub() throws Exception {
    UUID admin = person("subjects-admin-", List.of("qits:admin"));
    UUID plain = person("subjects-plain-", List.of());
    String bearer = tokenService.cli(admin).accessToken();

    Response answer = given().header("Authorization", "Bearer " + bearer).when().get(DOOR);
    answer.then().statusCode(200).header("Cache-Control", "no-store");

    List<Map<String, Object>> rows = answer.jsonPath().getList("$");
    Map<String, Object> plainRow = rowFor(rows, plain);
    assertEquals(Map.of("subject", plain.toString(), "username", usernameOf(plain)), plainRow);
    assertFalse(plainRow.containsKey("roles"), "the answer carries no roles");
    assertFalse(plainRow.containsKey("createdAt"), "the answer carries no instant");

    String plainSub =
        new JwtConsumerBuilder()
            .setSkipAllValidators()
            .setDisableRequireSignature()
            .setSkipSignatureVerification()
            .build()
            .processToClaims(tokenService.cli(plain).accessToken())
            .getSubject();
    assertEquals(plainSub, plainRow.get("subject"));
  }

  @Test
  public void theListingIsSortedByUsername() {
    String bearer = tokenService.cli(person("subjects-sort-", List.of("qits:admin"))).accessToken();
    List<String> names =
        given()
            .header("Authorization", "Bearer " + bearer)
            .when()
            .get(DOOR)
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .getList("username", String.class);
    List<String> sorted = new ArrayList<>(names);
    sorted.sort(null);
    assertEquals(sorted, names);
  }

  @Test
  public void theDeskReadsWhereTheAdminDoorsRefuseIt() {
    UUID plain = person("subjects-desk-", List.of());
    for (String bearer :
        List.of(signedWithRole("qits:desk-admin"), commissionedToken("desk-delivery"))) {
      List<Map<String, Object>> rows =
          given()
              .header("Authorization", "Bearer " + bearer)
              .when()
              .get(DOOR)
              .then()
              .statusCode(200)
              .header("Cache-Control", "no-store")
              .extract()
              .jsonPath()
              .getList("$");
      assertEquals(plain.toString(), rowFor(rows, plain).get("subject"));
      // The user administration listing stays the mint's callers': the desk is refused there.
      given()
          .header("Authorization", "Bearer " + bearer)
          .when()
          .get("/idp/api/users")
          .then()
          .statusCode(403);
    }
  }

  @Test
  public void anAdminSessionAndTheSystemClientRead() {
    UUID admin = person("subjects-session-", List.of("qits:admin"));
    String session =
        sessions.open(new Users.Account(admin, usernameOf(admin), List.of("qits:admin"))).token();
    given().cookie(SessionCookie.NAME, session).when().get(DOOR).then().statusCode(200);
    given()
        .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
        .when()
        .get(DOOR)
        .then()
        .statusCode(200);
  }

  /**
   * NO AGENT READS THE ROSTER. {@code qits:agent} and {@code qits:admin-agent} are refused, so is a
   * person without {@code qits:admin}, and so is an admin demoted since the token was minted.
   */
  @Test
  public void everyOtherBearerIsRefused() {
    UUID plain = person("subjects-refused-", List.of());
    UUID demoted = person("subjects-demoted-", List.of("qits:admin"));
    String demotedBearer = tokenService.cli(demoted).accessToken();
    QuarkusTransaction.requiringNew()
        .run(() -> IdpUserRole.delete("userId = ?1 and role = ?2", demoted, "qits:admin"));

    for (String bearer :
        List.of(
            signedWithRole("qits:agent"),
            signedWithRole("qits:admin-agent"),
            commissionedToken("workspace"),
            tokenService.cli(plain).accessToken(),
            demotedBearer)) {
      given()
          .header("Authorization", "Bearer " + bearer)
          .when()
          .get(DOOR)
          .then()
          .statusCode(403)
          .body("error", equalTo("access_denied"));
    }
  }

  /**
   * THE OPAQUE TOKEN IS WHAT ARRIVES. An agent's and the desk's {@code QITS_TOKEN} is a commissioned
   * {@code qits_tok_} value, and the edge passes it to idp's own route unexchanged. Live, it
   * authenticated: the desk's reads the roster and a project agent's is 403, not the 401 it got
   * while the bearer check knew only JWTs. A deleted one did not authenticate and stays 401.
   */
  @Test
  public void aCommissionedTokenIsJudgedByItsRolesNotRefusedAsUnauthenticated() {
    UUID plain = person("subjects-opaque-", List.of());
    String desk = opaqueToken("desk-delivery", "subjects-" + UUID.randomUUID());
    List<Map<String, Object>> rows =
        given()
            .header("Authorization", "Bearer " + desk)
            .when()
            .get(DOOR)
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .getList("$");
    assertEquals(plain.toString(), rowFor(rows, plain).get("subject"));
    given().header("Authorization", "Bearer " + desk).when().get("/idp/api/users")
        .then().statusCode(403).body("error", equalTo("access_denied"));

    String agentContext = "qits-a" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    for (String agent :
        List.of(
            opaqueToken("project-agent", agentContext),
            opaqueToken("workspace-admin", "subjects-" + UUID.randomUUID()))) {
      given()
          .header("Authorization", "Bearer " + agent)
          .when()
          .get(DOOR)
          .then()
          .statusCode(403)
          .body("error", equalTo("access_denied"));
    }

    CommissionedTokens.Commissioned gone =
        commissionedTokens.commission(
            SYSTEM, "desk-delivery", "subjects-" + UUID.randomUUID(), Map.of(), List.of());
    assertTrue(commissionedTokens.delete(gone.token().id(), SYSTEM));
    given()
        .header("Authorization", "Bearer " + gone.value())
        .when()
        .get(DOOR)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_token"));
  }

  @Test
  public void aCommissionedBasicClientIsRefusedAndNoCredentialIs401() {
    Response commissioned = commission("workspace");
    given()
        .header(
            "Authorization",
            basic(commissioned.path("clientId"), commissioned.path("secret")))
        .when()
        .get(DOOR)
        .then()
        .statusCode(403);
    given().when().get(DOOR).then().statusCode(401);
    given()
        .header("Authorization", "Bearer not-a-jwt")
        .when()
        .get(DOOR)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_token"));
  }

  // --- helpers ----------------------------------------------------------------------------------

  private static Map<String, Object> rowFor(List<Map<String, Object>> rows, UUID id) {
    List<Map<String, Object>> matching =
        rows.stream().filter(row -> id.toString().equals(row.get("subject"))).toList();
    assertTrue(matching.size() == 1, "exactly one row for " + id + ": " + matching);
    return matching.get(0);
  }

  /** An account made directly in the store, holding exactly these roles. */
  private static UUID person(String prefix, List<String> granted) {
    UUID id = UUID.randomUUID();
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpUser row = new IdpUser();
              row.id = id;
              row.username = prefix + id;
              row.createdAt = Instant.now();
              row.persist();
              for (String role : granted) {
                IdpUserRole grant = new IdpUserRole();
                grant.userId = id;
                grant.role = role;
                grant.createdAt = Instant.now();
                grant.persist();
              }
            });
    return id;
  }

  private static String usernameOf(UUID id) {
    return QuarkusTransaction.requiringNew()
        .call(() -> ((IdpUser) IdpUser.findById(id)).username);
  }

  /** A JWT this idp signed, holding exactly one role and naming no account. */
  private String signedWithRole(String role) {
    SigningKeys.SigningKey key = signingKeys.signing();
    Instant now = Instant.now();
    return Jwt.claims()
        .issuer(PublishedJwks.ISSUER)
        .subject("user-subjects-reader")
        .audience(TokenService.PLATFORM_AUDIENCE)
        .groups(role)
        .issuedAt(now)
        .expiresAt(now.plusSeconds(300))
        .jws()
        .keyId(key.kid())
        .sign(key.privateKey());
  }

  private static Response commission(String kind) {
    Response created =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
            .body(
                "{\"contextKind\":\""
                    + kind
                    + "\",\"contextId\":\"subjects-"
                    + UUID.randomUUID()
                    + "\"}")
            .when()
            .post("/idp/api/clients");
    created.then().statusCode(201);
    return created;
  }

  /** A real commission of this kind, and the token it mints for {@code qits-platform}. */
  private static String commissionedToken(String kind) {
    Response pair = commission(kind);
    return given()
        .contentType(ContentType.URLENC)
        .body(
            "grant_type=client_credentials&client_id="
                + pair.path("clientId")
                + "&client_secret="
                + pair.path("secret")
                + "&audience=qits-platform")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(200)
        .extract()
        .path("access_token");
  }

  /** A commissioned opaque {@code qits_tok_} value of this kind — what QITS_TOKEN holds. */
  private String opaqueToken(String kind, String contextId) {
    return commissionedTokens.commission(SYSTEM, kind, contextId, Map.of(), List.of()).value();
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
