package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The CLI sign-in walk: the bounce, the code page, the paste, the rotation, and the two fences.
 *
 * <p>Written beside {@link WorkstationOAuthTest} and deliberately in its shape, because the two
 * clients share one store and one endpoint pair — so the interesting assertions are the ones that
 * say they are still separate: a code approved for one cannot be spent by the other, and neither
 * can a refresh token.
 *
 * <p>The addresses are the SHIPPED ones, not test-only overrides. The canonical origin is
 * {@code http://localhost:8080} — what {@link PlatformDomain} derives with no domain stated — and
 * the endpoint base is the platform-network address the discovery document advertises, and this
 * suite pins both spellings of the code page: an installation answers on two addresses and a CLI
 * configured from the discovery document knows only the second. The issuer is not a third: it is
 * {@code https://idp.qits.<domain>} with no path (qits-730), so it names no page.
 */
@QuarkusTest
public class CliOAuthTest {

  private static final String CLIENT = "qits-cli";
  private static final String WORKSTATION_CLIENT = "qits-git-workstation";
  private static final String WORKSTATION_AUDIENCE = "prod-qits-githost";
  private static final String WORKSTATION_REDIRECT = "http://127.0.0.1:38472/callback";

  /** The page a browser loads, built from the canonical origin. */
  private static final String PAGE = "http://localhost:8080/idp/connect/cli";

  /** The same page on the address the discovery document advertises. */
  private static final String ADDRESS_PAGE = PublishedJwks.ENDPOINT_BASE + "/connect/cli";

  /** The issuer with the page's path hung off it — a page this service does not serve. */
  private static final String ISSUER_PAGE = PublishedJwks.ISSUER + "/connect/cli";

  private static final String VERIFIER =
      "cli-verifier-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

  @Inject IdpUserRepository users;

  @Inject Sessions sessions;

  @Test
  public void aSignedInPersonGetsACodeOnThePageAndTradesItForTheirOwnRoles() throws Exception {
    Sessions.Opened session = signedInSession();
    String code = authorize(session.token(), PAGE, VERIFIER, "state-that-must-return");

    Response exchanged = token(CLIENT, "authorization_code", PAGE, code, VERIFIER, null);
    exchanged
        .then()
        .statusCode(200)
        .body("token_type", equalTo("Bearer"))
        .body("expires_in", equalTo(900))
        // Not RFC 6749, and the reason it is here is that the RFC gives a client no way to learn
        // when its refresh credential dies. 720 hours, the shared family TTL.
        .body("refresh_expires_in", equalTo(720 * 3600));

    String access = exchanged.jsonPath().getString("access_token");
    String firstRefresh = exchanged.jsonPath().getString("refresh_token");

    JwtClaims claims = PublishedJwks.verify(access, "qits-platform");
    assertEquals(session.session().userId().toString(), claims.getSubject());
    assertEquals("cli", claims.getClaimValueAsString("credential_type"));
    // The person's OWN roles, which is the epic's decision: the CLI is as strong as the browser
    // session the same person just signed in with.
    assertEquals(List.of("qits:admin"), claims.getStringListClaimValue("groups"));
    // The one platform-wide audience, and nothing the request asked for. The roles above are the
    // permission; the audience only says "any qits service".
    assertEquals(List.of("qits-platform"), claims.getAudience());
    // A person is not a machine client, so no `clients/…` stamp — the same rule the workstation
    // token keeps, and the reason a resource service may gate a door on that prefix.
    assertFalse(
        claims.getStringListClaimValue("groups").stream().anyMatch(g -> g.startsWith("clients/")),
        "only a client credential names a client");
    // The workstation's old claim stays off: this token is not the workstation's.
    assertEquals(null, claims.getClaimValueAsString("git_ref_pattern"));
    // But a person pushes only external/*, whatever their roles (principal-bound-git-refs-plan.md,
    // C1) — qits:admin above does not widen it.
    assertEquals(List.of("refs/heads/external/*"), claims.getStringListClaimValue("git_refs"));

    Response refreshed = token(CLIENT, "refresh_token", null, null, null, firstRefresh);
    refreshed.then().statusCode(200).body("expires_in", equalTo(900));
    String secondRefresh = refreshed.jsonPath().getString("refresh_token");
    assertNotEquals(firstRefresh, secondRefresh, "a refresh credential rotates on every use");

    // Replaying the spent value revokes the family, including the token rotation just produced.
    token(CLIENT, "refresh_token", null, null, null, firstRefresh)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
    token(CLIENT, "refresh_token", null, null, null, secondRefresh)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
  }

  @Test
  public void anAnonymousAuthorizeBouncesToSignInAndComesBackHere() {
    String bounce =
        given()
            .redirects()
            .follow(false)
            .queryParam("response_type", "code")
            .queryParam("client_id", CLIENT)
            .queryParam("redirect_uri", PAGE)
            .queryParam("code_challenge", challenge(VERIFIER))
            .queryParam("code_challenge_method", "S256")
            .queryParam("state", "back-again")
            .when()
            .get("/idp/authorize")
            .then()
            .statusCode(303)
            .extract()
            .header("Location");

    assertTrue(bounce.startsWith("http://localhost:8080/idp/login?"), bounce);
    // The login page asks /idp/api/auth/return-location with exactly these two, and BrowserSso
    // decides. The authority is the canonical origin, which that class refuses to start without on
    // its own allow-list — so the bounce is not a second, weaker copy of the redirect rule.
    assertEquals("localhost:8080", param(bounce, "return_host"));
    String returnPath = param(bounce, "return_path");
    assertTrue(returnPath.startsWith("/idp/authorize?"), returnPath);
    assertTrue(returnPath.contains("client_id=" + CLIENT), returnPath);
    assertTrue(returnPath.contains("state=back-again"), returnPath);

    // And that is what the allow-list actually answers for it: the same URL, made absolute.
    given()
        .queryParam("return_host", param(bounce, "return_host"))
        .queryParam("return_path", returnPath)
        .when()
        .get("/idp/api/auth/return-location")
        .then()
        .statusCode(200)
        .body("location", equalTo("http://localhost:8080" + returnPath));
  }

  @Test
  public void theAddressSpellingOfThePageIsAcceptedToo() {
    Sessions.Opened session = signedInSession();
    String code = authorize(session.token(), ADDRESS_PAGE, VERIFIER, null);
    // And it stays bound to the spelling it was approved with: the redirect URI is compared
    // byte-for-byte at exchange, so the two names are two grants rather than one.
    token(CLIENT, "authorization_code", PAGE, code, VERIFIER, null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
    token(CLIENT, "authorization_code", ADDRESS_PAGE, code, VERIFIER, null).then().statusCode(200);
  }

  @Test
  public void theIssuerIsNotASpellingOfThePage() {
    Sessions.Opened session = signedInSession();
    // The issuer is an identifier with no path since qits-730; <issuer>/connect/cli is not a page
    // this service serves, so it is refused like any other foreign target.
    given()
        .redirects()
        .follow(false)
        .cookie(SessionCookie.NAME, session.token())
        .queryParam("response_type", "code")
        .queryParam("client_id", CLIENT)
        .queryParam("redirect_uri", ISSUER_PAGE)
        .queryParam("code_challenge", challenge(VERIFIER))
        .queryParam("code_challenge_method", "S256")
        .when()
        .get("/idp/authorize")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void aForeignRedirectIsRefusedAndAProtocolErrorReachesThePage() throws Exception {
    Sessions.Opened session = signedInSession();
    // Not the page, not a loopback listener: refused flatly, because until the target is known to
    // be this idp's own there is nowhere an error may be sent.
    given()
        .redirects()
        .follow(false)
        .cookie(SessionCookie.NAME, session.token())
        .queryParam("response_type", "code")
        .queryParam("client_id", CLIENT)
        .queryParam("redirect_uri", "https://evil.example/connect/cli")
        .queryParam("code_challenge", challenge(VERIFIER))
        .queryParam("code_challenge_method", "S256")
        .when()
        .get("/idp/authorize")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));

    // A near-miss on this idp's own host is refused for the same reason: the match is exact.
    given()
        .redirects()
        .follow(false)
        .cookie(SessionCookie.NAME, session.token())
        .queryParam("response_type", "code")
        .queryParam("client_id", CLIENT)
        .queryParam("redirect_uri", PAGE + "/../../evil")
        .queryParam("code_challenge", challenge(VERIFIER))
        .queryParam("code_challenge_method", "S256")
        .when()
        .get("/idp/authorize")
        .then()
        .statusCode(400);

    // A protocol error once the target is known good travels to the page, for a person to read,
    // instead of becoming a JSON body in a browser.
    String errored =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, session.token())
            .queryParam("response_type", "code")
            .queryParam("client_id", CLIENT)
            .queryParam("redirect_uri", PAGE)
            .queryParam("code_challenge", challenge(VERIFIER))
            .queryParam("code_challenge_method", "plain")
            .queryParam("state", "kept")
            .when()
            .get("/idp/authorize")
            .then()
            .statusCode(303)
            .extract()
            .header("Location");
    assertTrue(errored.startsWith(PAGE + "?"), errored);
    assertEquals("invalid_request", param(errored, "error"));
    assertEquals("kept", param(errored, "state"));

    // An audience parameter is not such an error any more: it is accepted and ignored (qits-163).
    // The approval goes through, and the token it buys has the one audience.
    String approved =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, session.token())
            .queryParam("response_type", "code")
            .queryParam("client_id", CLIENT)
            .queryParam("redirect_uri", PAGE)
            .queryParam("code_challenge", challenge(VERIFIER))
            .queryParam("code_challenge_method", "S256")
            .queryParam("audience", "prod-qits-githost")
            .queryParam("state", "kept")
            .when()
            .get("/idp/authorize")
            .then()
            .statusCode(303)
            .extract()
            .header("Location");
    assertTrue(approved.startsWith(PAGE + "?"), approved);
    assertEquals(null, param(approved, "error"), approved);
    assertEquals("kept", param(approved, "state"));
    String access =
        token(CLIENT, "authorization_code", PAGE, param(approved, "code"), VERIFIER, null)
            .jsonPath()
            .getString("access_token");
    assertEquals(
        List.of("qits-platform"), PublishedJwks.verify(access, "qits-platform").getAudience());
  }

  @Test
  public void neitherClientCanSpendTheOthersCredentials() {
    Sessions.Opened session = signedInSession();

    // A code approved for the CLI, offered as the workstation's.
    String cliCode = authorize(session.token(), PAGE, VERIFIER, null);
    token(WORKSTATION_CLIENT, "authorization_code", PAGE, cliCode, VERIFIER, null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));

    // A code approved for the workstation, offered as the CLI's. This is the direction that
    // matters: it would turn one narrow Git credential into the person's whole set of roles.
    String gitCode = workstationAuthorize(session.token());
    token(CLIENT, "authorization_code", WORKSTATION_REDIRECT, gitCode, VERIFIER, null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));

    // Each still works for its own client, so the refusals above are the client check and not a
    // code that was broken to begin with.
    String cliRefresh =
        token(CLIENT, "authorization_code", PAGE, cliCode, VERIFIER, null)
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .getString("refresh_token");
    String gitRefresh =
        token(
                WORKSTATION_CLIENT,
                "authorization_code",
                WORKSTATION_REDIRECT,
                gitCode,
                VERIFIER,
                null)
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .getString("refresh_token");

    // And a refresh token of one client is not the other's either. It is NOT treated as replay:
    // the holder may simply have both grants and crossed them, and revoking a live Git credential
    // for a CLI's mistake would be the wrong trade — so both families survive the refusal.
    token(WORKSTATION_CLIENT, "refresh_token", null, null, null, cliRefresh)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
    token(CLIENT, "refresh_token", null, null, null, gitRefresh)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
    token(CLIENT, "refresh_token", null, null, null, cliRefresh).then().statusCode(200);
    token(WORKSTATION_CLIENT, "refresh_token", null, null, null, gitRefresh).then().statusCode(200);
  }

  @Test
  public void aPublicClientMayNotPresentASecretAndIsUnknownByAnyOtherName() {
    given()
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "refresh_token")
        .formParam("client_id", CLIENT)
        .formParam("client_secret", "not-a-thing")
        .formParam("refresh_token", "whatever")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));

    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", "Basic cXVpdHM6c2VjcmV0")
        .formParam("grant_type", "refresh_token")
        .formParam("client_id", CLIENT)
        .formParam("refresh_token", "whatever")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));

    given()
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "refresh_token")
        .formParam("client_id", "qits-cli-but-not-really")
        .formParam("refresh_token", "whatever")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void theDevicesListNamesTheClientOfEveryFamilyAndRevokesOnePerDevice() {
    Sessions.Opened session = signedInSession();
    token(
        CLIENT,
        "authorization_code",
        PAGE,
        authorize(session.token(), PAGE, VERIFIER, null),
        VERIFIER,
        null)
        .then()
        .statusCode(200);
    String gitRefresh =
        token(
                WORKSTATION_CLIENT,
                "authorization_code",
                WORKSTATION_REDIRECT,
                workstationAuthorize(session.token()),
                VERIFIER,
                null)
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .getString("refresh_token");

    Response listed =
        given().cookie(SessionCookie.NAME, session.token()).when().get("/idp/api/devices");
    listed
        .then()
        .statusCode(200)
        .body("clientId", org.hamcrest.Matchers.hasItems(CLIENT, WORKSTATION_CLIENT))
        // The page renders `kind`, resolved here from the configured ids so a browser never has to
        // hold a copy of a deployment's setting.
        .body("kind", org.hamcrest.Matchers.hasItems("cli", "workstation"));

    // The old path is the same answer: it is a cross-repository contract and stayed working.
    given()
        .cookie(SessionCookie.NAME, session.token())
        .when()
        .get("/idp/api/workstations")
        .then()
        .statusCode(200)
        .body("clientId", org.hamcrest.Matchers.hasItems(CLIENT, WORKSTATION_CLIENT));

    String gitFamily =
        listed.jsonPath().getString("find { it.clientId == '" + WORKSTATION_CLIENT + "' }.id");
    given()
        .cookie(SessionCookie.NAME, session.token())
        .when()
        .delete("/idp/api/devices/" + gitFamily)
        .then()
        .statusCode(204);
    // Revoking one device is revoking one device: the Git family is dead and the CLI's is not.
    token(WORKSTATION_CLIENT, "refresh_token", null, null, null, gitRefresh)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
    given()
        .cookie(SessionCookie.NAME, session.token())
        .when()
        .get("/idp/api/devices")
        .then()
        .statusCode(200)
        .body("find { it.clientId == '" + CLIENT + "' }.revokedAt", org.hamcrest.Matchers.nullValue());
  }

  // --- the walk -----------------------------------------------------------------------------------

  private String authorize(String sessionToken, String redirectUri, String verifier, String state) {
    io.restassured.specification.RequestSpecification request =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, sessionToken)
            .queryParam("response_type", "code")
            .queryParam("client_id", CLIENT)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("code_challenge", challenge(verifier))
            .queryParam("code_challenge_method", "S256");
    if (state != null) {
      request.queryParam("state", state);
    }
    Response response = request.when().get("/idp/authorize");
    response.then().statusCode(303);
    String location = response.getHeader("Location");
    assertTrue(location.startsWith(redirectUri + "?"), location);
    if (state != null) {
      assertEquals(state, param(location, "state"));
    }
    return param(location, "code");
  }

  private String workstationAuthorize(String sessionToken) {
    Response response =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, sessionToken)
            .queryParam("response_type", "code")
            .queryParam("client_id", WORKSTATION_CLIENT)
            .queryParam("redirect_uri", WORKSTATION_REDIRECT)
            .queryParam("code_challenge", challenge(VERIFIER))
            .queryParam("code_challenge_method", "S256")
            .queryParam("audience", WORKSTATION_AUDIENCE)
            .when()
            .get("/idp/authorize");
    response.then().statusCode(303);
    return param(response.getHeader("Location"), "code");
  }

  private static Response token(
      String clientId,
      String grantType,
      String redirectUri,
      String code,
      String verifier,
      String refreshToken) {
    io.restassured.specification.RequestSpecification request =
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", grantType)
            .formParam("client_id", clientId);
    if (code != null) {
      request.formParam("code", code).formParam("redirect_uri", redirectUri).formParam("code_verifier", verifier);
    }
    if (refreshToken != null) {
      request.formParam("refresh_token", refreshToken);
    }
    return request.when().post("/idp/token");
  }

  /**
   * A real account with a real role assignment — not just a session object carrying a role list.
   *
   * <p>That distinction is the test: the CLI mint reads the roles from the STORE rather than from
   * the session that approved the code, because a refresh weeks later must reflect what the person
   * holds then and not what they held at sign-in. A fixture that only dressed the session would
   * pass while that behaviour was absent.
   */
  private Sessions.Opened signedInSession() {
    UUID id = UUID.randomUUID();
    String username = "cli-" + id;
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpUser row = new IdpUser();
              row.id = id;
              row.username = username;
              row.createdAt = Instant.now();
              users.persist(row);
              IdpUserRole role = new IdpUserRole();
              role.userId = id;
              role.role = "qits:admin";
              role.createdAt = Instant.now();
              role.persist();
            });
    return sessions.open(new Users.Account(id, username, List.of("qits:admin")));
  }

  /**
   * One query parameter of a URL, decoded — the honest way to read a {@code Location}, because how
   * a {@code UriBuilder} escapes a nested query is its business and not something a suite should
   * pin by matching raw text.
   */
  static String param(String url, String name) {
    String query = URI.create(url).getRawQuery();
    if (query == null) {
      return null;
    }
    for (String pair : query.split("&")) {
      int equals = pair.indexOf('=');
      if (equals > 0 && URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8).equals(name)) {
        return URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8);
      }
    }
    return null;
  }

  private static String challenge(String verifier) {
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    } catch (Exception impossible) {
      throw new AssertionError(impossible);
    }
  }
}
