package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.entity.IdpAuthorizationCode;
import eu.wohlben.qits.idp.entity.IdpRegisterToken;
import eu.wohlben.qits.idp.entity.IdpSession;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpWebAuthnCredential;
import eu.wohlben.qits.idp.entity.IdpWorkstationRefreshToken;
import eu.wohlben.qits.idp.persistence.IdpRegisterTokenRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRoleRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The admin doors (qits-1260): minting a register token, listing users and deleting one, each
 * reached by the three admin callers {@link AdminCaller} accepts — a service client over Basic, a
 * signed-in {@code qits:admin} session, a {@code qits:admin} person's bearer — and refused to every
 * other.
 *
 * <p>The person's bearer is minted by {@link TokenService#cli}, the same mint the CLI's code
 * exchange runs, so the token under test is the real one rather than a hand-built JWT. Every case
 * invents its own usernames: the suite shares one store, and the listing case reads the whole of
 * it, so it asserts on order and on its own rows rather than on a count.
 */
@QuarkusTest
public class UserAdministrationTest {

  private static final String SYSTEM = "test-broad";
  private static final String SYSTEM_SECRET = "test-broad-secret";

  private static final String CLI = "qits-cli";
  private static final String CLI_REDIRECT = "http://127.0.0.1:53682/callback";
  private static final String VERIFIER =
      "admin-verifier-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

  @Inject TokenService tokenService;

  @Inject Sessions sessions;

  @Inject IdpUserRepository users;

  @Inject IdpUserRoleRepository roles;

  @Inject IdpRegisterTokenRepository registerTokens;

  // --- minting a register token -----------------------------------------------------------------

  @Test
  public void anAdminSessionMintsARegisterTokenThatInvitesTheNextPerson() {
    Registered admin = registerWithPassword(mintBySystem());

    Response minted =
        given().cookie(SessionCookie.NAME, admin.session()).when().post("/idp/api/register-tokens");
    minted.then().statusCode(201).header("Cache-Control", "no-store");
    String token = minted.jsonPath().getString("token");
    assertEquals(43, token.length(), "the same 256-bit value a service client is answered");
    assertNotNull(minted.jsonPath().getString("id"));
    assertNotNull(minted.jsonPath().getString("createdAt"));

    // The row names the person, by account id, under a prefix no client id can carry.
    IdpRegisterToken row =
        inTx(() -> registerTokens.findById(UUID.fromString(minted.jsonPath().getString("id"))));
    assertEquals("user:" + admin.userId(), row.mintedBy);

    // And it is an invite: user #2 registers with it.
    registerWithPassword(token);
  }

  @Test
  public void anAdminPersonsBearerMintsARegisterToken() {
    Registered admin = registerWithPassword(mintBySystem());

    given()
        .header("Authorization", "Bearer " + cliBearer(admin.userId()))
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(201)
        .header("Cache-Control", "no-store")
        .body("token", org.hamcrest.Matchers.notNullValue());
  }

  @Test
  public void theSystemClientOverBasicStillMints() {
    String id =
        given()
            .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
            .when()
            .post("/idp/api/register-tokens")
            .then()
            .statusCode(201)
            .header("Cache-Control", "no-store")
            .extract()
            .path("id");
    assertEquals(SYSTEM, inTx(() -> registerTokens.findById(UUID.fromString(id))).mintedBy);
  }

  /**
   * NO MACHINE BEARER IS AN ADMIN. A {@code qits:system} bearer is a service client's and a {@code
   * qits:agent} bearer an agent's; both are refused with 403 — the bearer exception on these doors
   * is a person's, and an agent keeps no write. A person without {@code qits:admin} is refused the
   * same way, and so is an admin whose account is gone, though the token is still unexpired.
   */
  @Test
  public void everyBearerButAnAdminPersonsIsRefused() {
    String systemBearer = clientCredentials(basic(SYSTEM, SYSTEM_SECRET));

    JsonPath agent =
        given()
            .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("contextKind", "workspace")
                    .put("contextId", "admin-" + UUID.randomUUID())
                    .encode())
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract()
            .jsonPath();
    String agentBearer =
        clientCredentials(basic(agent.getString("clientId"), agent.getString("secret")));

    UUID plainPerson = personWithRoles(List.of());
    String plainBearer = cliBearer(plainPerson);

    for (String bearer : List.of(systemBearer, agentBearer, plainBearer)) {
      for (Request door : doors()) {
        door.send(given().header("Authorization", "Bearer " + bearer))
            .then()
            .statusCode(403)
            .body("error", equalTo("access_denied"));
      }
    }

    // Not a token at all: authentication failed, which is 401.
    given()
        .header("Authorization", "Bearer not-a-jwt")
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_token"));
  }

  @Test
  public void aCommissionedBasicClientIsStillRefused() {
    JsonPath commissioned =
        given()
            .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
            .contentType(ContentType.JSON)
            .body("{\"contextKind\":\"admin-doors-kind\",\"contextId\":\"ctx-1\"}")
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract()
            .jsonPath();
    String header = basic(commissioned.getString("clientId"), commissioned.getString("secret"));
    for (Request door : doors()) {
      door.send(given().header("Authorization", header))
          .then()
          .statusCode(403)
          .body("error", equalTo("access_denied"));
    }
  }

  /**
   * A browser with no session gets 401 and <b>no Basic challenge</b> — on a {@code fetch} that is a
   * native credentials dialog. A session without {@code qits:admin} is 403.
   */
  @Test
  public void noCredentialsIs401WithoutAChallengeAndANonAdminSessionIs403() {
    for (Request door : doors()) {
      door.send(given())
          .then()
          .statusCode(401)
          .header("WWW-Authenticate", nullValue())
          .body("error", equalTo("invalid_credentials"));
      door.send(given().cookie(SessionCookie.NAME, "not-a-live-session")).then().statusCode(401);
    }

    UUID plain = personWithRoles(List.of());
    String session =
        sessions.open(new Users.Account(plain, usernameOf(plain), List.of())).token();
    for (Request door : doors()) {
      door.send(given().cookie(SessionCookie.NAME, session))
          .then()
          .statusCode(403)
          .body("error", equalTo("access_denied"));
    }
  }

  // --- listing users ----------------------------------------------------------------------------

  @Test
  public void anAdminListsEveryUserSortedByNameWithRolesAndNoCredential() {
    Registered admin = registerWithPassword(mintBySystem());
    Registered other = registerWithPassword(mintBySystem());

    for (var spec :
        List.of(
            given().cookie(SessionCookie.NAME, admin.session()),
            given().header("Authorization", "Bearer " + cliBearer(admin.userId())),
            given().header("Authorization", basic(SYSTEM, SYSTEM_SECRET)))) {
      Response listed = spec.when().get("/idp/api/users");
      listed.then().statusCode(200).header("Cache-Control", "no-store");

      List<Map<String, Object>> rows = listed.jsonPath().getList("$");
      List<String> names = rows.stream().map(row -> (String) row.get("username")).toList();
      List<String> sorted = new ArrayList<>(names);
      sorted.sort(null);
      assertEquals(sorted, names, "sorted by username");
      for (Map<String, Object> row : rows) {
        assertEquals(
            List.of("createdAt", "roles", "username"),
            row.keySet().stream().sorted().toList(),
            "a user is its name, its creation and its roles; never a hash or a credential");
      }

      Map<String, Object> mine =
          rows.stream().filter(row -> admin.username().equals(row.get("username"))).findFirst()
              .orElseThrow();
      assertEquals(List.of("qits:admin"), mine.get("roles"));
      Instant.parse((String) mine.get("createdAt"));
      assertTrue(names.contains(other.username()));
    }
  }

  // --- deleting a user --------------------------------------------------------------------------

  @Test
  public void deletingAUserRemovesItsSessionsRolesFactorsAndTokens() {
    Registered admin = registerWithPassword(mintBySystem());
    Registered victim = registerWithPassword(mintBySystem());
    UUID victimId = victim.userId();

    // Everything keyed to the account: a second session, an authorization code and a refresh
    // token from a real CLI sign-in, on top of the registration's own session, role and password.
    String loginSession = sessionCookieOf(passwordLogin(victim.username(), victim.password()));
    String refresh = cliSignIn(victim.session());
    addPasskey(victim.session());
    assertEquals(1L, inTx(() -> IdpWebAuthnCredential.count("userId", victimId)));
    introspect(victim.session()).then().statusCode(200);
    introspect(loginSession).then().statusCode(200);

    given()
        .cookie(SessionCookie.NAME, admin.session())
        .when()
        .delete("/idp/api/users/{username}", victim.username())
        .then()
        .statusCode(204);

    introspect(victim.session()).then().statusCode(404);
    introspect(loginSession).then().statusCode(404);
    passwordLogin(victim.username(), victim.password())
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_credentials"));
    given()
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "refresh_token")
        .formParam("client_id", CLI)
        .formParam("refresh_token", refresh)
        .when()
        .post("/idp/token")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));

    assertNull(inTx(() -> users.findById(victimId)));
    assertEquals(List.of(), inTx(() -> roles.rolesOf(victimId)));
    assertEquals(0L, inTx(() -> IdpSession.count("userId", victimId)));
    assertEquals(0L, inTx(() -> IdpWebAuthnCredential.count("userId", victimId)));
    assertEquals(0L, inTx(() -> IdpAuthorizationCode.count("userId", victimId)));
    assertEquals(0L, inTx(() -> IdpWorkstationRefreshToken.count("userId", victimId)));
    // The token it was made from stays spent; only the link to the account is gone.
    IdpRegisterToken spent =
        inTx(() -> registerTokens.findById(UUID.fromString(victim.registerTokenId())));
    assertNotNull(spent.consumedAt);
    assertNull(spent.createdUserId);

    given()
        .cookie(SessionCookie.NAME, admin.session())
        .when()
        .get("/idp/api/users")
        .then()
        .statusCode(200)
        .body("find { it.username == '" + victim.username() + "' }", nullValue());

    // The admin is untouched.
    introspect(admin.session()).then().statusCode(200);
  }

  @Test
  public void anAdminBearerAndTheSystemClientDeleteToo() {
    Registered admin = registerWithPassword(mintBySystem());
    Registered first = registerWithPassword(mintBySystem());
    Registered second = registerWithPassword(mintBySystem());

    given()
        .header("Authorization", "Bearer " + cliBearer(admin.userId()))
        .when()
        .delete("/idp/api/users/{username}", first.username())
        .then()
        .statusCode(204);
    given()
        .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
        .when()
        .delete("/idp/api/users/{username}", second.username())
        .then()
        .statusCode(204);

    // A deleted admin's bearer stops working at once, though the JWT itself has not expired.
    Registered doomed = registerWithPassword(mintBySystem());
    String doomedBearer = cliBearer(doomed.userId());
    given()
        .cookie(SessionCookie.NAME, admin.session())
        .when()
        .delete("/idp/api/users/{username}", doomed.username())
        .then()
        .statusCode(204);
    given()
        .header("Authorization", "Bearer " + doomedBearer)
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(403);
  }

  @Test
  public void anAdminCannotDeleteThemselves() {
    Registered admin = registerWithPassword(mintBySystem());

    given()
        .cookie(SessionCookie.NAME, admin.session())
        .when()
        .delete("/idp/api/users/{username}", admin.username())
        .then()
        .statusCode(409)
        .body("error", equalTo("conflict"))
        .body("error_description", equalTo("an admin cannot delete themselves"));
    given()
        .header("Authorization", "Bearer " + cliBearer(admin.userId()))
        .when()
        .delete("/idp/api/users/{username}", admin.username())
        .then()
        .statusCode(409);

    introspect(admin.session()).then().statusCode(200);
  }

  @Test
  public void anUnknownUserIs404() {
    Registered admin = registerWithPassword(mintBySystem());
    given()
        .cookie(SessionCookie.NAME, admin.session())
        .when()
        .delete("/idp/api/users/{username}", "nobody-" + UUID.randomUUID())
        .then()
        .statusCode(404)
        .body("error", equalTo("not_found"));
  }

  // --- helpers ----------------------------------------------------------------------------------

  /** A registered account, with the password the idp answered and its open session. */
  record Registered(
      UUID userId, String username, String password, String session, String registerTokenId) {}

  /** One admin door, sent with whatever credentials the spec carries. */
  @FunctionalInterface
  interface Request {
    Response send(io.restassured.specification.RequestSpecification spec);
  }

  private static List<Request> doors() {
    return List.of(
        spec -> spec.when().post("/idp/api/register-tokens"),
        spec -> spec.when().get("/idp/api/users"),
        spec -> spec.when().delete("/idp/api/users/{username}", "nobody-" + UUID.randomUUID()));
  }

  private String mintBySystem() {
    return given()
        .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(201)
        .extract()
        .path("token");
  }

  /** Spend a token without a passkey; the idp answers the password it set. */
  private Registered registerWithPassword(String token) {
    String username = "admin-doors-" + UUID.randomUUID();
    Response registered =
        given()
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", username).put("token", token).encode())
            .when()
            .post("/idp/api/auth/register");
    registered.then().statusCode(200).body("roles", equalTo(List.of("qits:admin")));
    UUID userId = UUID.fromString(registered.jsonPath().getString("userId"));
    String tokenId =
        inTx(
            () ->
                registerTokens.find("createdUserId", userId).firstResultOptional()
                    .map(row -> row.id.toString())
                    .orElseThrow());
    return new Registered(
        userId,
        username,
        registered.jsonPath().getString("password"),
        sessionCookieOf(registered),
        tokenId);
  }

  /** An account made directly in the store, holding exactly these roles. */
  private UUID personWithRoles(List<String> granted) {
    UUID id = UUID.randomUUID();
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpUser row = new IdpUser();
              row.id = id;
              row.username = "admin-doors-plain-" + id;
              row.createdAt = Instant.now();
              users.persist(row);
              for (String role : granted) {
                eu.wohlben.qits.idp.entity.IdpUserRole grant =
                    new eu.wohlben.qits.idp.entity.IdpUserRole();
                grant.userId = id;
                grant.role = role;
                grant.createdAt = Instant.now();
                grant.persist();
              }
            });
    return id;
  }

  private String usernameOf(UUID id) {
    return inTx(() -> users.findById(id)).username;
  }

  /** The person's CLI access token, from the CLI's own mint. */
  private String cliBearer(UUID userId) {
    return tokenService.cli(userId).accessToken();
  }

  private static String clientCredentials(String basicHeader) {
    return given()
        .header("Authorization", basicHeader)
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(200)
        .extract()
        .path("access_token");
  }

  /** A passkey added from a live session — the session-guarded register path. */
  private static void addPasskey(String session) {
    CookieFilter browser = new CookieFilter();
    WebAuthnTestHardware authenticator = new WebAuthnTestHardware();
    String challenge =
        given()
            .filter(browser)
            .cookie(SessionCookie.NAME, session)
            .contentType(ContentType.JSON)
            .body(new JsonObject().encode())
            .when()
            .post("/idp/api/auth/register-options")
            .then()
            .statusCode(200)
            .extract()
            .path("challenge");
    given()
        .filter(browser)
        .cookie(SessionCookie.NAME, session)
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("attestation", authenticator.registration(challenge)).encode())
        .when()
        .post("/idp/api/auth/register")
        .then()
        .statusCode(200)
        .body("password", nullValue());
  }

  /** A real CLI sign-in from this session: authorize, then the code exchange. The refresh token. */
  private static String cliSignIn(String session) {
    Response authorized =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, session)
            .queryParam("response_type", "code")
            .queryParam("client_id", CLI)
            .queryParam("redirect_uri", CLI_REDIRECT)
            .queryParam("code_challenge", challenge(VERIFIER))
            .queryParam("code_challenge_method", "S256")
            .when()
            .get("/idp/authorize");
    authorized.then().statusCode(303);
    String code = param(authorized.getHeader("Location"), "code");
    return given()
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "authorization_code")
        .formParam("client_id", CLI)
        .formParam("code", code)
        .formParam("redirect_uri", CLI_REDIRECT)
        .formParam("code_verifier", VERIFIER)
        .when()
        .post("/idp/token")
        .then()
        .statusCode(200)
        .extract()
        .path("refresh_token");
  }

  private static Response passwordLogin(String username, String password) {
    return given()
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("username", username).put("password", password).encode())
        .when()
        .post("/idp/api/auth/login");
  }

  private static Response introspect(String sessionToken) {
    return given()
        .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", sessionToken).encode())
        .when()
        .post("/idp/api/sessions/introspect");
  }

  private static String sessionCookieOf(Response response) {
    String line =
        response.getHeaders().getValues("Set-Cookie").stream()
            .filter(value -> value.startsWith(SessionCookie.NAME + "="))
            .findFirst()
            .orElseThrow();
    assertFalse(line.isEmpty());
    return line.substring((SessionCookie.NAME + "=").length(), line.indexOf(';'));
  }

  private static String param(String url, String name) {
    for (String pair : URI.create(url).getRawQuery().split("&")) {
      int equals = pair.indexOf('=');
      if (equals > 0 && pair.substring(0, equals).equals(name)) {
        return URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8);
      }
    }
    return null;
  }

  private static String challenge(String verifier) {
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(
              MessageDigest.getInstance("SHA-256")
                  .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    } catch (Exception impossible) {
      throw new AssertionError(impossible);
    }
  }

  private static <T> T inTx(java.util.function.Supplier<T> read) {
    return QuarkusTransaction.requiringNew().call(read::get);
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
