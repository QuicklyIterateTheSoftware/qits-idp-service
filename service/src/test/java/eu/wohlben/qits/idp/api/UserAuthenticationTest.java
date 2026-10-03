package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.entity.IdpRegisterToken;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpWebAuthnCredential;
import eu.wohlben.qits.idp.persistence.IdpRegisterTokenRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRoleRepository;
import eu.wohlben.qits.idp.persistence.IdpWebAuthnCredentialRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * User authentication end to end: a register token becomes an account with a passkey, the passkey
 * logs in, the edge introspects the cookie, and logout stops all of it.
 *
 * <p><b>The ceremony is real.</b> {@link WebAuthnTestHardware} wraps quarkus-test-security-webauthn's
 * emulated authenticator, which holds an actual EC keypair and produces actual attestations and
 * assertions over the server's own challenge. There is no recorded fixture to go stale, and nothing
 * here mocks the verification — a change that broke the rp id, the origin list or the challenge
 * cookie fails these tests rather than passing them.
 *
 * <p><b>Every test invents its own username.</b> The suite shares one application and therefore one
 * store, so an account created by one case is visible to the next; a name derived from {@link
 * UUID#randomUUID()} is what keeps the cases independent without a truncate between them — the same
 * discipline {@code CommissionedClientsTest} keeps with its context kinds.
 *
 * <p>The cases are the invariants rather than the endpoints: a token registers exactly one account,
 * the two bootstrap roles are granted, the cookie carries the attributes the plan fixed, a session
 * introspects until it is revoked and not after, only a service client may mint or introspect, and
 * every way a login can fail is the same 401.
 */
@QuarkusTest
public class UserAuthenticationTest {

  /** A static service client from the suite's own list — the stand-in for {@code {env}-qits-edge}. */
  private static final String EDGE = "test-broad";

  private static final String EDGE_SECRET = "test-broad-secret";

  @Inject IdpUserRepository users;

  @Inject IdpUserRoleRepository roles;

  @Inject IdpWebAuthnCredentialRepository credentials;

  @Inject IdpRegisterTokenRepository tokens;

  // --- the round trip ---------------------------------------------------------------------------

  @Test
  public void aTokenBecomesAnAccountWithAPasskeyThatLogsInAndIntrospects() throws Exception {
    String username = someUsername();
    CookieFilter browser = new CookieFilter();
    WebAuthnTestHardware authenticator = new WebAuthnTestHardware();

    Response registered = register(browser, authenticator, username, mintToken());
    registered.then().statusCode(200).body("username", equalTo(username));
    String userId = registered.jsonPath().getString("userId");
    assertNotNull(userId, "the answer names the account the edge will inject");
    assertNotNull(registered.jsonPath().getString("expiresAt"), "and when it stops being true");

    // THE TWO BOOTSTRAP ROLES, in the answer and in the store. Nothing enforces them yet; that they
    // are granted at all is what a later authorization plan will build on.
    //
    // THE ORDER IS ASSERTED, not just the membership. The edge joins this list into one
    // comma-separated X-Qits-Roles header and caches it, so an order that varied between reads
    // would vary the header. It is Java's, deliberately, and not the database's — see
    // IdpUserRoleRepository, where a postgres collation was measured putting these two the other
    // way round.
    registered.then().body("roles", equalTo(List.of("qits:admin")));
    assertEquals(
        List.of("qits:admin"),
        inTx(() -> roles.rolesOf(UUID.fromString(userId))),
        "the roles are rows, not a column");

    // The passkey is a row with the fields quarkus-security-webauthn asks back for.
    IdpWebAuthnCredential stored =
        inTx(() -> credentials.listForUser(UUID.fromString(userId))).get(0);
    assertNotNull(stored.publicKey, "the public key is what a later assertion verifies against");
    assertNotNull(stored.aaguid);
    assertEquals(-7L, stored.publicKeyAlgorithm, "the emulated authenticator signs ES256");

    String sessionFromRegistration = sessionCookieOf(registered);
    assertNotNull(sessionFromRegistration, "registering signs the operator in");

    // The cookie introspects at the edge's credential, and says the same four things.
    //
    // expiresAt is asserted EQUAL to the one the registration reported, which it only is because
    // the row's timestamps are truncated to what timestamp(6) holds. Untruncated, the answer that
    // opened the session and every introspection of it afterwards disagree in the last three
    // digits — one session with two deadlines.
    introspect(sessionFromRegistration)
        .then()
        .statusCode(200)
        .body("userId", equalTo(userId))
        .body("username", equalTo(username))
        .body("expiresAt", equalTo(registered.jsonPath().getString("expiresAt")))
        .body("roles", hasItems("qits:admin"));

    // And the passkey logs in again, in a browser that kept no session.
    CookieFilter secondVisit = new CookieFilter();
    Response loggedIn = login(secondVisit, authenticator, username);
    loggedIn.then().statusCode(200).body("userId", equalTo(userId));
    String sessionFromLogin = sessionCookieOf(loggedIn);
    assertNotEquals(
        sessionFromRegistration, sessionFromLogin, "every login opens a session of its own");
    introspect(sessionFromLogin).then().statusCode(200);

    // Logging out revokes THAT session and clears the cookie. The other one is untouched: a
    // session is ended by its holder, not by its account.
    Response loggedOut =
        given()
            .filter(secondVisit)
            .cookie(SessionCookie.NAME, sessionFromLogin)
            .when()
            .post("/idp/api/auth/logout");
    loggedOut.then().statusCode(204);
    assertEquals(
        "qits-session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        setCookieLine(loggedOut),
        "the clearing line repeats the attributes, or the browser keeps the old cookie");
    introspect(sessionFromLogin).then().statusCode(404);
    introspect(sessionFromRegistration).then().statusCode(200);
  }

  /**
   * THE COOKIE'S EXACT LINE. Every attribute on it is a decision from the plan, and each one fails
   * differently if it goes: no {@code HttpOnly} and a scripting bug leaks the platform; no {@code
   * Path=/} and the edge never sees the cookie on the segments it gates; no {@code SameSite=Lax}
   * and a cross-site POST rides it; a {@code Domain} and the machine vhosts are offered a browser's
   * credential.
   *
   * <p>{@code Secure} is deliberately absent here, and that is the assertion rather than an
   * oversight: the suite speaks plain http to localhost, and a {@code Secure} cookie would simply
   * never be stored by a browser doing the same — which is the developer host's whole login flow.
   */
  @Test
  public void theSessionCookieCarriesExactlyTheAttributesThePlanFixed() throws Exception {
    Response registered =
        register(new CookieFilter(), new WebAuthnTestHardware(), someUsername(), mintToken());
    String line = setCookieLine(registered);

    assertTrue(line.startsWith(SessionCookie.NAME + "="), line);
    assertTrue(line.contains("; Path=/"), line);
    assertTrue(line.contains("; HttpOnly"), line);
    assertTrue(line.contains("; SameSite=Lax"), line);
    assertTrue(line.contains("; Max-Age=43200"), "PT12H, from qits.idp.session-ttl: " + line);
    assertFalse(line.contains("Domain"), "host-only, so no sibling name is offered it: " + line);
    assertFalse(line.contains("Secure"), "plain http here, and localhost is a secure context: " + line);

    // The value is opaque: 256 bits of base64url, and nothing about the account in it.
    String value = line.substring((SessionCookie.NAME + "=").length(), line.indexOf(';'));
    assertEquals(43, value.length(), "32 bytes, base64url, unpadded: " + value);
  }

  @Test
  public void aConfiguredParentCookieDomainIsRepeatedWhenTheSessionIsCleared() {
    String opened = SessionCookie.set("opaque", java.time.Duration.ofHours(12), true, "wohlben.eu");
    String cleared = SessionCookie.clear(true, "wohlben.eu");
    assertTrue(opened.contains("; Domain=wohlben.eu"), opened);
    assertTrue(cleared.contains("; Domain=wohlben.eu"), cleared);
    assertTrue(opened.contains("; Secure"), opened);
    assertTrue(cleared.contains("; Max-Age=0"), cleared);
  }

  @Test
  public void theIdpResolvesBrowserReturnsOnlyToConfiguredAuthorities() {
    given()
        .queryParam("return_host", "localhost:8080")
        .queryParam("return_path", "/projects/7?tab=runs")
        .when()
        .get("/idp/api/auth/return-location")
        .then()
        .statusCode(200)
        .body("location", equalTo("http://localhost:8080/projects/7?tab=runs"));
    given()
        .queryParam("return_host", "evil.example")
        .queryParam("return_path", "//evil.example/steal")
        .when()
        .get("/idp/api/auth/return-location")
        .then()
        .statusCode(200)
        .body("location", equalTo("http://localhost:8080/"));
  }

  // --- the register token -----------------------------------------------------------------------

  @Test
  public void aRegisterTokenIsGoodForExactlyOneAccount() throws Exception {
    String token = mintToken();
    String first = someUsername();
    register(new CookieFilter(), new WebAuthnTestHardware(), first, token)
        .then()
        .statusCode(200);

    // The row records that it was spent, and on whom.
    IdpRegisterToken row =
        inTx(
            () ->
                tokens.find("createdUserId is not null").stream()
                    .filter(t -> t.consumedAt != null)
                    .filter(t -> users.findById(t.createdUserId).username.equals(first))
                    .findFirst()
                    .orElse(null));
    assertNotNull(row, "consuming a token is a row update, not a delete");
    assertEquals(EDGE, row.mintedBy);

    // And the second try is refused before any ceremony state is made — at options, not at register.
    given()
        .filter(new CookieFilter())
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("username", someUsername()).put("token", token).encode())
        .when()
        .post("/idp/api/auth/register-options")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_credentials"));
  }

  @Test
  public void registeringNeedsAnUnspentTokenOrASignedInSession() {
    // Nothing at all.
    given()
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("username", someUsername()).encode())
        .when()
        .post("/idp/api/auth/register-options")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_credentials"));

    // A token this idp never minted.
    given()
        .contentType(ContentType.JSON)
        .body(
            new JsonObject()
                .put("username", someUsername())
                .put("token", "not-a-token-this-idp-ever-minted")
                .encode())
        .when()
        .post("/idp/api/auth/register")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_credentials"));
  }

  @Test
  public void aTakenUsernameIsSaidSoRatherThanFailingAfterTheCeremony() throws Exception {
    String username = someUsername();
    register(new CookieFilter(), new WebAuthnTestHardware(), username, mintToken())
        .then()
        .statusCode(200);

    // The caller already holds a valid token, so telling it the name is taken leaks nothing — and
    // it is said at options time, before an authenticator is asked to make a key.
    given()
        .filter(new CookieFilter())
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("username", username).put("token", mintToken()).encode())
        .when()
        .post("/idp/api/auth/register-options")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  // --- the password path ------------------------------------------------------------------------

  @Test
  public void aPasswordRegistersAndLogsInWithNoAuthenticatorAtAll() {
    String username = someUsername();

    Response registered =
        given()
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("username", username)
                    .put("token", mintToken())
                    .put("password", "correct horse battery staple")
                    .encode())
            .when()
            .post("/idp/api/auth/register");
    registered.then().statusCode(200).body("username", equalTo(username));
    assertNotNull(sessionCookieOf(registered), "a password registration signs in like any other");

    // This is the path that exists for the one browsing route with no secure context — a raw IP,
    // where navigator.credentials does not exist — and for automated callers.
    Response loggedIn =
        given()
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("username", username)
                    .put("password", "correct horse battery staple")
                    .encode())
            .when()
            .post("/idp/api/auth/login");
    loggedIn.then().statusCode(200).body("username", equalTo(username));
    introspect(sessionCookieOf(loggedIn)).then().statusCode(200);

    // The row holds no plaintext, under a named scheme, so a second scheme can land beside it.
    IdpUser row = inTx(() -> users.findByUsername(username));
    assertTrue(row.passwordHash.startsWith("bcrypt:"), row.passwordHash);
    assertFalse(row.passwordHash.contains("correct horse"), "nor any part of it");
  }

  @Test
  public void aPasswordIsSetFromALiveSessionAndThenLogsIn() throws Exception {
    String username = someUsername();
    Response registered =
        register(new CookieFilter(), new WebAuthnTestHardware(), username, mintToken());
    String session = sessionCookieOf(registered);

    // A passkey account starts with no password factor at all, and a login with one is refused
    // exactly like a wrong one.
    assertEquals(null, inTx(() -> users.findByUsername(username)).passwordHash);
    given()
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("username", username).put("password", "anything").encode())
        .when()
        .post("/idp/api/auth/login")
        .then()
        .statusCode(401);

    given()
        .cookie(SessionCookie.NAME, session)
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("password", "a").encode())
        .when()
        .post("/idp/api/auth/password")
        .then()
        .statusCode(204);

    // Non-empty is the only rule, so a one-character password is accepted and works.
    given()
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("username", username).put("password", "a").encode())
        .when()
        .post("/idp/api/auth/login")
        .then()
        .statusCode(200);

    // An empty one is not a password, and setting it needs a session.
    given()
        .cookie(SessionCookie.NAME, session)
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("password", "").encode())
        .when()
        .post("/idp/api/auth/password")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    given()
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("password", "b").encode())
        .when()
        .post("/idp/api/auth/password")
        .then()
        .statusCode(401);
  }

  // --- a second authenticator -------------------------------------------------------------------

  @Test
  public void aSecondAuthenticatorIsAddedFromALiveSessionWithNoToken() throws Exception {
    String username = someUsername();
    CookieFilter browser = new CookieFilter();
    Response registered =
        register(browser, new WebAuthnTestHardware(), username, mintToken());
    String session = sessionCookieOf(registered);
    UUID userId = UUID.fromString(registered.jsonPath().getString("userId"));

    WebAuthnTestHardware second = new WebAuthnTestHardware();
    CookieFilter signedIn = new CookieFilter();
    String challenge =
        given()
            .filter(signedIn)
            .cookie(SessionCookie.NAME, session)
            .contentType(ContentType.JSON)
            .body(new JsonObject().encode())
            .when()
            .post("/idp/api/auth/register-options")
            .then()
            .statusCode(200)
            .extract()
            .path("challenge");

    Response added =
        given()
            .filter(signedIn)
            .cookie(SessionCookie.NAME, session)
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("attestation", second.registration(challenge)).encode())
            .when()
            .post("/idp/api/auth/register");
    added.then().statusCode(200).body("username", equalTo(username));
    assertEquals(
        null, setCookieLine(added), "the session that authorised the call is the one that continues");

    assertEquals(2, inTx(() -> credentials.listForUser(userId)).size());

    // Both authenticators log the same account in.
    login(new CookieFilter(), second, username).then().statusCode(200).body("userId", equalTo(userId.toString()));
  }

  // --- uniform refusals -------------------------------------------------------------------------

  @Test
  public void everyWayALoginCanFailIsTheSame401() {
    // An account that does not exist, and one that does with the wrong password: one code, one
    // status, and nothing in either answer that tells the two apart.
    String unknown =
        given()
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", someUsername()).put("password", "x").encode())
            .when()
            .post("/idp/api/auth/login")
            .then()
            .statusCode(401)
            .body("error", equalTo("invalid_credentials"))
            .extract()
            .asString();

    String username = someUsername();
    given()
        .contentType(ContentType.JSON)
        .body(
            new JsonObject()
                .put("username", username)
                .put("token", mintToken())
                .put("password", "right")
                .encode())
        .when()
        .post("/idp/api/auth/register")
        .then()
        .statusCode(200);

    String wrong =
        given()
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", username).put("password", "wrong").encode())
            .when()
            .post("/idp/api/auth/login")
            .then()
            .statusCode(401)
            .body("error", equalTo("invalid_credentials"))
            .extract()
            .asString();

    assertEquals(unknown, wrong, "a caller must not be able to tell an unknown name from a wrong password");

    // An assertion with no challenge cookie behind it is the same refusal again.
    given()
        .contentType(ContentType.JSON)
        .body(
            new JsonObject()
                .put("assertion", new JsonObject().put("id", "x").put("rawId", "x").put("type", "public-key"))
                .encode())
        .when()
        .post("/idp/api/auth/login")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_credentials"));
  }

  /**
   * NO {@code WWW-Authenticate} ON THE USER SURFACE, and it is asserted rather than assumed. These
   * routes are called by a browser with {@code fetch}; a Basic challenge on a failed login is at
   * best noise and at worst a native credentials dialog in front of the login page. The machine
   * surfaces next door still send one, which the case below pins from the other side.
   */
  @Test
  public void theUserSurfaceRefusesWithoutABasicChallengeAndTheMachineSurfaceWithOne() {
    given()
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("username", someUsername()).put("password", "x").encode())
        .when()
        .post("/idp/api/auth/login")
        .then()
        .statusCode(401)
        .header("WWW-Authenticate", org.hamcrest.Matchers.nullValue());

    given()
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", "x").encode())
        .when()
        .post("/idp/api/sessions/introspect")
        .then()
        .statusCode(401)
        .header("WWW-Authenticate", "Basic realm=\"qits-platform-idp\"");
  }

  // --- the machine surfaces ---------------------------------------------------------------------

  @Test
  public void introspectionAnswersNothingForAnUnknownRevokedOrForgedToken() {
    introspect("nothing-this-idp-ever-issued").then().statusCode(404).body("error", equalTo("not_found"));

    given()
        .header("Authorization", basic(EDGE, EDGE_SECRET))
        .contentType(ContentType.JSON)
        .body(new JsonObject().encode())
        .when()
        .post("/idp/api/sessions/introspect")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));

    // And it needs the caller's own credentials, like every other machine verb here.
    given()
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", "x").encode())
        .when()
        .post("/idp/api/sessions/introspect")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  /**
   * THE COMMISSIONING RULE, REUSED. A commissioned credential belongs to one dynamic context — a ci
   * run, a workspace, an agent container — and lives exactly as long as it does. Minting a register
   * token would let it produce a platform account that outlives it, and introspecting would let it
   * turn any browser cookie it saw into a username and a role set. It authenticates here; it may
   * not use either verb.
   */
  @Test
  public void aCommissionedCredentialMayNeitherMintNorIntrospect() {
    io.restassured.path.json.JsonPath commissioned =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic(EDGE, EDGE_SECRET))
            .body("{\"contextKind\":\"user-auth-kind\",\"contextId\":\"ctx-1\"}")
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract()
            .jsonPath();
    String header = basic(commissioned.getString("clientId"), commissioned.getString("secret"));

    given()
        .header("Authorization", header)
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(403)
        .body("error", equalTo("access_denied"));

    given()
        .header("Authorization", header)
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", "x").encode())
        .when()
        .post("/idp/api/sessions/introspect")
        .then()
        .statusCode(403)
        .body("error", equalTo("access_denied"));
  }

  /**
   * ANY SERVICE CLIENT MAY MINT A REGISTER TOKEN AND INTROSPECT A SESSION, and the bootstrap depends
   * on it: the {@code {env}-qits-edge} credential never asks for a token for itself — it only
   * authenticates Basic against these two endpoints. {@code test-audienceless} once had no audience
   * list, to pin that; every client has the one audience now, so what is left to pin is that the
   * Basic doors and the token endpoint answer the same adopted client.
   */
  @Test
  public void aServiceClientMintsIntrospectsAndGetsATokenToo() {
    String header = basic("test-audienceless", "test-audienceless-secret");

    String token =
        given()
            .header("Authorization", header)
            .when()
            .post("/idp/api/register-tokens")
            .then()
            .statusCode(201)
            .extract()
            .path("token");
    assertNotNull(token);

    String username = someUsername();
    Response registered =
        given()
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("username", username)
                    .put("token", token)
                    .put("password", "p")
                    .encode())
            .when()
            .post("/idp/api/auth/register");
    registered.then().statusCode(200);

    given()
        .header("Authorization", header)
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", sessionCookieOf(registered)).encode())
        .when()
        .post("/idp/api/sessions/introspect")
        .then()
        .statusCode(200)
        .body("username", equalTo(username));

    // And the token endpoint issues it the one audience, like every client.
    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", header)
        .body("grant_type=client_credentials")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(200);
  }

  @Test
  public void mintingARegisterTokenNeedsAServiceClientsOwnCredentials() {
    given().when().post("/idp/api/register-tokens").then().statusCode(401);
    given()
        .header("Authorization", basic(EDGE, "wrong"))
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
    // An id listed for adoption with no secret was never adopted: unknown here too, never open.
    given()
        .header("Authorization", basic("prod-qits-workspaces", ""))
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(401);

    // The row holds no plaintext.
    String token =
        given()
            .header("Authorization", basic(EDGE, EDGE_SECRET))
            .when()
            .post("/idp/api/register-tokens")
            .then()
            .statusCode(201)
            .header("Cache-Control", "no-store")
            .extract()
            .path("token");
    assertEquals(43, token.length(), "32 bytes, base64url, unpadded");
    assertFalse(
        inTx(() -> tokens.listAll()).stream().anyMatch(row -> row.tokenHash.contains(token)),
        "a token is stored as a fingerprint, never as itself");
  }

  // --- helpers ----------------------------------------------------------------------------------

  /** A name no other case in this shared-store suite can be using. */
  private static String someUsername() {
    return "user-" + UUID.randomUUID();
  }

  private String mintToken() {
    return given()
        .header("Authorization", basic(EDGE, EDGE_SECRET))
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(201)
        .extract()
        .path("token");
  }

  /** The whole register ceremony: options, the authenticator's answer, and the attestation. */
  private Response register(
      CookieFilter browser, WebAuthnTestHardware authenticator, String username, String token) {
    String challenge =
        given()
            .filter(browser)
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", username).put("token", token).encode())
            .when()
            .post("/idp/api/auth/register-options")
            .then()
            .statusCode(200)
            .extract()
            .path("challenge");
    return given()
        .filter(browser)
        .contentType(ContentType.JSON)
        .body(
            new JsonObject()
                .put("username", username)
                .put("token", token)
                .put("attestation", authenticator.registration(challenge))
                .encode())
        .when()
        .post("/idp/api/auth/register");
  }

  /** The whole login ceremony. */
  private Response login(
      CookieFilter browser, WebAuthnTestHardware authenticator, String username) {
    String challenge =
        given()
            .filter(browser)
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", username).encode())
            .when()
            .post("/idp/api/auth/login-options")
            .then()
            .statusCode(200)
            .extract()
            .path("challenge");
    return given()
        .filter(browser)
        .contentType(ContentType.JSON)
        .body(
            new JsonObject()
                .put("username", username)
                .put("assertion", authenticator.assertion(challenge))
                .encode())
        .when()
        .post("/idp/api/auth/login");
  }

  private Response introspect(String sessionToken) {
    return given()
        .header("Authorization", basic(EDGE, EDGE_SECRET))
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", sessionToken).encode())
        .when()
        .post("/idp/api/sessions/introspect");
  }

  /**
   * The {@code Set-Cookie} line for the session, or null when the answer set none.
   *
   * <p>It is picked out by name rather than taken as "the header", because the WebAuthn extension
   * clears its own challenge cookie on the same response — so a register answer genuinely carries
   * two, and taking the first would assert about the wrong one.
   */
  private static String setCookieLine(Response response) {
    return response.getHeaders().getValues("Set-Cookie").stream()
        .filter(line -> line.startsWith(SessionCookie.NAME + "="))
        .findFirst()
        .orElse(null);
  }

  private static String sessionCookieOf(Response response) {
    String line = setCookieLine(response);
    if (line == null) {
      return null;
    }
    return line.substring((SessionCookie.NAME + "=").length(), line.indexOf(';'));
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
