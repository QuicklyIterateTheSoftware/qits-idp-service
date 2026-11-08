package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.entity.IdpWebAuthnCredential;
import eu.wohlben.qits.idp.persistence.IdpWebAuthnCredentialRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The account page's passkeys end to end (qits-1953): real authenticators from {@link
 * WebAuthnTestHardware}, registered through the ceremony, listed and removed through {@code
 * /idp/api/passkeys}. A removed passkey must stop logging in, the account's last way in is kept,
 * and only a session reaches either door.
 *
 * <p>Every case invents its own account: the suite shares one store.
 */
@QuarkusTest
public class PasskeysTest {

  private static final String SYSTEM = "test-broad";
  private static final String SYSTEM_SECRET = "test-broad-secret";

  @Inject IdpWebAuthnCredentialRepository credentials;

  @Inject TokenService tokenService;

  // --- listing ------------------------------------------------------------------------------------

  @Test
  public void theListingShowsOnlyTheCallersOwnPasskeysAndNoKeyMaterial() {
    Account mine = account();
    WebAuthnTestHardware second = new WebAuthnTestHardware();
    addPasskey(mine, second);
    Account theirs = account();

    Response listed = list(mine.session());
    listed.then().statusCode(200);
    assertEquals("no-store", listed.getHeader("Cache-Control"));
    assertEquals("no-cache", listed.getHeader("Pragma"));
    List<Map<String, Object>> passkeys = listed.jsonPath().getList("$");
    List<String> ids = passkeys.stream().map(p -> (String) p.get("credentialId")).toList();
    assertEquals(credentialIds(mine.userId()), ids, "the caller's two, oldest first");
    for (String foreign : credentialIds(theirs.userId())) {
      assertFalse(ids.contains(foreign), "never another account's");
    }
    for (Map<String, Object> passkey : passkeys) {
      assertEquals(
          Set.of("credentialId", "aaguid", "createdAt"),
          passkey.keySet(),
          "no public key, algorithm or counter: " + passkey);
      assertNotNull(UUID.fromString((String) passkey.get("aaguid")));
      assertNotNull(passkey.get("createdAt"));
    }
  }

  // --- removing -----------------------------------------------------------------------------------

  @Test
  public void removingOneOfTwoPasskeysStopsItLoggingInAndKeepsTheOther() {
    Account account = account();
    WebAuthnTestHardware second = new WebAuthnTestHardware();
    addPasskey(account, second);
    List<String> ids = credentialIds(account.userId());
    assertEquals(2, ids.size());

    delete(account.session(), ids.get(1)).then().statusCode(204);

    assertEquals(List.of(ids.get(0)), credentialIds(account.userId()));
    list(account.session()).then().statusCode(200).body("credentialId", equalTo(List.of(ids.get(0))));
    login(second, account.username()).then().statusCode(401);
    login(account.authenticator(), account.username()).then().statusCode(200);
  }

  @Test
  public void aForeignOrUnknownCredentialIdIs404AndRemovesNothing() {
    Account mine = account();
    Account theirs = account();
    WebAuthnTestHardware extra = new WebAuthnTestHardware();
    addPasskey(theirs, extra);
    List<String> foreign = credentialIds(theirs.userId());

    delete(mine.session(), foreign.get(0))
        .then()
        .statusCode(404)
        .body("error", equalTo("not_found"))
        .body("error_description", equalTo("passkey not found"));
    delete(mine.session(), "no-such-credential-" + UUID.randomUUID()).then().statusCode(404);

    assertEquals(foreign, credentialIds(theirs.userId()));
  }

  @Test
  public void theLastPasskeyOfAnAccountWithNoPasswordIsKept() {
    Account account = account();
    List<String> ids = credentialIds(account.userId());
    assertEquals(1, ids.size());

    JsonPath refused = delete(account.session(), ids.get(0)).then().statusCode(409).extract().jsonPath();
    assertEquals("conflict", refused.getString("error"));
    assertEquals(
        "this is the account's only way to sign in: set a password or add another passkey first",
        refused.getString("error_description"));

    assertEquals(ids, credentialIds(account.userId()), "the row remains");
    login(account.authenticator(), account.username()).then().statusCode(200);
  }

  @Test
  public void theLastPasskeyMayGoOnceThereIsAPassword() {
    Account account = account();
    given()
        .cookie(SessionCookie.NAME, account.session())
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("password", "a password").encode())
        .when()
        .post("/idp/api/auth/password")
        .then()
        .statusCode(204);

    delete(account.session(), credentialIds(account.userId()).get(0)).then().statusCode(204);

    assertEquals(List.of(), credentialIds(account.userId()));
    given()
        .contentType(ContentType.JSON)
        .body(
            new JsonObject().put("username", account.username()).put("password", "a password").encode())
        .when()
        .post("/idp/api/auth/login")
        .then()
        .statusCode(200);
  }

  // --- the caller ---------------------------------------------------------------------------------

  @Test
  public void noSessionIs401OnBothDoors() {
    Account account = account();
    String id = credentialIds(account.userId()).get(0);

    given().when().get("/idp/api/passkeys").then().statusCode(401);
    given().when().delete("/idp/api/passkeys/" + id).then().statusCode(401);
    given()
        .cookie(SessionCookie.NAME, "not-a-session")
        .when()
        .get("/idp/api/passkeys")
        .then()
        .statusCode(401)
        .header("WWW-Authenticate", nullValue());
    given().cookie(SessionCookie.NAME, "not-a-session").when().delete("/idp/api/passkeys/" + id)
        .then()
        .statusCode(401);
  }

  @Test
  public void aBearerIs403OnBothDoorsEvenBesideALiveSession() {
    Account account = account();
    String id = credentialIds(account.userId()).get(0);
    String bearer = "Bearer " + tokenService.cli(account.userId()).accessToken();

    for (String authorization : List.of(bearer, "Bearer anything", basic(SYSTEM, SYSTEM_SECRET))) {
      given()
          .header("Authorization", authorization)
          .cookie(SessionCookie.NAME, account.session())
          .when()
          .get("/idp/api/passkeys")
          .then()
          .statusCode(403)
          .body("error", equalTo("access_denied"));
      given()
          .header("Authorization", authorization)
          .cookie(SessionCookie.NAME, account.session())
          .when()
          .delete("/idp/api/passkeys/" + id)
          .then()
          .statusCode(403);
    }
    // A person's CLI bearer alone, with no session beside it, is 403 as well.
    given().header("Authorization", bearer).when().get("/idp/api/passkeys").then().statusCode(403);

    assertEquals(List.of(id), credentialIds(account.userId()));
  }

  // --- helpers ------------------------------------------------------------------------------------

  /** A passkey account just registered: its first authenticator and the session it opened. */
  private record Account(
      String username, UUID userId, String session, WebAuthnTestHardware authenticator) {}

  private Account account() {
    String username = "passkeys-" + UUID.randomUUID();
    WebAuthnTestHardware authenticator = new WebAuthnTestHardware();
    String token = mintToken();
    CookieFilter browser = new CookieFilter();
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
    Response registered =
        given()
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
    registered.then().statusCode(200);
    return new Account(
        username,
        UUID.fromString(registered.jsonPath().getString("userId")),
        sessionOf(registered),
        authenticator);
  }

  /** A second authenticator, added from the account's live session as the account page does. */
  private void addPasskey(Account account, WebAuthnTestHardware authenticator) {
    CookieFilter signedIn = new CookieFilter();
    String challenge =
        given()
            .filter(signedIn)
            .cookie(SessionCookie.NAME, account.session())
            .contentType(ContentType.JSON)
            .body(new JsonObject().encode())
            .when()
            .post("/idp/api/auth/register-options")
            .then()
            .statusCode(200)
            .extract()
            .path("challenge");
    given()
        .filter(signedIn)
        .cookie(SessionCookie.NAME, account.session())
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("attestation", authenticator.registration(challenge)).encode())
        .when()
        .post("/idp/api/auth/register")
        .then()
        .statusCode(200);
  }

  private Response login(WebAuthnTestHardware authenticator, String username) {
    CookieFilter visit = new CookieFilter();
    String challenge =
        given()
            .filter(visit)
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", username).encode())
            .when()
            .post("/idp/api/auth/login-options")
            .then()
            .statusCode(200)
            .extract()
            .path("challenge");
    return given()
        .filter(visit)
        .contentType(ContentType.JSON)
        .body(
            new JsonObject()
                .put("username", username)
                .put("assertion", authenticator.assertion(challenge))
                .encode())
        .when()
        .post("/idp/api/auth/login");
  }

  private static Response list(String session) {
    return given().cookie(SessionCookie.NAME, session).when().get("/idp/api/passkeys");
  }

  private static Response delete(String session, String credentialId) {
    return given()
        .cookie(SessionCookie.NAME, session)
        .when()
        .delete("/idp/api/passkeys/{credentialId}", credentialId);
  }

  /** The account's credential ids as the store holds them, oldest first. */
  private List<String> credentialIds(UUID userId) {
    return QuarkusTransaction.requiringNew()
        .call(
            () ->
                credentials.listForUser(userId).stream()
                    .map((IdpWebAuthnCredential row) -> row.credentialId)
                    .toList());
  }

  private String mintToken() {
    return given()
        .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(201)
        .extract()
        .path("token");
  }

  private static String sessionOf(Response response) {
    String line =
        response.getHeaders().getValues("Set-Cookie").stream()
            .filter(l -> l.startsWith(SessionCookie.NAME + "="))
            .findFirst()
            .orElseThrow(() -> new AssertionError("no session cookie"));
    return line.substring((SessionCookie.NAME + "=").length(), line.indexOf(';'));
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
