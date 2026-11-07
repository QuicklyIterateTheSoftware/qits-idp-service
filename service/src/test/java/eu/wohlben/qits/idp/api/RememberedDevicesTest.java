package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.ClientSecret;
import eu.wohlben.qits.idp.control.CommissionedTokens;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.entity.IdpDevice;
import eu.wohlben.qits.idp.entity.IdpDeviceSecret;
import eu.wohlben.qits.idp.entity.IdpSession;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/**
 * Remembered devices end to end (qits-1944): a login that asks to be remembered gets a {@code
 * qits-device} cookie, {@code /api/auth/resume} spends it for a fresh session and rotates it, a
 * spent secret within the grace is two tabs and past it a theft, and the account lists and revokes
 * its devices from a session or from its CLI bearer.
 *
 * <p><b>The clock is moved in the store, not waited out.</b> The shipped deadlines are thirty and
 * ninety days and the grace thirty seconds; a case that needs one of them behind it backdates the
 * row's column instead, which exercises exactly the comparison {@code Devices} makes against now —
 * and, for the grace, proves the shipped thirty seconds is the number in force.
 *
 * <p>Every case invents its own account: the suite shares one store.
 */
@QuarkusTest
public class RememberedDevicesTest {

  private static final String SYSTEM = "test-broad";
  private static final String SYSTEM_SECRET = "test-broad-secret";

  @Inject TokenService tokenService;

  @Inject CommissionedTokens commissionedTokens;

  // --- remembering -------------------------------------------------------------------------------

  @Test
  public void aRememberingPasswordLoginSetsBothCookiesAndAPlainOneOnlyTheSession() {
    Account account = account();

    Response remembered = login(account, true);
    remembered.then().statusCode(200).body("username", equalTo(account.username()));
    String device = deviceLine(remembered);
    assertNotNull(device, "a remembering login sets the device cookie");
    assertNotNull(sessionOf(remembered), "beside the session cookie");
    assertTrue(device.contains("; Path=/idp/api/auth;"), device);
    assertTrue(device.contains("; HttpOnly"), device);
    assertTrue(device.contains("; SameSite=Lax"), device);
    assertFalse(device.contains("Domain"), "host-only, whatever the session cookie does: " + device);
    assertFalse(device.contains("Secure"), "plain http here: " + device);
    long maxAge = maxAge(device);
    long ninetyDays = Duration.ofDays(90).toSeconds();
    assertTrue(
        maxAge <= ninetyDays && maxAge > ninetyDays - 60,
        "Max-Age counts down to the device's fixed deadline: " + device);
    assertEquals(43, deviceOf(remembered).length(), "256 bits, base64url");

    Response plain = login(account, false);
    plain.then().statusCode(200);
    assertNull(deviceLine(plain), "no remember, no device");

    // The row: labelled with the User-Agent, both deadlines stamped, the session linked to it.
    IdpDevice row = deviceRow(deviceOf(remembered));
    assertEquals("remembered-devices-test/1.0", row.label);
    assertEquals(row.createdAt.plus(Duration.ofDays(90)), row.absoluteExpiresAt);
    assertEquals(row.createdAt.plus(Duration.ofDays(30)), row.expiresAt);
    assertEquals(row.id, sessionRow(sessionOf(remembered)).deviceId);
    assertNull(sessionRow(sessionOf(plain)).deviceId);
  }

  @Test
  public void aRememberingPasskeyLoginSetsTheDeviceCookieToo() {
    String username = "remember-" + UUID.randomUUID();
    WebAuthnTestHardware authenticator = new WebAuthnTestHardware();
    CookieFilter browser = new CookieFilter();
    String token = mintToken();
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
        .post("/idp/api/auth/register")
        .then()
        .statusCode(200);

    CookieFilter visit = new CookieFilter();
    String loginChallenge =
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
    Response loggedIn =
        given()
            .filter(visit)
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("username", username)
                    .put("assertion", authenticator.assertion(loginChallenge))
                    .put("remember", true)
                    .encode())
            .when()
            .post("/idp/api/auth/login");
    loggedIn.then().statusCode(200).body("username", equalTo(username));
    assertNotNull(deviceOf(loggedIn));
    resume(deviceOf(loggedIn)).then().statusCode(204);
  }

  // --- resuming ----------------------------------------------------------------------------------

  @Test
  public void resumingWithTheCurrentSecretOpensASessionAndRotatesTheSecret() {
    Account account = account();
    Response remembered = login(account, true);
    String first = deviceOf(remembered);

    Response resumed = resume(first);
    resumed.then().statusCode(204).header("Cache-Control", "no-store");
    String session = sessionOf(resumed);
    assertNotNull(session, "a resume signs the browser in");
    assertNotEquals(sessionOf(remembered), session, "with a session of its own");
    introspect(session).then().statusCode(200).body("username", equalTo(account.username()));
    String second = deviceOf(resumed);
    assertNotNull(second, "and rotates the device secret");
    assertNotEquals(first, second);
    assertTrue(deviceLine(resumed).contains("; Path=/idp/api/auth;"), deviceLine(resumed));

    IdpDeviceSecret spent = secretRow(first);
    IdpDeviceSecret current = secretRow(second);
    assertNotNull(spent.supersededAt, "the presented secret is spent");
    assertNull(current.supersededAt, "and its successor is the current one");
    assertEquals(spent.deviceId, current.deviceId, "of the same device");
    assertEquals(spent.deviceId, sessionRow(session).deviceId, "which the session names");

    // The idle deadline moved, the fixed one did not.
    IdpDevice device = deviceRow(second);
    assertEquals(device.lastUsedAt.plus(Duration.ofDays(30)), device.expiresAt);
    assertEquals(device.createdAt.plus(Duration.ofDays(90)), device.absoluteExpiresAt);

    // The rotated secret resumes in turn.
    resume(second).then().statusCode(204);
  }

  @Test
  public void aJustSpentSecretWithinTheGraceOpensASessionWithoutRotating() {
    String first = deviceOf(login(account(), true));
    String second = deviceOf(resume(first));

    // The second tab, still holding the pre-rotation cookie.
    Response tab = resume(first);
    tab.then().statusCode(204);
    introspect(sessionOf(tab)).then().statusCode(200);
    assertNull(deviceLine(tab), "nothing rotated, so the browser keeps the other tab's cookie");

    // And the winner's secret is untouched by the loser.
    assertNull(secretRow(second).supersededAt);
    resume(second).then().statusCode(204);
  }

  @Test
  public void twoResumesAtOnceBothSucceedAndExactlyOneRotates() {
    String secret = deviceOf(login(account(), true));

    CompletableFuture<Response> one = CompletableFuture.supplyAsync(() -> resume(secret));
    CompletableFuture<Response> other = CompletableFuture.supplyAsync(() -> resume(secret));
    List<Response> both = List.of(one.join(), other.join());

    for (Response answer : both) {
      answer.then().statusCode(204);
      introspect(sessionOf(answer)).then().statusCode(200);
    }
    assertEquals(
        1,
        both.stream().filter(answer -> deviceLine(answer) != null).count(),
        "the device lock serializes the two: one rotates, the other is inside the grace");
  }

  @Test
  public void aSpentSecretPastTheGraceRevokesTheDeviceAndEverySessionItOpened() {
    Account account = account();
    Response remembered = login(account, true);
    String first = deviceOf(remembered);
    Response resumed = resume(first);
    String second = deviceOf(resumed);
    Response unrelated = login(account, false);

    // Spent thirty-one seconds ago: past the shipped thirty.
    inTx(
        () ->
            IdpDeviceSecret.update(
                "supersededAt = ?1 where tokenHash = ?2",
                Instant.now().minusSeconds(31),
                ClientSecret.hash(first)));

    Response replayed = resume(first);
    assertRefused(replayed);

    assertNotNull(deviceRow(second).revokedAt, "the device is revoked");
    introspect(sessionOf(remembered)).then().statusCode(404);
    introspect(sessionOf(resumed)).then().statusCode(404);
    assertRefused(resume(second));
    // A session the device never opened is not the device's to end.
    introspect(sessionOf(unrelated)).then().statusCode(200);
  }

  @Test
  public void noUnknownOrBlankCookieIsTheLoginsOne401AndClearsTheCookie() {
    assertRefused(given().when().post("/idp/api/auth/resume"));
    assertRefused(resume("not-a-device-" + UUID.randomUUID()));
    assertRefused(given().cookie(DeviceCookie.NAME, "").when().post("/idp/api/auth/resume"));

    // The same shape as a login refused for bad credentials.
    Account account = account();
    JsonPath login =
        given()
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("username", account.username())
                    .put("password", "wrong")
                    .encode())
            .when()
            .post("/idp/api/auth/login")
            .then()
            .statusCode(401)
            .extract()
            .jsonPath();
    JsonPath resume = resume("unknown").jsonPath();
    assertEquals(login.getMap("$").keySet(), resume.getMap("$").keySet());
    assertEquals(login.getString("error"), resume.getString("error"));
  }

  @Test
  public void aDevicePastEitherDeadlineIsRefused() {
    String idle = deviceOf(login(account(), true));
    UUID idleId = secretRow(idle).deviceId;
    inTx(() -> IdpDevice.update("expiresAt = ?1 where id = ?2", Instant.now().minusSeconds(1), idleId));
    assertRefused(resume(idle));

    // Used yesterday, so idle is fresh — but its fixed deadline has passed.
    String absolute = deviceOf(login(account(), true));
    UUID absoluteId = secretRow(absolute).deviceId;
    inTx(
        () ->
            IdpDevice.update(
                "absoluteExpiresAt = ?1 where id = ?2", Instant.now().minusSeconds(1), absoluteId));
    assertRefused(resume(absolute));
  }

  // --- listing and revoking ----------------------------------------------------------------------

  @Test
  public void aSessionListsItsAccountsLiveDevicesAndMarksItsOwnCurrent() {
    Account account = account();
    Response older = login(account, true);
    Response newer = login(account, true);
    Response plain = login(account, false);
    UUID olderId = secretRow(deviceOf(older)).deviceId;
    UUID newerId = secretRow(deviceOf(newer)).deviceId;
    // And one more that is revoked, which the listing leaves out.
    Response gone = login(account, true);
    revoke(given().cookie(SessionCookie.NAME, sessionOf(plain)), secretRow(deviceOf(gone)).deviceId)
        .then()
        .statusCode(204);
    // Another account's device is never listed.
    login(account(), true);

    Response listed = given().cookie(SessionCookie.NAME, sessionOf(older)).when().get(DEVICES);
    listed.then().statusCode(200).header("Cache-Control", "no-store");
    List<Map<String, Object>> rows = listed.jsonPath().getList("$");
    assertEquals(
        List.of(newerId.toString(), olderId.toString()),
        rows.stream().map(row -> row.get("id")).toList(),
        "live devices only, most recently used first");
    assertEquals(
        List.of(
            "absoluteExpiresAt", "createdAt", "current", "expiresAt", "id", "label", "lastUsedAt"),
        rows.get(0).keySet().stream().sorted().toList(),
        "a device is its timestamps and label; never a secret");
    assertEquals(List.of(false, true), rows.stream().map(row -> row.get("current")).toList());
    assertEquals("remembered-devices-test/1.0", rows.get(0).get("label"));

    // A session from an ordinary login has no current device.
    List<Object> currents =
        given()
            .cookie(SessionCookie.NAME, sessionOf(plain))
            .when()
            .get(DEVICES)
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .getList("current");
    assertEquals(List.of(false, false), currents);
  }

  @Test
  public void revokingADeviceEndsItsSessionsAndItsResume() {
    Account account = account();
    Response remembered = login(account, true);
    String secret = deviceOf(remembered);
    Response resumed = resume(secret);
    UUID id = secretRow(secret).deviceId;
    Response manager = login(account, false);

    // Somebody else cannot revoke it: a foreign id is a 404 and changes nothing.
    Response stranger = login(account(), false);
    revoke(given().cookie(SessionCookie.NAME, sessionOf(stranger)), id).then().statusCode(404);
    introspect(sessionOf(resumed)).then().statusCode(200);

    revoke(given().cookie(SessionCookie.NAME, sessionOf(manager)), id).then().statusCode(204);
    introspect(sessionOf(remembered)).then().statusCode(404);
    introspect(sessionOf(resumed)).then().statusCode(404);
    introspect(sessionOf(manager)).then().statusCode(200);
    assertRefused(resume(deviceOf(resumed)));
    revoke(given().cookie(SessionCookie.NAME, sessionOf(manager)), id).then().statusCode(404);
    revoke(given().cookie(SessionCookie.NAME, sessionOf(manager)), UUID.randomUUID())
        .then()
        .statusCode(404);
  }

  @Test
  public void logoutForgetsTheDeviceAndClearsBothCookies() {
    // Sent with the device cookie: the login's own device.
    Response remembered = login(account(), true);
    Response loggedOut =
        given()
            .cookie(SessionCookie.NAME, sessionOf(remembered))
            .cookie(DeviceCookie.NAME, deviceOf(remembered))
            .when()
            .post("/idp/api/auth/logout");
    loggedOut.then().statusCode(204);
    assertEquals(
        "qits-device=; Path=/idp/api/auth; Max-Age=0; HttpOnly; SameSite=Lax",
        deviceLine(loggedOut));
    assertNotNull(sessionLine(loggedOut));
    assertRefused(resume(deviceOf(remembered)));

    // Without it: the device the session was opened through.
    String secret = deviceOf(login(account(), true));
    Response resumed = resume(secret);
    given()
        .cookie(SessionCookie.NAME, sessionOf(resumed))
        .when()
        .post("/idp/api/auth/logout")
        .then()
        .statusCode(204);
    assertRefused(resume(deviceOf(resumed)));
  }

  // --- the bearer --------------------------------------------------------------------------------

  @Test
  public void aPersonsCliBearerListsAndRevokesItsOwnDevices() {
    Account account = account();
    Response remembered = login(account, true);
    UUID id = secretRow(deviceOf(remembered)).deviceId;
    String bearer = "Bearer " + tokenService.cli(account.userId()).accessToken();

    given()
        .header("Authorization", bearer)
        .when()
        .get(DEVICES)
        .then()
        .statusCode(200)
        .body("id", equalTo(List.of(id.toString())))
        .body("current", equalTo(List.of(false)));
    revoke(given().header("Authorization", bearer), id).then().statusCode(204);
    introspect(sessionOf(remembered)).then().statusCode(404);
  }

  @Test
  public void everyOtherBearerIs403AndNoCredentialIs401() {
    Account account = account();
    UUID id = secretRow(deviceOf(login(account, true))).deviceId;

    String service = clientCredentials(basic(SYSTEM, SYSTEM_SECRET));
    JsonPath agent =
        given()
            .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("contextKind", "workspace")
                    .put("contextId", "remembered-" + UUID.randomUUID())
                    .encode())
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .extract()
            .jsonPath();
    String agentToken =
        clientCredentials(basic(agent.getString("clientId"), agent.getString("secret")));
    String workstation = tokenService.workstation(account.userId()).accessToken();

    String commissioned =
        commissionedTokens
            .commission(SYSTEM, "workspace", "remembered-" + UUID.randomUUID(), Map.of(), List.of())
            .value();
    List<String> refused = new ArrayList<>(List.of(service, agentToken, workstation, commissioned));
    for (String bearer : refused) {
      given()
          .header("Authorization", "Bearer " + bearer)
          .when()
          .get(DEVICES)
          .then()
          .statusCode(403)
          .body("error", equalTo("access_denied"));
      revoke(given().header("Authorization", "Bearer " + bearer), id)
          .then()
          .statusCode(403)
          .body("error", equalTo("access_denied"));
    }
    // Basic is not a way in either.
    given().header("Authorization", basic(SYSTEM, SYSTEM_SECRET)).when().get(DEVICES)
        .then().statusCode(403);
    // A bearer that is not a token of this idp did not authenticate.
    given().header("Authorization", "Bearer not-a-jwt").when().get(DEVICES).then().statusCode(401);

    given()
        .when()
        .get(DEVICES)
        .then()
        .statusCode(401)
        .header("WWW-Authenticate", nullValue())
        .body("error", equalTo("invalid_credentials"));
    revoke(given(), id).then().statusCode(401);
    revoke(given().cookie(SessionCookie.NAME, "not-a-session"), id).then().statusCode(401);

    // And the device survived all of it.
    assertNull(inTx(() -> IdpDevice.<IdpDevice>findById(id)).revokedAt);
  }

  // --- helpers ------------------------------------------------------------------------------------

  private static final String DEVICES = "/idp/api/remembered-devices";

  record Account(UUID userId, String username, String password) {}

  /** A fresh account with the password the idp generated for it. */
  private Account account() {
    String username = "remember-" + UUID.randomUUID();
    JsonPath registered =
        given()
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", username).put("token", mintToken()).encode())
            .when()
            .post("/idp/api/auth/register")
            .then()
            .statusCode(200)
            .extract()
            .jsonPath();
    return new Account(
        UUID.fromString(registered.getString("userId")), username, registered.getString("password"));
  }

  private static Response login(Account account, boolean remember) {
    return given()
        .header("User-Agent", "remembered-devices-test/1.0")
        .contentType(ContentType.JSON)
        .body(
            new JsonObject()
                .put("username", account.username())
                .put("password", account.password())
                .put("remember", remember)
                .encode())
        .when()
        .post("/idp/api/auth/login");
  }

  private static Response resume(String deviceSecret) {
    return given().cookie(DeviceCookie.NAME, deviceSecret).when().post("/idp/api/auth/resume");
  }

  private static Response revoke(io.restassured.specification.RequestSpecification spec, UUID id) {
    return spec.when().delete(DEVICES + "/{id}", id);
  }

  /** A refused resume: the login's 401, no session, and the device cookie cleared. */
  private static void assertRefused(Response response) {
    response.then().statusCode(401).body("error", equalTo("invalid_credentials"));
    assertNull(sessionLine(response), "a refused resume opens nothing");
    assertEquals(
        "qits-device=; Path=/idp/api/auth; Max-Age=0; HttpOnly; SameSite=Lax",
        deviceLine(response),
        "and tells the browser to stop presenting the cookie");
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

  private static Response introspect(String sessionToken) {
    return given()
        .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", sessionToken).encode())
        .when()
        .post("/idp/api/sessions/introspect");
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

  private static String line(Response response, String name) {
    return response.getHeaders().getValues("Set-Cookie").stream()
        .filter(value -> value.startsWith(name + "="))
        .findFirst()
        .orElse(null);
  }

  private static String sessionLine(Response response) {
    return line(response, SessionCookie.NAME);
  }

  private static String deviceLine(Response response) {
    return line(response, DeviceCookie.NAME);
  }

  private static String valueOf(String line, String name) {
    return line == null ? null : line.substring((name + "=").length(), line.indexOf(';'));
  }

  private static String sessionOf(Response response) {
    return valueOf(sessionLine(response), SessionCookie.NAME);
  }

  private static String deviceOf(Response response) {
    return valueOf(deviceLine(response), DeviceCookie.NAME);
  }

  private static long maxAge(String line) {
    int start = line.indexOf("; Max-Age=") + "; Max-Age=".length();
    return Long.parseLong(line.substring(start, line.indexOf(';', start)));
  }

  private static IdpDeviceSecret secretRow(String secret) {
    return inTx(() -> IdpDeviceSecret.<IdpDeviceSecret>findById(ClientSecret.hash(secret)));
  }

  private static IdpDevice deviceRow(String secret) {
    UUID id = secretRow(secret).deviceId;
    return inTx(() -> IdpDevice.<IdpDevice>findById(id));
  }

  private static IdpSession sessionRow(String token) {
    return inTx(
        () ->
            IdpSession.<IdpSession>find("tokenHash", ClientSecret.hash(token)).firstResult());
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
