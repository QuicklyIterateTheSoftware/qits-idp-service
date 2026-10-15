package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * That {@code qits.idp.session-ttl} is honoured, in both places a session's lifetime shows up.
 *
 * <p>It costs its own application start, for the same reason {@code TokenLifetimeTest} does: the
 * TTL is read once and the shipped twelve hours cannot be waited out. One second can be, and the
 * lever being connected is the whole assertion — the row's deadline and the cookie's {@code
 * Max-Age} both come from this one key, so a change that wired either of them to a constant fails
 * here.
 *
 * <p>The expiry half is what the {@code @QuarkusTest} suite next door cannot cover: it proves an
 * unknown and a revoked session refuse introspection, and this proves that a session nobody touched
 * refuses it too — the third of the three states the edge treats alike.
 */
@QuarkusTest
@TestProfile(SessionLifetimeTest.OneSecondSessions.class)
public class SessionLifetimeTest {

  private static final String EDGE = "test-broad";
  private static final String EDGE_SECRET = "test-broad-secret";

  /** A TTL a test can outlive. Nothing else about the application changes. */
  public static class OneSecondSessions implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of("qits.idp.session-ttl", "PT1S");
    }
  }

  @Test
  public void aSessionStopsIntrospectingOnceItsDeadlinePasses() throws Exception {
    String username = "user-" + UUID.randomUUID();
    String token =
        given()
            .header("Authorization", basic(EDGE, EDGE_SECRET))
            .when()
            .post("/idp/api/register-tokens")
            .then()
            .statusCode(201)
            .extract()
            .path("token");

    Response registered =
        given()
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", username).put("token", token).encode())
            .when()
            .post("/idp/api/auth/register");
    registered.then().statusCode(200);

    String setCookie =
        registered.getHeaders().getValues("Set-Cookie").stream()
            .filter(line -> line.startsWith(SessionCookie.NAME + "="))
            .findFirst()
            .orElse(null);
    assertNotNull(setCookie);
    assertTrue(
        setCookie.contains("; Max-Age=1"),
        "the cookie's Max-Age is the same value as the row's deadline: " + setCookie);
    String session = setCookie.substring((SessionCookie.NAME + "=").length(), setCookie.indexOf(';'));

    introspect(session).then().statusCode(200).body("username", equalTo(username));

    // Past the deadline the row is still there, unrevoked, and answers nothing — "expired" is a
    // comparison against the clock rather than a state written on the row.
    Thread.sleep(Duration.ofMillis(1500).toMillis());
    introspect(session).then().statusCode(404).body("error", equalTo("not_found"));

    // And it is no longer a session for the routes it used to authorise either.
    given()
        .cookie(SessionCookie.NAME, session)
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("password", "q").encode())
        .when()
        .post("/idp/api/auth/password")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_credentials"));
  }

  private static Response introspect(String sessionToken) {
    return given()
        .header("Authorization", basic(EDGE, EDGE_SECRET))
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", sessionToken).encode())
        .when()
        .post("/idp/api/sessions/introspect");
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
