package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import eu.wohlben.qits.eventstream.entity.OutboxEvent;
import io.quarkus.hibernate.orm.PersistenceUnit;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@code DELETE /idp/api/users/{username}} announces {@code UserDeleted} (qits-1977), asserted as
 * rows in the real outbox.
 *
 * <p><b>The bus is on and aimed at a CLOSED PORT</b>, which is what makes a publish assertable from
 * this side: {@code QitsEventBus.publish} tries the idempotent PUT inline and hands anything that
 * does not land to the outbox, so every published event becomes exactly one row carrying the
 * canonical payload it would have been sent with. The suite's scheduler is off, so no sweeper moves
 * a row under an assertion. A class of its own because a bus that is on is a different process
 * configuration, and {@code @TestProfile} is per class.
 *
 * <p>The door's answers are {@link UserAdministrationTest}'s; what is under test here is only what
 * each answer publishes.
 */
@QuarkusTest
@TestProfile(UserDeletedPublishTest.BusEnabled.class)
public class UserDeletedPublishTest {

  private static final String SYSTEM = "test-broad";
  private static final String SYSTEM_SECRET = "test-broad-secret";

  public static class BusEnabled implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "qits.eventstream.enabled", "true",
          // Nothing answers here: a refused connection is immediate, so the event lands in the
          // outbox rather than on a socket.
          "qits.events.url", "http://localhost:1");
    }
  }

  /**
   * The outbox through its OWN persistence unit: {@code OutboxEvent} comes from the eventstream jar,
   * and a Panache static on an entity this application did not compile is not enhanced here.
   */
  @Inject
  @PersistenceUnit("eventstream")
  EntityManager outbox;

  @BeforeEach
  void forgetPreviousPublishes() {
    QuarkusTransaction.requiringNew()
        .run(() -> outbox.createQuery("delete from OutboxEvent").executeUpdate());
  }

  @Test
  public void aDeletePublishesExactlyOneUserDeletedWithTheAccountsId() {
    Registered admin = registerWithPassword(mintBySystem());
    Registered victim = registerWithPassword(mintBySystem());

    given()
        .cookie(SessionCookie.NAME, admin.session())
        .when()
        .delete("/idp/api/users/{username}", victim.username())
        .then()
        .statusCode(204);

    List<OutboxEvent> rows = rows();
    assertEquals(1, rows.size(), "one delete, one event: " + rows);
    OutboxEvent row = rows.get(0);
    assertEquals("UserDeleted", row.name);
    JsonObject payload = new JsonObject(row.payload);
    assertEquals(victim.userId().toString(), payload.getString("userId"), row.payload);
    assertEquals(victim.username(), payload.getString("username"), row.payload);
    // The envelope's identity stays out of the payload (the library's mix-in).
    assertFalse(payload.containsKey("eventId"), row.payload);
  }

  @Test
  public void theRefusedSelfDeletePublishesNothing() {
    Registered admin = registerWithPassword(mintBySystem());

    given()
        .cookie(SessionCookie.NAME, admin.session())
        .when()
        .delete("/idp/api/users/{username}", admin.username())
        .then()
        .statusCode(409)
        .body("error", equalTo("conflict"));

    assertEquals(List.of(), rows());
  }

  @Test
  public void anUnknownUserPublishesNothing() {
    given()
        .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
        .when()
        .delete("/idp/api/users/{username}", "nobody-" + UUID.randomUUID())
        .then()
        .statusCode(404);

    assertEquals(List.of(), rows());
  }

  // --- helpers ----------------------------------------------------------------------------------

  record Registered(UUID userId, String username, String session) {}

  private List<OutboxEvent> rows() {
    return QuarkusTransaction.requiringNew()
        .call(
            () ->
                outbox
                    .createQuery("from OutboxEvent", OutboxEvent.class)
                    .getResultList());
  }

  private static String mintBySystem() {
    return given()
        .header("Authorization", basic(SYSTEM, SYSTEM_SECRET))
        .when()
        .post("/idp/api/register-tokens")
        .then()
        .statusCode(201)
        .extract()
        .path("token");
  }

  private static Registered registerWithPassword(String token) {
    String username = "publish-" + UUID.randomUUID();
    Response registered =
        given()
            .contentType(ContentType.JSON)
            .body(new JsonObject().put("username", username).put("token", token).encode())
            .when()
            .post("/idp/api/auth/register");
    registered.then().statusCode(200);
    return new Registered(
        UUID.fromString(registered.jsonPath().getString("userId")),
        username,
        sessionCookieOf(registered));
  }

  private static String sessionCookieOf(Response response) {
    String line =
        response.getHeaders().getValues("Set-Cookie").stream()
            .filter(value -> value.startsWith(SessionCookie.NAME + "="))
            .findFirst()
            .orElseThrow();
    return line.substring((SessionCookie.NAME + "=").length(), line.indexOf(';'));
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
