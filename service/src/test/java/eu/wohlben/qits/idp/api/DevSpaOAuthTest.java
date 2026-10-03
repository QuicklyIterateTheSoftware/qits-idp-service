package eu.wohlben.qits.idp.api;

import static eu.wohlben.qits.idp.api.CliOAuthTest.param;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The landing SPA under {@code ng serve} signs in as the public client {@code qits-landing-dev}:
 * its callback is accepted on any port, every other target is refused, PKCE S256 is required, and
 * the token is the CLI's.
 */
@QuarkusTest
public class DevSpaOAuthTest {

  private static final String CLIENT = "qits-landing-dev";
  private static final String CALLBACK = "http://localhost:4200/auth/callback";

  private static final String VERIFIER =
      "spa-verifier-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

  @Inject IdpUserRepository users;

  @Inject Sessions sessions;

  @Test
  public void theCallbackOnLocalhostTradesACodeForThePersonsCliToken() throws Exception {
    Sessions.Opened session = signedInSession();
    Response approved = authorize(session.token(), CLIENT, CALLBACK, challenge(VERIFIER), "S256");
    approved.then().statusCode(303);
    String location = approved.getHeader("Location");
    assertTrue(location.startsWith(CALLBACK + "?"), location);
    assertEquals("s", param(location, "state"));
    String code = param(location, "code");

    Response exchanged = token("authorization_code", CALLBACK, code, VERIFIER, null);
    exchanged
        .then()
        .statusCode(200)
        .body("token_type", equalTo("Bearer"))
        .body("expires_in", equalTo(900))
        .body("refresh_expires_in", equalTo(720 * 3600));

    JwtClaims claims =
        PublishedJwks.verify(exchanged.jsonPath().getString("access_token"), "qits-platform");
    assertEquals(session.session().userId().toString(), claims.getSubject());
    assertEquals(List.of("qits-platform"), claims.getAudience());
    assertEquals(List.of("qits:admin"), claims.getStringListClaimValue("groups"));
    assertEquals("cli", claims.getClaimValueAsString("credential_type"));

    String refresh = exchanged.jsonPath().getString("refresh_token");
    Response refreshed = token("refresh_token", null, null, null, refresh);
    refreshed.then().statusCode(200).body("expires_in", equalTo(900));
    assertNotEquals(refresh, refreshed.jsonPath().getString("refresh_token"));
  }

  @Test
  public void anyPortOnEveryLoopbackSpellingIsAccepted() {
    Sessions.Opened session = signedInSession();
    for (String callback :
        List.of(
            "http://localhost:4201/auth/callback",
            "http://127.0.0.1:4200/auth/callback",
            "http://127.0.0.1:51234/auth/callback",
            "http://[::1]:4200/auth/callback")) {
      Response approved = authorize(session.token(), CLIENT, callback, challenge(VERIFIER), "S256");
      approved.then().statusCode(303);
      String location = approved.getHeader("Location");
      assertTrue(location.startsWith(callback + "?code="), location);
    }
  }

  @Test
  public void everyOtherTargetIsRefusedWithoutARedirect() {
    Sessions.Opened session = signedInSession();
    for (String foreign :
        List.of(
            "https://localhost:4200/auth/callback",
            "http://localhost/auth/callback",
            "http://localhost:4200/auth/callback/",
            "http://localhost:4200/other",
            "http://localhost:4200/auth/callback?x=1",
            "http://localhost:4200/auth/callback#x",
            "http://user@localhost:4200/auth/callback",
            "http://localhost.evil.example:4200/auth/callback",
            "http://evil.example:4200/auth/callback",
            "http://localhost:8080/idp/connect/cli")) {
      authorize(session.token(), CLIENT, foreign, challenge(VERIFIER), "S256")
          .then()
          .statusCode(400)
          .body("error", equalTo("invalid_request"));
    }
  }

  @Test
  public void localhostIsStillRefusedForTheCli() {
    Sessions.Opened session = signedInSession();
    authorize(session.token(), "qits-cli", CALLBACK, challenge(VERIFIER), "S256")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void pkceS256IsRequired() {
    Sessions.Opened session = signedInSession();
    // No challenge, and a plain one: refused, and the refusal reaches the callback page.
    for (String[] pkce : new String[][] {{null, null}, {challenge(VERIFIER), "plain"}, {null, "S256"}}) {
      Response refused = authorize(session.token(), CLIENT, CALLBACK, pkce[0], pkce[1]);
      refused.then().statusCode(303);
      String location = refused.getHeader("Location");
      assertTrue(location.startsWith(CALLBACK + "?"), location);
      assertEquals("invalid_request", param(location, "error"));
      assertEquals(null, param(location, "code"));
    }

    // At the token endpoint: the code is worth nothing without its verifier.
    String code =
        param(
            authorize(session.token(), CLIENT, CALLBACK, challenge(VERIFIER), "S256")
                .getHeader("Location"),
            "code");
    token("authorization_code", CALLBACK, code, null, null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    token("authorization_code", CALLBACK, code, VERIFIER.replace('A', 'B'), null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
  }

  @Test
  public void anAudienceIsIgnoredAndItPresentsNoSecret() {
    Sessions.Opened session = signedInSession();
    Response approved =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, session.token())
            .queryParam("response_type", "code")
            .queryParam("client_id", CLIENT)
            .queryParam("redirect_uri", CALLBACK)
            .queryParam("code_challenge", challenge(VERIFIER))
            .queryParam("code_challenge_method", "S256")
            .queryParam("audience", "prod-qits-githost")
            .when()
            .get("/idp/authorize");
    // Accepted and ignored (qits-163): a code, not an error.
    approved.then().statusCode(303);
    assertEquals(null, param(approved.getHeader("Location"), "error"));
    assertNotNull(param(approved.getHeader("Location"), "code"));

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
  }

  @Test
  public void itsCodeIsNotTheCliCode() {
    Sessions.Opened session = signedInSession();
    String code =
        param(
            authorize(session.token(), CLIENT, CALLBACK, challenge(VERIFIER), "S256")
                .getHeader("Location"),
            "code");
    given()
        .contentType(ContentType.URLENC)
        .formParam("grant_type", "authorization_code")
        .formParam("client_id", "qits-cli")
        .formParam("code", code)
        .formParam("redirect_uri", CALLBACK)
        .formParam("code_verifier", VERIFIER)
        .when()
        .post("/idp/token")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
  }

  // --- helpers ------------------------------------------------------------------------------------

  private static Response authorize(
      String sessionToken, String clientId, String redirectUri, String challenge, String method) {
    RequestSpecification request =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, sessionToken)
            .queryParam("response_type", "code")
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("state", "s");
    if (challenge != null) {
      request.queryParam("code_challenge", challenge);
    }
    if (method != null) {
      request.queryParam("code_challenge_method", method);
    }
    return request.when().get("/idp/authorize");
  }

  private static Response token(
      String grantType, String redirectUri, String code, String verifier, String refreshToken) {
    RequestSpecification request =
        given()
            .contentType(ContentType.URLENC)
            .formParam("grant_type", grantType)
            .formParam("client_id", CLIENT);
    if (code != null) {
      request.formParam("code", code).formParam("redirect_uri", redirectUri);
    }
    if (verifier != null) {
      request.formParam("code_verifier", verifier);
    }
    if (refreshToken != null) {
      request.formParam("refresh_token", refreshToken);
    }
    return request.when().post("/idp/token");
  }

  private Sessions.Opened signedInSession() {
    UUID id = UUID.randomUUID();
    String username = "spa-" + id;
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
}
