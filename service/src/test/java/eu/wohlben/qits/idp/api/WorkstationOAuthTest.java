package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/** The PKCE browser hand-off, one-use code, rotating refresh token and constrained JWT contract. */
@QuarkusTest
public class WorkstationOAuthTest {

  private static final String CLIENT = "qits-git-workstation";
  /**
   * The githost audience a workstation used to be issued, and which qits-bootstrap may still send.
   * It is accepted and ignored now (qits-163): the token's {@code aud} is {@code qits-platform}.
   */
  private static final String AUDIENCE = "prod-qits-githost";
  private static final String REDIRECT = "http://127.0.0.1:38471/callback";
  private static final String VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefgh";

  @Inject IdpUserRepository users;

  @Inject Sessions sessions;

  @Test
  public void aSignedInUserGetsAConstrainedGitTokenAndRotatingRefreshCredential() throws Exception {
    Sessions.Opened session = signedInSession();
    String code = authorize(session.token(), VERIFIER, "state-that-must-return");

    Response exchanged = token("authorization_code", code, VERIFIER, null);
    exchanged.then()
        .statusCode(200)
        .body("token_type", equalTo("Bearer"))
        .body("expires_in", equalTo(900));
    String access = exchanged.jsonPath().getString("access_token");
    String firstRefresh = exchanged.jsonPath().getString("refresh_token");
    JwtClaims claims = PublishedJwks.verify(access, "qits-platform");
    assertEquals(List.of("qits-platform"), claims.getAudience(), "the one audience; no githost");
    assertEquals(session.session().userId().toString(), claims.getSubject());
    assertEquals(List.of("qits:git:external"), claims.getStringListClaimValue("groups"));
    // A USER credential, so no `clients/…` self-role: that stamp says "this bearer is that machine
    // client", and a resource service gating on one must not be reachable through a login.
    assertFalse(
        claims.getStringListClaimValue("groups").stream().anyMatch(g -> g.startsWith("clients/")),
        "only a client credential names a client");
    assertEquals("workstation", claims.getClaimValueAsString("credential_type"));
    // Both spellings: the old claim for githosts that read only it, and the list (C1).
    assertEquals("refs/heads/external/*", claims.getClaimValueAsString("git_ref_pattern"));
    assertEquals(List.of("refs/heads/external/*"), claims.getStringListClaimValue("git_refs"));

    Response refreshed = token("refresh_token", null, null, firstRefresh);
    refreshed.then().statusCode(200).body("expires_in", equalTo(900));
    String secondRefresh = refreshed.jsonPath().getString("refresh_token");
    assertNotEquals(firstRefresh, secondRefresh, "a refresh credential rotates on every use");

    // Replaying the old value revokes the family, including the token that rotation just produced.
    token("refresh_token", null, null, firstRefresh)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
    token("refresh_token", null, null, secondRefresh)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
  }

  @Test
  public void anAuthorizationCodeIsBoundToPkceAndUsedExactlyOnce() {
    Sessions.Opened session = signedInSession();
    String code = authorize(session.token(), VERIFIER, null);

    token("authorization_code", code, VERIFIER + "x", null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
    // A verifier mismatch must not consume the code: a local process retrying after a bug can still
    // present the correct verifier, while an attacker still cannot exchange it.
    token("authorization_code", code, VERIFIER, null).then().statusCode(200);
    token("authorization_code", code, VERIFIER, null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
  }

  @Test
  public void authorizeBouncesAnonymousToSignInAndRejectsNonLoopbackRedirects() {
    // CHANGED WITH THE CLI CLIENT, and it applies to the workstation too: an anonymous /authorize
    // is a person who has not signed in yet, which is the normal first step rather than an error.
    // The 401 it used to answer left a browser with nothing to do; the bounce carries this very
    // request back as the login page's return location.
    String bounce =
        given()
            .redirects()
            .follow(false)
            .queryParam("response_type", "code")
            .queryParam("client_id", CLIENT)
            .queryParam("redirect_uri", REDIRECT)
            .queryParam("code_challenge", challenge(VERIFIER))
            .queryParam("code_challenge_method", "S256")
            .queryParam("audience", AUDIENCE)
            .when()
            .get("/idp/authorize")
            .then()
            .statusCode(303)
            .extract()
            .header("Location");
    org.junit.jupiter.api.Assertions.assertTrue(
        bounce.startsWith("http://localhost:8080/idp/login?"), bounce);
    assertEquals("localhost:8080", CliOAuthTest.param(bounce, "return_host"));
    String returnPath = CliOAuthTest.param(bounce, "return_path");
    org.junit.jupiter.api.Assertions.assertTrue(
        returnPath.startsWith("/idp/authorize?"), returnPath);
    org.junit.jupiter.api.Assertions.assertTrue(returnPath.contains("client_id=" + CLIENT), returnPath);

    Sessions.Opened session = signedInSession();
    given()
        .redirects()
        .follow(false)
        .cookie(SessionCookie.NAME, session.token())
        .queryParam("response_type", "code")
        .queryParam("client_id", CLIENT)
        .queryParam("redirect_uri", "https://example.invalid/callback")
        .queryParam("code_challenge", challenge(VERIFIER))
        .queryParam("code_challenge_method", "S256")
        .queryParam("audience", AUDIENCE)
        .when()
        .get("/idp/authorize")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  private String authorize(String sessionToken, String verifier, String state) {
    io.restassured.specification.RequestSpecification request =
        given()
            .redirects()
            .follow(false)
            .cookie(SessionCookie.NAME, sessionToken)
            .queryParam("response_type", "code")
            .queryParam("client_id", CLIENT)
            .queryParam("redirect_uri", REDIRECT)
            .queryParam("code_challenge", challenge(verifier))
            .queryParam("code_challenge_method", "S256")
            .queryParam("audience", AUDIENCE);
    if (state != null) {
      request.queryParam("state", state);
    }
    Response response = request.when().get("/idp/authorize");
    response.then().statusCode(303);
    String query = URI.create(response.getHeader("Location")).getQuery();
    if (state != null) {
      org.junit.jupiter.api.Assertions.assertTrue(query.contains("state=" + state));
    }
    return query.substring(query.indexOf("code=") + "code=".length()).split("&")[0];
  }

  private static Response token(
      String grantType, String code, String verifier, String refreshToken) {
    io.restassured.specification.RequestSpecification request =
        given().contentType(ContentType.URLENC).formParam("grant_type", grantType).formParam("client_id", CLIENT);
    if (code != null) {
      request.formParam("code", code).formParam("redirect_uri", REDIRECT).formParam("code_verifier", verifier);
    }
    if (refreshToken != null) {
      request.formParam("refresh_token", refreshToken);
    }
    return request.when().post("/idp/token");
  }

  private Sessions.Opened signedInSession() {
    UUID id = UUID.randomUUID();
    String username = "workstation-" + id;
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpUser row = new IdpUser();
              row.id = id;
              row.username = username;
              row.createdAt = Instant.now();
              users.persist(row);
            });
    return sessions.open(new Users.Account(id, username, java.util.List.of("qits:admin")));
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
