package eu.wohlben.qits.idp.api;

import static eu.wohlben.qits.idp.api.CliOAuthTest.param;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * A platform page signs in as the public client {@code qits-spa}: its callback is {@code
 * https://<platform host>/auth/callback}, the host held to the same anchor as the login page's
 * {@code return_host} ({@link BrowserSso#allows}); every other target is refused, PKCE S256 is
 * required, and the token is the CLI's.
 *
 * <p>The suite's own domain is {@code localhost}, whose anchor names only {@code
 * localhost:8080}-style authorities — and this client takes the default port only — so this class
 * states a public domain instead. Only the browser-boundary keys move; the issuer stays the
 * suite's.
 */
@QuarkusTest
@TestProfile(SpaOAuthTest.PublicDomain.class)
public class SpaOAuthTest {

  private static final String DOMAIN = "wohlben.eu";

  /** The landing app, on the platform's apex. */
  private static final String CALLBACK = "https://qits." + DOMAIN + "/auth/callback";

  private static final String CLIENT = "qits-spa";

  private static final String VERIFIER =
      "spa-verifier-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

  public static class PublicDomain implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          PlatformDomain.DOMAIN, DOMAIN,
          PlatformDomain.WEBAUTHN_ORIGINS, PlatformDomain.canonicalOrigin(DOMAIN),
          PlatformDomain.WEBAUTHN_RP_ID, PlatformDomain.relyingPartyId(DOMAIN));
    }
  }

  @Inject IdpUserRepository users;

  @Inject Sessions sessions;

  @Test
  public void aPlatformCallbackTradesACodeForThePersonsCliTokenAndTheRefreshRotates()
      throws Exception {
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
    assertEquals(List.of("refs/heads/external/*"), claims.getStringListClaimValue("git_refs"));

    // The code is spent: a second exchange is refused.
    token("authorization_code", CALLBACK, code, VERIFIER, null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));

    String refresh = exchanged.jsonPath().getString("refresh_token");
    Response refreshed = token("refresh_token", null, null, null, refresh);
    refreshed.then().statusCode(200).body("expires_in", equalTo(900));
    String rotated = refreshed.jsonPath().getString("refresh_token");
    assertNotEquals(refresh, rotated);
    assertEquals(
        List.of("refs/heads/external/*"),
        PublishedJwks.verify(refreshed.jsonPath().getString("access_token"), "qits-platform")
            .getStringListClaimValue("git_refs"));
    // Replaying the rotated-out token revokes the family, the rotated one with it.
    token("refresh_token", null, null, null, refresh).then().statusCode(400);
    token("refresh_token", null, null, null, rotated).then().statusCode(400);
  }

  @Test
  public void everyHostTheLoginAnchorAdmitsIsAccepted() {
    Sessions.Opened session = signedInSession();
    for (String callback :
        List.of(
            "https://" + DOMAIN + "/auth/callback",
            "https://qits." + DOMAIN + "/auth/callback",
            "https://projects.qits." + DOMAIN + "/auth/callback",
            "https://projects.dev.qits." + DOMAIN + "/auth/callback",
            "https://idp.qits." + DOMAIN + "/auth/callback")) {
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
            // A foreign host, however it is spelled.
            "https://evil.example/auth/callback",
            "https://" + DOMAIN + ".example/auth/callback",
            "https://qits." + DOMAIN + ".example/auth/callback",
            "https://evil" + DOMAIN + "/auth/callback",
            // Deeper than the anchor's grammar.
            "https://a.projects.dev.qits." + DOMAIN + "/auth/callback",
            // Not https.
            "http://qits." + DOMAIN + "/auth/callback",
            // Any explicit port, the default one included.
            "https://qits." + DOMAIN + ":443/auth/callback",
            "https://qits." + DOMAIN + ":8443/auth/callback",
            // Another path.
            "https://qits." + DOMAIN + "/auth/callback/",
            "https://qits." + DOMAIN + "/other",
            "https://qits." + DOMAIN + "/",
            // A query, a fragment, userinfo.
            "https://qits." + DOMAIN + "/auth/callback?x=1",
            "https://qits." + DOMAIN + "/auth/callback#x",
            "https://user@qits." + DOMAIN + "/auth/callback",
            // The dev SPA's loopback callback is not this client's.
            "http://localhost:4200/auth/callback",
            "not a uri")) {
      authorize(session.token(), CLIENT, foreign, challenge(VERIFIER), "S256")
          .then()
          .statusCode(400)
          .body("error", equalTo("invalid_request"));
    }
  }

  @Test
  public void pkceS256IsRequired() {
    Sessions.Opened session = signedInSession();
    for (String[] pkce :
        new String[][] {{null, null}, {challenge(VERIFIER), "plain"}, {null, "S256"}}) {
      Response refused = authorize(session.token(), CLIENT, CALLBACK, pkce[0], pkce[1]);
      refused.then().statusCode(303);
      String location = refused.getHeader("Location");
      assertTrue(location.startsWith(CALLBACK + "?"), location);
      assertEquals("invalid_request", param(location, "error"));
      assertEquals(null, param(location, "code"));
    }

    String code =
        param(
            authorize(session.token(), CLIENT, CALLBACK, challenge(VERIFIER), "S256")
                .getHeader("Location"),
            "code");
    token("authorization_code", CALLBACK, code, VERIFIER.replace('A', 'B'), null)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
  }

  @Test
  public void itPresentsNoSecretAndItsCodeIsNoOtherClientsCode() {
    Sessions.Opened session = signedInSession();
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

    String code =
        param(
            authorize(session.token(), CLIENT, CALLBACK, challenge(VERIFIER), "S256")
                .getHeader("Location"),
            "code");
    for (String other : List.of("qits-cli", "qits-landing-dev")) {
      given()
          .contentType(ContentType.URLENC)
          .formParam("grant_type", "authorization_code")
          .formParam("client_id", other)
          .formParam("code", code)
          .formParam("redirect_uri", CALLBACK)
          .formParam("code_verifier", VERIFIER)
          .when()
          .post("/idp/token")
          .then()
          .statusCode(400)
          .body("error", equalTo("invalid_grant"));
    }
  }

  @Test
  public void aPlatformCallbackIsStillRefusedForTheOtherPublicClients() {
    Sessions.Opened session = signedInSession();
    for (String other : List.of("qits-cli", "qits-landing-dev", "qits-git-workstation")) {
      authorize(session.token(), other, CALLBACK, challenge(VERIFIER), "S256")
          .then()
          .statusCode(400)
          .body("error", equalTo("invalid_request"));
    }
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
    String username = "platform-spa-" + id;
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
