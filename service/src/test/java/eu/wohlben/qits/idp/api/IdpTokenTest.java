package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.Test;

/**
 * The token endpoint end to end. Tests address the absolute {@code /idp/token} path, which is what
 * makes them catch a prefix regression, and every issued token is verified against what {@code
 * /idp/jwks} published rather than against anything reachable in-process.
 *
 * <p>The clients are database rows the application adopted at start from {@code
 * src/test/resources/application.properties} (qits-163, {@code EnvironmentClientAdoption}). {@code
 * prod-qits-workspaces} is listed there without a secret, so it was never adopted — that is what the
 * blank-secret case runs against.
 *
 * <p>Every token's {@code aud} is {@code ["qits-platform"]}, whatever was asked for.
 */
@QuarkusTest
public class IdpTokenTest {

  @Test
  public void aServiceTokenHasTheOneAudienceTheFixedRolesAndItsSelfRole() throws Exception {
    String token =
        post("grant_type=client_credentials"
                + "&client_id=test-broad"
                + "&client_secret=test-broad-secret")
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            // The SHIPPED lifetime, raised to an hour on 2026-08-14 with the commission model.
            // That the key is honoured at all is TokenLifetimeTest's; this pins the default.
            .body("expires_in", equalTo(3600))
            .body("access_token", notNullValue())
            // RFC 6749 §5.1 — a token response is never cached.
            .header("Cache-Control", "no-store")
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-platform");
    assertEquals("test-broad", claims.getSubject());
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer());
    assertEquals(List.of("qits-platform"), PublishedJwks.audienceOf(claims));
    // The fixed service-client role, then the self-role this service stamps. The whole claim is
    // pinned rather than searched: `groups` is the token's shape, and a change to it is a change
    // every consumer reads.
    assertEquals(
        List.of("qits:system", "clients/test-broad"),
        claims.getStringListClaimValue("groups"));
    assertNotNull(claims.getIssuedAt(), "iat");
    assertEquals(
        3600,
        claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue(),
        "exp must be iat plus the configured lifetime");
    assertNotNull(
        PublishedJwks.kidOf(token), "every token carries a kid, or rotation is a flag day");
  }

  @Test
  public void anAudienceParameterIsAcceptedAndIgnored() throws Exception {
    // Any value — one the client used to be allowed, one it never was, the platform's own, several
    // at once — is accepted, and the answer is the one audience. Never invalid_target.
    for (String audience :
        List.of(
            "&audience=qits-deployments",
            "&audience=qits-platform-artifacts",
            "&audience=qits-platform",
            "&audience=never-heard-of-it",
            "&audience=a&audience=b",
            "&audience=a%20b")) {
      String token =
          post("grant_type=client_credentials"
                  + "&client_id=test-narrow"
                  + "&client_secret=test-narrow-secret"
                  + audience)
              .statusCode(200)
              .extract()
              .path("access_token");
      assertEquals(
          List.of("qits-platform"),
          PublishedJwks.audienceOf(PublishedJwks.verify(token, "qits-platform")),
          audience);
    }
  }

  @Test
  public void basicAuthenticationWorksLikeTheFormFields() throws Exception {
    String token =
        given()
            .contentType(ContentType.URLENC)
            .header("Authorization", basic("test-broad", "test-broad-secret"))
            .body("grant_type=client_credentials")
            .when()
            .post("/idp/token")
            .then()
            .statusCode(200)
            .extract()
            .path("access_token");

    assertEquals("test-broad", PublishedJwks.verify(token, "qits-platform").getSubject());
  }

  @Test
  public void aServiceClientCarriesTheFixedProjectClaimAndNoOther() throws Exception {
    String token =
        post("grant_type=client_credentials"
                + "&client_id=test-broad"
                + "&client_secret=test-broad-secret")
            .statusCode(200)
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-platform");
    assertEquals("*", claims.getClaimValueAsString("project"), "project=*, in code");
    assertFalse(claims.hasClaim("workspace"), "an ungranted claim must not appear");
    assertFalse(claims.hasClaim("branch"), "an ungranted claim must not appear");
    assertNull(claims.getClaimValue("scope"), "claims, not scope strings");
  }

  @Test
  public void everyClientTokenNamesItsOwnClientAndNoOther() throws Exception {
    String broad =
        post("grant_type=client_credentials"
                + "&client_id=test-broad"
                + "&client_secret=test-broad-secret")
            .statusCode(200)
            .extract()
            .path("access_token");
    String narrow =
        post("grant_type=client_credentials"
                + "&client_id=test-narrow"
                + "&client_secret=test-narrow-secret")
            .statusCode(200)
            .extract()
            .path("access_token");

    List<String> broadGroups =
        PublishedJwks.verify(broad, "qits-platform").getStringListClaimValue("groups");
    List<String> narrowGroups =
        PublishedJwks.verify(narrow, "qits-platform").getStringListClaimValue("groups");

    assertTrue(broadGroups.contains("clients/test-broad"), "a client token names its own client");
    assertTrue(narrowGroups.contains("clients/test-narrow"), "a client token names its own client");
    // The point of the whole feature: a role naming one client is held by that client only, so
    // @RolesAllowed("clients/<x>") is a door exactly one caller can reach.
    assertFalse(
        narrowGroups.contains("clients/test-broad"),
        "no client may hold another client's self-role");
    assertFalse(
        broadGroups.contains("clients/test-narrow"),
        "no client may hold another client's self-role");
  }

  @Test
  public void aConfiguredRolesOrAudiencesLineIsNotReadAnyMore() throws Exception {
    // test-role-thief's configuration still says roles=qits:system,clients/test-broad and
    // audiences=qits-deployments. Neither key is read (qits-163): the adopted client has the fixed
    // service-client roles and the one audience, and it cannot reach another client's identity.
    String token =
        post("grant_type=client_credentials"
                + "&client_id=test-role-thief"
                + "&client_secret=test-role-thief-secret")
            .statusCode(200)
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-platform");
    assertEquals(
        List.of("qits:system", "clients/test-role-thief"),
        claims.getStringListClaimValue("groups"));
    assertEquals(List.of("qits-platform"), PublishedJwks.audienceOf(claims));
  }

  @Test
  public void theWrongSecretIsRefused() {
    post("grant_type=client_credentials&client_id=test-broad&client_secret=wrong")
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .header("WWW-Authenticate", "Basic realm=\"qits-platform-idp\"");
  }

  @Test
  public void anUnknownClientIsRefused() {
    post("grant_type=client_credentials&client_id=not-a-client&client_secret=anything")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void aClientWithNoSecretIsUnusableRatherThanOpen() {
    // prod-qits-workspaces is listed for adoption with no secret, so it was never adopted. A blank
    // secret must be refused like a wrong one, never accepted as "no authentication required".
    post("grant_type=client_credentials&client_id=prod-qits-workspaces&client_secret=")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
    post("grant_type=client_credentials&client_id=prod-qits-workspaces")
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic("prod-qits-workspaces", ""))
        .body("grant_type=client_credentials")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void onlyClientCredentialsIsSupported() {
    post("grant_type=password&client_id=test-broad&client_secret=test-broad-secret&username=a")
        .statusCode(400)
        .body("error", equalTo("unsupported_grant_type"));
    post("client_id=test-broad&client_secret=test-broad-secret")
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void credentialsMayBePresentedOnlyOnce() {
    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic("test-broad", "test-broad-secret"))
        .body("grant_type=client_credentials&client_id=test-broad&client_secret=test-broad-secret")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void aRequestWithNoCredentialsIsRefused() {
    post("grant_type=client_credentials").statusCode(401).body("error", equalTo("invalid_client"));
  }

  @Test
  public void aTokenDoesNotVerifyForAnAudienceItDoesNotCarry() throws Exception {
    String token =
        post("grant_type=client_credentials"
                + "&client_id=test-narrow"
                + "&client_secret=test-narrow-secret"
                + "&audience=qits-deployments")
            .statusCode(200)
            .extract()
            .path("access_token");

    assertTrue(PublishedJwks.verify(token, "qits-platform").hasClaim("aud"));
    assertThrows(
        InvalidJwtException.class,
        () -> PublishedJwks.verify(token, "qits-deployments"),
        "a requested audience is ignored, so a receiver checking for its own name refuses it");
  }

  private static ValidatableResponse post(String form) {
    return given().contentType(ContentType.URLENC).body(form).when().post("/idp/token").then();
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
