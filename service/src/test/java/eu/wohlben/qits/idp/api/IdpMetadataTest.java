package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import io.quarkus.test.junit.QuarkusTest;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The two documents a consumer reads before it can validate anything. Both are asserted at their
 * absolute paths: {@code /idp/.well-known/openid-configuration} is where an OIDC client derives the
 * discovery document from an auth-server-url of {@code .../idp}, and moving it silently breaks
 * every consumer at once.
 */
@QuarkusTest
public class IdpMetadataTest {

  /**
   * The endpoints hang off the ADDRESS and the issuer is only the identifier. They are different
   * strings here on purpose — see {@link eu.wohlben.qits.idp.control.Issuer} — and asserting the
   * endpoints against {@code ISSUER} is exactly the mistake that shipped a {@code jwks_uri} on a
   * host nothing resolves.
   */
  @Test
  public void theDiscoveryDocumentAdvertisesEndpointsDerivedFromTheAddressAndNotTheIssuer() {
    given()
        .when()
        .get("/idp/.well-known/openid-configuration")
        .then()
        .statusCode(200)
        .body("issuer", equalTo(PublishedJwks.ISSUER))
        .body("token_endpoint", equalTo(PublishedJwks.ENDPOINT_BASE + "/token"))
        .body("jwks_uri", equalTo(PublishedJwks.ENDPOINT_BASE + "/jwks"))
        .body(
            "grant_types_supported",
            contains("client_credentials", "authorization_code", "refresh_token"))
        .body(
            "token_endpoint_auth_methods_supported",
            containsInAnyOrder("client_secret_basic", "client_secret_post", "none"))
        .body("id_token_signing_alg_values_supported", contains("RS256"))
        .body(
            "claims_supported",
            hasItems(
                "iss",
                "sub",
                "aud",
                "groups",
                "project",
                "workspace",
                "branch",
                "credential_type",
                "git_ref_pattern"))
        .body("authorization_endpoint", equalTo(PublishedJwks.ENDPOINT_BASE + "/authorize"))
        .body("code_challenge_methods_supported", contains("S256"))
        .body("userinfo_endpoint", nullValue());
  }

  /**
   * A caller that used the public name is told the public endpoints: a browser page outside
   * qits-net cannot dial the in-network address. Under test no domain is stated, so the public
   * origin is {@code http://localhost:8080}. The issuer does not change.
   */
  @Test
  public void aCallerOnThePublicNameIsToldThePublicEndpoints() {
    for (String[] header :
        new String[][] {
          {"Host", "localhost:8080"},
          {"X-Forwarded-Host", "localhost:8080"},
          {"X-Forwarded-Host", "LOCALHOST:8080, inner-hop:8080"}
        }) {
      given()
          .header(header[0], header[1])
          .when()
          .get("/idp/.well-known/openid-configuration")
          .then()
          .statusCode(200)
          .body("issuer", equalTo(PublishedJwks.ISSUER))
          .body("authorization_endpoint", equalTo("http://localhost:8080/idp/authorize"))
          .body("token_endpoint", equalTo("http://localhost:8080/idp/token"))
          .body("jwks_uri", equalTo("http://localhost:8080/idp/jwks"))
          .body("code_challenge_methods_supported", contains("S256"));
    }
  }

  /** Any other name — the in-network alias, or a foreign host — gets the address, never itself. */
  @Test
  public void anyOtherNameIsToldTheAddress() {
    for (String host : List.of("dev-qits-platform-idp:8080", "evil.example", "localhost:9999")) {
      given()
          .header("X-Forwarded-Host", host)
          .when()
          .get("/idp/.well-known/openid-configuration")
          .then()
          .statusCode(200)
          .body("token_endpoint", equalTo(PublishedJwks.ENDPOINT_BASE + "/token"))
          .body("authorization_endpoint", equalTo(PublishedJwks.ENDPOINT_BASE + "/authorize"))
          .body("jwks_uri", equalTo(PublishedJwks.ENDPOINT_BASE + "/jwks"));
    }
  }

  @Test
  public void theJwksPublishesOnlyPublicKeyMaterial() {
    given()
        .when()
        .get("/idp/jwks")
        .then()
        .statusCode(200)
        .body("keys", hasSize(1))
        .body("keys[0].kty", equalTo("RSA"))
        .body("keys[0].use", equalTo("sig"))
        .body("keys[0].alg", equalTo("RS256"))
        .body("keys[0].kid", not(nullValue()))
        .body("keys[0].n", not(nullValue()))
        .body("keys[0].e", equalTo("AQAB"))
        // The private half has no JWK member here, and must never gain one.
        .body("keys[0].d", nullValue())
        .body("keys[0].p", nullValue())
        .body("keys[0].q", nullValue());
  }
}
