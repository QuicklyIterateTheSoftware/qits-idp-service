package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The token lifetime is a config key and is honoured, so the hour the platform ships can be taken
 * back without a code change.
 *
 * <p>Why that matters enough for its own application start: {@code qits.idp.token-ttl-seconds} went
 * from 300 to 3600 on 2026-08-14 with the commission model, and the number is a trade rather than a
 * setting — a token minted a second before a decommission keeps working for the rest of its
 * lifetime. Shrinking it again is the lever that closes that grace, and this pins that the lever is
 * connected to both places a caller reads a lifetime: {@code expires_in} in the response, and
 * {@code exp} in the token itself.
 */
@QuarkusTest
@TestProfile(TokenLifetimeTest.ShortLivedTokens.class)
public class TokenLifetimeTest {

  /** Nothing like the shipped value, so a hard-coded 3600 anywhere would fail here. */
  private static final int TTL_SECONDS = 47;

  public static class ShortLivedTokens implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of("qits.idp.token-ttl-seconds", String.valueOf(TTL_SECONDS));
    }
  }

  @Test
  public void theConfiguredLifetimeIsWhatTheResponseAndTheTokenBothSay() throws Exception {
    String token =
        given()
            .contentType(ContentType.URLENC)
            .body(
                "grant_type=client_credentials"
                    + "&client_id=test-broad"
                    + "&client_secret=test-broad-secret"
                    + "&audience=qits-deployments")
            .when()
            .post("/idp/token")
            .then()
            .statusCode(200)
            .body("expires_in", equalTo(TTL_SECONDS))
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(token, "qits-platform");
    assertEquals(
        TTL_SECONDS,
        claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue(),
        "exp is iat plus the configured lifetime");
  }
}
