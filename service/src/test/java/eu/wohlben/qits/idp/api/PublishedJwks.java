package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;

import java.util.List;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;

/**
 * Verifies a token the way a consumer would: against whatever {@code GET /idp/jwks} publishes, over
 * HTTP, resolving the key by the token's own {@code kid}.
 *
 * <p>That indirection is the point. Verifying against the signing key the suite could reach
 * in-process would pass even if the JWKS were empty, wrong, or built from the private half — and
 * the JWKS is the only thing a real consumer ever sees.
 */
public final class PublishedJwks {

  /**
   * The issuer derived from the domain — {@code https://idp.qits.<domain>} — with no {@code
   * QITS_DOMAIN} stated, which is the suite's case. It is the {@code iss} claim and the discovery
   * document's {@code issuer} member, nothing dials it, and nothing configures it (qits-730).
   */
  public static final String ISSUER = "https://idp.qits.localhost";

  /**
   * The address the shipped {@code qits.idp.endpoint-base} default names — every advertised
   * endpoint hangs off this, not off {@link #ISSUER}. {@code QITS_ENVIRONMENT} is unset under the
   * suite, so the default resolves its own {@code dev} arm.
   */
  public static final String ENDPOINT_BASE = "http://dev-qits-platform-idp:8080/idp";

  private PublishedJwks() {}

  /** The raw document, for tests that assert its shape rather than use it. */
  public static String document() {
    return given().when().get("/idp/jwks").then().statusCode(200).extract().asString();
  }

  /**
   * The claims of {@code jwt}, or a failure. RS256 is the only permitted algorithm and the
   * expiration is required, so a token signed with {@code none} or without an {@code exp} fails
   * here rather than reading as valid.
   */
  public static JwtClaims verify(String jwt, String expectedAudience) throws InvalidJwtException {
    JsonWebKeySet jwks;
    try {
      jwks = new JsonWebKeySet(document());
    } catch (org.jose4j.lang.JoseException e) {
      throw new IllegalStateException("the published JWKS is not a key set", e);
    }
    return new JwtConsumerBuilder()
        .setVerificationKeyResolver(new JwksVerificationKeyResolver(jwks.getJsonWebKeys()))
        .setJwsAlgorithmConstraints(
            new AlgorithmConstraints(ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256))
        .setExpectedIssuer(ISSUER)
        .setExpectedAudience(expectedAudience)
        .setRequireExpirationTime()
        .setRequireSubject()
        .build()
        .processToClaims(jwt);
  }

  /** The {@code kid} header of a serialized JWS, read without verifying anything. */
  public static String kidOf(String jwt) {
    try {
      org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();
      jws.setCompactSerialization(jwt);
      return jws.getKeyIdHeaderValue();
    } catch (org.jose4j.lang.JoseException e) {
      throw new IllegalStateException("not a JWS", e);
    }
  }

  /** The {@code aud} of a token, whatever JSON shape it arrived in. */
  public static List<String> audienceOf(JwtClaims claims) {
    try {
      return claims.getAudience();
    } catch (org.jose4j.jwt.MalformedClaimException e) {
      throw new IllegalStateException("malformed aud", e);
    }
  }
}
