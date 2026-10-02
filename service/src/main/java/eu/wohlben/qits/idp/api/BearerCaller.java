package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Issuer;
import eu.wohlben.qits.idp.control.SigningKeys;
import eu.wohlben.qits.idp.control.SigningKeys.SigningKey;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.Key;
import java.util.List;
import java.util.Optional;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;

/**
 * "Who is calling", for a <b>read</b> route that accepts a bearer beside {@link BasicCaller}'s pair:
 * a JWT this idp itself issued, verified in-process.
 *
 * <p><b>In-process, against {@link SigningKeys#published()}</b> — the exact key list {@code GET
 * /idp/jwks} serves, resolved by the token's {@code kid} — with no OIDC stack and no HTTP call to
 * itself. That is what keeps clear of the circular boot dependency {@code IdpClientsController}
 * warns about: the keys are already loaded at boot, and verifying against them is a lookup.
 *
 * <p>The checks are the ones every consumer makes ({@code PublishedJwks} in the suite is the same
 * shape over HTTP): RS256 only, {@code iss} is {@link Issuer#url()}, {@code aud} includes {@link
 * TokenService#PLATFORM_AUDIENCE} — which every token minted here carries — and {@code exp} and
 * {@code sub} are required.
 *
 * <p><b>Reads only.</b> No write route accepts a bearer: an agent keeps every read and gains no
 * write (user ruling 2026-09-12), and a write here moves a credential.
 */
@ApplicationScoped
public class BearerCaller {

  private static final String SCHEME = "bearer";

  @Inject SigningKeys signingKeys;

  @Inject Issuer issuer;

  /** True when the header is a {@code Bearer} one — the caller routes on this, before verifying. */
  public static boolean isBearer(String authorization) {
    if (authorization == null) {
      return false;
    }
    // The scheme alone counts, token or not: an empty "Bearer " arrives trimmed to "Bearer", and
    // it is still a bearer that failed, not a Basic pair that is missing.
    String value = authorization.trim();
    return value.regionMatches(true, 0, SCHEME, 0, SCHEME.length())
        && (value.length() == SCHEME.length()
            || Character.isWhitespace(value.charAt(SCHEME.length())));
  }

  /**
   * Verify the bearer and require at least one of {@code roles} in its {@code groups}.
   *
   * @return the verified claims
   * @throws OAuthException {@code invalid_token} (401) when the token does not verify, {@code
   *     access_denied} (403) when it does and holds none of the roles
   */
  public JwtClaims requireAnyRole(String authorization, String... roles) {
    JwtClaims claims = verified(authorization);
    List<String> groups;
    try {
      groups = Optional.ofNullable(claims.getStringListClaimValue("groups")).orElse(List.of());
    } catch (MalformedClaimException e) {
      throw OAuthException.invalidToken("the bearer's groups claim is not a list of strings");
    }
    for (String role : roles) {
      if (groups.contains(role)) {
        return claims;
      }
    }
    throw OAuthException.accessDenied("the bearer lacks every role of " + List.of(roles));
  }

  private JwtClaims verified(String authorization) {
    if (!isBearer(authorization)) {
      throw OAuthException.invalidToken("a bearer token is required");
    }
    String jwt = authorization.trim().substring(SCHEME.length()).trim();
    try {
      return new JwtConsumerBuilder()
          .setVerificationKeyResolver(new PublishedKeys(signingKeys.published()))
          .setJwsAlgorithmConstraints(
              new AlgorithmConstraints(
                  ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256))
          .setExpectedIssuer(issuer.url())
          .setExpectedAudience(TokenService.PLATFORM_AUDIENCE)
          .setRequireExpirationTime()
          .setRequireSubject()
          .build()
          .processToClaims(jwt);
    } catch (InvalidJwtException e) {
      throw OAuthException.invalidToken("the bearer is not a valid token from this idp");
    }
  }

  /** The published key whose {@code kid} the token names; no kid, or an unknown one, verifies nothing. */
  private record PublishedKeys(List<SigningKey> keys) implements VerificationKeyResolver {
    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
        throws org.jose4j.lang.UnresolvableKeyException {
      String kid = jws.getKeyIdHeaderValue();
      return keys.stream()
          .filter(key -> key.kid().equals(kid))
          .map(SigningKey::publicKey)
          .findFirst()
          .orElseThrow(
              () -> new org.jose4j.lang.UnresolvableKeyException("no published key " + kid));
    }
  }
}
