package eu.wohlben.qits.idp.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import eu.wohlben.qits.idp.control.Issuer;
import eu.wohlben.qits.idp.control.SigningKeys;
import eu.wohlben.qits.idp.control.SigningKeys.SigningKey;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.error.OAuthException;
import io.quarkus.test.junit.QuarkusTest;
import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * The issuers a bearer may carry across the qits-730 cutover: the derived one, and the legacy
 * configured one while tokens minted before the cutover can still be alive. Anything else is a
 * token from somebody else's idp, even when it is signed with this one's key.
 */
@QuarkusTest
public class BearerCallerTest {

  private static final String ROLE = "qits:agent";

  @Inject BearerCaller bearers;

  @Inject SigningKeys signingKeys;

  private String signedWithIssuer(String iss) {
    SigningKey key = signingKeys.signing();
    Instant now = Instant.now();
    return Jwt.claims()
        .issuer(iss)
        .subject("bearer-caller-test")
        .audience(TokenService.PLATFORM_AUDIENCE)
        .groups(ROLE)
        .issuedAt(now)
        .expiresAt(now.plusSeconds(300))
        .jws()
        .keyId(key.kid())
        .sign(key.privateKey());
  }

  @Test
  public void aTokenCarryingTheDerivedIssuerIsAccepted() throws Exception {
    JwtClaims claims =
        bearers.requireAnyRole("Bearer " + signedWithIssuer(PublishedJwks.ISSUER), ROLE);
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer());
  }

  @Test
  public void aTokenMintedBeforeTheCutoverIsStillAccepted() throws Exception {
    JwtClaims claims =
        bearers.requireAnyRole(
            "Bearer " + signedWithIssuer("http://qits-platform-idp:8080/idp"), ROLE);
    assertEquals(Issuer.LEGACY, claims.getIssuer());
  }

  @Test
  public void aTokenNamingAnyOtherIssuerIsRefused() {
    for (String foreign :
        List.of(
            "https://idp.qits.example.test",
            "http://dev-qits-platform-idp:8080/idp",
            "https://idp.qits.localhost/")) {
      OAuthException refused =
          assertThrows(
              OAuthException.class,
              () -> bearers.requireAnyRole("Bearer " + signedWithIssuer(foreign), ROLE),
              foreign);
      assertEquals(401, refused.statusCode(), foreign);
    }
  }
}
