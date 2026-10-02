package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * The issuer is derived from the stated domain and configured nowhere (qits-730). A plain unit
 * test rather than a {@code @TestProfile} stating {@code QITS_DOMAIN}: a profile is a whole second
 * application, and the derivation is one line of string composition.
 */
class IssuerTest {

  private static Issuer issuer(String domain) {
    Issuer issuer = new Issuer();
    issuer.domain = Optional.ofNullable(domain);
    issuer.endpointBase = "http://dev-qits-platform-idp:8080/idp/";
    return issuer;
  }

  @Test
  void theIssuerIsTheIdpHostUnderThePlatformProjectUnderTheStatedDomain() {
    assertEquals("https://idp.qits.example.test", issuer("example.test").url());
    assertEquals("https://idp.qits.wohlben.eu", issuer(" Wohlben.EU ").url());
  }

  @Test
  void withNoDomainStatedTheIssuerIsTheLocalOne() {
    assertEquals("https://idp.qits.localhost", issuer(null).url());
    assertEquals("https://idp.qits.localhost", issuer("  ").url());
  }

  @Test
  void theAddressIsASeparateFactAndDoesNotFollowTheIssuer() {
    Issuer issuer = issuer("example.test");
    assertEquals("http://dev-qits-platform-idp:8080/idp", issuer.endpointBase());
    assertEquals("http://dev-qits-platform-idp:8080/idp/jwks", issuer.jwksUri());
    assertEquals("http://dev-qits-platform-idp:8080/idp/token", issuer.tokenEndpoint());
  }

  @Test
  void theLegacyIssuerIsStillAcceptedBesideTheDerivedOne() {
    assertArrayEquals(
        new String[] {"https://idp.qits.example.test", "http://qits-platform-idp:8080/idp"},
        issuer("example.test").accepted());
  }
}
