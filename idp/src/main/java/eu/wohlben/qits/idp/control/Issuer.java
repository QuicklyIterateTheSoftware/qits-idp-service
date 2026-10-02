package eu.wohlben.qits.idp.control;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The issuer string and the advertised endpoint base, in one place — and they are TWO values, not
 * one.
 *
 * <p>They were one string for as long as the idp answered on one name. The {@code iss} of every
 * token was also the address a consumer dialled, so deriving {@code <issuer>/jwks} from it could
 * not be wrong. Deleting the platform plane ended that: the idp's bare alias {@code
 * qits-platform-idp} stopped resolving and its address became {@code <env>-qits-platform-idp}.
 * The discovery document kept deriving its endpoints from the issuer through that change, so a
 * consumer that had cached nothing followed it to an {@code UnknownHostException} and rolled back.
 *
 * <p>So: {@link #url()} is an IDENTIFIER and is compared, {@link #endpointBase()} is an ADDRESS and
 * is dialled. They are allowed to differ and on this platform they do. The one thing that must
 * still hold is that the {@code issuer} member of the discovery document and the {@code iss} of a
 * token are the same string, and both come from {@link #url()}.
 *
 * <p><b>The issuer is derived from the domain, never configured</b> (owner rule, qits-730): {@code
 * https://idp.qits.<QITS_DOMAIN>}, see {@link PlatformHostname#issuer(String)}. A configurable
 * issuer is a string some other service can be handed the wrong half of — an address read as an
 * identifier refuses every machine token — and a derived one has exactly one value per domain.
 */
@ApplicationScoped
public class Issuer {

  /** The platform's domain, as qits-deployments states it. Nothing stated means a local build. */
  @ConfigProperty(name = PlatformHostname.QITS_DOMAIN)
  Optional<String> domain;

  /**
   * Where a consumer reaches this service, which is not necessarily what it is called.
   *
   * <p>Derived from the environment rather than stored as deployment configuration: an address that
   * follows one rule is code, and a config entry holding it is a second copy that goes stale
   * silently — as the issuer's did.
   */
  @ConfigProperty(name = "qits.idp.endpoint-base")
  String endpointBase;

  /** The issuer string: {@code https://idp.qits.<domain>}, derived from {@code QITS_DOMAIN}. */
  public String url() {
    return PlatformHostname.issuer(PlatformHostname.domainOrLocal(domain.orElse(null)));
  }

  /** Every {@code iss} a token this idp minted may carry: the one derived issuer. */
  public String[] accepted() {
    return new String[] {url()};
  }

  /**
   * The base every advertised endpoint hangs off: {@code qits.idp.endpoint-base}, normalised the
   * same way. Normalising once — here — is what keeps a configured trailing slash from becoming the
   * one character that breaks a URL.
   */
  public String endpointBase() {
    return trimmed(endpointBase);
  }

  /** {@code <endpointBase>/token} — derived, never separately configured. */
  public String tokenEndpoint() {
    return endpointBase() + "/token";
  }

  /** {@code <endpointBase>/authorize} — the Git workstation's Authorization Code + PKCE leg. */
  public String authorizationEndpoint() {
    return endpointBase() + "/authorize";
  }

  /** {@code <endpointBase>/jwks} — derived, never separately configured. */
  public String jwksUri() {
    return endpointBase() + "/jwks";
  }

  private static String trimmed(String value) {
    String url = value.trim();
    while (url.endsWith("/")) {
      url = url.substring(0, url.length() - 1);
    }
    return url;
  }
}
