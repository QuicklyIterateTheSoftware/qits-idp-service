package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.PlatformHostname;
import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigSourceFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.PropertiesConfigSource;
import java.util.List;
import java.util.Map;
import org.eclipse.microprofile.config.spi.ConfigSource;

/**
 * Reads the platform's domain, once, and publishes what {@link PlatformDomain} derives from it as
 * configuration.
 *
 * <p>A config source rather than three lines in {@code application.properties} because the
 * derivation is a CONDITIONAL — a public installation's origin is
 * {@code https://idp.qits.<domain>} and a developer's is {@code http://localhost:8080} — and a
 * property expression cannot branch. Writing it as config at all, rather than deriving it in Java
 * next to its reader, is forced by the consumer: {@link PlatformDomain#WEBAUTHN_ORIGINS} and
 * {@link PlatformDomain#WEBAUTHN_RP_ID} are resolved by quarkus-security-webauthn itself, which
 * this repository's code never calls with a value of its own.
 *
 * <p>A {@link ConfigSourceFactory} rather than a plain {@link ConfigSource} because a factory is
 * handed a {@link ConfigSourceContext} and can therefore READ config — the sources registered
 * ahead of it, environment among them — where a plain source would have to reach for
 * {@code System.getenv} behind Quarkus' back and miss every other way a value can arrive. It is
 * registered the same way, through {@code META-INF/services}.
 *
 * <p>The ordinal sits above {@code application.properties} (250) and below environment (300). Above
 * the file because these keys are not the file's to state any more. Below environment on purpose:
 * {@code QITS_DOMAIN} is read HERE rather than competing with this source, so nothing legitimate
 * needs to outrank it, and a deployment that sets {@code QUARKUS_WEBAUTHN_ORIGINS} by hand anyway
 * gets the startup refusal in {@link BrowserSso} rather than a passkey ceremony that fails closed
 * with no configuration error anywhere.
 */
public class DerivedBrowserHosts implements ConfigSourceFactory {

  /**
   * The platform-wide name for the one stated fact. qits-deployments propagates it into every
   * container; the bootstrap CLI takes it as {@code --domain}. The browser boundary reads it only
   * here; the one other reader is {@code Issuer}, which derives the token issuer from the same value
   * through the same {@code PlatformHostname} normalisation.
   */
  static final String QITS_DOMAIN = PlatformHostname.QITS_DOMAIN;

  private static final int ORDINAL = 275;

  private static final String NAME = "derived-browser-hosts";

  @Override
  public Iterable<ConfigSource> getConfigSources(ConfigSourceContext context) {
    ConfigValue value = context.getValue(QITS_DOMAIN);
    String domain = PlatformDomain.stated(value == null ? null : value.getValue());
    if (domain.isEmpty()) {
      domain = PlatformDomain.LOCAL;
    }
    return List.of(
        new PropertiesConfigSource(
            Map.of(
                PlatformDomain.DOMAIN, domain,
                PlatformDomain.WEBAUTHN_ORIGINS, PlatformDomain.canonicalOrigin(domain),
                PlatformDomain.WEBAUTHN_RP_ID, PlatformDomain.relyingPartyId(domain)),
            NAME,
            ORDINAL));
  }
}
