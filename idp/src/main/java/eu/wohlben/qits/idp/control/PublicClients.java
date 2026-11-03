package eu.wohlben.qits.idp.control;

import jakarta.enterprise.context.ApplicationScoped;
import java.time.Duration;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The public OAuth clients this idp knows: the Git workstation, the command-line tool, every
 * platform page that signs in with a bearer token, and the landing SPA under {@code ng serve} on a
 * developer's machine.
 *
 * <p>All are PKCE-only — no secret, no {@code Authorization} header, no way to become a machine
 * identity — and both spend an authorization code for a rotating refresh family. What separates
 * them is what the code is worth ({@link Kind}) and how long a person has to spend it: a loopback
 * listener catches a redirect in milliseconds, while a person reading a code off a page and
 * pasting it into a terminal is switching windows, so {@code qits-cli} gets its own, longer code
 * TTL rather than sharing the workstation's two minutes.
 *
 * <p>The third, {@code qits-landing-dev}, exists because a page served from {@code
 * http://localhost:4200} is a different site from the platform, so the platform's {@code
 * SameSite=Lax} session cookie never reaches its API calls. It signs in the way the CLI does and
 * gets the same token; only its redirect rule and its code TTL differ.
 *
 * <p>The fourth, {@code qits-spa}, is the same token for a page the platform itself serves: its
 * callback is {@code https://<host>/auth/callback} on the platform's apex or any name under it —
 * the anchor the login page checks {@code return_host} against, not a list of its own. It is what
 * a deployed page uses when it wants a bearer rather than the session cookie.
 *
 * <p><b>The ids are configuration and the lookup is exact.</b> A {@code client_id} that is none
 * of the configured values is unknown — there is no fall-through to "the public client",
 * because which one it is decides the roles and the redirect rule.
 *
 * <p>This is deliberately NOT {@link ClientRegistry}: that registry holds secret-bearing machine
 * identities, and nothing here has a secret to hold.
 */
@ApplicationScoped
public class PublicClients {

  /** What a code approved for this client is worth once it is spent. */
  public enum Kind {
    /** The constrained Git credential: one external-Git role and a ref pattern. */
    WORKSTATION,
    /** The person's own credential for the command line: their roles. */
    CLI,
    /**
     * The landing SPA under {@code ng serve}: the same token as {@link #CLI}, caught by the page at
     * {@code http://localhost:<port>/auth/callback}.
     */
    DEV_SPA,
    /**
     * A page the platform serves: the same token as {@link #CLI}, caught by the page at {@code
     * https://<platform host>/auth/callback}.
     */
    SPA
  }

  /**
   * One public client, resolved from configuration.
   *
   * @param id the {@code client_id} on the wire, and the value recorded on every code and refresh
   *     row so a credential of one client can never be spent as the other
   * @param kind which mint the exchanged code reaches
   * @param authorizationCodeTtl how long an approved code stays spendable
   */
  public record PublicClient(String id, Kind kind, Duration authorizationCodeTtl) {
    public boolean cli() {
      return kind == Kind.CLI;
    }

    public boolean devSpa() {
      return kind == Kind.DEV_SPA;
    }

    public boolean spa() {
      return kind == Kind.SPA;
    }

    /** Whether a spent grant mints the person's own token rather than the narrow Git one. */
    public boolean personToken() {
      return kind != Kind.WORKSTATION;
    }
  }

  @ConfigProperty(name = "qits.idp.workstation.client-id")
  String workstationClientId;

  @ConfigProperty(name = "qits.idp.workstation.authorization-code-ttl")
  Duration workstationAuthorizationCodeTtl;

  @ConfigProperty(name = "qits.idp.cli.client-id")
  String cliClientId;

  @ConfigProperty(name = "qits.idp.cli.authorization-code-ttl")
  Duration cliAuthorizationCodeTtl;

  @ConfigProperty(name = "qits.idp.dev-spa.client-id")
  String devSpaClientId;

  @ConfigProperty(name = "qits.idp.dev-spa.authorization-code-ttl")
  Duration devSpaAuthorizationCodeTtl;

  @ConfigProperty(name = "qits.idp.spa.client-id")
  String spaClientId;

  @ConfigProperty(name = "qits.idp.spa.authorization-code-ttl")
  Duration spaAuthorizationCodeTtl;

  public PublicClient workstation() {
    return new PublicClient(
        workstationClientId, Kind.WORKSTATION, workstationAuthorizationCodeTtl);
  }

  public PublicClient cli() {
    return new PublicClient(cliClientId, Kind.CLI, cliAuthorizationCodeTtl);
  }

  public PublicClient devSpa() {
    return new PublicClient(devSpaClientId, Kind.DEV_SPA, devSpaAuthorizationCodeTtl);
  }

  public PublicClient spa() {
    return new PublicClient(spaClientId, Kind.SPA, spaAuthorizationCodeTtl);
  }

  /** The client this {@code client_id} names, or empty when it names none. */
  public Optional<PublicClient> byId(String clientId) {
    if (clientId == null || clientId.isBlank()) {
      return Optional.empty();
    }
    if (workstationClientId.equals(clientId)) {
      return Optional.of(workstation());
    }
    if (cliClientId.equals(clientId)) {
      return Optional.of(cli());
    }
    if (devSpaClientId.equals(clientId)) {
      return Optional.of(devSpa());
    }
    if (spaClientId.equals(clientId)) {
      return Optional.of(spa());
    }
    return Optional.empty();
  }
}
