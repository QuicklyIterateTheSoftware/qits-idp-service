package eu.wohlben.qits.idp.control;

import java.util.Locale;

/**
 * The hostname grammar as it applies to this service: {@code <host>.<project>.<domain>}, with the
 * domain the platform's one stated fact, {@code QITS_DOMAIN}.
 *
 * <p>Here rather than beside its browser-facing readers in {@code service} because the ISSUER is
 * composed from it too, and {@link Issuer} lives in this module. One spelling of the grammar for
 * both: {@code PlatformDomain} in {@code service} reuses these constants rather than repeating them.
 */
public final class PlatformHostname {

  /**
   * The platform-wide name for the stated domain. qits-deployments propagates it into every
   * container; the bootstrap CLI takes it as {@code --domain}.
   */
  public static final String QITS_DOMAIN = "QITS_DOMAIN";

  /**
   * The platform's own project slug. The platform is a project on itself, and its applications are
   * named {@code <app>.<project>.<domain>} by the same grammar as everybody else's.
   */
  public static final String PROJECT = "qits";

  /**
   * This service's host label — {@code host: idp} in {@code .config/qits/deployments.yml}, which is
   * what the edge routes {@code /idp/*} at. The two have to agree, and this is the side that can be
   * read from Java.
   */
  public static final String HOST = "idp";

  /** The developer's domain, and the default when nothing states one. */
  public static final String LOCAL = "localhost";

  private PlatformHostname() {}

  /** The stated domain, normalised. Empty when nothing was stated. */
  public static String stated(String raw) {
    return raw == null ? "" : raw.strip().toLowerCase(Locale.ROOT);
  }

  /** The stated domain, normalised, or {@link #LOCAL} when nothing was stated. */
  public static String domainOrLocal(String raw) {
    String domain = stated(raw);
    return domain.isEmpty() ? LOCAL : domain;
  }

  /**
   * The issuer: {@code https://idp.qits.<domain>} — no path, no trailing slash, and the same shape
   * locally ({@code https://idp.qits.localhost}). It is an identifier, compared and never dialled,
   * so unlike the browser origin it needs no local special case: nothing has to resolve it.
   */
  public static String issuer(String domain) {
    return "https://" + HOST + "." + PROJECT + "." + domain;
  }
}
