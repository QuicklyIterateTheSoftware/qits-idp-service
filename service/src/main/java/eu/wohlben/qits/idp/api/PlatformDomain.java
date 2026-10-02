package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.PlatformHostname;

/**
 * The platform's domain, and every browser-facing name this service composes from it.
 *
 * <p><b>One fact, stated once.</b> The domain is the bootstrap's own {@code --domain} input, which
 * qits-deployments propagates into every container as {@code QITS_DOMAIN}. Everything this service
 * shows a browser — the origin it serves login on, the WebAuthn relying party, the origin list the
 * ceremony accepts, the session cookie's parent, and the return-host allow-list next door in
 * {@link BrowserSso} — is DERIVED from that one value here, and none of it is separately
 * configurable. The four keys that used to carry them were injected from outside this repository
 * and went stale the moment the estate's hostname grammar moved: they all still named
 * {@code idp.dev.qits.wohlben.eu} after the {@code qits} project became env-less, an address that
 * had stopped existing. A value nobody can set is a value nobody can leave behind.
 *
 * <p>The derivations live in one class, rather than beside their readers, because two of them are
 * read by the WebAuthn extension rather than by this repository's Java —
 * {@link #WEBAUTHN_ORIGINS} and {@link #WEBAUTHN_RP_ID} are config keys the extension resolves on
 * its own — so {@link DerivedBrowserHosts} has to compose them as configuration while
 * {@link BrowserSso} composes the rest as objects. Same source, two consumers, one file.
 *
 * <p>The grammar's constants themselves — project slug, host label, the local default — live in
 * {@link PlatformHostname} in the domain module, because the token issuer ({@code
 * https://idp.qits.<domain>}) is composed from them there too. They are aliased here, not repeated.
 */
final class PlatformDomain {

  /** The key the stated domain arrives on. {@link DerivedBrowserHosts} is what writes it. */
  static final String DOMAIN = "qits.idp.browser-sso.domain";

  /**
   * The platform's own project slug.
   *
   * <p>A constant rather than a literal spelled into each derivation: the platform is a project on
   * itself, like any other, and its applications are named {@code <app>.<project>.<domain>} by the
   * same grammar as everybody else's. This service is one of those applications, so its own host
   * carries the slug too. It is env-less — there is no {@code <env>} label in front of it any more
   * — which is exactly the move that invalidated the three addresses this class replaced.
   */
  static final String PROJECT = PlatformHostname.PROJECT;

  /**
   * The developer's domain, and the default when nothing states one.
   *
   * <p>A single label, which is what tells the two installations apart below: a public domain has a
   * dot in it and {@code localhost} does not.
   */
  static final String LOCAL = PlatformHostname.LOCAL;

  /**
   * This service's host label — {@code host: idp} in {@code .config/qits/deployments.yml}, which is
   * what the edge routes {@code /idp/login} at. The two have to agree, and this is the side that
   * can be read from Java.
   */
  private static final String HOST = PlatformHostname.HOST;

  /** Where a local build listens. {@code quarkus.http.port}'s own default. */
  private static final int LOCAL_PORT = 8080;

  /** The origin list webauthn4j checks the browser's {@code clientDataJSON} against. */
  static final String WEBAUTHN_ORIGINS = "quarkus.webauthn.origins";

  /** The relying party a passkey is bound to. See {@link #relyingPartyId(String)}. */
  static final String WEBAUTHN_RP_ID = "quarkus.webauthn.relying-party.id";

  private PlatformDomain() {}

  /** The stated domain, normalised. Empty when nothing was stated, which is a refusal upstream. */
  static String stated(String raw) {
    return PlatformHostname.stated(raw);
  }

  /**
   * Whether this is the developer's installation rather than a public one.
   *
   * <p>The test is the dot, not the string {@code localhost}: a public DNS domain has at least one
   * label boundary in it and a single-label name cannot be one. The same rule already governs the
   * cookie parent, which {@link BrowserSso} refuses unless it is dotted.
   */
  private static boolean local(String domain) {
    return domain.indexOf('.') < 0;
  }

  /**
   * The one origin this idp serves login, registration and WebAuthn on.
   *
   * <p>Public: {@code https://idp.qits.<domain>} — this service's host label, under the platform's
   * own project, under the stated domain, which is the hostname grammar applied to this service
   * like to any other application. Local: {@code http://localhost:8080}, unchanged, and
   * deliberately NOT {@code idp.qits.localhost:8080} — {@code localhost} is a secure context over
   * plain http by browser rule, nothing resolves the longer name on a developer's machine, and the
   * emulated authenticator the suite runs the real ceremony against hard-hashes {@code localhost}
   * as its relying party with no way to change it.
   */
  static String canonicalOrigin(String domain) {
    return local(domain)
        ? "http://" + domain + ":" + LOCAL_PORT
        : "https://" + HOST + "." + PROJECT + "." + domain;
  }

  /**
   * The session cookie's parent domain, or {@code null} for a host-only cookie.
   *
   * <p>The stated domain itself, so the apex and every browser host under it share one login. There
   * is no parent to name locally: a single-label host has none, and a browser refuses
   * {@code Domain=localhost} on a cookie anyway.
   */
  static String cookieDomain(String domain) {
    return local(domain) ? null : domain;
  }

  /**
   * The WebAuthn relying party: the stated domain, FLAT, with no override and no deeper name.
   *
   * <p>Flat so that one passkey asserts on every host of the installation — a ceremony's rp id must
   * be the page's origin or a parent of it, and the apex is the only parent every application
   * shares.
   *
   * <p><b>And with no override, which is a decision and not an omission.</b> A passkey is bound to
   * the rp id it was registered under and will not assert under another, so changing the stated
   * domain invalidates every credential on the estate — every passkey, for every account. The
   * obvious guard is a separate key that can be pinned to the old value across such a move, and it
   * was proposed and DECLINED: "if a domain change means breaking them, then that means breaking
   * them. thats not an issue." Accounts here are per-installation by decision, a new domain is a
   * new installation in every way that matters, and a key that exists only to survive one event
   * would be set wrong on every deployment in between. Do not add the override back without
   * reopening that decision — the derivation being flat IS the answer, not a gap in it.
   */
  static String relyingPartyId(String domain) {
    return domain;
  }
}
