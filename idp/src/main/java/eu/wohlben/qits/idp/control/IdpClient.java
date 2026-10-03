package eu.wohlben.qits.idp.control;

import java.util.List;
import java.util.Map;

/**
 * One client the idp will issue for: its id, its shared secret, its roles, and the structured
 * claims its tokens carry.
 *
 * <p>Two kinds of client arrive here through this one record, and {@link ClientRegistry} is where
 * they meet: the <b>service clients</b> built from {@code idp_service_client} rows ({@link
 * ServiceClients}), and the <b>commissioned clients</b> built from {@code idp_client} rows ({@link
 * DynamicClients}). Nothing in the record tells them apart, which is the point: a commissioned
 * credential mints exactly like a service client, because {@link TokenService} cannot see which one
 * it has.
 *
 * <p>There is no audience here. Every token this idp mints has {@code aud = ["qits-platform"]}
 * ({@link TokenService#PLATFORM_AUDIENCE}), whoever the client is.
 *
 * @param secret how a presented secret is checked; never the raw string, only stored hashes
 * @param roles the roles copied into {@code groups}, before the client's own {@code clients/<id>}
 * @param claims granted claims, copied into the token verbatim
 * @param contextKind the commission's context kind, stamped as {@code context_kind}; null for a
 *     service client, which carries no such claim
 * @param gitRefs the Git refs this client may push, stamped as {@code git_refs}; null when no list
 *     was stated (every service client), which carries no such claim. Empty means "push nothing".
 */
public record IdpClient(
    String clientId,
    ClientSecret secret,
    List<String> roles,
    Map<String, String> claims,
    String contextKind,
    List<String> gitRefs) {

  /**
   * Whether this client can authenticate at all.
   *
   * <p><b>A client with no live secret is unusable, never open.</b> It is refused exactly like a
   * wrong secret, so a missing secret never turns into identity for whoever asks.
   */
  public boolean usable() {
    return secret != null && secret.usable();
  }

  /**
   * Whether {@code candidate} is this client's secret. False when the client is unusable, so this
   * is never on its own a reason to issue a token. Constant-time — see {@link ClientSecret}.
   */
  public boolean secretMatches(String candidate) {
    return secret != null && secret.matches(candidate);
  }
}
