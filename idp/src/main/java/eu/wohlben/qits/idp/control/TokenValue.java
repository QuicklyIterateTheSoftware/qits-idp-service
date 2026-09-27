package eu.wohlben.qits.idp.control;

/**
 * A commissioned token's value: how one is minted, how one is recognised, and what the store keeps
 * of it.
 *
 * <p><b>The prefix is a protocol constant, not decoration.</b> A bearer arriving at the edge is
 * either a JWT this service signed or one of these, and the edge decides which by this prefix alone
 * — so a JWT is never sent to introspection and a token is never handed to the JWKS check. A JWT
 * starts with the base64url of <code>{"</code>, which is {@code eyJ}, so the two can never be
 * confused. Changing the prefix is therefore a change at every hop that decides by it, not a
 * refactoring here.
 *
 * <p><b>Everything after the prefix is 32 random bytes and nothing else</b> — {@link RandomSecret},
 * base64url, 43 characters. No id, no claim and no expiry is encoded in it: the value means
 * something only because a row holds its hash, which is what makes deleting that row the whole of
 * revocation.
 */
public final class TokenValue {

  /** What every commissioned token value begins with, and what a hop recognises one by. */
  public static final String PREFIX = "qits_tok_";

  private TokenValue() {}

  /** A fresh value: {@link #PREFIX} plus 256 bits from {@link RandomSecret}. */
  static String mint() {
    return PREFIX + RandomSecret.bytes(RandomSecret.CREDENTIAL_BYTES);
  }

  /**
   * Whether this string is shaped like a token at all. The cheap test that runs before a hash and
   * before any store read, so a JWT, a session cookie or a stray header costs nothing.
   */
  public static boolean isToken(String value) {
    return value != null && value.startsWith(PREFIX);
  }

  /**
   * What the {@code token_hash} column holds for this value: {@link ClientSecret#hash}, the same
   * {@code sha-256:} base64url fingerprint a commissioned secret and a register token are stored
   * under. The same argument applies — 256 bits nobody chose leave nothing for a password hash to
   * slow down, and this runs on the edge's introspection path — so one scheme, one helper.
   */
  static String hash(String value) {
    return ClientSecret.hash(value);
  }
}
