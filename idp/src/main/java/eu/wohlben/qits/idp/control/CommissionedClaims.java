package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.error.OAuthException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The structured claims a <b>commission</b> states, and the one rule that bounds them: a commission
 * narrows, never widens.
 *
 * <p>This is the per-context scoping {@code V2__commissioned_clients.sql} declared as the follow-up
 * when it dropped the {@code claims} column: "a column no reader has is not forward compatibility;
 * it is a trap for whoever writes it first and sees nothing happen". The column is back here, with
 * the reader — {@link ClientRegistry} — in the same change.
 *
 * <h2>The narrowing rule, which is the whole security argument</h2>
 *
 * <p><b>A commission may state a concrete value, and may never state {@link #WILDCARD}.</b> That
 * asymmetry is not a style choice. A resource service reads an absent claim as "this token is not
 * scoped" and answers it from the caller's roles; it reads a concrete value as "this token is about
 * exactly that one thing". So a concrete value is <em>strictly less</em> than saying nothing,
 * whatever the owner itself holds, and stating one can only ever cost a commissioned credential
 * access. {@code *} is the one value that is never a narrowing — it is what a token says when it
 * covers everything — so it stays a service client's alone: the fixed {@code project=*} every
 * service client carries in code ({@link ClientRegistry}), which no request can state.
 *
 * <p>That is why there is no "the owner must already hold it" check here, and why adding one would
 * be the wrong shape. The owners are the platform's own service clients — the only callers the
 * commission API admits at all ({@code BasicCaller.staticOnly}) — and each of them holds {@code
 * project=*}, because each serves every project. A check against that would admit every value and
 * prove nothing. What keeps a commission narrow is that it inherits nothing from its owner (D3):
 * each commission says what its context is about, and nothing else.
 *
 * <h2>The stored form</h2>
 *
 * <p>{@code name=value} lines in one column, and no JSON. The vocabulary is closed ({@link
 * ClaimNames#GRANTABLE}) and {@link #VALUE} excludes both delimiters, so there is nothing to escape
 * and nothing to parse defensively — and the {@code idp} module carries no Jackson, which a JSON
 * column would have to add for three names. It also stays readable in a {@code psql} row, which is
 * where an operator asks why a credential is scoped the way it is.
 */
public final class CommissionedClaims {

  /** As long as a context id: a claim value names the same kind of thing one does. */
  public static final int MAX_VALUE_LENGTH = 256;

  /**
   * What a stated value may be. Wide enough for every identifier this platform mints — UUIDs, slugs,
   * branch names, {@code <env>-qits-<app>} ids — and narrow enough that the stored form needs no
   * escaping: neither {@code =} nor a newline is in it.
   *
   * <p>{@code *} is not in it either, which is where the narrowing rule is actually enforced. The
   * refusal below names it explicitly all the same, because "the wildcard is refused" and "that
   * character is not allowed" are different things to be told.
   */
  private static final Pattern VALUE = Pattern.compile("[A-Za-z0-9._:@/+-]{1," + MAX_VALUE_LENGTH + "}");

  /** The stored form's separators. Excluded from {@link #VALUE}, so neither can appear in a value. */
  private static final String PAIR_SEPARATOR = "\n";

  private static final char NAME_SEPARATOR = '=';

  /**
   * The value a commission may not state. The idp does not interpret claim values — that is the
   * resource service's job, and {@code qits-auth-core} is where {@code *} is read as "every value" —
   * so this is spelled here as the one string the narrowing rule refuses, not as a meaning.
   */
  public static final String WILDCARD = "*";

  /**
   * The claims a commission may keep, or a refusal.
   *
   * <p>Null and empty are the ordinary case — most commissions state nothing — and both answer an
   * empty map rather than a failure.
   *
   * @throws OAuthException {@code invalid_request} (400) on an unknown claim name, a blank or
   *     over-long value, a value outside {@link #VALUE}, or the wildcard
   */
  public static Map<String, String> stated(Map<String, String> requested) {
    if (requested == null || requested.isEmpty()) {
      return Map.of();
    }
    // LinkedHashMap in GRANTABLE order, so the stored line order and the token's claim order are
    // the same one every other reader here already follows.
    Map<String, String> stated = new LinkedHashMap<>();
    for (String name : requested.keySet()) {
      if (name == null || !ClaimNames.GRANTABLE.contains(name)) {
        throw OAuthException.invalidRequest(
            "claims may name only " + ClaimNames.GRANTABLE + ", not " + name);
      }
    }
    for (String name : ClaimNames.GRANTABLE) {
      String value = requested.get(name);
      if (value == null) {
        continue;
      }
      String trimmed = value.trim();
      if (trimmed.isEmpty()) {
        throw OAuthException.invalidRequest("claim " + name + " was stated with no value");
      }
      if (WILDCARD.equals(trimmed)) {
        throw OAuthException.invalidRequest(
            "a commission may narrow a credential, never widen it: claim "
                + name
                + " may not be "
                + WILDCARD
                + ", which is granted to a service client in configuration");
      }
      if (!VALUE.matcher(trimmed).matches()) {
        throw OAuthException.invalidRequest(
            "claim "
                + name
                + " must be at most "
                + MAX_VALUE_LENGTH
                + " characters of [A-Za-z0-9._:@/+-]");
      }
      stated.put(name, trimmed);
    }
    return Collections.unmodifiableMap(stated);
  }

  /** The stored form of already-{@link #stated} claims. Empty answers null, so the column stays null. */
  public static String format(Map<String, String> claims) {
    if (claims == null || claims.isEmpty()) {
      return null;
    }
    StringBuilder stored = new StringBuilder();
    claims.forEach(
        (name, value) -> {
          if (stored.length() > 0) {
            stored.append(PAIR_SEPARATOR);
          }
          stored.append(name).append(NAME_SEPARATOR).append(value);
        });
    return stored.toString();
  }

  /**
   * Read a stored column back.
   *
   * <p><b>Anything unreadable is dropped, never thrown.</b> This runs on the token path for every
   * commissioned credential, and a row it cannot parse must cost that credential a claim — the
   * fail-closed direction — rather than cost the platform its issuer.
   */
  public static Map<String, String> parse(String stored) {
    if (stored == null || stored.isBlank()) {
      return Map.of();
    }
    Map<String, String> byName = new LinkedHashMap<>();
    for (String line : stored.split(PAIR_SEPARATOR)) {
      int at = line.indexOf(NAME_SEPARATOR);
      if (at <= 0) {
        continue;
      }
      String name = line.substring(0, at);
      String value = line.substring(at + 1);
      if (ClaimNames.GRANTABLE.contains(name) && VALUE.matcher(value).matches()) {
        byName.put(name, value);
      }
    }
    // Re-ordered into GRANTABLE order, so a hand-edited column cannot change a token's claim order.
    Map<String, String> ordered = new LinkedHashMap<>();
    for (String name : ClaimNames.GRANTABLE) {
      if (byName.containsKey(name)) {
        ordered.put(name, byName.get(name));
      }
    }
    return Collections.unmodifiableMap(ordered);
  }

  private CommissionedClaims() {}
}
