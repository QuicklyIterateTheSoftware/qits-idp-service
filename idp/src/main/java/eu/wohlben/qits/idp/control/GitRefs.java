package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.error.OAuthException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The Git refs a credential may push: the {@code git_refs} claim, and the rules a commission's list
 * must follow.
 *
 * <p>The contract is C1 and C2 of {@code principal-bound-git-refs-plan.md} in the qits superproject.
 * Each entry is an exact ref ({@code refs/heads/ticket/t-1}) or a prefix pattern that ends in {@code
 * *}: it covers every ref that starts with what precedes the {@code *}. So {@code
 * refs/heads/external/*} covers everything under {@code external/}, and {@code
 * refs/heads/ticket/t-1-*} covers {@code ticket/t-1-fix} but not {@code ticket/t-1}. An empty list means "may push nothing". No list (null) means
 * "no scope stated", and the token then carries no {@code git_refs} claim. The idp states the list;
 * the githost enforces it.
 *
 * <p><b>Any list narrows.</b> A credential without a list pushes what its roles allow; a list can
 * only take refs away from that. So every owner may state any valid list, and there is no "the owner
 * must hold it" check — the same argument as in {@link CommissionedClaims}.
 *
 * <p><b>The stored form</b> is one entry per line in {@code idp_client.git_refs}. Null is "not
 * stated" and the empty string is the empty list, so the column keeps the two apart. Control
 * characters are refused, so a line break can never be part of an entry. Git forbids them in a ref
 * name anyway.
 */
public final class GitRefs {

  /** Every entry starts with this. Tags and other ref spaces are never in a list. */
  public static final String PREFIX = "refs/heads/";

  public static final int MAX_ENTRIES = 500;

  public static final int MAX_LENGTH = 255;

  /** What a person may push — from the workstation and the CLI alike, whatever their roles. */
  public static final List<String> PERSON = List.of("refs/heads/external/*");

  private static final String SEPARATOR = "\n";

  private GitRefs() {}

  /**
   * A commission's list, checked. Null stays null: the commission states no scope.
   *
   * <p>The error names the index of the bad entry, never its value: the value is the caller's
   * string and may hold anything.
   *
   * @throws OAuthException {@code invalid_request} (400) when an entry breaks a rule, the list is
   *     too long, or an entry repeats
   */
  public static List<String> stated(List<String> requested) {
    if (requested == null) {
      return null;
    }
    if (requested.size() > MAX_ENTRIES) {
      throw OAuthException.invalidRequest("gitRefs may hold at most " + MAX_ENTRIES + " entries");
    }
    Set<String> seen = new LinkedHashSet<>();
    for (int i = 0; i < requested.size(); i++) {
      String entry = requested.get(i);
      String problem = problem(entry);
      if (problem != null) {
        throw OAuthException.invalidRequest("gitRefs[" + i + "] " + problem);
      }
      if (!seen.add(entry)) {
        throw OAuthException.invalidRequest("gitRefs[" + i + "] repeats an earlier entry");
      }
    }
    return List.copyOf(seen);
  }

  /** The stored form of a checked list. Null stays null; the empty list is the empty string. */
  public static String format(List<String> refs) {
    return refs == null ? null : String.join(SEPARATOR, refs);
  }

  /**
   * Read a stored column back.
   *
   * <p><b>This never throws.</b> It runs on the token path of every commissioned credential. A line
   * that breaks a rule (a hand-edited row) is dropped, which only narrows the list — the safe
   * direction. A column that holds nothing readable becomes the empty list: push nothing.
   */
  public static List<String> parse(String stored) {
    if (stored == null) {
      return null;
    }
    if (stored.isEmpty()) {
      return List.of();
    }
    Set<String> kept = new LinkedHashSet<>();
    for (String line : stored.split(SEPARATOR, -1)) {
      if (kept.size() == MAX_ENTRIES) {
        break;
      }
      if (problem(line) == null) {
        kept.add(line);
      }
    }
    return List.copyOf(kept);
  }

  /** What is wrong with one entry, or null when nothing is. */
  private static String problem(String entry) {
    if (entry == null) {
      return "may not be null";
    }
    if (entry.length() > MAX_LENGTH) {
      return "must be at most " + MAX_LENGTH + " characters";
    }
    for (int i = 0; i < entry.length(); i++) {
      char c = entry.charAt(i);
      if (c < 0x20 || c == 0x7f) {
        return "may not hold a control character";
      }
    }
    if (!entry.startsWith(PREFIX)) {
      return "must start with " + PREFIX;
    }
    int star = entry.indexOf('*');
    if (star >= 0 && star != entry.length() - 1) {
      return "may hold * only as its last character";
    }
    return null;
  }
}
