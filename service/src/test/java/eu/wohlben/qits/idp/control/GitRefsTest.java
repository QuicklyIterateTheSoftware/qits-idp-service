package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.error.OAuthException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The rules a commission's Git refs are held to (principal-bound-git-refs-plan.md, C2), one per
 * test, and the column they are stored in. {@code CommissionedGitRefsTest} checks the same rules as
 * status codes and minted tokens.
 */
public class GitRefsTest {

  @Test
  public void aValidListIsKeptInTheCallersOrder() {
    List<String> refs =
        List.of("refs/heads/ticket/t-1", "refs/heads/external/*", "refs/heads/epic/e-1");

    assertEquals(refs, GitRefs.stated(refs));
  }

  @Test
  public void noListStaysNoList() {
    assertNull(GitRefs.stated(null), "not stated is not the empty list");
    assertNull(GitRefs.format(null), "and the column stays null");
    assertNull(GitRefs.parse(null));
  }

  @Test
  public void theEmptyListIsPushNothingAndSurvivesTheColumn() {
    assertEquals(List.of(), GitRefs.stated(List.of()));
    assertEquals("", GitRefs.format(List.of()), "the empty string, not null");
    assertEquals(List.of(), GitRefs.parse(""));
  }

  @Test
  public void everyEntryStartsWithRefsHeads() {
    refused("refs/tags/v1");
    refused("refs/heads");
    refused("main");
    refused("");
    refused(" refs/heads/main");
  }

  @Test
  public void aStarMayStandOnlyAsTheLastCharacter() {
    assertEquals(List.of("refs/heads/feature/*"), GitRefs.stated(List.of("refs/heads/feature/*")));
    // Every branch, but still no tags: narrower than no list, so the contract's rules allow it.
    assertEquals(List.of("refs/heads/*"), GitRefs.stated(List.of("refs/heads/*")));
    // A trailing * after any character: every ref that starts with what precedes it.
    assertEquals(List.of("refs/heads/a-*"), GitRefs.stated(List.of("refs/heads/a-*")));
    assertEquals(
        List.of("refs/heads/ticket/qits-1-*"),
        GitRefs.stated(List.of("refs/heads/ticket/qits-1-*")));
    assertEquals(List.of("refs/heads/feature*"), GitRefs.stated(List.of("refs/heads/feature*")));

    refused("refs/heads/*/x");
    refused("refs/heads/a*b");
    refused("refs/heads/a/**");
    refused("refs/heads/a**");
    refused("refs/heads/*-x");
  }

  @Test
  public void aListHoldsAtMost500Entries() {
    List<String> full = new ArrayList<>();
    for (int i = 0; i < GitRefs.MAX_ENTRIES; i++) {
      full.add("refs/heads/task/t-" + i);
    }
    assertEquals(GitRefs.MAX_ENTRIES, GitRefs.stated(full).size());

    full.add("refs/heads/task/one-too-many");
    assertThrows(OAuthException.class, () -> GitRefs.stated(full));
  }

  @Test
  public void anEntryIsAtMost255Characters() {
    String longest = GitRefs.PREFIX + "x".repeat(GitRefs.MAX_LENGTH - GitRefs.PREFIX.length());
    assertEquals(List.of(longest), GitRefs.stated(List.of(longest)));

    refused(longest + "x");
  }

  @Test
  public void anEntryMayNotRepeat() {
    assertThrows(
        OAuthException.class,
        () -> GitRefs.stated(List.of("refs/heads/a", "refs/heads/b", "refs/heads/a")));
  }

  @Test
  public void anEntryIsNeitherNullNorAControlCharacter() {
    assertThrows(OAuthException.class, () -> GitRefs.stated(Arrays.asList("refs/heads/a", null)));
    // The line break is the stored form's separator. Git refuses control characters in a ref too.
    refused("refs/heads/a\nrefs/heads/b");
    refused("refs/heads/a\tb");
    refused("refs/heads/ab");
  }

  @Test
  public void theRefusalNamesTheIndexAndNotTheValue() {
    OAuthException refused =
        assertThrows(
            OAuthException.class,
            () -> GitRefs.stated(List.of("refs/heads/ok", "refs/tags/secret-looking-value")));

    assertEquals("invalid_request", refused.error());
    assertEquals(400, refused.statusCode());
    assertTrue(refused.getMessage().contains("gitRefs[1]"), refused.getMessage());
    assertFalse(refused.getMessage().contains("secret-looking-value"), refused.getMessage());
  }

  @Test
  public void theStoredFormRoundTrips() {
    List<String> refs = List.of("refs/heads/epic/e-1", "refs/heads/feature/f-1/*");

    assertEquals("refs/heads/epic/e-1\nrefs/heads/feature/f-1/*", GitRefs.format(refs));
    assertEquals(refs, GitRefs.parse(GitRefs.format(refs)));
  }

  @Test
  public void anUnreadableColumnNarrowsAndNeverThrows() {
    // This runs on the token path of every commissioned credential. A hand-edited row drops what
    // breaks a rule — which only takes refs away — and never takes the issuer down.
    assertEquals(
        List.of("refs/heads/ok"),
        GitRefs.parse("refs/tags/v1\nrefs/heads/ok\n\nrefs/heads/a*b\nrefs/heads/ok"));
    assertEquals(List.of(), GitRefs.parse("nonsense"), "nothing readable is push nothing");
    assertEquals(List.of(), GitRefs.parse("   "));
  }

  private static void refused(String entry) {
    assertThrows(OAuthException.class, () -> GitRefs.stated(List.of(entry)), entry);
  }
}
