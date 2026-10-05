package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.control.CommissionedTokens.Commissioned;
import eu.wohlben.qits.idp.control.CommissionedTokens.StoredToken;
import eu.wohlben.qits.idp.entity.IdpToken;
import eu.wohlben.qits.idp.error.OAuthException;
import eu.wohlben.qits.idp.persistence.IdpTokenRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The commissioning control for opaque tokens (qits-448), against the real store: a value is minted
 * once and stored as a hash, introspection finds the row by that hash and nothing else, and a
 * deleted row is refused on the very next call.
 *
 * <p>A {@code @QuarkusTest} in {@code service/} rather than a test in the domain jar: {@code idp/}
 * has no test tree, and the property under test is the store round trip, which needs the embedded
 * postgres this module already starts. No {@code @TestProfile}: it shares the suite's application.
 *
 * <p>Every test names its own {@code contextKind}, because the suite shares one store.
 */
@QuarkusTest
public class CommissionedTokensTest {

  private static final String OWNER = "test-broad";

  @Inject CommissionedTokens tokens;

  @Inject IdpTokenRepository repository;

  @Test
  public void aTokenIsMintedOnceStoredAsAHashAndIntrospectedByItsValue() {
    Commissioned issued =
        tokens.commission(OWNER, "tok-roundtrip", "Run/4711", null, List.of("refs/heads/a"));

    assertTrue(issued.value().startsWith(TokenValue.PREFIX), issued.value());
    assertTrue(
        issued.token().subject().startsWith("tok-tok-roundtrip-run-4711-"),
        "the subject reads like a commissioned client's id: " + issued.token().subject());

    IdpToken row =
        QuarkusTransaction.requiringNew().call(() -> repository.findById(issued.token().id()));
    assertNotNull(row, "the commission is a row");
    assertNotEquals(issued.value(), row.tokenHash, "the value must not be stored");
    assertFalse(row.tokenHash.contains(issued.value()), "nor any part of it");
    assertEquals(TokenValue.hash(issued.value()), row.tokenHash);
    assertEquals("refs/heads/a", row.gitRefs);

    StoredToken found = tokens.introspect(issued.value()).orElseThrow();
    assertEquals(issued.token().id(), found.id());
    assertEquals(issued.token().subject(), found.subject());
    assertEquals(OWNER, found.owner());
    assertEquals("tok-roundtrip", found.contextKind());
    assertEquals("Run/4711", found.contextId(), "the context id is stored raw");
    assertEquals(List.of("refs/heads/a"), found.gitRefs());
  }

  @Test
  public void anUnknownValueIsNoToken() {
    assertTrue(tokens.introspect(TokenValue.PREFIX + RandomSecret.credential()).isEmpty());
  }

  @Test
  public void aStringThatIsNotShapedLikeATokenIsNeverLookedUp() {
    // A JWT header and payload; the prefix check refuses it before any hash or store read.
    assertTrue(
        tokens.introspect("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl").isEmpty());
    assertTrue(tokens.introspect("").isEmpty());
    assertTrue(tokens.introspect(null).isEmpty());
    assertFalse(TokenValue.isToken("qits_to"));
  }

  @Test
  public void aDeletedTokenIsRefusedOnTheVeryNextIntrospection() {
    Commissioned issued = tokens.commission(OWNER, "tok-delete", "ctx", null, null);
    assertTrue(tokens.introspect(issued.value()).isPresent());

    assertTrue(tokens.delete(issued.token().id(), OWNER));

    assertTrue(tokens.introspect(issued.value()).isEmpty(), "no cache to wait out");
    assertFalse(tokens.delete(issued.token().id(), OWNER), "gone is gone");
  }

  @Test
  public void onlyTheOwnerOrTheTokenItselfMayDelete() {
    Commissioned issued = tokens.commission(OWNER, "tok-owner", "ctx", null, null);

    assertFalse(tokens.delete(issued.token().id(), "test-narrow"), "another owner: one answer");
    assertFalse(tokens.delete(UUID.randomUUID(), OWNER), "an unknown id: the same answer");
    assertTrue(tokens.introspect(issued.value()).isPresent());

    assertTrue(tokens.delete(issued.token().id(), issued.token().subject()), "itself");
    assertTrue(tokens.introspect(issued.value()).isEmpty());
  }

  @Test
  public void claimsAreRefusedExactlyAsForAClientWithNothingWritten() {
    assertRefused(() -> tokens.commission(OWNER, "tok-wild", "ctx", Map.of("project", "*"), null));
    assertRefused(
        () -> tokens.commission(OWNER, "tok-invent", "ctx", Map.of("groups", "qits:admin"), null));

    assertEquals(List.of(), kindsListed("tok-wild"), "a refused claim leaves no row");
    assertEquals(List.of(), kindsListed("tok-invent"));
  }

  @Test
  public void gitRefsAreRefusedExactlyAsForAClientWithNothingWritten() {
    assertRefused(
        () -> tokens.commission(OWNER, "tok-refs", "ctx", null, List.of("refs/tags/v1")));

    assertEquals(List.of(), kindsListed("tok-refs"));
  }

  @Test
  public void theContextRuleIsTheClients() {
    assertRefused(() -> tokens.commission(OWNER, "CI Run", "ctx", null, null));
    assertRefused(() -> tokens.commission(OWNER, "tok-ctx", "  ", null, null));
  }

  @Test
  public void theListingIsTheOwnersOwnAndCarriesTheStatedScope() {
    Commissioned mine =
        tokens.commission(OWNER, "tok-listing", "ctx", Map.of("project", "qits"), null);
    Commissioned theirs = tokens.commission("test-narrow", "tok-listing", "ctx", null, null);

    List<StoredToken> listed = tokens.listOwned(OWNER);
    assertTrue(listed.stream().anyMatch(t -> t.id().equals(mine.token().id())));
    assertFalse(listed.stream().anyMatch(t -> t.id().equals(theirs.token().id())));
    StoredToken row =
        listed.stream().filter(t -> t.id().equals(mine.token().id())).findFirst().orElseThrow();
    assertEquals(Map.of("project", "qits"), row.claims());
    assertNull(row.gitRefs(), "no list stated");
  }

  @Test
  public void replaceGitRefsNarrowsAndEmptyMeansPushNothing() {
    Commissioned issued =
        tokens.commission(OWNER, "tok-replace", "ctx", null, List.of("refs/heads/a"));

    StoredToken replaced =
        tokens.replaceGitRefs(issued.token().id(), OWNER, List.of("refs/heads/b")).orElseThrow();
    assertEquals(List.of("refs/heads/b"), replaced.gitRefs());
    assertEquals(
        List.of("refs/heads/b"), tokens.introspect(issued.value()).orElseThrow().gitRefs());

    StoredToken emptied =
        tokens.replaceGitRefs(issued.token().id(), OWNER, List.of()).orElseThrow();
    assertEquals(List.of(), emptied.gitRefs(), "[] means push nothing");

    assertFalse(
        tokens.replaceGitRefs(UUID.randomUUID(), OWNER, List.of()).isPresent(),
        "an unknown id");
    assertFalse(
        tokens.replaceGitRefs(issued.token().id(), "test-narrow", List.of()).isPresent(),
        "another owner: the same answer");
  }

  @Test
  public void replaceGitRefsRefusesAMalformedRefAndWritesNothing() {
    Commissioned issued =
        tokens.commission(OWNER, "tok-replace-bad", "ctx", null, List.of("refs/heads/a"));

    assertRefused(
        () -> tokens.replaceGitRefs(issued.token().id(), OWNER, List.of("refs/tags/v1")));
    assertRefused(() -> tokens.replaceGitRefs(issued.token().id(), OWNER, null));

    assertEquals(
        List.of("refs/heads/a"),
        tokens.introspect(issued.value()).orElseThrow().gitRefs(),
        "a refused replace leaves the row unchanged");
  }

  @Test
  public void theCiRunnerKindsCarryTheirOwnRoles() {
    assertEquals(List.of("qits:ci-runner"), CommissionRoles.forKind("ci-runner"));
    assertEquals(
        List.of("qits:ci-runner-registration"), CommissionRoles.forKind("ci-runner-registration"));
    assertEquals(List.of("qits:ci-run"), CommissionRoles.forKind("ci-run"), "unchanged");
  }

  private List<String> kindsListed(String kind) {
    return tokens.listOwned(OWNER).stream()
        .map(StoredToken::contextKind)
        .filter(kind::equals)
        .toList();
  }

  private static void assertRefused(Runnable commission) {
    OAuthException refused = assertThrows(OAuthException.class, commission::run);
    assertEquals(400, refused.statusCode());
    assertEquals("invalid_request", refused.error());
  }
}
