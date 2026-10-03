package eu.wohlben.qits.idp.stories.refusals;

import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import eu.wohlben.qits.idp.api.PublishedJwks;
import eu.wohlben.qits.idp.stories.support.StoryNetwork;
import eu.wohlben.qits.idp.stories.support.StoryProfile;
import eu.wohlben.qits.idp.stories.support.StoryTarget;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.NetworkCapture;
import eu.wohlben.qits.userflows.NetworkEdge;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.Slugs;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import java.util.ArrayList;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * <b>A deployment cannot hand one client another client's identity: a client's roles are code, and
 * a configured roles line is not read at all.</b>
 *
 * <p>Every {@code client_credentials} token's {@code groups} ends with {@code clients/<the id in
 * sub>}, computed from the id that just authenticated. Nobody asks for it and nobody can turn it
 * off, which is what lets a resource service write {@code @RolesAllowed("clients/prod-qits-ci")} and
 * know that exactly one caller in the platform can ever reach that door.
 *
 * <p>The whole of that guarantee rests on the namespace being <b>minted and never granted</b>. Roles
 * used to be configuration — {@code qits.idp.client.<id>.roles} — and a line under {@code clients/}
 * was refused where it was read. Since qits-163 there is no such line to read: a service client is a
 * database row whose roles are fixed in code ({@code qits:system} and its own {@code
 * clients/<id>}), and a configured {@code roles} line is inert.
 *
 * <h2>Why this story keeps a client the other stories do not need</h2>
 *
 * <p>{@link StoryTarget#ROLE_THIEF} is still configured with a roles line naming {@link
 * StoryTarget#CI}'s self-role. Its secret gets it adopted into the database at the first start, like
 * any other configured client — and the story shows the roles line did nothing. {@link
 * StoryProfile} explains the client list this costs.
 */
@QuarkusIntegrationTest
@TestProfile(StoryProfile.class)
public class ReservedRoleNamespaceIT {

  static final String CATEGORY = "refusals";

  static final String CATEGORY_SLUG = Slugs.slug(CATEGORY);

  static final String STORY = "A deployment cannot grant a client another client's identity";

  static final String SLUG = Slugs.slug(STORY);

  /** Generated values that must appear in no file of the bundle — see {@code @AfterAll}. */
  private static final List<String> NEVER_IN_THE_BUNDLE = new ArrayList<>();

  @BeforeAll
  static void tapWhatReachesTheIssuer() {
    StoryNetwork.install();
  }

  @UserStory(value = STORY, category = CATEGORY)
  @UserStoryDescription(
      """
      Somebody configures a client with `roles=qits:system,clients/prod-qits-ci` — the one role
      that says "this bearer IS prod-qits-ci". If it worked, every door on the platform gated with
      `@RolesAllowed("clients/prod-qits-ci")` would open for it.

      It does not work, because roles are not configuration any more. The client's secret got it
      moved into the database at the first start, as a service client like any other, and a
      service client's roles are fixed in code. It presents its pair and gets a token whose
      `groups` are `qits:system` and its OWN `clients/uf-role-thief` — the roles line was never
      read.

      And the client whose identity was being reached for mints its own token, and the role is
      right there in it — minted from the id in `sub`, granted nowhere. It is held by exactly one
      client by CONSTRUCTION rather than by grant.
      """)
  void aConfiguredRolesLineIsNotRead(Interactions story)
      throws Exception {
    // (a) the client whose configuration reaches for another's identity. Its roles line is inert.
    NetworkCapture.actor(StoryTarget.ROLE_THIEF);
    String thiefToken =
        StoryTarget.form()
            .body(
                StoryTarget.clientCredentials(
                    StoryTarget.ROLE_THIEF,
                    StoryTarget.ROLE_THIEF_SECRET,
                    StoryTarget.DEPLOYMENTS_AUDIENCE))
            .when()
            .post(StoryTarget.TOKEN)
            .then()
            .statusCode(200)
            .body("access_token", notNullValue())
            .extract()
            .path("access_token");
    NEVER_IN_THE_BUNDLE.add(thiefToken);
    NetworkCapture.actor(StoryTarget.VALIDATOR);
    List<String> thiefGroups =
        PublishedJwks.verify(thiefToken, StoryTarget.PLATFORM_AUDIENCE)
            .getStringListClaimValue("groups");
    assertEquals(
        List.of(StoryTarget.SYSTEM_ROLE, StoryTarget.selfRoleOf(StoryTarget.ROLE_THIEF)),
        thiefGroups,
        "the fixed service-client roles; the configured line was never read");
    story
        .note(
            "a client configured with another client's minted self-role presents its pair and gets"
                + " a token carrying qits:system and its OWN self-role. The roles line was never"
                + " read: a service client is a database row and its roles are code")
        .as("a-configured-roles-line-is-not-read");

    // (b) and the identity it was reaching for is minted, not granted.
    NetworkCapture.actor(StoryTarget.CI);
    String token =
        StoryTarget.form()
            .body(
                StoryTarget.clientCredentials(
                    StoryTarget.CI, StoryTarget.CI_SECRET, StoryTarget.DEPLOYMENTS_AUDIENCE))
            .when()
            .post(StoryTarget.TOKEN)
            .then()
            .statusCode(200)
            .body("access_token", notNullValue())
            .extract()
            .path("access_token");
    NEVER_IN_THE_BUNDLE.add(token);

    NetworkCapture.actor(StoryTarget.VALIDATOR);
    JwtClaims claims = PublishedJwks.verify(token, StoryTarget.PLATFORM_AUDIENCE);
    List<String> groups = claims.getStringListClaimValue("groups");
    assertEquals(
        List.of(
            StoryTarget.SYSTEM_ROLE, StoryTarget.selfRoleOf(StoryTarget.CI)),
        groups,
        "the fixed role, then the self-role stamped from the id in sub");
    assertFalse(
        groups.contains(StoryTarget.selfRoleOf(StoryTarget.ROLE_THIEF)),
        "and nothing of the client that tried to reach for this one");
    story
        .note(
            "meanwhile the client whose identity was being reached for mints its own token, and the"
                + " role is right there — stamped from the id in sub, additive to the fixed role,"
                + " and grantable nowhere. A role naming one client is held by exactly that"
                + " client by CONSTRUCTION rather than by grant, which is what lets a resource"
                + " service gate a route on it and know one caller can reach the door")
        .as("the-self-role-is-minted-from-the-id-that-authenticated");
  }

  @AfterAll
  static void theReservedNamespaceStoryIsComplete() {
    ReportAssertions.assertComplete(CATEGORY_SLUG, SLUG, UserflowReport.PASSED);

    // --- the graph -------------------------------------------------------------------------------
    // The same route, twice, from two clients — both 200, each with its own identity. Plus the JWKS
    // read that makes both halves a proof rather than a look at a decoded body.
    edge(StoryTarget.ROLE_THIEF, StoryTarget.posted(StoryTarget.TOKEN, 200));
    edge(StoryTarget.CI, StoryTarget.posted(StoryTarget.TOKEN, 200));
    edge(StoryTarget.VALIDATOR, StoryTarget.read(StoryTarget.JWKS, 200));

    ReportAssertions.assertEdgeCount(CATEGORY_SLUG, SLUG, 3);
    ReportAssertions.assertOnlyEdgesFrom(
        CATEGORY_SLUG,
        SLUG,
        List.of(StoryTarget.ROLE_THIEF, StoryTarget.CI, StoryTarget.VALIDATOR));

    // Both clients are service clients held in memory, so neither mint opened a connection — and
    // no peer was asked about a role either: roles are code.
    ReportAssertions.assertNoEdgesFrom(CATEGORY_SLUG, SLUG, StoryTarget.SERVICE);

    ReportAssertions.assertStepId(CATEGORY_SLUG, SLUG, "a-configured-roles-line-is-not-read");
    ReportAssertions.assertStepId(
        CATEGORY_SLUG, SLUG, "the-self-role-is-minted-from-the-id-that-authenticated");

    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.CI_SECRET);
    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.ROLE_THIEF_SECRET);
    for (String value : NEVER_IN_THE_BUNDLE) {
      ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, value);
    }
  }

  private static void edge(String actor, String label) {
    ReportAssertions.assertEdge(
        CATEGORY_SLUG, SLUG, NetworkEdge.HTTP, actor, StoryTarget.SERVICE, label);
  }
}
