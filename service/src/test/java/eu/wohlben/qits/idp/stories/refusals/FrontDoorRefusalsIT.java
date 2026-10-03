package eu.wohlben.qits.idp.stories.refusals;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

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
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * <b>Six ways to be refused at the platform's front door, and not one of them is "open".</b>
 *
 * <p>This service is the one every other service asks before it can do anything, so the shape of its
 * refusals is the shape of the platform's whole trust boundary. Two rules run through all six:
 *
 * <p><b>Authentication failing and authorization failing are different answers.</b> 401 says "I do
 * not know you"; 400 says "I know you and that request is not one you may make". Collapsing them
 * would tell an operator to fix a secret when the secret is fine, and would hide from a deployment
 * that its client authenticated with a credential it should not have had.
 *
 * <p><b>And a refusal is coarse.</b> Which of "unknown client", "no secret configured" and "wrong
 * secret" happened is one answer — {@code invalid_client} — because the caller is not always the
 * right party to learn the difference. The log line is where it lives, and {@code LoggableClientId}
 * bounds what a caller can write into it.
 *
 * <h2>What this story pins that no unit test can</h2>
 *
 * <p>{@link StoryTarget#ARTIFACTS} is listed for the one-time adoption with <b>no secret</b>
 * (qits-163), so it never became a row: a client with no secret is unusable rather than open, and
 * there is no flag that turns that around. {@code StoryProfile} deliberately gives that one client
 * no secret, the same discipline {@code IdpTokenTest} keeps in the {@code @QuarkusTest} suite.
 *
 * <h2>And what it says about the store</h2>
 *
 * <p>None of these six touches postgres. A service client is a read of the map {@code ServiceClients}
 * loaded at start, while {@code DynamicClients.find} refuses anything that does not begin {@code
 * dyn-} without opening a connection. So the diagram carries no store edge and {@code
 * assertNoEdgesFrom} says so: <b>a refusal at the front door costs the database nothing</b>, which
 * is what keeps a burst of bad credentials from becoming a burst of connections.
 */
@QuarkusIntegrationTest
@TestProfile(StoryProfile.class)
public class FrontDoorRefusalsIT {

  static final String CATEGORY = "refusals";

  static final String CATEGORY_SLUG = Slugs.slug(CATEGORY);

  static final String STORY = "Six ways to be refused at the front door, and none of them is open";

  static final String SLUG = Slugs.slug(STORY);

  // --- the six initiators, because on the wire five of these requests are the same shape ---------

  private static final String UNKNOWN = "a caller naming a client that does not exist";

  private static final String EMPTY_HANDED = "a caller presenting no credential at all";

  private static final String DOUBLE_DIPPER = "a caller presenting its pair twice";

  private static final String WRONG_GRANT = "a caller asking for the password grant";

  private static final String GRANTLESS = "a caller naming no grant at all";

  @BeforeAll
  static void tapWhatReachesTheIssuer() {
    StoryNetwork.install();
  }

  @UserStory(value = STORY, category = CATEGORY)
  @UserStoryDescription(
      """
      Six requests arrive at `POST /idp/token` and none of them gets a bearer. What they get
      instead is four different RFC 6749 error codes, and the differences are the point.

      A caller naming a client that does not exist is `invalid_client`, 401 — answered from the
      service clients held in memory, without a query.

      qits-platform-artifacts was configured with no secret, so the one-time move of configured
      clients into the database skipped it and it does not exist either. It is refused exactly
      like a wrong secret. A client with no secret is unusable, never open, and there is no flag
      that turns that around: adding one would make an unconfigured deployment issue identity to
      whoever asks.

      A caller presenting nothing at all is `invalid_client` too, with the `WWW-Authenticate:
      Basic` challenge RFC 6749 §5.2 requires — because the machine surfaces authenticate with a
      Basic pair.

      A caller presenting its pair BOTH in the Authorization header and in the form is
      `invalid_request`, 400. RFC 6749 §2.3 forbids it, and accepting both would make "which one
      was checked" a question nobody should have to ask about a credential.

      A caller asking for the `password` grant is `unsupported_grant_type`; a caller naming no
      grant at all is `invalid_request`. Two codes, because "I do not implement that" and "you did
      not say" are two different things for the developer reading them.

      And nothing here reached the database. A service client is a read of a map loaded at start,
      so a burst of bad credentials at this door costs the store nothing at all.
      """)
  void everyRefusalIsOneOfFourCodesAndNoneOfThemIsABearer(Interactions story) {
    // (a) an id that is no client at all. Answered from memory.
    NetworkCapture.actor(UNKNOWN);
    StoryTarget.form()
        .body(
            StoryTarget.clientCredentials(
                "prod-qits-not-a-service", "any-secret-at-all", StoryTarget.DEPLOYMENTS_AUDIENCE))
        .when()
        .post(StoryTarget.TOKEN)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .body("access_token", nullValue())
        .header("WWW-Authenticate", equalTo("Basic realm=\"qits-platform-idp\""));
    story
        .note(
            "an id that is no client is invalid_client — answered from the service clients held in"
                + " memory, without a query")
        .as("an-unknown-client-is-refused-without-a-lookup");

    // (b) a client configured with no secret, so never adopted. The safe direction.
    NetworkCapture.actor(StoryTarget.ARTIFACTS);
    StoryTarget.form()
        .body(
            StoryTarget.clientCredentials(
                StoryTarget.ARTIFACTS, "any-secret-at-all", StoryTarget.DEPLOYMENTS_AUDIENCE))
        .when()
        .post(StoryTarget.TOKEN)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .body("access_token", nullValue());
    story
        .note(
            "a client configured with NO secret was never moved into the database, so it is"
                + " refused exactly like a wrong secret. Unusable, never open — there is no flag that"
                + " turns that around, and adding one would make an unconfigured deployment issue"
                + " identity to whoever asks")
        .as("a-client-with-no-secret-is-unusable-rather-than-open");

    // (c) nothing presented at all.
    NetworkCapture.actor(EMPTY_HANDED);
    StoryTarget.form()
        .body("grant_type=client_credentials&audience=" + StoryTarget.DEPLOYMENTS_AUDIENCE)
        .when()
        .post(StoryTarget.TOKEN)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .header("WWW-Authenticate", equalTo("Basic realm=\"qits-platform-idp\""));
    story
        .note(
            "a request with no credential in either supported place is invalid_client, and it"
                + " carries the WWW-Authenticate: Basic challenge RFC 6749 §5.2 requires — the"
                + " machine surfaces authenticate with a Basic pair, so that is the challenge to"
                + " send")
        .as("a-caller-with-nothing-is-challenged");

    // (d) both places at once — forbidden by RFC 6749 §2.3, and refused as a malformed REQUEST
    // rather than as a failed authentication, because the credential was never the problem.
    NetworkCapture.actor(DOUBLE_DIPPER);
    StoryTarget.form()
        .header("Authorization", StoryTarget.basic(StoryTarget.CI, StoryTarget.CI_SECRET))
        .body(
            StoryTarget.clientCredentials(
                StoryTarget.CI, StoryTarget.CI_SECRET, StoryTarget.DEPLOYMENTS_AUDIENCE))
        .when()
        .post(StoryTarget.TOKEN)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("access_token", nullValue());
    story
        .note(
            "credentials presented BOTH in the Authorization header and in the form is"
                + " invalid_request, 400 — RFC 6749 §2.3 forbids it, and accepting both would make"
                + " \"which one was checked\" a question somebody would eventually have to ask"
                + " about a credential. Note the pair here is the REAL one: this is a malformed"
                + " request, not a failed authentication")
        .as("a-pair-presented-twice-is-a-malformed-request");

    // (e) a grant this issuer does not implement.
    NetworkCapture.actor(WRONG_GRANT);
    StoryTarget.form()
        .body(
            "grant_type=password&client_id="
                + StoryTarget.CI
                + "&client_secret="
                + StoryTarget.CI_SECRET)
        .when()
        .post(StoryTarget.TOKEN)
        .then()
        .statusCode(400)
        .body("error", equalTo("unsupported_grant_type"))
        .body("access_token", nullValue());

    // (f) and no grant named at all. A different code, because "I do not implement that" and "you
    // did not say" are different things for the developer reading them.
    NetworkCapture.actor(GRANTLESS);
    StoryTarget.form()
        .body("client_id=" + StoryTarget.CI + "&client_secret=" + StoryTarget.CI_SECRET)
        .when()
        .post(StoryTarget.TOKEN)
        .then()
        .statusCode(400)
        .body("error", equalTo("invalid_request"))
        .body("access_token", nullValue());
    story
        .note(
            "the password grant is unsupported_grant_type and a missing grant_type is"
                + " invalid_request — two codes for two different facts. Both are answered BEFORE"
                + " the credential is looked at, which is why a valid pair does not turn either of"
                + " them into a bearer")
        .as("two-answers-for-two-kinds-of-wrong-grant");

    story
        .note(
            "and none of the six reached the database: a service client is a read of a map loaded"
                + " at start, so a burst of bad credentials at the platform's front door costs the"
                + " store nothing at all")
        .as("a-refusal-costs-the-store-nothing");
  }

  @AfterAll
  static void theRefusalStoryIsComplete() {
    ReportAssertions.assertComplete(CATEGORY_SLUG, SLUG, UserflowReport.PASSED);

    // --- the graph -------------------------------------------------------------------------------
    // SIX arrows into one route. A form body never reaches a label, so what tells these apart is the
    // actor and the status — which is the whole reason the actors are named rather than derived.
    in(UNKNOWN, 401);
    in(StoryTarget.ARTIFACTS, 401);
    in(EMPTY_HANDED, 401);
    in(DOUBLE_DIPPER, 400);
    in(WRONG_GRANT, 400);
    in(GRANTLESS, 400);

    ReportAssertions.assertEdgeCount(CATEGORY_SLUG, SLUG, 6);
    ReportAssertions.assertOnlyEdgesFrom(
        CATEGORY_SLUG,
        SLUG,
        List.of(
            UNKNOWN,
            StoryTarget.ARTIFACTS,
            EMPTY_HANDED,
            DOUBLE_DIPPER,
            WRONG_GRANT,
            GRANTLESS));

    // THE LEAF'S CLAIM, and here it has teeth: not one of these six reached anything — not a peer,
    // not an audit sink, and not the store, because none of them got as far as a client that has a
    // row. A refusal is this service's own answer, and it costs nothing downstream.
    ReportAssertions.assertNoEdgesFrom(CATEGORY_SLUG, SLUG, StoryTarget.SERVICE);

    for (String step :
        List.of(
            "an-unknown-client-is-refused-without-a-lookup",
            "a-client-with-no-secret-is-unusable-rather-than-open",
            "a-caller-with-nothing-is-challenged",
            "a-pair-presented-twice-is-a-malformed-request",
            "two-answers-for-two-kinds-of-wrong-grant",
            "a-refusal-costs-the-store-nothing")) {
      ReportAssertions.assertStepId(CATEGORY_SLUG, SLUG, step);
    }

    // The one real credential this story presented — twice, and never into a bearer.
    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.CI_SECRET);
  }

  private static void in(String actor, int status) {
    ReportAssertions.assertEdge(
        CATEGORY_SLUG,
        SLUG,
        NetworkEdge.HTTP,
        actor,
        StoryTarget.SERVICE,
        StoryTarget.posted(StoryTarget.TOKEN, status));
  }
}
