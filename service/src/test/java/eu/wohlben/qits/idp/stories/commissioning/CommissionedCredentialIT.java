package eu.wohlben.qits.idp.stories.commissioning;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.api.PublishedJwks;
import eu.wohlben.qits.idp.stories.support.StoryNetwork;
import eu.wohlben.qits.idp.stories.support.StoryProfile;
import eu.wohlben.qits.idp.stories.support.StoryTarget;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.Network;
import eu.wohlben.qits.userflows.NetworkCapture;
import eu.wohlben.qits.userflows.NetworkEdge;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.Slugs;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import java.util.ArrayList;
import java.util.List;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * <b>The commission model, told from the idp's side of it.</b>
 *
 * <p>qits-platform-workspaces provisions a container and needs that container to be able to talk to
 * the platform — so it asks this service for a credential of the container's own, hands it over, and
 * deletes it when the context ends. Every sibling tells the calling half of that; this is the half
 * where the credential is actually made, used, and taken away again.
 *
 * <p><b>The invariant the whole model rests on is that there is no branch.</b> {@code TokenService}
 * asks {@code ClientRegistry} for a client and never learns which half answered, so a commissioned
 * credential mints <i>identically</i> to a service client — same endpoint, same grant, same response
 * shape, same hour. That is what lets docker's Bearer dance and {@code quarkus-oidc-client} work
 * against a commissioned pair with no second code path anywhere on the platform. On a diagram it
 * shows as the arrow this story shares with {@code TokenIssuanceBootstrapIT}: {@code POST /idp/token
 * -> 200}, from a different actor and otherwise the same.
 *
 * <p><b>And the credential is its own identity, not a copy of its owner's.</b> It is issued its
 * owner's audiences — resolved at mint time from the owner's record rather than copied into the
 * row — but its roles are its own context kind's fixed ones in code, or none (D12 of
 * {@code service-client-identity-plan.md}), and its claims are only what it stated for itself (D3).
 * The {@code clients/…} self-role is stamped from the id in {@code sub}, so it carries {@code
 * clients/dyn-…} and never {@code clients/prod-qits-workspaces}. A door held open for the owner
 * stays shut to the credential it commissioned. That falls out of the mechanism and this story
 * asserts it rather than trusting it.
 *
 * <h2>The one declared edge in this catalogue lives here</h2>
 *
 * <p>A commission is a row: an insert, a read on the first mint after a cache miss, and a delete.
 * No tap can see a JDBC call, so the store arrives as {@link Network#declare} — dashed in the
 * diagram and flagged {@code declared} in the sidecar, because a claim must never render like
 * evidence. It is the reason this story does <b>not</b> assert {@code assertNoEdgesFrom} the way the
 * minting and reading stories do: the negative claim is theirs to make, because a static mint is
 * four config lookups and touches no store at all, and the positive one is this story's.
 */
@QuarkusIntegrationTest
@TestProfile(StoryProfile.class)
public class CommissionedCredentialIT {

  static final String CATEGORY = "commissioning";

  static final String CATEGORY_SLUG = Slugs.slug(CATEGORY);

  static final String STORY = "A workspace commissions a credential and the container mints with it";

  static final String SLUG = Slugs.slug(STORY);

  /**
   * This story's own context kind. Every story that writes rows names one, because the launched
   * process migrates but does not clean its schema — {@code flyway.clean-at-start} is in the {@code
   * @QuarkusTest} suite's resources, not in the jar — so the store carries whatever earlier runs
   * left. A listing assertion filters on the kind and the id rather than assuming an empty table.
   */
  private static final String CONTEXT_KIND = "uf-mint";

  /** The workspace whose container this is. Unique per run, so a listing can find exactly this one. */
  private static final String CONTEXT_ID = "ws-" + System.nanoTime();

  /**
   * What must not be anywhere in the emitted bundle. Collected during the story because the values
   * are generated, and asserted in {@code @AfterAll} because that is when the files exist.
   *
   * <p>The client id is in here beside the two credentials, and it is not a secret — it is the
   * <b>hash-stability</b> check wearing the same coat. If a run-local id ever reached a label, a
   * note or a step id, this story's {@code networkHash} and {@code definitionHash} would move on
   * every run, and the only symptom would be a hash that never settles.
   */
  private static final List<String> NEVER_IN_THE_BUNDLE = new ArrayList<>();

  @BeforeAll
  static void tapWhatReachesTheIssuer() {
    StoryNetwork.install();
  }

  @UserStory(value = STORY, category = CATEGORY)
  @UserStoryDescription(
      """
      A workspace is being provisioned and its container will have to talk to the platform. The
      workspaces service does not hand out its own credential — that would put one secret in every
      container and make a leak unbounded — so it asks the idp for a credential of the container's
      own, naming the context it is for.

      What comes back is an id and a secret, and the secret exists in that one answer and nowhere
      else: the store holds a SHA-256 of it. A caller that loses it decommissions and commissions
      again.

      The container then mints exactly the way a platform service does. Same endpoint, same grant,
      same response, same hour-long lifetime — because `TokenService` asks the registry for a
      client and is never told which half answered. That identity is the whole commission model
      working: nothing else on the platform needs a second code path for a commissioned pair.

      The bearer it gets is its owner's REACH and its own IDENTITY. The audiences are resolved from
      the owner's record at mint time, so narrowing the owner narrows every credential it
      commissioned, at once. Its roles are NOT the owner's: they are this context kind's fixed role
      in code, or none at all. The `clients/…` self-role is stamped from the id in `sub`, so the
      credential carries `clients/dyn-…` and never its owner's — a door held open for
      qits-platform-workspaces stays shut to the container it provisioned.

      Then the context ends. The owner deletes the row and the credential mints nothing from the
      very next request onward — no TTL, no propagation delay, no second instance holding a stale
      copy. What it already minted lives out its `exp`, which is the accepted cost recorded on
      `qits.idp.token-ttl-seconds` and the reason an owner decommissions at the end of a context
      rather than treating it as an emergency stop.
      """)
  void aCommissionedCredentialMintsItsOwnersReachUnderItsOwnIdentity(
      Interactions story, Network network) throws Exception {
    // The store is real and no tap can see it: an insert, a read on the first mint after the cache
    // miss, and a delete. Declared, so the diagram carries the one dependency this service has —
    // dashed, because it is a claim and the rest of the picture is evidence.
    network.declare(
        NetworkEdge.JDBC,
        StoryTarget.SERVICE,
        "postgres (the idp's own store)",
        "commissioned clients: insert, read, delete");

    // ---- the owner asks for a credential for one context ---------------------------------------
    NetworkCapture.actor(StoryTarget.WORKSPACES);
    JsonPath commissioned =
        StoryTarget.machine(StoryTarget.WORKSPACES, StoryTarget.WORKSPACES_SECRET)
            .contentType(ContentType.JSON)
            .body(
                "{\"contextKind\":\""
                    + CONTEXT_KIND
                    + "\",\"contextId\":\""
                    + CONTEXT_ID
                    + "\"}")
            .when()
            .post(StoryTarget.CLIENTS)
            .then()
            .statusCode(201)
            .body("owner", equalTo(StoryTarget.WORKSPACES))
            .body("contextKind", equalTo(CONTEXT_KIND))
            .body("contextId", equalTo(CONTEXT_ID))
            .body("clientId", startsWith("dyn-"))
            .body("secret", notNullValue())
            // The body holds a credential: same rule as the token response, same reason.
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            // No Location header, deliberately: the URL a caller reaches this service at is the
            // deployment's — direct on qits-net for a service, through the edge for an operator —
            // and this process knows neither, so a self-built absolute URL would be wrong for
            // somebody. The clientId in the body is the whole address.
            .header("Location", nullValue())
            .extract()
            .jsonPath();
    String clientId = commissioned.getString("clientId");
    String secret = commissioned.getString("secret");
    assertNotNull(clientId, "the answer is the only place the id is");
    assertNotNull(secret, "and the only place the secret will ever be");
    assertTrue(
        clientId.startsWith("dyn-" + CONTEXT_KIND + "-"),
        "the id is readable on purpose: an operator reading a listing tells a stuck workspace from"
            + " a stuck ci run without joining anything");
    story
        .note(
            "the workspaces service asks for a credential for ONE context, naming the kind and the"
                + " id; the answer carries the pair and is no-store, because the secret is in that"
                + " answer and nowhere else — the row holds a SHA-256 of it, so a caller that loses"
                + " it decommissions and commissions again")
        .as("a-credential-is-commissioned");

    // ---- the container mints, and it is the same mint a platform service makes -----------------
    NetworkCapture.actor(StoryTarget.CONTAINER);
    String token =
        StoryTarget.machine(clientId, secret)
            .contentType(ContentType.URLENC)
            .body("grant_type=client_credentials&audience=" + StoryTarget.ARTIFACTS_AUDIENCE)
            .when()
            .post(StoryTarget.TOKEN)
            .then()
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .body("access_token", notNullValue())
            // The SHIPPED lifetime, and the same one a static client gets. There is no branch.
            .body("expires_in", equalTo(StoryTarget.TOKEN_TTL_SECONDS))
            .header("Cache-Control", "no-store")
            .extract()
            .path("access_token");
    story
        .note(
            "the container presents the pair with client_secret_basic and gets back exactly what a"
                + " platform service gets — same grant, same response shape, same shipped hour."
                + " TokenService asks the registry for a client and is never told which half"
                + " answered, and that identity is the whole commission model working")
        .as("the-container-mints");

    // ---- what the bearer says, verified the way its recipient would ----------------------------
    // Against whatever /idp/jwks publishes, over HTTP. The actor is the service the bearer will be
    // presented TO, because that is who fetches the JWKS in the real flow — not the minter.
    NetworkCapture.actor(StoryTarget.VALIDATOR);
    JwtClaims claims = PublishedJwks.verify(token, StoryTarget.ARTIFACTS_AUDIENCE);
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer(), "iss is the one derived issuer");
    assertEquals(
        clientId, claims.getSubject(), "sub is the commissioned id, never the owner's");
    assertEquals(
        List.of(
            StoryTarget.CI,
            StoryTarget.ARTIFACTS_AUDIENCE,
            StoryTarget.WORKSPACES,
            StoryTarget.DEPLOYMENTS_AUDIENCE,
            "prod-qits-githost",
            "qits-platform"),
        PublishedJwks.audienceOf(claims),
        "aud is the OWNER's WHOLE shipped list, not narrowed to the one audience that was asked"
            + " for, plus qits-platform — both transitional (service-client-identity-plan.md, C2):"
            + " a receiver that has not yet taken the qits-auth-core release accepting"
            + " qits-platform still finds its own name on the token");
    List<String> groups = claims.getStringListClaimValue("groups");
    assertEquals(
        List.of(StoryTarget.selfRoleOf(clientId)),
        groups,
        "this story's own kind has no fixed role (D12 of service-client-identity-plan.md), so the"
            + " credential carries only its own self-role — never the owner's roles any more");
    assertFalse(
        groups.contains(StoryTarget.selfRoleOf(StoryTarget.WORKSPACES)),
        "and never the owner's self-role: a door held open for the owner stays shut to what it"
            + " commissioned");
    story
        .note(
            "the bearer carries the OWNER's reach and its OWN identity: the audiences are resolved"
                + " from the owner's record at mint time, so narrowing the owner narrows every"
                + " credential it commissioned at once. Its roles are NOT the owner's any more —"
                + " they are this context kind's fixed role in code, or none — and its claims are"
                + " only what it stated for itself. The clients/… self-role is stamped from the id"
                + " in sub, so it is the credential's own and never qits-platform-workspaces'")
        .as("the-bearer-is-its-owners-reach-and-its-own-identity");

    // ---- the owner can see what it holds, which is how a crash cannot leak a credential --------
    NetworkCapture.actor(StoryTarget.WORKSPACES);
    StoryTarget.machine(StoryTarget.WORKSPACES, StoryTarget.WORKSPACES_SECRET)
        .when()
        .get(StoryTarget.CLIENTS)
        .then()
        .statusCode(200)
        .body(
            "find { it.contextId == '" + CONTEXT_ID + "' }.clientId", equalTo(clientId))
        .body("find { it.contextId == '" + CONTEXT_ID + "' }.owner", equalTo(StoryTarget.WORKSPACES))
        // No secret is on the listing, ever. It was in the commission answer and nowhere since.
        .body("find { it.contextId == '" + CONTEXT_ID + "' }.secret", nullValue());
    story
        .note(
            "the owner can list what it commissioned — and only what it commissioned — so a service"
                + " that crashed mid-provision reconciles against its own live contexts and"
                + " decommissions whatever it no longer recognises. Leaked credentials are answered"
                + " structurally here rather than by a TTL, which is why the credential has none")
        .as("the-owner-reconciles-against-its-own-listing");

    // ---- the context ends -----------------------------------------------------------------------
    StoryTarget.machine(StoryTarget.WORKSPACES, StoryTarget.WORKSPACES_SECRET)
        .when()
        .delete(StoryTarget.client(clientId))
        .then()
        .statusCode(204);

    NetworkCapture.actor(StoryTarget.CONTAINER);
    StoryTarget.machine(clientId, secret)
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials&audience=" + StoryTarget.ARTIFACTS_AUDIENCE)
        .when()
        .post(StoryTarget.TOKEN)
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .body("access_token", nullValue());
    story
        .note(
            "the context ends, the owner deletes the row, and the credential mints nothing from the"
                + " VERY NEXT REQUEST — the resolved row is evicted on both sides of the delete, so"
                + " there is no window in which a cache re-reads it. What it already minted lives"
                + " out its exp: that hour is the accepted cost recorded on"
                + " qits.idp.token-ttl-seconds, and the reason an owner decommissions at the end of"
                + " a context rather than as an emergency stop")
        .as("decommission-stops-the-minting-immediately");

    // Nothing run-local goes into a note or a step id: a commissioned id and a secret would move the
    // definitionHash on every run and would put a credential in the bundle. Both are checked in
    // @AfterAll, over the bundle's raw bytes.
    NEVER_IN_THE_BUNDLE.add(secret);
    NEVER_IN_THE_BUNDLE.add(token);
    NEVER_IN_THE_BUNDLE.add(clientId);
  }

  @AfterAll
  static void theCommissionStoryIsComplete() {
    ReportAssertions.assertComplete(CATEGORY_SLUG, SLUG, UserflowReport.PASSED);

    // --- the graph -------------------------------------------------------------------------------
    // Five incoming arrows and one declared store edge. The two POST /idp/token arrows are the
    // same route from the same actor and differ only in status, which IS the story: the credential
    // worked, and then the row was gone.
    in(StoryTarget.WORKSPACES, StoryTarget.posted(StoryTarget.CLIENTS, 201));
    in(StoryTarget.CONTAINER, StoryTarget.posted(StoryTarget.TOKEN, 200));
    in(StoryTarget.VALIDATOR, StoryTarget.read(StoryTarget.JWKS, 200));
    in(StoryTarget.WORKSPACES, StoryTarget.read(StoryTarget.CLIENTS, 200));
    in(StoryTarget.WORKSPACES, StoryTarget.deleted(StoryTarget.ANY_CLIENT, 204));
    in(StoryTarget.CONTAINER, StoryTarget.posted(StoryTarget.TOKEN, 401));

    ReportAssertions.assertDeclaredEdge(
        CATEGORY_SLUG,
        SLUG,
        NetworkEdge.JDBC,
        StoryTarget.SERVICE,
        "postgres (the idp's own store)",
        "commissioned clients: insert, read, delete");

    // SEVEN, and the seventh is the declared one. An eighth would mean this process dialled
    // something — and "the idp reaches its own store and nothing else" is a claim no presence check
    // can make.
    ReportAssertions.assertEdgeCount(CATEGORY_SLUG, SLUG, 7);
    ReportAssertions.assertOnlyEdgesFrom(
        CATEGORY_SLUG,
        SLUG,
        List.of(
            StoryTarget.WORKSPACES,
            StoryTarget.CONTAINER,
            StoryTarget.VALIDATOR,
            // The service itself initiates exactly one thing, and it is the DECLARED store edge.
            // Listing it here is what makes the actor set the story's whole promise: any other
            // initiator — a leaked actor, a story that forgot to name itself — fails right here.
            StoryTarget.SERVICE));

    for (String step :
        List.of(
            "a-credential-is-commissioned",
            "the-container-mints",
            "the-bearer-is-its-owners-reach-and-its-own-identity",
            "the-owner-reconciles-against-its-own-listing",
            "decommission-stops-the-minting-immediately")) {
      ReportAssertions.assertStepId(CATEGORY_SLUG, SLUG, step);
    }

    // Nothing that was presented and nothing that was answered is in the bundle. A token in a label
    // would be a bearer published to a docs site.
    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.WORKSPACES_SECRET);
    for (String value : NEVER_IN_THE_BUNDLE) {
      ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, value);
    }
  }

  private static void in(String actor, String label) {
    ReportAssertions.assertEdge(
        CATEGORY_SLUG, SLUG, NetworkEdge.HTTP, actor, StoryTarget.SERVICE, label);
  }
}
