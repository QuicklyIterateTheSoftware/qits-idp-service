package eu.wohlben.qits.idp.stories.keys;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * <b>Two open documents are the whole bootstrap of the platform, and a consumer that cached them is
 * holding the right thing.</b>
 *
 * <p>Every service on qits is configured with exactly one string about identity: the idp's address.
 * From it OIDC derives {@code /.well-known/openid-configuration} by its own rule, and from that
 * document a consumer reads the token endpoint and the JWKS. The {@code iss} it will then compare
 * against has <b>one</b> source, {@code Issuer.url()}, derived from the platform's domain as {@code
 * https://idp.qits.<domain>} and configured nowhere — two sources for that one string is exactly
 * how a consumer ends up rejecting a token whose {@code iss} differs from the discovery document's
 * {@code issuer} by one character.
 *
 * <p><b>The endpoints are NOT that string, and this suite used to insist they were.</b> The rule
 * read "one key, and every advertised URL derived from it", which was sound while the idp's
 * identifier and its address were the same text. Deleting the platform plane ended that: the
 * address became {@code <env>-qits-platform-idp} while the issuer stayed {@code qits-platform-idp}
 * until qits-730 derived it from the domain. Deriving the endpoints from the issuer across that split published a {@code jwks_uri} on a
 * dead host — invisible to every running consumer, which had it cached, and fatal to any service
 * booting for the first time. So the endpoints hang off {@code qits.idp.endpoint-base} now and the
 * story asserts the two are different strings.
 *
 * <p><b>And both documents are unauthenticated, which is not a relaxation.</b> A service fetches the
 * JWKS at boot, <i>before</i> it holds a token; a JWKS behind a bearer would be a service unable to
 * validate the bearer that would let it fetch the JWKS. There is nothing secret on either: the
 * published key is the public half and carries no private member, and this story asserts the absence
 * of every one of them by name rather than trusting the serializer.
 *
 * <h2>Cache semantics, as shipped</h2>
 *
 * <p>This is the half a reader arrives here asking about, and the honest answer is short: <b>this
 * service sets no cache TTL on either document</b>. The token response is {@code no-store} — RFC
 * 6749 §5.1, and the only shipped lifetime on this whole path is the token's own {@code expires_in},
 * one hour. The two bootstrap documents carry no {@code no-store}, which is what makes them
 * cacheable at all, and no {@code max-age} either, so <b>how long a consumer holds them is the
 * consumer's own policy</b> — {@code quarkus-oidc}'s JWKS cache on the validating side, not
 * anything this service dictates. The story pins the difference between the two postures rather than
 * inventing a number, because a shrunken TTL asserted here would be a fixture rather than the
 * deployment.
 *
 * <p>What the service <i>does</i> promise is that a cached copy stays right: read twice, the JWKS is
 * byte-identical and names the same {@code kid}. Rotation is a data change — many rows, one {@code
 * ACTIVE}, all published — so a key leaving the active seat never removes it from this document, and
 * a consumer holding a cached copy across a rotation still validates the tokens it was minted for.
 *
 * <h2>One seam is out of reach, and it is stated rather than worked around</h2>
 *
 * <p>The advertised URLs are absolute and name {@code http://dev-qits-platform-idp:8080/idp}, a host
 * that resolves on {@code qits-net} and nowhere else. So this story <b>reads the document's
 * derivation and then addresses the paths on the launched process's own port</b> rather than
 * following the absolute URL the way a real consumer does. Pointing {@code qits.idp.endpoint-base}
 * at the launched process is not available to a {@code @TestProfile}: the port is ephemeral and the
 * overrides are computed before the process exists. What is proven here is therefore that the
 * document derives its endpoints from the endpoint base and that those <i>paths</i> serve; that a
 * consumer can resolve the <i>host</i> is a deployment fact, and {@code qits-net} is where it is
 * true.
 *
 * <p><b>That unreachable seam is where the defect lived, and it is worth naming as a cost.</b> A
 * story that can only assert paths cannot notice that the host in front of them stopped resolving.
 * Nothing here would have caught it; what caught it was a service that failed to boot in
 * production. The nearest available guard is the one added above — that the base and the issuer are
 * different strings, so the derivation cannot quietly collapse back onto the identifier.
 */
@QuarkusIntegrationTest
@TestProfile(StoryProfile.class)
public class BootstrapDocumentsIT {

  static final String CATEGORY = "keys";

  static final String CATEGORY_SLUG = Slugs.slug(CATEGORY);

  static final String STORY = "A consumer bootstraps from two open documents and caches the right one";

  static final String SLUG = Slugs.slug(STORY);

  /** The one thing a consumer is configured with, before it has fetched anything. */
  private static final String NEWCOMER = "a consumer holding nothing but the issuer string";

  /** Generated values that must appear in no file of the bundle — see {@code @AfterAll}. */
  private static final List<String> NEVER_IN_THE_BUNDLE = new ArrayList<>();

  @BeforeAll
  static void tapWhatReachesTheIssuer() {
    StoryNetwork.install();
  }

  @UserStory(value = STORY, category = CATEGORY)
  @UserStoryDescription(
      """
      A service is deployed and knows one string about identity: the idp's address,
      `http://dev-qits-platform-idp:8080/idp`. Everything else it learns by asking.

      It derives the discovery document from that string by OIDC's own rule and reads its
      endpoints off it. Every one of them hangs off the same ADDRESS inside this service too —
      `token_endpoint` is `<base>/token`, `jwks_uri` is `<base>/jwks` — so what the document sends
      a consumer to is somewhere that answers.

      The `issuer` it advertises is a different string, and that is deliberate rather than a
      mistake: the idp is IDENTIFIED by `https://idp.qits.<domain>`, derived from the platform's
      domain (`https://idp.qits.localhost` here, where none is stated) and configured nowhere.
      The issuer is compared and the address is dialled, so they are two values. What must not
      drift is `iss` itself, and it has exactly one source.

      Then it fetches the JWKS, holding no credential of any kind, and that has to work: a service
      fetches the keys at BOOT, before it holds a token, and a JWKS behind a bearer would be a
      service unable to validate the bearer that would let it fetch the JWKS. The discovery
      document is open for the same reason.

      Nothing secret is on either. The published key is the public half — `n` and `e` and no
      more — and every private member is checked absent by name, because "the serializer would
      not do that" is not something to find out from a production JWKS.

      It reads the document twice and gets the same bytes and the same `kid`, which is what makes
      caching it safe. And the cache posture is the shipped one, not a shrunken one: the TOKEN
      response is `no-store`, because a bearer must never sit in a cache; the two bootstrap
      documents are not, because they are meant to be held. Neither carries a `max-age` — how
      long a consumer keeps them is the consumer's own OIDC client policy, and the only lifetime
      this service ships on this path is the token's own hour.
      """)
  void theTwoBootstrapDocumentsAreOpenDerivedAndCacheable(Interactions story) {
    // ---- the one address a consumer was configured with ------------------------------------------
    NetworkCapture.actor(NEWCOMER);
    JsonPath discovery =
        given()
            .when()
            .get(StoryTarget.DISCOVERY)
            .then()
            .statusCode(200)
            .body("issuer", equalTo(StoryTarget.ISSUER))
            .body("token_endpoint", equalTo(StoryTarget.ENDPOINT_BASE + "/token"))
            .body("jwks_uri", equalTo(StoryTarget.ENDPOINT_BASE + "/jwks"))
            .body("authorization_endpoint", equalTo(StoryTarget.ENDPOINT_BASE + "/authorize"))
            .body("grant_types_supported", hasItem("client_credentials"))
            .body(
                "token_endpoint_auth_methods_supported",
                hasItems("client_secret_basic", "client_secret_post"))
            .body("id_token_signing_alg_values_supported", hasItem("RS256"))
            .body("claims_supported", hasItems("iss", "sub", "aud", "groups", "exp"))
            .extract()
            .jsonPath();

    // The endpoints are derived from ONE base and the issuer is derived from ANOTHER, and the split
    // is the fix rather than the drift the old single-key rule feared. What that rule got right is
    // that `iss` has ONE source; what it got wrong is treating an address as the same kind of thing.
    String issuer = discovery.getString("issuer");
    assertEquals(
        StoryTarget.TOKEN,
        URI.create(discovery.getString("token_endpoint")).getPath(),
        "the token endpoint is the endpoint base's own path plus /token");
    assertEquals(
        StoryTarget.JWKS,
        URI.create(discovery.getString("jwks_uri")).getPath(),
        "and the JWKS is the endpoint base's own path plus /jwks");
    assertTrue(
        discovery.getString("token_endpoint").startsWith(StoryTarget.ENDPOINT_BASE)
            && discovery.getString("jwks_uri").startsWith(StoryTarget.ENDPOINT_BASE),
        "both are derived from the endpoint base rather than configured one by one");
    assertNotEquals(
        issuer,
        StoryTarget.ENDPOINT_BASE,
        "and the base is NOT the issuer: this platform's idp is identified by a name it stopped"
            + " answering on, which is exactly the case the one-string rule could not express");
    story
        .note(
            "the consumer derives the discovery document from the ONE string it was configured with"
                + " and reads every endpoint off it. Those endpoints hang off the ADDRESS the idp"
                + " answers on, and the issuer is a separate string it is merely IDENTIFIED by —"
                + " here they differ, because deleting the platform plane moved the address and"
                + " deliberately left the issuer behind. Deriving the endpoints from the issuer"
                + " through that change is what advertised a jwks_uri on a host that no longer"
                + " resolves: every running consumer had it cached and never noticed, and a service"
                + " booting for the first time followed the document into UnknownHostException and"
                + " rolled back. What still must not drift is `iss`, and it has one source")
        .as("the-endpoints-derive-from-the-address-the-issuer-identifies-only");

    // ---- the keys, fetched holding nothing --------------------------------------------------------
    // The PATH comes from the document; the host does not, and cannot — see the class javadoc.
    String jwksPath = URI.create(discovery.getString("jwks_uri")).getPath();
    Response first =
        given()
            .when()
            .get(jwksPath)
            .then()
            .statusCode(200)
            .body("keys[0].kty", equalTo("RSA"))
            .body("keys[0].use", equalTo("sig"))
            .body("keys[0].alg", equalTo("RS256"))
            .body("keys[0].kid", notNullValue())
            .body("keys[0].n", notNullValue())
            .body("keys[0].e", notNullValue())
            // The private half has no member here and must never gain one. Named one by one,
            // because a JWK's private members are five and "there is no d" is not the whole check.
            .body("keys[0].d", nullValue())
            .body("keys[0].p", nullValue())
            .body("keys[0].q", nullValue())
            .body("keys[0].dp", nullValue())
            .body("keys[0].dq", nullValue())
            .body("keys[0].qi", nullValue())
            .extract()
            .response();
    String kid = first.jsonPath().getString("keys[0].kid");
    assertNotNull(kid, "every published key names itself, or rotation is a flag day");
    NEVER_IN_THE_BUNDLE.add(kid);
    story
        .note(
            "and it fetches the keys holding NO credential at all, which is what the door has to"
                + " allow: a service fetches the JWKS at boot, before it holds a token, and a JWKS"
                + " behind a bearer would be a service unable to validate the bearer that would let"
                + " it fetch the JWKS. Nothing secret is on it — the published key is the public"
                + " half and every private member is checked absent by name")
        .as("the-keys-are-served-to-a-caller-holding-nothing");

    // ---- read it again: the same bytes, so a cached copy is the right copy -------------------------
    Response second = given().when().get(jwksPath).then().statusCode(200).extract().response();
    assertEquals(
        first.asString(),
        second.asString(),
        "two reads of the JWKS are byte-identical: a consumer's cached copy is the served copy");
    assertEquals(
        kid,
        second.jsonPath().getString("keys[0].kid"),
        "and it names the same key — rotation is a data change, not a restart");
    story
        .note(
            "read twice, the document is byte-identical and names the same kid — which is what makes"
                + " caching it safe. Rotation here is a DATA change: many rows, one ACTIVE, all"
                + " published, so a key leaving the active seat never leaves this document and a"
                + " consumer holding a cached copy across a rotation still validates what it was"
                + " minted for")
        .as("a-cached-jwks-stays-the-served-jwks");

    // ---- the cache posture, as shipped ------------------------------------------------------------
    String jwksCacheControl = first.header("Cache-Control");
    assertTrue(
        jwksCacheControl == null || !jwksCacheControl.contains("no-store"),
        "the JWKS is meant to be cached, so it must not be no-store; was: " + jwksCacheControl);

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
            // The SHIPPED lifetime — an hour since the commission model landed — read from the
            // jar's own default and not from a test file.
            .body("expires_in", equalTo(StoryTarget.TOKEN_TTL_SECONDS))
            .header("Cache-Control", equalTo("no-store"))
            .header("Pragma", equalTo("no-cache"))
            .extract()
            .path("access_token");
    NEVER_IN_THE_BUNDLE.add(token);
    story
        .note(
            "the two postures on one process: the TOKEN response is no-store, because a bearer must"
                + " never sit in a cache, and the bootstrap documents are not, because they are"
                + " meant to be held. Neither document carries a max-age either — how long a"
                + " consumer keeps them is its own OIDC client policy, and the only lifetime this"
                + " service ships on this path is the token's own hour")
        .as("no-store-for-the-bearer-cacheable-for-the-documents");

    story
        .note(
            "nothing left this process to answer any of it. The keys are served from a cache this"
                + " service loaded at boot and a static client is four configuration lookups, so"
                + " the platform's whole bootstrap path — the document, the keys, the mint — is"
                + " answered without a single outbound call")
        .as("the-bootstrap-path-dials-nothing");
  }

  @AfterAll
  static void theBootstrapStoryIsComplete() {
    ReportAssertions.assertComplete(CATEGORY_SLUG, SLUG, UserflowReport.PASSED);

    // --- the graph -------------------------------------------------------------------------------
    // THREE arrows, and the JWKS was read twice: same caller, same route, same status, one edge.
    // The count is not the claim — what the two reads proved is in the note beside them.
    in(NEWCOMER, StoryTarget.read(StoryTarget.DISCOVERY, 200));
    in(NEWCOMER, StoryTarget.read(StoryTarget.JWKS, 200));
    in(StoryTarget.CI, StoryTarget.posted(StoryTarget.TOKEN, 200));

    ReportAssertions.assertEdgeCount(CATEGORY_SLUG, SLUG, 3);
    ReportAssertions.assertOnlyEdgesFrom(CATEGORY_SLUG, SLUG, List.of(NEWCOMER, StoryTarget.CI));

    // THE LEAF'S CLAIM, on the path that carries the whole platform: the document, the keys and a
    // static client's bearer are all answered without this process initiating anything — no store
    // read behind the JWKS (the keys are a volatile cache loaded at boot), and none behind the mint
    // (a static client is four config lookups, and keeping that true is a standing rule here).
    ReportAssertions.assertNoEdgesFrom(CATEGORY_SLUG, SLUG, StoryTarget.SERVICE);

    for (String step :
        List.of(
            "the-endpoints-derive-from-the-address-the-issuer-identifies-only",
            "the-keys-are-served-to-a-caller-holding-nothing",
            "a-cached-jwks-stays-the-served-jwks",
            "no-store-for-the-bearer-cacheable-for-the-documents",
            "the-bootstrap-path-dials-nothing")) {
      ReportAssertions.assertStepId(CATEGORY_SLUG, SLUG, step);
    }

    ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, StoryTarget.CI_SECRET);
    for (String value : NEVER_IN_THE_BUNDLE) {
      ReportAssertions.assertNotLeaked(CATEGORY_SLUG, SLUG, value);
    }
  }

  private static void in(String actor, String label) {
    ReportAssertions.assertEdge(
        CATEGORY_SLUG, SLUG, NetworkEdge.HTTP, actor, StoryTarget.SERVICE, label);
  }
}
