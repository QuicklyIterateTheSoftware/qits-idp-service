package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * The whole service as it is <b>packaged</b>, telling the platform's auth bootstrap <b>from the
 * minting end</b>.
 *
 * <p>Category {@code authentication}, and the name is exact rather than approximate: every sibling
 * service on the platform carries a {@code TokenValidationBootstrapIT} that proves the
 * <em>validating</em> end of one story — a service fetches this service's JWKS at startup, and a
 * bearer signed by the key it found opens its guarded surface. Those stories all stand on a {@code
 * MockIdp}, because a service under test cannot also be the issuer. <b>This is the same story with
 * the mock taken out.</b> qits-platform-idp validates nothing against an OIDC tenant — it has none,
 * and there is no {@code MockIdp} here for exactly that reason. It MINTS, so what is asserted is
 * the half every sibling has to stand in for: the credential goes in, the bearer comes out, and the
 * public key that validates it is on the document the sibling fetches.
 *
 * <p><b>There is no far side at all, and that is the shape of this service rather than an
 * omission.</b> The idp is a leaf: it dials the postgres its datasource names and nothing else, so
 * there is no upstream to record and no stand-in to start. Every observed edge therefore runs from
 * a caller INTO this one — which is precisely the network diagram a reader of the sibling stories
 * arrives here looking for, with the arrow pointing the other way. It is also why {@link
 * StoryNetwork} installs one feed where every sibling pairs the tap with a mock's recording.
 *
 * <p>Why the PACKAGED artifact and not a {@code @QuarkusTest}: the launched process reads the jar's
 * <b>shipped</b> defaults — the token lifetime, the endpoint base, the roles a service client gets in
 * code — so what the assertions below pin is the deployment's own behaviour, not a fixture that
 * resembles it. Its one service client arrives the way a live installation's did: listed with a
 * secret, and adopted into the database at the first start (qits-163, {@code StoryProfile}). The
 * signing key is generated into the shipped datasource expression on the way
 * up, which {@link IdpPackagedSurfaceIT} already proves survives packaging; here it is the story's
 * subject rather than its precondition.
 *
 * <p>It is also this repo's first <b>userflow</b>: the proof doubles as documentation, emitted
 * under {@code target/userstories/} with a network diagram beside the steps. Both stories are
 * browserless (an {@code Interactions} parameter and no {@code Flow}), so the framework's
 * transitive Playwright never launches anything — which is what lets this run in a step container
 * with no browser in it.
 *
 * <p><b>The diagram is observed, never narrated.</b> {@link Interactions} records notes only;
 * the framework's shipped RestAssured tap ({@link StoryNetwork}) sees what a story sends into this
 * service and labels it with the status this service answered. A story method therefore asserts and notes; it draws nothing. Two
 * consequences shape the code below. The actor is <b>named before the call</b>, because nothing on
 * this surface distinguishes the client from an impostor presenting its id — that distinction is
 * the second story. And the bearer this service <i>answers</i> with is no edge of its own: it is
 * the response half of {@code POST /idp/token}, so what the token contains lives in a note beside
 * the step.
 *
 * <p><b>This IT is named on the command line rather than opted in from the pom</b> ({@code
 * .config/qits/ci-event-userflows.yml}): {@link IdpPackagedSurfaceIT} is the module's other IT and
 * half of it is about the CLIENT — the {@code <base href>}, the deep links, the fallback that must
 * not swallow a machine path — which the userflow run deliberately does not build ({@code
 * -Dquarkus.quinoa=false}, and the webui submodule arrives empty in a step container). A blanket
 * {@code -DskipITs=false} would make that quinoa-less run red on a test that is right, so {@code
 * skipITs} stays true in the root pom and keeps meaning "run everything" for the {@code native}
 * profile that sets it.
 */
@QuarkusIntegrationTest
@TestProfile(StoryProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class TokenIssuanceBootstrapIT {

  static final String CATEGORY = "authentication";
  static final String MINTED_SLUG =
      "a-platform-service-exchanges-its-client-credentials-for-a-bearer";
  static final String REFUSED_SLUG = "the-wrong-secret-mints-nothing-and-the-jwks-stays-open";

  /** How the diagram names this service — the {@code to} of every edge either story observes. */
  static final String SERVICE = StoryTarget.SERVICE;

  /**
   * The client this story is told as: a service client adopted into the database at the first
   * start from its configured id and secret ({@code StoryProfile}). Its roles are code.
   */
  static final String CLIENT = StoryTarget.CI;

  /** What a deployment sets as {@code QITS_IDP_CLIENT_PROD_QITS_CI_SECRET}. */
  static final String SECRET = StoryTarget.CI_SECRET;

  /**
   * The audience the story's caller still asks for: the deployer's intake, the platform's first real
   * service-to-service call. The parameter is accepted and ignored (qits-163).
   */
  static final String AUDIENCE = StoryTarget.DEPLOYMENTS_AUDIENCE;

  /**
   * An audience this client was never entitled to. Asking for it used to be {@code invalid_target};
   * it is ignored now, like every requested audience.
   */
  static final String UNENTITLED_AUDIENCE = StoryTarget.UNENTITLED_AUDIENCE;

  /** Bearers this class was answered. Checked absent from the bundle in {@code @AfterAll}. */
  private static final List<String> NEVER_IN_THE_BUNDLE = new ArrayList<>();

  /**
   * Installs the capture wiring this catalogue shares, once, before either story runs.
   *
   * <p>One line, and {@link StoryNetwork} is where the reason there is only one feed is written
   * down: this service has no upstream to record, so the shipped RestAssured tap is the whole
   * diagram. The method order is pinned beside it, which costs nothing and keeps the emitted
   * reports reproducible run to run.
   */
  @BeforeAll
  static void tapWhatReachesTheIssuer() {
    StoryNetwork.install();
  }

  @UserStory(
      value = "A platform service exchanges its client credentials for a bearer",
      category = "authentication")
  @UserStoryDescription(
      """
      This is the other half of the story every qits service tells. A sibling boots, fetches the
      platform's signing keys from qits-platform-idp and accepts a bearer that carries them —
      and to prove it, stands a mock idp where this service really is. Here there is no mock:
      the issuer itself is running, packaged exactly as it deploys.

      A platform service reaches it the way OIDC says to. It knows one string — the idp's address,
      `http://dev-qits-idp:8080/idp` — derives the discovery document from it, and follows
      the document to the token endpoint and to the JWKS. Then it presents the credential pair
      its deployment gave it.

      What comes back is a bearer that says who the caller is (`sub`), what it may be presented
      to (`aud` — `qits-platform`, the one audience every qits service accepts) and what it is
      (`groups` — the system role every service client has plus `clients/<its own id>`, which
      the idp stamps and nobody can be granted). And the key that signed it is on the
      published JWKS, under the `kid` the token names: the token and the document a consumer
      fetches are the two ends of one key, which is the whole of why offline validation works.
      """)
  @Order(1)
  void aPlatformServiceMintsABearerAndTheKeyThatSignedItIsPublished(Interactions story)
      throws Exception {
    // Everything this story sends is the platform service's, so the actor is named once, up front —
    // before the first call, because the tap sees a request and never a narrative role. The
    // framework resets it to a default at every story start, so nothing leaks in from elsewhere.
    NetworkCapture.actor(CLIENT);

    story.note(
        "qits-platform-idp starts against its own database and generates the signing key into it");
    given().get("/idp/q/health/ready").then().statusCode(200).body("status", equalTo("UP"));

    // The consumer's first move, and the only address it was configured with. Everything below is
    // reached by following this document rather than by knowing a path.
    //
    // TWO STRINGS COME BACK, not one. `issuer` is what the consumer will compare a token's `iss`
    // against — https://idp.qits.<domain>, derived from the domain (qits-730) — and the endpoints
    // hang off the ADDRESS this service answers on, which is not the same text. Deriving the
    // endpoints from the identifier is what once published a jwks_uri on a host nothing resolves.
    given()
        .get("/idp/.well-known/openid-configuration")
        .then()
        .statusCode(200)
        .body("issuer", equalTo(PublishedJwks.ISSUER))
        .body("token_endpoint", equalTo(PublishedJwks.ENDPOINT_BASE + "/token"))
        .body("jwks_uri", equalTo(PublishedJwks.ENDPOINT_BASE + "/jwks"))
        .body("grant_types_supported", hasItem("client_credentials"))
        .body("id_token_signing_alg_values_supported", hasItem("RS256"));
    story
        .note(
            "the consumer knows ONE string — the idp's address — and follows its discovery document to the"
                + " token endpoint and the JWKS; every path below is read off it, never known")
        .as("discovery-read");

    // The exchange itself: client_secret_post, RFC 6749 client_credentials, one named audience.
    String token =
        given()
            .contentType(ContentType.URLENC)
            .body(
                "grant_type=client_credentials&client_id="
                    + CLIENT
                    + "&client_secret="
                    + SECRET
                    + "&audience="
                    + AUDIENCE)
            .post("/idp/token")
            .then()
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .body("access_token", notNullValue())
            // The SHIPPED lifetime — an hour since the commission model landed, and this process
            // reads the jar's own default rather than a test file's.
            .body("expires_in", equalTo(3600))
            // RFC 6749 §5.1: a token response is never cached, anywhere.
            .header("Cache-Control", "no-store")
            .extract()
            .path("access_token");
    // The bearer is generated, so it goes into no note and no label — it is checked ABSENT from the
    // whole bundle in @AfterAll. A token in a diagram would be a live credential on a docs site.
    NEVER_IN_THE_BUNDLE.add(token);
    story
        .note(
            "it presents the credential pair its deployment gave it — RFC 6749"
                + " client_credentials, answered with the SHIPPED hour-long lifetime and no-store."
                + " The audience it names, "
                + AUDIENCE
                + ", is accepted and ignored")
        .as("bearer-minted");

    // End (a), the token's: verified the way a consumer would — against whatever /idp/jwks
    // publishes, over HTTP, resolving the key by the token's own kid. Verifying against a key this
    // JVM could reach in-process would pass even if the published document were empty.
    JwtClaims claims = PublishedJwks.verify(token, StoryTarget.PLATFORM_AUDIENCE);
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer(), "iss is the issuer derived from the domain");
    assertEquals(CLIENT, claims.getSubject(), "sub is the client that authenticated");
    assertEquals(
        List.of(StoryTarget.PLATFORM_AUDIENCE),
        PublishedJwks.audienceOf(claims),
        "aud is the one audience, whatever was asked for (C7 of epic qits-540, qits-163)");
    // The claim pinned whole rather than searched: `groups` is the token's shape, and a change to
    // it is a change every consumer reads. The system role is every service client's, in code; the
    // second is the self-role the idp mints from the id that authenticated and grants nowhere,
    // which is what lets a resource service write @RolesAllowed("clients/prod-qits-ci") and know
    // exactly one caller can reach the door.
    assertEquals(
        List.of("qits:system", "clients/" + CLIENT),
        claims.getStringListClaimValue("groups"),
        "the fixed role, then the self-role this service stamps");
    // The ANSWER is not an edge of its own. Direction on a diagram is who initiated, and nobody
    // initiated the response to a request already drawn — the `-> 200` on the POST above is where
    // it shows. What the bearer CONTAINS is a claim about a body, which no tap can see; it belongs
    // here, beside the assertions that pinned it.
    story
        .note(
            "the bearer says who the caller is (sub="
                + CLIENT
                + "), what it may be presented to (aud=qits-platform, the one audience every qits"
                + " service accepts) and what it is (groups = the system role every service client"
                + " has plus clients/"
                + CLIENT
                + ", the self-role this service stamps and nobody can be granted)")
        .as("bearer-answered");

    // End (b), the document's: the key a sibling fetches at startup is the key that signed this
    // token — spelled out with plain JCA rather than left to the resolver above, because "the
    // published key validates the signature" is the sentence the whole platform's offline
    // validation rests on, and it is worth reading as an assertion rather than as a side effect.
    String kid = PublishedJwks.kidOf(token);
    assertNotNull(kid, "every token carries a kid, or rotation is a flag day");
    thePublishedKeyValidatesTheSignature(token, kid);
    // The JWKS was read twice — once by the consumer-shaped verification above, once by the plain
    // JCA check — and both are the same edge: same caller, same route, same 200. The count is not
    // the point and the diagram is right to draw one arrow; what matters is in the note.
    story
        .note(
            "the key that signed the token is on the published JWKS under the kid the token names —"
                + " the two ends of one key, which is the whole of why offline validation works")
        .as("signing-key-published");
  }

  @UserStory(
      value = "The wrong secret mints nothing, and the JWKS stays open",
      category = "authentication")
  @UserStoryDescription(
      """
      The flip side of being the platform's issuer: what must be refused, and the one thing that
      must never be.

      A wrong secret is `invalid_client`, and the refusal is deliberately coarse — which of
      "unknown client", "no secret configured" and "wrong secret" happened is not something the
      caller is told, because the caller is not always the one who should learn it. An audience
      the client was never entitled to is NOT a refusal any more: every token carries the one
      audience, `qits-platform`, and a requested one is ignored. What bounds a credential is its
      roles, never where it may be presented.

      And the JWKS stays served to anyone who asks, with no credential of any kind. It has to:
      every service on the platform fetches it at boot, BEFORE it holds a token, and a JWKS
      behind a bearer would be a service unable to validate the bearer that would let it fetch
      the JWKS. The discovery document is open for the same reason. Nothing secret is on either
      — the published key is the public half and carries no private member, and never gains one.
      """)
  @Order(2)
  void aWrongSecretIsRefusedAndAnUnentitledAudienceIsIgnored(Interactions story)
      throws Exception {
    // (a) authentication fails. The client id is real and on the shipped list; the secret is not.
    // The request therefore CARRIES client_id=prod-qits-ci and is not from that client at all,
    // which is exactly why the initiator is named by the story and never derived from the wire.
    NetworkCapture.actor(StoryTarget.IMPOSTOR);
    given()
        .contentType(ContentType.URLENC)
        .body(
            "grant_type=client_credentials&client_id="
                + CLIENT
                + "&client_secret=not-the-secret&audience="
                + AUDIENCE)
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"))
        .body("access_token", nullValue());
    story
        .note(
            "a wrong secret is invalid_client, and the refusal is deliberately COARSE — which of"
                + " \"unknown client\", \"no secret configured\" and \"wrong secret\" happened is not"
                + " something the caller is always the right one to learn")
        .as("wrong-secret-refused");

    // (b) the real client, asking for an audience it was never entitled to. That used to be 400
    // invalid_target; it is ignored now (qits-163), and the token carries the one audience.
    //
    // The diagram says so: same route as the impostor's, a different initiator and a different
    // status.
    NetworkCapture.actor(CLIENT);
    String ignored =
        given()
            .contentType(ContentType.URLENC)
            .body(
                "grant_type=client_credentials&client_id="
                    + CLIENT
                    + "&client_secret="
                    + SECRET
                    + "&audience="
                    + UNENTITLED_AUDIENCE)
            .post("/idp/token")
            .then()
            .statusCode(200)
            .extract()
            .path("access_token");
    NEVER_IN_THE_BUNDLE.add(ignored);
    assertEquals(
        List.of(StoryTarget.PLATFORM_AUDIENCE),
        PublishedJwks.audienceOf(PublishedJwks.decodeUnverified(ignored)),
        "a requested audience is ignored, never refused");
    story
        .note(
            "an audience the client was never entitled to is not refused any more: the parameter"
                + " is ignored and the token carries the one audience, qits-platform. What bounds a"
                + " credential is its roles, not where it may be presented")
        .as("unentitled-audience-ignored");

    // (c) the two bootstrap doors, with no credential presented at all. This service configures no
    // HTTP path permissions — its guarded surfaces check the caller in code — so today this passes
    // by construction; it is asserted at the DEPLOYED posture so that a future blanket policy over
    // /idp/* fails here rather than in every consumer's startup at once.
    NetworkCapture.actor(StoryTarget.UNCREDENTIALED);
    given()
        .get("/idp/jwks")
        .then()
        .statusCode(200)
        .body("keys[0].kty", equalTo("RSA"))
        .body("keys[0].use", equalTo("sig"))
        .body("keys[0].alg", equalTo("RS256"))
        // The private half has no JWK member here, and must never gain one.
        .body("keys[0].d", nullValue())
        .body("keys[0].p", nullValue())
        .body("keys[0].q", nullValue());
    given().get("/idp/.well-known/openid-configuration").then().statusCode(200);
    story
        .note(
            "both bootstrap doors stay open to a caller holding NOTHING: every service fetches the"
                + " JWKS at boot, before it holds a token, and a JWKS behind a bearer would be a"
                + " service unable to validate the bearer that would let it fetch the JWKS. Nothing"
                + " secret is on either — the published key is the public half and never gains a"
                + " private member")
        .as("bootstrap-doors-open");
  }

  /**
   * The published key, rebuilt from its JWK members and used to verify the token's own signature —
   * plain JCA, no JOSE library in between.
   *
   * <p>{@code n} and {@code e} are base64url of the UNSIGNED big-endian value, so they are read
   * back through {@link BigInteger#BigInteger(int, byte[])} with a positive signum: the
   * two-argument constructor keeps a modulus whose top bit is set from reading as negative,
   * which is the same rounding the service applies when it writes them.
   *
   * <p>The signing input of a JWS is the compact serialization up to (and excluding) the last dot,
   * ASCII bytes as they appear on the wire.
   */
  private static void thePublishedKeyValidatesTheSignature(String jwt, String kid)
      throws Exception {
    JsonPath jwks = JsonPath.from(PublishedJwks.document());
    Map<String, Object> jwk = jwks.getMap("keys.find { it.kid == '" + kid + "' }");
    assertNotNull(jwk, "the published JWKS carries no key with kid " + kid);
    assertNull(jwk.get("d"), "the published JWKS must never carry the private half");

    RSAPublicKey published =
        (RSAPublicKey)
            KeyFactory.getInstance("RSA")
                .generatePublic(
                    new RSAPublicKeySpec(
                        unsignedBigEndian((String) jwk.get("n")),
                        unsignedBigEndian((String) jwk.get("e"))));

    int lastDot = jwt.lastIndexOf('.');
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initVerify(published);
    rsa.update(jwt.substring(0, lastDot).getBytes(StandardCharsets.US_ASCII));
    assertTrue(
        rsa.verify(Base64.getUrlDecoder().decode(jwt.substring(lastDot + 1))),
        "the key published at /idp/jwks must be the key that signed the token");
  }

  private static BigInteger unsignedBigEndian(String base64Url) {
    return new BigInteger(1, Base64.getUrlDecoder().decode(base64Url));
  }

  @AfterAll
  static void bothStoryReportsAreComplete() {
    // The extension emits each report in its afterEach, so both are on disk before @AfterAll runs.
    // assertComplete also proves the network section: the sidecar's edges are canonical, the
    // networkHash recomputes from them, and every mermaid line is in the markdown.
    ReportAssertions.assertComplete(CATEGORY, MINTED_SLUG, UserflowReport.PASSED);

    // --- the minting story's whole graph -------------------------------------------------------
    // Three edges and all of them incoming, because there is no upstream to draw. The JWKS was read
    // twice and is one edge: same caller, same route, same status.
    ReportAssertions.assertEdge(
        CATEGORY,
        MINTED_SLUG,
        NetworkEdge.HTTP,
        CLIENT,
        SERVICE,
        "GET /idp/.well-known/openid-configuration -> 200");
    ReportAssertions.assertEdge(
        CATEGORY, MINTED_SLUG, NetworkEdge.HTTP, CLIENT, SERVICE, "POST /idp/token -> 200");
    ReportAssertions.assertEdge(
        CATEGORY, MINTED_SLUG, NetworkEdge.HTTP, CLIENT, SERVICE, "GET /idp/jwks -> 200");
    // EXACTLY those three. A fourth would mean a probe the tap's skip missed, or this process
    // dialling something — and "the idp is a leaf" is a claim no presence check can make.
    ReportAssertions.assertEdgeCount(CATEGORY, MINTED_SLUG, 3);

    ReportAssertions.assertStepId(CATEGORY, MINTED_SLUG, "discovery-read");
    ReportAssertions.assertStepId(CATEGORY, MINTED_SLUG, "bearer-minted");
    ReportAssertions.assertStepId(CATEGORY, MINTED_SLUG, "bearer-answered");
    ReportAssertions.assertStepId(CATEGORY, MINTED_SLUG, "signing-key-published");

    ReportAssertions.assertComplete(CATEGORY, REFUSED_SLUG, UserflowReport.PASSED);

    // --- the refusal story's whole graph -------------------------------------------------------
    // The two token requests are the same route and differ in initiator and status — which is the
    // story, and is why neither distinction was ever allowed into a label.
    ReportAssertions.assertEdge(
        CATEGORY,
        REFUSED_SLUG,
        NetworkEdge.HTTP,
        StoryTarget.IMPOSTOR,
        SERVICE,
        "POST /idp/token -> 401");
    ReportAssertions.assertEdge(
        CATEGORY, REFUSED_SLUG, NetworkEdge.HTTP, CLIENT, SERVICE, "POST /idp/token -> 200");
    ReportAssertions.assertEdge(
        CATEGORY,
        REFUSED_SLUG,
        NetworkEdge.HTTP,
        StoryTarget.UNCREDENTIALED,
        SERVICE,
        "GET /idp/jwks -> 200");
    ReportAssertions.assertEdge(
        CATEGORY,
        REFUSED_SLUG,
        NetworkEdge.HTTP,
        StoryTarget.UNCREDENTIALED,
        SERVICE,
        "GET /idp/.well-known/openid-configuration -> 200");
    ReportAssertions.assertEdgeCount(CATEGORY, REFUSED_SLUG, 4);

    ReportAssertions.assertStepId(CATEGORY, REFUSED_SLUG, "wrong-secret-refused");
    ReportAssertions.assertStepId(CATEGORY, REFUSED_SLUG, "unentitled-audience-ignored");
    ReportAssertions.assertStepId(CATEGORY, REFUSED_SLUG, "bootstrap-doors-open");

    // --- what NEITHER story has ------------------------------------------------------------------
    // THE LEAF'S CLAIM. Both stories are told entirely against a service client, and a service
    // client is a read of a map loaded at start — so the platform's whole daily-bread path (discovery, mint,
    // JWKS, and every refusal on it) is answered without this process initiating anything at all,
    // not even toward its own store. The commissioning stories are where a row is really touched,
    // and they DECLARE that edge rather than leaving the picture half-drawn.
    ReportAssertions.assertNoEdgesFrom(CATEGORY, MINTED_SLUG, SERVICE);
    ReportAssertions.assertNoEdgesFrom(CATEGORY, REFUSED_SLUG, SERVICE);

    // And nothing that was presented or answered is in either bundle. A secret in a label would be
    // a deployment credential on a docs site; a bearer would be a live one.
    for (String slug : List.of(MINTED_SLUG, REFUSED_SLUG)) {
      ReportAssertions.assertNotLeaked(CATEGORY, slug, SECRET);
      for (String value : NEVER_IN_THE_BUNDLE) {
        ReportAssertions.assertNotLeaked(CATEGORY, slug, value);
      }
    }
  }
}
