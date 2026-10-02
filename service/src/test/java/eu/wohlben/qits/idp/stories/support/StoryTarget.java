package eu.wohlben.qits.idp.stories.support;

import static io.restassured.RestAssured.given;

import eu.wohlben.qits.userflows.Labels;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * The one launched qits-platform-idp, as every story in this catalogue addresses it and as every
 * diagram names it.
 *
 * <h2>This service is a LEAF, and that is the whole shape of the catalogue</h2>
 *
 * <p>Every sibling on the platform carries a {@code TokenValidationBootstrapIT} that stands a
 * {@code MockIdp} where this service really is. Here there is nothing to stand in for: the idp
 * validates nothing against an OIDC tenant — it <i>is</i> the tenant — it holds no HTTP client on
 * its classpath, and the only host it dials is the postgres its own datasource names. So there is
 * <b>no far-side recording anywhere in this catalogue</b>: {@link StoryNetwork} installs the
 * shipped incoming tap and nothing else, and every observed edge runs from a caller INTO this
 * service.
 *
 * <p>Which makes {@code assertNoEdgesFrom(SERVICE)} the claim these stories are for — and it is
 * worth being exact about what it does and does not prove. It proves the story's <b>diagram</b>
 * carries no outbound arrow. It cannot prove a socket was never opened, because there is no tap
 * that could have seen one; what makes the claim true is structural (no rest-client, no oidc-client,
 * no event bus on this module's classpath) plus the one dial-out that does exist — the OTLP
 * exporter — being switched off by {@link StoryProfile}. The two commissioning stories, which
 * really do write and read rows, say the other half out loud: they <b>declare</b> the jdbc edge, so
 * the one dependency this service has is drawn, dashed, exactly once per story that incurs it.
 *
 * <h2>One process, one port, three surfaces</h2>
 *
 * <p>Everything is under {@code /idp}, because {@code quarkus.rest.path} is the segment itself
 * rather than {@code /idp/api} — OIDC fixes the discovery path, so the protocol routes sit directly
 * beside the client's:
 *
 * <ul>
 *   <li><b>the protocol</b> — {@link #DISCOVERY}, {@link #JWKS}, {@link #TOKEN}. Unauthenticated by
 *       design for the first two: every service fetches the JWKS at boot, before it holds a token.
 *   <li><b>the machine admin surface</b> — {@link #CLIENTS}, HTTP Basic against the caller's own
 *       idp client pair, because a caller here already holds one and a second credential would be a
 *       second thing to distribute.
 *   <li><b>the probes</b> — {@link #READY}, at {@code /idp/q}, which the shipped tap skips.
 * </ul>
 *
 * <h2>The shipped tap's default skip was checked here</h2>
 *
 * <p>{@link eu.wohlben.qits.userflows.NetworkTaps#restAssured(String)} skips any path carrying a
 * {@code /q/} <b>segment</b> rather than a leading one, which is exactly this service's case:
 * {@code quarkus.http.non-application-root-path=/idp/q}, nested under the application root. No
 * route of this service can contain a {@code /q/} segment otherwise — the protocol paths are fixed
 * literals and the only free segment anywhere is a commissioned client id, which always begins
 * {@code dyn-}. So no story class overrides the predicate.
 *
 * <h2>Labels: what survives, what is rewritten, and what must never appear</h2>
 *
 * <p>{@link Labels} rewrites a whole path segment it can tell was generated — a UUID, a long hex
 * run, a bare number. A <b>commissioned client id</b> is none of those: {@code
 * dyn-<kind>-<context slug>-<22 base64url characters>} is a readable identifier on purpose, so an
 * operator can tell a stuck ci run from a stuck workspace in a listing. The default scrubber
 * therefore leaves it alone and it would move a story's {@code networkHash} on every run —
 * so {@link #normalize} rewrites it to {@code {id}}, composed over the default through {@link
 * eu.wohlben.qits.userflows.NetworkCapture#labelNormalizer}. {@link #served} runs an assertion's
 * expected label through the very same two functions, so an assertion and an observation cannot
 * disagree about what a generated segment became.
 *
 * <p><b>A query string never reaches an incoming label</b> — the shipped tap labels {@code METHOD
 * <scrubbed path> -> <status>} and drops the query entirely. Nothing on this service's surface is
 * addressed by query, so nothing is lost. What IS lost, and is worth saying because it is this
 * service's own surface: a form body never reaches a label either, so every {@code grant_type} on
 * {@code POST /idp/token} draws the same arrow. Which grant was asked for, and which of the six
 * ways to be refused happened, is carried by the <b>actor</b> and the <b>status</b> — which is why
 * every story here names its initiators before it calls.
 *
 * <p><b>And no credential ever reaches one.</b> Neither a client secret (form body or Basic header)
 * nor a minted bearer is on a path, so nothing that must stay out of the bundle can arrive in a
 * label by accident. Every story asserts that rather than assuming it — {@code assertNotLeaked}
 * over each secret it presented and each token it was answered.
 */
public final class StoryTarget {

  /** How every diagram in this catalogue names the service under test. */
  public static final String SERVICE = "qits-platform-idp";

  // --- the clients this launched process knows ---------------------------------------------------
  //
  // THE THREE SHIPPED IDS ARE THE JAR'S OWN. The launched artifact reads `qits.idp.clients` from the
  // idp jar's META-INF/microprofile-config.properties, so their audiences and roles below are the
  // deployment's configuration and not a fixture that resembles it. Only the secrets are supplied,
  // because a static client ships WITHOUT one and is unusable until a deployment gives it one —
  // which is itself a story arm here (see ARTIFACTS).

  /** The everyday service client. Mints, and is the one this catalogue tells the happy path as. */
  public static final String CI = "prod-qits-ci";

  /** What a deployment sets as {@code QITS_IDP_CLIENT_PROD_QITS_CI_SECRET}. */
  public static final String CI_SECRET = "ci-userflow-pair-2f9c";

  /** The commissioning owner: the service that provisions workspaces and their credentials. */
  public static final String WORKSPACES = "prod-qits-workspaces";

  /** What a deployment sets as {@code QITS_IDP_CLIENT_PROD_QITS_WORKSPACES_SECRET}. */
  public static final String WORKSPACES_SECRET = "workspaces-userflow-pair-7b41";

  /**
   * The third shipped client, deliberately left <b>without a secret</b> in this launched process —
   * which is the shipped state of every static client. It is the {@code
   * FrontDoorRefusalsIT} arm that pins the safe direction against the real default rather than
   * against a fixture: a client with a blank secret is unusable, never open.
   */
  public static final String ARTIFACTS = "qits-platform-artifacts";

  /**
   * A FOURTH client, which the shipped list does not carry and which this profile adds — the one
   * misconfiguration the reserved {@code clients/} namespace exists to refuse. Its roles line names
   * {@link #CI}'s self-role, so it is a deployment trying to hand one client another's identity.
   *
   * <p>Adding it costs restating {@code qits.idp.clients}, because the list is what says an id
   * exists; the three shipped ids are restated verbatim beside it. See {@link StoryProfile}.
   */
  public static final String ROLE_THIEF = "uf-role-thief";

  public static final String ROLE_THIEF_SECRET = "role-thief-userflow-pair-4d8e";

  /** The roles line that makes {@link #ROLE_THIEF} unusable — another client's minted self-role. */
  public static final String ROLE_THIEF_ROLES = "qits:system,clients/" + CI;

  // --- audiences ---------------------------------------------------------------------------------

  /** The deployer's intake: an audience with no client, because it receives and mints nothing. */
  public static final String DEPLOYMENTS_AUDIENCE = "qits-deployments";

  /** The platform's artifact store, as an audience. Also a client id — the two namespaces overlap. */
  public static final String ARTIFACTS_AUDIENCE = "qits-platform-artifacts";

  /** On nobody's shipped list. Asking for it is the {@code invalid_target} refusal. */
  public static final String UNENTITLED_AUDIENCE = "prod-qits-observability";

  // --- the coarse machine role every shipped client carries --------------------------------------

  public static final String SYSTEM_ROLE = "qits:system";

  /** The reserved namespace: minted from the id that authenticated, granted nowhere. */
  public static String selfRoleOf(String clientId) {
    return "clients/" + clientId;
  }

  // --- the wire paths, spelled in full -----------------------------------------------------------

  /** {@code quarkus.rest.path}, and the prefix the edge routes here verbatim. */
  public static final String BASE = "/idp";

  /** The one address a consumer is configured with derives this by OIDC's own rule. */
  public static final String DISCOVERY = BASE + "/.well-known/openid-configuration";

  /** The published signing keys. Open, and it has to be — see {@code BootstrapDocumentsIT}. */
  public static final String JWKS = BASE + "/jwks";

  /** RFC 6749 {@code client_credentials}, {@code application/x-www-form-urlencoded}. */
  public static final String TOKEN = BASE + "/token";

  /** The commission API. Under {@code /api}, which is why the Quinoa ignore list is one entry. */
  public static final String CLIENTS = BASE + "/api/clients";

  /** One commissioned credential, addressed by its id. The tap's label scrubs the id to {@code {id}}. */
  public static String client(String clientId) {
    return CLIENTS + "/" + clientId;
  }

  /**
   * The same route as {@link #client(String)} <b>after</b> normalization — what an assertion spells,
   * because the id in the real path is run-local and never reaches a label.
   */
  public static final String ANY_CLIENT = CLIENTS + "/{id}";

  /** Readiness, which the shipped tap skips — see the class javadoc. */
  public static final String READY = BASE + "/q/health/ready";

  // --- the issuer, and what it derives ----------------------------------------------------------

  /**
   * The derived issuer: {@code https://idp.qits.<domain>}, and no {@code QITS_DOMAIN} is stated for
   * the launched process, so the domain is {@code localhost}. Nothing configures it (qits-730).
   *
   * <p>It is an IDENTIFIER: the {@code iss} of every token and the {@code issuer} member of the
   * discovery document, compared for equality and dialled by nothing. {@link #ENDPOINT_BASE} is
   * the address, and the two are deliberately different strings on this platform.
   */
  public static final String ISSUER = "https://idp.qits.localhost";

  /**
   * The shipped {@code qits.idp.endpoint-base}: what the discovery document's endpoints hang off,
   * and the address a consumer actually dials.
   *
   * <p>{@code QITS_ENVIRONMENT} is unset under the suite, so the shipped default resolves its own
   * {@code dev} arm — which is the point of asserting it here rather than a fixture: the launched
   * process reads the jar's default, so a change to that default fails this suite rather than a
   * deployment.
   */
  public static final String ENDPOINT_BASE = "http://dev-qits-platform-idp:8080/idp";

  /** The token's shipped lifetime, in seconds — an hour since the commission model landed. */
  public static final int TOKEN_TTL_SECONDS = 3600;

  // --- the initiators, named because the wire cannot tell them apart -----------------------------

  /**
   * A caller presenting {@link #CI}'s id with a secret that is not {@link #CI}'s. On the wire this
   * request is byte-shaped exactly like the real client's, which is the entire reason an actor is
   * named by the story and never derived from what a tap saw.
   */
  public static final String IMPOSTOR = "an impostor";

  /** A service at boot, holding no token at all — which is what makes the two doors have to be open. */
  public static final String UNCREDENTIALED = "any service, holding nothing";

  /** The holder of a commissioned credential: an agent container a workspace provisioned. */
  public static final String CONTAINER = "a workspace container";

  /**
   * Whoever the bearer will be presented to. It fetches the JWKS to validate offline — the sibling
   * half of every story here, and the reason a story's JWKS read is not the minter's.
   */
  public static final String VALIDATOR = "a resource service validating the bearer";

  // --- what a caller carries ----------------------------------------------------------------------

  private StoryTarget() {}

  /** {@code client_secret_basic}: the machine surfaces' only authentication, and the token's other. */
  public static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }

  /** A machine-admin call: JSON out, a Basic pair in, nothing else. */
  public static RequestSpecification machine(String clientId, String secret) {
    return given().header("Authorization", basic(clientId, secret));
  }

  /** A token request as {@code client_secret_post} sends one — the form, with the pair inside it. */
  public static RequestSpecification form() {
    return given().contentType(ContentType.URLENC);
  }

  /** {@code grant_type=client_credentials} with the pair in the form and one audience named. */
  public static String clientCredentials(String clientId, String secret, String audience) {
    return "grant_type=client_credentials&client_id="
        + clientId
        + "&client_secret="
        + secret
        + "&audience="
        + audience;
  }

  // --- what an assertion has to spell -------------------------------------------------------------

  /**
   * A commissioned client id anywhere in a label. {@code dyn-} is minted by {@code DynamicClients}
   * and is the one prefix a static id can never carry, so the pattern cannot swallow an authored
   * segment; the run-local tail is 128 random bits in base64url, whose alphabet is what the
   * character class spells.
   */
  private static final Pattern COMMISSIONED_ID = Pattern.compile("dyn-[A-Za-z0-9_-]+");

  /**
   * The normalizer this catalogue composes over {@link Labels#scrub} — installed once, JVM-wide, by
   * {@link StoryNetwork#install()}.
   */
  public static String normalize(String label) {
    return COMMISSIONED_ID.matcher(label).replaceAll("{id}");
  }

  /**
   * The label the shipped RestAssured tap gives an incoming request: {@code METHOD <path> ->
   * <status>}, run through the default scrubber and then through {@link #normalize}, in that order
   * — the same two functions, in the same order, that {@code NetworkCapture} applies on the way in.
   */
  public static String served(String method, String path, int status) {
    return normalize(Labels.scrub(method + " " + path + " -> " + status));
  }

  public static String read(String path, int status) {
    return served("GET", path, status);
  }

  public static String posted(String path, int status) {
    return served("POST", path, status);
  }

  public static String deleted(String path, int status) {
    return served("DELETE", path, status);
  }
}
