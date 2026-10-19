package eu.wohlben.qits.idp.contracts;

import eu.wohlben.qits.idp.control.ClientSecret;
import eu.wohlben.qits.idp.control.CommissionedTokens;
import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.control.PublicClients;
import eu.wohlben.qits.idp.control.PublicClients.PublicClient;
import eu.wohlben.qits.idp.control.RegisterTokens;
import eu.wohlben.qits.idp.control.ServiceClients;
import eu.wohlben.qits.idp.control.ServiceClientsAccess;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.SigningKeys;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.control.UnclaimedServiceClientCollector;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.control.WorkstationCredentials;
import eu.wohlben.qits.idp.entity.IdpAuthorizationCode;
import eu.wohlben.qits.idp.entity.IdpDynamicClient;
import eu.wohlben.qits.idp.entity.IdpSigningKey;
import eu.wohlben.qits.idp.entity.IdpSigningKeyStatus;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import eu.wohlben.qits.idp.entity.IdpWorkstationRefreshToken;
import eu.wohlben.qits.idp.persistence.IdpAuthorizationCodeRepository;
import eu.wohlben.qits.idp.persistence.IdpDynamicClientRepository;
import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import eu.wohlben.qits.idp.persistence.IdpSigningKeyRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import eu.wohlben.qits.idp.persistence.IdpWorkstationRefreshTokenRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;

/**
 * <b>The provider states qits-idp answers for</b>: a state name → a setup that seeds what the state
 * names and returns its parameters. The same shape as qits-githost-service's and
 * qits-projects-service's.
 *
 * <p>Two callers. {@link GoldenMasterRecordingTest} runs a state before recording each operation
 * that names it, and {@code ConsumerPactVerificationTest}'s {@code @State} methods delegate here.
 *
 * <p><b>The caller.</b> Every door a service calls here authenticates with HTTP Basic of a service
 * client holding {@code qits:system}. Each state names that caller in its {@code authorization}
 * param: {@value #CALLER}, which the suite adopts at start from {@code
 * src/test/resources/application.properties} with a fixed secret, so the header is the same on
 * every run. A consumer pact sends its own credential; it declares the header with a
 * provider-state generator on {@code ${authorization}}, so verification sends this one.
 *
 * <p><b>Every state but one assumes nothing about the database.</b> The suite shares one store, so
 * every row a state makes has a fresh id, and the recorder keeps only the list entries a state
 * {@linkplain Setup#created created}. The exception is {@value #A_SERVICE_CLIENT_NOTHING_CLAIMS}:
 * the collection it sets up judges every service client there is, so it deletes the ones the suite
 * did not adopt at start before it seeds its own.
 */
@ApplicationScoped
public class ProviderStates {

  public static final String A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE =
      "a service client with the system role";
  public static final String A_SERVICE_CLIENT_WHOSE_STATED_GIT_REFS_ARE_REFUSED =
      "a service client whose stated Git refs are refused";
  public static final String A_PUBLISHED_SIGNING_KEY = "a published signing key";
  public static final String A_COMMISSIONED_CLIENT = "a commissioned client";
  public static final String NO_COMMISSIONED_CLIENT_WITH_THE_GIVEN_ID =
      "no commissioned client with the given id";
  public static final String A_COMMISSIONED_TOKEN = "a commissioned token";
  public static final String A_SIGNED_IN_PERSON = "a signed-in person";
  public static final String A_DATABASE_SERVICE_CLIENT = "a database service client";
  public static final String NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID =
      "no service client with the given id";
  public static final String A_SERVICE_CLIENT_NOTHING_CLAIMS = "a service client nothing claims";
  public static final String A_SERVICE_CLIENT_NOTHING_CLAIMS_CALLING_WITH_ITS_BEARER =
      "a service client nothing claims, calling with its bearer";
  public static final String A_COMMISSIONED_CLIENT_HANDING_ITSELF_BACK =
      "a commissioned client handing itself back";
  public static final String AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI =
      "an authorization code issued to the CLI";
  public static final String AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI_FOR_THE_CONNECT_PAGE =
      "an authorization code issued to the CLI for the connect page";
  public static final String AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT =
      "an authorization code issued to the git client";
  public static final String A_SESSION_TO_REFRESH = "a session to refresh";
  public static final String A_GIT_SESSION_TO_REFRESH = "a git session to refresh";
  public static final String A_SERVICE_CLIENT_CALLING_ITS_PEERS =
      "a service client calling its peers";
  public static final String A_SERVICE_CLIENT_PRESENTING_A_WRONG_SECRET =
      "a service client presenting a wrong secret";
  public static final String NO_COMMISSIONED_TOKEN_WITH_THE_GIVEN_ID =
      "no commissioned token with the given id";
  public static final String NO_SESSION_WITH_THE_GIVEN_TOKEN = "no session with the given token";
  public static final String NO_SESSION_WITH_THE_GIVEN_REFRESH_TOKEN =
      "no session with the given refresh token";
  public static final String AN_ADMIN_SIGNED_IN_TO_THE_CLI = "an admin signed in to the CLI";
  public static final String NO_USER_WITH_THE_GIVEN_NAME = "no user with the given name";
  public static final String AN_UNSPENT_REGISTER_TOKEN = "an unspent register token";
  public static final String NO_REGISTER_TOKEN_WITH_THE_GIVEN_VALUE =
      "no register token with the given value";

  // --- one state per commissioner's body (qits-1149 round 3) -----------------------------------
  // A consumer binds a commission by replaying the recorded body exactly, so each caller whose body
  // differs gets its own recording. The values that vary between calls are the state's params.

  public static final String A_CI_RUNNER_BEING_COMMISSIONED = "a ci runner being commissioned";
  public static final String A_CI_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED =
      "a ci runner's registration token being commissioned";
  public static final String A_CI_RUNS_TOKEN_BEING_COMMISSIONED =
      "a ci run's token being commissioned";
  public static final String A_CI_RUNS_TOKEN_BEING_COMMISSIONED_WITHOUT_A_GIT_SCOPE =
      "a ci run's token being commissioned without a Git scope";
  public static final String A_WORKSPACES_CLIENT_BEING_COMMISSIONED =
      "a workspace's client being commissioned";
  public static final String A_WORKSPACES_CLIENT_WHOSE_STATED_GIT_REFS_ARE_REFUSED =
      "a workspace's client whose stated Git refs are refused";
  public static final String A_WORKSPACES_CLIENT_BEING_COMMISSIONED_TO_PUSH_NOTHING =
      "a workspace's client being commissioned to push nothing";
  public static final String A_WORKSPACES_TOKEN_BEING_COMMISSIONED =
      "a workspace's token being commissioned";
  public static final String A_WORKSPACES_TOKEN_WHOSE_STATED_GIT_REFS_ARE_REFUSED =
      "a workspace's token whose stated Git refs are refused";
  public static final String A_WORKSPACES_TOKEN_BEING_COMMISSIONED_TO_PUSH_NOTHING =
      "a workspace's token being commissioned to push nothing";
  public static final String AN_AGENTS_TOKEN_BEING_COMMISSIONED =
      "an agent's token being commissioned";
  public static final String AN_AGENTS_TOKEN_WHOSE_STATED_GIT_REFS_ARE_REFUSED =
      "an agent's token whose stated Git refs are refused";
  public static final String AN_AGENTS_TOKEN_BEING_COMMISSIONED_TO_PUSH_NOTHING =
      "an agent's token being commissioned to push nothing";
  public static final String A_WORKSPACE_RUNNER_BEING_COMMISSIONED =
      "a workspace runner being commissioned";
  public static final String A_WORKSPACE_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED =
      "a workspace runner's registration token being commissioned";
  public static final String A_DESK_RUNNER_BEING_COMMISSIONED = "a desk runner being commissioned";
  public static final String A_DESK_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED =
      "a desk runner's registration token being commissioned";
  public static final String A_REFINEMENTS_CLIENT_BEING_COMMISSIONED =
      "a refinement's client being commissioned";
  public static final String A_FRONT_DESKS_TOKEN_BEING_COMMISSIONED =
      "a front desk's token being commissioned";

  /** The calling service client: adopted at start, holds {@code qits:system}. */
  static final String CALLER = "test-broad";

  private static final String CALLER_SECRET = "test-broad-secret";

  /** The context every commission here names. */
  static final String CONTEXT_KIND = "contract";

  static final String CONTEXT_ID = "run-1";

  /**
   * {@value #A_COMMISSIONED_CLIENT_HANDING_ITSELF_BACK}'s pair: the shape of a commissioned id and
   * secret (22 random characters, 43 for the secret), spelled as {@value #A_COMMISSIONED_CLIENT}'s
   * frozen pair reads.
   */
  static final String HANDBACK_CLIENT_ID =
      DynamicClients.ID_PREFIX + CONTEXT_KIND + "-" + CONTEXT_ID + "-0000000000000000000001";

  static final String HANDBACK_SECRET = "0000000000000000000000000000000000000000002";

  /**
   * The PKCE verifier of every authorization code a state makes: fixed, so a consumer sends the
   * same one. The code itself is random and comes back as the state's {@code code} param.
   */
  static final String CODE_VERIFIER = "contract-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";

  /** {@link #CODE_VERIFIER}'s S256 challenge. */
  static final String CODE_CHALLENGE = s256(CODE_VERIFIER);

  /** The loopback callback every authorization code here is bound to. */
  static final String REDIRECT_URI = "http://127.0.0.1:53682/callback";

  /**
   * The CLI's connect page, {@code <idp>/connect/cli}, as {@code qits login} names it: the code
   * page this idp serves under the endpoint base its discovery document advertises (with nothing
   * configured, {@code http://dev-qits-idp:8080/idp}). Written out rather than read off {@code
   * Issuer}, so the recorded param is the same whatever environment the suite runs in; a consumer
   * names it with a provider-state generator, because its own idp address is a mock server's.
   */
  static final String CLI_PAGE_URI = "http://dev-qits-idp:8080/idp/connect/cli";

  /**
   * A Git ref the idp refuses in any list: outside {@code refs/heads/} ({@code GitRefs}). A
   * commission that states it answers 400 {@code invalid_request}, whatever else it says.
   */
  static final String REFUSED_GIT_REF = "refs/tags/contract";

  /** The Git ref a commissioner's stated list names: a branch, as every list entry must be. */
  static final String GIT_REF = "refs/heads/ticket/contract";

  /** A workspace's row id, as qits-workspaces-service names its commission's context. */
  static final String WORKSPACE_ID = "7";

  /** A refinement's row id, as qits-projects-service names its commission's context. */
  static final String REFINEMENT_ID = "41";

  /** The audience a refresh names; the idp accepts and ignores it (qits-163). */
  static final String AUDIENCE = "qits-platform";

  /** The service clients the suite adopts at start (src/test/resources/application.properties). */
  private static final Set<String> ADOPTED =
      Set.of("prod-qits-workspaces", "test-broad", "test-narrow", "test-audienceless", "test-role-thief");

  /** What every commissioned token value begins with ({@code TokenValue.PREFIX}). */
  private static final String TOKEN_PREFIX = "qits_tok_";

  /**
   * What a state hands back.
   *
   * @param params its parameters, keys sorted
   * @param uniqueTokens random values the state put into names, frozen by {@link Freezer}
   * @param created the values that mark an entry this state created, for the list filter
   */
  public record Setup(Map<String, String> params, List<String> uniqueTokens, List<String> created) {}

  @Inject DynamicClients dynamicClients;
  @Inject CommissionedTokens commissionedTokens;
  @Inject ServiceClients serviceClients;
  @Inject Sessions sessions;
  @Inject SigningKeys signingKeys;
  @Inject IdpUserRepository users;
  @Inject IdpServiceClientRepository serviceClientRows;
  @Inject IdpSigningKeyRepository signingKeyRows;
  @Inject PublicClients publicClients;
  @Inject WorkstationCredentials workstations;
  @Inject TokenService tokenService;
  @Inject RegisterTokens registerTokens;
  @Inject IdpDynamicClientRepository dynamicClientRows;
  @Inject IdpAuthorizationCodeRepository codeRows;
  @Inject Users accounts;
  @Inject IdpWorkstationRefreshTokenRepository refreshTokenRows;

  private final Map<String, Supplier<Setup>> states = new LinkedHashMap<>();

  public ProviderStates() {
    states.put(A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE, this::aServiceClientWithTheSystemRole);
    states.put(
        A_SERVICE_CLIENT_WHOSE_STATED_GIT_REFS_ARE_REFUSED,
        this::aServiceClientWhoseStatedGitRefsAreRefused);
    states.put(A_PUBLISHED_SIGNING_KEY, this::aPublishedSigningKey);
    states.put(A_COMMISSIONED_CLIENT, this::aCommissionedClient);
    states.put(NO_COMMISSIONED_CLIENT_WITH_THE_GIVEN_ID, this::noCommissionedClientWithTheGivenId);
    states.put(A_COMMISSIONED_TOKEN, this::aCommissionedToken);
    states.put(A_SIGNED_IN_PERSON, this::aSignedInPerson);
    states.put(A_DATABASE_SERVICE_CLIENT, this::aDatabaseServiceClient);
    states.put(NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID, this::noServiceClientWithTheGivenId);
    states.put(A_SERVICE_CLIENT_NOTHING_CLAIMS, this::aServiceClientNothingClaims);
    states.put(
        A_SERVICE_CLIENT_NOTHING_CLAIMS_CALLING_WITH_ITS_BEARER,
        this::aServiceClientNothingClaimsCallingWithItsBearer);
    states.put(
        A_COMMISSIONED_CLIENT_HANDING_ITSELF_BACK, this::aCommissionedClientHandingItselfBack);
    states.put(
        AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI, () -> anAuthorizationCode(true, REDIRECT_URI));
    states.put(
        AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI_FOR_THE_CONNECT_PAGE,
        () -> anAuthorizationCode(true, CLI_PAGE_URI));
    states.put(
        AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT,
        () -> anAuthorizationCode(false, REDIRECT_URI));
    states.put(A_SESSION_TO_REFRESH, () -> aSessionToRefresh(true));
    states.put(A_GIT_SESSION_TO_REFRESH, () -> aSessionToRefresh(false));
    states.put(A_SERVICE_CLIENT_CALLING_ITS_PEERS, this::aServiceClientCallingItsPeers);
    states.put(
        A_SERVICE_CLIENT_PRESENTING_A_WRONG_SECRET, this::aServiceClientPresentingAWrongSecret);
    states.put(NO_COMMISSIONED_TOKEN_WITH_THE_GIVEN_ID, this::noCommissionedTokenWithTheGivenId);
    states.put(NO_SESSION_WITH_THE_GIVEN_TOKEN, this::noSessionWithTheGivenToken);
    states.put(
        NO_SESSION_WITH_THE_GIVEN_REFRESH_TOKEN, this::noSessionWithTheGivenRefreshToken);
    states.put(AN_ADMIN_SIGNED_IN_TO_THE_CLI, this::anAdminSignedInToTheCli);
    states.put(NO_USER_WITH_THE_GIVEN_NAME, this::noUserWithTheGivenName);
    states.put(AN_UNSPENT_REGISTER_TOKEN, this::anUnspentRegisterToken);
    states.put(
        NO_REGISTER_TOKEN_WITH_THE_GIVEN_VALUE, this::noRegisterTokenWithTheGivenValue);
    // The commissioners: each the caller and the context its body names.
    states.put(A_CI_RUNNER_BEING_COMMISSIONED, () -> commissioning("runnerId", uuid()));
    states.put(
        A_CI_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED,
        () -> commissioning("runnerId", uuid()));
    states.put(
        A_CI_RUNS_TOKEN_BEING_COMMISSIONED,
        () -> commissioning("runId", uuid(), "gitRef", GIT_REF));
    states.put(
        A_CI_RUNS_TOKEN_BEING_COMMISSIONED_WITHOUT_A_GIT_SCOPE,
        () -> commissioning("runId", uuid()));
    for (String state :
        List.of(
            A_WORKSPACES_CLIENT_BEING_COMMISSIONED,
            A_WORKSPACES_CLIENT_BEING_COMMISSIONED_TO_PUSH_NOTHING,
            A_WORKSPACES_TOKEN_BEING_COMMISSIONED,
            A_WORKSPACES_TOKEN_BEING_COMMISSIONED_TO_PUSH_NOTHING)) {
      states.put(
          state,
          () ->
              commissioning(
                  "workspaceId", WORKSPACE_ID, "projectId", uuid(), "gitRef", GIT_REF));
    }
    for (String state :
        List.of(
            A_WORKSPACES_CLIENT_WHOSE_STATED_GIT_REFS_ARE_REFUSED,
            A_WORKSPACES_TOKEN_WHOSE_STATED_GIT_REFS_ARE_REFUSED)) {
      states.put(
          state,
          () ->
              commissioning(
                  "workspaceId", WORKSPACE_ID, "projectId", uuid(),
                  "refusedGitRef", REFUSED_GIT_REF));
    }
    states.put(
        AN_AGENTS_TOKEN_BEING_COMMISSIONED,
        () -> commissioning("agentId", uuid(), "projectId", uuid(), "gitRef", GIT_REF));
    states.put(
        AN_AGENTS_TOKEN_BEING_COMMISSIONED_TO_PUSH_NOTHING,
        () -> commissioning("agentId", uuid(), "projectId", uuid(), "gitRef", GIT_REF));
    states.put(
        AN_AGENTS_TOKEN_WHOSE_STATED_GIT_REFS_ARE_REFUSED,
        () ->
            commissioning(
                "agentId", uuid(), "projectId", uuid(), "refusedGitRef", REFUSED_GIT_REF));
    states.put(A_WORKSPACE_RUNNER_BEING_COMMISSIONED, () -> commissioning("runnerId", uuid()));
    states.put(
        A_WORKSPACE_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED,
        () -> commissioning("runnerId", uuid()));
    states.put(A_DESK_RUNNER_BEING_COMMISSIONED, () -> commissioning("runnerId", uuid()));
    states.put(
        A_DESK_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED,
        () -> commissioning("runnerId", uuid()));
    states.put(
        A_REFINEMENTS_CLIENT_BEING_COMMISSIONED,
        () -> commissioning("refinementId", REFINEMENT_ID, "projectId", uuid()));
    states.put(A_FRONT_DESKS_TOKEN_BEING_COMMISSIONED, () -> commissioning("projectId", uuid()));
  }

  /** Every state name this provider answers for. */
  public Set<String> names() {
    return Collections.unmodifiableSet(states.keySet());
  }

  /** Runs the named state; an unknown name is a programming error, not an empty state. */
  public Setup setUp(String state) {
    Supplier<Setup> setup = states.get(state);
    if (setup == null) {
      throw new IllegalArgumentException(
          "No provider state '" + state + "' — this provider answers for " + states.keySet());
    }
    return setup.get();
  }

  /** {@link #setUp} for a pact {@code @State} method, which returns only the params. */
  public Map<String, String> params(String state) {
    return setUp(state).params();
  }

  /**
   * {@value #A_COMMISSIONED_CLIENT} as a consumer's pact states it, for verification.
   *
   * <p>A commissioned client's id and secret are random, so a consumer can only send the ones the
   * state hands back. A consumer that names them with provider-state generators gets this state's
   * fresh pair either way; one that sends the form literally (the daemons' pacts do: a form body
   * carries no generator there) sends the frozen pair its params state. When those params name a
   * {@code dyn-} id and a secret, this commissions exactly that client — the same row a commission
   * leaves, owned by {@value #CALLER} — so the state the consumer describes is the state it gets.
   */
  public Map<String, String> commissionedClientAsStated(Map<String, ?> stated) {
    Object id = stated == null ? null : stated.get("clientId");
    Object secret = stated == null ? null : stated.get("clientSecret");
    if (!(id instanceof String clientId)
        || !clientId.startsWith(DynamicClients.ID_PREFIX)
        || !(secret instanceof String clientSecret)
        || clientSecret.isEmpty()) {
      return params(A_COMMISSIONED_CLIENT);
    }
    seedCommissionedClient(clientId, clientSecret);
    return commissionedClientParams(clientId, clientSecret);
  }

  /**
   * {@value #A_COMMISSIONED_CLIENT_HANDING_ITSELF_BACK} as a consumer's pact states it: a {@code
   * dyn-} id and secret in its params are the client seeded, and its {@code authorization} is that
   * pair's own Basic. Without them it is the ordinary state.
   */
  public Map<String, String> commissionedClientHandingItselfBackAsStated(Map<String, ?> stated) {
    String clientId = statedString(stated, "clientId");
    String clientSecret = statedString(stated, "clientSecret");
    if (clientId == null
        || !clientId.startsWith(DynamicClients.ID_PREFIX)
        || clientSecret == null) {
      return params(A_COMMISSIONED_CLIENT_HANDING_ITSELF_BACK);
    }
    return handingItselfBack(clientId, clientSecret).params();
  }

  /** A {@code dyn-} client of exactly this id and secret, owned by {@link #CALLER}. */
  private void seedCommissionedClient(String clientId, String clientSecret) {
    // Evicts the cache too, so a row an earlier interaction seeded is not answered from it.
    dynamicClients.decommission(clientId, CALLER);
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpDynamicClient row = new IdpDynamicClient();
              row.clientId = clientId;
              row.secretHash = ClientSecret.hash(clientSecret);
              row.owner = CALLER;
              row.contextKind = CONTEXT_KIND;
              row.contextId = CONTEXT_ID;
              row.createdAt = Instant.now();
              dynamicClientRows.persist(row);
            });
  }

  /**
   * {@value #AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI}, {@value
   * #AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI_FOR_THE_CONNECT_PAGE} or {@value
   * #AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT} as a consumer's pact states it, for
   * verification.
   *
   * <p>The same reasoning as {@link #commissionedClientAsStated}: a code is random, and a consumer
   * that sends the token form literally (the two CLIs' pacts do: a form body carries no generator
   * there) sends the frozen {@code code} its params state. When the params name a {@code code},
   * this issues exactly that code — the row {@code GET /idp/authorize} leaves, for a fresh person,
   * bound to the stated {@code redirectUri} and to the stated {@code codeVerifier}'s challenge — so
   * the state the consumer describes is the state it gets. An earlier interaction's row of the same
   * value (spent, by then) is replaced. Without a stated code it is the ordinary state.
   */
  public Map<String, String> authorizationCodeAsStated(String state, Map<String, ?> stated) {
    boolean cli = !AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT.equals(state);
    String fallbackUri =
        AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI_FOR_THE_CONNECT_PAGE.equals(state)
            ? CLI_PAGE_URI
            : REDIRECT_URI;
    String code = statedString(stated, "code");
    if (code == null) {
      return params(state);
    }
    String redirectUri = orElse(statedString(stated, "redirectUri"), fallbackUri);
    String verifier = orElse(statedString(stated, "codeVerifier"), CODE_VERIFIER);
    PublicClient client = cli ? publicClients.cli() : publicClients.workstation();
    UUID person = person();
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              codeRows.delete("codeHash", ClientSecret.hash(code));
              Instant now = Instant.now();
              IdpAuthorizationCode row = new IdpAuthorizationCode();
              row.id = UUID.randomUUID();
              row.codeHash = ClientSecret.hash(code);
              row.clientId = client.id();
              row.userId = person;
              row.redirectUri = redirectUri;
              row.codeChallenge = s256(verifier);
              row.createdAt = now;
              row.expiresAt = now.plus(client.authorizationCodeTtl());
              codeRows.persist(row);
            });
    return params(
        "clientId", client.id(),
        "code", code,
        "codeVerifier", verifier,
        "redirectUri", redirectUri);
  }

  /**
   * {@value #A_SESSION_TO_REFRESH} or {@value #A_GIT_SESSION_TO_REFRESH} as a consumer's pact
   * states it, for verification: when the params name a {@code refreshToken}, this starts a live
   * refresh family holding exactly that value for a fresh person — what a spent code leaves —
   * replacing an earlier interaction's row of the same value (rotated away, by then). Without a
   * stated value it is the ordinary state. See {@link #authorizationCodeAsStated}.
   */
  public Map<String, String> sessionToRefreshAsStated(String state, Map<String, ?> stated) {
    boolean cli = A_SESSION_TO_REFRESH.equals(state);
    String refreshToken = statedString(stated, "refreshToken");
    if (refreshToken == null) {
      return params(state);
    }
    PublicClient client = cli ? publicClients.cli() : publicClients.workstation();
    UUID person = person();
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              refreshTokenRows.delete("tokenHash", ClientSecret.hash(refreshToken));
              Instant now = Instant.now();
              IdpWorkstationRefreshToken row = new IdpWorkstationRefreshToken();
              row.id = UUID.randomUUID();
              row.familyId = UUID.randomUUID();
              row.clientId = client.id();
              row.tokenHash = ClientSecret.hash(refreshToken);
              row.userId = person;
              row.createdAt = now;
              row.expiresAt = now.plus(Duration.ofDays(1));
              refreshTokenRows.persist(row);
            });
    Map<String, String> params = params("clientId", client.id(), "refreshToken", refreshToken);
    return cli ? params : with(params, "audience", AUDIENCE);
  }

  private static String statedString(Map<String, ?> stated, String key) {
    Object value = stated == null ? null : stated.get(key);
    return value instanceof String text && !text.isEmpty() ? text : null;
  }

  private static String orElse(String value, String fallback) {
    return value != null ? value : fallback;
  }

  /** The state's slug: lower-cased, every run of non-alphanumerics replaced by {@code -}. */
  public static String slug(String state) {
    return state.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
  }

  /** The {@code Authorization} header of {@link #CALLER}. */
  static String callerAuthorization() {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((CALLER + ":" + CALLER_SECRET).getBytes(StandardCharsets.UTF_8));
  }

  // --- the states ------------------------------------------------------------------------------

  /**
   * The caller itself. {@code clientSecret} is its fixed test secret, for a consumer that sends the
   * pair in the form rather than as Basic.
   */
  private Setup aServiceClientWithTheSystemRole() {
    return new Setup(with(caller(), "clientSecret", CALLER_SECRET), List.of(), List.of());
  }

  /**
   * The same caller, and {@code refusedGitRef}: a ref no list may hold ({@link #REFUSED_GIT_REF}).
   * The idp checks a stated list by its entries alone, so what makes a commission refused is what
   * it states; a consumer names the entry with a provider-state generator on {@code
   * ${refusedGitRef}}, and the commission it sends answers 400. Its retry with {@code gitRefs: []}
   * is an ordinary commission by a {@code qits:system} caller and answers 201.
   */
  private Setup aServiceClientWhoseStatedGitRefsAreRefused() {
    return new Setup(
        with(with(caller(), "clientSecret", CALLER_SECRET), "refusedGitRef", REFUSED_GIT_REF),
        List.of(),
        List.of());
  }

  /**
   * {@link ContractSigningKey} as the one signing key: every other key row is deleted and the cache
   * reloaded, so the JWKS is that key alone, with a real and stable modulus. It stays the active
   * key afterwards — it is a complete key pair, so every token minted later is signed and verified
   * as before, and the store still holds exactly one key.
   */
  private Setup aPublishedSigningKey() {
    if (!ContractSigningKey.KID.equals(signingKeys.signing().kid())
        || signingKeys.published().size() != 1) {
      QuarkusTransaction.requiringNew()
          .run(
              () -> {
                signingKeyRows.deleteAll();
                IdpSigningKey row = new IdpSigningKey();
                row.kid = ContractSigningKey.KID;
                row.algorithm = SigningKeys.ALGORITHM;
                row.status = IdpSigningKeyStatus.ACTIVE;
                row.privateKeyPem = pem("PRIVATE KEY", ContractSigningKey.PRIVATE_KEY);
                row.publicKeyPem = pem("PUBLIC KEY", ContractSigningKey.PUBLIC_KEY);
                row.createdAt = Instant.now();
                signingKeyRows.persist(row);
              });
      signingKeys.reload();
    }
    String kid = ContractSigningKey.KID;
    return new Setup(params("kid", kid), List.of(), List.of(kid));
  }

  private static String pem(String type, String base64) {
    return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
  }

  /** A commissioned {@code dyn-} client and its secret, as a commissioner hands them out. */
  private Setup aCommissionedClient() {
    DynamicClients.Commissioned issued =
        dynamicClients.commission(CALLER, CONTEXT_KIND, CONTEXT_ID, null, null);
    String clientId = issued.client().clientId();
    return new Setup(
        commissionedClientParams(clientId, issued.secret()),
        List.of(randomSuffix(clientId), issued.secret()),
        List.of(clientId));
  }

  private static Map<String, String> commissionedClientParams(String clientId, String secret) {
    // clientSecret and secret are the same value: consumers asked for both names.
    return with(
        with(with(with(caller(), "clientId", clientId), "clientSecret", secret), "secret", secret),
        "audience",
        AUDIENCE);
  }

  /** A client id nothing ever commissions: commissioned ids end in 22 random characters. */
  private Setup noCommissionedClientWithTheGivenId() {
    Map<String, String> params = caller();
    params = with(params, "clientId", DynamicClients.ID_PREFIX + "contract-unknown");
    params = with(params, "clientSecret", "contract-unknown-secret");
    params = with(params, "secret", "contract-unknown-secret");
    return new Setup(with(params, "audience", AUDIENCE), List.of(), List.of());
  }

  /**
   * The caller as a peer-calling service mints: HTTP Basic and {@code audience} in the form, which
   * is how {@code quarkus-oidc-client} sends a {@code client_credentials} grant
   * ({@code credentials.secret} is {@code client_secret_basic}) and how the bootstrap CLI does.
   */
  private Setup aServiceClientCallingItsPeers() {
    return new Setup(with(caller(), "audience", AUDIENCE), List.of(), List.of());
  }

  /** The caller's id with a secret that is not its own: a rotated-away or mistyped secret. */
  private Setup aServiceClientPresentingAWrongSecret() {
    String authorization =
        "Basic "
            + Base64.getEncoder()
                .encodeToString(
                    (CALLER + ":not-" + CALLER_SECRET).getBytes(StandardCharsets.UTF_8));
    return new Setup(
        params("authorization", authorization, "callerClientId", CALLER, "audience", AUDIENCE),
        List.of(),
        List.of());
  }

  /** A token id and value nothing ever commissioned: the decommissioned or never-issued case. */
  private Setup noCommissionedTokenWithTheGivenId() {
    String tokenId = UUID.randomUUID().toString();
    return new Setup(
        with(with(caller(), "tokenId", tokenId), "token", TOKEN_PREFIX + "contract-unknown"),
        List.of(),
        List.of());
  }

  /** A session cookie value no sign-in opened: an expired or signed-out browser. */
  private Setup noSessionWithTheGivenToken() {
    return new Setup(
        with(caller(), "sessionToken", "contract-unknown-session"), List.of(), List.of());
  }

  /** The CLI's refresh token that no live session holds: spent, revoked or never issued. */
  private Setup noSessionWithTheGivenRefreshToken() {
    return new Setup(
        params(
            "clientId", publicClients.cli().id(), "refreshToken", "contract-unknown-refresh-token"),
        List.of(),
        List.of());
  }

  /**
   * A {@code qits:admin} person signed in to the CLI — {@code authorization} is their bearer, as
   * the CLI's login leaves it — and a second person, {@code username}, for the admin to list and
   * delete.
   *
   * <p><b>Those two are the only accounts</b>: every other one — what earlier tests and states
   * left, some without a role — is deleted first, so {@code GET /idp/api/users}, whose answer is
   * every account there is, lists exactly the people this state describes, whatever ran before it.
   */
  private Setup anAdminSignedInToTheCli() {
    for (Users.Summary account : accounts.list()) {
      accounts.delete(account.username());
    }
    Setup admin = adminBearer();
    UUID other = person();
    String username = "contract-" + other;
    return new Setup(
        with(admin.params(), "username", username), admin.uniqueTokens(), List.of(username));
  }

  /** {@value #AN_ADMIN_SIGNED_IN_TO_THE_CLI}'s bearer, and a username no account holds. */
  private Setup noUserWithTheGivenName() {
    Setup admin = adminBearer();
    return new Setup(
        with(admin.params(), "username", "contract-unknown-user"),
        admin.uniqueTokens(),
        List.of());
  }

  private Setup adminBearer() {
    UUID id = person();
    String bearer = tokenService.cli(id).accessToken();
    return new Setup(
        params("authorization", "Bearer " + bearer, "userId", id.toString()),
        List.of(bearer),
        List.of(id.toString()));
  }

  /** A register token an admin minted and nobody spent, and a username no account holds yet. */
  private Setup anUnspentRegisterToken() {
    String token = registerTokens.mint(CALLER).token();
    String suffix = hex();
    return new Setup(
        params("token", token, "username", "contract-" + suffix),
        List.of(token, suffix),
        List.of());
  }

  /** A register token value this idp never minted (or one already spent: the same answer). */
  private Setup noRegisterTokenWithTheGivenValue() {
    String suffix = hex();
    return new Setup(
        params("token", "contract-unknown-register-token", "username", "contract-" + suffix),
        List.of(suffix),
        List.of());
  }

  private Setup aCommissionedToken() {
    CommissionedTokens.Commissioned issued =
        commissionedTokens.commission(CALLER, CONTEXT_KIND, CONTEXT_ID, null, null);
    String tokenId = issued.token().id().toString();
    return new Setup(
        with(with(caller(), "tokenId", tokenId), "token", issued.value()),
        // The value's random part only, so the recorded value keeps its qits_tok_ prefix.
        List.of(
            issued.value().substring(TOKEN_PREFIX.length()),
            randomSuffix(issued.token().subject())),
        List.of(tokenId));
  }

  /** A person with {@code qits:admin} and a live session, as a sign-in would leave them. */
  private Setup aSignedInPerson() {
    UUID id = person();
    Sessions.Opened opened =
        sessions.open(new Users.Account(id, "contract-" + id, List.of("qits:admin")));
    return new Setup(
        with(with(caller(), "sessionToken", opened.token()), "userId", id.toString()),
        List.of(opened.token()),
        List.of(id.toString()));
  }

  private Setup aDatabaseServiceClient() {
    String token = hex();
    String clientId = "contract-" + token;
    serviceClients.create(clientId, CALLER);
    return new Setup(with(caller(), "clientId", clientId), List.of(token), List.of(clientId));
  }

  private Setup noServiceClientWithTheGivenId() {
    String token = hex();
    return new Setup(
        with(caller(), "clientId", "contract-" + token), List.of(token), List.of("contract-" + token));
  }

  /**
   * The service-client store holding exactly the clients the suite adopts at start, plus two past
   * their grace: {@code claimedClientId}, which the request claims, and {@code unclaimedClientId},
   * which nothing claims. Every other service client — what earlier tests and states left — is
   * deleted first, so the collection's whole answer (both lists and the counts) is the same on
   * every run, whatever ran before it.
   */
  private Setup aServiceClientNothingClaims() {
    for (ServiceClients.StoredServiceClient client : serviceClients.list()) {
      if (!ADOPTED.contains(client.clientId())) {
        serviceClients.delete(client.clientId());
      }
    }
    String token = hex();
    String claimed = "contract-claimed-" + token;
    String unclaimed = "contract-unclaimed-" + token;
    serviceClients.create(claimed, CALLER);
    serviceClients.create(unclaimed, CALLER);
    Instant old = Instant.now().minus(UnclaimedServiceClientCollector.GRACE).minusSeconds(3600);
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              serviceClientRows.findById(claimed).createdAt = old;
              serviceClientRows.findById(unclaimed).createdAt = old;
            });
    ServiceClientsAccess.reload(serviceClients);
    return new Setup(
        with(with(caller(), "claimedClientId", claimed), "unclaimedClientId", unclaimed),
        List.of(token),
        List.of());
  }

  /**
   * {@value #A_SERVICE_CLIENT_NOTHING_CLAIMS}, the caller presenting its own bearer instead of its
   * Basic pair: {@code authorization} is {@code Bearer <token>}, a token this idp minted for
   * {@value #CALLER} by client credentials — a service client holding {@code qits:system}, which is
   * what the collection door takes a bearer from (the orchestrator calls it so). The store is set up
   * exactly as for the Basic caller, so the answer is the same.
   */
  private Setup aServiceClientNothingClaimsCallingWithItsBearer() {
    Setup claims = aServiceClientNothingClaims();
    String bearer = tokenService.clientCredentials(CALLER, CALLER_SECRET).accessToken();
    List<String> unique = new ArrayList<>(claims.uniqueTokens());
    unique.add(bearer);
    return new Setup(
        with(claims.params(), "authorization", "Bearer " + bearer),
        List.copyOf(unique),
        claims.created());
  }

  /**
   * A commissioned {@code dyn-} client about to hand itself back: the caller is the client ITSELF,
   * {@code authorization} the Basic of its own {@code clientId} and {@code clientSecret} — any
   * credential may decommission its own row with no platform role (the bootstrap hands back its
   * publishing credential so). The pair is fixed, {@link #HANDBACK_CLIENT_ID} and {@link
   * #HANDBACK_SECRET}, rather than random: a random pair's Basic header could not be frozen, and
   * the row is seeded afresh (any earlier one of that id evicted first) on every run.
   */
  private Setup aCommissionedClientHandingItselfBack() {
    return handingItselfBack(HANDBACK_CLIENT_ID, HANDBACK_SECRET);
  }

  private Setup handingItselfBack(String clientId, String clientSecret) {
    seedCommissionedClient(clientId, clientSecret);
    String own =
        "Basic "
            + Base64.getEncoder()
                .encodeToString(
                    (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    Map<String, String> params =
        params(
            "authorization", own,
            "clientId", clientId,
            "clientSecret", clientSecret,
            "secret", clientSecret);
    return new Setup(params, List.of(), List.of(clientId));
  }

  /**
   * A code the person approved for the CLI ({@code qits-cli}) or the git client ({@code
   * qits-git-workstation}), bound to {@code redirectUri} — the loopback {@link #REDIRECT_URI}, or
   * for {@code qits login} the connect page {@link #CLI_PAGE_URI} — and to {@link
   * #CODE_VERIFIER}'s challenge: what {@code GET /idp/authorize} leaves in the store, without a
   * browser. The exchange must name the same {@code redirect_uri}, so it is the state's param.
   */
  private Setup anAuthorizationCode(boolean cli, String redirectUri) {
    PublicClient client = cli ? publicClients.cli() : publicClients.workstation();
    String code = workstations.authorize(client, person(), redirectUri, CODE_CHALLENGE).value();
    return new Setup(
        params(
            "clientId", client.id(),
            "code", code,
            "codeVerifier", CODE_VERIFIER,
            "redirectUri", redirectUri),
        List.of(code),
        List.of());
  }

  /** A signed-in CLI or git client: a code already exchanged, its refresh token live. */
  private Setup aSessionToRefresh(boolean cli) {
    PublicClient client = cli ? publicClients.cli() : publicClients.workstation();
    String code =
        workstations.authorize(client, person(), REDIRECT_URI, CODE_CHALLENGE).value();
    String refreshToken =
        workstations.exchangeCode(client, code, REDIRECT_URI, CODE_VERIFIER).refreshToken();
    Map<String, String> params = params("clientId", client.id(), "refreshToken", refreshToken);
    if (!cli) {
      params = with(params, "audience", AUDIENCE);
    }
    return new Setup(params, List.of(refreshToken), List.of());
  }

  /**
   * A commissioner about to commission: the caller, and the context values its body names — the
   * ids it varies per call, the project it scopes to, the branch it states. Nothing is seeded: the
   * commission the consumer sends is what makes the row, and a row's id is fresh every time. A
   * {@code {param}} the recording's body names is filled from these, and a consumer names each
   * with a provider-state generator.
   */
  private Setup commissioning(String... keysAndValues) {
    Map<String, String> params = caller();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      params = with(params, keysAndValues[i], keysAndValues[i + 1]);
    }
    return new Setup(params, List.of(), List.of());
  }

  private static String uuid() {
    return UUID.randomUUID().toString();
  }

  /** A fresh person holding {@code qits:admin}; their id. */
  private UUID person() {
    UUID id = UUID.randomUUID();
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpUser row = new IdpUser();
              row.id = id;
              row.username = "contract-" + id;
              row.createdAt = Instant.now();
              users.persist(row);
              IdpUserRole role = new IdpUserRole();
              role.userId = id;
              role.role = "qits:admin";
              role.createdAt = Instant.now();
              role.persist();
            });
    return id;
  }

  // --- helpers ---------------------------------------------------------------------------------

  private static Map<String, String> caller() {
    return params("authorization", callerAuthorization(), "callerClientId", CALLER);
  }

  /**
   * The random tail of a generated name: 16 random bytes, base64url without padding, so 22
   * characters. Counted from the end, not split on {@code -}, which base64url may contain.
   */
  private static String randomSuffix(String name) {
    return name.substring(name.length() - 22);
  }

  private static String s256(String verifier) {
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(
              MessageDigest.getInstance("SHA-256")
                  .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  private static String hex() {
    byte[] bytes = new byte[4];
    ThreadLocalRandom.current().nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }

  private static Map<String, String> with(Map<String, String> params, String key, String value) {
    Map<String, String> out = new TreeMap<>(params);
    out.put(key, value);
    return Collections.unmodifiableMap(out);
  }

  private static Map<String, String> params(String... keysAndValues) {
    Map<String, String> out = new TreeMap<>();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      out.put(keysAndValues[i], keysAndValues[i + 1]);
    }
    return Collections.unmodifiableMap(out);
  }
}
