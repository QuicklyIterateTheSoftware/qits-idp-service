package eu.wohlben.qits.idp.contracts;

import eu.wohlben.qits.idp.control.CommissionedTokens;
import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.control.PublicClients;
import eu.wohlben.qits.idp.control.PublicClients.PublicClient;
import eu.wohlben.qits.idp.control.ServiceClients;
import eu.wohlben.qits.idp.control.ServiceClientsAccess;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.SigningKeys;
import eu.wohlben.qits.idp.control.UnclaimedServiceClientCollector;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.control.WorkstationCredentials;
import eu.wohlben.qits.idp.entity.IdpSigningKey;
import eu.wohlben.qits.idp.entity.IdpSigningKeyStatus;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import eu.wohlben.qits.idp.persistence.IdpSigningKeyRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
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
  public static final String AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI =
      "an authorization code issued to the CLI";
  public static final String AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT =
      "an authorization code issued to the git client";
  public static final String A_SESSION_TO_REFRESH = "a session to refresh";
  public static final String A_GIT_SESSION_TO_REFRESH = "a git session to refresh";

  /** The calling service client: adopted at start, holds {@code qits:system}. */
  static final String CALLER = "test-broad";

  private static final String CALLER_SECRET = "test-broad-secret";

  /** The context every commission here names. */
  static final String CONTEXT_KIND = "contract";

  static final String CONTEXT_ID = "run-1";

  /**
   * The PKCE verifier of every authorization code a state makes: fixed, so a consumer sends the
   * same one. The code itself is random and comes back as the state's {@code code} param.
   */
  static final String CODE_VERIFIER = "contract-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";

  /** {@link #CODE_VERIFIER}'s S256 challenge. */
  static final String CODE_CHALLENGE = s256(CODE_VERIFIER);

  /** The loopback callback every authorization code here is bound to. */
  static final String REDIRECT_URI = "http://127.0.0.1:53682/callback";

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

  private final Map<String, Supplier<Setup>> states = new LinkedHashMap<>();

  public ProviderStates() {
    states.put(A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE, this::aServiceClientWithTheSystemRole);
    states.put(A_PUBLISHED_SIGNING_KEY, this::aPublishedSigningKey);
    states.put(A_COMMISSIONED_CLIENT, this::aCommissionedClient);
    states.put(NO_COMMISSIONED_CLIENT_WITH_THE_GIVEN_ID, this::noCommissionedClientWithTheGivenId);
    states.put(A_COMMISSIONED_TOKEN, this::aCommissionedToken);
    states.put(A_SIGNED_IN_PERSON, this::aSignedInPerson);
    states.put(A_DATABASE_SERVICE_CLIENT, this::aDatabaseServiceClient);
    states.put(NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID, this::noServiceClientWithTheGivenId);
    states.put(A_SERVICE_CLIENT_NOTHING_CLAIMS, this::aServiceClientNothingClaims);
    states.put(AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI, () -> anAuthorizationCode(true));
    states.put(AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT, () -> anAuthorizationCode(false));
    states.put(A_SESSION_TO_REFRESH, () -> aSessionToRefresh(true));
    states.put(A_GIT_SESSION_TO_REFRESH, () -> aSessionToRefresh(false));
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
        // clientSecret and secret are the same value: consumers asked for both names.
        with(
            with(
                with(with(caller(), "clientId", clientId), "clientSecret", issued.secret()),
                "secret",
                issued.secret()),
            "audience",
            AUDIENCE),
        List.of(randomSuffix(clientId), issued.secret()),
        List.of(clientId));
  }

  /** A client id nothing ever commissions: commissioned ids end in 22 random characters. */
  private Setup noCommissionedClientWithTheGivenId() {
    return new Setup(
        params(
            "clientId", DynamicClients.ID_PREFIX + "contract-unknown",
            "clientSecret", "contract-unknown-secret",
            "secret", "contract-unknown-secret",
            "audience", AUDIENCE),
        List.of(),
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
   * A code the person approved for the CLI ({@code qits-cli}) or the git client ({@code
   * qits-git-workstation}), bound to {@link #REDIRECT_URI} and to {@link #CODE_VERIFIER}'s
   * challenge — what {@code GET /idp/authorize} leaves in the store, without a browser.
   */
  private Setup anAuthorizationCode(boolean cli) {
    PublicClient client = cli ? publicClients.cli() : publicClients.workstation();
    String code =
        workstations.authorize(client, person(), REDIRECT_URI, CODE_CHALLENGE).value();
    return new Setup(
        params(
            "clientId", client.id(),
            "code", code,
            "codeVerifier", CODE_VERIFIER,
            "redirectUri", REDIRECT_URI),
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
