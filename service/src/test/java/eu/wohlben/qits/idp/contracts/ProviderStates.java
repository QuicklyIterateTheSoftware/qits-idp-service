package eu.wohlben.qits.idp.contracts;

import eu.wohlben.qits.idp.control.CommissionedTokens;
import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.control.ServiceClients;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.SigningKeys;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
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
 * <p><b>Every state is parallel-safe and assumes nothing about the database.</b> The suite shares
 * one store, so every row a state makes has a fresh id, and the recorder keeps only the list
 * entries a state {@linkplain Setup#created created}.
 */
@ApplicationScoped
public class ProviderStates {

  public static final String A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE =
      "a service client with the system role";
  public static final String THE_PUBLISHED_SIGNING_KEY = "the published signing key";
  public static final String A_COMMISSIONED_CLIENT = "a commissioned client";
  public static final String A_COMMISSIONED_TOKEN = "a commissioned token";
  public static final String A_SIGNED_IN_PERSON = "a signed-in person";
  public static final String A_DATABASE_SERVICE_CLIENT = "a database service client";
  public static final String NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID =
      "no service client with the given id";

  /** The calling service client: adopted at start, holds {@code qits:system}. */
  static final String CALLER = "test-broad";

  private static final String CALLER_SECRET = "test-broad-secret";

  /** The context every commission here names. */
  static final String CONTEXT_KIND = "contract";

  static final String CONTEXT_ID = "run-1";

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

  private final Map<String, Supplier<Setup>> states = new LinkedHashMap<>();

  public ProviderStates() {
    states.put(A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE, this::aServiceClientWithTheSystemRole);
    states.put(THE_PUBLISHED_SIGNING_KEY, this::thePublishedSigningKey);
    states.put(A_COMMISSIONED_CLIENT, this::aCommissionedClient);
    states.put(A_COMMISSIONED_TOKEN, this::aCommissionedToken);
    states.put(A_SIGNED_IN_PERSON, this::aSignedInPerson);
    states.put(A_DATABASE_SERVICE_CLIENT, this::aDatabaseServiceClient);
    states.put(NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID, this::noServiceClientWithTheGivenId);
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

  private Setup aServiceClientWithTheSystemRole() {
    return new Setup(caller(), List.of(), List.of());
  }

  /** The active key: its {@code kid} marks the one JWKS entry to keep, since keys may rotate. */
  private Setup thePublishedSigningKey() {
    String kid = signingKeys.signing().kid();
    return new Setup(params("kid", kid), List.of(kid), List.of(kid));
  }

  private Setup aCommissionedClient() {
    DynamicClients.Commissioned issued =
        dynamicClients.commission(CALLER, CONTEXT_KIND, CONTEXT_ID, null, null);
    String clientId = issued.client().clientId();
    return new Setup(
        with(caller(), "clientId", clientId), List.of(randomSuffix(clientId)), List.of(clientId));
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
    UUID id = UUID.randomUUID();
    String username = "contract-" + id;
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpUser row = new IdpUser();
              row.id = id;
              row.username = username;
              row.createdAt = Instant.now();
              users.persist(row);
              IdpUserRole role = new IdpUserRole();
              role.userId = id;
              role.role = "qits:admin";
              role.createdAt = Instant.now();
              role.persist();
            });
    Sessions.Opened opened = sessions.open(new Users.Account(id, username, List.of("qits:admin")));
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
