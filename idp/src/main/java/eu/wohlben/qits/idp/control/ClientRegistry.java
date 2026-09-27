package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.control.DynamicClients.StoredClient;
import eu.wohlben.qits.idp.control.IdpClient.AudienceSource;
import eu.wohlben.qits.idp.control.ServiceClients.StoredServiceClient;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;

/**
 * Every client this idp knows, from all three halves: the environment service clients in config,
 * the database service clients in {@code idp_service_client}, and the commissioned clients in
 * {@code idp_client}.
 *
 * <p><b>Config is asked first, always.</b> An environment id therefore cannot be shadowed by a
 * database row, and that ordering is the collision answer rather than a uniqueness check somewhere:
 * whatever ends up in the store, the names services are dialed by keep meaning what the deployment
 * configured. Commissioned ids carry {@link DynamicClients#ID_PREFIX} on top of that, so all three
 * namespaces do not overlap in the first place.
 *
 * <p><b>A service client can exist in both places at once, transitionally</b> ({@code
 * service-client-identity-plan.md}, contract C2, C5): {@code POST /idp/api/service-clients} answers
 * 201 even for an id that already has an environment entry, so a caller mid-cutover can hold the
 * old environment secret and the new database one at the same time. When that happens, the
 * environment entry still decides the client's roles, claims and audience list — the same "config
 * wins" ordering as {@link #find} — but {@link IdpClient#secret()} accepts either secret: {@link
 * ClientSecret#either} merges the environment value with the database's current and unexpired
 * previous hash. An id with only a database row gets the roles/claims/audience rule {@link
 * #asServiceClient} builds in code.
 *
 * <p><b>A commissioned client is issued its owner's audiences</b>, read here at mint time rather
 * than copied into the row: a credential commissioned by qits-ci can be used where qits-ci can be
 * used. Narrowing an owner's audiences narrows every credential it commissioned, at once; an owner
 * removed from the registry leaves its commissioned clients able to authenticate and entitled to
 * nothing, which is refused as {@code invalid_target}. <b>Its audience RULE also follows its
 * owner's</b> — {@link IdpClient.AudienceSource} — so a commission owned by a database client gets
 * the database's unchecked-copy-back rule and one owned by an environment client keeps today's.
 * <b>A test client is owned by an agent, not a service</b>, and takes what that agent is issued,
 * one hop further up — {@link #ownerAudiences}.
 *
 * <p><b>Roles and claims are NOT inherited by a commission any more</b> (D3, D12 of the plan). A
 * commission's roles are its context kind's fixed ones ({@link CommissionRoles}, code, no owner
 * fallback and no configuration); its claims are only what it stated for itself ({@link
 * CommissionedClaims}, already resolved into {@link DynamicClients.StoredClient#claims()}).
 *
 * <p><b>The commission's context kind and Git refs ride along</b> on the {@link IdpClient}, and
 * {@link TokenService} stamps them as {@code context_kind} and {@code git_refs}. A service client
 * has neither, so its token carries neither.
 */
@ApplicationScoped
public class ClientRegistry {

  private static final Logger LOG = Logger.getLogger(ClientRegistry.class);

  /**
   * A database service client's fixed roles (D3 of the plan): {@code qits:system}, the open calling
   * model's service-to-service role. It is spelled here rather than read from {@code
   * BasicCaller.PLATFORM_SYSTEM}: this module has no compile-time dependency on {@code service}
   * ("Adding a dependency on another context").
   */
  private static final List<String> DATABASE_SERVICE_CLIENT_ROLES = List.of("qits:system");

  /** A database service client's one fixed claim (D3): it serves every project. */
  private static final Map<String, String> DATABASE_SERVICE_CLIENT_CLAIMS =
      Map.of(ClaimNames.PROJECT, "*");

  @Inject IdpClients staticClients;

  @Inject ServiceClients serviceClients;

  @Inject DynamicClients dynamicClients;

  /** The client with this id, from any of the three registries, or empty when there is none. */
  public Optional<IdpClient> find(String clientId) {
    Optional<IdpClient> serviceClient = findServiceClient(clientId);
    if (serviceClient.isPresent()) {
      return serviceClient;
    }
    return dynamicClients.find(clientId).map(this::asClient);
  }

  /**
   * Whether this id is a service client — environment or database — rather than a commissioned one.
   *
   * <p>The commission endpoints and the service-client management API both ask, because <b>a
   * commissioned client may not commission or manage service clients</b>: that ability belongs to
   * the platform's own services, and a credential handed to a build step or an agent container must
   * not be able to produce more of itself. That is what keeps the blast radius of a leaked
   * commissioned secret at one context.
   */
  public boolean isServiceClient(String clientId) {
    return findServiceClient(clientId).isPresent();
  }

  /**
   * Authenticate a presented id and secret, or refuse.
   *
   * <p>One refusal for three causes — unknown id, no secret configured, wrong secret. The caller
   * learns only that it did not authenticate; the log line is where the difference lives.
   *
   * @throws OAuthException {@code invalid_client} (401)
   */
  public IdpClient authenticate(String clientId, String secret) {
    IdpClient client = find(clientId).orElse(null);
    if (client == null || !client.secretMatches(secret)) {
      LOG.warnf(
          "client authentication failed for %s: %s",
          LoggableClientId.of(clientId),
          client == null
              ? "unknown client"
              : (client.usable() ? "wrong secret" : "no secret configured"));
      throw OAuthException.invalidClient("client authentication failed");
    }
    return client;
  }

  /** The environment client, the database client, or both merged — see the class javadoc. */
  private Optional<IdpClient> findServiceClient(String clientId) {
    Optional<IdpClient> env = staticClients.find(clientId);
    Optional<StoredServiceClient> db = serviceClients.find(clientId);
    if (env.isPresent()) {
      if (db.isEmpty()) {
        return env;
      }
      return Optional.of(withDatabaseSecret(env.get(), db.get()));
    }
    return db.map(ClientRegistry::asServiceClient);
  }

  /** An environment client that also has a database row: the env roles/claims/audiences, either secret. */
  private static IdpClient withDatabaseSecret(IdpClient env, StoredServiceClient db) {
    ClientSecret merged =
        ClientSecret.either(
            env.secret(),
            ClientSecret.serviceClient(
                null, db.secretHash(), db.previousSecretHash(), db.previousValidUntil()));
    return new IdpClient(
        env.clientId(),
        merged,
        env.audiences(),
        env.roles(),
        env.claims(),
        env.contextKind(),
        env.gitRefs(),
        AudienceSource.ENVIRONMENT);
  }

  /** A database-only service client: fixed roles and claims in code, the database's secret rule. */
  private static IdpClient asServiceClient(StoredServiceClient db) {
    return new IdpClient(
        db.clientId(),
        ClientSecret.serviceClient(null, db.secretHash(), db.previousSecretHash(), db.previousValidUntil()),
        List.of(),
        DATABASE_SERVICE_CLIENT_ROLES,
        DATABASE_SERVICE_CLIENT_CLAIMS,
        null,
        null,
        AudienceSource.DATABASE);
  }

  private IdpClient asClient(StoredClient stored) {
    OwnerAudiences owner = ownerAudiences(stored);
    return new IdpClient(
        stored.clientId(),
        ClientSecret.stored(stored.secretHash()),
        owner.audiences(),
        // D12: the context kind's fixed role, or none — never the owner's (D3 removed that
        // inheritance for roles the same way it removed it for claims).
        CommissionRoles.forKind(stored.contextKind()),
        // D3: a commission's claims are only what it stated for itself. DynamicClients.toStored has
        // already run them through CommissionedClaims, so this is the row, verbatim.
        stored.claims(),
        stored.contextKind(),
        stored.gitRefs(),
        owner.source());
  }

  /** The audiences a commission is issued, and the rule they are minted under. */
  private record OwnerAudiences(List<String> audiences, AudienceSource source) {

    /** An owner nobody can find: entitled to nothing, refused as {@code invalid_target}. */
    static final OwnerAudiences NONE = new OwnerAudiences(List.of(), AudienceSource.ENVIRONMENT);

    /**
     * A test client whose chain broke: {@code qits-platform} alone, under the environment rule, so
     * a request may name nothing else and an empty one gets exactly that.
     */
    static final OwnerAudiences PLATFORM_ONLY =
        new OwnerAudiences(List.of(TokenService.PLATFORM_AUDIENCE), AudienceSource.ENVIRONMENT);

    static OwnerAudiences of(IdpClient owner) {
      return new OwnerAudiences(owner.audiences(), owner.audienceSource());
    }
  }

  /**
   * A commission's owner's audiences — its owning service client's, and for a {@link
   * CommissionRoles#TEST_CLIENT} one hop further.
   *
   * <p><b>Every other kind is owned by a service client</b>, because only a service client may
   * commission it, and that owner's audiences and rule are the answer — or nothing, when the owner
   * is gone (the class javadoc).
   *
   * <p><b>A test client is owned by an agent</b> (qits-439): a commissioned client, which has no
   * audiences of its own to read. So its audiences are the ones that agent itself is issued —
   * the agent's own owner's, read the same way, exactly one hop and never a walk: a test client
   * cannot commission a client, so no chain is ever longer, and a loop is impossible by
   * construction rather than by a visited-set here. That keeps it <b>never wider than its
   * agent</b>: the same list under the same rule. A test client commissioned directly by a service
   * client (a system caller may commission any kind) takes that owner's, like any other kind.
   *
   * <p><b>When the chain cannot be resolved</b> — the agent is gone, or its own owner is — a test
   * client gets {@code qits-platform} alone rather than an {@code invalid_target}: the owner asked
   * for at least that much, and it is the one audience every token here carries anyway, so it
   * widens nothing. Its tokens ({@link TokenService#forCommissionedToken}) resolve through this
   * same method, because they ask {@link #find} for their owner.
   */
  private OwnerAudiences ownerAudiences(StoredClient stored) {
    Optional<IdpClient> owner = findServiceClient(stored.owner());
    if (owner.isPresent()) {
      return OwnerAudiences.of(owner.get());
    }
    if (!CommissionRoles.TEST_CLIENT.equals(stored.contextKind())) {
      return OwnerAudiences.NONE;
    }
    Optional<IdpClient> agentsOwner =
        dynamicClients
            .find(stored.owner())
            // Defensive only: a test client cannot commission, so its owner is never one.
            .filter(agent -> !CommissionRoles.TEST_CLIENT.equals(agent.contextKind()))
            .flatMap(agent -> findServiceClient(agent.owner()));
    if (agentsOwner.isEmpty()) {
      // DEBUG: this runs on every mint and every introspection of a test client's tokens.
      LOG.debugf(
          "test client %s: owner chain from %s does not resolve, issuing qits-platform only",
          LoggableClientId.of(stored.clientId()), LoggableClientId.of(stored.owner()));
      return OwnerAudiences.PLATFORM_ONLY;
    }
    return OwnerAudiences.of(agentsOwner.get());
  }
}
