package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.control.DynamicClients.StoredClient;
import eu.wohlben.qits.idp.control.ServiceClients.StoredServiceClient;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;

/**
 * Every client this idp knows, from both registries: the service clients in {@code
 * idp_service_client} and the commissioned clients in {@code idp_client}.
 *
 * <p>The service clients are asked first. Commissioned ids carry {@link DynamicClients#ID_PREFIX},
 * which no service client id may start with, so the two namespaces do not overlap anyway.
 *
 * <p>There used to be a third registry, the environment one ({@code qits.idp.clients}), asked
 * before both. qits-163 retired it: its clients were moved into the database once ({@link
 * EnvironmentClientAdoption}), and nothing here reads configuration any more.
 *
 * <p><b>A service client's roles and claims are code</b> (D3 of epic qits-540, dossier page "Plan
 * (as of 2026-09-13)"): {@code qits:system} plus its own {@code clients/<id>}, and the claim {@code
 * project=*}.
 *
 * <p><b>A commission's roles and claims are its own</b> (D3, D12). Its roles are its context
 * kind's fixed ones ({@link CommissionRoles}, code, no owner fallback); its claims are only what it
 * stated for itself ({@link CommissionedClaims}, already resolved into {@link
 * DynamicClients.StoredClient#claims()}). Nothing about a commission is read from its owner.
 *
 * <p><b>The commission's context kind and Git refs ride along</b> on the {@link IdpClient}, and
 * {@link TokenService} stamps them as {@code context_kind} and {@code git_refs}. A service client
 * has neither, so its token carries neither.
 */
@ApplicationScoped
public class ClientRegistry {

  private static final Logger LOG = Logger.getLogger(ClientRegistry.class);

  /**
   * A service client's fixed roles (D3): {@code qits:system}, the open calling model's
   * service-to-service role. It is spelled here rather than read from {@code
   * BasicCaller.PLATFORM_SYSTEM}: this module has no compile-time dependency on {@code service}
   * ("Adding a dependency on another context").
   */
  private static final List<String> SERVICE_CLIENT_ROLES = List.of("qits:system");

  /** A service client's one fixed claim (D3): it serves every project. */
  private static final Map<String, String> SERVICE_CLIENT_CLAIMS = Map.of(ClaimNames.PROJECT, "*");

  @Inject ServiceClients serviceClients;

  @Inject DynamicClients dynamicClients;

  /** The client with this id, from either registry, or empty when there is none. */
  public Optional<IdpClient> find(String clientId) {
    Optional<IdpClient> serviceClient = serviceClients.find(clientId).map(ClientRegistry::asServiceClient);
    if (serviceClient.isPresent()) {
      return serviceClient;
    }
    return dynamicClients.find(clientId).map(ClientRegistry::asClient);
  }

  /**
   * Whether this id is a service client — it has an {@code idp_service_client} row — rather than a
   * commissioned one.
   *
   * <p>The commission endpoints and the service-client management API both ask, because <b>a
   * commissioned client may not commission or manage service clients</b>: that ability belongs to
   * the platform's own services, and a credential handed to a build step or an agent container must
   * not be able to produce more of itself. That is what keeps the blast radius of a leaked
   * commissioned secret at one context.
   */
  public boolean isServiceClient(String clientId) {
    return serviceClients.find(clientId).isPresent();
  }

  /**
   * Authenticate a presented id and secret, or refuse.
   *
   * <p>One refusal for three causes — unknown id, no live secret, wrong secret. The caller learns
   * only that it did not authenticate; the log line is where the difference lives.
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

  /** A service client: fixed roles and claims in code, the database's secret rule. */
  private static IdpClient asServiceClient(StoredServiceClient db) {
    return new IdpClient(
        db.clientId(),
        ClientSecret.serviceClient(
            db.secretHash(), db.previousSecretHash(), db.previousValidUntil(), db.legacySecretHash()),
        SERVICE_CLIENT_ROLES,
        SERVICE_CLIENT_CLAIMS,
        null,
        null);
  }

  private static IdpClient asClient(StoredClient stored) {
    return new IdpClient(
        stored.clientId(),
        ClientSecret.stored(stored.secretHash()),
        // D12: the context kind's fixed role, or none — never the owner's.
        CommissionRoles.forKind(stored.contextKind()),
        // D3: a commission's claims are only what it stated for itself. DynamicClients.toStored has
        // already run them through CommissionedClaims, so this is the row, verbatim.
        stored.claims(),
        stored.contextKind(),
        stored.gitRefs());
  }
}
