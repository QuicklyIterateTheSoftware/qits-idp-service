package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.ClientRegistry;
import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;

/**
 * "Who is calling", for the machine surfaces: the commission API, session introspection, and
 * register-token minting.
 *
 * <p><b>One implementation, because it is one credential.</b> A caller here is a platform service
 * that already holds its own idp client id and secret — that is how it gets tokens at all — so
 * checking that pair directly adds nothing to configure: no new audience, no bearer-validation
 * stack inside the service that issues the bearers, no second credential to distribute. It is the
 * same {@code client_secret_basic} the token endpoint accepts, read by the same {@link
 * BasicCredentials} parser and checked by the same {@link ClientRegistry}. This class exists so
 * that stays true as the number of machine surfaces grows.
 *
 * <p><b>And the static-client rule travels with it.</b> A commissioned credential authenticates
 * here — it has to, so a context can hand its own credential back — but it may not commission
 * another, and it may not mint a register token either. Both are the same argument: a credential
 * handed to a build step or an agent container must not be able to produce more access, so the
 * blast radius of a leaked one stops at its own context.
 */
@ApplicationScoped
public class BasicCaller {

  /**
   * The role that gates every machine-admin route here: the open calling model's service-to-service
   * role (epic qits-540, dossier page "Plan (as of 2026-09-13)", "open calling model" and D5). Every
   * service client is minted with it in code ({@code ClientRegistry}), so it is the one role that
   * gates a machine-admin route here.
   */
  public static final String SYSTEM = "qits:system";

  /**
   * The agent role. Every read route here accepts it beside the roles it accepted before: agents
   * keep every read they have and lose only write access (user ruling 2026-09-12,
   * principal-bound-git-refs-plan.md). Write routes do not accept it.
   */
  public static final String AGENT = "qits:agent";

  @Inject ClientRegistry registry;

  /**
   * The authenticated caller. Basic only — these are JSON APIs, not the token endpoint, so there is
   * no form to carry credentials and no second place to look.
   *
   * @throws OAuthException {@code invalid_client} (401)
   */
  public IdpClient authenticated(String authorization) {
    BasicCredentials credentials = BasicCredentials.parse(authorization);
    if (credentials == null) {
      throw OAuthException.invalidClient("client authentication is required");
    }
    return registry.authenticate(credentials.clientId(), credentials.secret());
  }

  /**
   * The authenticated caller, refused unless it is a <b>service</b> client — one with an {@code
   * idp_service_client} row.
   *
   * @param refusal what the commissioned caller is told it may not do
   * @throws OAuthException {@code invalid_client} (401) when authentication failed, {@code
   *     access_denied} (403) when it succeeded and the caller is a commissioned credential
   */
  public IdpClient staticOnly(String authorization, String refusal) {
    IdpClient caller = authenticated(authorization);
    if (!registry.isServiceClient(caller.clientId())) {
      throw OAuthException.accessDenied(refusal);
    }
    return caller;
  }

  /** Require one machine role after the Basic pair has authenticated. */
  public IdpClient requireRole(IdpClient caller, String role) {
    if (!caller.roles().contains(role)) {
      throw OAuthException.accessDenied("the client lacks role " + role);
    }
    return caller;
  }

  /**
   * Require at least one of these roles after the Basic pair has authenticated. A read route uses
   * it to accept {@link #AGENT} beside its old role.
   *
   * @throws OAuthException {@code access_denied} (403) when the caller holds none of them
   */
  public IdpClient requireAnyRole(IdpClient caller, String... roles) {
    for (String role : roles) {
      if (caller.roles().contains(role)) {
        return caller;
      }
    }
    throw OAuthException.accessDenied("the client lacks every role of " + List.of(roles));
  }

  /** Authenticate a service client and require its machine role. */
  public IdpClient staticOnly(String authorization, String refusal, String role) {
    return requireRole(staticOnly(authorization, refusal), role);
  }
}
