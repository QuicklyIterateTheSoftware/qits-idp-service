package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.control.DynamicClients.Commissioned;
import eu.wohlben.qits.idp.control.DynamicClients.StoredClient;
import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The commission API: {@code /idp/api/clients}, where a service that provisions a dynamic context
 * gets a credential for it and gives it back when the context ends.
 *
 * <p>Four verbs and no more. {@code POST} commissions, {@code DELETE} decommissions, {@code GET}
 * lists what the caller commissioned so a crash cannot leak credentials nobody can see, and {@code
 * PUT …/git-refs} replaces the Git refs a commission may push. The lifetime model is in {@link
 * DynamicClients}; this class is the boundary.
 *
 * <h2>Why HTTP Basic against the existing clients</h2>
 *
 * <p>A caller here is a platform service that <b>already holds its own idp client id and secret</b>
 * — that is how it gets tokens at all. Checking that pair directly is therefore the mechanism that
 * adds nothing: no new audience to configure, no bearer-validation stack in the service that issues
 * the bearers (the idp validating its own tokens would be a circular boot dependency the moment the
 * signing key load and the commission call meet), and no second credential for a deployment to
 * distribute. It is the same {@code client_secret_basic} the token endpoint already accepts, and it
 * is read and checked by {@link BasicCaller}, which every machine surface here shares — so there is
 * exactly one answer in this service to "is this who it says it is".
 *
 * <p>A token-based guard would be the right call the day these endpoints need per-caller
 * permissions beyond "is it a service client", and it can bring its own audience then. <b>Per-context
 * scoping was expected to be that day and turned out not to be.</b> A commission may now state the
 * claims its credential carries, and that needed no per-caller permission at all: the states it may
 * ask for are narrowings, so every caller may ask for every one of them and the answer does not
 * depend on which service is asking. See {@code CommissionedClaims} for why the wildcard is the one
 * value that is not.
 *
 * <p><b>Only a service client may commission</b> — one with an {@code idp_service_client} row,
 * never a commissioned one. A commissioned credential authenticates
 * here (it has to, so a context can hand its own credential back), but {@code POST} refuses it:
 * a credential that could commission more credentials would outlive its own decommission through
 * the ones it made, and the blast radius of a leaked build-step secret would stop being one build.
 *
 * <p><b>These routes are reachable through the gateway</b>, which routes {@code /idp/*} verbatim.
 * They are protected by the credential above and by nothing else, exactly like the token endpoint
 * next to them.
 */
@Path("/api/clients")
@Produces(MediaType.APPLICATION_JSON)
public class IdpClientsController {

  /**
   * What a caller asks for: which context this credential is being commissioned for, and — since
   * per-context scoping landed — what that context is <em>about</em>.
   *
   * <p>{@code claims} is optional and absent is the ordinary case. A caller that states one narrows
   * the credential it is about to receive: a workspace commission says {@code
   * {"project":"<projectId>"}}, and every resource service that reads a {@code project} claim then
   * judges that credential on the project rather than on the platform role alone. The names it may
   * use and the values it may state are {@code CommissionedClaims}' to decide — notably not {@code
   * *}, because a commission narrows and never widens.
   *
   * <p><b>A body that omits it binds to null</b>, which is every caller written before scoping
   * existed and is read as "states nothing". One canonical constructor and no second one: Jackson
   * binds a record through the canonical constructor, and a convenience overload nobody calls would
   * be dead code standing where an ambiguity could grow.
   *
   * <p>{@code gitRefs} is optional too: the Git refs the credential may push, as {@code
   * GitRefs} checks them. Absent or null states no scope, and the token carries no {@code git_refs}
   * (today's behaviour). {@code []} states "push nothing".
   */
  public record CommissionRequest(
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs) {}

  /**
   * The body of {@code PUT /{clientId}/git-refs}: the new list, whole. {@code []} is "push nothing".
   */
  public record GitRefsRequest(List<String> gitRefs) {}

  /**
   * The answer to a commission. <b>The secret is in this response and nowhere else</b> — the store
   * holds a hash — so a caller that loses it decommissions and commissions again.
   *
   * <p>{@code claims} is what was actually granted, not what was asked for. They are the same thing
   * whenever the call succeeds — a claim this service will not grant is a 400, never a quiet drop —
   * and echoing them is what lets a caller assert the scoping it asked for without minting a token
   * to look inside.
   */
  public record CommissionResponse(
      String clientId,
      String secret,
      String owner,
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs,
      String createdAt) {}

  /** One live commission, as the owner's reconcile reads it. No secret, ever. */
  public record CommissionView(
      String clientId,
      String owner,
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs,
      String createdAt) {}

  @Inject BasicCaller caller;

  @Inject DynamicClients dynamicClients;

  /**
   * Commission a credential for one context.
   *
   * <p>201 with the pair. The response carries <b>no {@code Location} header</b>: the URL a caller
   * reaches this service at is the deployment's — direct on the platform network for a service,
   * through the gateway for an operator — and this process knows neither, so a self-built absolute
   * URL would be wrong for somebody. The {@code clientId} in the body is the whole address.
   *
   * <p><b>The return type is {@code RestResponse<CommissionResponse>} and not a bare {@code
   * Response}, and that is not a style choice.</b> A {@code Response} carries its entity as an
   * {@code Object}, so the native build has no static type to register for reflection and the
   * packaged binary answers 500 with "no properties discovered" — green on the JVM, broken as
   * shipped. Measured here on 2026-08-14, caught by {@code IdpPackagedSurfaceIT}. Naming the type
   * keeps the status and the headers and tells the image builder what to keep.
   */
  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  public RestResponse<CommissionResponse> commission(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization, CommissionRequest request) {
    IdpClient owner =
        caller.staticOnly(
            authorization,
            "a commissioned client may not commission another",
            BasicCaller.SYSTEM);
    if (request == null) {
      throw OAuthException.invalidRequest(
          "a JSON body naming contextKind and contextId is required");
    }

    Commissioned issued =
        dynamicClients.commission(
            owner.clientId(),
            request.contextKind(),
            request.contextId(),
            request.claims(),
            request.gitRefs());
    StoredClient client = issued.client();
    return RestResponse.ResponseBuilder.create(
            Response.Status.CREATED,
            new CommissionResponse(
                client.clientId(),
                issued.secret(),
                client.owner(),
                client.contextKind(),
                client.contextId(),
                client.claims(),
                client.gitRefs(),
                client.createdAt().toString()))
        // The body holds a credential. Same rule as the token response, same reason.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * The caller's own live commissions — for reconciliation: a service compares this against its
   * live contexts at boot and periodically, and decommissions whatever it no longer recognises.
   * Leaked credentials are answered structurally here rather than by a TTL.
   *
   * <p><b>Only the caller's own.</b> There is no listing across owners and no way to ask for
   * another's, because a service's live contexts are its own business.
   *
   * <p><b>A read, so {@code qits:agent} is accepted too.</b> An agent keeps every read it had while
   * it carried its owner's roles; only writes are restricted. It commissions nothing, so its own
   * listing is empty — the answer it got before.
   */
  @GET
  public List<CommissionView> list(@HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
    IdpClient owner =
        caller.requireAnyRole(
            caller.authenticated(authorization), BasicCaller.SYSTEM, BasicCaller.AGENT);
    return dynamicClients.listOwnedBy(owner.clientId()).stream()
        .map(IdpClientsController::view)
        .toList();
  }

  /**
   * Replace the Git refs of one commission (principal-bound-git-refs-plan.md, C2). This is the
   * narrowing: when a sub-workspace takes over a branch, the epic's credential loses that ref here.
   * The next token carries the new list.
   *
   * <p><b>Only the owner</b>, with the same Basic pair and role as {@code POST}; a commissioned
   * caller is 403, as there. Another owner's client, an unknown id and a service client id are all 404 —
   * the decommission rule, so nobody maps other services' contexts from here.
   *
   * <p><b>The body must carry a list.</b> {@code []} removes every ref. There is no way back to "no
   * scope stated": that would widen the credential to what its roles allow.
   *
   * <p>200 with the commission as the listing shows it. A plain return type, so the native image
   * builder sees the record (see {@link #commission} for why that matters).
   */
  @PUT
  @Path("/{clientId}/git-refs")
  @Consumes(MediaType.APPLICATION_JSON)
  public CommissionView replaceGitRefs(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId,
      GitRefsRequest request) {
    IdpClient owner =
        caller.staticOnly(
            authorization,
            "a commissioned client may not change a commission",
            BasicCaller.SYSTEM);
    if (request == null || request.gitRefs() == null) {
      throw OAuthException.invalidRequest(
          "a JSON body with a gitRefs list is required; send [] for a credential that may push"
              + " nothing");
    }
    return dynamicClients
        .replaceGitRefs(clientId, owner.clientId(), request.gitRefs())
        .map(IdpClientsController::view)
        .orElseThrow(() -> OAuthException.notFound("no such commissioned client"));
  }

  /**
   * Decommission — the context ended.
   *
   * <p>204 and the row is gone, so the credential mints nothing from the next request onward.
   * <b>Tokens it already minted live out their {@code exp}</b>; that grace is the accepted cost
   * recorded on {@code qits.idp.token-ttl-seconds}, and it is why an owner decommissions at the end
   * of a context rather than treating this as an emergency stop.
   *
   * <p>The caller must be the owner, or the credential itself. Anything else is a 404 — the same
   * answer as an id that never existed, so nobody maps other services' contexts from here.
   */
  @DELETE
  @Path("/{clientId}")
  public Response decommission(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId) {
    IdpClient authenticated = caller.authenticated(authorization);
    // A credential may always hand itself back. Its roles may be its kind's own fixed ones
    // (CommissionRoles, e.g. qits:agent) rather than its owner's — or none at all — and giving back
    // one's own credential needs no platform role either way.
    if (!authenticated.clientId().equals(clientId)) {
      caller.requireRole(authenticated, BasicCaller.SYSTEM);
    }
    if (!dynamicClients.decommission(clientId, authenticated.clientId())) {
      throw OAuthException.notFound("no such commissioned client");
    }
    return Response.noContent().build();
  }

  private static CommissionView view(StoredClient client) {
    return new CommissionView(
        client.clientId(),
        client.owner(),
        client.contextKind(),
        client.contextId(),
        client.claims(),
        client.gitRefs(),
        client.createdAt().toString());
  }
}
