package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * Session introspection: {@code POST /idp/api/sessions/introspect}, the call the edge makes to turn
 * a {@code qits-session} cookie into an identity.
 *
 * <p><b>This is why the cookie can be opaque.</b> The value carries nothing — no user id, no
 * signature, no expiry the holder could read — so the only way to learn anything from it is to ask
 * here, and this store stays the single truth. That is what makes logout a row update instead of a
 * cryptographic problem, and it is the trade the plan made against a signed cookie the edge could
 * verify offline: the cost is one cached call, and what it buys is revocation.
 *
 * <p><b>The guard is a service client's Basic pair</b>, the same credential and the same
 * check as the commission API next door ({@link BasicCaller}). The edge holds {@code
 * {env}-qits-edge} for exactly this. A commissioned credential is refused: introspection turns a
 * browser session into a username and a role set, and a build step has no business asking.
 *
 * <p><b>A refusal is a 404, and it is one answer for four causes</b> — unknown value, expired,
 * revoked, or an account that has since gone. The caller's only question is "is there a live
 * session behind this", and a caller that could tell "expired" from "never existed" could probe the
 * store for which cookie values were ever real.
 */
@Path("/api/sessions")
@Produces(MediaType.APPLICATION_JSON)
public class IdpSessionsController {

  /**
   * The cookie's value, as the edge read it.
   *
   * <p>It travels in a JSON body rather than a path segment or a query parameter because it is a
   * credential: a URL is written to access logs on both sides, and a body is not.
   */
  public record IntrospectRequest(String token) {}

  @Inject BasicCaller caller;

  @Inject Sessions sessions;

  /**
   * The live session behind this value, or a 404.
   *
   * <p>The answer is {@link SessionView} — the same four fields a register and a login return —
   * because the edge builds {@code X-Qits-User}, {@code X-Qits-User-Id} and {@code X-Qits-Roles}
   * out of them and the client draws its header out of them, and two shapes would be two places for
   * the role list to drift.
   *
   * <p><b>{@code RestResponse<SessionView>} rather than a bare {@code Response}</b>, because a
   * {@code Response} carries its entity as an {@code Object} and the native image builder then has
   * no type to register — a packaged binary that answers 500 with "no properties discovered" while
   * the JVM suite stays green. Measured in this repository on 2026-08-14.
   */
  @POST
  @Path("/introspect")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "introspectSession")
  public RestResponse<SessionView> introspect(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization, IntrospectRequest request) {
    caller.staticOnly(
        authorization,
        "a commissioned client may not introspect sessions",
        BasicCaller.SYSTEM);
    if (request == null || request.token() == null || request.token().isBlank()) {
      throw OAuthException.invalidRequest("a JSON body naming the session token is required");
    }
    return sessions
        .resolve(request.token())
        .map(
            session ->
                RestResponse.ResponseBuilder.create(
                        Response.Status.OK, SessionView.of(session))
                    // The body names a user and their roles, keyed by a credential. Never cached
                    // here; the edge's own cache is a decision it makes with a TTL it owns.
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .header("Pragma", "no-cache")
                    .build())
        .orElseThrow(() -> OAuthException.notFound("no live session for that token"));
  }
}
