package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.CommissionedTokens;
import eu.wohlben.qits.idp.control.CommissionedTokens.Commissioned;
import eu.wohlben.qits.idp.control.CommissionedTokens.StoredToken;
import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.control.TokenService;
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
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * Commissioned tokens: {@code /idp/api/tokens}, where a service client gets an opaque bearer for
 * one dynamic context and takes it back when the context ends.
 *
 * <p>The commission API's shape again, for the third credential: {@code POST} commissions, {@code
 * GET} lists what the caller commissioned so a crash leaks nothing nobody can see, {@code DELETE}
 * ends one, and {@code PUT …/git-refs} replaces the Git refs a token may push. {@code POST
 * /introspect} is the fifth verb, the edge's: it turns a value into the identity behind it and a
 * short JWT for the service behind the edge. The lifetime model — no expiry, deleting the row is
 * the whole revocation — is in {@link CommissionedTokens}; this class is the boundary.
 *
 * <p><b>The caller authenticates with its own Basic pair</b>, through {@link BasicCaller}, for the
 * reasons {@link IdpClientsController} gives: the platform's services already hold one, so it adds
 * nothing to configure. <b>Only a service client commissions</b> — a commissioned client is 403,
 * and a token cannot even authenticate here, because a token is not a client and has no id:secret
 * pair. That is what keeps a leaked token or a build step's credential from producing more access.
 *
 * <p><b>The one exception is a token handing itself back.</b> {@code DELETE} also accepts {@code
 * Authorization: Bearer qits_tok_…} — the raw token — and deletes the row if, and only if, that
 * token is the one the path names. A context that knows it is finishing can end its own credential
 * without going through its owner, exactly as a commissioned client may decommission itself.
 *
 * <p><b>The value appears in the {@code POST} answer and nowhere else</b> — no log line, no event,
 * no listing. The store holds its hash.
 */
@Path("/api/tokens")
@Produces(MediaType.APPLICATION_JSON)
public class IdpTokensController {

  /** The scheme a token presents itself under, and only on {@code DELETE} of its own id. */
  private static final String BEARER_PREFIX = "bearer ";

  /**
   * Which context the token is for, and what that context is about. The same four members, with
   * the same rules, as a commissioned client's {@link IdpClientsController.CommissionRequest}:
   * {@code claims} and {@code gitRefs} are optional, and absent means "states nothing".
   */
  public record CommissionRequest(
      String contextKind, String contextId, Map<String, String> claims, List<String> gitRefs) {}

  /**
   * The answer to a commission. <b>The token is in this response and nowhere else</b> — the store
   * holds a hash — so a caller that loses it deletes the row and commissions again.
   */
  public record CommissionResponse(
      String tokenId,
      String token,
      String subject,
      String owner,
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs,
      String createdAt) {}

  /** One live token, as the owner's reconcile reads it. No value, ever. */
  public record TokenView(
      String tokenId,
      String subject,
      String owner,
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs,
      String createdAt) {}

  /**
   * The value the edge read off a {@code Bearer} header. In a JSON body rather than a path or query
   * because it is a credential, and a URL is written to access logs on both sides.
   */
  public record IntrospectRequest(String token) {}

  /**
   * The body of {@code PUT /{tokenId}/git-refs}: the new list, whole. {@code []} is "push nothing".
   */
  public record GitRefsRequest(List<String> gitRefs) {}

  /**
   * What a live token is, and a JWT that says the same thing to the service behind the edge.
   *
   * <p>{@code roles} are exactly the {@code groups} of {@code accessToken} — the kind's fixed roles
   * plus the token's own {@code clients/<subject>} — so the edge can build its identity headers
   * without decoding what it was just handed. {@code expiresIn} is the JWT's lifetime in seconds;
   * the token itself has none.
   */
  public record IntrospectionResponse(
      String tokenId,
      String subject,
      List<String> roles,
      Map<String, String> claims,
      List<String> gitRefs,
      String contextKind,
      String contextId,
      String accessToken,
      long expiresIn) {}

  @Inject BasicCaller caller;

  @Inject CommissionedTokens tokens;

  @Inject TokenService tokenService;

  /**
   * Commission a token for one context.
   *
   * <p>201 with the value, and no {@code Location} header for the reason {@link
   * IdpClientsController#commission} gives. <b>{@code RestResponse<CommissionResponse>}, not a bare
   * {@code Response}</b>: a {@code Response} carries its entity as an {@code Object}, and the
   * native image then has no type to register and answers 500 while the JVM suite stays green.
   */
  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "commissionToken")
  public RestResponse<CommissionResponse> commission(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization, CommissionRequest request) {
    IdpClient owner =
        caller.staticOnly(
            authorization,
            "a commissioned client may not commission a token",
            BasicCaller.SYSTEM);
    if (request == null) {
      throw OAuthException.invalidRequest(
          "a JSON body naming contextKind and contextId is required");
    }
    Commissioned issued =
        tokens.commission(
            owner.clientId(),
            request.contextKind(),
            request.contextId(),
            request.claims(),
            request.gitRefs());
    StoredToken token = issued.token();
    return RestResponse.ResponseBuilder.create(
            Response.Status.CREATED,
            new CommissionResponse(
                token.id().toString(),
                issued.value(),
                token.subject(),
                token.owner(),
                token.contextKind(),
                token.contextId(),
                token.claims(),
                token.gitRefs(),
                token.createdAt().toString()))
        // The body holds a credential. Same rule as the token response and the clients door.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * The live token behind this value, and a short JWT for it — or a 404.
   *
   * <p>The call the edge makes on a {@code qits_tok_} bearer, the counterpart of {@code POST
   * /idp/api/sessions/introspect} for a cookie, with <b>the identical caller rule</b>: a service
   * client's Basic pair holding {@code qits:system}; a commissioned client is 403. A value that is
   * not shaped like a token is refused before any store read ({@link
   * CommissionedTokens#introspect}), so a JWT sent here by mistake costs nothing.
   *
   * <p><b>It also mints.</b> The answer carries {@code accessToken}, minted as {@link
   * TokenService#forCommissionedToken} describes — exactly what a commissioned client of that kind
   * would get, with the short {@code qits.idp.token-introspection-jwt-ttl-seconds} lifetime — so
   * the service behind the edge verifies an ordinary JWT and needs no second code path for tokens.
   *
   * <p><b>A refusal is one 404 for every cause</b> — unknown value, deleted row, an owner that no
   * longer exists — in the shape the sessions door gives, for the same reason: the only question is
   * "is there a live token behind this", and a finer answer would let a caller probe the store.
   *
   * <p>{@code RestResponse<IntrospectionResponse>}, never a bare {@code Response}, for the native
   * image reason {@link #commission} gives. Logged at DEBUG only, by subject, never by value.
   */
  @POST
  @Path("/introspect")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "introspectToken")
  public RestResponse<IntrospectionResponse> introspect(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization, IntrospectRequest request) {
    caller.staticOnly(
        authorization,
        "a commissioned client may not introspect tokens",
        BasicCaller.SYSTEM);
    if (request == null || request.token() == null || request.token().isBlank()) {
      throw OAuthException.invalidRequest("a JSON body naming the token is required");
    }
    StoredToken token =
        tokens.introspect(request.token()).orElseThrow(IdpTokensController::noLiveToken);
    TokenService.CommissionedTokenGrant grant =
        tokenService.forCommissionedToken(token).orElseThrow(IdpTokensController::noLiveToken);
    return RestResponse.ResponseBuilder.create(
            Response.Status.OK,
            new IntrospectionResponse(
                token.id().toString(),
                token.subject(),
                grant.groups(),
                token.claims(),
                token.gitRefs(),
                token.contextKind(),
                token.contextId(),
                grant.token().accessToken(),
                grant.token().expiresInSeconds()))
        // The body carries a bearer. Never cached here; the edge's cache is its own decision.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  private static OAuthException noLiveToken() {
    return OAuthException.notFound("no live token for that value");
  }

  /**
   * The caller's own live tokens — the reconciliation read. Never a value, and never another
   * owner's.
   *
   * <p><b>A read, so {@code qits:agent} is accepted beside {@code qits:system}</b>, exactly as on
   * {@code GET /idp/api/clients}: agents keep every read and lose only writes.
   */
  @GET
  @Operation(operationId = "listTokens")
  public List<TokenView> list(@HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
    IdpClient owner =
        caller.requireAnyRole(
            caller.authenticated(authorization), BasicCaller.SYSTEM, BasicCaller.AGENT);
    return tokens.listOwned(owner.clientId()).stream().map(IdpTokensController::view).toList();
  }

  /**
   * Delete one token — the context ended. 204, and the very next introspection refuses it.
   *
   * <p>Two callers may: <b>the owner</b>, with its Basic pair and {@code qits:system}; and <b>the
   * token itself</b>, presented raw as {@code Authorization: Bearer qits_tok_…}, for its own id
   * only. A bearer that resolves to no live token is a 401, like any credential that does not
   * authenticate. Everything else — another owner, a live token naming a different id, an unknown
   * id, an id that is not a uuid — is the same 404, so nobody maps other services' contexts here.
   */
  @DELETE
  @Path("/{tokenId}")
  @Operation(operationId = "deleteToken")
  public Response delete(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("tokenId") String tokenId) {
    String deleter = bearerToken(authorization).map(this::subjectOf).orElse(null);
    if (deleter == null) {
      deleter =
          caller
              .requireRole(caller.authenticated(authorization), BasicCaller.SYSTEM)
              .clientId();
    }
    UUID id = parseId(tokenId);
    if (id == null || !tokens.delete(id, deleter)) {
      throw OAuthException.notFound("no such commissioned token");
    }
    return Response.noContent().build();
  }

  /**
   * Replace the Git refs a token may push. The counterpart of {@link
   * IdpClientsController#replaceGitRefs} for the third credential: a RUNNER workspace's token
   * loses or gains push scope here instead of being re-commissioned.
   *
   * <p><b>Only the owner</b>, with the same Basic pair and role as {@code POST}; a commissioned
   * caller is 403 — a token may hand itself back on {@code DELETE} but may not widen or narrow its
   * own scope. Another owner's token, an unknown id and an id that is not a uuid are all the same
   * 404, so nobody maps other services' contexts from here.
   *
   * <p><b>The body must carry a list.</b> {@code []} removes every ref. There is no way back to "no
   * scope stated": that would widen the token to what its roles allow.
   *
   * <p><b>The next introspection carries the new {@code git_refs}.</b> The edge caches an
   * introspection for 15 s ({@code EdgeAuth}), so a caller that just replaced the scope may still
   * see the old one at the edge for up to that long.
   *
   * <p>200 with the {@code TokenView}. A plain record return type, not a bare {@code Response}, for
   * the native-image reason {@link #commission} gives.
   */
  @PUT
  @Path("/{tokenId}/git-refs")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "replaceTokenGitRefs")
  public TokenView replaceGitRefs(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("tokenId") String tokenId,
      GitRefsRequest request) {
    IdpClient owner =
        caller.staticOnly(
            authorization,
            "a commissioned client may not change a commission",
            BasicCaller.SYSTEM);
    if (request == null || request.gitRefs() == null) {
      throw OAuthException.invalidRequest(
          "a JSON body with a gitRefs list is required; send [] for a token that may push"
              + " nothing");
    }
    UUID id = parseId(tokenId);
    if (id == null) {
      throw OAuthException.notFound("no such commissioned token");
    }
    return tokens
        .replaceGitRefs(id, owner.clientId(), request.gitRefs())
        .map(IdpTokensController::view)
        .orElseThrow(() -> OAuthException.notFound("no such commissioned token"));
  }

  /** The raw value of a {@code Bearer} header, or empty when the header is anything else. */
  private static Optional<String> bearerToken(String authorization) {
    if (authorization == null
        || !authorization.toLowerCase(Locale.ROOT).startsWith(BEARER_PREFIX)) {
      return Optional.empty();
    }
    return Optional.of(authorization.substring(BEARER_PREFIX.length()).trim());
  }

  /**
   * The subject of the live token this value is, which {@link CommissionedTokens#delete} accepts as
   * the token itself.
   *
   * @throws OAuthException {@code invalid_client} (401) when the value is no live token
   */
  private String subjectOf(String value) {
    return tokens
        .introspect(value)
        .map(StoredToken::subject)
        .orElseThrow(() -> OAuthException.invalidClient("token authentication failed"));
  }

  /** The path's id, or null when it is not a uuid — answered like an unknown id. */
  private static UUID parseId(String tokenId) {
    try {
      return tokenId == null ? null : UUID.fromString(tokenId);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private static TokenView view(StoredToken token) {
    return new TokenView(
        token.id().toString(),
        token.subject(),
        token.owner(),
        token.contextKind(),
        token.contextId(),
        token.claims(),
        token.gitRefs(),
        token.createdAt().toString());
  }
}
