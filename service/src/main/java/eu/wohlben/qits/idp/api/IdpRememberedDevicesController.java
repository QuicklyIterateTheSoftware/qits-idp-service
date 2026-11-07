package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.CommissionedTokens;
import eu.wohlben.qits.idp.control.Devices;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.TokenValue;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.error.AuthException;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

/**
 * The signed-in person's remembered browsers (qits-1944): {@code GET /idp/api/remembered-devices}
 * and {@code DELETE /idp/api/remembered-devices/{id}}. The devices are {@link Devices}'; this is the
 * page's door to them. Not {@code /api/devices}, which is the public clients' refresh families
 * ({@code IdpWorkstationController}) and stays exactly as it is.
 *
 * <p><b>Two callers, and each sees its own account's devices only.</b>
 *
 * <ol>
 *   <li><b>A live {@code qits-session}</b>, the account page in a browser. Its session row names the
 *       device it was opened through, which is how the listing marks one entry {@code current}: the
 *       {@link DeviceCookie} itself never reaches this path, by its own {@code Path}.
 *   <li><b>A person's CLI bearer</b>: a JWT this idp issued ({@link BearerCaller}) with {@code
 *       credential_type=cli} — the token {@code TokenService.cli} mints, which carries no client id
 *       claim of its own — whose {@code sub} is an account that still exists. That person runs
 *       {@code qits} at a terminal and may see and revoke their own browsers. A bearer has no
 *       device, so nothing is {@code current} for it.
 * </ol>
 *
 * <p><b>Every other bearer is 403, on both doors</b> — a service client's, a commissioned
 * credential's ({@code qits:agent} among them), a live commissioned token ({@code qits_tok_…}, an
 * agent's {@code QITS_TOKEN}, which reaches this host unexchanged), a Git workstation's. One rule for the read and the
 * write keeps it simple to state: this page is a person's, and no machine has a use for anyone's
 * browsers. A {@code DELETE} through a bearer is the third bearer write {@link BearerCaller} names,
 * and it only takes access away from the bearer's own person. No credential at all is 401 with no
 * challenge ({@link AuthException}), as on every browser door here.
 *
 * <p>A foreign id is indistinguishable from an unknown one: 404 either way.
 */
@Path("/api/remembered-devices")
@Produces(MediaType.APPLICATION_JSON)
public class IdpRememberedDevicesController {

  private static final Logger LOG = Logger.getLogger(IdpRememberedDevicesController.class);

  /** What {@code TokenService.cli} stamps a person's CLI token with, and the only bearer here. */
  static final String CLI_CREDENTIAL = "cli";

  /**
   * One remembered browser. Instants are ISO-8601, like every instant this service answers.
   *
   * @param current true for the device the calling session was opened through
   */
  public record RememberedDevice(
      UUID id,
      String label,
      Instant createdAt,
      Instant lastUsedAt,
      Instant expiresAt,
      Instant absoluteExpiresAt,
      boolean current) {}

  @Inject Devices devices;

  @Inject Sessions sessions;

  @Inject Users users;

  @Inject BearerCaller bearerCaller;

  @Inject CommissionedTokens commissionedTokens;

  /** The caller's live remembered devices, most recently used first. */
  @GET
  @Operation(operationId = "listRememberedDevices")
  public RestResponse<List<RememberedDevice>> list(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @CookieParam(SessionCookie.NAME) String sessionToken) {
    Caller caller = caller(authorization, sessionToken);
    List<RememberedDevice> answer =
        devices.list(caller.userId()).stream()
            .map(
                device ->
                    new RememberedDevice(
                        device.id(),
                        device.label(),
                        device.createdAt(),
                        device.lastUsedAt(),
                        device.expiresAt(),
                        device.absoluteExpiresAt(),
                        device.id().equals(caller.currentDevice())))
            .toList();
    return RestResponse.ResponseBuilder.ok(answer)
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /** Forget one device, and end every session it opened. 404 for a foreign or unknown id. */
  @DELETE
  @Path("/{id}")
  @Operation(operationId = "revokeRememberedDevice")
  public RestResponse<Void> revoke(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @CookieParam(SessionCookie.NAME) String sessionToken,
      @PathParam("id") UUID id) {
    Caller caller = caller(authorization, sessionToken);
    if (!devices.revoke(caller.userId(), id)) {
      throw OAuthException.notFound("remembered device not found");
    }
    LOG.infof("a remembered device of user %s was revoked by its owner", caller.userId());
    return RestResponse.noContent();
  }

  // --- the guard --------------------------------------------------------------------------------

  /** Whose devices, and which one is the caller's own; {@code currentDevice} may be null. */
  private record Caller(UUID userId, UUID currentDevice) {}

  private Caller caller(String authorization, String sessionToken) {
    if (authorization != null && !authorization.isBlank()) {
      // An explicit header is the caller's intent, as in AdminCaller; a browser sends none.
      if (!BearerCaller.isBearer(authorization)) {
        throw OAuthException.accessDenied("only a person's CLI bearer or a session may list devices");
      }
      String raw = authorization.trim().substring("bearer".length()).trim();
      // An agent's QITS_TOKEN is a commissioned token, not a JWT: the edge hands it to this host
      // as it is. A live one authenticated, so it is the same 403 as every other machine bearer.
      if (TokenValue.isToken(raw) && commissionedTokens.introspect(raw).isPresent()) {
        throw OAuthException.accessDenied("a commissioned token may not reach remembered devices");
      }
      return new Caller(person(bearerCaller.verify(authorization)), null);
    }
    Sessions.Live session =
        sessions
            .resolve(sessionToken)
            .orElseThrow(
                () ->
                    AuthException.invalidCredentials(
                        "a signed-in session or a person's CLI bearer is required"));
    return new Caller(session.userId(), session.deviceId());
  }

  /** A verified bearer: it must be a CLI token naming an account that still exists. */
  private UUID person(JwtClaims claims) {
    String credentialType;
    String subject;
    try {
      credentialType = claims.getStringClaimValue("credential_type");
      subject = claims.getSubject();
    } catch (MalformedClaimException e) {
      throw OAuthException.accessDenied("the bearer is not a person's CLI token");
    }
    if (!CLI_CREDENTIAL.equals(credentialType)) {
      throw OAuthException.accessDenied("only a person's CLI bearer may reach remembered devices");
    }
    return userId(subject)
        .flatMap(users::byId)
        .map(Users.Account::id)
        .orElseThrow(
            () -> OAuthException.accessDenied("the bearer's account no longer exists"));
  }

  private static Optional<UUID> userId(String subject) {
    if (subject == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(UUID.fromString(subject));
    } catch (IllegalArgumentException notAUserId) {
      return Optional.empty();
    }
  }
}
