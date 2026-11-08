package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Sessions;
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
import java.util.UUID;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The signed-in person's passkeys (qits-1953): {@code GET /idp/api/passkeys} and {@code DELETE
 * /idp/api/passkeys/{credentialId}}. The authenticators are {@link Users}'; this is the account
 * page's door to them. Adding one stays where it was, the register ceremony from a live session.
 *
 * <p><b>One caller: a live {@code qits-session}</b>, the account page in a browser, and it sees
 * and removes its own account's passkeys only. <b>Every bearer is 403</b>, on both doors and
 * before the cookie is looked at — a person's CLI token included, unlike the remembered-devices
 * doors: an authenticator is the account's way in, and nothing that is not the person at their
 * browser has a use for removing one. No session at all is 401 with no challenge ({@link
 * AuthException}), as on every browser door here.
 *
 * <p><b>The last way in is kept.</b> Removing the account's only passkey while it has no password
 * is 409 ({@link Users.PasskeyRemoval#LAST_AUTHENTICATOR}); with a password set it is allowed. A
 * foreign credential id is indistinguishable from an unknown one: 404 either way.
 *
 * <p>The listing carries the credential id, the authenticator model's AAGUID and when it was
 * registered — never the public key, its algorithm or the signature counter.
 */
@Path("/api/passkeys")
@Produces(MediaType.APPLICATION_JSON)
public class IdpPasskeysController {

  private static final Logger LOG = Logger.getLogger(IdpPasskeysController.class);

  /**
   * One passkey. Instants are ISO-8601, like every instant this service answers.
   *
   * @param credentialId the WebAuthn credential id, base64url — what the delete names
   * @param aaguid the authenticator model; all zeroes for the software ones, which is normal
   */
  public record Passkey(String credentialId, UUID aaguid, Instant createdAt) {}

  @Inject Users users;

  @Inject Sessions sessions;

  /** The caller's passkeys, oldest first. */
  @GET
  @Operation(operationId = "listPasskeys")
  public RestResponse<List<Passkey>> list(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @CookieParam(SessionCookie.NAME) String sessionToken) {
    UUID userId = caller(authorization, sessionToken);
    List<Passkey> answer =
        users.passkeysOf(userId).stream()
            .map(passkey -> new Passkey(passkey.credentialId(), passkey.aaguid(), passkey.createdAt()))
            .toList();
    return RestResponse.ResponseBuilder.ok(answer)
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * Remove one passkey. 404 for a foreign or unknown id; 409 when it is the account's only passkey
   * and the account has no password.
   */
  @DELETE
  @Path("/{credentialId}")
  @Operation(operationId = "deletePasskey")
  public RestResponse<Void> delete(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @CookieParam(SessionCookie.NAME) String sessionToken,
      @PathParam("credentialId") String credentialId) {
    UUID userId = caller(authorization, sessionToken);
    switch (users.removePasskey(userId, credentialId)) {
      case NOT_FOUND -> throw OAuthException.notFound("passkey not found");
      case LAST_AUTHENTICATOR ->
          throw OAuthException.conflict(
              "this is the account's only way to sign in: set a password or add another passkey"
                  + " first");
      case REMOVED -> LOG.infof("a passkey of user %s was removed by its owner", userId);
    }
    return RestResponse.noContent();
  }

  /** The session's account; any {@code Authorization} header is 403, checked first. */
  private UUID caller(String authorization, String sessionToken) {
    if (authorization != null && !authorization.isBlank()) {
      // An explicit header is the caller's intent, as in AdminCaller; a browser sends none.
      throw OAuthException.accessDenied("passkeys are reachable only from a signed-in session");
    }
    return sessions
        .resolve(sessionToken)
        .map(Sessions.Live::userId)
        .orElseThrow(() -> AuthException.invalidCredentials("a signed-in session is required"));
  }
}
