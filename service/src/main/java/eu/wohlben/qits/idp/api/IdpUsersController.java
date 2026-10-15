package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Users;
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
import java.util.List;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The accounts, for an admin (qits-1260): {@code GET /idp/api/users} and {@code DELETE
 * /idp/api/users/{username}}.
 *
 * <p><b>Both doors take the admin callers and nobody else</b> ({@link AdminCaller}): a service
 * client over Basic holding {@code qits:system}, a signed-in {@code qits:admin} session, or a
 * {@code qits:admin} person's bearer. The listing is not one of the reads every {@code qits:agent}
 * keeps: it is a roster of the installation's people, which no agent's context has a use for.
 *
 * <p><b>Nothing here answers a credential.</b> A user is its name, when it was made, and its roles;
 * the password hash and the passkeys stay in the store.
 *
 * <p>There is no "create": an account is made by spending a register token, which an admin mints
 * ({@code IdpRegisterTokensController}), and that is the only way in.
 */
@Path("/api/users")
@Produces(MediaType.APPLICATION_JSON)
public class IdpUsersController {

  private static final Logger LOG = Logger.getLogger(IdpUsersController.class);

  /** One account. {@code createdAt} is an ISO-8601 instant, like every instant this service answers. */
  public record UserView(String username, String createdAt, List<String> roles) {}

  @Inject AdminCaller caller;

  @Inject Users users;

  /** Every account, sorted by username. */
  @GET
  @Operation(operationId = "listUsers")
  public RestResponse<List<UserView>> list(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @CookieParam(SessionCookie.NAME) String sessionToken) {
    caller.require(authorization, sessionToken, "a commissioned client may not list users");
    List<UserView> answer =
        users.list().stream()
            .map(user -> new UserView(user.username(), user.createdAt().toString(), user.roles()))
            .toList();
    return RestResponse.ResponseBuilder.ok(answer)
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .build();
  }

  /**
   * Delete an account with everything keyed to it — its roles, passkeys, password, sessions,
   * authorization codes and refresh tokens — in one transaction ({@link Users#delete}).
   *
   * <p>404 for an unknown name; 409 when the caller is that account, so an installation cannot lose
   * its last admin by a slip of the same hand that holds it. A service client has no account and so
   * is never refused that way.
   */
  @DELETE
  @Path("/{username}")
  @Operation(operationId = "deleteUser")
  public RestResponse<Void> delete(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @CookieParam(SessionCookie.NAME) String sessionToken,
      @PathParam("username") String username) {
    AdminCaller.Admin admin =
        caller.require(authorization, sessionToken, "a commissioned client may not delete users");
    Users.Account target =
        users.byUsername(username).orElseThrow(() -> OAuthException.notFound("no such user"));
    if (admin.is(target.id())) {
      throw OAuthException.conflict("an admin cannot delete themselves");
    }
    if (!users.delete(target.username())) {
      // Deleted by somebody else between the read and the write: the same answer as never there.
      throw OAuthException.notFound("no such user");
    }
    LOG.infof("deleted user %s", target.username());
    return RestResponse.noContent();
  }
}
