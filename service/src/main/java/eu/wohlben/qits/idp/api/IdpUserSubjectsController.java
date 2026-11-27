package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Users;
import jakarta.inject.Inject;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import java.util.List;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The people a toggle's USER rule can name (qits-2725): {@code GET /idp/api/user-subjects}.
 *
 * <p><b>{@code subject} is the account's id</b>, which is exactly the {@code sub} of every token the
 * person is minted ({@code TokenService.cli}, so also the landing app's {@code qits-spa} sign-in)
 * and therefore what qits-toggles matches a USER rule against. {@code username} is the only name an
 * account has, so it is the name a picker shows.
 *
 * <p><b>The callers are the configuring ones</b> ({@link AdminCaller#requireConfiguring}): whoever
 * may change a toggle's rules — a {@code qits:admin} person (bearer or session), the delivery desk
 * ({@code qits:desk-admin}) — and a static {@code qits:system} client over Basic. {@code
 * qits:agent} and {@code qits:admin-agent} are 403.
 *
 * <p><b>People only.</b> Agents and service clients are subjects too, but their ids are not
 * accounts; a rule names them by typing.
 */
@Path("/api/user-subjects")
@Produces(MediaType.APPLICATION_JSON)
public class IdpUserSubjectsController {

  /** One account as a picker shows it. Never a role, an instant or a credential. */
  public record SubjectView(String subject, String username) {}

  @Inject AdminCaller caller;

  @Inject Users users;

  /** Every account's subject and username, sorted by username. */
  @GET
  @Operation(operationId = "listUserSubjects")
  public RestResponse<List<SubjectView>> list(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @CookieParam(SessionCookie.NAME) String sessionToken) {
    caller.requireConfiguring(
        authorization, sessionToken, "a commissioned client may not list user subjects");
    List<SubjectView> answer =
        users.subjects().stream()
            .map(subject -> new SubjectView(subject.id().toString(), subject.username()))
            .toList();
    return RestResponse.ResponseBuilder.ok(answer)
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .build();
  }
}
