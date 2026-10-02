package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.Issuer;
import eu.wohlben.qits.idp.control.PublicClients;
import eu.wohlben.qits.idp.control.PublicClients.PublicClient;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.control.WorkstationCredentials;
import eu.wohlben.qits.idp.error.AuthException;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The browser leg of the public-client OAuth flows, and the signed-in user's revocation surface.
 *
 * <p>Two public clients arrive here. The Git workstation names a loopback listener and catches its
 * own redirect. {@code qits-cli} has no listener at the moment the person finishes signing in, so
 * it names this idp's OWN page — {@code <origin>/idp/connect/cli} — which shows the code for the
 * person to paste into the waiting command. Both spend the code at {@code /token} with the PKCE
 * verifier the waiting process holds, which is what makes a pasted code worth nothing on its own.
 *
 * <p><b>{@code /authorize} with no session bounces to the sign-in page</b> rather than answering
 * 401. A person who followed a URL their terminal printed has not signed in yet — that is the
 * normal case, not an error — and 401 leaves them with nothing to do. The bounce carries the whole
 * authorize URL as the login page's return location, so signing in lands back here and the code is
 * issued on the second pass. The return location is validated by {@link BrowserSso} exactly like
 * every other one: the authority is this idp's own canonical one, which its allow-list is checked
 * to contain at startup.
 *
 * <p>The API below {@code /api} is not an OAuth protocol endpoint and requires a live session for
 * every request.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class IdpWorkstationController {

  private static final String RESPONSE_TYPE_CODE = "code";
  private static final String S256 = "S256";

  /** The SPA route that shows a pasted-code, relative to the idp's own path prefix. */
  private static final String CLI_PAGE_PATH = "/connect/cli";

  /** The SPA route that signs a person in, relative to the idp's own path prefix. */
  private static final String LOGIN_PAGE_PATH = "/login";

  @Inject Sessions sessions;

  @Inject WorkstationCredentials workstations;

  @Inject PublicClients publicClients;

  @Inject BrowserSso browserSso;

  @Inject Issuer issuer;

  @ConfigProperty(name = "qits.idp.workstation.githost-audience")
  String githostAudience;

  /**
   * Approve a PKCE code and send it to the client's redirect target.
   *
   * <p>The order of the checks is the contract. The client and the redirect URI are settled first,
   * because everything after them is only answerable once it is known WHERE an answer may be sent:
   * an unknown {@code client_id} or a redirect target this idp does not recognise is refused with a
   * 400 here and never redirected anywhere. Only then does the session decide between the bounce
   * and the code, and only then — and only for the CLI page, whose reader is a person rather than a
   * loopback listener — does a later protocol refusal travel to that page as {@code ?error=…}, the
   * way RFC 6749 §4.1.2.1 says it should. The workstation client keeps the flat 400 it had: its
   * redirect target is a local listener whose behaviour on an error response nobody has designed,
   * and widening that was not asked for.
   */
  @GET
  @Path("/authorize")
  public Response authorize(
      @Context UriInfo uriInfo,
      @CookieParam(SessionCookie.NAME) String sessionToken,
      @QueryParam("response_type") String responseType,
      @QueryParam("client_id") String requestedClientId,
      @QueryParam("redirect_uri") String redirectUri,
      @QueryParam("code_challenge") String codeChallenge,
      @QueryParam("code_challenge_method") String challengeMethod,
      @QueryParam("audience") String audience,
      @QueryParam("state") String state) {
    PublicClient client =
        publicClients
            .byId(requestedClientId)
            .orElseThrow(() -> OAuthException.invalidRequest("invalid workstation authorization request"));
    URI callback = redirectTarget(client, redirectUri);
    boolean reportable = client.cli() && !isLoopback(callback);
    try {
      if (!RESPONSE_TYPE_CODE.equals(responseType) || !S256.equals(challengeMethod)) {
        throw OAuthException.invalidRequest("invalid workstation authorization request");
      }
      if (client.cli()) {
        if (audience != null && !audience.isBlank()) {
          // The CLI's audiences are qits.idp.cli.audiences and nothing else. Refusing the parameter
          // rather than ignoring it keeps the answer honest: a tool that asked for one and silently
          // got another list would have no way to notice.
          throw OAuthException.invalidRequest("qits-cli does not choose its own audience");
        }
      } else if (!isAcceptedWorkstationAudience(audience)) {
        throw OAuthException.invalidRequest("invalid workstation authorization request");
      }
      WorkstationCredentials.requireChallenge(codeChallenge);

      Optional<Sessions.Live> session = sessions.resolve(sessionToken);
      if (session.isEmpty()) {
        return Response.seeOther(signIn(uriInfo)).build();
      }
      WorkstationCredentials.AuthorizationCode code =
          workstations.authorize(client, session.get().userId(), redirectUri, codeChallenge);
      return Response.seeOther(withParams(callback, "code", code.value(), state)).build();
    } catch (OAuthException refused) {
      if (!reportable) {
        throw refused;
      }
      return Response.seeOther(withParams(callback, "error", refused.error(), state)).build();
    }
  }

  /**
   * One signed-in device, as the account's own page reads it.
   *
   * <p>{@code kind} is what the page renders, and it is resolved HERE rather than in the browser:
   * the client ids are configuration, so a page that matched on {@code "qits-cli"} would be a
   * second copy of a deployment's setting and would silently mislabel an installation that renamed
   * one. A family whose client id is no longer configured at all keeps its id and reports {@code
   * unknown} — it is still the person's to revoke, which is the only thing the page needs of it.
   */
  public record Device(
      UUID id,
      String clientId,
      String kind,
      java.time.Instant createdAt,
      java.time.Instant expiresAt,
      java.time.Instant revokedAt) {}

  /** List revocable public-client grants for the signed-in account. */
  @GET
  @Path("/api/devices")
  public java.util.List<Device> devices(@CookieParam(SessionCookie.NAME) String sessionToken) {
    return workstations.list(requireSession(sessionToken).userId()).stream()
        .map(
            family ->
                new Device(
                    family.id(),
                    family.clientId(),
                    publicClients
                        .byId(family.clientId())
                        .map(client -> client.kind().name().toLowerCase(java.util.Locale.ROOT))
                        .orElse("unknown"),
                    family.createdAt(),
                    family.expiresAt(),
                    family.revokedAt()))
        .toList();
  }

  /**
   * The name this listing had when a workstation was the only thing it could hold.
   *
   * <p>Kept working rather than redirected: it is a cross-repository contract, and the answer is
   * the same one — every entry now carries its {@code clientId}, so a reader that ignores the field
   * sees exactly what it saw before plus the CLI's own rows.
   */
  @GET
  @Path("/api/workstations")
  public java.util.List<Device> list(@CookieParam(SessionCookie.NAME) String sessionToken) {
    return devices(sessionToken);
  }

  /** Revoke a grant. A foreign id is indistinguishable from no such grant. */
  @DELETE
  @Path("/api/devices/{familyId}")
  public Response revokeDevice(
      @CookieParam(SessionCookie.NAME) String sessionToken,
      @jakarta.ws.rs.PathParam("familyId") UUID familyId) {
    if (!workstations.revoke(requireSession(sessionToken).userId(), familyId)) {
      throw OAuthException.notFound("signed-in device not found");
    }
    return Response.noContent().build();
  }

  /** The older spelling of the revoke above, kept for the same reason the listing is. */
  @DELETE
  @Path("/api/workstations/{familyId}")
  public Response revoke(
      @CookieParam(SessionCookie.NAME) String sessionToken,
      @jakarta.ws.rs.PathParam("familyId") UUID familyId) {
    return revokeDevice(sessionToken, familyId);
  }

  /**
   * A workstation's {@code audience} parameter, checked against three values it may legitimately
   * name (C2 of {@code service-client-identity-plan.md}): none at all (the ordinary case: {@code
   * qits-bootstrap login} does not name one), the old githost value it always accepted, or the
   * platform-wide one every minted workstation token now also carries. Anything else is refused, as
   * before.
   */
  private boolean isAcceptedWorkstationAudience(String audience) {
    return audience == null
        || audience.isBlank()
        || githostAudience.equals(audience)
        || TokenService.PLATFORM_AUDIENCE.equals(audience);
  }

  private Sessions.Live requireSession(String sessionToken) {
    return sessions
        .resolve(sessionToken)
        .orElseThrow(() -> AuthException.invalidCredentials("a signed-in session is required"));
  }

  // --- where a browser is sent ------------------------------------------------------------------

  /**
   * The sign-in page, carrying this very request back as its return location.
   *
   * <p>The query string is forwarded RAW — it is the caller's own PKCE challenge, state and
   * redirect URI, and re-encoding parameter by parameter would be a second parser to keep in step
   * with the one above. {@link UriBuilder} escapes it once as a parameter value, the login page
   * hands it back to {@code /api/auth/return-location}, and {@link BrowserSso} decides whether the
   * authority may receive a browser at all. This one can: it is the canonical origin, which that
   * class refuses to start without on its own allow-list.
   */
  private URI signIn(UriInfo uriInfo) {
    String query = uriInfo.getRequestUri().getRawQuery();
    String here = prefix() + "/authorize" + (query == null || query.isBlank() ? "" : "?" + query);
    return UriBuilder.fromUri(browserSso.canonicalOrigin() + prefix() + LOGIN_PAGE_PATH)
        .queryParam("return_host", browserSso.canonicalAuthority())
        .queryParam("return_path", here)
        .build();
  }

  private static URI withParams(URI callback, String name, String value, String state) {
    UriBuilder built = UriBuilder.fromUri(callback).queryParam(name, value);
    if (state != null) {
      built.queryParam("state", state);
    }
    return built.build();
  }

  /**
   * The redirect target this client may use, as an exact match.
   *
   * <p>The CLI's own page is compared against strings BUILT FROM CONFIGURATION — never assembled
   * from anything in the request — so there is no spelling of {@code redirect_uri} that can widen
   * it. Two spellings are accepted because this installation answers on two addresses: the origin a
   * browser reaches ({@link PlatformDomain#canonicalOrigin}, derived from the stated domain, which
   * is what the person's browser will actually load) and the endpoint base the discovery document
   * advertises. The ISSUER is not one of them: it is an identifier with no path, and {@code
   * <issuer>/connect/cli} names no page this service serves.
   *
   * <p>A loopback URI stays allowed for both clients, under the rules it always had.
   */
  private URI redirectTarget(PublicClient client, String raw) {
    if (raw == null || raw.isBlank()) {
      throw OAuthException.invalidRequest("redirect_uri is required");
    }
    if (client.cli() && cliPages().contains(raw)) {
      return URI.create(raw);
    }
    return loopbackRedirect(raw);
  }

  /**
   * Every exact spelling of the code page this installation answers to.
   *
   * <p>Two, because a client may have arrived at either and a {@code redirect_uri} is matched by
   * exact string: the browser origin, and the ADDRESS the discovery document advertises. The issuer
   * spelling that used to be a third went with qits-730: the issuer is now {@code
   * https://idp.qits.<domain>} with no {@code /idp} path, so {@code <issuer>/connect/cli} is not a
   * page, and on a public installation the canonical origin entry already is the page it would
   * have named.
   */
  private Set<String> cliPages() {
    Set<String> pages = new LinkedHashSet<>();
    pages.add(browserSso.canonicalOrigin() + prefix() + CLI_PAGE_PATH);
    pages.add(issuer.endpointBase() + CLI_PAGE_PATH);
    return pages;
  }

  /**
   * This service's own path prefix, taken from the endpoint base rather than from {@code
   * quarkus.rest.path} — the same string by construction, because the endpoint base is the
   * documented base of every endpoint the discovery document advertises, and one source cannot
   * drift from itself.
   *
   * <p>It used to be read off the issuer, which held only while the issuer WAS that base. It is not
   * any more: the issuer is an identifier this service is known by and the base is the address it
   * answers on. Both carried {@code /idp} until qits-730 spelled the issuer without a path, which
   * is exactly when reading the prefix off it would have become a live bug.
   */
  private String prefix() {
    String path = URI.create(issuer.endpointBase()).getRawPath();
    return path == null || "/".equals(path) ? "" : path;
  }

  private static boolean isLoopback(URI uri) {
    String host = uri.getHost();
    return "127.0.0.1".equals(host) || "[::1]".equals(host) || "::1".equals(host);
  }

  /**
   * OAuth loopback redirects are intentionally narrow: HTTP only, a numeric loopback IP, an
   * ephemeral listener port, no query/user-info/fragment. Restricting the host prevents an open
   * redirect while the exact original spelling remains bound to the authorization code.
   */
  private static URI loopbackRedirect(String raw) {
    try {
      URI uri = new URI(raw);
      if (!"http".equals(uri.getScheme())
          || !isLoopback(uri)
          || uri.getPort() < 1
          || uri.getUserInfo() != null
          || uri.getRawQuery() != null
          || uri.getRawFragment() != null
          || uri.getRawPath() == null
          || uri.getRawPath().isBlank()) {
        throw OAuthException.invalidRequest("redirect_uri must be an exact HTTP loopback callback");
      }
      return uri;
    } catch (URISyntaxException badUri) {
      throw OAuthException.invalidRequest("redirect_uri must be a URI");
    }
  }
}
