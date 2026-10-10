package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.PublicClients;
import eu.wohlben.qits.idp.control.PublicClients.PublicClient;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.control.TokenService.IssuedToken;
import eu.wohlben.qits.idp.control.WorkstationCredentials;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import org.eclipse.microprofile.openapi.annotations.Operation;

/**
 * The token endpoint: {@code POST /idp/token}, {@code application/x-www-form-urlencoded}, RFC 6749
 * {@code client_credentials}.
 *
 * <p>This class does the wire work only — pulling the client's credentials out of whichever of the
 * two supported places they arrived in, and dressing the result as a token response. Who the client
 * is and what it may have is {@link TokenService}'s.
 *
 * <p>The path is relative to {@code quarkus.rest.path=/idp}. It is a cross-repo contract: every
 * consumer reaches it through the {@code token_endpoint} of the discovery document, which is
 * derived from the same issuer string, so the three cannot drift apart.
 */
@Path("/token")
public class IdpTokenController {

  private static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
  private static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
  private static final String GRANT_REFRESH_TOKEN = "refresh_token";

  @Inject TokenService tokenService;

  @Inject WorkstationCredentials workstations;

  @Inject PublicClients publicClients;

  /**
   * Client authentication is {@code client_secret_basic} or {@code client_secret_post}, never both
   * in one request — RFC 6749 §2.3 forbids it, and accepting both would make which one was checked
   * a question.
   *
   * <p>An {@code audience} parameter is accepted and ignored: every token's {@code aud} is {@code
   * ["qits-platform"]} (qits-163), so a caller that still names one gets that, not a refusal. It is
   * not declared here because nothing reads it.
   */
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(operationId = "issueToken")
  public Response token(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @FormParam("grant_type") String grantType,
      @FormParam("client_id") String clientIdParam,
      @FormParam("client_secret") String clientSecretParam,
      @FormParam("code") String code,
      @FormParam("redirect_uri") String redirectUri,
      @FormParam("code_verifier") String codeVerifier,
      @FormParam("refresh_token") String refreshToken) {

    if (grantType == null || grantType.isBlank()) {
      throw OAuthException.invalidRequest("grant_type is required");
    }
    if (GRANT_AUTHORIZATION_CODE.equals(grantType)) {
      PublicClient client = publicClient(clientIdParam, clientSecretParam, authorization);
      WorkstationCredentials.RefreshGrant grant =
          workstations.exchangeCode(client, code, redirectUri, codeVerifier);
      return tokenResponse(mint(client, grant), grant);
    }
    if (GRANT_REFRESH_TOKEN.equals(grantType)) {
      PublicClient client = publicClient(clientIdParam, clientSecretParam, authorization);
      WorkstationCredentials.RefreshGrant grant = workstations.refresh(client, refreshToken);
      return tokenResponse(mint(client, grant), grant);
    }
    if (!GRANT_CLIENT_CREDENTIALS.equals(grantType)) {
      throw OAuthException.unsupportedGrantType(
          "supported grants are client_credentials, authorization_code, and refresh_token");
    }

    BasicCredentials credentials = credentials(authorization, clientIdParam, clientSecretParam);
    return tokenResponse(
        tokenService.clientCredentials(credentials.clientId(), credentials.secret()), null);
  }

  /**
   * Which mint a spent grant reaches — the whole of what the two public clients differ by here.
   *
   * <p>It is the CLIENT that decides, not the grant: {@link WorkstationCredentials} has already
   * refused a code or a refresh token whose row names the other one, so by this line the two facts
   * agree and reading either would give the same answer.
   */
  private IssuedToken mint(PublicClient client, WorkstationCredentials.RefreshGrant grant) {
    // The dev SPA gets the CLI's token on purpose: it is the same person, signed in the same way.
    return client.personToken()
        ? tokenService.cli(grant.userId())
        : tokenService.workstation(grant.userId());
  }

  /**
   * RFC 6749 §5.1 response, with a refresh token only for the public-client grants.
   *
   * <p><b>{@code refresh_expires_in} rides beside every {@code refresh_token}</b> and is not in RFC
   * 6749 — the spec gives a client no way to learn when its refresh credential dies, so a tool can
   * only discover the end of a session by being refused mid-command. One extra member lets {@code
   * qits login} say "this sign-in ends on Friday" instead. It is the same additive shape several
   * providers settled on, and a client that ignores it is unaffected.
   */
  private static Response tokenResponse(
      IssuedToken issued, WorkstationCredentials.RefreshGrant grant) {
    // LinkedHashMap so the response reads in the order RFC 6749 §5.1 lists the members.
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("access_token", issued.accessToken());
    body.put("token_type", "Bearer");
    body.put("expires_in", issued.expiresInSeconds());
    if (grant != null) {
      body.put("refresh_token", grant.refreshToken());
      body.put("refresh_expires_in", grant.refreshExpiresInSeconds());
    }
    return Response.ok(body)
        // RFC 6749 §5.1: a token response is never cached, anywhere.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * A public client authenticates by PKCE, never by an empty or shared secret.
   *
   * <p>Both of them: a request carrying an {@code Authorization} header or a {@code client_secret}
   * is refused whichever id it names, because a public client that could also present a secret
   * would be two authentication models on one grant and the weaker one would be the one that
   * decided.
   */
  private PublicClient publicClient(String clientId, String secret, String authorization) {
    if (authorization != null && !authorization.isBlank()) {
      throw OAuthException.invalidRequest("a public client must not use Authorization");
    }
    if (secret != null && !secret.isBlank()) {
      throw OAuthException.invalidClient("a public client is required");
    }
    return publicClients
        .byId(clientId)
        .orElseThrow(() -> OAuthException.invalidClient("a public client is required"));
  }

  /**
   * The client's credentials, from the Authorization header or the form — not both, and at least
   * one. The header half is {@link BasicCredentials}, which the commission API reads too.
   */
  private static BasicCredentials credentials(
      String authorization, String clientIdParam, String clientSecretParam) {
    BasicCredentials basic = BasicCredentials.parse(authorization);
    boolean postPresent = clientIdParam != null && !clientIdParam.isBlank();
    if (basic != null && postPresent) {
      throw OAuthException.invalidRequest(
          "client credentials must be presented once, not both in the header and in the form");
    }
    if (basic != null) {
      return basic;
    }
    if (!postPresent) {
      throw OAuthException.invalidClient("client authentication is required");
    }
    return new BasicCredentials(clientIdParam, clientSecretParam);
  }
}
