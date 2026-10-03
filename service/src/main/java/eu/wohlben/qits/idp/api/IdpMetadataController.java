package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.ClaimNames;
import eu.wohlben.qits.idp.control.Issuer;
import eu.wohlben.qits.idp.control.Jwks;
import eu.wohlben.qits.idp.control.SigningKeys;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The two documents a consumer needs before it can validate anything: the discovery document and
 * the JWKS. Both are public and unauthenticated — that is what they are for.
 *
 * <p>Paths are relative to {@code quarkus.rest.path=/idp}, so this class serves {@code
 * /idp/.well-known/openid-configuration} and {@code /idp/jwks}. A consumer configured with this
 * idp's auth-server-url finds the first by OIDC's own derivation and follows the document to the
 * rest.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class IdpMetadataController {

  @Inject Issuer issuer;

  @Inject SigningKeys signingKeys;

  @Inject BrowserSso browserSso;

  /**
   * The discovery document. The {@code issuer} member is the derived {@code
   * https://idp.qits.<domain>} ({@link Issuer#url()}) and, for an in-network caller, every endpoint
   * is derived from {@code qits.idp.endpoint-base} — an identifier and an address, which on this
   * platform are different strings. Deriving the endpoints from the issuer is what advertised a
   * {@code jwks_uri} on the deleted plane's bare alias; see {@link Issuer} for the whole of it.
   *
   * <p><b>The endpoints follow the name the caller used.</b> A caller that reached this service on
   * its public name ({@link BrowserSso#canonicalOrigin()}, e.g. {@code https://idp.qits.<domain>})
   * is told the public endpoints, because the in-network address means nothing outside qits-net. A
   * browser page doing PKCE from a developer's machine is that caller. Every other caller — a
   * service on qits-net dialling the address — is told the address, as before. The request only
   * picks between these two derived values; no spelling of {@code Host} puts anything else in the
   * document.
   *
   * <p>What is NOT here is as deliberate as what is: no {@code userinfo_endpoint}, no {@code
   * scopes_supported}. This service issues no id_tokens and takes no scope.
   */
  @GET
  @Path("/.well-known/openid-configuration")
  public Map<String, Object> discovery(
      @HeaderParam(HttpHeaders.HOST) String host,
      @HeaderParam("X-Forwarded-Host") String forwardedHost) {
    String base = publicCaller(host, forwardedHost) ? publicBase() : issuer.endpointBase();
    // LinkedHashMap: this document is read by people debugging a consumer at least as often as by
    // the consumer, and member order is what makes it scannable.
    Map<String, Object> document = new LinkedHashMap<>();
    document.put("issuer", issuer.url());
    document.put("authorization_endpoint", base + "/authorize");
    document.put("token_endpoint", base + "/token");
    document.put("jwks_uri", base + "/jwks");
    document.put("grant_types_supported", List.of("client_credentials", "authorization_code", "refresh_token"));
    document.put(
        "token_endpoint_auth_methods_supported",
        List.of("client_secret_basic", "client_secret_post", "none"));
    document.put("response_types_supported", List.of("code"));
    // Every public client must use PKCE, and only S256 (IdpWorkstationController).
    document.put("code_challenge_methods_supported", List.of("S256"));
    document.put("subject_types_supported", List.of("public"));
    // OIDC names this member for id_tokens, which this service does not issue; it is the algorithm
    // of the access tokens it does issue, and consumers read it as the signing alg either way.
    document.put("id_token_signing_alg_values_supported", List.of(SigningKeys.ALGORITHM));
    document.put("claims_supported", claimsSupported());
    return document;
  }

  /** The public signing keys — every key that may have signed a token that is still alive. */
  @GET
  @Path("/jwks")
  public Map<String, Object> jwks() {
    return Jwks.document(signingKeys.published());
  }

  /** Whether the caller named this service by its public authority, in Host or X-Forwarded-Host. */
  private boolean publicCaller(String host, String forwardedHost) {
    return isCanonical(host) || isCanonical(firstOf(forwardedHost));
  }

  private boolean isCanonical(String raw) {
    String authority = BrowserSso.authority(raw);
    if (authority == null) {
      return false;
    }
    String canonical = browserSso.canonicalAuthority();
    String origin = browserSso.canonicalOrigin();
    String defaultPort = origin.startsWith("https://") ? ":443" : ":80";
    return authority.equals(canonical) || authority.equals(canonical + defaultPort);
  }

  private static String firstOf(String list) {
    return list == null ? null : list.split(",")[0].strip();
  }

  /**
   * The public origin plus this service's path prefix, taken from the endpoint base so the two
   * cannot disagree on it: {@code https://idp.qits.<domain>/idp}.
   */
  private String publicBase() {
    String path = URI.create(issuer.endpointBase()).getRawPath();
    return browserSso.canonicalOrigin() + (path == null || "/".equals(path) ? "" : path);
  }

  /** The registered claims every token carries, plus the structured ones a client may be granted. */
  private static List<String> claimsSupported() {
    List<String> claims =
        new ArrayList<>(
            List.of(
                "iss",
                "sub",
                "aud",
                "groups",
                "exp",
                "iat",
                "jti",
                "credential_type",
                "git_ref_pattern"));
    claims.addAll(ClaimNames.GRANTABLE);
    return List.copyOf(claims);
  }
}
