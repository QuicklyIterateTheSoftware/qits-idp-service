package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.ClaimNames;
import eu.wohlben.qits.idp.control.Issuer;
import eu.wohlben.qits.idp.control.Jwks;
import eu.wohlben.qits.idp.control.SigningKeys;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
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

  /**
   * The discovery document. The {@code issuer} member is the derived {@code
   * https://idp.qits.<domain>} ({@link Issuer#url()}) and every endpoint
   * is derived from {@code qits.idp.endpoint-base} — an identifier and an address, which on this
   * platform are different strings. Deriving the endpoints from the issuer is what advertised a
   * {@code jwks_uri} on the deleted plane's bare alias; see {@link Issuer} for the whole of it.
   *
   * <p>What is NOT here is as deliberate as what is: no {@code authorization_endpoint}, no {@code
   * userinfo_endpoint}, no {@code scopes_supported}. Phase 1 issues machine tokens through one
   * grant; the browser-facing half arrives in phase 3 and adds its members then.
   */
  @GET
  @Path("/.well-known/openid-configuration")
  public Map<String, Object> discovery() {
    // LinkedHashMap: this document is read by people debugging a consumer at least as often as by
    // the consumer, and member order is what makes it scannable.
    Map<String, Object> document = new LinkedHashMap<>();
    document.put("issuer", issuer.url());
    document.put("authorization_endpoint", issuer.authorizationEndpoint());
    document.put("token_endpoint", issuer.tokenEndpoint());
    document.put("jwks_uri", issuer.jwksUri());
    document.put("grant_types_supported", List.of("client_credentials", "authorization_code", "refresh_token"));
    document.put(
        "token_endpoint_auth_methods_supported",
        List.of("client_secret_basic", "client_secret_post", "none"));
    document.put("response_types_supported", List.of("code"));
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
