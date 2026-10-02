package eu.wohlben.qits.idp.error;

/**
 * A token-endpoint refusal in the shape RFC 6749 §5.2 requires: an {@code error} code, a human
 * {@code error_description}, and the status the code is answered with.
 *
 * <p>Framework-free like the siblings' domain exceptions — the HTTP response is assembled in
 * {@code service} by the mapper.
 *
 * <p>The descriptions are written for the operator reading the caller's log, and are deliberately
 * coarse: which of "unknown client", "no secret configured" and "wrong secret" happened is not
 * something the caller is told.
 */
public class OAuthException extends RuntimeException {

  private final String error;
  private final int statusCode;

  private OAuthException(String error, int statusCode, String description) {
    super(description);
    this.error = error;
    this.statusCode = statusCode;
  }

  /** The RFC 6749 error code, the {@code error} member of the response body. */
  public String error() {
    return error;
  }

  public int statusCode() {
    return statusCode;
  }

  /** Malformed request: a missing parameter, or client credentials presented two ways at once. */
  public static OAuthException invalidRequest(String description) {
    return new OAuthException("invalid_request", 400, description);
  }

  /**
   * Client authentication failed — unknown id, no secret configured, or the wrong secret. 401,
   * because it is authentication that failed.
   */
  public static OAuthException invalidClient(String description) {
    return new OAuthException("invalid_client", 401, description);
  }

  /**
   * A bearer was presented and is not one this idp issued and still honours — bad signature, wrong
   * issuer or audience, expired, or not a JWT at all (RFC 6750 §3.1). 401, like {@link
   * #invalidClient}: it is authentication that failed.
   */
  public static OAuthException invalidToken(String description) {
    return new OAuthException("invalid_token", 401, description);
  }

  public static OAuthException unsupportedGrantType(String description) {
    return new OAuthException("unsupported_grant_type", 400, description);
  }

  public static OAuthException invalidGrant(String description) {
    return new OAuthException("invalid_grant", 400, description);
  }

  /** RFC 8707: the requested {@code audience} is not one this client may ask for. */
  public static OAuthException invalidTarget(String description) {
    return new OAuthException("invalid_target", 400, description);
  }

  /**
   * The caller authenticated and still may not do this — a commissioned client asking to
   * commission another. 403, because it is authorization that failed, and the code is RFC 6749's
   * own {@code access_denied} so the commission API answers in one shape with the token endpoint.
   */
  public static OAuthException accessDenied(String description) {
    return new OAuthException("access_denied", 403, description);
  }

  /**
   * No such commissioned client — <b>or</b> one the caller does not own. Deliberately one answer
   * for both: an owner must not be able to discover which contexts other services hold by asking
   * to delete their credentials.
   */
  public static OAuthException notFound(String description) {
    return new OAuthException("not_found", 404, description);
  }

  /**
   * The service-client management API's one extra case: a create where a database row already
   * exists, or a delete of the caller's own row. 409, because the request is well formed and the
   * caller is allowed here — the state of the row is what stands in the way.
   */
  public static OAuthException conflict(String description) {
    return new OAuthException("conflict", 409, description);
  }
}
