package eu.wohlben.qits.idp.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/**
 * The answer to {@code POST /idp/api/auth/register}: {@link SessionView}'s four fields, flattened,
 * plus the {@code password} the idp generated (qits-1260).
 *
 * <p><b>The idp sets the password, never the registrant.</b> A token registration without a passkey
 * gets a random one ({@code RandomSecret.password()}), stored only as its hash and answered here
 * <b>once</b>: no endpoint reads it back, nothing logs it, and the response is {@code no-store}. A
 * passkey registration, and adding a passkey from a live session, answer no password at all — the
 * member is then <i>absent</i>, not {@code null} ({@link JsonInclude.Include#NON_NULL}), so a client
 * tells the two cases apart by its presence.
 *
 * <p>A record of its own rather than a nullable member on {@link SessionView}, because that record
 * is also the edge's introspection answer and a login's, and neither may ever grow a password field.
 */
public record RegisteredView(
    String userId,
    String username,
    List<String> roles,
    String expiresAt,
    @JsonInclude(JsonInclude.Include.NON_NULL) String password) {

  static RegisteredView of(SessionView session, String password) {
    return new RegisteredView(
        session.userId(), session.username(), session.roles(), session.expiresAt(), password);
  }

  /** Never the password: a record's generated {@code toString} would put it in any log line. */
  @Override
  public String toString() {
    return "RegisteredView[userId=" + userId + ", username=" + username + "]";
  }
}
