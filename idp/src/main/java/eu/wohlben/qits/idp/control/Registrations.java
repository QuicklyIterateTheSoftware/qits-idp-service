package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpRegisterToken;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.error.AuthException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Turning a register token into an account — the one operation in this service that writes five
 * tables and must write all of them or none.
 *
 * <p>This is the only class that knows {@link Users}, {@link RegisterTokens} and {@link Sessions}
 * all exist, the same way {@link ClientRegistry} is the only class that knows both halves of the
 * client registry do. Each of those three does one thing at a time and owns its own transaction; a
 * registration is the composite, so the boundary moves here and theirs is not used.
 *
 * <p><b>What "all or none" is protecting.</b> Five writes go in: the account, its factor (a passkey
 * or a password), the token's consumption, the two bootstrap roles, and the session. Every partial
 * outcome is a bad one, and two are genuinely dangerous — a token spent against an account that was
 * never created leaves an installation with no way in and a one-time ticket already gone, and an
 * account created without the token being spent leaves the ticket good for a second account nobody
 * asked for. One transaction is what makes both unreachable.
 *
 * <p><b>And it is {@link DbRetry#inNewTx}, not {@link DbRetry#call}.</b> The retry has to own the
 * boundary so that it knows which failures certainly did not commit; a commit whose acknowledgement
 * was lost is reported rather than repeated, because repeating this one would try to insert an
 * account that is already there and fail on the unique name — a confusing answer to a registration
 * that in fact worked. The same reasoning as a commission, one table wider.
 */
@ApplicationScoped
public class Registrations {

  private static final Logger LOG = Logger.getLogger(Registrations.class);

  @Inject Users users;

  @Inject RegisterTokens tokens;

  @Inject Sessions sessions;

  /**
   * Spend a register token on a new account and log it straight in.
   *
   * <p>Exactly one factor arrives: an authenticator the WebAuthn ceremony has already verified, or
   * a password. Since qits-1260 the password is never the registrant's: the boundary generates it
   * ({@link RandomSecret#password()}) and refuses one sent in the body, and it reaches the store
   * only as its hash, through {@link Users}' ordinary path. Nothing here logs it.
   *
   * @param plaintextToken the token as the operator was handed it
   * @param username the requested login name, already normalised
   * @param authenticator the verified passkey, or null when registering with a password
   * @param password the idp-generated password, or null when registering with a passkey
   * @throws AuthException {@code invalid_credentials} (401) for a token that is unknown or already
   *     spent; {@code invalid_request} (400) for a name that is taken or a body naming no factor
   */
  public Sessions.Opened withToken(
      String plaintextToken,
      String username,
      Users.NewAuthenticator authenticator,
      String password) {
    if (authenticator == null && password == null) {
      throw AuthException.invalidRequest(
          "a registration needs either a verified authenticator or a password");
    }
    Sessions.Opened opened =
        DbRetry.inNewTx(
            "register an idp user",
            () -> {
              // The token is re-checked inside the transaction even though register-options checked
              // it minutes ago: between the two calls it may have been spent by whoever else holds
              // the same printed string, and the row read here is the row consumed below.
              IdpRegisterToken token = tokens.requireUnspentRow(plaintextToken);
              IdpUser user = users.createRow(username, password);
              if (authenticator != null) {
                users.addCredentialRow(user.id, authenticator);
              }
              users.grantRows(user.id, Users.BOOTSTRAP_ROLES);
              tokens.consumeRow(token, user.id);
              return sessions.openRow(users.accountOf(user));
            });
    LOG.infof(
        "registered user %s with %s, roles %s",
        opened.session().username(),
        authenticator != null ? "a passkey" : "a password",
        opened.session().roles());
    return opened;
  }
}
