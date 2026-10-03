package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpRegisterToken;
import eu.wohlben.qits.idp.error.AuthException;
import eu.wohlben.qits.idp.persistence.IdpRegisterTokenRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.UUID;
import org.jboss.logging.Logger;

/**
 * One-time registration tickets: minting one, and spending one.
 *
 * <p><b>A token is a row, and the plaintext exists once.</b> It is minted through the API, printed
 * by the bootstrap in its closing report, and stored here as a {@code sha-256:} fingerprint — the
 * same scheme, the same helper and the same argument as a commissioned client's secret, because it
 * is the same kind of value: 256 bits of {@link RandomSecret} that nobody chose and nobody can
 * guess. Deliberately <b>not</b> a log line: this service's logs ship to qits-observability, and a
 * credential must not ride the log plane.
 *
 * <p><b>Only a service client may mint.</b> That check lives at the boundary, on the caller's
 * credentials, and it is the commissioning rule reused verbatim: a credential handed to a build step
 * or an agent container must not be able to produce platform accounts.
 *
 * <p><b>There is no expiry.</b> A register token is spent or it is not, and the operator who minted
 * it is the one holding it — a deadline would only turn a bootstrap interrupted by lunch into a
 * re-bootstrap. Revocation, if it is ever wanted, is deleting the row.
 */
@ApplicationScoped
public class RegisterTokens {

  private static final Logger LOG = Logger.getLogger(RegisterTokens.class);

  /** A freshly minted token, with the plaintext that exists only in this answer. */
  public record Minted(UUID id, String token, Instant createdAt) {}

  @Inject IdpRegisterTokenRepository tokens;

  /**
   * Mint a token for whoever asked.
   *
   * @param mintedBy the client id of the caller, already authenticated and already known to be a
   *     service client
   */
  public Minted mint(String mintedBy) {
    String plaintext = RandomSecret.credential();
    IdpRegisterToken row = new IdpRegisterToken();
    row.id = UUID.randomUUID();
    row.tokenHash = ClientSecret.hash(plaintext);
    row.mintedBy = mintedBy;
    row.createdAt = Instant.now();

    // A bare insert, so DbRetry.inNewTx rather than DbRetry.call — the same reasoning as a
    // commission: the retry has to own the transaction boundary to know which failures certainly
    // did not commit, and a lost commit acknowledgement is reported rather than repeated. Repeating
    // it would leave a second register token in the store that nobody was ever handed, which is one
    // unaccounted-for account waiting to happen.
    DbRetry.runInNewTx("mint an idp register token", () -> tokens.persist(row));

    LOG.infof(
        "minted register token %s for %s", row.id, LoggableClientId.of(mintedBy));
    return new Minted(row.id, plaintext, row.createdAt);
  }

  /**
   * Check that this plaintext is a token that has not been spent, without spending it.
   *
   * <p>The register-options call does this <b>before any ceremony state is created</b>: a browser
   * that cannot register must not be handed a challenge and a cookie first and refused after, and
   * an authenticator must not be asked to make a key that will be thrown away.
   *
   * @throws AuthException {@code invalid_credentials} (401) for an absent, unknown or spent token
   */
  public void requireUnspent(String plaintext) {
    DbRetry.runInNewTx("check an idp register token", () -> requireUnspentRow(plaintext));
  }

  // --- inside the caller's transaction, for Registrations ------------------------------------

  /** {@link #requireUnspent}, in the caller's transaction. */
  IdpRegisterToken requireUnspentRow(String plaintext) {
    if (plaintext == null || plaintext.isBlank()) {
      throw AuthException.invalidCredentials("a register token is required");
    }
    IdpRegisterToken row = tokens.findByTokenHash(ClientSecret.hash(plaintext));
    if (row == null) {
      LOG.warn("registration refused: the presented register token is not one this idp minted");
      throw AuthException.invalidCredentials("that register token is not valid");
    }
    if (row.consumedAt != null) {
      LOG.warnf("registration refused: register token %s has already been used", row.id);
      throw AuthException.invalidCredentials("that register token is not valid");
    }
    return row;
  }

  /**
   * Spend the token on this account, in the caller's transaction.
   *
   * <p>The consumption and the account's creation commit together, which is the whole reason
   * {@link Registrations} holds one transaction: there is no state in which a token is spent and no
   * account exists, and none in which an account exists and the token is still good for a second.
   */
  void consumeRow(IdpRegisterToken row, UUID createdUserId) {
    row.consumedAt = Instant.now();
    row.createdUserId = createdUserId;
  }
}
