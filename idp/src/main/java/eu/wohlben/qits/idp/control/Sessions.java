package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpSession;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.persistence.IdpSessionRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Browser sessions: opening one, resolving one, ending one.
 *
 * <p><b>The cookie is opaque and the row is the truth.</b> A session's value is 256 random bits and
 * nothing else — no user id encoded in it, no signature to verify, no way to tell a valid one from
 * a made-up one without asking this store. What is stored is a {@code sha-256:} fingerprint, so a
 * dump of the idp's database logs nobody in, exactly as a dump of {@code idp_client} mints nothing.
 *
 * <p><b>Why not a signed cookie the edge could verify offline.</b> A JWT in the cookie would let the
 * edge check a session against the JWKS it already holds, with no call here at all — and it would
 * cost revocation, because there is no revocation list and validation would be offline. The edge
 * introspects and caches instead: the same shape as its Basic-credential cache, logout is a row
 * update, and the only thing bought back is a lag of seconds. That trade is the plan's decision.
 *
 * <p><b>Expiry is absolute.</b> A session dies {@code qits.idp.session-ttl} after it was opened,
 * whatever the user did in between, and it never slides. "Remember me" is {@link Devices}
 * (qits-1944): a remembered browser holds a second, rotating credential that opens a <i>new</i>
 * session here when the old one has died, and every session it opens names it ({@code device_id}),
 * so revoking the device ends them.
 */
@ApplicationScoped
public class Sessions {

  /**
   * How long a session lives from the moment it is opened.
   *
   * <p>Twelve hours is a working day plus the evening: long enough that an operator is not asked to
   * re-authenticate mid-task, short enough that a browser left on a machine somewhere stops being a
   * way in by the next morning. It is a deployment's to override; there is nothing about the number
   * that this repository knows better than an installation does.
   */
  @ConfigProperty(name = "qits.idp.session-ttl")
  Duration sessionTtl;

  /**
   * A live session, as the cookie's holder and the edge's introspection both see it.
   *
   * @param deviceId the remembered device it was opened through, or null (qits-1944). Never part
   *     of what introspection answers.
   */
  public record Live(
      UUID sessionId,
      UUID userId,
      String username,
      List<String> roles,
      Instant expiresAt,
      UUID deviceId) {}

  /** A freshly opened session, with the cookie value that exists only in this answer. */
  public record Opened(String token, Live session) {}

  @Inject IdpSessionRepository sessions;

  @Inject IdpUserRepository users;

  @Inject Users accounts;

  /** Open a session for an account that has just authenticated. */
  public Opened open(Users.Account account) {
    return DbRetry.inNewTx("open an idp session", () -> openRow(account));
  }

  /**
   * The live session behind this cookie value, or empty.
   *
   * <p>Empty for an absent cookie, an unknown value, a revoked session and an expired one alike —
   * the edge and the session-guarded routes all need one answer, and which of the four it was is
   * not something a caller is told. <b>Nothing is written here</b>: resolving a session is a read,
   * so an expired row is left to be swept rather than deleted on the way past.
   */
  public Optional<Live> resolve(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    return DbRetry.inNewTx(
        "resolve an idp session",
        () -> {
          IdpSession row = sessions.findByTokenHash(ClientSecret.hash(token));
          if (row == null || !isLive(row)) {
            return Optional.empty();
          }
          IdpUser user = users.findById(row.userId);
          if (user == null) {
            return Optional.empty();
          }
          return Optional.of(
              new Live(
                  row.id,
                  user.id,
                  user.username,
                  accounts.accountOf(user).roles(),
                  row.expiresAt,
                  row.deviceId));
        });
  }

  /**
   * End the session behind this cookie value.
   *
   * <p>The row is <b>revoked, not deleted</b>, so a session that ended stays distinguishable from
   * one that never existed — which is what an account page listing sessions, and any later audit of
   * one, needs. Logging out twice is not an error.
   *
   * @return false when there was nothing live to end
   */
  public boolean revoke(String token) {
    if (token == null || token.isBlank()) {
      return false;
    }
    return DbRetry.inNewTx(
        "revoke an idp session",
        () -> {
          IdpSession row = sessions.findByTokenHash(ClientSecret.hash(token));
          if (row == null || !isLive(row)) {
            return false;
          }
          row.revokedAt = Instant.now();
          return true;
        });
  }

  // --- inside the caller's transaction, for Registrations ------------------------------------

  /**
   * Revoke every session a device opened, in the caller's transaction — {@link Devices} revokes a
   * device and its sessions in one boundary (qits-1944).
   */
  void revokeForDeviceRow(UUID deviceId, Instant at) {
    sessions.revokeForDevice(deviceId, at);
  }

  /** {@link #open}, in the caller's transaction — a registration opens its session inside one. */
  Opened openRow(Users.Account account) {
    return openRow(account, null);
  }

  /**
   * {@link #openRow(Users.Account)}, naming the remembered device the session is opened through, or
   * null for none (qits-1944). {@link Devices} calls it inside its own transaction.
   */
  Opened openRow(Users.Account account, UUID deviceId) {
    String token = RandomSecret.credential();
    IdpSession row = new IdpSession();
    row.id = UUID.randomUUID();
    row.tokenHash = ClientSecret.hash(token);
    row.userId = account.id();
    // TRUNCATED TO WHAT THE COLUMN HOLDS. `Instant.now()` has nanosecond resolution here and
    // `timestamp(6)` has microsecond, so an untruncated value would be reported one way in the
    // answer to the login that created it and another way by every introspection afterwards —
    // the same session with two deadlines, differing in the last three digits. Measured
    // 2026-08-14; it is cosmetic until something compares the two, and then it is a bug report.
    row.createdAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
    row.expiresAt = row.createdAt.plus(sessionTtl);
    row.deviceId = deviceId;
    sessions.persist(row);
    return new Opened(
        token,
        new Live(
            row.id, account.id(), account.username(), account.roles(), row.expiresAt, deviceId));
  }

  /** How long a cookie may be kept — the same number as the row's deadline, by construction. */
  public Duration ttl() {
    return sessionTtl;
  }

  /** Neither revoked nor past its deadline. Both are compared against the clock, not a constraint. */
  private static boolean isLive(IdpSession row) {
    return row.revokedAt == null && row.expiresAt.isAfter(Instant.now());
  }
}
