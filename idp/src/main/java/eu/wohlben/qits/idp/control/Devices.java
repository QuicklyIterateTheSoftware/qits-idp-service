package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpDevice;
import eu.wohlben.qits.idp.entity.IdpDeviceSecret;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.persistence.IdpDeviceRepository;
import eu.wohlben.qits.idp.persistence.IdpDeviceSecretRepository;
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
import org.jboss.logging.Logger;

/**
 * Remembered devices — "remember me" (qits-1944): a browser that asked at login to be remembered
 * holds a second credential, the {@code qits-device} cookie, which it spends for a fresh session
 * once its twelve-hour one has died.
 *
 * <p><b>A device is not a longer session.</b> The session is what the edge introspects on every
 * request; a device secret is presented to the idp alone, only to open a session, and it
 * <b>rotates on every use</b>: the secret spent is superseded and a new one is answered. A copy of
 * the cookie therefore stops working the moment either holder resumes with it, and the other
 * holder's next presentation is a spent secret — which is how a theft becomes visible.
 *
 * <p><b>What a spent secret means depends on how long ago it was spent.</b> Within {@code
 * qits.idp.device.reuse-grace} (thirty seconds) it is two tabs of one browser resuming at once,
 * both holding the cookie from before the first rotation landed: the loser is answered a session
 * and <i>no</i> new secret, so the browser keeps the winner's. Past the grace it is a copy somebody
 * else holds, and the whole device is revoked with every session it opened, logged as a warning.
 * The same fail-closed trade {@link WorkstationCredentials#refresh} makes for refresh tokens, with
 * the grace added because a browser, unlike a CLI, genuinely runs two requests at once.
 *
 * <p><b>Two deadlines.</b> {@code expires_at} is idle: each resume moves it to now + {@code
 * qits.idp.device.idle-ttl} (thirty days). {@code absolute_expires_at} is stamped once, {@code
 * qits.idp.device.absolute-ttl} (ninety days) after the login, and caps the idle one, so a device
 * used daily still ends on a fixed date and its owner signs in again.
 *
 * <p><b>The shape is {@link Sessions}' and {@link WorkstationCredentials}'.</b> Every public method
 * owns its transaction through {@link DbRetry}; the sessions it opens and revokes go through {@link
 * Sessions}' package-private {@code …Row} methods, inside that one boundary — a resume that
 * rotated the secret but opened no session would strand the browser with a cookie that opens
 * nothing. Secrets are {@link RandomSecret#credential()} and stored as {@link ClientSecret#hash},
 * exactly like a session's.
 */
@ApplicationScoped
public class Devices {

  private static final Logger LOG = Logger.getLogger(Devices.class);

  /** As long as the column allows. A label is the browser's User-Agent, shown and never parsed. */
  public static final int LABEL_LENGTH = 200;

  /** What a device whose login sent no User-Agent is called. */
  public static final String UNKNOWN_LABEL = "unknown device";

  /** How long a device lives unused: every resume moves its idle deadline this far ahead. */
  @ConfigProperty(name = "qits.idp.device.idle-ttl")
  Duration idleTtl;

  /** How long a device lives at most, from the login that remembered it, however often it is used. */
  @ConfigProperty(name = "qits.idp.device.absolute-ttl")
  Duration absoluteTtl;

  /** How long a just-spent secret still opens a session, unrotated: two tabs resuming at once. */
  @ConfigProperty(name = "qits.idp.device.reuse-grace")
  Duration reuseGrace;

  @Inject IdpDeviceRepository devices;

  @Inject IdpDeviceSecretRepository secrets;

  @Inject IdpUserRepository users;

  @Inject Users accounts;

  @Inject Sessions sessions;

  /** One live device, as its account's listing shows it. Never a secret. */
  public record Device(
      UUID id,
      String label,
      Instant createdAt,
      Instant lastUsedAt,
      Instant expiresAt,
      Instant absoluteExpiresAt) {}

  /**
   * A login that asked to be remembered: the device, its first secret, and the session the login
   * opened through it.
   *
   * @param secret the {@code qits-device} cookie's value; it exists only in this answer
   * @param absoluteExpiresAt the cookie's Max-Age is the time left until this
   */
  public record Remembered(
      UUID deviceId, String secret, Instant absoluteExpiresAt, Sessions.Opened session) {}

  /**
   * A resume that opened a session.
   *
   * @param secret the rotated {@code qits-device} value, or null when the spent one was presented
   *     within the grace and nothing rotated — the browser keeps the cookie it has
   */
  public record Resumed(Sessions.Opened session, String secret, Instant absoluteExpiresAt) {}

  /** Remember this browser for the account that just logged in, and open its session through it. */
  public Remembered remember(Users.Account account, String label) {
    return DbRetry.inNewTx(
        "remember an idp device",
        () -> {
          Instant now = now();
          IdpDevice row = new IdpDevice();
          row.id = UUID.randomUUID();
          row.userId = account.id();
          row.label = label(label);
          row.createdAt = now;
          row.lastUsedAt = now;
          row.absoluteExpiresAt = now.plus(absoluteTtl);
          row.expiresAt = earlier(now.plus(idleTtl), row.absoluteExpiresAt);
          devices.persist(row);
          String secret = newSecret(row.id, now);
          return new Remembered(
              row.id, secret, row.absoluteExpiresAt, sessions.openRow(account, row.id));
        });
  }

  /**
   * Spend a device secret for a fresh session.
   *
   * <p>Empty for an absent value, an unknown one, a device that is revoked or past either deadline,
   * an account that is gone — and for a replay, which also revokes the device and every session it
   * opened before this returns. One transaction, with the device row locked ({@code SELECT … FOR
   * UPDATE}), so two resumes of one device serialize and exactly one of them rotates.
   */
  public Optional<Resumed> resume(String secret) {
    if (secret == null || secret.isBlank()) {
      return Optional.empty();
    }
    Attempt attempt =
        DbRetry.inNewTx(
            "resume an idp device",
            () -> {
              IdpDeviceSecret presented = secrets.findById(ClientSecret.hash(secret));
              if (presented == null) {
                return Attempt.REFUSED;
              }
              IdpDevice device = devices.lock(presented.deviceId);
              Instant now = now();
              if (device == null || !isLive(device, now)) {
                return Attempt.REFUSED;
              }
              // Re-read under the lock: a resume that held it a moment ago may have just spent
              // this very secret, and the copy loaded above would not know.
              secrets.getEntityManager().refresh(presented);
              IdpUser user = users.findById(device.userId);
              if (user == null) {
                return Attempt.REFUSED;
              }
              Users.Account account = accounts.accountOf(user);
              if (presented.supersededAt == null) {
                presented.supersededAt = now;
                String next = newSecret(device.id, now);
                device.lastUsedAt = now;
                device.expiresAt = earlier(now.plus(idleTtl), device.absoluteExpiresAt);
                return Attempt.resumed(
                    new Resumed(
                        sessions.openRow(account, device.id), next, device.absoluteExpiresAt));
              }
              if (now.isBefore(presented.supersededAt.plus(reuseGrace))) {
                return Attempt.resumed(
                    new Resumed(sessions.openRow(account, device.id), null, device.absoluteExpiresAt));
              }
              // A secret spent longer ago than any two tabs could explain: a copy exists. Revoke,
              // and let the transaction COMMIT — throwing here would roll the revocation back.
              device.revokedAt = now;
              sessions.revokeForDeviceRow(device.id, now);
              return Attempt.replay(device.id, device.userId);
            });
    if (attempt.replayedDevice() != null) {
      LOG.warnf(
          "a spent device secret was presented again; device %s of user %s and its sessions are"
              + " revoked",
          attempt.replayedDevice(),
          attempt.replayedUser());
    }
    return Optional.ofNullable(attempt.resumed());
  }

  /** The account's live devices, most recently used first. */
  public List<Device> list(UUID userId) {
    return DbRetry.inNewTx(
        "list idp devices",
        () -> {
          Instant now = now();
          return devices.listForUser(userId).stream()
              .filter(row -> isLive(row, now))
              .map(
                  row ->
                      new Device(
                          row.id,
                          row.label,
                          row.createdAt,
                          row.lastUsedAt,
                          row.expiresAt,
                          row.absoluteExpiresAt))
              .toList();
        });
  }

  /**
   * Revoke one of the account's live devices and every session it opened. A foreign id, an unknown
   * one and a device that is already dead are the same answer.
   *
   * @return false when the account has no such live device
   */
  public boolean revoke(UUID userId, UUID deviceId) {
    if (userId == null || deviceId == null) {
      return false;
    }
    return DbRetry.inNewTx("revoke an idp device", () -> revokeRow(userId, deviceId));
  }

  /**
   * Revoke the device this secret belongs to — current or spent — if it is one of the account's.
   * Logout calls it with the {@code qits-device} cookie the browser sent.
   *
   * @return false when there was no such live device of this account
   */
  public boolean revokeBySecret(UUID userId, String secret) {
    if (userId == null || secret == null || secret.isBlank()) {
      return false;
    }
    return DbRetry.inNewTx(
        "revoke an idp device by its secret",
        () -> {
          IdpDeviceSecret presented = secrets.findById(ClientSecret.hash(secret));
          return presented != null && revokeRow(userId, presented.deviceId);
        });
  }

  /** How long a {@code qits-device} cookie may be kept: until the device's fixed deadline. */
  public static Duration remaining(Instant absoluteExpiresAt) {
    Duration left = Duration.between(Instant.now(), absoluteExpiresAt);
    return left.isNegative() ? Duration.ZERO : left;
  }

  /** A User-Agent reduced to a label: no control characters, at most {@value #LABEL_LENGTH}. */
  static String label(String userAgent) {
    if (userAgent == null) {
      return UNKNOWN_LABEL;
    }
    StringBuilder clean = new StringBuilder();
    userAgent
        .trim()
        .codePoints()
        .forEach(c -> clean.appendCodePoint(Character.isISOControl(c) ? ' ' : c));
    String value = clean.toString().trim();
    if (value.isEmpty()) {
      return UNKNOWN_LABEL;
    }
    if (value.length() > LABEL_LENGTH) {
      // Never cut a surrogate pair in half: the column would then hold half a character.
      int end = LABEL_LENGTH;
      if (Character.isHighSurrogate(value.charAt(end - 1))) {
        end--;
      }
      value = value.substring(0, end);
    }
    return value;
  }

  // --- inside the caller's transaction ----------------------------------------------------------

  private boolean revokeRow(UUID userId, UUID deviceId) {
    IdpDevice device = devices.lock(deviceId);
    Instant now = now();
    if (device == null || !userId.equals(device.userId) || !isLive(device, now)) {
      return false;
    }
    device.revokedAt = now;
    sessions.revokeForDeviceRow(deviceId, now);
    return true;
  }

  private String newSecret(UUID deviceId, Instant now) {
    String value = RandomSecret.credential();
    IdpDeviceSecret row = new IdpDeviceSecret();
    row.tokenHash = ClientSecret.hash(value);
    row.deviceId = deviceId;
    row.createdAt = now;
    secrets.persist(row);
    return value;
  }

  /** Not revoked and before both deadlines; compared against the clock, never a constraint. */
  private static boolean isLive(IdpDevice row, Instant now) {
    return row.revokedAt == null
        && row.expiresAt.isAfter(now)
        && row.absoluteExpiresAt.isAfter(now);
  }

  private static Instant earlier(Instant one, Instant other) {
    return one.isBefore(other) ? one : other;
  }

  /** Truncated to what {@code timestamp(6)} holds — the reason is on {@link Sessions#openRow}. */
  private static Instant now() {
    return Instant.now().truncatedTo(ChronoUnit.MICROS);
  }

  /** What one resume transaction decided; the replay warning is logged after it commits. */
  private record Attempt(Resumed resumed, UUID replayedDevice, UUID replayedUser) {
    static final Attempt REFUSED = new Attempt(null, null, null);

    static Attempt resumed(Resumed resumed) {
      return new Attempt(resumed, null, null);
    }

    static Attempt replay(UUID deviceId, UUID userId) {
      return new Attempt(null, deviceId, userId);
    }
  }
}
