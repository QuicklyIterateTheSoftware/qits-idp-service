package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One browser session — the row behind the {@code qits-session} cookie.
 *
 * <p><b>The cookie is opaque and this row is the truth.</b> The cookie carries 256 random bits;
 * {@link #tokenHash} is their {@code sha-256:} fingerprint, so a dump of this database logs nobody
 * in. The edge introspects here and caches the answer, which is what keeps logout and revocation
 * row updates rather than cryptography. The alternative considered and refused — a JWT cookie the
 * edge verifies offline against the JWKS it already holds — costs exactly revocation and buys only
 * tolerance of an idp outage, which the edge's cache grace buys back.
 *
 * <p><b>Three columns decide whether a session is live, and none of them is a constraint.</b>
 * {@link #expiresAt} is the absolute deadline stamped at creation ({@code qits.idp.session-ttl});
 * {@link #revokedAt} is logout, <b>set rather than deleted</b> so that a session which ended is
 * distinguishable from one that never existed. A reader compares both against the clock, because
 * "expired" is a fact about the clock and not about the row.
 *
 * <p>Revocation lags at the edge by its introspection cache TTL — seconds, configurable, and named
 * in the plan so nobody files it as a bug.
 */
@Entity
@Table(name = "idp_session")
public class IdpSession extends PanacheEntityBase {

  @Id
  @Column(name = "id")
  public UUID id;

  /** {@code sha-256:…} of the cookie's value. Unique, and the only way a session is looked up. */
  @Column(name = "token_hash", nullable = false, length = 255, unique = true)
  public String tokenHash;

  @Column(name = "user_id", nullable = false)
  public UUID userId;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  /**
   * The absolute deadline. A session itself never slides; a remembered device ({@code Devices},
   * qits-1944) opens a fresh one instead.
   */
  @Column(name = "expires_at", nullable = false)
  public Instant expiresAt;

  /** Set by logout. Null while the session is the user's to use. */
  @Column(name = "revoked_at")
  public Instant revokedAt;

  /**
   * The remembered device this session was opened through (qits-1944, V12), or null for an
   * ordinary login that did not ask to be remembered. Revoking the device revokes the sessions that
   * name it.
   */
  @Column(name = "device_id")
  public UUID deviceId;
}
