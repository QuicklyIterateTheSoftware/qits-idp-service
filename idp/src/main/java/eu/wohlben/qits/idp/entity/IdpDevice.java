package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One remembered browser — the row behind the {@code qits-device} cookie (qits-1944, V12).
 *
 * <p>The cookie's value is not here: it is a secret, and a device has a chain of them in {@link
 * IdpDeviceSecret}, one current and the spent ones kept so a replay is recognisable.
 *
 * <p><b>Four columns decide whether a device is live, and none of them is a constraint.</b> {@link
 * #expiresAt} is the idle deadline, moved forward by every resume; {@link #absoluteExpiresAt} is
 * stamped once and never moves; {@link #revokedAt} is the account, a logout or a replay ending it.
 * A reader compares all three against the clock, as for {@link IdpSession}.
 */
@Entity
@Table(name = "idp_device")
public class IdpDevice extends PanacheEntityBase {

  @Id
  @Column(name = "id")
  public UUID id;

  @Column(name = "user_id", nullable = false)
  public UUID userId;

  /** The User-Agent the remembering login arrived with, truncated. Shown, never parsed. */
  @Column(name = "label", nullable = false, length = 200)
  public String label;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  /** The last resume, or the remembering login itself. */
  @Column(name = "last_used_at", nullable = false)
  public Instant lastUsedAt;

  /** The idle deadline: {@code qits.idp.device.idle-ttl} past the last use, capped by the next. */
  @Column(name = "expires_at", nullable = false)
  public Instant expiresAt;

  /** The fixed deadline, {@code qits.idp.device.absolute-ttl} after creation. Never moves. */
  @Column(name = "absolute_expires_at", nullable = false)
  public Instant absoluteExpiresAt;

  /** Set by a revoke, a logout or a detected replay. Null while the device is the user's. */
  @Column(name = "revoked_at")
  public Instant revokedAt;
}
