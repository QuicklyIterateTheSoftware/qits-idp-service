package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One secret a remembered device was given (qits-1944, V12): the {@code sha-256:} fingerprint of a
 * {@code qits-device} cookie value.
 *
 * <p>The current secret is the device's row with {@link #supersededAt} null. A resume supersedes it
 * and writes the next; the spent row stays, because a spent secret presented again is the one
 * signal that a copy of the cookie exists.
 */
@Entity
@Table(name = "idp_device_secret")
public class IdpDeviceSecret extends PanacheEntityBase {

  /** {@code sha-256:…} of the cookie's value — the key, and the only way a secret is looked up. */
  @Id
  @Column(name = "token_hash", length = 255)
  public String tokenHash;

  @Column(name = "device_id", nullable = false)
  public UUID deviceId;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  /** When a resume replaced this secret with the next. Null for the current one. */
  @Column(name = "superseded_at")
  public Instant supersededAt;
}
