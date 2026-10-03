package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One service client's identity, kept in the database rather than in configuration (epic qits-540,
 * dossier page "Plan (as of 2026-09-13)", contract C2). Unlike a commissioned row ({@link
 * IdpDynamicClient}) this one has no owner and no context: a service client's roles and claims are
 * code, not stored here — see {@code ClientRegistry}. {@link #createdBy} is another service client,
 * {@code bootstrap} for the seeded one, or {@code adopted} for one moved in from the retired
 * environment registry ({@code EnvironmentClientAdoption}).
 *
 * <p>{@link #previousSecretHash} and {@link #previousValidUntil} exist only right after a
 * rotation, and only for the grace window (D4, fifteen minutes): the old secret stays acceptable so
 * a start-first rollback to the predecessor container is not locked out the moment its successor
 * rotates. Null once the grace has passed or the row has never rotated.
 */
@Entity
@Table(name = "idp_service_client")
public class IdpServiceClient extends PanacheEntityBase {

  /** The {@code sub} of every token this client mints, and the row's identity. */
  @Id
  @Column(name = "client_id", length = 128)
  public String clientId;

  /** The current secret, one-way — see {@link eu.wohlben.qits.idp.control.ClientSecret}. */
  @Column(name = "secret_hash", nullable = false, length = 255)
  public String secretHash;

  /** The hash a rotation retired, still accepted until {@link #previousValidUntil}. */
  @Column(name = "previous_secret_hash", length = 255)
  public String previousSecretHash;

  /** When {@link #previousSecretHash} stops being accepted. Null when there is none to expire. */
  @Column(name = "previous_valid_until")
  public Instant previousValidUntil;

  /** Who created this row: another service client's id, {@code bootstrap} or {@code adopted}. */
  @Column(name = "created_by", nullable = false, length = 128)
  public String createdBy;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  /** When {@link #secretHash} was last rotated. Null: never. */
  @Column(name = "rotated_at")
  public Instant rotatedAt;
}
