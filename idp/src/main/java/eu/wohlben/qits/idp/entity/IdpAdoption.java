package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * The one-row marker that the environment service clients have already been moved into {@code
 * idp_service_client} (qits-163). Its presence is what decides: once this row exists, {@code
 * EnvironmentClientAdoption} never reads {@code qits.idp.clients} or a client's secret again.
 *
 * <p>{@link #id} is always {@code 1}. The table's check constraint refuses any other value, so there
 * can only ever be the one row.
 */
@Entity
@Table(name = "idp_adoption")
public class IdpAdoption extends PanacheEntityBase {

  /** Always 1. */
  @Id public short id;

  @Column(name = "adopted_at", nullable = false)
  public Instant adoptedAt;

  /**
   * When qits-163's second pass ran: an id whose existing row did not match its environment secret
   * got that secret's hash as {@code legacy_secret_hash}. Nothing reads or writes it since qits-880's
   * release 2 retired that pass; it is mapped only because V11 created the column and the mapping
   * keeps the entity matching the schema. A rollback to release 1 reads it again — null there means
   * the pass runs once.
   */
  @Column(name = "legacy_adopted_at")
  public Instant legacyAdoptedAt;
}
