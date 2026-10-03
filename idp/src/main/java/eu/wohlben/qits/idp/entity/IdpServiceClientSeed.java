package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * The one-row marker that the first service client has already been seeded from
 * {@code QITS_IDP_SEED_CLIENT_ID}/{@code _SECRET}. Its presence, not the environment variables, is
 * what decides: once this row exists, {@code ServiceClients} never reads those variables again,
 * even if a later boot still sets them (epic qits-540 dossier, "Plan (as of 2026-09-13)", "seed
 * once").
 *
 * <p>{@link #id} is always {@code 1} — the table's check constraint refuses any other value, so
 * there can only ever be the one row.
 */
@Entity
@Table(name = "idp_seed")
public class IdpServiceClientSeed extends PanacheEntityBase {

  /** Always 1. */
  @Id public short id;

  /** The service client id that was seeded. Kept for the record; never read back to authenticate. */
  @Column(name = "client_id", nullable = false, length = 128)
  public String clientId;

  @Column(name = "seeded_at", nullable = false)
  public Instant seededAt;
}
