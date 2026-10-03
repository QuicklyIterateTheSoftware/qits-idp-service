package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A one-time registration ticket: the thing that turns "anyone may POST to register" into "whoever
 * holds this may register once".
 *
 * <p><b>It is a row minted through an API and printed by the bootstrap</b>, never a log line — idp's
 * logs ship to qits-observability, and a credential must not ride the log plane. The plaintext
 * exists once, in the mint response; this row holds a {@code sha-256:} fingerprint of it, the same
 * scheme {@link eu.wohlben.qits.idp.control.ClientSecret} stores a commissioned secret under.
 *
 * <p><b>One-time use is {@link #consumedAt}, not a delete.</b> The row outlives its spending so an
 * operator can see that a token was used and which account it made — {@link #createdUserId} is that
 * link. Consuming the token and creating the user happen in one transaction, so there is no state
 * in which a token is spent and no account exists.
 *
 * <p>{@link #mintedBy} is the client id of the caller that asked. Only a <b>static</b> service
 * client may mint: the commissioning rule reused verbatim, so that a credential handed to a build
 * step or an agent container cannot produce accounts.
 */
@Entity
@Table(name = "idp_register_token")
public class IdpRegisterToken extends PanacheEntityBase {

  @Id
  @Column(name = "id")
  public UUID id;

  /** {@code sha-256:…} of the plaintext the mint response carried. Unique, and the lookup key. */
  @Column(name = "token_hash", nullable = false, length = 255, unique = true)
  public String tokenHash;

  /** The service client that minted this token. */
  @Column(name = "minted_by", nullable = false, length = 128)
  public String mintedBy;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  /** When it was spent. Null while it is still good for exactly one registration. */
  @Column(name = "consumed_at")
  public Instant consumedAt;

  /** The account this token made. Null while {@link #consumedAt} is. */
  @Column(name = "created_user_id")
  public UUID createdUserId;
}
