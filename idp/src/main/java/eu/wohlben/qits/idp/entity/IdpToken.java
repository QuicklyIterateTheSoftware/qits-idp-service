package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One commissioned token: an opaque bearer a service client asked for on behalf of one dynamic
 * context, verified here on every use rather than by a signature anybody can check offline.
 *
 * <p><b>There is no expiry column, by design.</b> A token lives exactly as long as its row, and the
 * owner that commissioned it — or the token itself — is who ends it by deleting that row. Because
 * every use is an introspection against this table, the deletion is the whole revocation and it is
 * immediate for the next call: there is no {@code exp} to wait out, which is the thing a JWT could
 * not offer and the reason this third credential exists. A deadline column would add a second way
 * for a token to end without adding any safety the delete does not already give.
 *
 * <p>{@link #owner}, {@link #contextKind} and {@link #contextId} are the same triple a commissioned
 * client carries ({@link IdpDynamicClient}), with the same meaning: who may list and delete it, and
 * what a reconcile compares against its live contexts. {@link #claims} and {@link #gitRefs} are the
 * same two scoping columns in the same formats.
 */
@Entity
@Table(name = "idp_token")
public class IdpToken extends PanacheEntityBase {

  @Id
  @Column(name = "id")
  public UUID id;

  /**
   * The {@code sub} of every JWT an introspection mints for this token: {@code
   * tok-<kind>-<context slug>-<random>}, disjoint from a commissioned client's {@code dyn-…} and
   * from every service client's name.
   */
  @Column(name = "subject", nullable = false, length = 128, unique = true)
  public String subject;

  /**
   * {@code sha-256:…} of the value — never the value, which left this process once, in the
   * commission response. The lookup key, and unique for that reason.
   */
  @Column(name = "token_hash", nullable = false, length = 255, unique = true)
  public String tokenHash;

  /** The service client that commissioned this token, and whose audiences its JWTs carry. */
  @Column(name = "owner", nullable = false, length = 128)
  public String owner;

  /** What kind of context this token belongs to, which also decides its roles. */
  @Column(name = "context_kind", nullable = false, length = 32)
  public String contextKind;

  /** Which context of that kind, in the owner's own spelling. Opaque here. */
  @Column(name = "context_id", nullable = false, length = 256)
  public String contextId;

  /**
   * The structured claims the commission stated, as {@code name=value} lines — {@link
   * eu.wohlben.qits.idp.control.CommissionedClaims} owns the format. Null when it stated none.
   */
  @Column(name = "claims", length = 1024)
  public String claims;

  /**
   * The Git refs this token may push, one per line — {@link eu.wohlben.qits.idp.control.GitRefs}
   * owns the format. Null: no list stated. The empty string: the empty list, "may push nothing".
   */
  @Column(name = "git_refs", columnDefinition = "text")
  public String gitRefs;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;
}
