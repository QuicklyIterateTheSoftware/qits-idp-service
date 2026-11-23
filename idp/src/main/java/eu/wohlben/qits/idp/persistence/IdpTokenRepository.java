package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpToken;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.UUID;

/** Panache DAO for {@link IdpToken} (keyed by its generated {@code id}). */
@ApplicationScoped
public class IdpTokenRepository implements PanacheRepositoryBase<IdpToken, UUID> {

  /**
   * The token with this fingerprint, or null. A bearer presents a value, never an id, so the hash
   * is the only lookup introspection has — which is also why the column is unique.
   */
  public IdpToken findByHash(String tokenHash) {
    return find("tokenHash", tokenHash).firstResult();
  }

  /**
   * The token with this subject, or null, locked for update until the transaction ends — the read
   * a fixed-subject commission (qits-2518) rotates in place, so two rotations of one subject take
   * turns rather than both writing.
   */
  public IdpToken findBySubjectForUpdate(String subject) {
    return find("subject", subject).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
  }

  /**
   * One owner's live tokens, oldest first — the reconciliation read, ordered like the commissioned
   * clients' so the longest-lived orphan comes first.
   */
  public List<IdpToken> listOwnedBy(String owner) {
    return list("owner = ?1 order by createdAt asc, subject asc", owner);
  }
}
