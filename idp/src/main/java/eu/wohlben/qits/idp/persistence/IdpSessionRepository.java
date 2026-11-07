package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpSession;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Instant;
import java.util.UUID;

/** Panache DAO for {@link IdpSession} (keyed by its generated {@code id}). */
@ApplicationScoped
public class IdpSessionRepository implements PanacheRepositoryBase<IdpSession, UUID> {

  /**
   * The session with this cookie fingerprint, or null. Introspection arrives holding a cookie value
   * and nothing else, so this is the only read there is — and the column is unique so it is one row.
   *
   * <p>It answers a revoked or expired row too. Deciding whether a session is <b>live</b> is the
   * caller's, because that is a comparison against the clock rather than a property of the row.
   */
  public IdpSession findByTokenHash(String tokenHash) {
    return find("tokenHash", tokenHash).firstResult();
  }

  /**
   * Revoke every session opened through this device that is not revoked already (qits-1944). An
   * expired one is stamped too: it is already dead, and a revoked dead row says the same thing.
   *
   * @return how many rows were stamped
   */
  public int revokeForDevice(UUID deviceId, Instant at) {
    return update("revokedAt = ?2 where deviceId = ?1 and revokedAt is null", deviceId, at);
  }
}
