package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpDevice;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.UUID;

/** Panache DAO for {@link IdpDevice} (keyed by its generated {@code id}). */
@ApplicationScoped
public class IdpDeviceRepository implements PanacheRepositoryBase<IdpDevice, UUID> {

  /**
   * The device, row-locked for the rest of the caller's transaction ({@code SELECT … FOR UPDATE}).
   * Two resumes of one device serialize here, so exactly one of them rotates the secret.
   */
  public IdpDevice lock(UUID id) {
    return findById(id, LockModeType.PESSIMISTIC_WRITE);
  }

  /** Every device of the account, live or not; deciding liveness is the caller's clock comparison. */
  public List<IdpDevice> listForUser(UUID userId) {
    return find("userId = ?1 order by lastUsedAt desc", userId).list();
  }
}
