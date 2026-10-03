package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpAdoption;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

/** Panache DAO for the one-row {@link IdpAdoption} marker. */
@ApplicationScoped
public class IdpAdoptionRepository implements PanacheRepositoryBase<IdpAdoption, Short> {

  /** The row's one fixed id. */
  public static final short ID = 1;

  /** Whether the marker row exists: whether the environment clients were already adopted. */
  public boolean adopted() {
    return findById(ID) != null;
  }

  /** Whether both passes ran: the marker exists and carries {@code legacy_adopted_at}. */
  public boolean complete() {
    IdpAdoption marker = findById(ID);
    return marker != null && marker.legacyAdoptedAt != null;
  }
}
