package eu.wohlben.qits.idp.persistence;

import eu.wohlben.qits.idp.entity.IdpDeviceSecret;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

/** Panache DAO for {@link IdpDeviceSecret} (keyed by its fingerprint). */
@ApplicationScoped
public class IdpDeviceSecretRepository implements PanacheRepositoryBase<IdpDeviceSecret, String> {}
