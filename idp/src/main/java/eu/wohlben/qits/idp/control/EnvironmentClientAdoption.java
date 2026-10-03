package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpAdoption;
import eu.wohlben.qits.idp.entity.IdpServiceClient;
import eu.wohlben.qits.idp.persistence.IdpAdoptionRepository;
import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

/**
 * Moves the old environment service clients into {@code idp_service_client}, once (qits-163).
 *
 * <p>The idp used to have two service-client registries: configuration ({@code qits.idp.clients}
 * and {@code qits.idp.client.<id>.secret}) and the database. Every service now has a database row,
 * so the configuration registry is gone. This class is the one thing left that reads its keys, and
 * it reads them at most once per installation.
 *
 * <p><b>What it does.</b> At start, after Flyway, when the {@code idp_adoption} marker row is
 * absent: for every id on {@code qits.idp.clients} that has a non-blank secret and no database row,
 * insert a row holding the hash of that secret ({@link ClientSecret#hash}, the same hash every
 * database client uses), {@code created_by = 'adopted'}. Then write the marker, in the same
 * transaction. The client keeps working with the secret it already has, and from then on it is an
 * ordinary database service client: {@code qits:system}, {@code clients/<id>}, {@code project=*}.
 *
 * <p><b>An id that already had a row keeps that row, and keeps its environment secret too.</b>
 * Before qits-163 such an id authenticated with either secret, and its caller may well hold the
 * environment one — live, {@code dev-qits-edge} did, and lost every token the moment the registry
 * went. So when the environment secret matches neither of the row's own hashes, its hash goes into
 * {@code legacy_secret_hash}, which {@link ClientSecret#serviceClient} accepts beside them until the
 * next rotation clears it. An installation that already ran the adoption before that column existed
 * runs this pass on its own, once, guarded by {@code idp_adoption.legacy_adopted_at}; a first
 * adoption does both in one transaction.
 *
 * <p><b>What it leaves alone.</b> A row whose environment secret already matches. An id
 * with no secret is skipped, because it could never authenticate. An id that is not a valid service
 * client id is skipped with a warning. And once the marker exists, nothing here runs again, even if
 * a later boot still sets the variables.
 *
 * <p><b>The keys are read exactly as the retired {@code IdpClients} read them</b>: {@code
 * Config.getOptionalValues("qits.idp.clients")} and {@code
 * Config.getOptionalValue("qits.idp.client.<id>.secret")}, so the environment spellings a live
 * installation sets ({@code QITS_IDP_CLIENTS}, {@code QITS_IDP_CLIENT_DEV_QITS_CI_SECRET} for {@code
 * dev-qits-ci}) are found by the same mapping as before.
 *
 * <p>Only ids reach the log. A secret never does.
 */
@ApplicationScoped
public class EnvironmentClientAdoption {

  private static final Logger LOG = Logger.getLogger(EnvironmentClientAdoption.class);

  /** The old registry's list of client ids. */
  static final String CLIENTS_KEY = "qits.idp.clients";

  /** The old registry's per-client key prefix: {@code qits.idp.client.<id>.secret}. */
  static final String CLIENT_PREFIX = "qits.idp.client.";

  /** What {@code created_by} says for a row this class writes. Not a real client id. */
  public static final String ADOPTED_BY = "adopted";

  @Inject IdpServiceClientRepository repository;

  @Inject IdpAdoptionRepository markerRepository;

  @Inject PublicClients publicClients;

  /**
   * Adopt the configured environment clients if that has not happened yet. Called from {@code
   * ServiceClients.onStart}, before the rows are loaded into its cache.
   */
  void adoptOnce() {
    // A cheap read on every boot after the first, so the configuration is not even looked at once
    // the marker exists.
    if (DbRetry.inNewTx("check idp adoption marker", markerRepository::complete)) {
      return;
    }
    Map<String, String> secrets = configuredSecrets();
    adopt(secrets);
    keepEnvironmentSecrets(secrets);
  }

  /**
   * Adopt these ids and secrets, unless the marker already exists.
   *
   * <p>Package-visible for one reason: {@code EnvironmentClientAdoptionTest} calls it with its own
   * ids, after deleting the marker, to prove what a first boot does and that a second does nothing.
   * One test run cannot boot the process twice.
   *
   * @param secrets every configured id, in list order, with its secret or null when it has none
   * @return the ids that got a row, in list order; empty when the marker was already there
   */
  List<String> adopt(Map<String, String> secrets) {
    Map<String, String> plaintexts = new LinkedHashMap<>();
    Map<String, String> hashes = new LinkedHashMap<>();
    secrets.forEach(
        (id, secret) -> {
          if (secret == null || secret.isBlank()) {
            return;
          }
          if (!validId(id)) {
            LOG.warnf(
                "environment client %s not adopted: not a valid service client id",
                LoggableClientId.of(id));
            return;
          }
          plaintexts.put(id, secret);
          hashes.put(id, ClientSecret.hash(secret));
        });
    Instant now = Instant.now();
    List<String> kept = new ArrayList<>();
    List<String> adopted =
        DbRetry.inNewTx(
            "adopt environment service clients",
            () -> {
              // Checked again inside the write: a second boot racing this one on the same database
              // must not adopt twice.
              if (markerRepository.adopted()) {
                return null;
              }
              List<String> inserted = new ArrayList<>();
              kept.clear();
              hashes.forEach(
                  (id, hash) -> {
                    IdpServiceClient existing = repository.findById(id);
                    if (existing != null) {
                      if (keepIfMismatched(existing, plaintexts.get(id))) {
                        kept.add(id);
                      }
                      return;
                    }
                    IdpServiceClient row = new IdpServiceClient();
                    row.clientId = id;
                    row.secretHash = hash;
                    row.createdBy = ADOPTED_BY;
                    row.createdAt = now;
                    repository.persist(row);
                    inserted.add(id);
                  });
              IdpAdoption marker = new IdpAdoption();
              marker.id = IdpAdoptionRepository.ID;
              marker.adoptedAt = now;
              marker.legacyAdoptedAt = now;
              markerRepository.persist(marker);
              return inserted;
            });
    if (adopted == null) {
      return List.of();
    }
    logKept(kept);
    LOG.infof(
        "adopted %d environment service client(s) into the database: %s",
        adopted.size(),
        String.join(",", adopted.stream().map(LoggableClientId::of).toList()));
    return List.copyOf(adopted);
  }

  /**
   * The second pass on its own, for an installation whose adoption ran before {@code
   * legacy_secret_hash} existed: every configured id whose row's own hashes do not match its
   * environment secret gets that secret's hash as {@code legacy_secret_hash}. Runs once, guarded by
   * {@code idp_adoption.legacy_adopted_at}; does nothing when the marker row is absent, because then
   * {@link #adopt} has not run and does this pass itself.
   *
   * <p>Package-visible for {@code EnvironmentClientAdoptionTest}, for the same reason as {@link
   * #adopt}.
   *
   * @return the ids that got a legacy hash, in list order; empty when the pass already ran
   */
  List<String> keepEnvironmentSecrets(Map<String, String> secrets) {
    Map<String, String> plaintexts = new LinkedHashMap<>();
    secrets.forEach(
        (id, secret) -> {
          if (secret != null && !secret.isBlank() && validId(id)) {
            plaintexts.put(id, secret);
          }
        });
    Instant now = Instant.now();
    List<String> kept =
        DbRetry.inNewTx(
            "keep environment secrets of existing service clients",
            () -> {
              // Re-checked inside the write, like the first pass.
              IdpAdoption marker = markerRepository.findById(IdpAdoptionRepository.ID);
              if (marker == null || marker.legacyAdoptedAt != null) {
                return null;
              }
              List<String> updated = new ArrayList<>();
              plaintexts.forEach(
                  (id, secret) -> {
                    IdpServiceClient row = repository.findById(id);
                    if (row != null && keepIfMismatched(row, secret)) {
                      updated.add(id);
                    }
                  });
              marker.legacyAdoptedAt = now;
              return updated;
            });
    if (kept == null) {
      return List.of();
    }
    logKept(kept);
    return List.copyOf(kept);
  }

  /**
   * Set {@code legacy_secret_hash} when {@code secret} matches neither of the row's own live hashes,
   * judged by the same {@link ClientSecret#serviceClient} the token path uses. Inside the caller's
   * transaction; the row is managed, so the assignment is the write.
   *
   * @return whether the row got a legacy hash
   */
  private static boolean keepIfMismatched(IdpServiceClient row, String secret) {
    if (ClientSecret.serviceClient(
            row.secretHash, row.previousSecretHash, row.previousValidUntil, null)
        .matches(secret)) {
      return false;
    }
    row.legacySecretHash = ClientSecret.hash(secret);
    return true;
  }

  private static void logKept(List<String> kept) {
    if (kept.isEmpty()) {
      return;
    }
    LOG.infof(
        "kept the environment secret of %d service client(s) that already had a database row: %s",
        kept.size(),
        String.join(",", kept.stream().map(LoggableClientId::of).toList()));
  }

  /** Every id on {@code qits.idp.clients}, with its configured secret or null. */
  private static Map<String, String> configuredSecrets() {
    Config config = ConfigProvider.getConfig();
    Map<String, String> secrets = new LinkedHashMap<>();
    for (String id : config.getOptionalValues(CLIENTS_KEY, String.class).orElse(List.of())) {
      if (id == null || id.isBlank()) {
        continue;
      }
      Optional<String> secret =
          config.getOptionalValue(CLIENT_PREFIX + id + ".secret", String.class);
      secrets.put(id, secret.orElse(null));
    }
    return secrets;
  }

  /** The same id rule {@link ServiceClients#requireValidId} applies to a create. */
  private boolean validId(String id) {
    return ServiceClients.ID_PATTERN.matcher(id).matches()
        && !id.startsWith(DynamicClients.ID_PREFIX)
        && publicClients.byId(id).isEmpty();
  }
}
