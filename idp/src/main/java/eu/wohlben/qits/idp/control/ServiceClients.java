package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpServiceClient;
import eu.wohlben.qits.idp.entity.IdpServiceClientSeed;
import eu.wohlben.qits.idp.error.OAuthException;
import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import eu.wohlben.qits.idp.persistence.IdpServiceClientSeedRepository;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Service clients, kept in the database (epic qits-540, dossier page "Plan (as of 2026-09-13)",
 * contract C2): the id and secret arrive from a call here rather than from configuration, and the
 * idp answers the secret exactly once. This is the only service-client registry. The old
 * configuration one was retired by qits-163; its clients were moved in here once, by {@link
 * EnvironmentClientAdoption}.
 *
 * <p><b>Every row is loaded at start into a volatile map, like {@link SigningKeys}' key set.</b>
 * The token path stays off postgres: {@link #find} is a map read, never a query. A write — {@link #create}, {@link
 * #rotate}, {@link #delete}, the one-time {@link #seedOnce} — goes through {@link DbRetry}, updates
 * the row, and replaces the map under a lock so two writers on this one process cannot lose one
 * another's change. <b>One idp process is assumed</b>, the same assumption {@link DynamicClients}
 * documents and for the same reason: a second instance would hold its own stale copy of a row
 * changed at the first.
 *
 * <p><b>Roles and claims are code, not stored here</b> (D3, "roles are code"). {@link
 * ClientRegistry} is where a row becomes an {@link IdpClient}: {@code qits:system} plus the
 * client's own {@code clients/<id>}, and the claim {@code project=*}. Its tokens' {@code aud} is
 * {@code qits-platform}, like every token's.
 */
@ApplicationScoped
public class ServiceClients {

  private static final Logger LOG = Logger.getLogger(ServiceClients.class);

  /**
   * A service client id: a lowercase slug, the same shape a wire alias already has. Shared with the
   * seed id, so both paths that create a row refuse the same malformed one.
   */
  static final Pattern ID_PATTERN = Pattern.compile("[a-z][a-z0-9-]{0,127}");

  /** D4: a rotated secret's predecessor stays valid this long. */
  static final Duration PREVIOUS_SECRET_GRACE = Duration.ofMinutes(15);

  /** What {@code created_by} says for the row {@link #seedOnce} writes. Not a real client id. */
  static final String SEEDED_BY = "bootstrap";

  /** A row as everything outside persistence sees it — a record, so nothing caches a live entity. */
  public record StoredServiceClient(
      String clientId,
      String secretHash,
      String previousSecretHash,
      Instant previousValidUntil,
      String legacySecretHash,
      String createdBy,
      Instant createdAt,
      Instant rotatedAt) {}

  /** What a create or a rotate answers: the row, and the plaintext that exists only in this answer. */
  public record Issued(StoredServiceClient client, String secret) {}

  @Inject IdpServiceClientRepository repository;

  @Inject IdpServiceClientSeedRepository seedRepository;

  @Inject PublicClients publicClients;

  @Inject EnvironmentClientAdoption adoption;

  @ConfigProperty(name = "qits.idp.seed-client.id")
  Optional<String> seedClientId;

  @ConfigProperty(name = "qits.idp.seed-client.secret")
  Optional<String> seedClientSecret;

  private volatile Map<String, StoredServiceClient> clients = Map.of();

  /**
   * Seed the first client if one is configured and none has ever been seeded, adopt the old
   * environment clients if that has not happened yet ({@link EnvironmentClientAdoption}), then load
   * every row into the cache. Runs after Flyway, the same way {@link SigningKeys#onStart} does — both
   * read the database at boot rather than on the first request, so a boot fails loudly here rather
   * than on whatever request happens to be first.
   */
  void onStart(@Observes StartupEvent event) {
    seedOnce();
    adoption.adoptOnce();
    load();
    LOG.infof("%d service client(s) loaded from the database", clients.size());
  }

  /** The database row for this id, from the cache — never a query. */
  public Optional<StoredServiceClient> find(String clientId) {
    if (clientId == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(clients.get(clientId));
  }

  /** Every database service client, in load order — the migration-progress listing. */
  public List<StoredServiceClient> list() {
    return List.copyOf(clients.values());
  }

  /**
   * The id rule every create — and the seed — must pass (400 otherwise): a lowercase slug, not a
   * commissioned id, not one of the two public client ids.
   *
   * @throws OAuthException {@code invalid_request} (400)
   */
  public void requireValidId(String clientId) {
    if (clientId == null || !ID_PATTERN.matcher(clientId).matches()) {
      throw OAuthException.invalidRequest(
          "clientId must match [a-z][a-z0-9-]{0,127}");
    }
    if (clientId.startsWith(DynamicClients.ID_PREFIX)) {
      throw OAuthException.invalidRequest(
          "clientId must not begin with " + DynamicClients.ID_PREFIX + ", which is reserved for"
              + " commissioned clients");
    }
    if (publicClients.byId(clientId).isPresent()) {
      throw OAuthException.invalidRequest(
          "clientId must not be a public client id (the workstation or the CLI)");
    }
  }

  /**
   * A fresh service client. The caller has already checked {@link #requireValidId} and that no row
   * exists for this id — this method does not re-check either, so the 409 the API answers stays the
   * controller's to phrase.
   */
  public Issued create(String clientId, String createdBy) {
    String secret = RandomSecret.credential();
    IdpServiceClient row = new IdpServiceClient();
    row.clientId = clientId;
    row.secretHash = ClientSecret.hash(secret);
    row.createdBy = createdBy;
    row.createdAt = Instant.now();
    DbRetry.runInNewTx("create idp service client", () -> repository.persist(row));
    StoredServiceClient stored = toStored(row);
    put(stored);
    LOG.infof(
        "service client %s created by %s",
        LoggableClientId.of(clientId), LoggableClientId.of(createdBy));
    return new Issued(stored, secret);
  }

  /**
   * Replace the secret. The old hash becomes {@code previous_secret_hash}, valid for {@link
   * #PREVIOUS_SECRET_GRACE} (D4) — a start-first rollback to the predecessor container must not be
   * locked out the moment its successor rotates. A kept environment secret ({@code
   * legacy_secret_hash}, qits-163) is cleared outright: it gets no grace.
   *
   * @return empty when there is no such row
   */
  public Optional<Issued> rotate(String clientId) {
    String secret = RandomSecret.credential();
    String newHash = ClientSecret.hash(secret);
    Instant now = Instant.now();
    StoredServiceClient updated =
        DbRetry.inNewTx(
            "rotate idp service client secret",
            () -> {
              IdpServiceClient row = repository.findById(clientId);
              if (row == null) {
                return null;
              }
              row.previousSecretHash = row.secretHash;
              row.previousValidUntil = now.plus(PREVIOUS_SECRET_GRACE);
              row.secretHash = newHash;
              row.rotatedAt = now;
              // The kept environment secret (qits-163) is retired by the first rotation: the
              // caller now holds a database secret, and the old one has no reason left to work.
              row.legacySecretHash = null;
              return toStored(row);
            });
    if (updated == null) {
      return Optional.empty();
    }
    put(updated);
    LOG.infof("service client %s secret rotated", LoggableClientId.of(clientId));
    return Optional.of(new Issued(updated, secret));
  }

  /** Delete the row. @return false when there was none. */
  public boolean delete(String clientId) {
    boolean existed =
        DbRetry.inNewTx("delete idp service client", () -> repository.deleteById(clientId));
    if (existed) {
      remove(clientId);
      LOG.infof("service client %s deleted", LoggableClientId.of(clientId));
    }
    return existed;
  }

  /**
   * Seed the first service client, once, from {@code QITS_IDP_SEED_CLIENT_ID}/{@code _SECRET}
   * (mapped from {@code qits.idp.seed-client.id}/{@code .secret}). Both must be set and non-blank;
   * the {@code idp_seed} marker row, not the variables, is what decides "once" — a later boot with
   * the variables still set, changed, or blanked does nothing once the row exists.
   *
   * <p>Only the id reaches the log. The secret never does, on this path or any other.
   *
   * <p>Package-visible rather than {@code private} for one reason: {@code ServiceClientSeedTest}
   * calls it a second time, after swapping {@link #seedClientId}/{@link #seedClientSecret}, to prove
   * a later boot with the variables changed or blanked does nothing once {@code idp_seed} exists —
   * the thing a real second boot cannot be made to do inside one test run.
   */
  void seedOnce() {
    String id = seedClientId.map(String::trim).filter(value -> !value.isEmpty()).orElse(null);
    String secret = seedClientSecret.filter(value -> !value.isEmpty()).orElse(null);
    if (id == null || secret == null) {
      return;
    }
    // A cheap read on every boot after the first, so an installation that leaves the variables set
    // (the ordinary case — nothing asks it to unset them) pays one query rather than a transaction.
    boolean already = DbRetry.inNewTx("check idp seed marker", seedRepository::seeded);
    if (already) {
      return;
    }
    requireValidId(id);
    String hash = ClientSecret.hash(secret);
    Instant now = Instant.now();
    DbRetry.runInNewTx(
        "seed the first idp service client",
        () -> {
          // Re-checked inside the write transaction: one process, but a second boot racing this one
          // on the same cold database must not seed twice.
          if (seedRepository.seeded()) {
            return;
          }
          IdpServiceClient row = new IdpServiceClient();
          row.clientId = id;
          row.secretHash = hash;
          row.createdBy = SEEDED_BY;
          row.createdAt = now;
          repository.persist(row);

          IdpServiceClientSeed marker = new IdpServiceClientSeed();
          marker.id = IdpServiceClientSeedRepository.ID;
          marker.clientId = id;
          marker.seededAt = now;
          seedRepository.persist(marker);
        });
    LOG.infof("seeded the first service client %s at first boot", LoggableClientId.of(id));
  }

  /**
   * Replace the cache with every row in the store. Package-visible so {@code
   * EnvironmentClientAdoptionTest} can pick up rows it adopted by calling the adoption directly.
   */
  synchronized void load() {
    List<IdpServiceClient> rows =
        DbRetry.inNewTx("load idp service clients", repository::listAllOrdered);
    Map<String, StoredServiceClient> loaded = new LinkedHashMap<>();
    for (IdpServiceClient row : rows) {
      loaded.put(row.clientId, toStored(row));
    }
    clients = Map.copyOf(loaded);
  }

  private synchronized void put(StoredServiceClient stored) {
    Map<String, StoredServiceClient> next = new LinkedHashMap<>(clients);
    next.put(stored.clientId(), stored);
    clients = Map.copyOf(next);
  }

  private synchronized void remove(String clientId) {
    Map<String, StoredServiceClient> next = new LinkedHashMap<>(clients);
    next.remove(clientId);
    clients = Map.copyOf(next);
  }

  private static StoredServiceClient toStored(IdpServiceClient row) {
    return new StoredServiceClient(
        row.clientId,
        row.secretHash,
        row.previousSecretHash,
        row.previousValidUntil,
        row.legacySecretHash,
        row.createdBy,
        row.createdAt,
        row.rotatedAt);
  }
}
