package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpDynamicClient;
import eu.wohlben.qits.idp.error.OAuthException;
import eu.wohlben.qits.idp.persistence.IdpDynamicClientRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;

/**
 * Commissioned clients: the store, the id and secret generation, and the small cache that keeps the
 * token path off the database.
 *
 * <p><b>Commission and decommission are the whole lifecycle.</b> A service that provisions a
 * dynamic context — a ci run, a workspace, an agent container — asks for a credential for that
 * context and deletes it when the context ends. There is no TTL on the credential itself: its
 * lifetime is the context's, which is what keeps a long-running workspace from ever needing to
 * re-commission. See {@code authenticated-reads-plan.md} in the qits superproject.
 *
 * <p><b>The cache, and why its invalidation is enough.</b> Token issuance is the platform's whole
 * call graph and it was a config lookup before this existed; a database round trip per token would
 * put the store on that path. So a resolved row is cached, {@link #decommission} evicts it in the
 * same call that deletes it, and a client that has just been decommissioned cannot mint from the
 * next request onward. Only positives are cached — a miss always reads the store — so a commission
 * is visible immediately too, and the map is bounded by the number of live contexts. <b>One idp
 * process is assumed</b>, which is what this service is deployed as; a second instance would hold
 * its own copy of a row deleted at the first, and that is the day this needs a bounded entry age or
 * an eviction announcement rather than a bigger cache.
 *
 * <p><b>What is not stored: audiences.</b> A commissioned client is issued its owner's, read from
 * the owner's record when a token is minted ({@link ClientRegistry}).
 *
 * <p><b>Claims are stored, and that is the per-context scoping the plan declared.</b> A commission
 * may state what its context is about — {@code project=<id>} for a workspace, and the rest of
 * {@link ClaimNames#GRANTABLE} — and those land on the row, narrowing what the credential may act
 * on wherever a resource service reads a claim. <b>Anything it does not state, it does not
 * carry</b>: a commission no longer inherits its owner's claims either (D3 of
 * {@code service-client-identity-plan.md}), so a row with nothing stated mints a token with no
 * structured claim at all. The rule that bounds what MAY be stated, and the reason there is no "the
 * owner must hold it" check, is in {@link CommissionedClaims}.
 */
@ApplicationScoped
public class DynamicClients {

  private static final Logger LOG = Logger.getLogger(DynamicClients.class);

  /**
   * The prefix every commissioned id carries. It is what makes a listing readable, and it is the
   * reason a commissioned id can never be mistaken for a service one: the static ids are the names
   * services are dialed by ({@code prod-qits-ci}, {@code qits-platform-artifacts}) and none of them
   * begins with this. {@link ClientRegistry} resolves config first regardless, so even a deployment
   * that configured a static {@code dyn-…} client would shadow the row rather than be shadowed by
   * it — the safe direction.
   */
  public static final String ID_PREFIX = "dyn-";

  /**
   * A context kind is a lowercase slug: it goes into a client id, which goes into logs, and into a
   * config key ({@link CommissionRoles}).
   */
  private static final Pattern CONTEXT_KIND = Pattern.compile("[a-z][a-z0-9-]{0,31}");

  /** Whether this is a context kind this service writes: a lowercase slug of at most 32. */
  static boolean isContextKind(String kind) {
    return kind != null && CONTEXT_KIND.matcher(kind).matches();
  }

  /**
   * A context kind and id as a commission names them, trimmed and checked — the one rule both
   * credentials a context can be handed share: a commissioned client here and a commissioned token
   * ({@link CommissionedTokens}). Both put the kind and a slug of the id into a generated name and
   * store the id raw, so a second copy of the check would be a second place for the bounds to drift.
   */
  record Context(String kind, String id) {

    /**
     * @throws OAuthException {@code invalid_request} (400) when the kind is not a lowercase slug of
     *     at most 32, or the id is blank or longer than the column
     */
    static Context validated(String contextKind, String contextId) {
      String kind = contextKind == null ? "" : contextKind.trim();
      String context = contextId == null ? "" : contextId.trim();
      if (!CONTEXT_KIND.matcher(kind).matches()) {
        throw OAuthException.invalidRequest(
            "contextKind must be a lowercase slug of at most 32 characters");
      }
      if (context.isEmpty() || context.length() > CONTEXT_ID_LENGTH) {
        throw OAuthException.invalidRequest(
            "contextId is required and must be at most " + CONTEXT_ID_LENGTH + " characters");
      }
      return new Context(kind, context);
    }
  }

  /** How much of the context id is echoed into the client id, before the random tail. */
  private static final int ID_SLUG_LENGTH = 24;

  /** As long as the column allows. The owner's own spelling, stored and never interpreted. */
  private static final int CONTEXT_ID_LENGTH = 256;

  /**
   * A row as everything outside persistence sees it — a record, so nothing caches a live entity.
   *
   * @param claims the claims this commission stated, already parsed. Empty is the ordinary case.
   * @param gitRefs the Git refs this credential may push ({@link GitRefs}); null when the
   *     commission stated no list, empty for "push nothing"
   */
  public record StoredClient(
      String clientId,
      String secretHash,
      String owner,
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs,
      Instant createdAt) {}

  /** A fresh commission, with the plaintext secret that exists only in this answer. */
  public record Commissioned(StoredClient client, String secret) {}

  @Inject IdpDynamicClientRepository repository;

  private final Map<String, StoredClient> cache = new ConcurrentHashMap<>();

  /**
   * Commission a credential for one context.
   *
   * @param owner the client id of the caller, already authenticated
   * @param claims what this commission says its context is about, or null/empty for none — see
   *     {@link CommissionedClaims}, which is what decides whether a stated claim is acceptable
   * @param gitRefs the Git refs the credential may push, or null for "no scope stated" — see
   *     {@link GitRefs}
   * @throws OAuthException {@code invalid_request} (400) when the context kind or id is not one
   *     this service will put in a client id and a row, a stated claim is not one it will grant, or
   *     the Git refs break a rule
   */
  public Commissioned commission(
      String owner,
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs) {
    Context validated = Context.validated(contextKind, contextId);
    String kind = validated.kind();
    String context = validated.id();
    // Validated BEFORE anything is generated or written: a refused claim must cost the caller a 400
    // and leave no row and no secret behind.
    Map<String, String> stated = CommissionedClaims.stated(claims);
    List<String> refs = GitRefs.stated(gitRefs);

    String secret = randomToken(32);
    IdpDynamicClient row = new IdpDynamicClient();
    row.clientId = newClientId(kind, context);
    row.secretHash = ClientSecret.hash(secret);
    row.owner = owner;
    row.contextKind = kind;
    row.contextId = context;
    row.claims = CommissionedClaims.format(stated);
    row.gitRefs = GitRefs.format(refs);
    row.createdAt = Instant.now();

    // A bare insert, so DbRetry.inNewTx rather than DbRetry.call: it owns the transaction boundary
    // and therefore retries only the failures that certainly did not commit. A commit whose
    // acknowledgement was lost is REPORTED, not repeated — repeating it would leave a second
    // credential in the store that no owner ever heard of and no reconcile could attribute.
    DbRetry.runInNewTx("commission an idp client", () -> repository.persist(row));

    StoredClient stored = toStored(row);
    cache.put(stored.clientId(), stored);
    // The context id is not logged: it is the caller's string and the generated client id already
    // carries a slug of it, which is enough to find the context and is bounded by construction.
    // The claim NAMES, never their values: a value is the caller's string about its own context,
    // exactly like the context id above, and the same rule applies to it.
    // The same rule for the Git refs: how many, never which.
    LOG.infof(
        "commissioned client %s for owner %s, context kind %s, scoped by %s, git refs %s",
        LoggableClientId.of(stored.clientId()),
        LoggableClientId.of(owner),
        kind,
        stated.isEmpty() ? "nothing" : stated.keySet(),
        refs == null ? "not stated" : refs.size() + " entries");
    return new Commissioned(stored, secret);
  }

  /**
   * Replace the Git refs of one commission. Only its owner may; the credential itself may not.
   *
   * <p>The next token carries the new list. The cache entry is evicted on both sides of the write,
   * for the reason {@link #decommission} gives.
   *
   * @return the updated client, or empty when there is no such row or {@code caller} does not own
   *     it — one answer for both, as for decommission
   * @throws OAuthException {@code invalid_request} (400) when the list is missing or breaks a rule.
   *     Checked before the row is read, so this answer says nothing about whether the client exists.
   */
  public Optional<StoredClient> replaceGitRefs(
      String clientId, String caller, List<String> gitRefs) {
    if (gitRefs == null) {
      // "No list" would widen the credential back to its roles, so a replace always states one.
      throw OAuthException.invalidRequest(
          "gitRefs is required; send [] for a credential that may push nothing");
    }
    List<String> refs = GitRefs.stated(gitRefs);
    if (clientId == null || !clientId.startsWith(ID_PREFIX)) {
      return Optional.empty();
    }
    cache.remove(clientId);
    StoredClient updated =
        DbRetry.inNewTx(
            "replace the git refs of an idp client",
            () -> {
              IdpDynamicClient row = repository.findById(clientId);
              if (row == null || !row.owner.equals(caller)) {
                return null;
              }
              row.gitRefs = GitRefs.format(refs);
              return toStored(row);
            });
    cache.remove(clientId);
    if (updated == null) {
      LOG.warnf(
          "git refs change refused: %s does not own %s, or it does not exist",
          LoggableClientId.of(caller), LoggableClientId.of(clientId));
      return Optional.empty();
    }
    LOG.infof(
        "replaced the git refs of client %s, by %s: %d entries",
        LoggableClientId.of(clientId), LoggableClientId.of(caller), refs.size());
    return Optional.of(updated);
  }

  /** The stored client with this id — from the cache, else from the store. Misses are not cached. */
  public Optional<StoredClient> find(String clientId) {
    if (clientId == null || !clientId.startsWith(ID_PREFIX)) {
      // Nothing else can be a row: the id is generated here and always carries the prefix. Saying
      // so keeps every unknown static id out of the database entirely.
      return Optional.empty();
    }
    StoredClient cached = cache.get(clientId);
    if (cached != null) {
      return Optional.of(cached);
    }
    StoredClient loaded =
        DbRetry.inNewTx(
            "load a commissioned idp client",
            () -> {
              IdpDynamicClient row = repository.findById(clientId);
              return row == null ? null : toStored(row);
            });
    if (loaded != null) {
      cache.put(clientId, loaded);
    }
    return Optional.ofNullable(loaded);
  }

  /**
   * Delete the credential, if {@code caller} is allowed to.
   *
   * <p>Allowed is the owner that commissioned it, or the client itself — a context that knows it is
   * finishing can hand its own credential back without going through its owner. Anyone else gets
   * the same answer as a caller naming an id that does not exist, so the endpoint tells nobody
   * which other services hold which contexts.
   *
   * @return false when there is no such row, or the caller does not own it
   */
  public boolean decommission(String clientId, String caller) {
    StoredClient stored = find(clientId).orElse(null);
    if (stored == null) {
      return false;
    }
    if (!stored.owner().equals(caller) && !stored.clientId().equals(caller)) {
      LOG.warnf(
          "decommission refused: %s does not own %s",
          LoggableClientId.of(caller), LoggableClientId.of(clientId));
      return false;
    }
    // EVICTED ON BOTH SIDES OF THE DELETE, and both are load-bearing. Before, so a delete that
    // throws still leaves nothing cached — the failure then costs the next request a read rather
    // than leaving a decommissioned credential minting until the process restarts. After, because
    // a token request arriving in between would miss, read the row that is still there, and cache
    // it again; that entry has to go with the row.
    cache.remove(clientId);
    DbRetry.runInNewTx("decommission an idp client", () -> repository.deleteById(clientId));
    cache.remove(clientId);
    LOG.infof(
        "decommissioned client %s, by %s",
        LoggableClientId.of(clientId), LoggableClientId.of(caller));
    return true;
  }

  /**
   * One owner's live commissions — the reconciliation read, and the only listing there is. It goes
   * to the store rather than the cache: a caller comparing this against its own live contexts is
   * asking what actually exists.
   */
  public List<StoredClient> listOwnedBy(String owner) {
    return DbRetry.inNewTx(
        "list commissioned idp clients",
        () -> repository.listOwnedBy(owner).stream().map(DynamicClients::toStored).toList());
  }

  private static StoredClient toStored(IdpDynamicClient row) {
    return new StoredClient(
        row.clientId,
        row.secretHash,
        row.owner,
        row.contextKind,
        row.contextId,
        CommissionedClaims.parse(row.claims),
        GitRefs.parse(row.gitRefs),
        row.createdAt);
  }

  /**
   * {@code dyn-<kind>-<context slug>-<random>}. Readable in a listing on purpose — an operator
   * looking at idp's rows should be able to tell a stuck ci run from a stuck workspace without
   * joining anything — and unguessable where it matters, because the tail is 128 random bits and
   * the secret is separate from all of it.
   */
  private static String newClientId(String contextKind, String contextId) {
    return ID_PREFIX + contextKind + "-" + slug(contextId) + "-" + randomToken(16);
  }

  /**
   * The context id reduced to what may appear in a generated name: lowercase, {@code [a-z0-9-]}, at
   * most 24. Package-visible because a commissioned token's subject ({@link CommissionedTokens}) is
   * built to the same grammar, and one slug rule is what keeps the two listings reading alike.
   */
  static String slug(String contextId) {
    StringBuilder slug = new StringBuilder();
    for (char c : contextId.toLowerCase(Locale.ROOT).toCharArray()) {
      boolean plain = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
      if (plain) {
        slug.append(c);
      } else if (slug.length() > 0 && slug.charAt(slug.length() - 1) != '-') {
        slug.append('-');
      }
      if (slug.length() >= ID_SLUG_LENGTH) {
        break;
      }
    }
    while (slug.length() > 0 && slug.charAt(slug.length() - 1) == '-') {
      slug.setLength(slug.length() - 1);
    }
    // A context id of nothing but punctuation still needs a segment; the random tail is what
    // carries the identity anyway.
    return slug.length() == 0 ? "x" : slug.toString();
  }

  /**
   * Random bytes, base64url — {@link RandomSecret}, which is where the rule about never holding a
   * {@code SecureRandom} in a static field is written down and why.
   */
  private static String randomToken(int bytes) {
    return RandomSecret.bytes(bytes);
  }
}
