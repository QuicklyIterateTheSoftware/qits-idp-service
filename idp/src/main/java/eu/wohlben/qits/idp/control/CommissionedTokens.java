package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.control.DynamicClients.Context;
import eu.wohlben.qits.idp.entity.IdpToken;
import eu.wohlben.qits.idp.error.OAuthException;
import eu.wohlben.qits.idp.persistence.IdpTokenRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.jboss.logging.Logger;

/**
 * Commissioned tokens: the third credential beside service clients and commissioned clients — an
 * opaque bearer, verified here on every use.
 *
 * <p><b>Why a third credential.</b> A commissioned client is an id and a secret that mints JWTs,
 * and a JWT is verified offline against the JWKS: deleting the client stops the minting, but a token
 * it minted a second earlier keeps working until its {@code exp} (the grace recorded on {@code
 * qits.idp.token-ttl-seconds}). A commissioned token has no claims inside it at all. The only way to
 * learn anything from one is to ask here, so the row is the single truth, and deleting it is
 * revocation that is immediate for the very next introspection.
 *
 * <p><b>No expiry and no TTL.</b> The lifetime is the context's, exactly as for a commissioned
 * client: the owner that commissioned the token deletes it when the context ends, or the token hands
 * itself back. Deleting the row is the whole revocation; there is no deadline column to enforce and
 * no second way for a token to end.
 *
 * <p><b>What a token carries is decided exactly as for a commissioned client of the same kind.</b>
 * The same kind and context rules ({@link Context}), the same claims rule ({@link
 * CommissionedClaims}), the same Git-refs rule ({@link GitRefs}), and at introspection the same
 * roles ({@link CommissionRoles#forKind}) — never the owner's. Only a service client commissions
 * one; that check is at the boundary, on the caller's credentials.
 *
 * <p><b>The value is never logged, never stored, never announced.</b> It exists in the commission
 * answer and nowhere else; the row holds {@link TokenValue#hash}. Log lines name the subject.
 */
@ApplicationScoped
public class CommissionedTokens {

  private static final Logger LOG = Logger.getLogger(CommissionedTokens.class);

  /**
   * The prefix every token subject carries. It keeps a token's {@code sub} disjoint from a
   * commissioned client's {@code dyn-…} and from every service client's name, so a resource service
   * reading {@code sub} — or a self-role {@code clients/tok-…} — can never mistake one for another.
   */
  public static final String SUBJECT_PREFIX = "tok-";

  /**
   * A row as everything outside persistence sees it — a record, so nothing caches a live entity.
   * Never the hash: nothing outside this class has a use for it.
   *
   * @param claims the claims this commission stated, already parsed; empty is the ordinary case
   * @param gitRefs the Git refs this token may push; null when no list was stated, empty for "push
   *     nothing"
   */
  public record StoredToken(
      UUID id,
      String subject,
      String owner,
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs,
      Instant createdAt) {}

  /** A fresh commission, with the value that exists only in this answer. */
  public record Commissioned(StoredToken token, String value) {}

  @Inject IdpTokenRepository repository;

  /**
   * Commission a token for one context.
   *
   * @param owner the client id of the caller, already authenticated as a service client
   * @param claims what this context is about, or null/empty for none — see {@link
   *     CommissionedClaims}
   * @param gitRefs the Git refs the token may push, or null for "no scope stated" — see {@link
   *     GitRefs}
   * @throws OAuthException {@code invalid_request} (400) when the kind or id is not one this service
   *     will put in a subject and a row, a stated claim is not one it will grant, or the Git refs
   *     break a rule
   */
  public Commissioned commission(
      String owner,
      String contextKind,
      String contextId,
      Map<String, String> claims,
      List<String> gitRefs) {
    // Every rule is checked BEFORE anything is generated or written, exactly as for a commissioned
    // client: a refusal costs the caller a 400 and leaves no row and no value behind.
    Context context = Context.validated(contextKind, contextId);
    Map<String, String> stated = CommissionedClaims.stated(claims);
    List<String> refs = GitRefs.stated(gitRefs);

    String value = TokenValue.mint();
    IdpToken row = new IdpToken();
    row.id = UUID.randomUUID();
    row.subject = newSubject(context);
    row.tokenHash = TokenValue.hash(value);
    row.owner = owner;
    row.contextKind = context.kind();
    row.contextId = context.id();
    row.claims = CommissionedClaims.format(stated);
    row.gitRefs = GitRefs.format(refs);
    row.createdAt = Instant.now();

    // A bare insert, so DbRetry.inNewTx rather than DbRetry.call, for the reason DynamicClients
    // gives: a commit whose acknowledgement was lost is REPORTED, not repeated, because repeating it
    // would leave a second live token in the store that no owner ever heard of.
    DbRetry.runInNewTx("commission an idp token", () -> repository.persist(row));

    StoredToken stored = toStored(row);
    // The subject, never the value; the claim names and the ref count, never their values — the
    // same rule as a commissioned client's log line, for the same reasons.
    LOG.infof(
        "commissioned token %s for owner %s, context kind %s, scoped by %s, git refs %s",
        LoggableClientId.of(stored.subject()),
        LoggableClientId.of(owner),
        stored.contextKind(),
        stated.isEmpty() ? "nothing" : stated.keySet(),
        refs == null ? "not stated" : refs.size() + " entries");
    return new Commissioned(stored, value);
  }

  /**
   * The live token behind this value, or empty.
   *
   * <p><b>A value that is not shaped like a token costs nothing</b>: no hash and no store read, so a
   * JWT or a stray header sent here by mistake is answered in memory. Otherwise the value is hashed
   * and looked up by that hash.
   *
   * <p><b>There is no cache, deliberately.</b> {@link DynamicClients} caches because a token request
   * is the platform's whole call graph; this read is behind the edge's own short cache instead, and
   * the promise it keeps is the opposite one — a deleted row is refused on the very next call. A
   * cache here would turn that into "after the entry ages out", which is the JWT's {@code exp}
   * problem this credential exists to avoid.
   */
  public Optional<StoredToken> introspect(String value) {
    if (!TokenValue.isToken(value)) {
      return Optional.empty();
    }
    String hash = TokenValue.hash(value);
    StoredToken found =
        DbRetry.inNewTx(
            "introspect an idp token",
            () -> {
              IdpToken row = repository.findByHash(hash);
              return row == null ? null : toStored(row);
            });
    // DEBUG only: this runs on every edge cache miss, and the subject is all that is worth naming.
    if (found == null) {
      LOG.debug("token introspection found no live token");
    } else {
      LOG.debugf("token introspection resolved %s", LoggableClientId.of(found.subject()));
    }
    return Optional.ofNullable(found);
  }

  /**
   * One owner's live tokens — the reconciliation read, and the only listing there is. Straight to
   * the store: a caller comparing this against its own live contexts is asking what exists.
   */
  public List<StoredToken> listOwned(String owner) {
    return DbRetry.inNewTx(
        "list commissioned idp tokens",
        () -> repository.listOwnedBy(owner).stream().map(CommissionedTokens::toStored).toList());
  }

  /**
   * Delete the token, if {@code caller} is allowed to.
   *
   * <p>Allowed is the owner that commissioned it, or the token itself — {@code caller} equal to its
   * own subject, which is how the boundary names a token that presented itself. Anyone else gets the
   * same answer as an id that does not exist, the rule {@link DynamicClients#decommission} keeps, so
   * nobody learns which contexts other services hold.
   *
   * @return false when there is no such row, or the caller may not delete it
   */
  public boolean delete(UUID id, String caller) {
    if (id == null || caller == null) {
      return false;
    }
    String deleted =
        DbRetry.inNewTx(
            "delete an idp token",
            () -> {
              IdpToken row = repository.findById(id);
              if (row == null || !(row.owner.equals(caller) || row.subject.equals(caller))) {
                return null;
              }
              repository.delete(row);
              return row.subject;
            });
    if (deleted == null) {
      LOG.warnf(
          "token delete refused: %s does not own %s, or it does not exist",
          LoggableClientId.of(caller), id);
      return false;
    }
    LOG.infof("deleted token %s, by %s", LoggableClientId.of(deleted), LoggableClientId.of(caller));
    return true;
  }

  private static StoredToken toStored(IdpToken row) {
    return new StoredToken(
        row.id,
        row.subject,
        row.owner,
        row.contextKind,
        row.contextId,
        CommissionedClaims.parse(row.claims),
        GitRefs.parse(row.gitRefs),
        row.createdAt);
  }

  /**
   * {@code tok-<kind>-<context slug>-<random>} — the commissioned client's grammar with its own
   * prefix, so an operator reads a token's context off a listing the same way, and a 128-bit tail
   * keeps two tokens for one context apart.
   */
  private static String newSubject(Context context) {
    return SUBJECT_PREFIX
        + context.kind()
        + "-"
        + DynamicClients.slug(context.id())
        + "-"
        + RandomSecret.bytes(16);
  }
}
