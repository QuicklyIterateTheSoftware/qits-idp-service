package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.control.ServiceClients.StoredServiceClient;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.jboss.logging.Logger;

/**
 * The rule that removes service clients no deployment claims any more (qits-878).
 *
 * <p><b>A service client is legitimate only while qits-deployments claims it</b>: the deployer
 * creates one per application it runs and records it as an {@code idp-client} resource, and that
 * claim is what says the credential still has a holder. The orchestrator reads {@code GET
 * /deployments/api/claims/idp-clients} and hands the answer here; it deletes nothing itself. This
 * class, the store's owner, applies the rule — the same split as qits-configuration's {@code
 * RetiredEntryCollector}.
 *
 * <p><b>The rule.</b> Every service client is judged, and kept for the first of these that holds:
 * {@link Reason#CLAIMED} (a claim names its id), {@link Reason#GRACE} (created less than {@link
 * #GRACE} ago), {@link Reason#CALLER} (it is the caller's own). Anything else is {@link
 * Reason#UNCLAIMED} and deleted through {@link ServiceClients#delete}, so the cache — and with it
 * the token path — forgets it in the same call. A dry run judges identically and deletes nothing.
 *
 * <p>Commissioned {@code dyn-*} clients are a different table ({@code idp_client}) with their own
 * lifecycle (a context's), and this class never sees them: it iterates {@link ServiceClients#list}
 * alone.
 *
 * <p>Refusing an empty claim set is the caller's job (the door answers 400), and it is the guard
 * that matters most: an empty set judged here would delete every client older than the grace.
 */
@ApplicationScoped
public class UnclaimedServiceClientCollector {

  private static final Logger LOG = Logger.getLogger(UnclaimedServiceClientCollector.class);

  /**
   * How young a client is kept regardless of claims. Code, not configuration: it covers two gaps
   * that exist by construction and are short — a bootstrap still running on its seed client before
   * any deployer has claimed it, and the deployer creating a client and writing its claim row in two
   * transactions, so a collection between the two must not take the credential from under a
   * deployment that is about to claim it. Six hours is far beyond either, and costs only that an
   * orphan lives a few hours longer.
   */
  public static final Duration GRACE = Duration.ofHours(6);

  /** Why a client was kept, or removed. The JSON spelling is {@link #wire()}. */
  public enum Reason {
    CLAIMED("claimed"),
    GRACE("grace"),
    CALLER("caller"),
    UNCLAIMED("unclaimed");

    private final String wire;

    Reason(String wire) {
      this.wire = wire;
    }

    public String wire() {
      return wire;
    }
  }

  /** One judged client. Never a secret or its hash. */
  public record Verdict(String clientId, Instant createdAt, String createdBy, Reason reason) {}

  /** What a run judged: every client lands in exactly one of the two lists. */
  public record Outcome(boolean dryRun, List<Verdict> removed, List<Verdict> kept) {

    /** How many were kept for this reason. */
    public int keptFor(Reason reason) {
      return (int) kept.stream().filter(verdict -> verdict.reason() == reason).count();
    }
  }

  @Inject ServiceClients serviceClients;

  /**
   * Judge every service client against the claimed ids and delete the unclaimed ones — or, on a dry
   * run, only name them.
   *
   * @param claimedIds the client ids qits-deployments claims; the caller has refused an empty set
   * @param callerId the authenticated caller's own client id, always kept
   */
  public Outcome collect(Set<String> claimedIds, String callerId, boolean dryRun) {
    Instant graceStart = Instant.now().minus(GRACE);
    List<Verdict> removed = new ArrayList<>();
    List<Verdict> kept = new ArrayList<>();
    for (StoredServiceClient client : serviceClients.list()) {
      Reason reason = judge(client, claimedIds, callerId, graceStart);
      Verdict verdict = new Verdict(client.clientId(), client.createdAt(), client.createdBy(), reason);
      if (reason != Reason.UNCLAIMED) {
        kept.add(verdict);
        continue;
      }
      if (dryRun) {
        removed.add(verdict);
        continue;
      }
      // false: somebody else deleted it between the listing and here — it is gone either way.
      serviceClients.delete(client.clientId());
      removed.add(verdict);
      LOG.infof(
          "gc: deleted service client %s (created %s by %s): no deployment claims it",
          LoggableClientId.of(client.clientId()),
          client.createdAt(),
          LoggableClientId.of(client.createdBy()));
    }
    Outcome outcome = new Outcome(dryRun, List.copyOf(removed), List.copyOf(kept));
    LOG.infof(
        "gc: service clients collected, dryRun=%s removed=%s kept claimed=%d grace=%d caller=%d",
        dryRun,
        removed.stream().map(verdict -> LoggableClientId.of(verdict.clientId())).toList(),
        outcome.keptFor(Reason.CLAIMED),
        outcome.keptFor(Reason.GRACE),
        outcome.keptFor(Reason.CALLER));
    return outcome;
  }

  private static Reason judge(
      StoredServiceClient client, Set<String> claimedIds, String callerId, Instant graceStart) {
    if (claimedIds.contains(client.clientId())) {
      return Reason.CLAIMED;
    }
    if (client.createdAt() != null && client.createdAt().isAfter(graceStart)) {
      return Reason.GRACE;
    }
    if (client.clientId().equals(callerId)) {
      return Reason.CALLER;
    }
    return Reason.UNCLAIMED;
  }
}
