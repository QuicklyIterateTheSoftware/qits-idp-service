package eu.wohlben.qits.idp.control;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The fixed roles of a commissioned credential, by its context kind (D12 of
 * {@code service-client-identity-plan.md}: roles are code, not configuration).
 *
 * <p><b>A commissioned credential no longer inherits its owner's roles.</b> Under the open calling
 * model {@code qits:system} is for service-to-service calls, and a commission is not a service — it
 * is a dynamic context a service provisioned, so it gets the kind's own role or none at all. Seven
 * kinds carry a role:
 *
 * <ul>
 *   <li>{@code workspace}, {@code agent-container} and {@code refinement} get {@code qits:agent};
 *   <li>{@code ci-run} and {@code bootstrap-publish} get {@code qits:ci-run};
 *   <li>{@code ci-runner} gets {@code qits:ci-runner} — a CI runner's own identity, distinct from
 *       any one run's;
 *   <li>{@code ci-runner-registration} gets {@code qits:ci-runner-registration} — the credential a
 *       runner registers itself with, and nothing more.
 * </ul>
 *
 * <p>The same map applies to a commissioned token ({@link CommissionedTokens}) as to a commissioned
 * client: the kind decides the roles, whichever credential carries it. <b>Every other
 * kind — including one this service has never heard of — gets no role</b>, only its own {@code
 * clients/<id>} self-role, and that is deliberate rather than a refusal: keeping this a plain map,
 * with no reserved-namespace check needed, is what {@code D12} bought by making an unknown kind
 * harmless instead of an error a test has to route around.
 *
 * <p><b>{@code bootstrap-publish} is the one kind that is not what its role's name says</b>, and the
 * reason is worth keeping next to the map. Publishing to qits-artifacts is CI's alone (user ruling
 * 2026-09-13, "only CI may publish"), so the anonymous publishing door is closed and {@code
 * qits:ci-run} is the only role that opens it. The bootstrap still has to publish once, before any
 * CI exists to do it for it — so it commissions <i>itself</i> a credential of this kind, with {@code
 * gitRefs: []} (it may push nothing), uses it for its publish phase, and <b>deletes it when that
 * phase ends</b> — a credential may always hand itself back, whatever role its kind gives it. The
 * identity is therefore short-lived by construction and no permanent publishing identity is left
 * behind; nothing here enforces that lifetime, the bootstrap does.
 *
 * <p>Only the roles are fixed here. A commission's claims are its own (D3, no owner merge — see
 * {@code CommissionedClaims}), and its audience rule follows its owner's (see {@link
 * IdpClient.AudienceSource}). Both are {@link ClientRegistry}'s.
 */
public final class CommissionRoles {

  private static final List<String> AGENT = List.of("qits:agent");

  private static final List<String> CI_RUN = List.of("qits:ci-run");

  private static final List<String> CI_RUNNER = List.of("qits:ci-runner");

  private static final List<String> CI_RUNNER_REGISTRATION =
      List.of("qits:ci-runner-registration");

  /**
   * Looked up by key and never iterated, which is why {@link Map#of} is safe here: its iteration
   * order is salted per JVM, so a reader that ever walks this map must sort or keep its own order.
   */
  private static final Map<String, List<String>> SHIPPED =
      Map.of(
          "workspace", AGENT,
          "agent-container", AGENT,
          "refinement", AGENT,
          "ci-run", CI_RUN,
          // The bootstrap's own publishing identity, for its publish phase only — same role as the
          // CI publisher because publishing is CI's door, deleted by the bootstrap at the end of
          // that phase. See the class javadoc.
          "bootstrap-publish", CI_RUN,
          // A runner's own identity, and the narrower one it registers itself with. Neither is a
          // run, so neither holds qits:ci-run.
          "ci-runner", CI_RUNNER,
          "ci-runner-registration", CI_RUNNER_REGISTRATION);

  private CommissionRoles() {}

  /** This kind's fixed role, or empty when it has none (D12) — never null. */
  public static List<String> forKind(String contextKind) {
    if (contextKind == null) {
      return List.of();
    }
    return Optional.ofNullable(SHIPPED.get(contextKind)).orElse(List.of());
  }
}
