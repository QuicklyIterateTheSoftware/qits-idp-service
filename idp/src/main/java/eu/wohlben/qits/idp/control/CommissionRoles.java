package eu.wohlben.qits.idp.control;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The fixed roles of a commissioned credential, by its context kind (D12 of
 * epic qits-540, dossier page "Plan (as of 2026-09-13)": roles are code, not configuration).
 *
 * <p><b>A commissioned credential no longer inherits its owner's roles.</b> Under the open calling
 * model {@code qits:system} is for service-to-service calls, and a commission is not a service — it
 * is a dynamic context a service provisioned, so it gets the kind's own role or none at all. Twelve
 * kinds carry a role:
 *
 * <ul>
 *   <li>{@code workspace}, {@code agent-container} and {@code refinement} get {@code qits:agent};
 *   <li>{@code workspace-admin} gets {@code qits:agent} and {@code qits:admin-agent} — the
 *       credential of an ADMIN workspace's container, the one that holds the host's docker socket.
 *       {@code qits:admin-agent} is the owner's role for an admin workspace's agent (qits-628
 *       follow-up, owner's request 2026-10-07): it is admitted wherever {@code qits:admin} is,
 *       named explicitly next to every such check, until the doors that must stay human-only drop
 *       it one by one. It is issued here and nowhere else — never to a person, never by
 *       configuration;
 *   <li>{@code ci-run} and {@code bootstrap-publish} get {@code qits:ci-run} — since the CI-runners
 *       campaign's closing release (qits-444, 2026-09-30), qits-ci commissions {@code ci-run} as a
 *       token ({@link CommissionedTokens}) rather than as a client; {@code bootstrap-publish} is
 *       still commissioned as a client, unchanged;
 *   <li>{@code ci-runner} gets {@code qits:ci-runner} — a CI runner's own identity, distinct from
 *       any one run's;
 *   <li>{@code ci-runner-registration} gets {@code qits:ci-runner-registration} — the credential a
 *       runner registers itself with, and nothing more;
 *   <li>{@code workspaces-runner} gets {@code qits:workspaces-runner} — a workspace runner's own
 *       identity, distinct from {@code ci-runner} and from {@code qits:agent};
 *   <li>{@code workspaces-runner-registration} gets {@code qits:workspaces-runner-registration} —
 *       the narrower credential a workspace runner registers itself with, and nothing more;
 *   <li>{@code projects-desk-runner} gets {@code qits:projects-desk-runner} — a front-desk runner's
 *       own identity, distinct from {@code workspaces-runner} and from {@code qits:agent};
 *   <li>{@code projects-desk-runner-registration} gets {@code qits:projects-desk-runner-registration}
 *       — the narrower credential a front-desk runner registers itself with, and nothing more.
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
 * {@code CommissionedClaims}), and its audience is {@code qits-platform} like every token's. Both
 * are {@link ClientRegistry}'s and {@link TokenService}'s.
 */
public final class CommissionRoles {

  private static final List<String> AGENT = List.of("qits:agent");

  /**
   * An admin workspace's agent: everything an agent is, plus the role every {@code qits:admin} door
   * also admits by name (qits-628 follow-up). See the class javadoc.
   */
  private static final List<String> ADMIN_AGENT = List.of("qits:agent", "qits:admin-agent");

  private static final List<String> CI_RUN = List.of("qits:ci-run");

  private static final List<String> CI_RUNNER = List.of("qits:ci-runner");

  private static final List<String> CI_RUNNER_REGISTRATION =
      List.of("qits:ci-runner-registration");

  private static final List<String> WORKSPACES_RUNNER = List.of("qits:workspaces-runner");

  private static final List<String> WORKSPACES_RUNNER_REGISTRATION =
      List.of("qits:workspaces-runner-registration");

  private static final List<String> PROJECTS_DESK_RUNNER = List.of("qits:projects-desk-runner");

  private static final List<String> PROJECTS_DESK_RUNNER_REGISTRATION =
      List.of("qits:projects-desk-runner-registration");

  /**
   * Looked up by key and never iterated, which is why {@link Map#ofEntries} is safe here: its
   * iteration order is salted per JVM, so a reader that ever walks this map must sort or keep its
   * own order. {@code Map.of}'s ten-argument overload is the varargs limit, not a design choice —
   * {@code ofEntries} is what a twelfth (and any later) kind moves to.
   */
  private static final Map<String, List<String>> SHIPPED =
      Map.ofEntries(
          Map.entry("workspace", AGENT),
          // An ADMIN workspace's container credential: it holds the host's docker socket, so its
          // agent is admitted wherever qits:admin is (qits-628 follow-up).
          Map.entry("workspace-admin", ADMIN_AGENT),
          Map.entry("agent-container", AGENT),
          Map.entry("refinement", AGENT),
          Map.entry("ci-run", CI_RUN),
          // The bootstrap's own publishing identity, for its publish phase only — same role as the
          // CI publisher because publishing is CI's door, deleted by the bootstrap at the end of
          // that phase. See the class javadoc.
          Map.entry("bootstrap-publish", CI_RUN),
          // A runner's own identity, and the narrower one it registers itself with. Neither is a
          // run, so neither holds qits:ci-run.
          Map.entry("ci-runner", CI_RUNNER),
          Map.entry("ci-runner-registration", CI_RUNNER_REGISTRATION),
          // A workspace runner's own identity, and the narrower one it registers itself with.
          // Neither is an agent, so neither holds qits:agent.
          Map.entry("workspaces-runner", WORKSPACES_RUNNER),
          Map.entry("workspaces-runner-registration", WORKSPACES_RUNNER_REGISTRATION),
          // A front-desk runner's own identity, and the narrower one it registers itself with.
          // Neither is a workspace runner, so neither holds qits:workspaces-runner.
          Map.entry("projects-desk-runner", PROJECTS_DESK_RUNNER),
          Map.entry("projects-desk-runner-registration", PROJECTS_DESK_RUNNER_REGISTRATION));

  private CommissionRoles() {}

  /** This kind's fixed role, or empty when it has none (D12) — never null. */
  public static List<String> forKind(String contextKind) {
    if (contextKind == null) {
      return List.of();
    }
    return Optional.ofNullable(SHIPPED.get(contextKind)).orElse(List.of());
  }
}
