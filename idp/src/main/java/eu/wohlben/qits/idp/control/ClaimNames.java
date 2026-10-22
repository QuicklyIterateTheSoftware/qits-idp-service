package eu.wohlben.qits.idp.control;

import java.util.List;

/**
 * The structured claims a token may carry beyond the registered ones.
 *
 * <p>Claims, not scopes: {@code aud} names the service a token is for, and these name what it is
 * for <em>within</em> that service. The list is closed on purpose — it bounds what a commission may
 * state ({@link CommissionedClaims}) and it is the same set the shared enforcement helpers in
 * {@code qits-auth-core} know. Adding a claim is a change in both places.
 *
 * <p>The idp only states a claim. What a value permits — including whether {@code *} means "any" —
 * is the resource service's decision.
 */
public final class ClaimNames {

  /** The project a token may act on, matched against the project a request names. */
  public static final String PROJECT = "project";

  /** The workspace a token may act on. */
  public static final String WORKSPACE = "workspace";

  /** The branch a token may act on — a workspace agent pushes only to its own. */
  public static final String BRANCH = "branch";

  /**
   * The coding agent a token belongs to: the agent's UUID. Only a commission states it, for an
   * agent's own credential — no service client carries it, because a service client's claims are
   * fixed in code ({@link ClientRegistry}) and name only {@link #PROJECT}.
   */
  public static final String AGENT = "agent";

  /**
   * The work item a token is bound to: the entity's UUID. qits-projects states it on a refinement
   * session's own token (qits-1482), and its refinement doors refuse a bearer whose entity is not
   * the refinement's. Only a commission states it.
   */
  public static final String ENTITY = "entity";

  /** Every claim a commission may state, in the order a token carries them. */
  public static final List<String> GRANTABLE = List.of(PROJECT, WORKSPACE, BRANCH, AGENT, ENTITY);

  /**
   * The Git refs a token may push, a JSON array — see {@link GitRefs}. NOT grantable: the idp sets
   * it on person tokens and from a commission's own list, never from config or a claims map.
   */
  public static final String GIT_REFS = "git_refs";

  /** The commission's {@code contextKind}, on every token of a commissioned client. Not grantable. */
  public static final String CONTEXT_KIND = "context_kind";

  private ClaimNames() {}
}
