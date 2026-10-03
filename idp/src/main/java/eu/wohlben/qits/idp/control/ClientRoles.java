package eu.wohlben.qits.idp.control;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The roles a client bearer carries: its fixed ones, plus the one this service writes itself.
 *
 * <p><b>Every client token names its own client.</b> {@code clients/<client-id>} is stamped into
 * the {@code groups} claim of every {@code client_credentials} token, additive to the client's
 * other roles. Nobody asks for it, nobody can turn it off, and it is computed from the id that just
 * authenticated — so a role naming one client is held by exactly that client, by construction
 * rather than by grant. That is what lets a resource service write
 * {@code @RolesAllowed("clients/prod-qits-projects")} and know the door opens for one caller only.
 * The commissioned credentials get theirs the same way, for free.
 *
 * <p><b>A commissioned client never carries its owner's self-role, whatever roles it does
 * carry.</b> The stamp is made from the id in the token's {@code sub}, so a credential commissioned
 * by qits-projects carries {@code clients/dyn-…} — its own — and cannot reach a door held open for
 * qits-projects itself. That falls out of the mechanism; there is no rule to keep. (Its other
 * roles, if any, are its context kind's fixed ones — {@link CommissionRoles} — not a copy of its
 * owner's; see {@link ClientRegistry}.)
 *
 * <p><b>So the namespace is reserved, and today nothing can even ask for it.</b> Every role a
 * client carries is code: a service client's {@code qits:system} ({@link ClientRegistry}) and a
 * commission's kind role ({@link CommissionRoles}). The configured {@code roles} lines that once
 * needed a guard against {@code clients/…} went with the environment registry (qits-163). A future
 * change that lets roles come from anywhere else — configuration, a request, a row — must refuse
 * this prefix there, or any client could be granted another client's identity.
 *
 * <p>User credentials get no self-role: a session belongs to a person and a workstation token is
 * deliberately not an ordinary identity either. This is a machine-client feature and lives on the
 * one path that mints to a client credential, {@link TokenService#clientCredentials}.
 */
public final class ClientRoles {

  /**
   * The reserved namespace. Everything under it is minted here and configurable nowhere — the
   * slash keeps it out of the {@code $app:$resource:$role} shape every configured role has.
   */
  public static final String SELF_PREFIX = "clients/";

  private ClientRoles() {}

  /** The role that names exactly one client. */
  public static String selfRoleOf(String clientId) {
    return SELF_PREFIX + clientId;
  }

  /**
   * The client's roles, then its self-role — the {@code groups} claim of a minted token.
   *
   * <p>A {@link LinkedHashSet}, so the roles' order is what a reader sees and a self-role that
   * somehow arrived twice appears once. No source of roles can produce that duplicate today;
   * deduplicating anyway costs nothing and keeps the claim's shape independent of how the roles
   * were assembled.
   */
  public static Set<String> mintedFor(IdpClient client) {
    Set<String> roles = new LinkedHashSet<>(client.roles());
    roles.add(selfRoleOf(client.clientId()));
    return roles;
  }
}
