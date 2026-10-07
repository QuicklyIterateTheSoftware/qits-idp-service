package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The fixed code map itself, without a process around it (D3/D12 of the epic qits-540 dossier,
 * "Plan (as of 2026-09-13)": a commission's roles are code, never configuration).
 * {@code CommissionedGitRefsTest} checks the same lines through minted tokens end to end.
 */
public class CommissionRolesTest {

  @Test
  public void eachShippedKindHasItsFixedRole() {
    assertEquals(List.of("qits:agent"), CommissionRoles.forKind("workspace"));
    assertEquals(List.of("qits:agent"), CommissionRoles.forKind("agent-container"));
    // An ADMIN workspace's container credential (it holds the host docker socket): an agent, plus
    // the role every qits:admin door also admits by name (qits-628 follow-up).
    assertEquals(
        List.of("qits:agent", "qits:admin-agent"), CommissionRoles.forKind("workspace-admin"));
    assertEquals(List.of("qits:agent"), CommissionRoles.forKind("refinement"));
    assertEquals(List.of("qits:ci-run"), CommissionRoles.forKind("ci-run"));
    // The bootstrap's own publishing identity holds the CI publisher's role, because publishing to
    // qits-artifacts is CI's door (user ruling 2026-09-13). It is short-lived: the bootstrap
    // deletes it when its publish phase ends.
    assertEquals(List.of("qits:ci-run"), CommissionRoles.forKind("bootstrap-publish"));
    // A CI runner's own identity and its registration credential: each its own role, neither a
    // run's — the token-auth epic (qits-448).
    assertEquals(List.of("qits:ci-runner"), CommissionRoles.forKind("ci-runner"));
    assertEquals(
        List.of("qits:ci-runner-registration"), CommissionRoles.forKind("ci-runner-registration"));
    // A workspace runner's own identity and its registration credential: each its own role,
    // neither qits:agent nor qits:ci-runner (qits-845, qits-629).
    assertEquals(
        List.of("qits:workspaces-runner"), CommissionRoles.forKind("workspaces-runner"));
    assertEquals(
        List.of("qits:workspaces-runner-registration"),
        CommissionRoles.forKind("workspaces-runner-registration"));
    assertNotEquals(List.of("qits:agent"), CommissionRoles.forKind("workspaces-runner"));
    assertNotEquals(List.of("qits:agent"), CommissionRoles.forKind("workspaces-runner-registration"));
    assertNotEquals(
        List.of("qits:ci-runner"), CommissionRoles.forKind("workspaces-runner"));
    assertNotEquals(
        List.of("qits:ci-runner"), CommissionRoles.forKind("workspaces-runner-registration"));
  }

  @Test
  public void onlyTheAdminWorkspaceKindCarriesTheAdminAgentRole() {
    // qits:admin-agent is issued by this one line and nowhere else: a plain workspace, and every
    // other shipped kind, stays without it.
    for (String kind :
        List.of(
            "workspace",
            "agent-container",
            "refinement",
            "ci-run",
            "bootstrap-publish",
            "ci-runner",
            "ci-runner-registration",
            "workspaces-runner",
            "workspaces-runner-registration")) {
      assertFalse(CommissionRoles.forKind(kind).contains("qits:admin-agent"), kind);
      assertFalse(CommissionRoles.forKind(kind).contains("qits:admin"), kind);
    }
    assertFalse(
        CommissionRoles.forKind("workspace-admin").contains("qits:admin"),
        "an admin workspace's agent is not a person: it never holds qits:admin itself");
  }

  @Test
  public void anUnknownKindGetsNoRoleAtAll() {
    // D12: unknown kind -> no role, not a refusal — the credential still mints, with only its own
    // clients/<id> self-role.
    assertEquals(List.of(), CommissionRoles.forKind("some-other-kind"));
    assertEquals(List.of(), CommissionRoles.forKind(null));
    assertEquals(List.of(), CommissionRoles.forKind(""));
    // Case matters: the shipped map is keyed on the exact lowercase spelling.
    assertEquals(List.of(), CommissionRoles.forKind("Workspace"));
    assertEquals(List.of(), CommissionRoles.forKind("Workspace-Admin"));
  }
}
