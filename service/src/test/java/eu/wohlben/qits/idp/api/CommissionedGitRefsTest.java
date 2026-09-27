package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.entity.IdpDynamicClient;
import eu.wohlben.qits.idp.persistence.IdpDynamicClientRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.restassured.http.ContentType;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.ValidatableResponse;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * Principal-bound Git refs, contracts C1 and C2 of {@code principal-bound-git-refs-plan.md}: the
 * {@code git_refs} and {@code context_kind} claims per principal, {@code gitRefs} on a commission,
 * the owner-only {@code PUT …/git-refs}, and roles per context kind.
 *
 * <p>The person tokens (CLI, workstation) are pinned in {@link CliOAuthTest} and {@link
 * WorkstationOAuthTest}; the rules for one list in {@code GitRefsTest}.
 *
 * <p>Every test names its own {@code contextKind}: the suite shares one store, so a listing check
 * filters on it. <b>Roles per kind are code now, not configuration</b>
 * (service-client-identity-plan.md, D3/D12): a commission's role is its context kind's fixed one
 * ({@code workspace}, {@code agent-container}, {@code refinement} → {@code qits:agent}; {@code
 * ci-run} and {@code bootstrap-publish} → {@code qits:ci-run}; {@code ci-runner} → {@code
 * qits:ci-runner}; {@code ci-runner-registration} → {@code qits:ci-runner-registration}; {@code
 * test-client} → {@code qits:token-test}) or, for any other kind, none at all beyond its own
 * self-role. There is no longer a way to configure one, so these tests exercise the eight shipped
 * kinds and an invented, deliberately unknown one rather
 * than a test-only configured kind.
 */
@QuarkusTest
public class CommissionedGitRefsTest {

  private static final String OWNER = "test-broad";
  private static final String OWNER_SECRET = "test-broad-secret";
  private static final String OTHER_OWNER = "test-narrow";
  private static final String OTHER_OWNER_SECRET = "test-narrow-secret";

  private static final String TICKET = "refs/heads/ticket/t-1";
  private static final String EPIC = "refs/heads/epic/e-1";
  private static final String FEATURES = "refs/heads/feature/e-1/*";

  @Inject IdpDynamicClientRepository repository;

  // --- C1: the claims per principal -----------------------------------------------------------

  @Test
  public void aStaticClientTokenCarriesNeitherClaim() throws Exception {
    JwtClaims claims = claimsOf(OWNER, OWNER_SECRET);

    assertFalse(claims.hasClaim("git_refs"), "a static service client stays unrestricted");
    assertFalse(claims.hasClaim("context_kind"), "and states no context");
  }

  @Test
  public void aCommissionThatStatesNoListCarriesItsKindAndNoRefs() throws Exception {
    Commission commission =
        commission(OWNER, OWNER_SECRET, body("refs-unstated", "ctx-1", null))
            .statusCode(201)
            .body("gitRefs", nullValue())
            .extract()
            .as(Commission.class);

    JwtClaims claims = claimsOf(commission.clientId(), commission.secret());
    assertEquals("refs-unstated", claims.getClaimValueAsString("context_kind"));
    assertFalse(claims.hasClaim("git_refs"), "no list stated is no claim — today's behaviour");
    assertNull(row(commission.clientId()).gitRefs, "and a null column");
  }

  @Test
  public void aCommissionsListReachesEveryTokenTheListingAndTheRow() throws Exception {
    Commission commission =
        commission(OWNER, OWNER_SECRET, body("refs-stated", "ctx-2", List.of(EPIC, FEATURES)))
            .statusCode(201)
            .body("gitRefs", equalTo(List.of(EPIC, FEATURES)))
            .extract()
            .as(Commission.class);

    JwtClaims claims = claimsOf(commission.clientId(), commission.secret());
    assertEquals(List.of(EPIC, FEATURES), claims.getStringListClaimValue("git_refs"));
    assertEquals("refs-stated", claims.getClaimValueAsString("context_kind"));
    // refs-stated has no fixed role (D12): stating a Git refs list changes nothing about roles.
    assertEquals(
        List.of("clients/" + commission.clientId()), claims.getStringListClaimValue("groups"));

    assertEquals(EPIC + "\n" + FEATURES, row(commission.clientId()).gitRefs);
    given()
        .header("Authorization", basic(OWNER, OWNER_SECRET))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .body(
            "find { it.clientId == '" + commission.clientId() + "' }.gitRefs",
            equalTo(List.of(EPIC, FEATURES)));
  }

  @Test
  public void anEmptyListIsPushNothingAndReachesTheToken() throws Exception {
    Commission commission =
        commission(OWNER, OWNER_SECRET, body("refs-empty", "ctx-3", List.of()))
            .statusCode(201)
            .body("gitRefs", equalTo(List.of()))
            .extract()
            .as(Commission.class);

    JwtClaims claims = claimsOf(commission.clientId(), commission.secret());
    assertTrue(claims.hasClaim("git_refs"), "an empty list is a statement, not an absence");
    assertEquals(List.of(), claims.getStringListClaimValue("git_refs"));
    assertEquals("", row(commission.clientId()).gitRefs, "the empty string, never null");
  }

  // --- C2: validation -------------------------------------------------------------------------

  @Test
  public void everyRuleIsA400AndLeavesNoRow() {
    String kind = "refs-refused";
    List<String> tooMany = new ArrayList<>();
    for (int i = 0; i <= 500; i++) {
      tooMany.add("refs/heads/task/t-" + i);
    }
    List<String> bodies =
        List.of(
            body(kind, "tag", List.of("refs/tags/v1")),
            body(kind, "star", List.of("refs/heads/a*b")),
            body(kind, "too-many", tooMany),
            body(kind, "too-long", List.of("refs/heads/" + "x".repeat(245))),
            body(kind, "repeated", List.of(TICKET, TICKET)),
            "{\"contextKind\":\"" + kind + "\",\"contextId\":\"null\",\"gitRefs\":[null]}",
            "{\"contextKind\":\"" + kind + "\",\"contextId\":\"control\","
                + "\"gitRefs\":[\"refs/heads/a\\nrefs/heads/b\"]}");

    for (String refused : bodies) {
      commission(OWNER, OWNER_SECRET, refused)
          .statusCode(400)
          .body("error", equalTo("invalid_request"));
    }
    assertEquals(List.of(), listedIds(OWNER, OWNER_SECRET, kind), "no row, no secret left behind");

    // The limits themselves are allowed: 255 characters and 500 entries.
    commission(OWNER, OWNER_SECRET, body(kind + "-ok", "longest", List.of("refs/heads/" + "x".repeat(244))))
        .statusCode(201);
    commission(OWNER, OWNER_SECRET, body(kind + "-ok", "most", tooMany.subList(0, 500)))
        .statusCode(201);
  }

  // --- C2: the owner replaces the list ----------------------------------------------------------

  @Test
  public void theOwnerReplacesTheListAndTheNextTokenCarriesIt() throws Exception {
    Commission commission = created(OWNER, OWNER_SECRET, body("refs-put", "ctx-4", List.of(EPIC, TICKET)));
    // Mint once first, so the credential is in the cache: the replace must reach past it.
    assertEquals(
        List.of(EPIC, TICKET),
        claimsOf(commission.clientId(), commission.secret()).getStringListClaimValue("git_refs"));

    replace(OWNER, OWNER_SECRET, commission.clientId(), List.of(EPIC))
        .statusCode(200)
        .body("clientId", equalTo(commission.clientId()))
        .body("contextKind", equalTo("refs-put"))
        .body("gitRefs", equalTo(List.of(EPIC)))
        .body("secret", nullValue());

    assertEquals(
        List.of(EPIC),
        claimsOf(commission.clientId(), commission.secret()).getStringListClaimValue("git_refs"),
        "the sub-workspace took the ticket branch; the epic credential lost it");

    replace(OWNER, OWNER_SECRET, commission.clientId(), List.of()).statusCode(200);
    assertEquals(
        List.of(),
        claimsOf(commission.clientId(), commission.secret()).getStringListClaimValue("git_refs"));
  }

  @Test
  public void aReplaceScopesACommissionThatStatedNoList() throws Exception {
    Commission commission = created(OWNER, OWNER_SECRET, body("refs-put-unstated", "ctx-5", null));
    assertFalse(claimsOf(commission.clientId(), commission.secret()).hasClaim("git_refs"));

    replace(OWNER, OWNER_SECRET, commission.clientId(), List.of(TICKET)).statusCode(200);

    assertEquals(
        List.of(TICKET),
        claimsOf(commission.clientId(), commission.secret()).getStringListClaimValue("git_refs"));
  }

  @Test
  public void onlyTheOwnerMayReplaceTheList() throws Exception {
    Commission commission = created(OWNER, OWNER_SECRET, body("refs-put-owner", "ctx-6", List.of(TICKET)));
    List<String> wider = List.of("refs/heads/*");

    // Another service client is told what a caller naming a nonexistent id is told.
    replace(OTHER_OWNER, OTHER_OWNER_SECRET, commission.clientId(), wider)
        .statusCode(404)
        .body("error", equalTo("not_found"));
    replace(OWNER, OWNER_SECRET, "dyn-nothing-here-Aaaaaaaaaaaaaaaaaaaaaa", wider)
        .statusCode(404)
        .body("error", equalTo("not_found"));
    replace(OWNER, OWNER_SECRET, "prod-qits-ci", wider).statusCode(404);

    // The credential itself may not widen its own list: only a static client may use this verb.
    replace(commission.clientId(), commission.secret(), commission.clientId(), wider)
        .statusCode(403)
        .body("error", equalTo("access_denied"));

    // No credentials, or the wrong secret.
    given()
        .contentType(ContentType.JSON)
        .body("{\"gitRefs\":[]}")
        .when()
        .put("/idp/api/clients/" + commission.clientId() + "/git-refs")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
    replace(OWNER, "wrong", commission.clientId(), wider).statusCode(401);

    assertEquals(
        List.of(TICKET),
        claimsOf(commission.clientId(), commission.secret()).getStringListClaimValue("git_refs"),
        "none of the refused calls changed the list");
  }

  @Test
  public void aReplaceMustStateAValidList() throws Exception {
    Commission commission = created(OWNER, OWNER_SECRET, body("refs-put-invalid", "ctx-7", List.of(TICKET)));
    String path = "/idp/api/clients/" + commission.clientId() + "/git-refs";

    // No list at all would widen the credential back to its roles, so it is refused.
    for (String refused : List.of("{}", "{\"gitRefs\":null}", "{\"gitRefs\":[\"refs/tags/v1\"]}")) {
      given()
          .contentType(ContentType.JSON)
          .header("Authorization", basic(OWNER, OWNER_SECRET))
          .body(refused)
          .when()
          .put(path)
          .then()
          .statusCode(400)
          .body("error", equalTo("invalid_request"));
    }

    // The list is checked before the client is looked up, so a foreign caller learns nothing.
    replace(OTHER_OWNER, OTHER_OWNER_SECRET, commission.clientId(), List.of("refs/tags/v1"))
        .statusCode(400);

    assertEquals(
        List.of(TICKET),
        claimsOf(commission.clientId(), commission.secret()).getStringListClaimValue("git_refs"));
  }

  // --- C2: roles per context kind ---------------------------------------------------------------

  @Test
  public void aShippedKindGetsItsFixedRoleInsteadOfTheOwners() throws Exception {
    Commission agent = created(OWNER, OWNER_SECRET, body("workspace", "ctx-8", List.of(TICKET)));

    JwtClaims claims = claimsOf(agent.clientId(), agent.secret());
    assertEquals(
        List.of("qits:agent", "clients/" + agent.clientId()),
        claims.getStringListClaimValue("groups"),
        "the kind's fixed role and the credential's own self-role; not qits:system");
    assertEquals(
        List.of("prod-qits-ci", "qits-deployments", "qits-platform"),
        PublishedJwks.audienceOf(claims),
        "only the roles change: the audiences are still the owner's, plus qits-platform");
    assertEquals("workspace", claims.getClaimValueAsString("context_kind"));

    // A kind with no fixed role gets none at all any more (D12) — not the owner's.
    Commission plain = created(OWNER, OWNER_SECRET, body("kind-with-no-line", "ctx-8b", null));
    assertEquals(
        List.of("clients/" + plain.clientId()),
        claimsOf(plain.clientId(), plain.secret()).getStringListClaimValue("groups"));
  }

  @Test
  public void aCredentialWithItsKindsRolesMayStillHandItselfBack() {
    Commission agent = created(OWNER, OWNER_SECRET, body("workspace", "ctx-10", null));
    Commission other = created(OWNER, OWNER_SECRET, body("workspace", "ctx-11", null));

    // It lacks the platform role, so it may not decommission another credential.
    decommission(agent.clientId(), agent.secret(), other.clientId()).statusCode(403);

    // But giving back its own credential needs no role.
    decommission(agent.clientId(), agent.secret(), agent.clientId()).statusCode(204);
    token(agent.clientId(), agent.secret()).statusCode(401);
    decommission(OWNER, OWNER_SECRET, other.clientId()).statusCode(204);
  }

  @Test
  public void anAgentKeepsItsReadsAndLosesOnlyWrites() {
    // User ruling 2026-09-12: agents keep every read; only writes are restricted. The workspace
    // kind carries qits:agent, its fixed role (D3/D12) — never the owner's.
    Commission agent = created(OWNER, OWNER_SECRET, body("workspace", "ctx-12", null));

    // The one read route with a role check: the listing. It commissions nothing, so it is empty —
    // the answer it got while it carried its owner's roles.
    given()
        .header("Authorization", basic(agent.clientId(), agent.secret()))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .body("size()", equalTo(0));

    // The writes stay shut: it may not commission, and may not change a commission.
    commission(agent.clientId(), agent.secret(), body("agent-test", "ctx-12-child", null))
        .statusCode(403);
    replace(agent.clientId(), agent.secret(), agent.clientId(), List.of()).statusCode(403);

    decommission(OWNER, OWNER_SECRET, agent.clientId()).statusCode(204);
  }

  // --- phase 4: the kinds the jar ships roles for -------------------------------------------------

  /**
   * The shipped code map, {@code CommissionRoles.SHIPPED}, as it is. Every case below iterates this
   * and each iteration stands alone, so {@code Map.of}'s salted, per-JVM iteration order changes
   * nothing — do not write a case here whose outcome depends on the order.
   */
  private static final Map<String, String> SHIPPED_KINDS =
      Map.of(
          "workspace", "qits:agent",
          "agent-container", "qits:agent",
          "refinement", "qits:agent",
          "ci-run", "qits:ci-run",
          "bootstrap-publish", "qits:ci-run",
          "ci-runner", "qits:ci-runner",
          "ci-runner-registration", "qits:ci-runner-registration",
          "test-client", "qits:token-test");

  @Test
  public void eachShippedKindCarriesExactlyItsRoleAndItsSelfRole() throws Exception {
    for (Map.Entry<String, String> kind : SHIPPED_KINDS.entrySet()) {
      Commission commission =
          created(OWNER, OWNER_SECRET, body(kind.getKey(), "shipped-roles", List.of(TICKET)));

      JwtClaims claims = claimsOf(commission.clientId(), commission.secret());
      assertEquals(
          List.of(kind.getValue(), "clients/" + commission.clientId()),
          claims.getStringListClaimValue("groups"),
          kind.getKey() + ": its kind's role and its own self-role; not the owner's roles");
      assertEquals(
          List.of("prod-qits-ci", "qits-deployments", "qits-platform"),
          PublishedJwks.audienceOf(claims),
          kind.getKey() + ": the audiences are still the owner's, plus qits-platform");
      assertEquals(kind.getKey(), claims.getClaimValueAsString("context_kind"));
      assertEquals(List.of(TICKET), claims.getStringListClaimValue("git_refs"));
      assertFalse(
          claims.hasClaim("project"),
          kind.getKey() + ": a commission no longer inherits the owner's claims (D3)");

      decommission(OWNER, OWNER_SECRET, commission.clientId()).statusCode(204);
    }
  }

  @Test
  public void theBootstrapsPublishingCredentialCarriesTheCiRunRoleAndMayPushNothing()
      throws Exception {
    // User ruling 2026-09-13: only CI may publish to qits-artifacts, so the bootstrap gets its own
    // publishing credential for its publish phase — the CI publisher's role, gitRefs: [] — and
    // deletes it when that phase ends.
    Commission publish =
        created(OWNER, OWNER_SECRET, body("bootstrap-publish", "ctx-bootstrap", List.of()));

    JwtClaims claims = claimsOf(publish.clientId(), publish.secret());
    assertEquals(
        List.of("qits:ci-run", "clients/" + publish.clientId()),
        claims.getStringListClaimValue("groups"),
        "the CI publisher's role, because publishing is CI's door — never the owner's roles");
    assertEquals("bootstrap-publish", claims.getClaimValueAsString("context_kind"));

    // [] is a statement and not an absence: the claim is there, and it permits nothing. A
    // credential with no list stated carries no claim at all and is therefore unrestricted, which
    // is the opposite answer — see aCommissionThatStatesNoListCarriesItsKindAndNoRefs.
    assertTrue(claims.hasClaim("git_refs"), "an empty list is a statement, not an absence");
    assertEquals(
        List.of(),
        claims.getStringListClaimValue("git_refs"),
        "may push nothing: no ref matches an empty list");
    assertEquals("", row(publish.clientId()).gitRefs, "the empty string, never null");

    // And it hands itself back with no platform role — which is what makes the bootstrap's own
    // clean-up at the end of its publish phase possible, so nothing permanent is left behind.
    decommission(publish.clientId(), publish.secret(), publish.clientId()).statusCode(204);
    token(publish.clientId(), publish.secret()).statusCode(401);
  }

  @Test
  public void aKindWithoutAShippedLineGetsNoRoleAtAll() throws Exception {
    Commission plain = created(OWNER, OWNER_SECRET, body("shipped-none", "ctx-13", null));

    assertEquals(
        List.of("clients/" + plain.clientId()),
        claimsOf(plain.clientId(), plain.secret()).getStringListClaimValue("groups"),
        "D12: an unshipped kind gets no role, only its own self-role — never the owner's");
  }

  @Test
  public void aStaticClientsRolesAreUnchanged() throws Exception {
    assertEquals(
        List.of("qits:system", "clients/" + OWNER),
        claimsOf(OWNER, OWNER_SECRET).getStringListClaimValue("groups"));
  }

  @Test
  public void eachShippedKindMintsAndHandsItselfBack() {
    for (String kind : SHIPPED_KINDS.keySet()) {
      Commission own = created(OWNER, OWNER_SECRET, body(kind, "shipped-self", null));
      Commission sibling = created(OWNER, OWNER_SECRET, body(kind, "shipped-sibling", null));
      token(own.clientId(), own.secret()).statusCode(200);

      // Without the platform role it may not give back another credential ...
      decommission(own.clientId(), own.secret(), sibling.clientId()).statusCode(403);
      // ... but it may give back its own.
      decommission(own.clientId(), own.secret(), own.clientId()).statusCode(204);
      token(own.clientId(), own.secret()).statusCode(401);

      decommission(OWNER, OWNER_SECRET, sibling.clientId()).statusCode(204);
    }
  }

  @Test
  public void theListingAcceptsTheAgentRoleAndNotTheCiRunRole() {
    // Reads accept qits:agent (user ruling 2026-09-12). qits:ci-run is not an agent role, so a CI
    // run's credential is refused here; nothing a run does lists commissions.
    for (Map.Entry<String, String> kind : SHIPPED_KINDS.entrySet()) {
      Commission commission = created(OWNER, OWNER_SECRET, body(kind.getKey(), "shipped-list", null));
      int expected = BasicCaller.AGENT.equals(kind.getValue()) ? 200 : 403;

      given()
          .header("Authorization", basic(commission.clientId(), commission.secret()))
          .when()
          .get("/idp/api/clients")
          .then()
          .statusCode(expected);

      decommission(OWNER, OWNER_SECRET, commission.clientId()).statusCode(204);
    }
  }

  // --- the migration --------------------------------------------------------------------------

  @Test
  public void v7AddsANullableTextColumn() {
    Object[] column =
        QuarkusTransaction.requiringNew()
            .call(
                () ->
                    (Object[])
                        repository
                            .getEntityManager()
                            .createNativeQuery(
                                "select data_type, is_nullable from information_schema.columns"
                                    + " where table_name = 'idp_client' and column_name = 'git_refs'")
                            .getSingleResult());
    assertEquals("text", column[0]);
    assertEquals("YES", column[1], "null is 'not stated', which every older row says");

    Object applied =
        QuarkusTransaction.requiringNew()
            .call(
                () ->
                    repository
                        .getEntityManager()
                        .createNativeQuery(
                            "select success from flyway_schema_history where version = '7'")
                        .getSingleResult());
    assertEquals(Boolean.TRUE, applied);
  }

  // --- helpers --------------------------------------------------------------------------------

  /** The two members of a commission answer a test uses. Unknown members are ignored. */
  @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
  public record Commission(String clientId, String secret) {}

  private static String body(String kind, String contextId, List<String> gitRefs) {
    StringBuilder json =
        new StringBuilder("{\"contextKind\":\"" + kind + "\",\"contextId\":\"" + contextId + "\"");
    if (gitRefs != null) {
      json.append(",\"gitRefs\":").append(array(gitRefs));
    }
    return json.append('}').toString();
  }

  /** The entries here never hold a quote or a backslash, so no escaping is needed. */
  private static String array(List<String> entries) {
    StringBuilder json = new StringBuilder("[");
    for (int i = 0; i < entries.size(); i++) {
      json.append(i == 0 ? "" : ",").append('"').append(entries.get(i)).append('"');
    }
    return json.append(']').toString();
  }

  private Commission created(String owner, String secret, String body) {
    return commission(owner, secret, body).statusCode(201).extract().as(Commission.class);
  }

  private static ValidatableResponse commission(String owner, String secret, String body) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(owner, secret))
        .body(body)
        .when()
        .post("/idp/api/clients")
        .then();
  }

  private static ValidatableResponse replace(
      String caller, String secret, String clientId, List<String> gitRefs) {
    return given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic(caller, secret))
        .body("{\"gitRefs\":" + array(gitRefs) + "}")
        .when()
        .put("/idp/api/clients/" + clientId + "/git-refs")
        .then();
  }

  private static ValidatableResponse decommission(String caller, String secret, String clientId) {
    return given()
        .header("Authorization", basic(caller, secret))
        .when()
        .delete("/idp/api/clients/" + clientId)
        .then();
  }

  private static ValidatableResponse token(String clientId, String secret) {
    return given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic(clientId, secret))
        .body("grant_type=client_credentials")
        .when()
        .post("/idp/token")
        .then();
  }

  /** A token for this client, asking for every audience it may have, verified against the JWKS. */
  private static JwtClaims claimsOf(String clientId, String secret) throws Exception {
    ExtractableResponse<?> answer = token(clientId, secret).statusCode(200).extract();
    return PublishedJwks.verify(answer.path("access_token"), "qits-deployments");
  }

  private IdpDynamicClient row(String clientId) {
    return QuarkusTransaction.requiringNew().call(() -> repository.findById(clientId));
  }

  private static List<String> listedIds(String caller, String secret, String contextKind) {
    return given()
        .header("Authorization", basic(caller, secret))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .extract()
        .path("findAll { it.contextKind == '" + contextKind + "' }.clientId");
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }
}
