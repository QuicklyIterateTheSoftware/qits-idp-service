package eu.wohlben.qits.idp.contracts;

import static org.junit.jupiter.api.Assertions.fail;

import au.com.dius.pact.core.model.Interaction;
import au.com.dius.pact.core.model.Pact;
import au.com.dius.pact.core.model.ProviderState;
import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactSource;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.net.URL;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * <b>Verifies every consumer's pact against the running provider</b>, the way qits-projects-service
 * does.
 *
 * <p>The pacts come off the test classpath: each consumer publishes its pact as a jar holding
 * {@code pacts/<consumer>_qits-idp-service.json} (repository names on both sides), this repo
 * pins that jar as a test dependency, and qits-maintenance bumps the pin when the consumer releases
 * a changed pact. {@link ClasspathPactLoader} finds them all.
 *
 * <p><b>Twenty-two consumers pin a pact</b> (qits-1149; the jars are in {@code service/pom.xml}):
 * both CLIs (qits-bootstrap-cli, qits-platform-access-cli), the ci-runner, projects and workspace
 * daemons, and the artifacts, ci, configuration, containers, deployments, edge, events, githost,
 * maintenance, mirror, observability, orchestrator, projects, system and workspaces services —
 * plus, through qits-runner-toolkit (qits-1163), the projects-desk-runner and
 * system-runner daemons, whose jars carry a three-part {@code pacts/<daemon>_qits-runner-javalib_qits-idp-service.json}:
 * {@link ClasspathPactLoader} matches on the {@code _qits-idp-service.json} suffix alone, so the
 * extra segment loads the same as everyone else's. {@link ClasspathPactLoader#REQUIRED} is
 * therefore true, so a classpath that lost them fails rather than verifying nothing. An
 * interaction naming a state this provider does not answer fails in {@link #target}: the fix is
 * the state here, with its golden master, never a weaker check.
 *
 * <p><b>A pinned pact that is wrong is named in {@link #KNOWN_WRONG}, by its jar's version</b>, and
 * its interaction is reported as skipped with the reason.
 *
 * <p>Each interaction runs against this {@code @QuarkusTest} application over real HTTP. The idp
 * has no synthetic user: a door that takes HTTP Basic gets the state's {@code authorization} param,
 * which the consumer's pact names with a provider-state generator on its {@code Authorization}
 * header — as {@link GoldenMasterRecordingTest} sends it. A token or session value in a request
 * body comes the same way, from the state's params. Every
 * {@code @State} method delegates to {@link ProviderStates}; {@link #target} fails an unknown state,
 * and an interaction without {@code comments.references.qits-call} or {@code qits-trigger}.
 */
@QuarkusTest
@Provider(ConsumerPactVerificationTest.PROVIDER)
@PactSource(ClasspathPactLoader.class)
class ConsumerPactVerificationTest {

  /** The provider's name in a pact: the repository name, not the application name. */
  static final String PROVIDER = "qits-idp-service";

  static {
    // pact-jvm reports usage metrics over the network unless told not to; a test never should.
    System.setProperty("pact_do_not_track", "true");
  }

  /** A pinned pact interaction this provider cannot honour, and why: the consumer must fix it. */
  record KnownWrong(String consumer, String version, String description, String reason) {

    boolean names(Pact pact, Interaction interaction) {
      return consumer.equals(pact.getConsumer().getName())
          && description.equals(interaction.getDescription())
          && String.valueOf(pact.getSource()).contains("/" + version + "/");
    }
  }

  /**
   * The pinned interactions that are wrong, each by the version of the consumer's jar: the entry
   * is for that version alone, so the bump carrying the consumer's fix verifies the interaction
   * for real, and a bump that does not fix it goes red here. Each is skipped with its reason —
   * never answered by bending the provider to it (the pattern of qits-maintenance-service's).
   * None now: bootstrap 2026.1019.84610 and orchestrator 2026.1019.92500 send the credential their
   * states name, which the six bootstrap and two orchestrator entries of the earlier jars did not.
   */
  static final List<KnownWrong> KNOWN_WRONG = List.of();

  @Inject ProviderStates states;

  @TestHTTPResource("/")
  URL base;

  @BeforeEach
  void target(PactVerificationContext context, Pact pact, Interaction interaction) {
    String consumer = pact.getConsumer().getName();
    for (ProviderState state : interaction.getProviderStates()) {
      if (!states.names().contains(state.getName())) {
        fail(
            "Consumer '"
                + consumer
                + "' needs the provider state '"
                + state.getName()
                + "' (interaction '"
                + interaction.getDescription()
                + "'), which qits-idp does not answer for — it answers for "
                + states.names());
      }
    }
    var references = interaction.getComments().get("references");
    for (String key : List.of("qits-call", "qits-trigger")) {
      if (references == null || !references.isObject() || !references.asObject().has(key)) {
        fail(
            "Consumer '"
                + consumer
                + "' interaction '"
                + interaction.getDescription()
                + "' carries no comments.references."
                + key);
      }
    }
    for (KnownWrong wrong : KNOWN_WRONG) {
      if (wrong.names(pact, interaction)) {
        Assumptions.abort(
            consumer + " " + wrong.version() + " '" + interaction.getDescription() + "': "
                + wrong.reason());
      }
    }
    context.setTarget(new HttpTestTarget(base.getHost(), base.getPort()));
  }

  @TestTemplate
  @ExtendWith(PactVerificationInvocationContextProvider.class)
  void consumerPactHolds(PactVerificationContext context) {
    context.verifyInteraction();
  }

  // --- the states: each one line into the registry -------------------------------------------

  @State(ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE)
  Map<String, String> aServiceClientWithTheSystemRole() {
    return states.params(ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE);
  }

  @State(ProviderStates.A_SERVICE_CLIENT_WHOSE_STATED_GIT_REFS_ARE_REFUSED)
  Map<String, String> aServiceClientWhoseStatedGitRefsAreRefused() {
    return states.params(ProviderStates.A_SERVICE_CLIENT_WHOSE_STATED_GIT_REFS_ARE_REFUSED);
  }

  @State(ProviderStates.A_PUBLISHED_SIGNING_KEY)
  Map<String, String> aPublishedSigningKey() {
    return states.params(ProviderStates.A_PUBLISHED_SIGNING_KEY);
  }

  /** Reads the consumer's params: {@link ProviderStates#commissionedClientAsStated}. */
  @State(ProviderStates.A_COMMISSIONED_CLIENT)
  Map<String, String> aCommissionedClient(Map<String, Object> stated) {
    return states.commissionedClientAsStated(stated);
  }

  @State(ProviderStates.NO_COMMISSIONED_CLIENT_WITH_THE_GIVEN_ID)
  Map<String, String> noCommissionedClientWithTheGivenId() {
    return states.params(ProviderStates.NO_COMMISSIONED_CLIENT_WITH_THE_GIVEN_ID);
  }

  @State(ProviderStates.A_COMMISSIONED_TOKEN)
  Map<String, String> aCommissionedToken() {
    return states.params(ProviderStates.A_COMMISSIONED_TOKEN);
  }

  @State(ProviderStates.A_COMMISSIONED_TOKEN_THAT_WAS_DELETED)
  Map<String, String> aCommissionedTokenThatWasDeleted() {
    return states.params(ProviderStates.A_COMMISSIONED_TOKEN_THAT_WAS_DELETED);
  }

  @State(ProviderStates.A_SIGNED_IN_PERSON)
  Map<String, String> aSignedInPerson() {
    return states.params(ProviderStates.A_SIGNED_IN_PERSON);
  }

  @State(ProviderStates.A_DATABASE_SERVICE_CLIENT)
  Map<String, String> aDatabaseServiceClient() {
    return states.params(ProviderStates.A_DATABASE_SERVICE_CLIENT);
  }

  @State(ProviderStates.NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID)
  Map<String, String> noServiceClientWithTheGivenId() {
    return states.params(ProviderStates.NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID);
  }

  @State(ProviderStates.A_SERVICE_CLIENT_NOTHING_CLAIMS_CALLING_WITH_ITS_BEARER)
  Map<String, String> aServiceClientNothingClaimsCallingWithItsBearer() {
    return states.params(ProviderStates.A_SERVICE_CLIENT_NOTHING_CLAIMS_CALLING_WITH_ITS_BEARER);
  }

  /**
   * Reads the consumer's params: {@link
   * ProviderStates#commissionedClientHandingItselfBackAsStated}.
   */
  @State(ProviderStates.A_COMMISSIONED_CLIENT_HANDING_ITSELF_BACK)
  Map<String, String> aCommissionedClientHandingItselfBack(Map<String, Object> stated) {
    return states.commissionedClientHandingItselfBackAsStated(stated);
  }

  @State(ProviderStates.A_SERVICE_CLIENT_NOTHING_CLAIMS)
  Map<String, String> aServiceClientNothingClaims() {
    return states.params(ProviderStates.A_SERVICE_CLIENT_NOTHING_CLAIMS);
  }

  /** Reads the consumer's params: {@link ProviderStates#authorizationCodeAsStated}. */
  @State(ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI)
  Map<String, String> anAuthorizationCodeIssuedToTheCli(Map<String, Object> stated) {
    return states.authorizationCodeAsStated(
        ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI, stated);
  }

  /** Reads the consumer's params: {@link ProviderStates#authorizationCodeAsStated}. */
  @State(ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI_FOR_THE_CONNECT_PAGE)
  Map<String, String> anAuthorizationCodeIssuedToTheCliForTheConnectPage(Map<String, Object> stated) {
    return states.authorizationCodeAsStated(
        ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI_FOR_THE_CONNECT_PAGE, stated);
  }

  /** Reads the consumer's params: {@link ProviderStates#authorizationCodeAsStated}. */
  @State(ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT)
  Map<String, String> anAuthorizationCodeIssuedToTheGitClient(Map<String, Object> stated) {
    return states.authorizationCodeAsStated(
        ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT, stated);
  }

  /** Reads the consumer's params: {@link ProviderStates#sessionToRefreshAsStated}. */
  @State(ProviderStates.A_SESSION_TO_REFRESH)
  Map<String, String> aSessionToRefresh(Map<String, Object> stated) {
    return states.sessionToRefreshAsStated(ProviderStates.A_SESSION_TO_REFRESH, stated);
  }

  /** Reads the consumer's params: {@link ProviderStates#sessionToRefreshAsStated}. */
  @State(ProviderStates.A_GIT_SESSION_TO_REFRESH)
  Map<String, String> aGitSessionToRefresh(Map<String, Object> stated) {
    return states.sessionToRefreshAsStated(ProviderStates.A_GIT_SESSION_TO_REFRESH, stated);
  }

  @State(ProviderStates.A_SERVICE_CLIENT_CALLING_ITS_PEERS)
  Map<String, String> aServiceClientCallingItsPeers() {
    return states.params(ProviderStates.A_SERVICE_CLIENT_CALLING_ITS_PEERS);
  }

  @State(ProviderStates.A_SERVICE_CLIENT_PRESENTING_A_WRONG_SECRET)
  Map<String, String> aServiceClientPresentingAWrongSecret() {
    return states.params(ProviderStates.A_SERVICE_CLIENT_PRESENTING_A_WRONG_SECRET);
  }

  @State(ProviderStates.NO_COMMISSIONED_TOKEN_WITH_THE_GIVEN_ID)
  Map<String, String> noCommissionedTokenWithTheGivenId() {
    return states.params(ProviderStates.NO_COMMISSIONED_TOKEN_WITH_THE_GIVEN_ID);
  }

  @State(ProviderStates.NO_SESSION_WITH_THE_GIVEN_TOKEN)
  Map<String, String> noSessionWithTheGivenToken() {
    return states.params(ProviderStates.NO_SESSION_WITH_THE_GIVEN_TOKEN);
  }

  @State(ProviderStates.NO_SESSION_WITH_THE_GIVEN_REFRESH_TOKEN)
  Map<String, String> noSessionWithTheGivenRefreshToken() {
    return states.params(ProviderStates.NO_SESSION_WITH_THE_GIVEN_REFRESH_TOKEN);
  }

  @State(ProviderStates.AN_ADMIN_SIGNED_IN_TO_THE_CLI)
  Map<String, String> anAdminSignedInToTheCli() {
    return states.params(ProviderStates.AN_ADMIN_SIGNED_IN_TO_THE_CLI);
  }

  @State(ProviderStates.NO_USER_WITH_THE_GIVEN_NAME)
  Map<String, String> noUserWithTheGivenName() {
    return states.params(ProviderStates.NO_USER_WITH_THE_GIVEN_NAME);
  }

  @State(ProviderStates.AN_UNSPENT_REGISTER_TOKEN)
  Map<String, String> anUnspentRegisterToken() {
    return states.params(ProviderStates.AN_UNSPENT_REGISTER_TOKEN);
  }

  @State(ProviderStates.NO_REGISTER_TOKEN_WITH_THE_GIVEN_VALUE)
  Map<String, String> noRegisterTokenWithTheGivenValue() {
    return states.params(ProviderStates.NO_REGISTER_TOKEN_WITH_THE_GIVEN_VALUE);
  }

  // --- the commissioners, one state per body each ---------------------------------------------

  @State(ProviderStates.A_CI_RUNNER_BEING_COMMISSIONED)
  Map<String, String> aCiRunnerBeingCommissioned() {
    return states.params(ProviderStates.A_CI_RUNNER_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_CI_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED)
  Map<String, String> aCiRunnersRegistrationTokenBeingCommissioned() {
    return states.params(ProviderStates.A_CI_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_CI_RUNS_TOKEN_BEING_COMMISSIONED)
  Map<String, String> aCiRunsTokenBeingCommissioned() {
    return states.params(ProviderStates.A_CI_RUNS_TOKEN_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_CI_RUNS_TOKEN_BEING_COMMISSIONED_WITHOUT_A_GIT_SCOPE)
  Map<String, String> aCiRunsTokenBeingCommissionedWithoutAGitScope() {
    return states.params(ProviderStates.A_CI_RUNS_TOKEN_BEING_COMMISSIONED_WITHOUT_A_GIT_SCOPE);
  }

  @State(ProviderStates.A_WORKSPACES_CLIENT_BEING_COMMISSIONED)
  Map<String, String> aWorkspacesClientBeingCommissioned() {
    return states.params(ProviderStates.A_WORKSPACES_CLIENT_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_WORKSPACES_CLIENT_WHOSE_STATED_GIT_REFS_ARE_REFUSED)
  Map<String, String> aWorkspacesClientWhoseStatedGitRefsAreRefused() {
    return states.params(ProviderStates.A_WORKSPACES_CLIENT_WHOSE_STATED_GIT_REFS_ARE_REFUSED);
  }

  @State(ProviderStates.A_WORKSPACES_CLIENT_BEING_COMMISSIONED_TO_PUSH_NOTHING)
  Map<String, String> aWorkspacesClientBeingCommissionedToPushNothing() {
    return states.params(ProviderStates.A_WORKSPACES_CLIENT_BEING_COMMISSIONED_TO_PUSH_NOTHING);
  }

  @State(ProviderStates.A_WORKSPACES_TOKEN_BEING_COMMISSIONED)
  Map<String, String> aWorkspacesTokenBeingCommissioned() {
    return states.params(ProviderStates.A_WORKSPACES_TOKEN_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_WORKSPACES_TOKEN_WHOSE_STATED_GIT_REFS_ARE_REFUSED)
  Map<String, String> aWorkspacesTokenWhoseStatedGitRefsAreRefused() {
    return states.params(ProviderStates.A_WORKSPACES_TOKEN_WHOSE_STATED_GIT_REFS_ARE_REFUSED);
  }

  @State(ProviderStates.A_WORKSPACES_TOKEN_BEING_COMMISSIONED_TO_PUSH_NOTHING)
  Map<String, String> aWorkspacesTokenBeingCommissionedToPushNothing() {
    return states.params(ProviderStates.A_WORKSPACES_TOKEN_BEING_COMMISSIONED_TO_PUSH_NOTHING);
  }

  @State(ProviderStates.AN_AGENTS_TOKEN_BEING_COMMISSIONED)
  Map<String, String> anAgentsTokenBeingCommissioned() {
    return states.params(ProviderStates.AN_AGENTS_TOKEN_BEING_COMMISSIONED);
  }

  @State(ProviderStates.AN_AGENTS_TOKEN_WHOSE_STATED_GIT_REFS_ARE_REFUSED)
  Map<String, String> anAgentsTokenWhoseStatedGitRefsAreRefused() {
    return states.params(ProviderStates.AN_AGENTS_TOKEN_WHOSE_STATED_GIT_REFS_ARE_REFUSED);
  }

  @State(ProviderStates.AN_AGENTS_TOKEN_BEING_COMMISSIONED_TO_PUSH_NOTHING)
  Map<String, String> anAgentsTokenBeingCommissionedToPushNothing() {
    return states.params(ProviderStates.AN_AGENTS_TOKEN_BEING_COMMISSIONED_TO_PUSH_NOTHING);
  }

  @State(ProviderStates.A_WORKSPACE_RUNNER_BEING_COMMISSIONED)
  Map<String, String> aWorkspaceRunnerBeingCommissioned() {
    return states.params(ProviderStates.A_WORKSPACE_RUNNER_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_WORKSPACE_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED)
  Map<String, String> aWorkspaceRunnersRegistrationTokenBeingCommissioned() {
    return states.params(ProviderStates.A_WORKSPACE_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_DESK_RUNNER_BEING_COMMISSIONED)
  Map<String, String> aDeskRunnerBeingCommissioned() {
    return states.params(ProviderStates.A_DESK_RUNNER_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_DESK_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED)
  Map<String, String> aDeskRunnersRegistrationTokenBeingCommissioned() {
    return states.params(ProviderStates.A_DESK_RUNNERS_REGISTRATION_TOKEN_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_REFINEMENTS_CLIENT_BEING_COMMISSIONED)
  Map<String, String> aRefinementsClientBeingCommissioned() {
    return states.params(ProviderStates.A_REFINEMENTS_CLIENT_BEING_COMMISSIONED);
  }

  @State(ProviderStates.A_FRONT_DESKS_TOKEN_BEING_COMMISSIONED)
  Map<String, String> aFrontDesksTokenBeingCommissioned() {
    return states.params(ProviderStates.A_FRONT_DESKS_TOKEN_BEING_COMMISSIONED);
  }
}
