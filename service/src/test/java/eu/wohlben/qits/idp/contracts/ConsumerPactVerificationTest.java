package eu.wohlben.qits.idp.contracts;

import static org.junit.jupiter.api.Assertions.fail;

import au.com.dius.pact.core.model.Interaction;
import au.com.dius.pact.core.model.Pact;
import au.com.dius.pact.core.model.ProviderState;
import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.IgnoreNoPactsToVerify;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactSource;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.net.URL;
import java.util.List;
import java.util.Map;
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
 * <p><b>No consumer pins a pact yet</b>, so {@code @IgnoreNoPactsToVerify} lets an empty classpath
 * pass and the loader logs that nothing was verified. When the first consumer's pact jar is pinned,
 * drop the annotation and set {@link ClasspathPactLoader#REQUIRED} to true.
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
@IgnoreNoPactsToVerify
class ConsumerPactVerificationTest {

  /** The provider's name in a pact: the repository name, not the application name. */
  static final String PROVIDER = "qits-idp-service";

  static {
    // pact-jvm reports usage metrics over the network unless told not to; a test never should.
    System.setProperty("pact_do_not_track", "true");
  }

  @Inject ProviderStates states;

  @TestHTTPResource("/")
  URL base;

  @BeforeEach
  void target(PactVerificationContext context, Pact pact, Interaction interaction) {
    if (context == null) {
      return; // no pact to verify: @IgnoreNoPactsToVerify's single empty run
    }
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
    context.setTarget(new HttpTestTarget(base.getHost(), base.getPort()));
  }

  @TestTemplate
  @ExtendWith(PactVerificationInvocationContextProvider.class)
  void consumerPactHolds(PactVerificationContext context) {
    if (context != null) {
      context.verifyInteraction();
    }
  }

  // --- the states: each one line into the registry -------------------------------------------

  @State(ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE)
  Map<String, String> aServiceClientWithTheSystemRole() {
    return states.params(ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE);
  }

  @State(ProviderStates.A_PUBLISHED_SIGNING_KEY)
  Map<String, String> aPublishedSigningKey() {
    return states.params(ProviderStates.A_PUBLISHED_SIGNING_KEY);
  }

  @State(ProviderStates.A_COMMISSIONED_CLIENT)
  Map<String, String> aCommissionedClient() {
    return states.params(ProviderStates.A_COMMISSIONED_CLIENT);
  }

  @State(ProviderStates.NO_COMMISSIONED_CLIENT_WITH_THE_GIVEN_ID)
  Map<String, String> noCommissionedClientWithTheGivenId() {
    return states.params(ProviderStates.NO_COMMISSIONED_CLIENT_WITH_THE_GIVEN_ID);
  }

  @State(ProviderStates.A_COMMISSIONED_TOKEN)
  Map<String, String> aCommissionedToken() {
    return states.params(ProviderStates.A_COMMISSIONED_TOKEN);
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

  @State(ProviderStates.A_SERVICE_CLIENT_NOTHING_CLAIMS)
  Map<String, String> aServiceClientNothingClaims() {
    return states.params(ProviderStates.A_SERVICE_CLIENT_NOTHING_CLAIMS);
  }

  @State(ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI)
  Map<String, String> anAuthorizationCodeIssuedToTheCli() {
    return states.params(ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI);
  }

  @State(ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT)
  Map<String, String> anAuthorizationCodeIssuedToTheGitClient() {
    return states.params(ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT);
  }

  @State(ProviderStates.A_SESSION_TO_REFRESH)
  Map<String, String> aSessionToRefresh() {
    return states.params(ProviderStates.A_SESSION_TO_REFRESH);
  }

  @State(ProviderStates.A_GIT_SESSION_TO_REFRESH)
  Map<String, String> aGitSessionToRefresh() {
    return states.params(ProviderStates.A_GIT_SESSION_TO_REFRESH);
  }
}
