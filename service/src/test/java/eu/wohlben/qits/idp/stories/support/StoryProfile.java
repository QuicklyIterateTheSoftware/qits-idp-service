package eu.wohlben.qits.idp.stories.support;

import eu.wohlben.qits.idp.testdb.EmbeddedPg;
import io.quarkus.test.junit.QuarkusTestProfile;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <b>One launched qits-platform-idp for the whole story catalogue</b>, and every seam a story moves,
 * declared once.
 *
 * <p>A {@code @TestProfile} is what failsafe launches a process for, so two profiles would be two
 * issuers — two boots, two databases, <b>two signing keys</b>, and a diagram whose traffic landed in
 * whichever process happened to be running. Every story class names this one, {@code
 * TokenIssuanceBootstrapIT} included: it is a story class like the others and it owns the boot.
 *
 * <h2>Why the PACKAGED artifact, and not a {@code @QuarkusTest}</h2>
 *
 * <p>The suite's settings come from {@code src/test/resources/application.properties}, which is not
 * in the jar. The launched process reads the <b>shipped</b> defaults instead — the hour-long token
 * lifetime, the endpoint base, and the roles a service client gets in code — so what these stories
 * pin is the deployment's own behaviour rather than a fixture that resembles it. Every key below is a <b>runtime</b> key, because a packaged process takes its configuration as
 * {@code -D} arguments on an artifact that was already built and a build-time key here would be
 * silently ignored.
 *
 * <h2>What a deployment supplies, and it is nearly all of what is here</h2>
 *
 * <ul>
 *   <li><b>the generic resource triple</b> — {@code .config/qits/deployments.yml} declares {@code
 *       resources: postgresql:db} and the deployer injects {@code QITS_RESOURCE_DB_URL} and its two
 *       siblings into the container. The jar carries no fallback, so a process that reached a store
 *       reached it through those three or died at Flyway. Here they name a database of this
 *       catalogue's own on the one embedded postgres — {@code idp_userflows_it}, beside {@code
 *       IdpPackagedSurfaceIT}'s {@code idp_packaged_it} — so the two launched processes can never
 *       mean the same schema and each generates its own signing key. <b>The url travels through a
 *       system property rather than a static field</b>: a test profile is instantiated in more than
 *       one classloader, so a field written by one copy is not the field the other reads, while the
 *       process has exactly one property table.
 *   <li><b>the clients, as the one-time adoption's input</b> (qits-163). The jar ships no service
 *       client; a live installation's configured ones were moved into the database once, at the
 *       first start of that version, and this profile hands the launched process the same input:
 *       {@code qits.idp.clients} and a secret per id. Every id with a secret becomes a row. {@link
 *       StoryTarget#ARTIFACTS} is deliberately given none, so it is never adopted and is what {@code
 *       FrontDoorRefusalsIT} runs its "no secret is unusable, never open" arm against. {@link
 *       StoryTarget#ROLE_THIEF} is also configured with a roles line naming another client's
 *       self-role, which nothing reads any more — {@code ReservedRoleNamespaceIT} shows it.
 * </ul>
 *
 * <h2>One thing is OFF, and it is the only thing this process would otherwise dial</h2>
 *
 * <p><b>The OTLP exporter.</b> The shipped configuration points this service's own SDK at {@code
 * http://dev-qits-observability:8080/observability/api/otel}, and that is the entire outbound surface of
 * a qits-platform-idp deployment besides its datasource. It is disabled here for three reasons, and
 * they are worth stating rather than assuming:
 *
 * <ul>
 *   <li>the shipped endpoint names a host that resolves on {@code qits-net} and nowhere else, so a
 *       launched artifact would spend the run retrying an export into the void;
 *   <li>an exporter flushes on a schedule of its own, on its own thread, so its batches would draw
 *       arrows into whichever story happened to be open — a {@code networkHash} that never settles;
 *   <li>and there is nothing here to point it at anyway: pointing it at a recording stand-in would
 *       add an edge to every story rather than remove one, and pointing it at the launched process
 *       itself is out of reach — a {@code @QuarkusIntegrationTest} gets an ephemeral port and a
 *       profile's overrides are computed before the process exists.
 * </ul>
 *
 * <p><b>So no story in this catalogue covers this service's self-export</b>, and none claims its
 * absence either: an {@code assertNoEdgesTo} over an exporter this profile switched off would be a
 * claim about the profile rather than about the service. The gap is stated in AGENTS.md rather than
 * papered over. What disabling it <i>buys</i> the catalogue is the other half of the same fact —
 * with it dark, nothing in the launched process can initiate anything at all except its own
 * datasource, which is what makes {@code assertNoEdgesFrom(SERVICE)} on the minting and reading
 * stories mean what it says.
 *
 * <h2>And one seam is out of reach entirely</h2>
 *
 * <p><b>This service calling itself.</b> The idp validates no bearer of its own — the commission API
 * authenticates with a Basic pair precisely so that the service issuing the bearers never has to
 * validate one, which would be a circular boot dependency the moment the signing-key load and the
 * commission call met. So there is no self-fetch to reach for here, and the {@code @TestProfile}'s
 * inability to know the launched port (it is computed before the process exists) costs this
 * catalogue nothing. It would cost the {@code qits.idp.endpoint-base} seam something: a base
 * pointed at the launched process would let a story fetch the discovery document by following the
 * advertised absolute URL rather than by knowing the path. {@code BootstrapDocumentsIT} states that gap where
 * it hits it.
 */
public class StoryProfile implements QuarkusTestProfile {

  /** Where the url is parked for whichever copy of this class is asked second. */
  private static final String URL_PROPERTY = "qits.test.userflow-it.db-url";

  /** This catalogue's own database on the one embedded postgres. */
  private static final String DATABASE = "idp_userflows_it";

  @Override
  public Map<String, String> getConfigOverrides() {
    // LinkedHashMap rather than Map.of: the order is the order this file explains them in, and a
    // reader diffing a launch command should find them in it.
    Map<String, String> overrides = new LinkedHashMap<>();

    // The platform's generic resource contract, exactly as a deployment fills it.
    overrides.put("QITS_RESOURCE_DB_URL", databaseUrl());
    overrides.put("QITS_RESOURCE_DB_USERNAME", EmbeddedPg.USER);
    overrides.put("QITS_RESOURCE_DB_PASSWORD", EmbeddedPg.PASSWORD);

    // The adoption's input (qits-163): the list, and a secret for every id but ARTIFACTS — see the
    // class javadoc. Each id with a secret becomes a database row at the first start.
    overrides.put("qits.idp.client." + StoryTarget.CI + ".secret", StoryTarget.CI_SECRET);
    overrides.put(
        "qits.idp.client." + StoryTarget.WORKSPACES + ".secret", StoryTarget.WORKSPACES_SECRET);
    overrides.put(
        "qits.idp.clients",
        String.join(
            ",",
            StoryTarget.CI,
            StoryTarget.ARTIFACTS,
            StoryTarget.WORKSPACES,
            StoryTarget.ROLE_THIEF));
    overrides.put(
        "qits.idp.client." + StoryTarget.ROLE_THIEF + ".secret", StoryTarget.ROLE_THIEF_SECRET);
    // Configured, and not read: a service client's roles are code. ReservedRoleNamespaceIT shows it.
    overrides.put(
        "qits.idp.client." + StoryTarget.ROLE_THIEF + ".roles", StoryTarget.ROLE_THIEF_ROLES);

    // Dark outside a deployment, like %dev and %test — and the only dial-out this process has
    // besides its datasource.
    overrides.put("quarkus.otel.sdk.disabled", "true");

    return Map.copyOf(overrides);
  }

  private static synchronized String databaseUrl() {
    String recorded = System.getProperty(URL_PROPERTY);
    if (recorded != null) {
      return recorded;
    }
    // localhost resolves for the launched process too — it is a child of this JVM on this host.
    String url = EmbeddedPg.url(DATABASE);
    System.setProperty(URL_PROPERTY, url);
    return url;
  }
}
