package eu.wohlben.qits.idp.testdb;

import java.util.Map;
import java.util.Set;
import org.eclipse.microprofile.config.spi.ConfigSource;

/**
 * Hands the running {@link EmbeddedPg} to every {@code @QuarkusTest} in this module, as the three
 * keys a deployment would supply: {@code jdbc.url}, {@code username}, {@code password}.
 *
 * <p>It is a config source rather than three lines in {@code
 * src/test/resources/application.properties} because the port is chosen at run time — the instance
 * takes a free one, so nothing can be written down ahead of the JVM that starts it.
 *
 * <p><b>Two datasources since qits-1977.</b> The qits-eventstream jar arrives with its own outbox:
 * its datasource, persistence unit and Flyway lineage. Being dark in {@code %test} does not stop any
 * of that — {@code qits.eventstream.enabled=false} stops publishing, sweeping and dialling, while
 * Quarkus still opens the connection and migrates at boot — so the outbox gets a database here or
 * the suite does not start.
 *
 * <p>The ordinal sits above application.properties (250) so this wins over the shipped defaults in
 * both jars, and it is registered through {@code META-INF/services}, which is how a config source
 * joins a Quarkus application without being a bean.
 */
public class EmbeddedPgConfigSource implements ConfigSource {

  /** This suite's database on the shared instance — the packaged IT names its own. */
  private static final String DATABASE = "idp_svc";

  /**
   * The outbox's database. Named for this repository, and deliberately not {@code eventstream_test}
   * — that is the qits-eventstream library's own suite's database.
   */
  private static final String EVENTSTREAM_DATABASE = "eventstream_idp";

  private static final String PREFIX = "quarkus.datasource.idp.";

  private static final String EVENTSTREAM = "quarkus.datasource.eventstream.";

  private final Map<String, String> values =
      Map.of(
          PREFIX + "jdbc.url", EmbeddedPg.url(DATABASE),
          PREFIX + "username", EmbeddedPg.USER,
          PREFIX + "password", EmbeddedPg.PASSWORD,
          EVENTSTREAM + "jdbc.url", EmbeddedPg.url(EVENTSTREAM_DATABASE),
          EVENTSTREAM + "username", EmbeddedPg.USER,
          EVENTSTREAM + "password", EmbeddedPg.PASSWORD);

  @Override
  public int getOrdinal() {
    return 500;
  }

  @Override
  public Set<String> getPropertyNames() {
    return values.keySet();
  }

  @Override
  public String getValue(String propertyName) {
    return values.get(propertyName);
  }

  @Override
  public String getName() {
    return "embedded-pg";
  }
}
