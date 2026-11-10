package eu.wohlben.qits.idp.contracts;

import eu.wohlben.qits.eventstream.contracts.EventstreamPact;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * <b>What qits-eventstream asks qits-events on qits-idp's behalf</b> (qits-1977): the outbox publish
 * of {@code UserDeleted}, which {@code Users.delete} announces, pacted by this service against the
 * library version it pins and committed as {@code
 * pacts/qits-idp-service_qits-eventstream-javalib_qits-events-service.json}. It consumes no event,
 * so no listener is declared. The publisher lives in the domain module, so the guard reads both
 * modules' classes and fails naming any listener or publisher left out here. Regenerate with {@code
 * -Dgolden.update=true}.
 */
class EventstreamPactTest {

  static final EventstreamPact PACT =
      EventstreamPact.forConsumer("qits-idp-service")
          .publishes(true)
          .guard(Path.of("target/classes"), Path.of("../idp/target/classes"));

  @TestFactory
  Stream<DynamicTest> rows() {
    return PACT.tests();
  }

  @Test
  void pactFile() {
    PACT.compareOrWritePactFile();
  }
}
