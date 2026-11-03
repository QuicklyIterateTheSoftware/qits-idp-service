package eu.wohlben.qits.idp.telemetry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.api.PublishedJwks;
import io.quarkus.oidc.client.NamedOidcClient;
import io.quarkus.oidc.client.OidcClient;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * <b>The idp mints its own bearer from itself</b> (epic qits-428). The {@code qits} named client
 * application.properties ships asks {@code http://localhost:8080/idp} — this very process, never the
 * edge — for a client-credentials token, which qits-telemetry-core's exporters attach to every OTLP
 * export. Here the client is switched on and the application is started on a port this profile
 * picks, so the client's loopback address and the process's own listener are the same socket, as
 * they are in a deployment on 8080. Nothing is stubbed: the token endpoint answering is this
 * service's own {@code TokenService}.
 *
 * <p>The id and secret are the suite's {@code test-broad} service client, the role a deployment's
 * {@code idp:client} resource plays. The token is checked against the published JWKS, and carries
 * the issuer derived from the domain rather than from the loopback host it was asked on — which is
 * what lets the edge in front of qits-observability accept a token minted this way.
 *
 * <p><b>The port is a system property, not a static field.</b> Quarkus loads the test profile in
 * its own classloader, so two static fields would be two ports; the process has one property
 * table.
 */
@QuarkusTest
@TestProfile(SelfIssuedTokenTest.OnItsOwnPort.class)
class SelfIssuedTokenTest {

  private static final String PORT_PROPERTY = "qits.idp.test.self-issue.port";

  /** The `qits` client on, dialling the port the application itself listens on. */
  public static class OnItsOwnPort implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "quarkus.http.test-port", String.valueOf(port()),
          "quarkus.oidc-client.qits.client-enabled", "true",
          "quarkus.oidc-client.qits.auth-server-url", "http://localhost:" + port() + "/idp",
          "quarkus.oidc-client.qits.client-id", "test-broad",
          "quarkus.oidc-client.qits.credentials.secret", "test-broad-secret");
    }
  }

  @Inject
  @NamedOidcClient("qits")
  OidcClient client;

  @Test
  void theQitsClientMintsAPlatformTokenFromThisVeryProcess() throws Exception {
    String token = client.getTokens().await().atMost(Duration.ofSeconds(20)).getAccessToken();

    JwtClaims claims = PublishedJwks.verify(token, "qits-platform");
    assertEquals("test-broad", claims.getSubject());
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer());
    assertEquals(List.of("qits-platform"), PublishedJwks.audienceOf(claims));
    assertTrue(
        claims.getStringListClaimValue("groups").contains("qits:system"),
        "a service client's token is qits:system: " + claims.getStringListClaimValue("groups"));
  }

  /** A free port, chosen once per JVM, whichever classloader asks first. */
  static synchronized int port() {
    String parked = System.getProperty(PORT_PROPERTY);
    if (parked != null) {
      return Integer.parseInt(parked);
    }
    try (ServerSocket socket = new ServerSocket(0)) {
      int port = socket.getLocalPort();
      System.setProperty(PORT_PROPERTY, String.valueOf(port));
      return port;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
