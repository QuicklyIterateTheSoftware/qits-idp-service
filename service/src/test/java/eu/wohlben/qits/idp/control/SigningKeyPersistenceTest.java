package eu.wohlben.qits.idp.control;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.idp.api.PublishedJwks;
import eu.wohlben.qits.idp.entity.IdpSigningKeyStatus;
import eu.wohlben.qits.idp.persistence.IdpSigningKeyRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

/**
 * The key is generated once and read back, not regenerated.
 *
 * <p>This is the property the whole design rests on: a token issued before a restart must still
 * verify after one, which is true exactly when the keypair lives in the {@code idp} datasource and
 * a start that finds it there uses it. The suite cannot restart the process, so it exercises the
 * same seam the restart does — {@link SigningKeys#reload()}, which drops the cache and goes back to
 * the database. A generate-on-every-load regression changes the {@code kid} here.
 */
@QuarkusTest
public class SigningKeyPersistenceTest {

  @Inject SigningKeys signingKeys;

  @Inject IdpSigningKeyRepository repository;

  @Test
  public void reloadingReadsTheStoredKeyRatherThanMakingANewOne() throws Exception {
    String kidBefore = signingKeys.signing().kid();
    String tokenBefore = issueToken();

    signingKeys.reload();

    assertEquals(kidBefore, signingKeys.signing().kid(), "the kid must survive a reload");
    assertEquals(1, keyRows(), "a reload must not add a key row");
    assertEquals(
        kidBefore,
        PublishedJwks.kidOf(tokenBefore),
        "the token minted before the reload names the key that is still active");
    // The whole point: what was issued before still verifies against what is published after.
    assertEquals(
        "test-broad", PublishedJwks.verify(tokenBefore, "qits-platform").getSubject());
  }

  @Test
  public void theStoredKeyIsActiveAndIsTheOnePublished() {
    var signing = signingKeys.signing();
    assertTrue(signing.active());
    assertEquals("RS256", signing.algorithm());
    assertEquals(1, signingKeys.published().size(), "one key, published");
    assertEquals(signing.kid(), signingKeys.published().get(0).kid());

    var row = QuarkusTransaction.requiringNew().call(() -> repository.findById(signing.kid()));
    assertEquals(IdpSigningKeyStatus.ACTIVE, row.status);
    assertTrue(row.privateKeyPem.startsWith("-----BEGIN PRIVATE KEY-----"), "PKCS#8 PEM");
    assertTrue(row.publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----"), "X.509 PEM");
  }

  @Test
  public void theCachedKeySetIsNotRebuiltPerCall() {
    assertSame(signingKeys.signing(), signingKeys.signing(), "reading a key is not a database hit");
  }

  private long keyRows() {
    return QuarkusTransaction.requiringNew().call(() -> repository.count());
  }

  private static String issueToken() {
    return given()
        .contentType(ContentType.URLENC)
        .body(
            "grant_type=client_credentials"
                + "&client_id=test-broad"
                + "&client_secret=test-broad-secret"
                + "&audience=qits-deployments")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(200)
        .extract()
        .path("access_token");
  }
}
