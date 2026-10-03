package eu.wohlben.qits.idp.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.idp.persistence.IdpServiceClientRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

/**
 * V8 landed: {@code idp_service_client} and {@code idp_seed}
 * (epic qits-540 dossier, "Plan (as of 2026-09-13)", contract C2). The same shape
 * {@code CommissionedGitRefsTest}
 * checks for V7 — the columns a reader actually depends on, and that Flyway recorded the migration
 * as applied.
 */
@QuarkusTest
public class V8SchemaTest {

  @Inject IdpServiceClientRepository repository;

  @Test
  public void v8CreatesBothTablesWithTheirNotNullColumns() {
    assertColumn("idp_service_client", "client_id", "NO");
    assertColumn("idp_service_client", "secret_hash", "NO");
    assertColumn("idp_service_client", "previous_secret_hash", "YES");
    assertColumn("idp_service_client", "previous_valid_until", "YES");
    assertColumn("idp_service_client", "created_by", "NO");
    assertColumn("idp_service_client", "created_at", "NO");
    assertColumn("idp_service_client", "rotated_at", "YES");

    assertColumn("idp_seed", "id", "NO");
    assertColumn("idp_seed", "client_id", "NO");
    assertColumn("idp_seed", "seeded_at", "NO");

    Object applied =
        QuarkusTransaction.requiringNew()
            .call(
                () ->
                    repository
                        .getEntityManager()
                        .createNativeQuery(
                            "select success from flyway_schema_history where version = '8'")
                        .getSingleResult());
    assertEquals(Boolean.TRUE, applied);
  }

  private void assertColumn(String table, String column, String expectedNullable) {
    Object nullable =
        QuarkusTransaction.requiringNew()
            .call(
                () ->
                    repository
                        .getEntityManager()
                        .createNativeQuery(
                            "select is_nullable from information_schema.columns where"
                                + " table_name = ?1 and column_name = ?2")
                        .setParameter(1, table)
                        .setParameter(2, column)
                        .getSingleResult());
    assertEquals(expectedNullable, nullable, table + "." + column);
  }
}
