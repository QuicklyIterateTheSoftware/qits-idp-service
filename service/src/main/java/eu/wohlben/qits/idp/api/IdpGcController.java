package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.ClientRegistry;
import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.control.UnclaimedServiceClientCollector;
import eu.wohlben.qits.idp.control.UnclaimedServiceClientCollector.Outcome;
import eu.wohlben.qits.idp.control.UnclaimedServiceClientCollector.Reason;
import eu.wohlben.qits.idp.control.UnclaimedServiceClientCollector.Verdict;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

/**
 * The orchestrator's door into service-client cleanup (qits-878): {@code POST
 * /idp/api/gc/service-clients} deletes the service clients no deployment claims any more.
 *
 * <p><b>The claims are an input, not a lookup</b>, on the pattern qits-configuration's {@code POST
 * /configuration/api/gc/entries} runs on: the orchestrator reads qits-deployments' {@code GET
 * /deployments/api/claims/idp-clients} and embeds its {@code claims} here. Only {@code clientId}
 * matters to the rule; the other fields, and any unknown one, are tolerated and ignored. <b>A body
 * with no claims is a 400 that deletes nothing</b>: a real claim set always holds at least the
 * deployer's own row, so an empty one is a broken read, not "nothing is running" — and reading it
 * the second way would delete every client past its grace. The rule itself is {@link
 * UnclaimedServiceClientCollector}'s.
 *
 * <p><b>Auth: a service client, by Basic pair or by its own bearer.</b> The Basic pair is exactly
 * what every machine write here accepts ({@link BasicCaller#staticOnly}). A bearer is accepted on
 * this door alone, and only when it verifies against this idp's keys, holds {@code qits:system}, and
 * its {@code sub} is a service client today — never a {@code dyn-} commissioned client, never a
 * person. That widening is safe here and nowhere else because this door can only remove
 * credentials, never issue or change one; the orchestrator holds a token for every peer rather than
 * a pair for each. {@code qits:agent} is refused (403) like on every write: agents keep reads only.
 * Commissioned {@code dyn-*} clients are a separate table and never judged here.
 */
@Path("/api/gc")
@Produces(MediaType.APPLICATION_JSON)
public class IdpGcController {

  /** The request. Unknown fields at any level are tolerated — Quarkus' Jackson default. */
  public record CollectRequest(boolean dryRun, List<Claim> claims) {

    /** One {@code idp-client} claim, as qits-deployments answered it. Only {@code clientId} is read. */
    public record Claim(
        String clientId, String applicationName, String environmentName, String createdAt) {}
  }

  /** The answer. These top-level keys are a contract with the orchestrator; keep them. */
  public record CollectReport(
      boolean dryRun, List<Judged> removed, List<Judged> kept, KeptCounts keptCounts) {}

  /** One client, removed (or, on a dry run, that would be) or kept. Never a secret. */
  public record Judged(String clientId, String createdAt, String createdBy, String reason) {}

  /** Kept clients by the first reason that held. */
  public record KeptCounts(int claimed, int grace, int caller) {}

  @Inject BasicCaller basicCaller;

  @Inject BearerCaller bearerCaller;

  @Inject ClientRegistry registry;

  @Inject UnclaimedServiceClientCollector collector;

  @POST
  @Path("/service-clients")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "collectServiceClients")
  public CollectReport collectServiceClients(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization, CollectRequest request) {
    String callerId = callerId(authorization);
    Set<String> claimed = claimedIds(request);
    Outcome outcome = collector.collect(claimed, callerId, request.dryRun());
    return new CollectReport(
        outcome.dryRun(),
        outcome.removed().stream().map(IdpGcController::judged).toList(),
        outcome.kept().stream().map(IdpGcController::judged).toList(),
        new KeptCounts(
            outcome.keptFor(Reason.CLAIMED),
            outcome.keptFor(Reason.GRACE),
            outcome.keptFor(Reason.CALLER)));
  }

  /**
   * The caller's own service-client id: a Basic service-client pair, or a {@code qits:system} bearer
   * whose {@code sub} is a service client. The header's scheme decides which is tried.
   *
   * @throws OAuthException 401 when nothing authenticates, 403 when it does and is not a service
   *     client holding {@code qits:system}
   */
  private String callerId(String authorization) {
    if (!BearerCaller.isBearer(authorization)) {
      return basicCaller
          .staticOnly(
              authorization,
              "a commissioned client may not collect service clients",
              BasicCaller.SYSTEM)
          .clientId();
    }
    JwtClaims claims = bearerCaller.requireAnyRole(authorization, BasicCaller.SYSTEM);
    String subject;
    try {
      subject = claims.getSubject();
    } catch (MalformedClaimException e) {
      throw OAuthException.invalidToken("the bearer's sub is not a string");
    }
    if (subject == null
        || subject.startsWith(DynamicClients.ID_PREFIX)
        || !registry.isServiceClient(subject)) {
      throw OAuthException.accessDenied(
          "only a service client's own bearer may collect service clients");
    }
    return subject;
  }

  /** Every claimed id; refused whole when the claims are missing, empty, or name no client. */
  private static Set<String> claimedIds(CollectRequest request) {
    if (request == null || request.claims() == null || request.claims().isEmpty()) {
      throw OAuthException.invalidRequest(
          "claims is required and must not be empty: embed the claims of GET"
              + " /deployments/api/claims/idp-clients");
    }
    Set<String> ids = new LinkedHashSet<>();
    for (CollectRequest.Claim claim : request.claims()) {
      if (claim == null || claim.clientId() == null || claim.clientId().isBlank()) {
        throw OAuthException.invalidRequest("every claim needs a clientId");
      }
      ids.add(claim.clientId());
    }
    return ids;
  }

  private static Judged judged(Verdict verdict) {
    return new Judged(
        verdict.clientId(),
        verdict.createdAt() == null ? null : verdict.createdAt().toString(),
        verdict.createdBy(),
        verdict.reason().wire());
  }
}
