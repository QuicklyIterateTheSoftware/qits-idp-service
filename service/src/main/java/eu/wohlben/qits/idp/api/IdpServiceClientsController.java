package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.control.ServiceClients;
import eu.wohlben.qits.idp.control.ServiceClients.Issued;
import eu.wohlben.qits.idp.control.ServiceClients.StoredServiceClient;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The service-client management API: {@code /idp/api/service-clients}, where service clients are
 * created, rotated, read and deleted (epic qits-540, dossier page "Plan (as of 2026-09-13)",
 * contract C2). The database is the only service-client registry since qits-163.
 *
 * <p><b>Auth is the same Basic pair every machine surface here uses</b> ({@link BasicCaller}), and
 * the caller must be a service client itself — never commissioned — and hold {@code qits:system}.
 * Every write — create, rotate, delete — accepts that and nothing else: managing a service's secret
 * is not a thing an agent's context has any business doing.
 *
 * <p><b>The two reads also accept a bearer</b> ({@link BearerCaller}): a JWT this idp issued whose
 * {@code groups} hold {@link #READ_ROLES} — {@code qits:agent}, {@code qits:system}, {@code
 * qits:admin} or {@code qits:admin-agent} (an admin workspace's agent, admitted wherever {@code
 * qits:admin} is — qits-628 follow-up). An agent keeps every read and gains no write (user ruling 2026-09-12, qits-162), and
 * the reads carry no secret, so there is nothing for a bearer to strip. A Basic caller on a read is
 * still held to the service-client rule above, unchanged.
 *
 * <p>{@code source} in a read is always {@code "database"}. It used to say which registry held an
 * id; there is one registry now, and the field stays so a reader that looks for it does not break.
 */
@Path("/api/service-clients")
@Produces(MediaType.APPLICATION_JSON)
public class IdpServiceClientsController {

  /** The body of {@code POST /api/service-clients}. */
  public record CreateRequest(String clientId) {}

  /** {@code POST}'s answer: the pair, in this response and nowhere else. */
  public record CreatedResponse(String clientId, String secret, String createdBy, String createdAt) {}

  /** {@code POST …/secret}'s answer: the new pair. The old hash stays live for the grace window. */
  public record RotatedResponse(String clientId, String secret, String rotatedAt) {}

  /** {@code GET}'s answer, singular or in a list. Never a secret. {@code source} is always {@link #SOURCE}. */
  public record ServiceClientView(String clientId, String source, String createdAt, String rotatedAt) {}

  /** The one value {@code source} has. See the class javadoc. */
  static final String SOURCE = "database";

  /** Any one of these, in a bearer's {@code groups}, reads both GET routes. */
  static final String[] READ_ROLES = {
    BasicCaller.AGENT, BasicCaller.SYSTEM, "qits:admin", "qits:admin-agent"
  };

  @Inject BasicCaller caller;

  @Inject BearerCaller bearer;

  @Inject ServiceClients serviceClients;

  /**
   * Create a database row for this id.
   *
   * <p>{@code RestResponse<CreatedResponse>}, not a bare {@code Response}: a native image has no
   * type to register for a plain {@code Response}'s entity, and the packaged binary answers 500
   * where the JVM suite stayed green — the same rule {@code IdpClientsController} already pays for.
   */
  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "createServiceClient")
  public RestResponse<CreatedResponse> create(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization, CreateRequest request) {
    IdpClient caller_ = requireSystemCaller(authorization);
    if (request == null || request.clientId() == null) {
      throw OAuthException.invalidRequest("a JSON body naming clientId is required");
    }
    String clientId = request.clientId().trim();
    serviceClients.requireValidId(clientId);
    if (serviceClients.find(clientId).isPresent()) {
      throw OAuthException.conflict(
          "a database row for this client id already exists; rotate its secret instead of"
              + " creating it again");
    }
    Issued issued = serviceClients.create(clientId, caller_.clientId());
    return RestResponse.ResponseBuilder.create(
            Response.Status.CREATED,
            new CreatedResponse(
                issued.client().clientId(),
                issued.secret(),
                issued.client().createdBy(),
                issued.client().createdAt().toString()))
        // The body holds a credential. Same rule as the token response, same reason.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * Rotate the secret. The old hash becomes the previous one, valid for the grace window (D4); the
   * new secret is in this response and nowhere else.
   */
  @POST
  @Path("/{clientId}/secret")
  @Operation(operationId = "rotateServiceClientSecret")
  public RestResponse<RotatedResponse> rotate(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId) {
    requireSystemCaller(authorization);
    Issued issued =
        serviceClients
            .rotate(clientId)
            .orElseThrow(() -> OAuthException.notFound("no such service client"));
    return RestResponse.ResponseBuilder.create(
            Response.Status.OK,
            new RotatedResponse(
                issued.client().clientId(), issued.secret(), issued.client().rotatedAt().toString()))
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /** One service client's row. Never a secret. */
  @GET
  @Path("/{clientId}")
  @Operation(operationId = "getServiceClient")
  public ServiceClientView get(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId) {
    requireReader(authorization);
    return serviceClients
        .find(clientId)
        .map(IdpServiceClientsController::view)
        .orElseThrow(() -> OAuthException.notFound("no such service client"));
  }

  /** Every service client, one row each. */
  @GET
  @Operation(operationId = "listServiceClients")
  public List<ServiceClientView> list(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
    requireReader(authorization);
    return serviceClients.list().stream().map(IdpServiceClientsController::view).toList();
  }

  /**
   * Delete the database row. 404 when there is none; <b>409 when the caller deletes its own row</b>
   * — a service client must not be able to lock itself out of its own management surface.
   */
  @DELETE
  @Path("/{clientId}")
  @Operation(operationId = "deleteServiceClient")
  public Response delete(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
      @PathParam("clientId") String clientId) {
    IdpClient caller_ = requireSystemCaller(authorization);
    if (caller_.clientId().equals(clientId)) {
      throw OAuthException.conflict("a service client may not delete its own row");
    }
    if (!serviceClients.delete(clientId)) {
      throw OAuthException.notFound("no such service client");
    }
    return Response.noContent().build();
  }

  /**
   * A read: a bearer holding one of {@link #READ_ROLES}, or the write rule's Basic caller. The
   * header's scheme decides which; a bearer is never tried as Basic or the other way round.
   */
  private void requireReader(String authorization) {
    if (BearerCaller.isBearer(authorization)) {
      bearer.requireAnyRole(authorization, READ_ROLES);
      return;
    }
    requireSystemCaller(authorization);
  }

  /**
   * Basic, a service client (never commissioned), holding {@code qits:system} — every write here,
   * and a Basic read.
   */
  private IdpClient requireSystemCaller(String authorization) {
    return caller.staticOnly(
        authorization,
        "a commissioned client may not manage service clients",
        BasicCaller.SYSTEM);
  }

  private static ServiceClientView view(StoredServiceClient row) {
    return new ServiceClientView(
        row.clientId(),
        SOURCE,
        row.createdAt().toString(),
        row.rotatedAt() == null ? null : row.rotatedAt().toString());
  }
}
