package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.control.RegisterTokens;
import eu.wohlben.qits.idp.control.RegisterTokens.Minted;
import jakarta.inject.Inject;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * Minting register tokens: {@code POST /idp/api/register-tokens}.
 *
 * <p><b>This is how an installation gets its first account.</b> The bootstrap CLI dials this once
 * idp is healthy and prints the token in its closing report, beside the workstation one-liner. It
 * is printed rather than logged for a reason worth repeating: this service's logs ship to
 * qits-observability, so a token in a log line is a credential on the log plane, readable by
 * everything that can read logs and durable for as long as they are kept.
 *
 * <p><b>Only a service client may mint</b> (never a commissioned one) —
 * the commissioning rule, reused verbatim through
 * {@link BasicCaller}. A commissioned credential belongs to one dynamic context and lives as long
 * as it does; if it could mint register tokens it could produce platform accounts that outlive it,
 * and the blast radius of a leaked build-step secret would stop being one build.
 *
 * <p>There is no listing and no revocation verb. A token is spent or it is not, the row records
 * which and by whom, and an installation that wants one gone deletes the row — which is a decision
 * to make once there is an operator UI to make it from, not a door to open now.
 */
@Path("/api/register-tokens")
@Produces(MediaType.APPLICATION_JSON)
public class IdpRegisterTokensController {

  /**
   * The answer to a mint. <b>The token is in this response and nowhere else</b> — the row holds a
   * {@code sha-256:} fingerprint — so a caller that loses it mints another and leaves the first
   * unspent.
   *
   * <p>The field is {@code token}, and that spelling is a cross-repo contract: the bootstrap CLI
   * reads it by name out of this body.
   */
  public record MintResponse(String id, String token, String createdAt) {}

  @Inject BasicCaller caller;

  @Inject RegisterTokens tokens;

  /**
   * Mint one.
   *
   * <p>No request body: there is nothing to ask for. A token is not scoped to a username, carries
   * no expiry and grants the same thing every time — the bootstrap roles, once — so a body would
   * only be a set of parameters that changed nothing.
   *
   * <p><b>The return type is {@code RestResponse<MintResponse>} and not a bare {@code Response}</b>,
   * for the reason this repository already paid for once: a {@code Response} carries its entity as
   * an {@code Object}, the native image builder has no type to register, and the packaged binary
   * answers 500 with "no properties discovered" while the JVM suite stays green.
   */
  @POST
  @Operation(operationId = "mintRegisterToken")
  public RestResponse<MintResponse> mint(
      @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
    IdpClient client =
        caller.staticOnly(
            authorization,
            "a commissioned client may not mint register tokens",
            BasicCaller.SYSTEM);
    Minted minted = tokens.mint(client.clientId());
    return RestResponse.ResponseBuilder.create(
            Response.Status.CREATED,
            new MintResponse(
                minted.id().toString(), minted.token(), minted.createdAt().toString()))
        // The body holds a credential. Same rule as the token response, same reason.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }
}
