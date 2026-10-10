package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.RegisterTokens;
import eu.wohlben.qits.idp.control.Registrations;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.error.AuthException;
import io.quarkus.security.webauthn.WebAuthnCredentialRecord;
import io.quarkus.security.webauthn.WebAuthnCredentialRecord.RequiredPersistedData;
import io.quarkus.security.webauthn.WebAuthnSecurity;
import io.smallrye.common.annotation.Blocking;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The user surface: {@code /idp/api/auth} — register, log in, log out, set a password.
 *
 * <h2>What this class is, and what the extension is</h2>
 *
 * <p>quarkus-security-webauthn is used here as a <b>library</b>. {@link WebAuthnSecurity} makes the
 * challenges and verifies the attestation and the assertion; everything a login <i>means</i> —
 * which account it is, whether a register token was spent, what session comes out — is this
 * service's. The extension's own built-in endpoints are off and its own {@code quarkus-credential}
 * cookie is never written, because {@code rememberUser()} is never called. What the browser gets is
 * {@link SessionCookie}, opaque, introspected at the edge.
 *
 * <h2>The two ways in, and the guard on each</h2>
 *
 * <p><b>Register is guarded by a register token or by an existing session</b>, never by nothing.
 * With a token it is a first registration: a new account, its factor, the token spent, the two
 * bootstrap roles, and a session — one transaction, in {@link Registrations}. With a session it is
 * the same ceremony used to add a <i>second</i> authenticator to the account already signed in, so
 * there is no new account, no token to spend and no new cookie.
 *
 * <p><b>Login is anonymous, and its failures are uniform.</b> Every way it can fail — an unknown
 * name, an account with no password, a wrong password, an assertion that did not verify — is one
 * 401 with one code. The one thing that does leak is inherent to WebAuthn: login options are
 * answered for any name, which is why they say nothing about whether that name has credentials.
 *
 * <h2>The order of the ceremony, and why options check the token first</h2>
 *
 * <p>{@code register-options} verifies the register token <b>before</b> it creates any ceremony
 * state. A browser that cannot register must not be handed a challenge and a cookie and refused
 * afterwards, and an authenticator must not be asked to make a key that will be thrown away. The
 * token is checked again inside the registration's transaction, because between the two calls it
 * may have been spent.
 *
 * <p>All of this sits under {@code /api}, which {@code quarkus.quinoa.ignored-path-prefixes}
 * already covers — so the client's SPA fallback is untouched by these routes and the ignore list
 * did not have to change for them.
 */
@Path("/api/auth")
@Produces(MediaType.APPLICATION_JSON)
@Blocking
public class IdpAuthController {

  private static final Logger LOG = Logger.getLogger(IdpAuthController.class);

  /**
   * What a register or register-options call sends.
   *
   * <p>One record for both calls on purpose: options reads {@code username} and {@code token},
   * register reads all four, and a second near-identical type would be a second thing to keep in
   * step — and a second thing for a native image to register for reflection.
   *
   * @param username the requested login name. Ignored when a session is guarding the call: an
   *     authenticator is added to the account that is signed in, never to a name it asks for.
   * @param token the one-time register token. Absent on the session-guarded path.
   * @param password a password instead of (or as well as) a passkey. Non-empty is the only rule.
   * @param attestation the browser's {@code PublicKeyCredential}, verbatim — the object
   *     {@code navigator.credentials.create()} resolved to, serialized with its {@code ArrayBuffer}
   *     members base64url-encoded. Passed through to the extension untouched.
   */
  public record RegisterRequest(
      String username, String token, String password, Map<String, Object> attestation) {}

  /**
   * What a login or login-options call sends.
   *
   * @param username the login name. Optional on both: the assertion names the credential, and the
   *     credential names the account. When present on {@code login} it must agree with it.
   * @param password the password, for the fallback path.
   * @param assertion the browser's {@code PublicKeyCredential} from
   *     {@code navigator.credentials.get()}, verbatim.
   */
  public record LoginRequest(String username, String password, Map<String, Object> assertion) {}

  /** What {@code /password} sends. */
  public record PasswordRequest(String password) {}

  @Inject WebAuthnSecurity webAuthn;

  @Inject Users users;

  @Inject RegisterTokens tokens;

  @Inject Registrations registrations;

  @Inject Sessions sessions;

  @Inject BrowserSso browserSso;

  /** The one server-validated answer the SPA may use for its post-login document navigation. */
  public record ReturnLocation(String location) {}

  /**
   * Resolve an edge-supplied browser return target.
   *
   * <p>This stays server-side rather than having the SPA compare a suffix: a public page can be
   * linked with arbitrary query parameters, while this process owns the configured allow-list.
   */
  @GET
  @Path("/return-location")
  @Operation(operationId = "getReturnLocation")
  public RestResponse<ReturnLocation> returnLocation(
      @QueryParam("return_host") String host, @QueryParam("return_path") String path) {
    return RestResponse.ResponseBuilder.ok(new ReturnLocation(browserSso.returnLocation(host, path)))
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * The WebAuthn creation options for a registration.
   *
   * <p>The answer is the extension's own serialization of {@code
   * PublicKeyCredentialCreationOptions} — {@code rp}, {@code user}, {@code challenge}, {@code
   * pubKeyCredParams} and the rest, with every binary member base64url — because that is what
   * {@code navigator.credentials.create()} takes and the client should not have to rebuild it. It
   * comes back beside a {@code _quarkus_webauthn_challenge} cookie, which is the server's only
   * memory of the challenge and must ride the next call.
   */
  @POST
  @Path("/register-options")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "getRegisterOptions")
  public String registerOptions(
      @Context RoutingContext ctx,
      @CookieParam(SessionCookie.NAME) String sessionToken,
      RegisterRequest request) {
    Registrant who = registrant(request, sessionToken);
    // displayName is the username: this idp stores no display name, and a browser prompt showing
    // the login name is the honest thing for an installation with one operator.
    return webAuthn.toJsonString(
        webAuthn.getRegisterChallenge(who.username(), who.username(), ctx).await().indefinitely());
  }

  /**
   * Finish a registration: an attestation, a password, or both.
   *
   * <p>On the token path the answer opens a session and sets the cookie — a fresh operator is
   * signed in by the act of registering, which is the whole point of the bootstrap flow. On the
   * session path nothing about the session changes; the answer describes the session that was
   * already there, so a client can render the same thing either way.
   */
  @POST
  @Path("/register")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "register")
  public RestResponse<SessionView> register(
      @Context RoutingContext ctx,
      @CookieParam(SessionCookie.NAME) String sessionToken,
      RegisterRequest request) {
    Registrant who = registrant(request, sessionToken);

    Users.NewAuthenticator authenticator = null;
    if (request.attestation() != null && !request.attestation().isEmpty()) {
      WebAuthnCredentialRecord verified =
          verify(
              webAuthn.register(who.username(), new JsonObject(request.attestation()), ctx),
              "the registration ceremony did not verify");
      authenticator = toAuthenticator(verified);
    }

    if (who.session() != null) {
      if (authenticator == null) {
        throw AuthException.invalidRequest(
            "a session-authenticated registration adds an authenticator;"
                + " use /api/auth/password to set a password");
      }
      users.addCredential(who.session().userId(), authenticator);
      LOG.infof("added an authenticator to %s", who.username());
      // No cookie: the session that authorised this call is the session that continues.
      return RestResponse.ResponseBuilder.create(Response.Status.OK, SessionView.of(who.session()))
          .header(HttpHeaders.CACHE_CONTROL, "no-store")
          .header("Pragma", "no-cache")
          .build();
    }

    String password = request.password() == null || request.password().isEmpty() ? null : request.password();
    return issued(
        ctx, registrations.withToken(who.token(), who.username(), authenticator, password));
  }

  /**
   * The WebAuthn request options for a login — the extension's serialization of {@code
   * PublicKeyCredentialRequestOptions}, and a challenge cookie beside it.
   *
   * <p><b>Anonymous, and it answers for any name.</b> The list of allowed credentials is empty
   * whatever was asked for (the extension leaves it empty upstream), so this is not a "does this
   * account exist" oracle — and a blank or absent username is fine too, which is the discoverable
   * -credential flow where the authenticator itself picks the account.
   */
  @POST
  @Path("/login-options")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "getLoginOptions")
  public String loginOptions(@Context RoutingContext ctx, LoginRequest request) {
    String username = request == null || request.username() == null ? "" : request.username().trim();
    return webAuthn.toJsonString(
        webAuthn.getLoginChallenge(username, ctx).await().indefinitely());
  }

  /** Log in with an assertion or with a password. Success sets the cookie; failure is one 401. */
  @POST
  @Path("/login")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "login")
  public RestResponse<SessionView> login(@Context RoutingContext ctx, LoginRequest request) {
    if (request == null) {
      throw AuthException.invalidRequest("a JSON body is required");
    }
    Users.Account account =
        request.assertion() != null && !request.assertion().isEmpty()
            ? byAssertion(ctx, request)
            : byPassword(request);
    return issued(ctx, sessions.open(account));
  }

  /**
   * End the session and clear the cookie.
   *
   * <p>A live session is required. This endpoint mutates session state and is not part of the
   * anonymous login/register bootstrap surface. There is no {@code @Consumes}: this call has no
   * body, and a POST with no {@code Content-Type} would not match a JSON one.
   */
  @POST
  @Path("/logout")
  @Operation(operationId = "logout")
  public Response logout(
      @Context RoutingContext ctx, @CookieParam(SessionCookie.NAME) String sessionToken) {
    requireSession(sessionToken);
    sessions.revoke(sessionToken);
    LOG.info("a session was ended by its holder");
    return Response.noContent()
        .header(
            HttpHeaders.SET_COOKIE,
            SessionCookie.clear(SessionCookie.isSecure(ctx), browserSso.cookieDomain()))
        .build();
  }

  /**
   * Set or replace the signed-in account's password.
   *
   * <p>Session-guarded, because a password is set by someone who is already authenticated — this is
   * the second factor being added, not a reset flow. There is no reset flow: an installation with
   * one operator and a lost password re-registers from a new token.
   *
   * <p><b>Non-empty is the whole rule</b>, deliberately: no length floor, no character classes, no
   * expiry. The reasoning is on {@code PasswordHash}.
   */
  @POST
  @Path("/password")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(operationId = "setPassword")
  public Response password(
      @CookieParam(SessionCookie.NAME) String sessionToken, PasswordRequest request) {
    Sessions.Live session = requireSession(sessionToken);
    users.setPassword(
        session.userId(), Users.requirePassword(request == null ? null : request.password()));
    LOG.infof("the password of %s was set", session.username());
    return Response.noContent().build();
  }

  // --- the guards -----------------------------------------------------------------------------

  /** Who a register call may act as, and by which of the two guards. Exactly one is set. */
  private record Registrant(String username, Sessions.Live session, String token) {}

  /**
   * The register guard: an unspent register token, or a live session.
   *
   * <p>The token is tried first because it is the explicit intent — a browser that still holds a
   * stale session cookie and is registering a new account from a fresh token means the token.
   *
   * <p>On the token path the name is checked for being free <b>here</b> rather than only inside the
   * transaction, so that a taken name is answered before the ceremony runs instead of after the
   * user has touched their authenticator. It is checked again there, because this one is advisory:
   * two registrations racing for the same name are separated by the unique index and by nothing in
   * this method.
   */
  private Registrant registrant(RegisterRequest request, String sessionToken) {
    if (request == null) {
      throw AuthException.invalidRequest("a JSON body is required");
    }
    if (request.token() != null && !request.token().isBlank()) {
      tokens.requireUnspent(request.token());
      String username = Users.normaliseUsername(request.username());
      if (users.byUsername(username).isPresent()) {
        throw AuthException.invalidRequest("that username is taken");
      }
      return new Registrant(username, null, request.token());
    }
    Sessions.Live session =
        sessions
            .resolve(sessionToken)
            .orElseThrow(
                () ->
                    AuthException.invalidCredentials(
                        "a register token or a signed-in session is required"));
    return new Registrant(session.username(), session, null);
  }

  /** The session guard, for the routes that only a signed-in user may call. */
  private Sessions.Live requireSession(String sessionToken) {
    return sessions
        .resolve(sessionToken)
        .orElseThrow(() -> AuthException.invalidCredentials("a signed-in session is required"));
  }

  // --- the two login paths --------------------------------------------------------------------

  private Users.Account byAssertion(RoutingContext ctx, LoginRequest request) {
    WebAuthnCredentialRecord verified =
        verify(
            webAuthn.login(new JsonObject(request.assertion()), ctx),
            "the login ceremony did not verify");
    Users.Account account =
        users
            .byUsername(verified.getUsername())
            .orElseThrow(
                () ->
                    AuthException.invalidCredentials(
                        "the assertion verified against a credential whose account is gone"));
    if (request.username() != null
        && !request.username().isBlank()
        && !request.username().trim().equals(account.username())) {
      // The page asked to sign in as one account and the authenticator answered for another.
      throw AuthException.invalidCredentials("the assertion is for a different account");
    }
    // The counter only ever increases, and webauthn4j refuses a login whose counter went backwards
    // — a cloned authenticator. That check works only while the newest value is stored.
    users.recordCounter(verified.getCredentialID(), verified.getCounter());
    return account;
  }

  private Users.Account byPassword(LoginRequest request) {
    String username = request.username() == null ? null : request.username().trim();
    return users
        .authenticate(username, request.password())
        .orElseThrow(
            () ->
                AuthException.invalidCredentials(
                    "no account with that name and password"));
  }

  // --- the plumbing ---------------------------------------------------------------------------

  /** The answer that opens a session: the view, the cookie, and no caching of either. */
  private RestResponse<SessionView> issued(RoutingContext ctx, Sessions.Opened opened) {
    return RestResponse.ResponseBuilder.create(
            Response.Status.OK, SessionView.of(opened.session()))
        .header(
            HttpHeaders.SET_COOKIE,
            SessionCookie.set(
                opened.token(), sessions.ttl(), SessionCookie.isSecure(ctx), browserSso.cookieDomain()))
        // The body describes a credential and the header IS one. Same rule as the token response.
        .header(HttpHeaders.CACHE_CONTROL, "no-store")
        .header("Pragma", "no-cache")
        .build();
  }

  /**
   * Run a ceremony verification and turn everything it can fail with into one 401.
   *
   * <p>The extension reports a missing challenge cookie, a malformed body and a signature that did
   * not verify as three different exceptions, and a caller is told about none of them: which one it
   * was is in the log line, with its stack. <b>An {@link AuthException} thrown from inside passes
   * through unchanged</b>, so the guards keep their own wording.
   *
   * <p>The honest wart: a database failure reached through the extension's credential lookup lands
   * here too and is answered 401 rather than 500. It is logged with its cause, which is where the
   * difference is visible — and by the time it happens {@code DbRetry} has already spent its
   * patience, so the request was failing either way.
   */
  private static <T> T verify(Uni<T> ceremony, String refusal) {
    try {
      return ceremony.await().indefinitely();
    } catch (AuthException passThrough) {
      throw passThrough;
    } catch (RuntimeException failure) {
      LOG.warnf(failure, "webauthn ceremony refused: %s", refusal);
      throw AuthException.invalidCredentials(refusal);
    }
  }

  /** The verified credential, reduced to the six fields the store keeps. */
  private static Users.NewAuthenticator toAuthenticator(WebAuthnCredentialRecord verified) {
    RequiredPersistedData data = verified.getRequiredPersistedData();
    return new Users.NewAuthenticator(
        data.credentialId(),
        data.aaguid(),
        data.publicKey(),
        data.publicKeyAlgorithm(),
        data.counter());
  }
}
