package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.idp.control.CommissionedTokens.StoredToken;
import eu.wohlben.qits.idp.control.SigningKeys.SigningKey;
import eu.wohlben.qits.idp.error.OAuthException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * The {@code client_credentials} grant: authenticate a client, resolve the audiences it may have,
 * and mint an RS256 JWT.
 *
 * <p>The token says who the caller is and what it may be used against. It says nothing about what
 * the caller may do — that decision belongs to the resource service, helped by the shared
 * enforcement library.
 *
 * <p><b>Every client token names its own client.</b> The {@code groups} claim carries the
 * configured roles plus {@code clients/<client-id>}, stamped from the id that just authenticated
 * ({@link ClientRoles}). A user credential gets none — {@link #workstation} and {@link #cli} are
 * the other two mints here, and neither stamps a client identity onto a person.
 *
 * <p><b>A commissioned client mints exactly like a service client.</b> This class asks {@link
 * ClientRegistry} for a client and never learns which half answered — that identity is the whole
 * of the commission model working, because it means docker's Bearer dance, quarkus-oidc-client and
 * everything else already wired to this endpoint need no second code path.
 */
@ApplicationScoped
public class TokenService {

  private static final Logger LOG = Logger.getLogger(TokenService.class);

  /**
   * The one platform-wide audience, always allowed and always included (transitional rule, C2 of
   * {@code service-client-identity-plan.md}). Every token minted here — client credentials,
   * workstation, and already the CLI's whole list — carries it, so a resource service that has
   * moved to accepting it (C1 of the same plan, {@code qits.auth.machine.platform-audience}) can
   * start reading a bearer minted before its own cutover.
   */
  public static final String PLATFORM_AUDIENCE = "qits-platform";

  /** What a caller gets back, before it is dressed as an RFC 6749 token response. */
  public record IssuedToken(String accessToken, long expiresInSeconds, List<String> audiences) {}

  /**
   * An introspected commissioned token's JWT, with the {@code groups} it carries — the kind's roles
   * and the token's own {@code clients/<subject>} — so an introspection answer can state them
   * without the caller decoding the token it was just handed.
   */
  public record CommissionedTokenGrant(IssuedToken token, List<String> groups) {}

  @Inject Issuer issuer;

  @ConfigProperty(name = "qits.idp.token-ttl-seconds")
  long tokenTtlSeconds;

  /**
   * How long the JWT an introspection of a commissioned token answers with is good for — the upper
   * bound on how long a deleted token keeps working behind the edge. See the key's comment.
   */
  @ConfigProperty(name = "qits.idp.token-introspection-jwt-ttl-seconds")
  long introspectionJwtTtlSeconds;

  /** Workstation access tokens deliberately live far less long than service credentials. */
  @ConfigProperty(name = "qits.idp.workstation.access-token-ttl-seconds")
  long workstationAccessTokenTtlSeconds;

  /** The one resource a workstation public client may ever target. */
  @ConfigProperty(name = "qits.idp.workstation.githost-audience")
  String workstationGithostAudience;

  /** A CLI access token is as short-lived as a workstation's, and configured on its own key. */
  @ConfigProperty(name = "qits.idp.cli.access-token-ttl-seconds")
  long cliAccessTokenTtlSeconds;

  /**
   * The resources a signed-in CLI may target — CONFIGURED, never derived from the request.
   *
   * <p>By default it is one platform-wide audience, {@code qits-platform}, with no environment
   * prefix: the edge and every service accept it, and the token's roles decide what the person may
   * do. A CLI naming its own audience would be a public client choosing its own blast radius, so
   * {@code /authorize} refuses an {@code audience} parameter for this client outright and this value
   * is the whole answer.
   */
  @ConfigProperty(name = "qits.idp.cli.audiences")
  List<String> cliAudiences;

  @Inject SigningKeys signingKeys;

  @Inject ClientRegistry clients;

  @Inject Users users;

  /**
   * Authenticate and mint.
   *
   * @param requestedAudiences the {@code audience} values the request asked for; empty means "all
   *     of the client's own"
   * @throws OAuthException {@code invalid_client} (401) when authentication fails, {@code
   *     invalid_target} (400) when an audience is not this client's to ask for
   */
  public IssuedToken clientCredentials(
      String clientId, String secret, List<String> requestedAudiences) {
    IdpClient client = clients.authenticate(clientId, secret);
    List<String> audiences = resolveAudiences(client, requestedAudiences);
    return new IssuedToken(signFor(client, audiences, tokenTtlSeconds), tokenTtlSeconds, audiences);
  }

  /**
   * The short JWT an introspection of a commissioned token answers with (qits-450), together with
   * the {@code groups} it carries.
   *
   * <p><b>It is minted exactly as {@link #clientCredentials} would mint for a commissioned client
   * of the same kind</b>, because it is built as one: an {@link IdpClient} whose id is the token's
   * subject, whose roles are {@link CommissionRoles#forKind} (never the owner's), whose claims,
   * kind and Git refs are the row's, and whose audiences and audience rule are its owner's —
   * resolved here, now, the way {@link ClientRegistry} resolves them for a commissioned client,
   * with an empty request. So {@code aud} is an environment owner's whole list plus {@code
   * qits-platform}, or just {@code qits-platform} for a database owner; {@code groups} ends with
   * {@code clients/<subject>}; and a service behind the edge verifies it against the JWKS like any
   * other token, with no second code path.
   *
   * <p><b>The one difference is its lifetime</b>: {@code
   * qits.idp.token-introspection-jwt-ttl-seconds}, not {@code qits.idp.token-ttl-seconds}.
   * Deleting the row refuses the next introspection at once, but a JWT already handed out behind
   * the edge lives out its {@code exp}; this TTL is the upper bound on that.
   *
   * @return empty when the token's owner no longer exists in any registry — the token is then
   *     refused like a deleted one, since there is no owner to take audiences from
   * @throws OAuthException {@code invalid_target} (400) when the owner is an environment client
   *     with no configured audience — the same refusal its own commissioned clients get
   */
  public Optional<CommissionedTokenGrant> forCommissionedToken(StoredToken token) {
    IdpClient owner = clients.find(token.owner()).orElse(null);
    if (owner == null) {
      LOG.warnf(
          "token %s refused: its owner %s no longer exists",
          LoggableClientId.of(token.subject()), LoggableClientId.of(token.owner()));
      return Optional.empty();
    }
    IdpClient asClient =
        new IdpClient(
            token.subject(),
            // Never authenticated: the value was already matched by its hash in CommissionedTokens.
            null,
            owner.audiences(),
            CommissionRoles.forKind(token.contextKind()),
            token.claims(),
            token.contextKind(),
            token.gitRefs(),
            owner.audienceSource());
    List<String> audiences = resolveAudiences(asClient, List.of());
    String jwt = signFor(asClient, audiences, introspectionJwtTtlSeconds);
    return Optional.of(
        new CommissionedTokenGrant(
            new IssuedToken(jwt, introspectionJwtTtlSeconds, audiences),
            List.copyOf(ClientRoles.mintedFor(asClient))));
  }

  /**
   * A client token's claims, signed: the one shape {@link #clientCredentials} and {@link
   * #forCommissionedToken} share, so the two cannot drift.
   */
  private String signFor(IdpClient client, List<String> audiences, long ttlSeconds) {
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();

    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(client.clientId())
            // A Set, so `aud` is always a JSON array — one shape for consumers to read whether the
            // token names one audience or four.
            .audience(new LinkedHashSet<>(audiences))
            // The configured roles AND the client's own `clients/<id>`, which is minted here and
            // grantable nowhere — see ClientRoles.
            .groups(ClientRoles.mintedFor(client))
            .issuedAt(now)
            .expiresAt(now.plusSeconds(ttlSeconds));
    // The granted claims, verbatim. The idp does not interpret these values.
    client.claims().forEach(token::claim);
    // A commissioned client's kind and Git refs (principal-bound-git-refs-plan.md, C1). This is not
    // a branch on the kind of client: the fields are null for a static client, so it gets neither,
    // and a commission that stated no list gets no git_refs.
    if (client.contextKind() != null) {
      token.claim(ClaimNames.CONTEXT_KIND, client.contextKind());
    }
    if (client.gitRefs() != null) {
      token.claim(ClaimNames.GIT_REFS, client.gitRefs());
    }

    return token.jws().keyId(key.kid()).sign(key.privateKey());
  }

  /**
   * Mint the constrained user-approved credential used by a local Git workstation.
   *
   * <p>This does not copy the user's ordinary admin roles. A workstation is intentionally a
   * different capability: the resource sees one external-Git role and a ref pattern claim, and
   * must reject every ref outside that pattern. The audience is fixed in configuration rather than
   * accepted from the public client, so this token can never be replayed at another service.
   *
   * <p><b>And it carries no {@code clients/…} self-role.</b> That stamp says "this bearer IS that
   * machine client"; a token minted to a person's browser approval is not one, so the machine
   * identity a resource service gates on cannot be reached through a login.
   */
  public IssuedToken workstation(UUID userId) {
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();
    // The githost audience, plus the platform-wide one (C2 of service-client-identity-plan.md): a
    // githost that has moved to accepting qits-platform (C1) can read this bearer too, ahead of
    // any per-service audience change here.
    List<String> audiences = List.of(workstationGithostAudience, PLATFORM_AUDIENCE);
    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(userId.toString())
            .audience(new LinkedHashSet<>(audiences))
            .groups(Set.of("qits:git:external"))
            .claim("credential_type", "workstation")
            // Both spellings of the same rule: git_ref_pattern for githosts that read only it,
            // git_refs for the ones that read the list (principal-bound-git-refs-plan.md, C1).
            .claim("git_ref_pattern", "refs/heads/external/*")
            .claim(ClaimNames.GIT_REFS, GitRefs.PERSON)
            .issuedAt(now)
            .expiresAt(now.plusSeconds(workstationAccessTokenTtlSeconds));
    String jwt = token.jws().keyId(key.kid()).sign(key.privateKey());
    return new IssuedToken(jwt, workstationAccessTokenTtlSeconds, audiences);
  }

  /**
   * Mint the credential a person's command-line tool holds after signing in through the browser.
   *
   * <p><b>It carries the person's own roles</b>, and that is the decision the epic records rather
   * than an oversight: a CLI that could do less than the browser the same person just signed in
   * with would be a tool that cannot do the job it exists for.  The token is therefore as strong as
   * that session, and the defences are elsewhere — fifteen minutes of access-token life, refresh
   * rotation with replay detection revoking the whole family, and a revoke button per device.
   * Tokens narrowed to a project or a service are named later work.
   *
   * <p><b>It carries no {@code clients/…} self-role</b>, for the same reason {@link #workstation}
   * does not: that stamp means "this bearer IS that machine client", and a person is not one.  A
   * role a user somehow holds under that prefix is dropped here rather than trusted, so the machine
   * identity a resource service gates on stays unreachable through a login however the user store
   * was written to.
   *
   * <p>The audiences are {@code qits.idp.cli.audiences}, which the public client cannot influence.
   *
   * <p><b>Its Git rights are not its roles.</b> It carries {@code git_refs=["refs/heads/external/*"]}:
   * a person pushes only there, and {@code qits:admin} does not widen it.
   */
  public IssuedToken cli(UUID userId) {
    Users.Account account =
        users
            .byId(userId)
            .orElseThrow(
                () ->
                    OAuthException.invalidGrant(
                        "the account this credential was approved for no longer exists"));
    if (cliAudiences.isEmpty()) {
      LOG.warn("a cli token was refused: qits.idp.cli.audiences is empty");
      throw OAuthException.invalidTarget("this installation configures no cli audience");
    }
    Set<String> groups = new LinkedHashSet<>();
    for (String role : account.roles()) {
      if (!role.startsWith(ClientRoles.SELF_PREFIX)) {
        groups.add(role);
      }
    }
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();
    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(userId.toString())
            .audience(new LinkedHashSet<>(cliAudiences))
            .groups(groups)
            .claim("credential_type", "cli")
            // A person pushes only external/*, whatever their roles (user ruling 2026-09-12).
            .claim(ClaimNames.GIT_REFS, GitRefs.PERSON)
            .issuedAt(now)
            .expiresAt(now.plusSeconds(cliAccessTokenTtlSeconds));
    String jwt = token.jws().keyId(key.kid()).sign(key.privateKey());
    return new IssuedToken(jwt, cliAccessTokenTtlSeconds, List.copyOf(cliAudiences));
  }

  /**
   * The {@code aud} of the token (transitional, C2 of {@code service-client-identity-plan.md}).
   *
   * <p><b>An environment client (and a commission owned by one) always gets its WHOLE allowed list,
   * plus {@link #PLATFORM_AUDIENCE} — never only what was asked for.</b> A requested audience is
   * still checked: each one named must be in the client's configured list or be {@link
   * #PLATFORM_AUDIENCE} itself, or the request is refused with {@code invalid_target} exactly as
   * before. What changed is that a narrower request no longer narrows the token it gets back.
   *
   * <p>The reason is the rollout, not the security model. A service moving to the one named {@code
   * qits} OIDC client asks for a single audience, {@code qits-platform}. A receiver that has not yet
   * taken the qits-auth-core release that accepts {@code qits-platform} (C1, carried in by the
   * ordinary maintenance bump train — which can be as late as the next nightly run) still needs to
   * find its OWN audience on the token, or it refuses a caller that is otherwise entitled to call it.
   * Putting the whole list on every token, regardless of what was asked for, means the caller does
   * not have to wait for every one of its receivers to have taken that bump first. Under the open
   * calling model an over-addressed token grants nothing beyond what the caller's roles already
   * allow — {@code aud} only says where a token may be PRESENTED, not what it may do there — so the
   * widening costs nothing. C7 narrows every token back down to {@code qits-platform} alone, once
   * every receiver has moved.
   *
   * <p><b>A database service client keeps the other rule</b>: it has no configured audience list
   * yet, so a requested audience is copied back <em>unchecked</em> rather than checked against one —
   * {@link IdpClient.AudienceSource#DATABASE} says so — and only what was requested (plus {@link
   * #PLATFORM_AUDIENCE}) comes back, not a "whole list" that does not exist for it.
   *
   * <p><b>An environment client with no configured audience at all is still issued nothing</b> — the
   * one case {@link #PLATFORM_AUDIENCE} does not rescue. "Always included" widens what a client that
   * can already ask for something gets; it is not a back door around "no audiences configured",
   * which is a deployment that has not finished wiring this client up.
   */
  private List<String> resolveAudiences(IdpClient client, List<String> requested) {
    if (client.audienceSource() == IdpClient.AudienceSource.DATABASE) {
      Set<String> resolved = new LinkedHashSet<>(requested);
      resolved.add(PLATFORM_AUDIENCE);
      return List.copyOf(resolved);
    }
    List<String> allowed = client.audiences();
    if (allowed.isEmpty()) {
      LOG.warnf(
          "token request refused for client %s: no audiences configured",
          LoggableClientId.of(client.clientId()));
      throw OAuthException.invalidTarget("this client may request no audience");
    }
    // Every requested audience is still checked — narrowing the REQUEST is still refused when it
    // asks for something the client may not have. Narrowing the ANSWER is what stopped: a valid
    // request, however small, gets the whole list back.
    for (String audience : requested) {
      if (!allowed.contains(audience) && !PLATFORM_AUDIENCE.equals(audience)) {
        LOG.warnf(
            "token request refused for client %s: audience not allowed",
            LoggableClientId.of(client.clientId()));
        throw OAuthException.invalidTarget("audience is not allowed for this client");
      }
    }
    Set<String> resolved = new LinkedHashSet<>(allowed);
    resolved.add(PLATFORM_AUDIENCE);
    return List.copyOf(resolved);
  }
}
