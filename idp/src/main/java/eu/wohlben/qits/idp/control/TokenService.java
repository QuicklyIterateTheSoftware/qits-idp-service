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
 * The {@code client_credentials} grant: authenticate a client and mint an RS256 JWT. Also the other
 * three mints — the workstation's, the CLI's, and a commissioned token's introspection JWT.
 *
 * <p>The token says who the caller is and what it may be used against. It says nothing about what
 * the caller may do — that decision belongs to the resource service, helped by the shared
 * enforcement library.
 *
 * <p><b>Every token has one audience, {@link #PLATFORM_AUDIENCE}</b> (contract C7 of epic
 * qits-540, dossier page "Plan (as of 2026-09-13)"; qits-163). {@code aud} says where a token may be
 * presented, and every qits service accepts {@code qits-platform}, so there is nothing for a
 * per-client list to add. A caller that still sends an {@code audience} parameter is not refused;
 * the value is ignored.
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
   * The one audience. Every token minted here — client credentials, commissioned introspection,
   * CLI, workstation — carries exactly this, and nothing else.
   */
  public static final String PLATFORM_AUDIENCE = "qits-platform";

  /** {@code aud} of every token, as a list. */
  private static final List<String> AUDIENCES = List.of(PLATFORM_AUDIENCE);

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

  /** A CLI access token is as short-lived as a workstation's, and configured on its own key. */
  @ConfigProperty(name = "qits.idp.cli.access-token-ttl-seconds")
  long cliAccessTokenTtlSeconds;

  @Inject SigningKeys signingKeys;

  @Inject ClientRegistry clients;

  @Inject Users users;

  /**
   * Authenticate and mint. There is no audience argument: every token's {@code aud} is {@link
   * #PLATFORM_AUDIENCE}, whatever the request named.
   *
   * @throws OAuthException {@code invalid_client} (401) when authentication fails
   */
  public IssuedToken clientCredentials(String clientId, String secret) {
    IdpClient client = clients.authenticate(clientId, secret);
    return new IssuedToken(signFor(client, tokenTtlSeconds), tokenTtlSeconds, AUDIENCES);
  }

  /**
   * The short JWT an introspection of a commissioned token answers with (qits-450), together with
   * the {@code groups} it carries.
   *
   * <p><b>It is minted exactly as {@link #clientCredentials} would mint for a commissioned client
   * of the same kind</b>, because it is built as one: an {@link IdpClient} whose id is the token's
   * subject, whose roles are {@link CommissionRoles#forKind} (never the owner's), and whose claims,
   * kind and Git refs are the row's. So {@code aud} is {@code ["qits-platform"]}, {@code groups}
   * ends with {@code clients/<subject>}, and a service behind the edge verifies it against the JWKS
   * like any other token, with no second code path.
   *
   * <p><b>The one difference is its lifetime</b>: {@code
   * qits.idp.token-introspection-jwt-ttl-seconds}, not {@code qits.idp.token-ttl-seconds}.
   * Deleting the row refuses the next introspection at once, but a JWT already handed out behind
   * the edge lives out its {@code exp}; this TTL is the upper bound on that.
   *
   * @return empty when the token's owner is no longer a service client — the token is then refused
   *     like a deleted one
   */
  public Optional<CommissionedTokenGrant> forCommissionedToken(StoredToken token) {
    if (!clients.isServiceClient(token.owner())) {
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
            CommissionRoles.forKind(token.contextKind()),
            token.claims(),
            token.contextKind(),
            token.gitRefs());
    String jwt = signFor(asClient, introspectionJwtTtlSeconds);
    return Optional.of(
        new CommissionedTokenGrant(
            new IssuedToken(jwt, introspectionJwtTtlSeconds, AUDIENCES),
            List.copyOf(ClientRoles.mintedFor(asClient))));
  }

  /**
   * A client token's claims, signed: the one shape {@link #clientCredentials} and {@link
   * #forCommissionedToken} share, so the two cannot drift.
   */
  private String signFor(IdpClient client, long ttlSeconds) {
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();

    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(client.clientId())
            // A Set, so `aud` is always a JSON array, never a bare string.
            .audience(new LinkedHashSet<>(AUDIENCES))
            // The configured roles AND the client's own `clients/<id>`, which is minted here and
            // grantable nowhere — see ClientRoles.
            .groups(ClientRoles.mintedFor(client))
            .issuedAt(now)
            .expiresAt(now.plusSeconds(ttlSeconds));
    // The granted claims, verbatim. The idp does not interpret these values.
    client.claims().forEach(token::claim);
    // A commissioned client's kind and Git refs (principal-bound-git-refs-plan.md, C1). This is not
    // a branch on the kind of client: the fields are null for a service client, so it gets neither,
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
   * must reject every ref outside that pattern. Its audience is {@link #PLATFORM_AUDIENCE}, like
   * every token's, and the public client cannot choose another; what keeps it narrow is its one
   * role and its ref pattern, not where it may be presented.
   *
   * <p><b>And it carries no {@code clients/…} self-role.</b> That stamp says "this bearer IS that
   * machine client"; a token minted to a person's browser approval is not one, so the machine
   * identity a resource service gates on cannot be reached through a login.
   */
  public IssuedToken workstation(UUID userId) {
    Instant now = Instant.now();
    SigningKey key = signingKeys.signing();
    JwtClaimsBuilder token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(userId.toString())
            .audience(new LinkedHashSet<>(AUDIENCES))
            .groups(Set.of("qits:git:external"))
            .claim("credential_type", "workstation")
            // Both spellings of the same rule: git_ref_pattern for githosts that read only it,
            // git_refs for the ones that read the list (principal-bound-git-refs-plan.md, C1).
            .claim("git_ref_pattern", "refs/heads/external/*")
            .claim(ClaimNames.GIT_REFS, GitRefs.PERSON)
            .issuedAt(now)
            .expiresAt(now.plusSeconds(workstationAccessTokenTtlSeconds));
    String jwt = token.jws().keyId(key.kid()).sign(key.privateKey());
    return new IssuedToken(jwt, workstationAccessTokenTtlSeconds, AUDIENCES);
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
   * <p>Its audience is {@link #PLATFORM_AUDIENCE}, like every token's. The public client cannot
   * choose another.
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
            .audience(new LinkedHashSet<>(AUDIENCES))
            .groups(groups)
            .claim("credential_type", "cli")
            // A person pushes only external/*, whatever their roles (user ruling 2026-09-12).
            .claim(ClaimNames.GIT_REFS, GitRefs.PERSON)
            .issuedAt(now)
            .expiresAt(now.plusSeconds(cliAccessTokenTtlSeconds));
    String jwt = token.jws().keyId(key.kid()).sign(key.privateKey());
    return new IssuedToken(jwt, cliAccessTokenTtlSeconds, AUDIENCES);
  }
}
