package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.control.RegisterTokens;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.error.AuthException;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Optional;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

/**
 * "Who is calling", for the <b>admin doors</b> (qits-1260): minting a register token, listing the
 * users, deleting one. Every one of them accepts the same three callers, and this class is the one
 * place that says which:
 *
 * <ol>
 *   <li><b>A service client over Basic</b>, holding {@code qits:system} — exactly what {@link
 *       BasicCaller#staticOnly} has always accepted, so the bootstrap's mint is unchanged. A
 *       commissioned client is still refused (403): a credential handed to one context must not
 *       produce accounts.
 *   <li><b>A {@code qits:admin} person's bearer</b> — a JWT this idp issued (verified by {@link
 *       BearerCaller}) whose {@code groups} hold {@code qits:admin} <i>and</i> whose {@code sub} is
 *       the id of an account that exists and still holds {@code qits:admin}. A person's token is
 *       the CLI's ({@code TokenService.cli}): its {@code sub} is the user's id and its {@code groups}
 *       are the user's roles. A service client's or a commissioned credential's {@code sub} is a
 *       client id, never a user id, so no machine bearer passes — and none holds {@code qits:admin}
 *       anyway: a {@code qits:system} or {@code qits:agent} bearer is 403. The store check means a
 *       deleted or demoted person's still-unexpired token stops working at once.
 *   <li><b>A signed-in browser session</b> ({@link SessionCookie#NAME}) whose account holds {@code
 *       qits:admin}. Used only when no {@code Authorization} header is sent — an explicit header is
 *       the caller's intent, and a browser does not send one.
 * </ol>
 *
 * <p><b>The bearer here is the second exception to "no write route accepts a bearer"</b> (user
 * ruling 2026-10-15, qits-1260), and only for a {@code qits:admin} USER bearer; see {@link
 * BearerCaller}. Agents gain nothing: their bearer holds {@code qits:agent} and is refused.
 *
 * <p><b>The refusals use both vocabularies, chosen by who called.</b> A Basic or bearer caller that
 * fails to authenticate gets {@link OAuthException} as on every machine door (401, with the Basic
 * challenge). A caller with no header at all is a browser whose session is missing or expired, and
 * gets {@link AuthException#invalidCredentials} — 401 with <i>no</i> challenge, because a Basic
 * challenge on a {@code fetch} is a native credentials dialog in front of the page. Authenticated
 * but not an admin is {@code access_denied} (403) for all three.
 */
@ApplicationScoped
public class AdminCaller {

  /** The role every admin door requires of a person. */
  public static final String ADMIN = "qits:admin";

  /**
   * Who passed an admin door.
   *
   * @param mintedBy what a register token records as its minter: the client id, or {@link
   *     RegisterTokens#mintedByPerson} for a person
   * @param userId the person's account id; null for a service client
   */
  public record Admin(String mintedBy, UUID userId) {

    /** True when this caller is the account with this id — the self-delete check. */
    public boolean is(UUID account) {
      return userId != null && userId.equals(account);
    }
  }

  @Inject BasicCaller basicCaller;

  @Inject BearerCaller bearerCaller;

  @Inject Sessions sessions;

  @Inject Users users;

  /**
   * The admin calling, by whichever of the three ways it came.
   *
   * @param authorization the {@code Authorization} header, or null
   * @param sessionToken the {@code qits-session} cookie's value, or null
   * @param refusal what a commissioned Basic client is told it may not do
   * @throws OAuthException 401 for a Basic pair or bearer that does not authenticate, 403 for one
   *     that does and is not allowed here
   * @throws AuthException 401 for no header and no live session
   */
  public Admin require(String authorization, String sessionToken, String refusal) {
    if (authorization != null && !authorization.isBlank()) {
      if (BearerCaller.isBearer(authorization)) {
        return person(bearerCaller.requireAnyRole(authorization, ADMIN));
      }
      IdpClient client = basicCaller.staticOnly(authorization, refusal, BasicCaller.SYSTEM);
      return new Admin(client.clientId(), null);
    }
    Sessions.Live session =
        sessions
            .resolve(sessionToken)
            .orElseThrow(
                () ->
                    AuthException.invalidCredentials(
                        "a signed-in session, a bearer or a service client's credentials are"
                            + " required"));
    if (!session.roles().contains(ADMIN)) {
      throw OAuthException.accessDenied("the signed-in account lacks role " + ADMIN);
    }
    return new Admin(RegisterTokens.mintedByPerson(session.userId()), session.userId());
  }

  /** A verified bearer holding {@code qits:admin}: it must name a person who still holds it. */
  private Admin person(JwtClaims claims) {
    String subject;
    try {
      subject = claims.getSubject();
    } catch (MalformedClaimException e) {
      throw OAuthException.invalidToken("the bearer's sub is not a string");
    }
    Optional<Users.Account> account = userId(subject).flatMap(users::byId);
    if (account.isEmpty() || !account.get().roles().contains(ADMIN)) {
      throw OAuthException.accessDenied(
          "only the bearer of a person holding " + ADMIN + " may use this door");
    }
    UUID id = account.get().id();
    return new Admin(RegisterTokens.mintedByPerson(id), id);
  }

  /** A person token's {@code sub} is the account's UUID; anything else is a client id. */
  private static Optional<UUID> userId(String subject) {
    if (subject == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(UUID.fromString(subject));
    } catch (IllegalArgumentException notAUserId) {
      return Optional.empty();
    }
  }
}
