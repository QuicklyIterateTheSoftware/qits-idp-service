package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import eu.wohlben.qits.idp.control.ClaimNames;
import eu.wohlben.qits.idp.control.CommissionedTokens;
import eu.wohlben.qits.idp.control.DynamicClients;
import eu.wohlben.qits.idp.control.Issuer;
import eu.wohlben.qits.idp.control.ServiceClients;
import eu.wohlben.qits.idp.control.Sessions;
import eu.wohlben.qits.idp.control.SigningKeys;
import eu.wohlben.qits.idp.control.SigningKeys.SigningKey;
import eu.wohlben.qits.idp.control.TokenService;
import eu.wohlben.qits.idp.control.Users;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The RFC 8693 token exchange at {@code POST /idp/token} (epic qits-2523, dossier page "Token
 * exchange at qits-idp"), end to end: who may ask, which subjects are accepted, what the exchanged
 * token copies and adds, and how long it lives.
 *
 * <p>The actor is {@code dev-qits-egress}: the shipped default of {@code
 * qits.idp.token-exchange.actors} with {@code QITS_ENVIRONMENT} unset, which is the suite's case.
 * It is made a service client here, so the default is what the suite tests — no config override.
 */
@QuarkusTest
public class TokenExchangeTest {

  static final String ACTOR = "dev-qits-egress";

  private static final String GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";

  @Inject ServiceClients serviceClients;
  @Inject DynamicClients dynamicClients;
  @Inject CommissionedTokens commissionedTokens;
  @Inject Sessions sessions;
  @Inject SigningKeys signingKeys;
  @Inject Issuer issuer;
  @Inject TokenService tokenService;
  @Inject IdpUserRepository users;

  private String actorSecret;

  @BeforeEach
  void anActor() {
    serviceClients.delete(ACTOR);
    actorSecret = serviceClients.create(ACTOR, "test-broad").secret();
  }

  @Test
  public void aJwtSubjectIsExchangedForATokenNamingItsActor() throws Exception {
    String subject = clientCredentials("test-narrow", "test-narrow-secret");
    JwtClaims subjectClaims = PublishedJwks.verify(subject, "qits-platform");

    String exchanged =
        exchange(basic(ACTOR, actorSecret), subject)
            .statusCode(200)
            .header("Cache-Control", "no-store")
            .body("issued_token_type", equalTo(ACCESS_TOKEN))
            .body("token_type", equalTo("Bearer"))
            .body("expires_in", equalTo(300))
            .extract()
            .path("access_token");

    // The same validation every resource service makes of an ordinary token.
    JwtClaims claims = PublishedJwks.verify(exchanged, "qits-platform");
    assertEquals(subjectClaims.getSubject(), claims.getSubject());
    assertEquals(PublishedJwks.ISSUER, claims.getIssuer());
    assertEquals(List.of("qits-platform"), PublishedJwks.audienceOf(claims));
    // No role is added or dropped: the exchange never widens access.
    assertEquals(
        subjectClaims.getStringListClaimValue("groups"), claims.getStringListClaimValue("groups"));
    assertEquals("*", claims.getClaimValueAsString(ClaimNames.PROJECT));
    assertEquals(Map.of("sub", ACTOR), claims.getClaimValue(ClaimNames.ACT));
    assertEquals(300, claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue());
  }

  @Test
  public void aCommissionedClientsClaimsAreCopiedAndNothingElse() throws Exception {
    String project = UUID.randomUUID().toString();
    String agent = UUID.randomUUID().toString();
    DynamicClients.Commissioned client =
        dynamicClients.commission(
            "test-broad",
            "workspace",
            "exchange-" + UUID.randomUUID(),
            Map.of(ClaimNames.PROJECT, project, ClaimNames.AGENT, agent),
            List.of("refs/heads/ticket/exchange"));
    String subject = clientCredentials(client.client().clientId(), client.secret());
    JwtClaims subjectClaims = PublishedJwks.verify(subject, "qits-platform");

    JwtClaims claims =
        PublishedJwks.verify(exchangedToken(basic(ACTOR, actorSecret), subject), "qits-platform");

    assertEquals(client.client().clientId(), claims.getSubject());
    assertEquals(
        subjectClaims.getStringListClaimValue("groups"), claims.getStringListClaimValue("groups"));
    assertEquals(project, claims.getClaimValueAsString(ClaimNames.PROJECT));
    assertEquals(agent, claims.getClaimValueAsString(ClaimNames.AGENT));
    assertEquals("workspace", claims.getClaimValueAsString(ClaimNames.CONTEXT_KIND));
    assertEquals(
        List.of("refs/heads/ticket/exchange"),
        claims.getStringListClaimValue(ClaimNames.GIT_REFS));
    assertFalse(claims.hasClaim(ClaimNames.WORKSPACE), "a claim the subject lacks is not added");
    assertFalse(claims.hasClaim(ClaimNames.BRANCH), "a claim the subject lacks is not added");
    assertEquals(
        Set.of("iss", "aud", "iat", "exp", "jti", "sub", "groups", "project", "agent",
            "context_kind", "git_refs", "act"),
        Set.copyOf(claims.getClaimNames()),
        "the copied claims, the exchanged token's own, and act — nothing else (no scope)");
  }

  @Test
  public void aPersonsCliTokenKeepsItsRolesItsCredentialTypeAndItsGitRefs() throws Exception {
    UUID id = person();
    String subject = tokenService.cli(id).accessToken();
    JwtClaims subjectClaims = PublishedJwks.verify(subject, "qits-platform");

    JwtClaims claims =
        PublishedJwks.verify(exchangedToken(basic(ACTOR, actorSecret), subject), "qits-platform");

    assertEquals(id.toString(), claims.getSubject());
    assertEquals(List.of("qits:admin"), claims.getStringListClaimValue("groups"));
    assertEquals(
        subjectClaims.getStringListClaimValue("groups"), claims.getStringListClaimValue("groups"));
    assertEquals("cli", claims.getClaimValueAsString("credential_type"));
    assertEquals(
        subjectClaims.getStringListClaimValue(ClaimNames.GIT_REFS),
        claims.getStringListClaimValue(ClaimNames.GIT_REFS));
    assertEquals(Map.of("sub", ACTOR), claims.getClaimValue(ClaimNames.ACT));
  }

  @Test
  public void anOpaqueSubjectIsResolvedAsIntrospectionResolvesIt() throws Exception {
    String project = UUID.randomUUID().toString();
    CommissionedTokens.Commissioned token =
        commissionedTokens.commission(
            "test-broad",
            "workspace",
            "exchange-" + UUID.randomUUID(),
            Map.of(ClaimNames.PROJECT, project),
            List.of("refs/heads/ticket/exchange"));
    List<String> introspectedGroups =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic("test-broad", "test-broad-secret"))
            .body(Map.of("token", token.value()))
            .post("/idp/api/tokens/introspect")
            .then()
            .statusCode(200)
            .extract()
            .path("roles");

    String exchanged =
        exchange(basic(ACTOR, actorSecret), token.value())
            .statusCode(200)
            // An opaque token has no expiry, so the exchange's own lifetime decides.
            .body("expires_in", equalTo(300))
            .extract()
            .path("access_token");

    JwtClaims claims = PublishedJwks.verify(exchanged, "qits-platform");
    assertEquals(token.token().subject(), claims.getSubject());
    assertEquals(introspectedGroups, claims.getStringListClaimValue("groups"));
    assertEquals(project, claims.getClaimValueAsString(ClaimNames.PROJECT));
    assertEquals("workspace", claims.getClaimValueAsString(ClaimNames.CONTEXT_KIND));
    assertEquals(
        List.of("refs/heads/ticket/exchange"),
        claims.getStringListClaimValue(ClaimNames.GIT_REFS));
    assertEquals(Map.of("sub", ACTOR), claims.getClaimValue(ClaimNames.ACT));
  }

  @Test
  public void theExchangedTokenNeverOutlivesItsSubject() throws Exception {
    Instant soon = Instant.now().plusSeconds(60);
    String subject = signed("test-narrow", soon, null);

    String exchanged =
        exchange(basic(ACTOR, actorSecret), subject).statusCode(200).extract().path("access_token");

    JwtClaims claims = PublishedJwks.verify(exchanged, "qits-platform");
    assertEquals(soon.getEpochSecond(), claims.getExpirationTime().getValue());
  }

  @Test
  public void aClientThatIsNoActorIsUnauthorized() {
    String subject = clientCredentials("test-narrow", "test-narrow-secret");

    exchange(basic("test-broad", "test-broad-secret"), subject)
        .statusCode(400)
        .body("error", equalTo("unauthorized_client"));
  }

  @Test
  public void anActorThatFailsAuthenticationIsAnInvalidClient() {
    String subject = clientCredentials("test-narrow", "test-narrow-secret");

    exchange(basic(ACTOR, "not-" + actorSecret), subject)
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }

  @Test
  public void anActorMayAuthenticateInTheFormToo() {
    String subject = clientCredentials("test-narrow", "test-narrow-secret");

    post(
            null,
            "grant_type=" + enc(GRANT)
                + "&client_id=" + ACTOR
                + "&client_secret=" + enc(actorSecret)
                + "&subject_token=" + enc(subject)
                + "&subject_token_type=" + enc(ACCESS_TOKEN))
        .statusCode(200);
  }

  @Test
  public void anExchangedTokenIsNeverASubjectAgain() {
    String subject = clientCredentials("test-narrow", "test-narrow-secret");
    String exchanged = exchangedToken(basic(ACTOR, actorSecret), subject);

    exchange(basic(ACTOR, actorSecret), exchanged)
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
  }

  @Test
  public void aSubjectCarryingActIsRefusedHoweverItCame() {
    // Signed by this idp's own key, so only the act claim is wrong with it.
    String subject = signed("test-narrow", Instant.now().plusSeconds(600), "someone-else");

    exchange(basic(ACTOR, actorSecret), subject)
        .statusCode(400)
        .body("error", equalTo("invalid_grant"));
  }

  @Test
  public void anythingButALiveTokenFromThisIdpIsAnInvalidGrant() throws Exception {
    UUID id = person();
    String sessionCookie =
        sessions.open(new Users.Account(id, "exchange-" + id, List.of("qits:admin"))).token();
    CommissionedTokens.Commissioned deleted =
        commissionedTokens.commission(
            "test-broad", "workspace", "exchange-" + UUID.randomUUID(), null, null);
    commissionedTokens.delete(deleted.token().id(), "test-broad");

    for (String subject :
        List.of(
            "not-a-token",
            sessionCookie,
            "qits_tok_never-commissioned",
            deleted.value(),
            signed("test-narrow", Instant.now().minusSeconds(60), null),
            foreignSigned("test-narrow"))) {
      exchange(basic(ACTOR, actorSecret), subject)
          .statusCode(400)
          .body("error", equalTo("invalid_grant"));
    }
  }

  @Test
  public void theSubjectTypeMustBeAnAccessToken() {
    String subject = clientCredentials("test-narrow", "test-narrow-secret");

    post(
            basic(ACTOR, actorSecret),
            "grant_type=" + enc(GRANT)
                + "&subject_token=" + enc(subject)
                + "&subject_token_type=" + enc("urn:ietf:params:oauth:token-type:id_token"))
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
    post(basic(ACTOR, actorSecret), "grant_type=" + enc(GRANT) + "&subject_token=" + enc(subject))
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void aMissingSubjectIsAnInvalidRequest() {
    post(
            basic(ACTOR, actorSecret),
            "grant_type=" + enc(GRANT) + "&subject_token_type=" + enc(ACCESS_TOKEN))
        .statusCode(400)
        .body("error", equalTo("invalid_request"));
  }

  @Test
  public void theExchangeCopiesOnlyTheListedClaims() {
    assertEquals(
        List.of("sub", "groups", "project", "workspace", "branch", "agent", "entity",
            "context_kind", "credential_type", "git_refs"),
        TokenService.EXCHANGED_CLAIMS);
    assertFalse(ClaimNames.GRANTABLE.contains(ClaimNames.ACT), "act is never grantable");
  }

  // --- helpers ---------------------------------------------------------------------------------

  /** A fresh person holding {@code qits:admin}, as a sign-in leaves them; their id. */
  private UUID person() {
    UUID id = UUID.randomUUID();
    QuarkusTransaction.requiringNew()
        .run(
            () -> {
              IdpUser row = new IdpUser();
              row.id = id;
              row.username = "exchange-" + id;
              row.createdAt = Instant.now();
              users.persist(row);
              IdpUserRole role = new IdpUserRole();
              role.userId = id;
              role.role = "qits:admin";
              role.createdAt = Instant.now();
              role.persist();
            });
    return id;
  }

  private static String clientCredentials(String clientId, String secret) {
    return post(basic(clientId, secret), "grant_type=client_credentials")
        .statusCode(200)
        .extract()
        .path("access_token");
  }

  private static String exchangedToken(String authorization, String subject) {
    return exchange(authorization, subject).statusCode(200).extract().path("access_token");
  }

  private static ValidatableResponse exchange(String authorization, String subject) {
    return post(
        authorization,
        "grant_type=" + enc(GRANT)
            + "&subject_token=" + enc(subject)
            + "&subject_token_type=" + enc(ACCESS_TOKEN));
  }

  private static ValidatableResponse post(String authorization, String form) {
    var request = given().contentType(ContentType.URLENC).body(form);
    if (authorization != null) {
      request = request.header("Authorization", authorization);
    }
    return request.when().post("/idp/token").then();
  }

  /** A token in this idp's own shape and key, expiring at {@code exp}, with {@code act} if named. */
  private String signed(String subject, Instant exp, String actor) {
    SigningKey key = signingKeys.signing();
    var token =
        Jwt.claims()
            .issuer(issuer.url())
            .subject(subject)
            .audience(Set.of(TokenService.PLATFORM_AUDIENCE))
            .groups(Set.of("qits:system", "clients/" + subject))
            .issuedAt(Instant.now().minusSeconds(120))
            .expiresAt(exp);
    if (actor != null) {
      token.claim(ClaimNames.ACT, Map.of("sub", actor));
    }
    return token.jws().keyId(key.kid()).sign(key.privateKey());
  }

  /** The right shape and the idp's own {@code kid}, signed by a key the idp never held. */
  private String foreignSigned(String subject) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    RSAPrivateKey foreign = (RSAPrivateKey) generator.generateKeyPair().getPrivate();
    return Jwt.claims()
        .issuer(issuer.url())
        .subject(subject)
        .audience(Set.of(TokenService.PLATFORM_AUDIENCE))
        .expiresAt(Instant.now().plusSeconds(600))
        .jws()
        .keyId(signingKeys.signing().kid())
        .sign(foreign);
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
  }

  private static String enc(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
