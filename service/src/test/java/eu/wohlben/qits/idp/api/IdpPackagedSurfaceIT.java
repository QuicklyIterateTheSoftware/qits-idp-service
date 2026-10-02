package eu.wohlben.qits.idp.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.wohlben.qits.idp.testdb.EmbeddedPg;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.http.ContentType;
import io.vertx.core.json.JsonObject;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The whole service as it is <b>packaged</b> — the fast-jar under {@code mvn verify
 * -DskipITs=false}, the GraalVM binary under {@code mvn verify -Dnative}. The assertions are chosen
 * for what a native build can silently lose rather than for API coverage (that is the
 * {@code @QuarkusTest} suite's job):
 *
 * <ul>
 *   <li>the routes are where the config says — {@code quarkus.rest.path} and {@code
 *       quarkus.http.non-application-root-path} are build-time settings baked into the artifact,
 *       and an OIDC consumer derives the discovery URL from the first of them;
 *   <li>the shipped datasource <b>expression</b> resolves and connects, and {@code
 *       db/idp/migration/} survived as a resource — migrations are loaded by scanning a classpath
 *       location, exactly the shape native-image drops;
 *   <li><b>RSA key generation works in the packaged process.</b> Key generation, PKCS#8 encoding
 *       and RS256 signing all go through JCA providers, which is the other thing a native image
 *       can lose. A service that boots and then cannot mint is the failure this catches.
 *   <li><b>the WebAuthn ceremony works in the packaged process</b>, which is the same class of loss
 *       one layer heavier: rebuilding a stored public key is {@code KeyFactory.getInstance("EC")},
 *       verifying an assertion is {@code SHA256withECDSA}, and webauthn4j parses CBOR reflectively.
 *       A binary that lost any of it boots, serves the discovery document, and cannot verify a
 *       single login.
 *   <li><b>the client is served, and does not swallow the protocol.</b> Quinoa is disabled by
 *       default in test mode, so no {@code @QuarkusTest} builds or serves the SPA and every
 *       assertion about {@code /idp/} would pass against a process with no client in it. The
 *       packaged artifact is the only place either half can be proven.
 * </ul>
 */
@QuarkusIntegrationTest
@TestProfile(IdpPackagedSurfaceIT.PackagedUnderTarget.class)
public class IdpPackagedSurfaceIT {

  private static final String SECRET = "packaged-it-secret";

  /**
   * The one string that identifies a response as the CLIENT's index.html rather than anything else
   * this process serves. It is also the string that has to agree with {@code
   * quarkus.quinoa.ui-root-path}, so the probes below double as the check that it still does.
   */
  private static final String BASE_HREF = "<base href=\"/idp/\">";

  /**
   * Hands the launched artifact a database the way a deployment does — as the generic resource
   * triple, not as the datasource keys. The idp jar ships {@code jdbc.url=${QITS_RESOURCE_DB_URL}}
   * and its two siblings, so supplying the variables leaves the <b>shipped</b> expression itself
   * under test (the AUTO_SERVER lesson, applied to what replaced that URL). Expression expansion
   * reads the whole config, and these overrides reach the launched process as system properties, so
   * the same three names resolve.
   *
   * <p>The database is an embedded postgres this JVM starts. <b>Its url travels through a system
   * property rather than a static field</b>: a test profile is instantiated in more than one
   * classloader, so a field written by one copy is not the field the other reads, while the process
   * has exactly one property table.
   *
   * <p>The secret is an override for the same reason the shipped config has none: a client with no
   * secret is unusable, so the packaged process can only be asked to mint once a deployment (here,
   * this profile) gives it one.
   */
  public static class PackagedUnderTarget implements QuarkusTestProfile {

    /** Where the url is parked for whichever copy of this class is asked second. */
    private static final String URL_PROPERTY = "qits.test.packaged-it.db-url";

    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "QITS_RESOURCE_DB_URL", databaseUrl(),
          "QITS_RESOURCE_DB_USERNAME", EmbeddedPg.USER,
          "QITS_RESOURCE_DB_PASSWORD", EmbeddedPg.PASSWORD,
          "qits.idp.client.prod-qits-workspaces.secret", SECRET);
    }

    private static synchronized String databaseUrl() {
      String recorded = System.getProperty(URL_PROPERTY);
      if (recorded != null) {
        return recorded;
      }
      // localhost resolves for the launched process too — it is a child of this JVM on this host.
      String url = EmbeddedPg.url("idp_packaged_it");
      System.setProperty(URL_PROPERTY, url);
      return url;
    }
  }

  @Test
  public void theDiscoveryDocumentIsWhereAnOidcConsumerLooksForIt() {
    // auth-server-url http://dev-qits-platform-idp:8080/idp + OIDC's own derivation = this path.
    // It is a build-time route prefix, so the artifact is the only place it can be proven.
    //
    // THE TWO STRINGS ARE DIFFERENT AND BOTH ARE SPELLED OUT HERE, because this is the packaged
    // artifact and the shipped defaults are what it serves. `issuer` is the identifier a consumer
    // compares `iss` against; `jwks_uri` hangs off the ADDRESS the service answers on. They were one
    // string until the platform plane was deleted, and a jwks_uri still derived from the identifier
    // pointed at a host that no longer resolves — see eu.wohlben.qits.idp.control.Issuer.
    given()
        .when()
        .get("/idp/.well-known/openid-configuration")
        .then()
        .statusCode(200)
        .body("issuer", equalTo("https://idp.qits.localhost"))
        .body("jwks_uri", equalTo("http://dev-qits-platform-idp:8080/idp/jwks"));

    // qits-platform-edge routes by declared route and keeps the path, so there is no unprefixed
    // form to fall back to.
    given().when().get("/.well-known/openid-configuration").then().statusCode(404);
  }

  /**
   * The client is mounted, and its {@code <base href>} agrees with where it is mounted. The two are
   * configured in different repositories — {@code quarkus.quinoa.ui-root-path} here,
   * {@code baseHref} in qits-platform-spa-idp's angular.json — and a disagreement serves a page
   * that loads and then fetches its own JavaScript from a path that 404s. Nothing on this side
   * notices, which is why the string is asserted rather than the status alone.
   */
  @Test
  public void theClientIsServedAtTheSegmentWithABaseHrefThatMatches() {
    given()
        .when()
        .get("/idp/")
        .then()
        .statusCode(200)
        .contentType(ContentType.HTML)
        .body(containsString(BASE_HREF));
  }

  /**
   * A deep link is the SPA fallback doing its job: {@code /idp/login} has no file behind it, and
   * {@code enable-spa-routing} is what makes a reload or a pasted link reach the Angular router
   * instead of a 404. One of the client's four doors stands for all of them — the others are
   * {@code /idp/register}, {@code /idp/clients} and {@code /idp/users}.
   */
  @Test
  public void aDeepLinkFallsBackToTheClientSoTheAngularRouterOwnsIt() {
    given().when().get("/idp/login").then().statusCode(200).contentType(ContentType.HTML);
  }

  /**
   * THE HALF THAT COSTS SOMETHING IF IT IS WRONG. The SPA fallback is a late-order catch-all, so a
   * path under {@code /idp} that matches no route is rerouted to index.html and answers
   * {@code 200 text/html}. This service shares one root between the client and the OIDC protocol —
   * {@code quarkus.rest.path=/idp}, because a consumer derives the discovery URL itself — so the
   * whole machine surface is protected by {@code quarkus.quinoa.ignored-path-prefixes} and by
   * nothing else.
   *
   * <p>A mistyped protocol path answering a page is not one bad response: an OIDC consumer that
   * asked for a discovery document and got HTML would <b>cache</b> it, and every service on the
   * platform is such a consumer.
   *
   * <p><b>What is asserted is the status and the absence of the client's page — not the absence of
   * HTML</b>, and the difference was measured here rather than assumed. An ignored path falls to
   * Quarkus' own not-found handler, which answers {@code 404 text/html} with a 53-byte {@code
   * <html><body><h1>Resource not found</h1></body></html>}. That is a correct refusal wearing a
   * browser's content type: a machine client reads the 404, and there is no document in it to
   * mis-parse or cache. Asserting "never text/html" would therefore fail on the working
   * configuration, which is exactly what it did first. {@link #BASE_HREF} is the discriminator that
   * means what the doctrine's "never HTML" was reaching for.
   *
   * <p>Each entry in the list gets a case here. Add a literal route, add its prefix entry, add its
   * line below — the same commit, which is the doctrine's rule.
   */
  @Test
  public void aMistypedMachinePathIs404AndNeverThePage() {
    // /api — the commission API. Its real routes answer above; this is the shape one segment off.
    given().when().get("/idp/api/nope").then().statusCode(404).body(not(containsString(BASE_HREF)));

    // /.well-known — the one an OIDC consumer reaches for, and the one whose wrong answer travels.
    given()
        .when()
        .get("/idp/.well-known/nope")
        .then()
        .statusCode(404)
        .body(not(containsString(BASE_HREF)));

    // /q — Quarkus' non-application root. Not an OIDC path, but it is in the list, so it is here.
    given().when().get("/idp/q/nope").then().statusCode(404).body(not(containsString(BASE_HREF)));
  }

  /**
   * THE LIMIT OF THE IGNORE LIST, ASSERTED SO IT IS A DECISION RATHER THAN A DISCOVERY. An entry
   * protects a path <b>segment</b>, not a string prefix: {@code /token} covers {@code /idp/token}
   * and anything below it, and does <b>not</b> cover {@code /idp/token-nope}, which shares the
   * first six characters and is a different segment. Measured on the packaged fast-jar 2026-08-14 —
   * {@code /idp/token-nope} and {@code /idp/jwks-nope} both answer 200 with index.html.
   *
   * <p><b>That is acceptable, and the reason is what /idp is.</b> It is a browser-facing segment
   * whose unmatched paths belong to the Angular router by design — that is the same fallback
   * {@code /idp/login} depends on, and it cannot tell a typo from a route the client owns. What the
   * list has to protect is the paths a MACHINE derives, and a machine does not derive
   * {@code jwks-nope}: an OIDC consumer builds {@code /idp/.well-known/openid-configuration} from
   * its configured auth-server-url and then follows the document, so the ways it can go wrong are
   * inside the segments the list covers — which the test above pins.
   *
   * <p>The consequence to keep in mind when adding a route: a new machine path must be a segment of
   * its own, or a sibling of it typed by hand will be answered with the page.
   */
  @Test
  public void aSiblingOfAProtocolPathIsTheClientsToAnswer() {
    given()
        .when()
        .get("/idp/jwks-nope")
        .then()
        .statusCode(200)
        .contentType(ContentType.HTML)
        .body(containsString(BASE_HREF));
  }

  /**
   * A KNOWN WART, PINNED RATHER THAN FIXED. Quinoa mounts the client at {@code ui-root-path + "*"}
   * — {@code /idp/*} — which does not match the bare segment, so {@code /idp} without the trailing
   * slash is a 404 while {@code /idp/} is the page (upstream quinoa issue #960). It affects every
   * client on the platform identically and a redirect would be a gateway-level decision, so it is
   * deliberately not solved per-service. This test exists so that a future Quinoa bump changing the
   * behaviour is a failing assertion rather than a surprise.
   */
  @Test
  public void theBareSegmentWithNoTrailingSlashIsStillA404() {
    given().when().get("/idp").then().statusCode(404);
  }

  @Test
  public void theReadinessEndpointIsWhereTheDeploymentLooksForIt() {
    given()
        .when()
        .get("/idp/q/health/ready")
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"));
  }

  @Test
  public void thePackagedProcessGeneratesAKeyIntoTheShippedDatabaseAndSignsWithIt()
      throws Exception {
    String token =
        given()
            .contentType(ContentType.URLENC)
            .body(
                "grant_type=client_credentials&client_id=prod-qits-workspaces&client_secret="
                    + SECRET
                    + "&audience=qits-platform-artifacts")
            .when()
            .post("/idp/token")
            .then()
            .statusCode(200)
            .extract()
            .path("access_token");

    assertNotNull(PublishedJwks.kidOf(token), "the kid header must survive the packaging");
    assertEquals(
        "prod-qits-workspaces",
        PublishedJwks.verify(token, "qits-platform-artifacts").getSubject());

    // That the round trip happened at all is the proof the shipped expression resolved: the jar
    // carries no fallback URL, so a process that reached a store did so through
    // QITS_RESOURCE_DB_URL, and one that had not would have died at Flyway before serving a route.
  }

  /**
   * The commission API in the packaged process: a JSON body in and out, a row written and deleted,
   * and a credential that mints between the two.
   *
   * <p>It is here rather than only in the {@code @QuarkusTest} suite because every step of it is a
   * thing a native image can lose quietly — record serialization needs a statically visible type to
   * register for reflection, SHA-256 needs a JCA provider (the same class of failure as RSA signing
   * above), and the {@code V2} migration has to have survived as a classpath resource for the table
   * to exist at all. It has already earned its place: the first native build answered 500 here,
   * because a {@code Response} return type hid the response record from the image builder.
   */
  @Test
  public void thePackagedProcessCommissionsMintsAndDecommissions() {
    String body =
        "{\"contextKind\":\"packaged-it\",\"contextId\":\"ctx-"
            + System.nanoTime()
            + "\",\"gitRefs\":[\"refs/heads/packaged/one\"]}";
    io.restassured.path.json.JsonPath commissioned =
        given()
            .contentType(ContentType.JSON)
            .header("Authorization", basic("prod-qits-workspaces", SECRET))
            .body(body)
            .when()
            .post("/idp/api/clients")
            .then()
            .statusCode(201)
            .body("owner", equalTo("prod-qits-workspaces"))
            .extract()
            .jsonPath();

    String clientId = commissioned.getString("clientId");
    String secret = commissioned.getString("secret");
    assertNotNull(clientId);
    assertNotNull(secret);

    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic(clientId, secret))
        .body("grant_type=client_credentials&audience=qits-platform-artifacts")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(200);

    // The listing is a second record through the same serializer, and a second native risk.
    given()
        .header("Authorization", basic("prod-qits-workspaces", SECRET))
        .when()
        .get("/idp/api/clients")
        .then()
        .statusCode(200)
        .body("find { it.clientId == '" + clientId + "' }.contextKind", equalTo("packaged-it"))
        .body(
            "find { it.clientId == '" + clientId + "' }.gitRefs",
            equalTo(java.util.List.of("refs/heads/packaged/one")));

    // The git-refs replace: a third record in, the view record out, and a row update.
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", basic("prod-qits-workspaces", SECRET))
        .body("{\"gitRefs\":[]}")
        .when()
        .put("/idp/api/clients/" + clientId + "/git-refs")
        .then()
        .statusCode(200)
        .body("gitRefs", equalTo(java.util.List.of()));

    given()
        .header("Authorization", basic("prod-qits-workspaces", SECRET))
        .when()
        .delete("/idp/api/clients/" + clientId)
        .then()
        .statusCode(204);

    given()
        .contentType(ContentType.URLENC)
        .header("Authorization", basic(clientId, secret))
        .body("grant_type=client_credentials")
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401);
  }

  /**
   * The whole user round trip in the packaged process: mint a register token, register a passkey,
   * log in with it, introspect the cookie, log out.
   *
   * <p>It is here for the same reason the commission round trip is, and it is the heavier case of
   * the two. <b>Every step is something a native image can lose quietly.</b> The ceremony runs on
   * JCA end to end — {@code KeyFactory.getInstance("EC")} rebuilding the stored public key, {@code
   * SHA256withECDSA} verifying the assertion, SHA-256 fingerprinting the session — and a binary
   * that lost a provider boots, serves the discovery document, and cannot verify a single login.
   * Beside that: webauthn4j parses CBOR reflectively, four request and response records have to
   * survive as types the image builder can see, and {@code V3} has to have survived as a classpath
   * resource for any of the five tables to exist.
   *
   * <p>The password path is deliberately not repeated here — bcrypt is exercised by the
   * {@code @QuarkusTest} suite and carries none of the reflective risk above.
   */
  @Test
  public void thePackagedProcessRegistersAPasskeyLogsInWithItAndIntrospectsTheSession() {
    String username = "packaged-it-" + java.util.UUID.randomUUID();
    CookieFilter browser = new CookieFilter();
    WebAuthnTestHardware authenticator = new WebAuthnTestHardware();

    String registerToken =
        given()
            .header("Authorization", basic("prod-qits-workspaces", SECRET))
            .when()
            .post("/idp/api/register-tokens")
            .then()
            .statusCode(201)
            .extract()
            .path("token");
    assertNotNull(registerToken, "the bootstrap reads this field by name");

    String registerChallenge =
        given()
            .filter(browser)
            .contentType(ContentType.JSON)
            .body("{\"username\":\"" + username + "\",\"token\":\"" + registerToken + "\"}")
            .when()
            .post("/idp/api/auth/register-options")
            .then()
            .statusCode(200)
            .extract()
            .path("challenge");

    io.restassured.response.Response registered =
        given()
            .filter(browser)
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("username", username)
                    .put("token", registerToken)
                    .put("attestation", authenticator.registration(registerChallenge))
                    .encode())
            .when()
            .post("/idp/api/auth/register");
    registered.then().statusCode(200).body("username", equalTo(username));
    String userId = registered.jsonPath().getString("userId");

    // A second browser, holding nothing — so the login below stands on the stored credential and
    // not on anything left over from the registration.
    CookieFilter secondVisit = new CookieFilter();
    String loginChallenge =
        given()
            .filter(secondVisit)
            .contentType(ContentType.JSON)
            .body("{\"username\":\"" + username + "\"}")
            .when()
            .post("/idp/api/auth/login-options")
            .then()
            .statusCode(200)
            .extract()
            .path("challenge");

    io.restassured.response.Response loggedIn =
        given()
            .filter(secondVisit)
            .contentType(ContentType.JSON)
            .body(
                new JsonObject()
                    .put("username", username)
                    .put("assertion", authenticator.assertion(loginChallenge))
                    .encode())
            .when()
            .post("/idp/api/auth/login");
    loggedIn.then().statusCode(200).body("userId", equalTo(userId));

    String session = sessionCookie(loggedIn);
    assertNotNull(session, "a login sets the cookie the edge introspects");

    given()
        .header("Authorization", basic("prod-qits-workspaces", SECRET))
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", session).encode())
        .when()
        .post("/idp/api/sessions/introspect")
        .then()
        .statusCode(200)
        .body("username", equalTo(username))
        .body("roles", hasItems("qits:admin"));

    given()
        .cookie("qits-session", session)
        .when()
        .post("/idp/api/auth/logout")
        .then()
        .statusCode(204);

    given()
        .header("Authorization", basic("prod-qits-workspaces", SECRET))
        .contentType(ContentType.JSON)
        .body(new JsonObject().put("token", session).encode())
        .when()
        .post("/idp/api/sessions/introspect")
        .then()
        .statusCode(404);
  }

  private static String sessionCookie(io.restassured.response.Response response) {
    return response.getHeaders().getValues("Set-Cookie").stream()
        .filter(line -> line.startsWith("qits-session="))
        .map(line -> line.substring("qits-session=".length(), line.indexOf(';')))
        .findFirst()
        .orElse(null);
  }

  private static String basic(String clientId, String secret) {
    return "Basic "
        + java.util.Base64.getEncoder()
            .encodeToString(
                (clientId + ":" + secret).getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  @Test
  public void anUnconfiguredClientStillCannotAuthenticate() {
    // Only prod-qits-workspaces was given a secret above. The other two ship without one and
    // must stay unusable in the packaged artifact too.
    given()
        .contentType(ContentType.URLENC)
        .body("grant_type=client_credentials&client_id=prod-qits-ci&client_secret=" + SECRET)
        .when()
        .post("/idp/token")
        .then()
        .statusCode(401)
        .body("error", equalTo("invalid_client"));
  }
}
