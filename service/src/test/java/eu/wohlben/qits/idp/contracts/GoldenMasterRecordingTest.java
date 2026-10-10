package eu.wohlben.qits.idp.contracts;

import static io.restassured.RestAssured.given;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * <b>Records qits-idp's provider golden masters</b> — {@code golden-masters/} at the repository
 * root, the source of the published golden-master artifact consumers write their pacts against.
 * The same machinery as qits-githost-service's, with three additions an identity provider needs:
 *
 * <ul>
 *   <li><b>A request.</b> Most doors here take a body (a form for {@code /token}, JSON elsewhere)
 *       and every service door takes HTTP Basic. The index records each operation's request: the
 *       route as {@code path} and its query apart as {@code query}, the request {@code headers},
 *       and for an operation that takes a body its {@code contentType} and {@code body} (a JSON
 *       value, or a form as its string). Header and body values keep their {@code {param}}
 *       placeholders, filled from the state's params. An operation that takes no body records
 *       none; the recording fails when that disagrees with the served openapi.
 *   <li><b>Opaque values.</b> A token, a secret or a key modulus is random by nature and nothing a
 *       state can seed. Each path in {@link Interaction#opaque} is replaced by {@value #OPAQUE} and
 *       listed in {@code frozen.strings}, so a consumer type-matches it.
 *   <li><b>Answers without a body.</b> A {@code 204} or a redirect records {@code file: null}; a
 *       redirect records the headers a consumer reads as {@code responseHeaders}, and those holding
 *       a frozen or opaque part in {@code frozen.headers}.
 * </ul>
 *
 * <p>For each (state, operation) pair in {@link #INTERACTIONS} it runs the state ({@link
 * ProviderStates}), calls the endpoint through REST-assured, keeps only the list entries the state
 * created, freezes ids, instants and unique tokens ({@link Freezer}) and renders {@code
 * golden-masters/<state-slug>/<operationId>.json}; then it renders {@code golden-masters/index.json}.
 *
 * <p>It <b>compares by default</b> and fails with a unified diff per differing file — including a
 * committed {@code .json} no interaction produces any more. {@code -Dgolden.update=true} (or {@code
 * QITS_GOLDEN_UPDATE=true}) rewrites instead, and deletes such stale files; see {@link
 * GoldenFiles}.
 */
@QuarkusTest
class GoldenMasterRecordingTest {

  static final int FORMAT_VERSION = 1;
  static final String PROVIDER = "qits-idp";

  /** What an opaque value is recorded as. */
  static final String OPAQUE = "opaque";

  private static final String FORM = "application/x-www-form-urlencoded";
  private static final String JSON_TYPE = "application/json";

  /** The Basic header of the state's caller, as most service doors take it. */
  private static final Map<String, String> BASIC = Map.of("Authorization", "{authorization}");

  /** The browser's session cookie, as {@code /authorize} reads it. */
  private static final Map<String, String> SESSION_COOKIE =
      Map.of("Cookie", "qits-session={sessionToken}");

  /**
   * One recorded interaction.
   *
   * @param path the route, with {@code {param}} placeholders, and an optional {@code ?query}; the
   *     index records the two apart
   * @param listFilteredTo the array ({@code $} or a {@code $.a.b} path) reduced to the entries the
   *     state created, or null — the index's {@code frozen.listFilteredTo}
   * @param sortedBy for arrays the provider answers in no guaranteed order: {@code
   *     <$.path-to-array>:<field.path in each entry>}, several joined by {@code ;}; null when the
   *     order is the provider's own
   * @param contentType the request body's type, or null for no body
   * @param body the request body, {@code {param}} placeholders filled from the state (form values
   *     URL-encoded), or null; recorded unexpanded into the index
   * @param headers request headers, values with {@code {param}} placeholders; recorded unexpanded
   * @param opaque paths ({@code $.a}, {@code $.a[*].b}) whose random values are recorded as {@value
   *     #OPAQUE}; {@code <Header>?<name>} blanks one query parameter of a response header
   * @param responseHeaders the response headers a consumer reads, recorded into the index
   */
  record Interaction(
      String state,
      String operationId,
      String method,
      String path,
      int status,
      String listFilteredTo,
      String sortedBy,
      String contentType,
      String body,
      Map<String, String> headers,
      List<String> opaque,
      List<String> responseHeaders) {

    /** A bodyless, unauthenticated interaction — the shape the machinery test builds. */
    Interaction(
        String state,
        String operationId,
        String method,
        String path,
        int status,
        String listFilteredTo,
        String sortedBy) {
      this(
          state,
          operationId,
          method,
          path,
          status,
          listFilteredTo,
          sortedBy,
          null,
          null,
          Map.of(),
          List.of(),
          List.of());
    }

    /** Whether the answer has a body to record: not for a 204 and not for a redirect. */
    boolean recordsBody() {
      return status != 204 && status / 100 != 3;
    }
  }

  private static Interaction get(String state, String operationId, String path, int status) {
    return new Interaction(
        state, operationId, "GET", path, status, null, null, null, null, BASIC, List.of(),
        List.of());
  }

  private static Interaction list(String state, String operationId, String path) {
    return new Interaction(
        state, operationId, "GET", path, 200, "$", null, null, null, BASIC, List.of(), List.of());
  }

  private static Interaction delete(String state, String operationId, String path) {
    return new Interaction(
        state, operationId, "DELETE", path, 204, null, null, null, null, BASIC, List.of(),
        List.of());
  }

  private static Interaction send(
      String state,
      String operationId,
      String method,
      String path,
      int status,
      String contentType,
      String body,
      String... opaque) {
    return new Interaction(
        state, operationId, method, path, status, null, null, contentType, body, BASIC,
        List.of(opaque), List.of());
  }

  /** {@code POST /idp/token}: a form, with the caller's Basic header or without any header. */
  private static Interaction token(
      String state, int status, boolean basic, String form, String... opaque) {
    return new Interaction(
        state, "issueToken", "POST", "/idp/token", status, null, null, FORM, form,
        basic ? BASIC : Map.of(), List.of(opaque), List.of());
  }

  static final String COMMISSION_BODY =
      "{\"contextKind\":\""
          + ProviderStates.CONTEXT_KIND
          + "\",\"contextId\":\""
          + ProviderStates.CONTEXT_ID
          + "\"}";

  static final String GIT_REFS_BODY = "{\"gitRefs\":[\"refs/heads/contract/run-1\"]}";

  static final String CLIENT_CREDENTIALS_IN_THE_FORM =
      "grant_type=client_credentials&client_id={clientId}&client_secret={clientSecret}"
          + "&audience={audience}";

  static final String AUTHORIZATION_CODE_FORM =
      "grant_type=authorization_code&client_id={clientId}&code={code}"
          + "&redirect_uri={redirectUri}&code_verifier={codeVerifier}";

  static final String REFRESH_FORM =
      "grant_type=refresh_token&client_id={clientId}&refresh_token={refreshToken}";

  static final String AUTHORIZE_PATH =
      "/idp/authorize?response_type=code&client_id=qits-cli&redirect_uri="
          + URLEncoder.encode(ProviderStates.REDIRECT_URI, StandardCharsets.UTF_8)
          + "&code_challenge="
          + ProviderStates.CODE_CHALLENGE
          + "&code_challenge_method=S256&state=contract";

  static final List<Interaction> INTERACTIONS =
      List.of(
          // --- the token endpoint: every grant, every way a client authenticates --------------
          token(
              ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE,
              200,
              true,
              "grant_type=client_credentials",
              "$.access_token"),
          token(
              ProviderStates.A_COMMISSIONED_CLIENT,
              200,
              false,
              CLIENT_CREDENTIALS_IN_THE_FORM,
              "$.access_token"),
          token(
              ProviderStates.NO_COMMISSIONED_CLIENT_WITH_THE_GIVEN_ID,
              401,
              false,
              CLIENT_CREDENTIALS_IN_THE_FORM),
          token(
              ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_CLI,
              200,
              false,
              AUTHORIZATION_CODE_FORM,
              "$.access_token",
              "$.refresh_token"),
          token(
              ProviderStates.AN_AUTHORIZATION_CODE_ISSUED_TO_THE_GIT_CLIENT,
              200,
              false,
              AUTHORIZATION_CODE_FORM,
              "$.access_token",
              "$.refresh_token"),
          token(
              ProviderStates.A_SESSION_TO_REFRESH,
              200,
              false,
              REFRESH_FORM,
              "$.access_token",
              "$.refresh_token"),
          token(
              ProviderStates.A_GIT_SESSION_TO_REFRESH,
              200,
              false,
              REFRESH_FORM + "&audience={audience}",
              "$.access_token",
              "$.refresh_token"),
          // --- the browser's half of the code grant -------------------------------------------
          new Interaction(
              ProviderStates.A_SIGNED_IN_PERSON,
              "authorize",
              "GET",
              AUTHORIZE_PATH,
              303,
              null,
              null,
              null,
              null,
              SESSION_COOKIE,
              List.of("Location?code"),
              List.of("Location")),
          // --- the documents every service reads ----------------------------------------------
          new Interaction(
              ProviderStates.A_PUBLISHED_SIGNING_KEY,
              "getJwks",
              "GET",
              "/idp/jwks",
              200,
              "$.keys",
              null,
              null,
              null,
              Map.of(),
              List.of(),
              List.of()),
          new Interaction(
              ProviderStates.A_PUBLISHED_SIGNING_KEY,
              "getOpenIdConfiguration",
              "GET",
              "/idp/.well-known/openid-configuration",
              200,
              null,
              null,
              null,
              null,
              Map.of(),
              List.of(),
              List.of()),
          // --- introspection: the edge and qits-projects ------------------------------------
          send(
              ProviderStates.A_SIGNED_IN_PERSON,
              "introspectSession",
              "POST",
              "/idp/api/sessions/introspect",
              200,
              JSON_TYPE,
              "{\"token\":\"{sessionToken}\"}"),
          send(
              ProviderStates.A_COMMISSIONED_TOKEN,
              "introspectToken",
              "POST",
              "/idp/api/tokens/introspect",
              200,
              JSON_TYPE,
              "{\"token\":\"{token}\"}",
              "$.accessToken"),
          // --- commissioned clients ----------------------------------------------------------
          send(
              ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE,
              "commissionClient",
              "POST",
              "/idp/api/clients",
              201,
              JSON_TYPE,
              COMMISSION_BODY,
              "$.clientId",
              "$.secret"),
          list(ProviderStates.A_COMMISSIONED_CLIENT, "listClients", "/idp/api/clients"),
          send(
              ProviderStates.A_COMMISSIONED_CLIENT,
              "replaceClientGitRefs",
              "PUT",
              "/idp/api/clients/{clientId}/git-refs",
              200,
              JSON_TYPE,
              GIT_REFS_BODY),
          delete(
              ProviderStates.A_COMMISSIONED_CLIENT,
              "decommissionClient",
              "/idp/api/clients/{clientId}"),
          // --- commissioned tokens -----------------------------------------------------------
          send(
              ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE,
              "commissionToken",
              "POST",
              "/idp/api/tokens",
              201,
              JSON_TYPE,
              COMMISSION_BODY,
              "$.token",
              "$.subject"),
          list(ProviderStates.A_COMMISSIONED_TOKEN, "listTokens", "/idp/api/tokens"),
          send(
              ProviderStates.A_COMMISSIONED_TOKEN,
              "replaceTokenGitRefs",
              "PUT",
              "/idp/api/tokens/{tokenId}/git-refs",
              200,
              JSON_TYPE,
              GIT_REFS_BODY),
          delete(ProviderStates.A_COMMISSIONED_TOKEN, "deleteToken", "/idp/api/tokens/{tokenId}"),
          // --- service clients ---------------------------------------------------------------
          send(
              ProviderStates.NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID,
              "createServiceClient",
              "POST",
              "/idp/api/service-clients",
              201,
              JSON_TYPE,
              "{\"clientId\":\"{clientId}\"}",
              "$.secret"),
          get(
              ProviderStates.NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID,
              "getServiceClient",
              "/idp/api/service-clients/{clientId}",
              404),
          send(
              ProviderStates.NO_SERVICE_CLIENT_WITH_THE_GIVEN_ID,
              "rotateServiceClientSecret",
              "POST",
              "/idp/api/service-clients/{clientId}/secret",
              404,
              null,
              null),
          get(
              ProviderStates.A_DATABASE_SERVICE_CLIENT,
              "getServiceClient",
              "/idp/api/service-clients/{clientId}",
              200),
          list(
              ProviderStates.A_DATABASE_SERVICE_CLIENT,
              "listServiceClients",
              "/idp/api/service-clients"),
          send(
              ProviderStates.A_DATABASE_SERVICE_CLIENT,
              "createServiceClient",
              "POST",
              "/idp/api/service-clients",
              409,
              JSON_TYPE,
              "{\"clientId\":\"{clientId}\"}"),
          send(
              ProviderStates.A_DATABASE_SERVICE_CLIENT,
              "rotateServiceClientSecret",
              "POST",
              "/idp/api/service-clients/{clientId}/secret",
              200,
              null,
              null,
              "$.secret"),
          delete(
              ProviderStates.A_DATABASE_SERVICE_CLIENT,
              "deleteServiceClient",
              "/idp/api/service-clients/{clientId}"),
          // --- the orchestrator's collection --------------------------------------------------
          new Interaction(
              ProviderStates.A_SERVICE_CLIENT_NOTHING_CLAIMS,
              "collectServiceClients",
              "POST",
              "/idp/api/gc/service-clients",
              200,
              null,
              "$.removed:clientId;$.kept:clientId",
              JSON_TYPE,
              "{\"dryRun\":false,\"claims\":[{\"clientId\":\"{claimedClientId}\","
                  + "\"applicationName\":\"contract\"}]}",
              BASIC,
              List.of(),
              List.of()),
          // --- register tokens: the bootstrap CLI --------------------------------------------
          send(
              ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE,
              "mintRegisterToken",
              "POST",
              "/idp/api/register-tokens",
              201,
              null,
              null,
              "$.token"));

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Pattern TEMPLATE_PARAM = Pattern.compile("\\{([A-Za-z][A-Za-z0-9]*)}");

  @Inject ProviderStates states;

  @Test
  void goldenMastersMatchTheProvider() throws IOException {
    Path dir = GoldenFiles.repositoryRoot().resolve("golden-masters");
    boolean update = GoldenFiles.updating();
    List<String> failures = new ArrayList<>();
    Set<String> written = new TreeSet<>();

    // slug -> recorded state, sorted by slug; operations sorted by operationId below
    Map<String, ObjectNode> indexStates = new TreeMap<>();
    Map<String, Map<String, ObjectNode>> indexOperations = new TreeMap<>();

    Set<String> takesBody = operationsTakingABody();
    for (Interaction interaction : INTERACTIONS) {
      if ((interaction.body() != null) != takesBody.contains(interaction.operationId())) {
        failures.add(
            interaction.operationId()
                + (interaction.body() != null
                    ? " takes no request body, but the recording sends one: record null."
                    : " takes a request body, but the recording sends none."));
      }
      Recorded recorded = record(interaction);
      String slug = ProviderStates.slug(interaction.state());
      String file = slug + "/" + interaction.operationId() + ".json";

      ObjectNode state = indexStates.get(slug);
      if (state == null) {
        state = JsonNodeFactory.instance.objectNode();
        state.put("name", interaction.state());
        state.put("slug", slug);
        state.set("params", recorded.params());
        state.set("dependsOn", JsonNodeFactory.instance.arrayNode());
        indexStates.put(slug, state);
      } else if (!state.get("params").equals(recorded.params())) {
        failures.add("State '" + interaction.state() + "' froze to different params per operation");
      }

      ObjectNode operation = JsonNodeFactory.instance.objectNode();
      operation.put("operationId", interaction.operationId());
      operation.put("method", interaction.method());
      // The path is the route alone and the query its own object, as the consumers' pacts send it.
      int at = interaction.path().indexOf('?');
      operation.put("path", at < 0 ? interaction.path() : interaction.path().substring(0, at));
      if (at >= 0) {
        operation.set("query", query(interaction.path().substring(at + 1)));
      }
      if (!interaction.headers().isEmpty()) {
        ObjectNode headers = operation.putObject("headers");
        new TreeMap<>(interaction.headers()).forEach(headers::put);
      }
      if (interaction.body() != null) {
        operation.put("contentType", interaction.contentType());
        if (FORM.equals(interaction.contentType())) {
          operation.put("body", interaction.body());
        } else {
          operation.set("body", JSON.readTree(interaction.body()));
        }
      }
      operation.put("status", interaction.status());
      if (!recorded.responseHeaders().isEmpty()) {
        ObjectNode headers = operation.putObject("responseHeaders");
        recorded.responseHeaders().forEach(headers::put);
      }
      if (interaction.recordsBody()) {
        operation.put("file", file);
      } else {
        operation.putNull("file");
      }
      ObjectNode frozen = operation.putObject("frozen");
      frozen.set("ids", strings(recorded.freezer().idPaths()));
      frozen.set("instants", strings(recorded.freezer().instantPaths()));
      Set<String> stringPaths = new LinkedHashSet<>(recorded.freezer().stringPaths());
      for (String path : interaction.opaque()) {
        if (path.startsWith("$")) {
          stringPaths.add(path);
        }
      }
      frozen.set("strings", strings(List.copyOf(stringPaths)));
      if (!recorded.frozenHeaders().isEmpty()) {
        frozen.set("headers", strings(recorded.frozenHeaders()));
      }
      if (interaction.listFilteredTo() == null) {
        frozen.putNull("listFilteredTo");
      } else {
        frozen.put("listFilteredTo", interaction.listFilteredTo());
      }
      if (indexOperations
              .computeIfAbsent(slug, k -> new TreeMap<>())
              .put(interaction.operationId(), operation)
          != null) {
        failures.add("Duplicate interaction " + file);
      }

      if (interaction.recordsBody()) {
        written.add(file);
        check(dir.resolve(file), GoldenJson.render(recorded.body()), update, failures);
      }
    }

    ObjectNode index = JsonNodeFactory.instance.objectNode();
    index.put("formatVersion", FORMAT_VERSION);
    index.put("provider", PROVIDER);
    ArrayNode stateArray = index.putArray("states");
    indexStates.forEach(
        (slug, state) -> {
          ArrayNode operations = state.putArray("operations");
          indexOperations.get(slug).values().forEach(operations::add);
          stateArray.add(state);
        });
    written.add("index.json");
    check(dir.resolve("index.json"), GoldenJson.render(index), update, failures);

    for (String stale : committedJson(dir)) {
      if (written.contains(stale)) {
        continue;
      }
      if (update) {
        Files.delete(dir.resolve(stale));
      } else {
        failures.add(
            dir.resolve(stale)
                + " is committed but no interaction records it any more — rerun with"
                + " -Dgolden.update=true to delete it.");
      }
    }

    if (!failures.isEmpty()) {
      throw new AssertionError(String.join("\n\n", failures));
    }
  }

  private static void check(Path golden, String actual, boolean update, List<String> failures) {
    String failure = GoldenFiles.check(golden, actual, update, UnaryOperator.identity());
    if (failure != null) {
      failures.add(failure);
    }
  }

  /**
   * One interaction's frozen answer (null when it records no body), its frozen params, what was
   * frozen where, the response headers it records and which of those were frozen.
   */
  record Recorded(
      JsonNode body,
      ObjectNode params,
      Freezer freezer,
      Map<String, String> responseHeaders,
      List<String> frozenHeaders) {}

  private Recorded record(Interaction interaction) throws IOException {
    ProviderStates.Setup setup = states.setUp(interaction.state());
    Map<String, String> params = setup.params();

    RequestSpecification request = given().redirects().follow(false);
    if (interaction.path().contains("?")) {
      // The query is written encoded already; RestAssured would encode its % signs a second time.
      request.urlEncodingEnabled(false);
    }
    interaction.headers().forEach((name, value) -> request.header(name, expand(value, params)));
    if (interaction.contentType() != null) {
      boolean form = FORM.equals(interaction.contentType());
      request
          .contentType(interaction.contentType())
          .body(form ? expandForm(interaction.body(), params) : expand(interaction.body(), params));
    } else {
      // As a client sends a body-less call: RestAssured would otherwise add a form content type.
      request.noContentType();
    }
    Response response =
        request.when().request(interaction.method(), expand(interaction.path(), params));
    String raw = response.asString();
    if (response.statusCode() != interaction.status()) {
      throw new AssertionError(
          interaction.method()
              + " "
              + interaction.path()
              + " in state '"
              + interaction.state()
              + "' answered "
              + response.statusCode()
              + ", expected "
              + interaction.status()
              + ": "
              + raw);
    }

    Freezer freezer = new Freezer().seed(params.values()).uniqueTokens(setup.uniqueTokens());
    // The params first, so a unique token is numbered the same whatever an operation answers.
    ObjectNode frozenParams = JsonNodeFactory.instance.objectNode();
    params.forEach((k, v) -> frozenParams.put(k, freezer.freezeParam(v)));
    JsonNode frozenBody = null;
    if (interaction.recordsBody()) {
      JsonNode body = recordable(JSON.readTree(raw), interaction, setup.created(), setup.uniqueTokens());
      frozenBody = freezer.freeze(body);
    }
    Map<String, String> headers = new TreeMap<>();
    List<String> frozenHeaders = new ArrayList<>();
    for (String name : interaction.responseHeaders()) {
      String value = response.header(name);
      if (value == null) {
        throw new AssertionError(interaction.operationId() + " answered no " + name + " header");
      }
      String recorded = value;
      for (String opaque : interaction.opaque()) {
        if (opaque.startsWith(name + "?")) {
          recorded = blankQueryParam(recorded, opaque.substring(name.length() + 1));
        }
      }
      recorded = freezer.freezeParam(recorded);
      if (!recorded.equals(value)) {
        frozenHeaders.add(name);
      }
      headers.put(name, recorded);
    }
    return new Recorded(frozenBody, frozenParams, freezer, headers, frozenHeaders);
  }

  /** The url with one query parameter's value set to {@value #OPAQUE}; fails when it is absent. */
  static String blankQueryParam(String url, String name) {
    Matcher m = Pattern.compile("([?&]" + Pattern.quote(name) + "=)[^&#]*").matcher(url);
    if (!m.find()) {
      throw new IllegalStateException("No query parameter " + name + " in " + url);
    }
    return m.replaceFirst("$1" + OPAQUE);
  }

  /**
   * The answer reduced to what the state controls: the {@code listFilteredTo} array keeps only the
   * entries mentioning a value the state created, a {@code sortedBy} array is put in seed order,
   * and every {@code opaque} path holds {@value #OPAQUE}. Package-private for the machinery test.
   */
  static JsonNode recordable(
      JsonNode body,
      Interaction interaction,
      Collection<String> createdIds,
      Collection<String> uniqueTokens) {
    JsonNode out = body.deepCopy();
    if (interaction.listFilteredTo() != null) {
      ArrayNode list = array(out, interaction.listFilteredTo());
      ArrayNode kept = JsonNodeFactory.instance.arrayNode();
      for (JsonNode entry : list) {
        String text = entry.toString();
        if (createdIds.stream().anyMatch(text::contains)) {
          kept.add(entry);
        }
      }
      list.removeAll();
      list.addAll(kept);
    }
    for (String sortedBy :
        interaction.sortedBy() == null ? new String[0] : interaction.sortedBy().split(";")) {
      String[] parts = sortedBy.split(":", 2);
      ArrayNode list = array(out, parts[0]);
      List<JsonNode> entries = new ArrayList<>();
      list.forEach(entries::add);
      String[] field = parts[1].split("\\.");
      entries.sort(
          Comparator.comparing(
              entry -> {
                JsonNode node = entry;
                for (String f : field) {
                  node = node.path(f);
                }
                String key = node.asText();
                for (String token : uniqueTokens) {
                  key = key.replace(token, "");
                }
                return key;
              }));
      list.removeAll();
      list.addAll(entries);
    }
    for (String path : interaction.opaque()) {
      if (path.startsWith("$")) {
        blank(out, path);
      }
    }
    return out;
  }

  /**
   * Sets every string at {@code path} ({@code $.a.b}, a segment may end in {@code [*]}) to {@value
   * #OPAQUE}. A path that matches nothing fails: an opaque list that names a field the answer lost
   * would otherwise hide the loss.
   */
  static void blank(JsonNode root, String path) {
    if (!path.startsWith("$.")) {
      throw new IllegalArgumentException("Only $.a.b paths are supported: " + path);
    }
    List<JsonNode> parents = List.of(root);
    String[] segments = path.substring(2).split("\\.");
    for (int i = 0; i < segments.length; i++) {
      boolean each = segments[i].endsWith("[*]");
      String name = each ? segments[i].substring(0, segments[i].length() - 3) : segments[i];
      boolean last = i == segments.length - 1;
      List<JsonNode> next = new ArrayList<>();
      for (JsonNode parent : parents) {
        if (last && !each) {
          if (parent.path(name).isTextual()) {
            ((ObjectNode) parent).set(name, TextNode.valueOf(OPAQUE));
            next.add(parent);
          }
          continue;
        }
        JsonNode child = parent.path(name);
        if (each) {
          child.forEach(next::add);
        } else if (!child.isMissingNode()) {
          next.add(child);
        }
      }
      parents = next;
    }
    if (parents.isEmpty()) {
      throw new IllegalStateException("The opaque path " + path + " matches nothing in " + root);
    }
  }

  /** The array at {@code $} or a {@code $.a.b} path — the only JSONPath shapes the table uses. */
  private static ArrayNode array(JsonNode root, String path) {
    JsonNode node = root;
    if (!"$".equals(path)) {
      if (!path.startsWith("$.")) {
        throw new IllegalArgumentException("Only $ and $.a.b paths are supported: " + path);
      }
      for (String segment : path.substring(2).split("\\.")) {
        node = node.path(segment);
      }
    }
    if (!node.isArray()) {
      throw new IllegalStateException(path + " is not an array in " + root);
    }
    return (ArrayNode) node;
  }

  private static String expand(String template, Map<String, String> params) {
    Matcher m = TEMPLATE_PARAM.matcher(template);
    StringBuilder out = new StringBuilder();
    while (m.find()) {
      String value = params.get(m.group(1));
      if (value == null) {
        throw new IllegalStateException(
            template + " names {" + m.group(1) + "}, which the state does not return");
      }
      m.appendReplacement(out, Matcher.quoteReplacement(value));
    }
    m.appendTail(out);
    return out.toString();
  }

  /** A form body with each {@code {param}} replaced by its URL-encoded value. */
  private static String expandForm(String template, Map<String, String> params) {
    Map<String, String> encoded = new TreeMap<>();
    params.forEach((k, v) -> encoded.put(k, URLEncoder.encode(v, StandardCharsets.UTF_8)));
    return expand(template, encoded);
  }

  /** A query string as an object, names and values decoded. */
  private static ObjectNode query(String raw) {
    ObjectNode query = JsonNodeFactory.instance.objectNode();
    for (String pair : raw.split("&")) {
      int eq = pair.indexOf('=');
      query.put(
          URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8),
          eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
    }
    return query;
  }

  /** The operationIds whose operation declares a request body, read off the served openapi. */
  private static Set<String> operationsTakingABody() throws IOException {
    JsonNode paths =
        JSON.readTree(
                given()
                    .when()
                    .get("/idp/q/openapi?format=json")
                    .then()
                    .statusCode(200)
                    .extract()
                    .asString())
            .path("paths");
    Set<String> ids = new TreeSet<>();
    paths.forEach(
        path ->
            path.forEach(
                operation -> {
                  if (operation.has("operationId") && operation.has("requestBody")) {
                    ids.add(operation.get("operationId").asText());
                  }
                }));
    return ids;
  }

  private static ArrayNode strings(List<String> values) {
    ArrayNode out = JsonNodeFactory.instance.arrayNode();
    values.forEach(out::add);
    return out;
  }

  /** Every committed {@code .json} under the directory, relative and {@code /}-separated. */
  private static List<String> committedJson(Path dir) throws IOException {
    if (!Files.isDirectory(dir)) {
      return List.of();
    }
    try (Stream<Path> files = Files.walk(dir)) {
      return files
          .filter(Files::isRegularFile)
          .filter(p -> p.getFileName().toString().endsWith(".json"))
          .map(p -> dir.relativize(p).toString().replace('\\', '/'))
          .sorted()
          .toList();
    }
  }
}
