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
 *       and every service door takes HTTP Basic. An interaction may name a body template, whose
 *       {@code {param}} placeholders the state fills, and whether it sends the state's {@code
 *       authorization} param.
 *   <li><b>Opaque values.</b> A token, a secret or a key modulus is random by nature and nothing a
 *       state can seed. Each path in {@link Interaction#opaque} is replaced by {@value #OPAQUE} and
 *       listed in {@code frozen.strings}, so a consumer type-matches it.
 *   <li><b>Status-only doors are not recorded.</b> A {@code 204} has no body to record; a consumer
 *       binds only its status and still names the state.
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

  /**
   * One recorded interaction.
   *
   * @param listFilteredTo the array ({@code $} or a {@code $.a.b} path) reduced to the entries the
   *     state created, or null — the index's {@code frozen.listFilteredTo}
   * @param sortedBy for an array the provider answers in no guaranteed order: {@code
   *     <$.path-to-array>:<field.path in each entry>}; null when the order is the provider's own
   * @param contentType the request body's type, or null for no body
   * @param body the request body, {@code {param}} placeholders filled from the state, or null
   * @param authorized whether the request sends the state's {@code authorization} param
   * @param opaque paths ({@code $.a}, {@code $.a[*].b}) whose random values are recorded as {@value
   *     #OPAQUE}
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
      boolean authorized,
      List<String> opaque) {

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
          state, operationId, method, path, status, listFilteredTo, sortedBy, null, null, false,
          List.of());
    }
  }

  private static Interaction get(String state, String operationId, String path, int status) {
    return new Interaction(
        state, operationId, "GET", path, status, null, null, null, null, true, List.of());
  }

  private static Interaction list(String state, String operationId, String path) {
    return new Interaction(
        state, operationId, "GET", path, 200, "$", null, null, null, true, List.of());
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
        state, operationId, method, path, status, null, null, contentType, body, true,
        List.of(opaque));
  }

  static final String COMMISSION_BODY =
      "{\"contextKind\":\""
          + ProviderStates.CONTEXT_KIND
          + "\",\"contextId\":\""
          + ProviderStates.CONTEXT_ID
          + "\"}";

  static final String GIT_REFS_BODY = "{\"gitRefs\":[\"refs/heads/contract/run-1\"]}";

  static final List<Interaction> INTERACTIONS =
      List.of(
          // --- the OAuth/OIDC surface every service reads -------------------------------------
          send(
              ProviderStates.A_SERVICE_CLIENT_WITH_THE_SYSTEM_ROLE,
              "issueToken",
              "POST",
              "/idp/token",
              200,
              FORM,
              "grant_type=client_credentials",
              "$.access_token"),
          new Interaction(
              ProviderStates.THE_PUBLISHED_SIGNING_KEY,
              "getJwks",
              "GET",
              "/idp/jwks",
              200,
              "$.keys",
              null,
              null,
              null,
              false,
              List.of("$.keys[*].n")),
          new Interaction(
              ProviderStates.THE_PUBLISHED_SIGNING_KEY,
              "getOpenIdConfiguration",
              "GET",
              "/idp/.well-known/openid-configuration",
              200,
              null,
              null,
              null,
              null,
              false,
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
              "introspectCommissionedToken",
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
          list(ProviderStates.A_COMMISSIONED_CLIENT, "listCommissionedClients", "/idp/api/clients"),
          send(
              ProviderStates.A_COMMISSIONED_CLIENT,
              "replaceCommissionedClientGitRefs",
              "PUT",
              "/idp/api/clients/{clientId}/git-refs",
              200,
              JSON_TYPE,
              GIT_REFS_BODY),
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
          list(ProviderStates.A_COMMISSIONED_TOKEN, "listCommissionedTokens", "/idp/api/tokens"),
          send(
              ProviderStates.A_COMMISSIONED_TOKEN,
              "replaceCommissionedTokenGitRefs",
              "PUT",
              "/idp/api/tokens/{tokenId}/git-refs",
              200,
              JSON_TYPE,
              GIT_REFS_BODY),
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
              "rotateServiceClientSecret",
              "POST",
              "/idp/api/service-clients/{clientId}/secret",
              200,
              null,
              null,
              "$.secret"),
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

    for (Interaction interaction : INTERACTIONS) {
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
      operation.put("path", interaction.path());
      operation.put("status", interaction.status());
      operation.put("file", file);
      ObjectNode frozen = operation.putObject("frozen");
      frozen.set("ids", strings(recorded.freezer().idPaths()));
      frozen.set("instants", strings(recorded.freezer().instantPaths()));
      Set<String> stringPaths = new LinkedHashSet<>(recorded.freezer().stringPaths());
      stringPaths.addAll(interaction.opaque());
      frozen.set("strings", strings(List.copyOf(stringPaths)));
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

      written.add(file);
      check(dir.resolve(file), GoldenJson.render(recorded.body()), update, failures);
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

  /** One interaction's frozen answer, its frozen params and what was frozen where. */
  record Recorded(JsonNode body, ObjectNode params, Freezer freezer) {}

  private Recorded record(Interaction interaction) throws IOException {
    ProviderStates.Setup setup = states.setUp(interaction.state());
    Map<String, String> params = setup.params();

    RequestSpecification request = given();
    if (interaction.authorized()) {
      request.header("Authorization", params.get("authorization"));
    }
    if (interaction.contentType() != null) {
      request.contentType(interaction.contentType()).body(expand(interaction.body(), params));
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
    JsonNode body = JSON.readTree(raw);
    body = recordable(body, interaction, setup.created(), setup.uniqueTokens());

    Freezer freezer = new Freezer().seed(params.values()).uniqueTokens(setup.uniqueTokens());
    JsonNode frozenBody = freezer.freeze(body);
    ObjectNode frozenParams = JsonNodeFactory.instance.objectNode();
    params.forEach((k, v) -> frozenParams.put(k, freezer.freezeParam(v)));
    return new Recorded(frozenBody, frozenParams, freezer);
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
    if (interaction.sortedBy() != null) {
      String[] parts = interaction.sortedBy().split(":", 2);
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
      blank(out, path);
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
