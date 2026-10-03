# qits-idp-platform-service — working notes

Read `README.md` first: it defines the surface, the token's shape, and where clients and keys come
from. This file is the working conventions on top of it.

## The rules that shape everything

**A clone of this repo alone builds and tests green** — no monorepo, no docker, no prior
`mvn install` elsewhere, no credentials. `./mvnw verify` is the gate, and it needs no port
argument — `service/src/test/resources/application.properties` sets `quarkus.http.test-port=0`.

**Clone-alone now means clone *and* `git submodule update --init`, plus a node on `PATH`.** This
service serves a client: `qits-idp-platform-frontend` at `service/src/main/webui`, built by Quinoa
during `package` and served at `/idp/`. `verify` runs `package`, so both are required — an uninitialised
submodule is an empty directory and stops the build at "No package.json found in Web UI directory".
`./mvnw test` needs neither, because Quinoa is disabled in test mode, which is also why nothing
about the client can be proven by a `@QuarkusTest` (see `IdpPackagedSurfaceIT`).

**The one thing it now needs besides Maven Central** is the platform's own Maven repository, for
`qits-db-core` and `qits-arch-rules` — the patient driver every connection opens through, and the
test that refuses to let the datasource baseline go missing. `<repositories>` in the root pom points
at `${qits.maven.repository.url}` (`https://registry.qits.wohlben.eu/artifacts/maven/maven` by
default), which answers 401 without the commissioned client; `.qits-maven-settings.xml` mirrors the
`qits-maven` repository id onto it — an exact id match, which is what gets past Maven's
`external:http:*` blocker without permitting arbitrary HTTP repositories. `docker/Dockerfile` derives
both that address and Central's from the one `QITS_DOMAIN` build-arg the CI recipe passes
(`registry.qits.$QITS_DOMAIN`, `mirror.qits.$QITS_DOMAIN`). Those three files move together; a third
platform jar needs none of them again.

**The baseline is not a formality here.** Every other service asks this one for a token, so a
postgres cutover that fails this pool fails the platform's whole call graph rather than one
application. `DatasourceBaselineTest` is three lines and fails the build naming any postgresql
datasource missing one of the three; the doctrine and the measurements are in the superproject's
`docs/project-setup-quinoa-angular.md`.

**Issuing a token for a SERVICE client does not read postgres, and that has to stay true.**
`SigningKeys.signing()` and `published()` take a volatile cache, and a service client is a read of
the volatile map `ServiceClients` loads at start. A commissioned client is a row, so `DynamicClients` caches a resolved one and only a miss
reaches the store — the map is bounded by live contexts, `decommission` evicts in the same call
that deletes, and misses are never cached, which is what makes both directions immediate. **One idp
process is assumed** (which is what this service is deployed as); a second instance would hold its
own copy of a row deleted at the first, and that is the day this needs a bounded entry age rather
than a bigger cache.

**Every seam that touches the store carries a `DbRetry`, and the rule is one boundary per use
case.** `SigningKeys.reload()` — the boot load and a rotation — plus `DynamicClients`' reads and
writes, plus `Users`, `RegisterTokens`, `Sessions` and `Registrations`. The writes use
`DbRetry.inNewTx`/`runInNewTx` rather than `DbRetry.call`: a commission is a bare insert, so the
retry has to own the transaction boundary to know which failures certainly did not commit, and a
lost commit acknowledgement must be reported rather than repeated — repeating it would leave a
second credential in the store that no owner ever heard of.

**The user-side classes add one shape worth knowing.** Each of `Users`, `RegisterTokens` and
`Sessions` owns its transaction in its public methods, and each also has package-private `…Row`
methods doing the same work *inside the caller's* transaction. That exists for exactly one caller:
`Registrations`, which puts a single boundary around the five writes a registration is — the
account, its factor, the token's consumption, the two roles, the session. A token spent against an
account that was never created leaves an installation with no way in and a one-time ticket gone, so
"all or none" here is not tidiness. Do not add a second composite operation without deciding which
of the two sets it uses; mixing them nests transactions.

The signing-key seam's shape is the part with the subtlety: the `synchronized` moved off `reload` and onto the private
`loadOnce`, so the retry sits **outside** the monitor and an attempt takes the lock and releases it
before the pause. A retry inside a monitor sleeps while holding it, which is why the placement rules
forbid it; the guard the lock exists for — two cold callers must not both generate a key — is
unchanged, because one load still commits before the next begins. What is no longer serialized is
the cache assignment, and two concurrent reloads writing complete key sets in either order is not a
disagreement worth a lock. `SigningKeyCutoverTest` is the proof.

**And it stays `DbRetry.call`, not `DbRetry.inNewTx`** — considered on 2026-08-11 and refused, so
that the question is not reopened by the write inside it. `inNewTx` owns the transaction boundary,
which here would have to sit either outside the monitor (a thread blocked on the lock would then be
holding an open transaction and its connection) or inside it (the pause back in the monitor, the
exact thing the paragraph above moved out). Both are worse shapes, and the safety they would buy is
already here: this write is generate-**or**-load, so a second attempt re-reads first and a key that
did commit is found rather than duplicated, and the ambiguous case `inNewTx` exists to refuse — a
failure the transaction manager reports — carries no connection marker for `DbRetry.call` to match,
so it is rethrown either way. A write without that re-read would need `inNewTx`; this one does not.

The store being PostgreSQL does not change that answer. `testdb/EmbeddedPg` starts **zonky's**
postgres — real binaries resolved as ordinary Maven artifacts, spawned as a child process — and
`testdb/EmbeddedPgConfigSource` hands its url, username and password to every `@QuarkusTest` at an
ordinal above `application.properties`, because the port is chosen at run time and cannot be written
down. Testcontainers is not on this classpath and must not arrive, and
`quarkus.devservices.enabled=false` says the same thing from the other side.

**`service/` compiles to a GraalVM native image.** `.sdkmanrc` names `25.0.2-graalce`. The
consequence to keep in your head here is narrower than in the siblings and more dangerous: this
service's whole job goes through JCA — `KeyPairGenerator`, `KeyFactory`, RS256 signing — and a
native image that lost a provider boots fine and cannot mint. `IdpPackagedSurfaceIT` mints a token
in the packaged process for exactly that reason; run it (`-DskipITs=false`, or `-Dnative`) after
touching anything about keys, secrets, or a JSON body.

**Two native traps this repo has already fallen into, both on 2026-08-14, both caught by `-Dnative`
and by nothing else:**

- **A `SecureRandom` in a static field** is instantiated during image generation and lands in the
  image heap with its seed baked in — every deployment of that binary would produce the same ids and
  secrets. GraalVM refuses to build it outright. Construct one per call — which is what
  `RandomSecret` does, and it is where every credential value (a commissioned secret, a register
  token, a session cookie) now comes from.
- **A resource method returning `jakarta.ws.rs.core.Response`** carries its entity as an `Object`,
  so the image builder has no type to register and the binary answers **500, "no properties
  discovered"**, while the JVM suite stays green. Return `RestResponse<T>` when a method needs a
  status or a header *and* a body; a plain `T` when it needs neither. `Response` is fine only where
  there is no entity at all (`noContent()`), and `@RegisterForReflection` is a workaround rather
  than the fix, because it leaves the signature still saying nothing.

**The `clients/` role namespace is minted, never granted.** Every `client_credentials` token's
`groups` ends with `clients/<the id in sub>` (`ClientRoles`, called from `TokenService`). Today no
role is configurable at all — a service client's `qits:system` and a commission's kind role are both
code — so nothing can ask for the prefix. The configured `roles` lines that once needed a refusal
(`ClientRoles.refuseReserved`) went with the environment registry in qits-163, and the guard went
with them. A future change that lets roles come from anywhere else must refuse the prefix there,
and a new mint that is not to a client credential must not stamp one — `TokenService.workstation` is
the standing example, and `@RolesAllowed("clients/<x>")` in a sibling service is what all of it is
for.

**A commissioned credential's roles are code, not a merge with its owner's**
(epic qits-540, dossier page "Plan (as of 2026-09-13)", D3/D12). `CommissionRoles.forKind` is a plain, unconfigured
`Map<String, List<String>>`: `workspace`, `agent-container`, `refinement` (`qits:agent`), `ci-run`
and `bootstrap-publish` (`qits:ci-run`), `ci-runner` (`qits:ci-runner`) and
`ci-runner-registration` (`qits:ci-runner-registration`) are the seven the jar ships, tested as
shipped in
`CommissionedGitRefsTest` — a change to that map is a change there. `bootstrap-publish` holds the
CI publisher's role on purpose (user ruling 2026-09-13, "only CI may publish to qits-artifacts"):
it is the bootstrap's own publishing identity, commissioned with `gitRefs: []` for its publish
phase and deleted by the bootstrap when that phase ends, so no permanent publishing identity
remains. **A kind not in the map gets no
role at all**, not a refusal (D12) — only its own self-role, so a test class is free to invent a
kind without a config line to write for it. There used to be a `qits.idp.commission.roles.<kind>`
config key that let a deployment override this; it is gone, along with the owner-role fallback it
replaced — `ClientRegistry.asClient` calls `CommissionRoles.forKind` directly and reads no config.
Claims followed the same change: a commission's claims are only what it stated for itself, never
merged with its owner's grants.

**Every read route accepts `qits:agent`; no write route does** (user ruling 2026-09-12: agents keep
every read and lose only write access). Today the one read route with a role check is `GET
/api/clients` (`BasicCaller.requireAnyRole`); the others are public or session-based. A new read
route with a role check accepts `BasicCaller.AGENT` too; a new write route does not. **The
service-client management API (`/api/service-clients`) is the one deliberate exception**: every
verb there, GET included, requires `qits:system` and refuses `qits:agent` — migrating a service's
own secret is not a thing an agent's context has any business doing, so `IdpServiceClientsController`
calls `BasicCaller.staticOnly` rather than `requireAnyRole` throughout.

**`POST /api/gc/service-clients` is the one write that takes a bearer** (qits-878,
`IdpGcController`): a `qits:system` bearer from this idp whose `sub` is a service client, beside the
usual Basic pair. It is safe there and nowhere else because the door can only remove credentials —
the service clients no `GET /deployments/api/claims/idp-clients` claim names, past a six-hour grace,
never the caller's own (`UnclaimedServiceClientCollector`). An empty claim set is a 400 that
deletes nothing. Do not let that bearer reach any other write.

**`BasicCaller.SYSTEM`'s VALUE is `qits:system`** — the open calling model's one
service-to-service role, which is what every service client's fixed roles are. No service client
holds `qits:admin`, and nothing here mints `qits-platform:system`. The constant's name is the seam it gates (the
platform's system surfaces), not the spelling of the role; every call site reads the constant.

**Never make the safe direction configurable.** A client with no secret is unusable. There is no
flag that turns that into "open", and adding one would make an unconfigured deployment issue
identity to whoever asks. The jar ships no service client at all, and the one-time adoption skips
an id with no secret, so such an id never becomes a row —
`IdpTokenTest.aClientWithNoSecretIsUnusableRatherThanOpen` runs against `prod-qits-workspaces`,
listed for adoption with no secret.

**Service clients live in the database, and only there** (epic qits-540, dossier page "Plan (as of
2026-09-13)", contract C2; the environment registry was retired by qits-163). `ServiceClients`
(`idp/control`) is the registry: `idp_service_client` rows, managed through
`/idp/api/service-clients` (`IdpServiceClientsController`). Five things to keep straight:

- **It loads at start into a volatile map, exactly like `SigningKeys`' key set** — `onStart` runs
  after Flyway: the seed (if not done), the adoption (if not done), then every row into the map. The
  token path stays off postgres: `ServiceClients.find` is a map read, never a query. Every write —
  `create`/`rotate`/`delete`/the seed/the adoption — goes through `DbRetry` and the map is replaced
  under a `synchronized` method, the same one-idp-process assumption `DynamicClients` documents.
- **Roles and claims are code** (D3): `groups` is `qits:system` plus its own `clients/<id>`, and the
  claim is `project=*`. No client holds `qits:admin`. `isServiceClient` means "has a row", which is
  what every commission door (`BasicCaller.staticOnly`) checks.
- **Every token's `aud` is `["qits-platform"]`** (C7) — service, commissioned, introspection JWT,
  CLI and workstation alike — and an `audience` parameter on `/token` or `/authorize` is accepted
  and ignored, never `invalid_target`. `TokenService.PLATFORM_AUDIENCE` is the one constant; there
  is no per-client list and no owner lookup for a commission's audience. Do not add one back.
- **`QITS_IDP_SEED_CLIENT_ID`/`_SECRET` seed the very first row, once** — nothing can call the
  management API before any service client exists to authenticate with. The `idp_seed` marker row
  is what "once" checks, not the variables: `ServiceClients.seedOnce` reads the marker before it
  reads the variables, so a later boot with them still set, changed, or blanked does nothing.
  `ServiceClientSeedTest` proves that by calling `seedOnce()` again directly (package-visible for
  exactly this) rather than by actually rebooting the process.
- **`EnvironmentClientAdoption` moved the old environment clients in, once.** At the first start
  that finds no `idp_adoption` row (V10), every id on `qits.idp.clients` with a non-blank
  `qits.idp.client.<id>.secret` and no row gets a row holding that secret's hash, `created_by =
  'adopted'`, and the marker is written in the same `DbRetry` transaction. Ids without a secret are
  skipped and existing rows untouched. The keys are read with raw `Config` lookups in that class
  alone — the same lookups the retired `IdpClients` made, so the env spellings
  (`QITS_IDP_CLIENT_DEV_QITS_CI_SECRET`) resolve as before — and never again once the marker exists.
  It is the only reader of those keys; do not add another. **An existing row whose own hashes do not
  match its environment secret gets that secret's hash as `legacy_secret_hash` (V11)**, accepted
  beside the row's own by `ClientSecret.serviceClient`: the retired registry accepted either, and the
  live edge still held the environment one. A rotation clears it — that is how it retires. The pass
  is guarded by `idp_adoption.legacy_adopted_at`, set by a first adoption in the same transaction or
  by `keepEnvironmentSecrets` on an installation that adopted before V11.

## Package and module conventions

`eu.wohlben.qits.idp.*`, split across maven modules with disjoint sub-packages so there is no split
package:

- `idp/` — `entity`, `persistence`, `control`, `error`. Framework-free in the sense that matters:
  no JAX-RS, no web stack. `control` owns the keys (`SigningKeys`), the JWKS document (`Jwks`), the
  issuer string (`Issuer`), the grant (`TokenService`) and the client registry — which is three
  classes: `ServiceClients` (service clients, from `idp_service_client` rows), `DynamicClients`
  (commissioned, from `idp_client` rows) and `ClientRegistry`, which is the only thing that knows
  both exist. `EnvironmentClientAdoption` is beside them and runs once per installation. The user half is four more:
  `Users`, `RegisterTokens`, `Sessions`, and `Registrations`, which is the only thing that knows
  those three exist — the same split as `ClientRegistry`, for the same reason. `PasswordHash` and
  `RandomSecret` are the two value helpers beside them.
- `service/` — `api` only, and it is the HTTP boundary plus the one bean the web stack demands:
  the two metadata routes, the token endpoint, the commission API, the user surface
  (`IdpAuthController`, `IdpSessionsController`, `IdpRegisterTokensController`), the shared
  machine-caller check (`BasicCaller`), the session cookie's spelling (`SessionCookie`), and two
  error mappers. `WebAuthnCredentials` lives here rather than in the domain because
  quarkus-security-webauthn is a web stack — it depends on quarkus-vertx-http and its ceremonies
  take a `RoutingContext` — and the domain jar's rule is that it does not.

**Two error vocabularies, and the difference is the caller.** `OAuthException` is RFC 6749's and its
mapper attaches `WWW-Authenticate: Basic` to every 401, because the machine surfaces authenticate
with a Basic pair. `AuthException` is the user surface's — two codes, `invalid_request` and
`invalid_credentials` — and its mapper sends **no** challenge, because these routes are called by a
browser with `fetch` and a Basic challenge there is a native credentials dialog in front of the
login page. A new route picks the one that matches who calls it, not the one nearest in the file.

**`TokenService` must not learn which half a client came from.** It asks `ClientRegistry` and gets
an `IdpClient` either way; a commissioned credential mints identically to a service client because
there is no branch to make it differ. That identity is the whole commission model working — docker's
Bearer dance and `quarkus-oidc-client` need no second code path — so a change that makes the token
endpoint check the kind of client it has is a change worth arguing about first. `context_kind` and
`git_refs` keep that rule: they are two nullable fields on `IdpClient`, stamped when present. A
service client has neither, so its token carries neither.

The directories are `idp/` and `service/`; the artifactIds are `qits-idp-domain` and
`qits-idp-service` — generic coordinates would collide in a shared `~/.m2`.

## Addressing

`quarkus.rest.path=/idp`, **not** `/idp/api`. That is the one place this repo departs from the
sibling services, and it is not cosmetic: an OIDC consumer configured with auth-server-url
`http://qits-idp:8080/idp` fetches `/idp/.well-known/openid-configuration` by its own
derivation and follows the document from there. An `/api` segment would move the discovery document off the path
every OIDC client computes. The commission API takes `@Path("/api/clients")` relative to
this — `/idp/api/clients` — which keeps the machine-admin surface separate without moving the
protocol.

**Everything added since goes under `/api` too, and that is why the ignore list has not had to
change**: `/api/auth/*`, `/api/sessions/introspect` and `/api/register-tokens` are all covered by
the single `/api` entry. Keep it that way — a route added as a new literal beside `/token` and
`/jwks` costs an ignore-list entry, an `IdpPackagedSurfaceIT` case, and the risk described below.
The one surface this rule does not cover is the extension's: quarkus-security-webauthn registers
`/idp/q/webauthn/*` (under `/q`, already ignored) and `/.well-known/webauthn` at the **root**,
outside `/idp` entirely, which the gateway therefore never routes to.

**That departure is what makes `quarkus.quinoa.ignored-path-prefixes` load-bearing here.** The
client mounts at `/idp/` like every sibling's, but because the REST surface is the segment rather
than `/idp/api`, the protocol routes sit directly beside the SPA's own. The SPA fallback answers any
unmatched path under `/idp` with `200 text/html`, so the list — `/api,/q,/.well-known,/token,/jwks`,
**relative**, matched after `/idp` is stripped — is the whole of what keeps a mistyped protocol path
a 404. Get it wrong and an OIDC consumer caches a page as its discovery document. Adding a literal
route means adding its entry and its `IdpPackagedSurfaceIT` case in the same commit.

The issuer is **derived, never configured** (qits-730): `https://idp.qits.<QITS_DOMAIN>` — no path,
no trailing slash, `https://idp.qits.localhost` with no domain stated — composed in `Issuer.url()`
from `PlatformHostname`, the hostname grammar `PlatformDomain` reuses. It is the discovery
document's `issuer` and every token's `iss`, and it is an IDENTIFIER: nothing dials it. Never add
a config key or a properties default for it — a configurable issuer is how an address once got read
as an issuer and every machine token was refused. The ADDRESS is `qits.idp.endpoint-base`
(`Issuer.endpointBase()`), and `token_endpoint`, `jwks_uri` and `authorization_endpoint` hang off
that — for an in-network caller. A caller whose `Host` or `X-Forwarded-Host` is the public
authority (`BrowserSso.canonicalAuthority()`) is told the same endpoints on the public origin
instead (`https://idp.qits.<domain>/idp/...`); the request only picks between those two values. `BearerCaller` also accepts `Issuer.LEGACY` (`http://qits-platform-idp:8080/idp`, the old
configured issuer) so tokens minted before the cutover live out their hour; it goes in qits-730
wave 3.

## Untrusted input

`client_id` arrives on an unauthenticated request. It is only ever a map key (`ServiceClients`) or
a prefix-checked row lookup (`DynamicClients` refuses anything not starting `dyn-` before it opens a
connection) — never part of a config key any more. Keep it that way: building a config key from it
would let a caller probe the config namespace.

Secrets are compared with `MessageDigest.isEqual`, never `String.equals` — the comparison is against
a value a caller may retry freely. `ClientSecret` is where that happens: every secret is stored as
a SHA-256 and the candidate is hashed and compared. That hash is deliberately not a password
hash — a commissioned secret is 256 bits of `SecureRandom` and there is nothing to slow a guesser
down, while the token path is the platform's whole call graph. The argument is in the class.

Client ids reach the log on a refusal, so `LoggableClientId.of` bounds what can be written there.
A **context id never reaches the log at all**: it is the caller's string and the generated client id
already carries a bounded slug of it.

`contextKind` and `contextId` arrive on an authenticated request and both end up inside a client id.
The kind is matched against a lowercase-slug pattern and refused outright; the id is slugged down to
`[a-z0-9-]` for the client id and stored raw, so what a listing shows an operator and what a
reconcile compares are the same string the owner sent.

**Randomness is generated per call, never from a static field.** A `SecureRandom` in a static is
instantiated during native-image generation and lands in the image heap with its seed baked in —
every deployment of that binary would then produce the same ids and secrets. GraalVM refuses to
build it (measured 2026-08-14, `DynamicClients` was written that way first), which is the only
reason this is a caught bug rather than a shipped one. `RandomSecret` is where the rule is written
down and where every credential value comes from; `SigningKeys.randomKid` keeps its own copy of the
idiom because a `kid` is an identifier rather than a secret.

**A username is an HTTP header value, and `Users.normaliseUsername` is where that is enforced.** It
leaves this service as `X-Qits-User`, injected by the edge and read by five services, so a name
carrying a carriage return would be a header-splitting hole in every one of them. Control
characters are refused; beyond that and the column's length the name is the user's own.

## Schema changes

`idp/src/main/resources/db/idp/migration/`, hand-written, its own lineage on its own datasource —
keep appending, never edit an applied migration. V1 is the keys and an empty client table, V2 fills
the client table in, V3 is the five user tables. **V8 is `idp_service_client` and `idp_seed`**
(contract C2 of epic qits-540, dossier page "Plan (as of 2026-09-13)"): a new table rather than a
kind column on `idp_client`, because a service client has no owner and no context — see
`ServiceClients` and `V8SchemaTest`. **V10 is `idp_adoption`**, the one-row marker that the
environment clients were moved into `idp_service_client` (qits-163, `EnvironmentClientAdoption`).
V8's header still talks about environment clients; it is applied, so it stays as it is. **V11 adds
`idp_service_client.legacy_secret_hash` and `idp_adoption.legacy_adopted_at`** — the environment
secret a pre-existing row keeps until its next rotation, and the marker for that second pass.

**One column set in V3 is not a design and must not be treated as one.** `idp_webauthn_credential`
is exactly `WebAuthnCredentialRecord.RequiredPersistedData` from quarkus-security-webauthn, read off
the extension's source — that record is what `fromRequiredPersistedData` rebuilds a verifiable
credential out of, so a field dropped from it is a login that cannot be checked. Its `username`
member is the one thing not stored, because the join to `idp_user` carries it. A Quarkus upgrade
that changes that record changes this table.

**The store is PostgreSQL, and the lineage restarted at V1 to say so.** The H2 lineage was deleted
rather than continued, on one precondition: the move is an **unwrap and a re-bootstrap**, so no
database anywhere is on it and no `V2__move_to_postgres.sql` had a reader. It costs a fresh idp
state — a new signing key, every token minted before the move stops verifying — which the
re-bootstrap accepts. The fresh V1 is the H2 pair **translated and not redesigned**: `clob` became
`text` and nothing else about either table moved, because what is stored here has identity
semantics. **A second clean start is not a precedent** — the ordinary rule (append, never edit) is
back from V1 onward.

The datasource is the platform's generic resource contract — `jdbc.url=${QITS_RESOURCE_DB_URL}` and
its two siblings, with **no fallback**, so a process that was handed nothing dies at Flyway instead
of opening a store nobody meant. `.config/qits/deployments.yml` carries the `resources:
postgresql:db` line that fills it, and the bootstrap CLI fills it for the seed container, since this
service boots before a deployer exists.

Two things about the shipped V1:

- `idp_signing_key` is shaped so **rotation is a data change**. Many rows, one `ACTIVE`, all
  published. Do not add a "one active key" partial unique index — postgres does have one now, and
  V1's header refuses it: a rotation inserts the new active row before retiring the old one, so the
  index would forbid the intermediate state of the very statement order that rotates. The reader
  already resolves the newest active row.
- `idp_client` was **empty on purpose** — and V2 is the migration that filled the shape in. It was
  written for a lease (a TTL the registrar asked for, a deadline on the row, expired rows
  collected); the credential model that shipped instead has no deadline, because a commissioned
  credential's lifetime is its context's. So V2 renames `registered_by` to `owner`, adds
  `context_kind` and `context_id`, and **drops `lease_expires_at`, `audiences` and `claims`**. The
  last two go because a commissioned client is issued its *owner's* audiences and claims, resolved
  at mint time — a column no reader has is not forward compatibility, it is a trap for whoever
  writes it first and sees nothing happen. Per-context scoping brings them back with the code that
  reads them.

  **V5 is that follow-up for `claims`**, and it keeps V2's bargain: the column comes back together
  with its reader (`ClientRegistry.claimsFor`) and its rule (`CommissionedClaims`). It holds
  `name=value` lines and not JSON — the vocabulary is closed at three names and the accepted value
  charset excludes `=` and the newline, so nothing needs escaping and the `idp` module needs no
  Jackson. Nullable, and null is what every row written before it says: inherit the owner's claims,
  exactly as before. `audiences` stays gone — every token's audience is `qits-platform` now (qits-163).

  The `add column … not null` statements have no default, so they fail loudly against a table that
  turned out to hold rows. That is deliberate: nothing had ever written this table, and if that were
  somehow wrong it is worth stopping for.

  **V7 adds `git_refs`**, with its reader (`ClientRegistry`, `TokenService`) and its rule (`GitRefs`)
  in the same change — contract C2 of `principal-bound-git-refs-plan.md`. One ref per line, `text`.
  **Null and the empty string differ:** null is "no list stated" (no `git_refs` claim, every older
  row), the empty string is the empty list ("push nothing"). Keep that difference in any reader.

**V9 is `idp_token`**, the commissioned tokens (qits-448): a new table rather than a kind column on
`idp_client`, because a token is looked up by the hash of what a caller presents and has a
generated uuid key and a separate readable `subject`. It has **no expiry column, by design** —
every use is an introspection, so deleting the row is the whole revocation. `claims` and `git_refs`
are V5's and V7's formats verbatim. See `CommissionedTokens` and `TokenValue`.

## Adding a dependency on another context

Don't. This context has no compile-time dependency on any other qits module and must not grow one —
least of all on a service it issues tokens for. Everything it knows arrives as config.

## Tests

- The **integration** tests are two different things and are listed separately: the story catalogue
  is under "Userflows" below, and `IdpPackagedSurfaceIT` is here. They share no `@TestProfile` and
  no database, deliberately.
- App-level config lives in `service/src/main/resources/application.properties` and Quarkus merges
  it into the test config. **Never re-declare an app-level setting in test resources.** The suite's
  copy adds `qits.idp.clients` and a secret per id — not an app setting any more but the input of
  the one-time adoption, which turns them into the suite's service clients at start (qits-163).
  `EnvironmentClientAdoptionTest` pins what that start did, and calls the adoption again directly
  to prove "once".
- **Tokens are verified against `GET /idp/jwks`, over HTTP, never against a key reachable
  in-process** (`PublishedJwks`). Verifying in-process would pass with an empty, wrong, or
  private-key-leaking JWKS, and the JWKS is the only thing a real consumer sees.
- `SigningKeyPersistenceTest` exercises the restart seam the suite cannot actually restart:
  `SigningKeys.reload()` drops the cache and goes back to the database. A generate-on-every-load
  regression changes the `kid` there.
- `CommissionedClientsTest` is the commission API end to end, and its cases are the invariants
  rather than the endpoints: a commissioned client mints exactly what its owner may, the row holds
  no plaintext, decommission stops the minting on the very next request, only the owner (or the
  credential itself) may delete, a commissioned client may not commission, and the listing is the
  caller's own. The suite shares one application and therefore one store, so **every test names its
  own `contextKind`** and the listing case filters on it instead of assuming an empty table. Its
  scoping half asserts the direction rather than the plumbing: a stated claim reaches the token and
  the row, it overrides the owner's grant for that name and leaves the owner's others alone, `*` and
  an invented name are both 400 with nothing written, and a commission that states nothing is the
  inheritance it always was. `CommissionedClaimsTest` is the same rule as plain unit tests, including
  what a hand-edited column must do — drop what it cannot read, never throw, because that parse runs
  on the token path for every commissioned credential.
- `CommissionedGitRefsTest` is contracts C1 and C2 of `principal-bound-git-refs-plan.md`: which
  token carries `git_refs` and `context_kind` (service client: neither), a commission with and
  without `gitRefs`, the empty list reaching the token as `[]`, each validation rule as a 400 with no
  row, the owner-only `PUT …/git-refs` (foreign or unknown is 404, the credential itself 403) and the
  next token after it, roles per kind (`agent-test` and `reserved-test` in the suite's config, and
  the seven shipped kinds as shipped, `bootstrap-publish` among them), and V7's column. `GitRefsTest`
  is the same rules as plain unit
  tests; `CommissionRolesTest` is the code map itself, including that an unknown kind gets no role
  at all rather than a refusal — there is no deployment override to test, that config key is gone.
  The person tokens' `git_refs`
  are pinned in `CliOAuthTest` and `WorkstationOAuthTest`.
- `CommissionedTokensApiTest` is the commissioned-token API end to end (qits-449), and
  `CommissionedTokensTest` (under `control/`, a `@QuarkusTest` because `idp/` has no test tree) is
  the control against the real store. The invariants: the value is `qits_tok_` + 43 base64url
  characters and the row holds only its hash, a non-token string is refused without a store read,
  only a service client commissions, the listing is the caller's own and never carries a value,
  only the owner or the token itself (`Bearer qits_tok_…`) deletes, and a deleted token is refused
  on the very next introspection.
- `UserAuthenticationTest` is the user surface end to end, and its cases are the invariants: a
  register token makes exactly one account, the two bootstrap roles are granted as rows, the cookie
  carries exactly the attributes the plan fixed, a session introspects until it is revoked and not
  after, only a service client may mint or introspect, and every way a login can fail is one 401
  whose body is byte-for-byte the same. **The ceremony is real** —
  `quarkus-test-security-webauthn`'s emulated authenticator holds an EC keypair and signs actual
  assertions, so nothing here is a fixture that can go stale. Two things it constrains:
  `WebAuthnTestHardware` hard-codes the origin `http://localhost:8080`, which must be a
  **shipped** `quarkus.webauthn.origins` value (webauthn4j checks the origin inside the browser's
  own clientDataJSON, never the port the request arrived on — so a random test port is fine), and
  the emulator hashes `localhost` as the relying party, which the shipped rp id must therefore be.
  Both are **derived** now, by `PlatformDomain` from the stated `QITS_DOMAIN`, and neither can be
  overridden — so the constraint lands on the derivation itself: with no domain stated it must keep
  composing `localhost` and `http://localhost:8080`, and never `idp.qits.localhost:8080`.
  `BrowserSsoTest` pins the arithmetic and `DerivedBrowserHostsTest` pins that the config source
  factory composing it is actually discovered, which is the only way that wiring can fail.
  Every test invents its own username, because the suite shares one application and one store.
- `SessionLifetimeTest` costs its own application start to pin `qits.idp.session-ttl`, the way
  `TokenLifetimeTest` does for the token's. It is also the only place expiry is proven: the shipped
  twelve hours cannot be waited out, and expiry is the third of the three states — unknown, revoked,
  expired — that introspection has to refuse alike.
- `TokenLifetimeTest` costs its own application start to pin that `qits.idp.token-ttl-seconds` is
  honoured, in both places a caller reads a lifetime. The number is a trade (see the key's comment),
  and shrinking it again is the lever that closes the post-decommission grace — so the lever has to
  stay connected.
- `IdpPackagedSurfaceIT` runs the **packaged artifact** and asserts what a native build can silently
  lose: the build-time route prefixes, the shipped datasource *expression* (it hands the launched
  process `QITS_RESOURCE_DB_URL` and its two siblings — the generic contract a deployment supplies —
  rather than restating the datasource keys, so the jar's own `${…}` indirection is what is under
  test), Flyway's migrations surviving as resources, and RSA key generation plus signing in the
  packaged process. **The commission round trip is there too** — commission, mint, decommission,
  refused — because every step of it is a thing native can lose quietly: record deserialization
  needs reflection registration, SHA-256 needs a JCA provider, and the table only exists if `V2`
  survived the packaging. **The user round trip is there for the same reason and is the heavier
  case** — register a passkey, log in with it, introspect, log out: the ceremony is JCA end to end
  (`KeyFactory.getInstance("EC")` rebuilding the stored key, `SHA256withECDSA` verifying the
  assertion), webauthn4j parses CBOR reflectively, four request and response records need types the
  image builder can see, and `V3` has to have survived as a resource for any of the five tables to
  exist. A binary that lost any of it boots, answers the discovery document, and verifies no login.
  Its embedded postgres reaches the profile through a **system property**, because
  a `QuarkusTestProfile` is instantiated in two classloaders and a static field is not shared
  between them. **The client's probes are here for the same reason** — Quinoa is off in test mode,
  so `/idp/` is served by nothing during the `@QuarkusTest` suite: that the page arrives with the
  matching `<base href>`, that a deep link falls back to it, and that every ignored prefix answers
  404 rather than HTML are all packaged-only facts.

## Userflows

The **story catalogue** — `service/src/test/java/eu/wohlben/qits/idp/stories/**` plus
`api/TokenIssuanceBootstrapIT`, which predates the package and stayed where it is because its name
is a cross-repo landmark. Seven `@UserStory` methods in six `@QuarkusIntegrationTest` classes,
emitting `service/target/userstories/<category>/<story>/` — sidecar, markdown, HTML — which the
second step of the release-request phase tars and publishes as `@userflows/qits-idp-platform-service`
(`.config/qits/release.yml` declares the `java-service` archetype and `userflows: true`, and `true`
means this repository's own name), once per release-request fold. That step **gates**, like every
step of the composed pipeline: a red story is a red verdict for the whole fold. The
framework is `eu.wohlben.qits:qits-userflows` (test scope, version pinned in the root pom); how to
write one is in that library's `AGENTS.md` and `docs/report-contract.md`.

**The catalogue is the mirror image of every sibling's.** Each of them carries a
`TokenValidationBootstrapIT` that stands a `MockIdp` where this service really is. Here there is
nothing to stand in for, so **there is no `NetworkCapture.source` anywhere in this repository**: the
shipped RestAssured tap (`NetworkTaps.restAssured`, installed once by `stories/support/StoryNetwork`)
is the whole feed, and every observed arrow points *in*. The hand-copied `api/StoryNetworkFilter`
this repo carried was deleted when the catalogue was written; a new story class calls
`StoryNetwork.install()` and never writes a tap.

**One `@TestProfile` for all six classes** — `stories/support/StoryProfile` — and that is not
tidiness. A profile is what failsafe launches a process for, so a second one would be a second
issuer with a second database and **a second signing key**, and a diagram whose traffic landed in
whichever process happened to be running. `IdpPackagedSurfaceIT` keeps its own profile and its own
database on purpose and is deliberately *not* in this run (see the ci file: it is half about the
client, which the run does not build).

**What the profile supplies.** The generic resource triple, `quarkus.otel.sdk.disabled`, and the
input of the one-time adoption (qits-163): `qits.idp.clients` and a secret for each id but one. The
jar ships no service client, so these become the launched process's service clients at its first
start, exactly as a live installation's did. `qits-platform-artifacts` gets **no** secret, so it is
never adopted and `FrontDoorRefusalsIT` runs its "unusable, never open" arm against it.
`uf-role-thief` is also configured with a roles line naming another client's self-role, and
`ReservedRoleNamespaceIT` shows the line is not read.

**The leaf claim, and exactly what it proves.** `assertNoEdgesFrom("qits-platform-idp")` is on the
minting, refusal and key-serving stories, and there it has teeth: a service client is a read of a
map loaded at start and `published()` is a volatile cache, so the platform's whole bootstrap path is answered
without this process initiating anything at all. The two commissioning stories really do touch rows,
so they **declare** the jdbc edge (`Network.declare`) instead — dashed in the diagram and flagged
`declared` in the sidecar, because a claim must never render like evidence. What the assertion does
*not* prove is that no socket was opened: there is no outbound tap that could have seen one. What
makes it true is structural — no rest-client, no oidc-client, no event bus on this classpath — plus
the exporter being off.

**Two stated coverage gaps, neither papered over:**

- **This service's own OTLP export is not covered.** The shipped config points its SDK at
  `http://qits-observability:8080/observability/api/otel`, which resolves on `qits-net` and nowhere
  else; a launched artifact would retry into the void, and an exporter flushing on its own thread
  would draw arrows into whichever story happened to be open. It is disabled, and no story claims
  its absence either — an `assertNoEdgesTo` over an exporter the profile switched off would be a
  claim about the profile.
- **A consumer cannot follow the advertised absolute URLs.** `qits.idp.endpoint-base` names
  `http://dev-qits-idp:8080/idp`, and a `@TestProfile` cannot point it at the launched
  process: the port is ephemeral and the overrides are computed before the process exists.
  `BootstrapDocumentsIT` therefore reads the document's *derivation* and addresses the paths on the
  real port. That the document derives its endpoints from the one endpoint base is proven; that a
  consumer resolves the host is a deployment fact.

**Labels.** A commissioned client id is `dyn-<kind>-<slug>-<22 base64url chars>` — readable on
purpose, and therefore invisible to the default scrubber, which looks for UUIDs, long hex and bare
numbers. `StoryTarget.normalize` rewrites it to `{id}` through `NetworkCapture.labelNormalizer`, and
`StoryTarget.served(...)` runs an assertion's expected label through the same two functions in the
same order, so an assertion and an observation cannot disagree. **No credential can reach a label**:
neither a secret nor a bearer is ever on a path — but every story asserts that rather than assuming
it, with `assertNotLeaked` over each secret it presented, each token it was answered, and each
generated id (which is the hash-stability check wearing the same coat).

**Adding a story.** One story per class, so `@UserflowPrecondition` / `@UserflowRunsAfter` stay
usable (they are `@Target(METHOD)`). Name the class's own `contextKind` if it writes rows — the
launched process migrates but does **not** clean its schema, so the store carries what earlier runs
left, and a listing assertion filters rather than assuming an empty table. Install the tap from
`@BeforeAll` and pin at least one edge, or a later edit that drops the install empties every diagram
in the class while every remaining assertion still passes. And **add the class to
`.config/qits/userflow-stories` in the same commit** — one class name per line, which the archetype
turns into the verify step's `-Dit.test`: a class that is not
named does not run there, and its story disappears from the published bundle with the build green.

The whole gate locally, in one line:

    ./mvnw -DskipITs=false -Dquarkus.quinoa=false verify \
      -Dit.test=TokenIssuanceBootstrapIT,BootstrapDocumentsIT,CommissionedCredentialIT,CommissionRefusalsIT,FrontDoorRefusalsIT,ReservedRoleNamespaceIT
