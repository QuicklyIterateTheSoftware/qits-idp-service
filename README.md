# qits-idp-platform-service

The platform's own identity provider, for **machines and for people**, deployed as the
`qits-idp` application.

The machine half is an RS256 signing key that survives restarts, a JWKS, an OIDC discovery document,
and a `client_credentials` token endpoint the platform's services authenticate to each other with,
plus a commission API for the credentials that belong to one dynamic context.

The user half is accounts: an operator registers with a one-time token minted at bootstrap, logs in
with a passkey (WebAuthn) or an optional password, and holds an opaque `qits-session` cookie that
the edge introspects here and turns into the `X-Qits-User` / `X-Qits-User-Id` / `X-Qits-Roles`
headers services already read. **There is no OAuth dance for the first-party UI** and no session at
the gateway any more: the edge is the single ingress and terminates the browser session against
this service. The model, the rollout order and the flags are `user-authentication-plan.md` in the
qits superproject.

## The surface

Everything is served under `/idp`, the segment the gateway routes verbatim.

| path | what it is |
|---|---|
| `GET /idp/.well-known/openid-configuration` | discovery. An OIDC consumer configured with auth-server-url `http://qits-idp:8080/idp` derives this URL itself. A caller on the public name is told the public endpoints. |
| `GET /idp/jwks` | the public signing keys, each with its `kid`. |
| `GET /idp/authorize` | signed-in browser approval for the public clients' Authorization Code + PKCE (S256) flow: `qits-git-workstation`, `qits-cli`, and `qits-landing-dev` (the landing SPA under `ng serve`, callback `http://localhost:<port>/auth/callback`). |
| `POST /idp/token` | `application/x-www-form-urlencoded`: `client_credentials`, workstation `authorization_code`, or rotating workstation `refresh_token`. |
| `POST /idp/api/clients` | commission a credential for one dynamic context. |
| `GET /idp/api/clients` | the caller's own live commissions. |
| `DELETE /idp/api/clients/{clientId}` | decommission one. |
| `PUT /idp/api/clients/{clientId}/git-refs` | replace the Git refs one commission may push. Owner only. |
| `POST /idp/api/tokens` | commission an opaque token for one dynamic context. Basic, a service client holding `qits:system`. |
| `GET /idp/api/tokens` | the caller's own live tokens, never a value. |
| `DELETE /idp/api/tokens/{tokenId}` | delete one — the owner, or the token itself as `Bearer qits_tok_…`. |
| `POST /idp/api/tokens/introspect` | what the edge asks a `qits_tok_` bearer about; answers the token and a short JWT for it. Basic, a service client holding `qits:system`. |
| `POST /idp/api/service-clients` | create a database row for a service client id. Basic, a service client holding `qits:system`. |
| `POST /idp/api/service-clients/{id}/secret` | rotate its secret; the old one stays valid fifteen minutes. |
| `GET /idp/api/service-clients` / `.../{id}` | the service clients, never a secret. |
| `DELETE /idp/api/service-clients/{id}` | remove its database row. |
| `POST /idp/api/auth/register-options` | WebAuthn creation options. Guarded by a register token or a session. |
| `POST /idp/api/auth/register` | an attestation or a password → an account and a session. |
| `POST /idp/api/auth/login-options` | WebAuthn request options. Anonymous. |
| `POST /idp/api/auth/login` | an assertion or `{username, password}` → a session. |
| `POST /idp/api/auth/logout` | revoke the session and clear the cookie. |
| `POST /idp/api/auth/password` | set or replace the signed-in account's password. |
| `POST /idp/api/sessions/introspect` | what the edge asks a cookie about. Basic, a service client. |
| `POST /idp/api/register-tokens` | mint a one-time register token. Basic, a service client. |
| `GET /idp/api/workstations` | the signed-in user's revocable Git workstation credentials. |
| `DELETE /idp/api/workstations/{familyId}` | revoke one signed-in user's workstation refresh-token family. |
| `GET /idp/q/health/ready` | readiness, where the deployment convention expects it. |
| `GET /idp/` | the client — four routes, `/idp/login`, `/idp/register`, `/idp/clients` and `/idp/users`. |

### The client

`qits-idp-platform-frontend` (Angular) is a submodule at `service/src/main/webui`, and Quinoa builds
it during `mvn package` and serves it from this process at `/idp/`.

**The client and the protocol share one root**, which no sibling service does: everywhere else the
REST surface is `/<segment>/api`, one level below the SPA. Here `quarkus.rest.path` is `/idp`
itself, because OIDC fixes where a consumer looks. So `quarkus.quinoa.ignored-path-prefixes` names
the whole machine surface — `/api,/q,/.well-known,/token,/jwks`, matched after `/idp` is stripped —
and it is the only thing keeping a mistyped protocol path from being answered with the page. The
reasoning is in `service/src/main/resources/application.properties`, the proof in
`IdpPackagedSurfaceIT`, and the rule is that a new literal route lands with its prefix entry in the
same commit.

A token request authenticates with `client_secret_basic` **or** `client_secret_post`, never both.
It may still name an `audience`; the parameter is accepted and **ignored** — never refused with
`invalid_target` — because every token has the same one audience (see below).

    curl -s -X POST http://qits-idp:8080/idp/token \
      -d grant_type=client_credentials \
      -d client_id=dev-qits-ci -d client_secret=...

The token is RS256, carries a `kid`, and says:

| claim | value |
|---|---|
| `iss` | `https://idp.qits.<QITS_DOMAIN>` — derived from the domain, never configured |
| `sub` | the client id |
| `aud` | always `["qits-platform"]` — see below |
| `iat`, `exp`, `jti` | issued now, valid for `qits.idp.token-ttl-seconds` (3600 by default) |
| `groups` | the client's roles (fixed in code), **plus `clients/<client id>`** — see below |
| `project`, `workspace`, `branch` | `project=*` for a service client; a commission's own stated claims |
| `context_kind` | commissioned clients only: the commission's `contextKind` |
| `git_refs` | commissioned clients only, and only when the commission stated a list — see [Git refs](#git-refs) |

**`aud` is always `["qits-platform"]`, for every token this idp mints** — a service client's, a
commissioned client's, the JWT a commissioned token's introspection answers with, the CLI's and a
Git workstation's (qits-163; contract C7 of epic qits-540, dossier page "Plan (as of
2026-09-13)"). `aud` says only where a token may be *presented*, and every qits service accepts
`qits-platform`; what a token may *do* there is its `groups`. So there is no per-client audience
list any more, nothing to ask for, and nothing to refuse.

**Every client token names its own client.** `groups` — which `quarkus-oidc` reads as roles — always
ends with `clients/<the id in `sub`>`, stamped at mint time and configured nowhere. A role naming one
client is therefore held by that client alone, by construction rather than by grant, and a resource
service can write `@RolesAllowed("clients/prod-qits-projects")` for a route exactly one caller may
ever reach. It is additive: consumers allowlist the roles they care about, so the extra entry is
inert everywhere else.

That is why **`clients/` is a reserved namespace**, and today nothing can even ask for it: every
role a client carries is fixed in code — `qits:system` for a service client, its kind's role for a
commission. The configured `roles` lines that once needed a guard against the prefix are gone with
the environment registry. A user credential gets no such role: the workstation
token below carries `qits:git:external` and nothing more, so the machine identity a service gates on
cannot be reached through a login.

**Claims, not scopes.** `aud` names the service a token may be used at; the structured claims name
what it may be used for *within* that service. The idp states them and interprets nothing — a
resource service decides what a value permits, including whether `*` means "any". They reach a
token from one of two places, never merged: a service client's one fixed claim, `project=*` (D3 of
epic qits-540, dossier page "Plan (as of 2026-09-13)"); or — for a commissioned credential — only
the `claims` its own commission stated (D3: no owner inheritance).

Refusals are RFC 6749 §5.2: `invalid_client` (401, with a `WWW-Authenticate` challenge),
`invalid_request` / `unsupported_grant_type` (400).

### Local Git workstations

`qits-bootstrap login` uses a public OAuth client, `qits-git-workstation`, rather than receiving a service
credential. It starts `GET /idp/authorize` in the browser with `response_type=code`, an S256 PKCE
challenge and an exact `http://127.0.0.1:<ephemeral-port>/…` callback.
The browser must already hold a `qits-session`; approval returns a two-minute, one-use code to that
loopback listener. Exchanging it at `/token` returns a fifteen-minute access token and a rotating,
opaque refresh token. Refresh-token replay revokes the entire family, and the account can revoke a
family through `/api/workstations`.

The access token is deliberately not the user's ordinary administrator identity: it has
`groups=["qits:git:external"]`, `credential_type=workstation`,
`git_ref_pattern=refs/heads/external/*`, `git_refs=["refs/heads/external/*"]`, and
`aud=["qits-platform"]` like every token — there is no githost audience any more. `/authorize`
accepts an `audience` parameter from any public client and ignores it. The githost must enforce that
ref pattern for every update; no workstation token has `qits:system`.

### Git refs

What a token may push is stated by the idp in `git_refs` and enforced by the githost. The contract
is C1/C2 of `principal-bound-git-refs-plan.md` in the qits superproject.

`git_refs` is a JSON array. Each entry is an exact ref (`refs/heads/ticket/t-1`) or a prefix
pattern ending in `/*` (`refs/heads/external/*`), and each starts with `refs/heads/`. An empty array
means "may push nothing". No claim means "no scope stated".

| token | `git_refs` | `context_kind` |
|---|---|---|
| workstation (`qits-git-workstation`) | `["refs/heads/external/*"]`, beside the older `git_ref_pattern` | — |
| CLI (`qits-cli`), and the dev SPA (`qits-landing-dev`), which gets the same token | `["refs/heads/external/*"]`, whatever the person's roles | — |
| commissioned client | the commission's `gitRefs`, when it stated them | the commission's `contextKind` |
| service client | — | — |

## Clients

There are two kinds, and they differ in where the identity comes from. **Service clients** are rows
in `idp_service_client`, created and rotated through `/idp/api/service-clients` rather than
configured (epic qits-540, dossier page "Plan (as of 2026-09-13)", contract C2). **Commissioned
clients** are rows of a different shape, in `idp_client`, because a build run or a workspace is not
a service at all.

### Service clients

`/idp/api/service-clients` is a machine surface, Basic-authenticated by the same rule as the
commission API next to it: the caller must be a service client — never commissioned — holding
`qits:system`.

**The two `GET`s also accept a bearer** (qits-162): a JWT this idp issued, with `aud` including
`qits-platform`, whose `groups` hold `qits:agent`, `qits:system`, `qits:admin` or `qits:admin-agent` (an admin
workspace's agent, admitted wherever `qits:admin` is — qits-628 follow-up) — verified in-process
against the published signing keys (`BearerCaller`). A bearer holding none of them is 403; one that
does not verify is 401 `invalid_token`. Every write stays Basic-only, so a bearer there is 401: an
agent keeps every read and gains no write.

    # create — the secret is in this answer and nowhere else
    curl -s -u dev-qits-ci:$SECRET -H 'Content-Type: application/json' \
      -d '{"clientId":"dev-qits-workspaces"}' \
      http://qits-idp:8080/idp/api/service-clients
    # 201 {"clientId":"dev-qits-workspaces","secret":"…","createdBy":"dev-qits-ci","createdAt":"…"}

| Verb | Answer |
|---|---|
| `POST /idp/api/service-clients` `{"clientId":"…"}` | 201 the pair; 409 when a row already exists; 400 for a bad id. |
| `POST /idp/api/service-clients/{id}/secret` | 200 a fresh pair; the old hash stays valid for fifteen minutes (D4), so a start-first rollback to the predecessor container is not locked out; 404 with no row. |
| `GET /idp/api/service-clients/{id}` | 200 `{clientId, source, createdAt, rotatedAt}`; 404 with no row. `source` is always `database` — there is one registry now, and the field stays so a reader that looks for it does not break. Never a secret. |
| `GET /idp/api/service-clients` | Every service client, same shape. |
| `DELETE /idp/api/service-clients/{id}` | 204; 404 unknown; 409 when a caller deletes its own row. |

The id rule (400 otherwise) is the same shape a wire alias already has: `[a-z][a-z0-9-]{0,127}`,
never a commissioned id (`dyn-…`) and never one of the public client ids.

**A service client's roles and claims are code, never configuration** (D3): `groups` is
`qits:system` plus its own `clients/<id>`, and the claim is `project=*`, because the open calling
model has it serve every project. No service client holds `qits:admin`. Its token's `aud` is
`["qits-platform"]`, like every token's.

**The first one is seeded, once**, because nothing can call this API before any service client
exists to call it with. `QITS_IDP_SEED_CLIENT_ID` / `QITS_IDP_SEED_CLIENT_SECRET`, read at the
first boot that finds `idp_seed` empty and never again — a later boot with the variables still set,
changed, or blanked does nothing once the marker row exists, and a deleted seed client does not
come back by restarting the process that made it.

**There used to be a second registry, in configuration, and qits-163 retired it.** It was
`qits.idp.clients` plus `qits.idp.client.<id>.secret`, `.audiences`, `.roles` and `.claims.<name>`,
and while services moved over an id could exist in both places. Every service has a database row
now. To carry an installation across, the first start of the version that retired it **adopts** the
old entries once (`EnvironmentClientAdoption`): for every id on `qits.idp.clients`
(`QITS_IDP_CLIENTS`) with a non-blank secret (`QITS_IDP_CLIENT_<ID>_SECRET`) and no row, it inserts
a row holding the hash of that secret, `created_by = 'adopted'`, and sets the `idp_adoption` marker
row in the same transaction. The client keeps working with the secret it already has. An id with no
secret is skipped; an id that already has a row keeps it untouched. It logs the adopted ids, never a
secret:

    adopted 2 environment service client(s) into the database: dev-qits-ci,dev-qits-workspaces

**An id that already had a row authenticates only with that row's own secret.** qits-163's hotfix
used to keep such an id's mismatched environment secret as `legacy_secret_hash` (V11), accepted with
no expiry — live, `dev-qits-edge` still held the environment one. qits-880 retired it in two
releases: release 1 logged which secret each service client authenticated with,

    service client dev-qits-edge authenticated with its current secret

once per secret per boot, to prove nothing still presented the kept one; release 2 stopped accepting
it. The line stays, naming `current` or `previous`. The `legacy_secret_hash` and
`idp_adoption.legacy_adopted_at` columns stay too, unread and unwritten, so that a rollback to
release 1 finds the data it would accept.

Once the marker exists nothing reads those keys again. The `audiences`, `roles` and
`claims.<name>` keys are not read at all.

### Commissioned clients

A service that provisions a **dynamic context** — one ci build run, one workspace, one agent
container — asks for a credential for that context and hands it back when the context ends. The
credential's lifetime *is* the context's: no lease, no TTL on the pair, nothing durable left behind.
The model, and which owner decommissions at which event, is `authenticated-reads-plan.md` in the
qits superproject.

Four verbs, all authenticated with **HTTP Basic carrying the caller's own client id and secret** —
the pair it already holds to get tokens with. No new audience, no bearer, no second credential to
distribute, and the idp does not have to validate its own tokens to answer.

    # commission — the secret is in this answer and nowhere else
    curl -s -u prod-qits-ci:$SECRET -H 'Content-Type: application/json' \
      -d '{"contextKind":"ci-run","contextId":"4711"}' \
      http://qits-idp:8080/idp/api/clients
    # 201
    # {"clientId":"dyn-ci-run-4711-8Xq…","secret":"…","owner":"prod-qits-ci",
    #  "contextKind":"ci-run","contextId":"4711","claims":{},"createdAt":"2026-08-14T11:02:03.412Z"}

    # commission SCOPED — what this context is about, and therefore what the credential may act on
    curl -s -u prod-qits-workspaces:$SECRET -H 'Content-Type: application/json' \
      -d '{"contextKind":"workspace","contextId":"1101",
           "claims":{"project":"b03b84b1-1875-4071-9dbf-854550156258"}}' \
      http://qits-idp:8080/idp/api/clients
    # 201, and every token it mints carries project=b03b84b1-…

    # commission with GIT REFS — what the credential may push
    curl -s -u prod-qits-workspaces:$SECRET -H 'Content-Type: application/json' \
      -d '{"contextKind":"workspace","contextId":"1102",
           "gitRefs":["refs/heads/epic/e-1","refs/heads/feature/e-1-a"]}' \
      http://qits-idp:8080/idp/api/clients
    # 201, "gitRefs":[…] echoed, and every token carries git_refs=[…] and context_kind=workspace

    # replace the list — the owner only; the next token carries it
    curl -s -X PUT -u prod-qits-workspaces:$SECRET -H 'Content-Type: application/json' \
      -d '{"gitRefs":["refs/heads/epic/e-1"]}' \
      http://qits-idp:8080/idp/api/clients/dyn-workspace-1102-…/git-refs
    # 200, the commission as the listing shows it

    # what this caller has out — for reconciling orphans after a crash
    curl -s -u prod-qits-ci:$SECRET http://qits-idp:8080/idp/api/clients
    # 200
    # [{"clientId":"dyn-ci-run-4711-8Xq…","owner":"prod-qits-ci",
    #   "contextKind":"ci-run","contextId":"4711","claims":{},"gitRefs":null,"createdAt":"…"}]

    # decommission — 204
    curl -s -X DELETE -u prod-qits-ci:$SECRET \
      http://qits-idp:8080/idp/api/clients/dyn-ci-run-4711-8Xq…

The rules around them:

- **A commissioned client mints exactly like a service client.** Same `POST /idp/token`, same
  grant, same token shape — which is why docker's Bearer dance and `quarkus-oidc-client` need no
  second code path.
- **Its audience is `qits-platform`**, like every token's. Nothing about it is read from its
  owner.
- **Its roles are its context kind's fixed ones — never its owner's**
  (epic qits-540, dossier page "Plan (as of 2026-09-13)", D3/D12). `CommissionRoles` is a plain code map, not
  configuration: `workspace`, `agent-container` and `refinement` get `qits:agent`;
  `workspace-admin` — the credential of an ADMIN workspace's container, which holds the host's
  docker socket — gets `qits:agent` and `qits:admin-agent`, the role every door that admits
  `qits:admin` also admits by name (qits-628 follow-up); `ci-run` and
  `bootstrap-publish` get `qits:ci-run` — publishing to qits-artifacts is CI's door, and
  `bootstrap-publish` is the short-lived identity the bootstrap commissions for its own publish
  phase and deletes when that phase ends; `ci-runner` gets `qits:ci-runner`, a CI runner's own
  identity rather than any one run's; and `ci-runner-registration` gets
  `qits:ci-runner-registration`, the credential a runner registers itself with. Agents and CI runs are domain-scoped, so neither
  inherits `qits:system` or `qits:admin`; their Git scope is their `git_refs`. **Any other kind gets no role at all** — only
  its own self-role — which is D12: an unknown kind is harmless, not refused. A credential may
  always mint and hand itself back (`DELETE` of its own id), whatever role its kind gives it. Since
  the CI-runners campaign's closing release (qits-444, 2026-09-30), qits-ci commissions `ci-run` as a
  **token** (see "Commissioned tokens" below) rather than as a client; `bootstrap-publish` is still
  commissioned as a client, unchanged.
- **Reads accept `qits:agent`; writes do not.** Agents keep every read they have and lose only
  write access (user ruling 2026-09-12). Here that is `GET /idp/api/clients`, which accepts
  `qits:system` or `qits:agent` — not `qits:ci-run`, so a CI run's credential gets 403 there.
  `POST`, `PUT` and `DELETE` are unchanged.
- **Its Git refs are its own.** The optional `gitRefs` member states what the credential may push;
  every token then carries it as `git_refs`. Not stated means no claim, as before. The rules, each a
  400 with nothing written: every entry starts with `refs/heads/`; `*` only as a trailing `/*`; at
  most 500 entries; each at most 255 characters; no repeats; no control characters. `PUT
  …/{clientId}/git-refs` with `{"gitRefs":[…]}` replaces the list: the owner only (a commissioned
  caller is 403; another owner's client or an unknown id is 404). It must state a list — `[]` for
  "push nothing" — because going back to "no list" would widen the credential. See
  `control/GitRefs`.
- **Its claims are its own, and only its own** (D3: a commission no longer inherits its owner's
  claims). The optional `claims` member states what this context is *about* —
  `{"project":"<projectId>"}` for a workspace — and those, and only those, land on the row and go
  into every token it mints. A commission that states nothing carries no claims at all any more.
  **`*` is refused with `invalid_request` (400)**: a concrete value is narrower than saying nothing
  (a resource service reads an absent claim as "unscoped" and answers it from roles), while `*` is
  the one value that is never a narrowing — it stays a service client's own fixed claim, which no
  request can state. Only `project`,
  `workspace` and `branch` may be stated; any other name is a 400. See `control/CommissionedClaims`.
- **Its self-role is its own, never its owner's.** `clients/dyn-…` is stamped from the id in `sub`,
  so a credential commissioned by a service cannot walk through a door held open for that service.
- **Only a service client may commission** — one with an `idp_service_client` row, never a commissioned one. A
  commissioned credential authenticates here — so a context can hand its own credential back — but
  `POST` refuses it, and the blast radius of a leaked one therefore stops at one context.
- **Decommission is deleting the row**, and it is immediate: the credential mints nothing from the
  next request onward. **Tokens it already minted live out their `exp`**, because validation is
  offline against the JWKS and there is no revocation list. With the shipped hour that grace is an
  hour — see `qits.idp.token-ttl-seconds`, where the trade is written down.
- **Only the owner may decommission or list**, or the credential itself for its own row. Anyone
  else is told exactly what a caller naming an id that never existed is told.
- **The secret is returned once.** The row holds a SHA-256 of it, so a dump of the idp's database
  mints nothing. A caller that lost the secret decommissions and commissions again.
- **The id reads in a listing** — `dyn-<kind>-<context slug>-<random>` — and cannot collide with a
  service client's name, because no service client id may carry the `dyn-` prefix.

### Commissioned tokens

The third credential, beside service clients and commissioned clients: an **opaque token** a
service client commissions for one dynamic context — the same `contextKind` and `contextId` a
commissioned client is bound to, with the same optional `claims` and `gitRefs`. It carries nothing
inside; the only way to learn anything from one is to ask this service, and that is the point. A
commissioned client's JWT is verified offline, so a deleted client's last token lives out its `exp`;
a deleted token is refused on the very next introspection.

The owner authenticates with **HTTP Basic carrying its own client id and secret**, as on the
commission API.

    # commission — the token is in this answer and nowhere else
    curl -s -u prod-qits-ci:$SECRET -H 'Content-Type: application/json' \
      -d '{"contextKind":"ci-runner","contextId":"runner-7","gitRefs":[]}' \
      http://qits-idp:8080/idp/api/tokens
    # 201
    # {"tokenId":"5b1c…","token":"qits_tok_Qm9…","subject":"tok-ci-runner-runner-7-kF3…",
    #  "owner":"prod-qits-ci","contextKind":"ci-runner","contextId":"runner-7","claims":{},
    #  "gitRefs":[],"createdAt":"2026-09-27T11:02:03.412Z"}

    # what this caller has out — for reconciling orphans; never a value
    curl -s -u prod-qits-ci:$SECRET http://qits-idp:8080/idp/api/tokens
    # 200 [{"tokenId":"5b1c…","subject":"tok-ci-runner-runner-7-kF3…","owner":"prod-qits-ci", …}]

    # delete — the owner; 204
    curl -s -X DELETE -u prod-qits-ci:$SECRET \
      http://qits-idp:8080/idp/api/tokens/5b1c…

    # self-delete — the token hands itself back, presented raw; 204
    curl -s -X DELETE -H "Authorization: Bearer qits_tok_Qm9…" \
      http://qits-idp:8080/idp/api/tokens/5b1c…

    # introspect — what the edge asks; answers the token and a JWT minted for it
    curl -s -u prod-qits-edge:$SECRET -H 'Content-Type: application/json' \
      -d '{"token":"qits_tok_Qm9…"}' \
      http://qits-idp:8080/idp/api/tokens/introspect
    # 200
    # {"tokenId":"5b1c…","subject":"tok-ci-runner-runner-7-kF3…",
    #  "roles":["qits:ci-runner","clients/tok-ci-runner-runner-7-kF3…"],"claims":{},"gitRefs":[],
    #  "contextKind":"ci-runner","contextId":"runner-7","accessToken":"eyJ…","expiresIn":300}

The rules around them:

- **A token has no expiry.** There is no TTL and no deadline column: its lifetime is its context's,
  exactly like a commissioned client's. **Deleting it is the whole revocation, and it is immediate
  for the next introspection** — nothing caches a token here.
- **The value is `qits_tok_` plus 32 random bytes, base64url**, so a hop recognises a token without
  asking — the edge sends a `qits_tok_` bearer to introspection and anything else to the JWKS check,
  and never the other way round. The row holds a SHA-256 of it; a dump of the store mints nothing.
  The value is returned once and never logged; a caller that lost it deletes and commissions again.
- **The subject is `tok-<kind>-<context slug>-<random>`**, disjoint from a commissioned client's
  `dyn-…` and from every service client's name.
- **Its roles are `CommissionRoles.forKind(contextKind)`, never the owner's** — the same code map a
  commissioned client of that kind gets. Its claims and Git refs are only what it stated, checked by
  the same rules as a commissioned client's, each a 400 with nothing written.
- **Only a service client commissions** — holding `qits:system`. A
  commissioned client is 403, and a token cannot authenticate to `POST` at all: it is not a client.
- **`GET` accepts `qits:system` or `qits:agent`**, like `GET /idp/api/clients`, and lists only the
  caller's own.
- **`DELETE` is the owner's, or the token's own.** The owner uses its Basic pair; a token presents
  itself as `Authorization: Bearer qits_tok_…` and may delete only the id it is. Another owner, a
  live token naming a different id, an unknown id and a malformed id are all the same 404; a bearer
  that is no live token is a 401.
- **Introspection is the session door's twin, and it also mints.** `POST
  /idp/api/tokens/introspect` takes the caller rule of `POST /idp/api/sessions/introspect` verbatim —
  a service client holding `qits:system`, a commissioned client 403 — and answers one 404, `no live
  token for that value`, for an unknown value, a deleted row and an owner that no longer exists. A
  value without the prefix is refused before any store read. The 200 carries `accessToken`: a JWT
  minted exactly as `/idp/token` would mint one for a commissioned client of that kind — `sub` the
  token's subject, `aud` `["qits-platform"]`, `groups` its kind's roles plus
  `clients/<subject>`, its own `claims`, `context_kind` and `git_refs` — so the service behind the
  edge verifies an ordinary JWT. That JWT lives `qits.idp.token-introspection-jwt-ttl-seconds` (300
  by default), which is the upper bound on how long a deleted token keeps working **behind** the
  edge; at the edge the bound is its own cache, `qits.edge.auth.token-cache-ttl-ms` (15 s).

## Users

Accounts are **per-installation**. They live in this service's store and survive deploys and
restarts like every other idp row, and they are never shared or migrated between installations: the
localhost platform now and a domain-hosted one later each start from their own register token. That
is the decision that makes a passkey's binding to one host a non-issue.

The user row is minimal on purpose — an id, a unique username, an optional password hash — and
**there is no role column**. Roles are `idp_user_role`, an assignment table, from day one. The
strings are namespaced `$app:$resource:$role` with the middle segment omitted while unused; a
bootstrap registration grants `qits:admin` and `qits:admin` and nothing else writes the
table today. The idp stores them and interprets none of them.

### Getting the first account

A register token is a row, minted through the API, printed by the bootstrap — never logged, because
this service's logs ship to qits-observability and a credential must not ride the log plane. It is
good for exactly one account, and only a **service** client may mint one (the commissioning
rule, reused).

    # mint — the token is in this answer and nowhere else
    curl -s -X POST -u prod-qits-ci:$SECRET \
      http://qits-idp:8080/idp/api/register-tokens
    # 201 {"id":"…","token":"CUiyE4rThoFF…","createdAt":"…"}

Registration is then two calls from the browser: `POST /idp/api/auth/register-options` with the
token and a username, which answers the WebAuthn creation options verbatim for
`navigator.credentials.create()`, and `POST /idp/api/auth/register` with the resulting attestation.
**The token is checked at the first call**, before any ceremony state exists, so an authenticator is
never asked to make a key that will be thrown away. The second call creates the account, stores the
passkey, spends the token, grants the two roles and opens a session — one transaction.

`{"password":"…"}` instead of an attestation registers without a passkey. That path exists for
automated callers and for the one browsing route with no secure context (see below).

### Logging in, and the session

`POST /idp/api/auth/login-options` then `.../login` with the assertion, or one `.../login` with
`{username, password}`. Either way the answer is the same four fields and a cookie:

    Set-Cookie: qits-session=<43 chars>; Path=/; Domain=wohlben.eu; Max-Age=43200; HttpOnly; SameSite=Lax

`Secure` is appended when the request — or `X-Forwarded-Proto` — says https. `Domain=` is the stated
domain itself, so the apex and every browser host under it share one login; localhost has no parent
and leaves it host-only. `Path=/` because the cookie is for the **edge**, which
introspects it on requests to every segment, not for this service. The edge removes this named
cookie before proxying to machine-only registry, mirror, and git-host vhosts.

WebAuthn still runs only at the canonical apex origin. An unauthenticated environment navigation is
sent there with a return authority and path; after login or registration the SPA asks
`GET /idp/api/auth/return-location`. This service validates the authority against its browser-host
allow-list and returns an absolute location. A public query string therefore cannot turn the login
page into an open redirect.

**Nothing on the browser boundary is configuration.** The platform's domain is one fact —
`QITS_DOMAIN`, the bootstrap's own `--domain` input, propagated into every container by
qits-deployments — and `DerivedBrowserHosts` reads it once and hands `PlatformDomain` everything
else:

| composed | public installation | with none stated |
| --- | --- | --- |
| the canonical origin | `https://idp.qits.<domain>` | `http://localhost:8080` |
| the session cookie's parent | `<domain>` | host-only |
| `quarkus.webauthn.relying-party.id` | `<domain>` | `localhost` |
| `quarkus.webauthn.origins` | the canonical origin | `http://localhost:8080` |
| the return-host allow-list | `<domain>` and `*.<domain>` | `localhost:8080` and `*.localhost:8080` |

`idp` is this repository's `host:` in `.config/qits/deployments.yml` and `qits` is the platform's own
project slug, which is env-less — so the origin is the platform's hostname grammar applied to this
application like to any other. The slug is one named constant, not a literal per derivation.

Four of those used to be keys — `QITS_IDP_BROWSER_SSO_CANONICAL_ORIGIN`,
`QITS_IDP_BROWSER_SSO_COOKIE_DOMAIN`, `QITS_IDP_WEBAUTHN_RP_ID` and `QITS_IDP_WEBAUTHN_ORIGINS` —
injected from outside this repository, and three of them still said `idp.dev.qits.wohlben.eu` after
the `qits` project went env-less, an address that had stopped resolving. They restated a fact
`QITS_DOMAIN` already carried, so nothing here could notice they had gone stale. **A value nobody
can set is a value nobody can leave behind.** A deployment that still sets any of the four is
ignored.

The derived pair is also **cross-checked at startup**: `BrowserSso` reads `quarkus.webauthn.origins`
back and refuses to start unless it names the canonical origin. webauthn4j compares the origin
inside the browser's own `clientDataJSON` against that list and against nothing else, so a
disagreement fails every passkey ceremony closed — registration and login alike — with no
configuration error logged anywhere. Both sides come from one value now, which is why the check
should be impossible to trip and why it is worth making.

**The allow-list in particular is not configuration.** It is derived from that same domain as
exactly two entries: the exact authority `<domain>`, and the wildcard `*.<domain>`, which matches
up to **three** extra labels in front of it. Three is the hostname grammar's own depth: a name is
`<app>[.<env>].<project>.<domain>` read right to left, so the two entries cover `wohlben.eu`,
`qits.wohlben.eu`, `projects.qits.wohlben.eu`, `dev.qits.wohlben.eu` and
`projects.dev.qits.wohlben.eu` — every application, of every project, in every environment, with
this service knowing no project and no environment name. A fourth label is not a name the grammar
can produce and is refused.

The port is part of an authority, so the canonical origin's port (where it has one) is appended to
both derived entries: locally the domain is `localhost` and the list is `localhost:8080` and
`*.localhost:8080`, which refuses `qits.localhost:9090`. The session cookie already spans those
hosts through `Domain=<parent domain>`, and WebAuthn is untouched because the ceremony still runs
only at the canonical origin.

**Three labels is a wider allow-list and not a wider trust boundary.** The wildcard is anchored
under the platform's own domain by construction, and the zone points `*`, `*.*` and `*.*.*` at the
platform's edge, where a name no vhost claims answers 404. An extra label therefore reaches deeper
*under* names the one-label rule already admitted, all of them served by this platform, so it opens
no redirect to a foreign host. The anchor is what carries that argument, not the label count: an
entry whose parent authority is not the platform's own domain would already have been an open door
at one label, and a derived list cannot produce one.

The process refuses to start when the derived list does not name the canonical origin's own
authority. With a list derived from the domain that can only mean the domain or the canonical
origin is wrong, which is exactly when starting anyway — and issuing bounces nobody can return
from — would be worse than not starting.

The value is 256 random bits and nothing else. This store holds a `sha-256:` fingerprint of it, so a
dump of the idp's database logs nobody in, and the only way to learn anything from a cookie is
`POST /idp/api/sessions/introspect` — Basic, a service client, the edge's own `{env}-qits-edge`
credential:

    curl -s -u prod-qits-edge:$SECRET -H 'Content-Type: application/json' \
      -d '{"token":"<cookie value>"}' \
      http://qits-idp:8080/idp/api/sessions/introspect
    # 200 {"userId":"…","username":"alice","roles":["qits:admin"],
    #      "expiresAt":"2026-08-15T05:48:00.427825Z"}
    # 404 for anything not live — unknown, expired or revoked alike

**An opaque cookie rather than a JWT the edge could verify offline** is the trade this service
makes: it costs one cached call per request and it buys revocation, because logout is a row update
and there is no revocation list to distribute. Revocation therefore lags at the edge by its own
cache TTL — seconds, configurable there, and stated so nobody files it as a bug.

Sessions expire absolutely, `qits.idp.session-ttl` after they open (PT12H). There is no sliding
renewal yet.

### Passkeys, and the one route without them

The ceremony is quarkus-security-webauthn used **as a library**: this service calls it, verifies the
attestation and the assertion itself, and issues its own session. The extension's built-in endpoints
are off and its own `quarkus-credential` cookie is never written.

`quarkus.webauthn.relying-party.id` and `.origins` are **derived from the stated domain** and are
not settable: the rp id is the domain, flat, and the origin list is the canonical origin. See the
table above. The rp id is flat so that one passkey asserts on every host of the installation — a
ceremony's rp id must be the page's origin or a parent of it, and the apex is the only parent every
application shares.

**A passkey is bound to the rp id it was registered under** and will not assert under another, so
changing the stated domain invalidates every credential on the estate. **There is deliberately no
override to pin the old value across such a move.** It was proposed and declined: *"if a domain
change means breaking them, then that means breaking them. thats not an issue."* Accounts here are
per-installation by decision, a new domain is a new installation in every way that matters, and a
key existing only to survive one event would be set wrong on every deployment in between. The
reasoning is restated in `PlatformDomain.relyingPartyId`, where the next person to reach for an
override will read it.

`localhost`, `*.localhost` and the loopback addresses are secure contexts over plain http by browser
rule, so passkeys work on `http://localhost:8080` with no TLS. The one route that is **not** a
secure context is a raw IP — `http://<wsl-ip>:8080`, today's Windows-browser path to this platform —
where `navigator.credentials` does not exist at all and only the password fallback logs in. TLS via
`QITS_DOMAIN`, or Windows reaching localhost again, dissolves it.

## The signing key

Generated on the first start that finds no active key, and stored in the `idp` datasource as PKCS#8
PEM with a random `kid`. Every start after that reads it back. **That row is the only reason a token
issued before a restart still verifies after one** — an idp pointed at a fresh or ephemeral database
rotates its key by accident and invalidates everything in flight.

The datasource is a **PostgreSQL database of this service's own**, provisioned for it and handed
over as the platform's generic resource triple: `QITS_RESOURCE_DB_URL`, `_USERNAME`, `_PASSWORD`.
`.config/qits/deployments.yml` declares `resources: postgresql:db`, which is what makes
qits-platform-deployments create the role and the database `qits_platform_idp` before the successor
container starts; at bootstrap, before any deployer exists, the CLI does the same. There is no
default and no fallback URL — a process handed none stops at Flyway rather than opening a store
nobody meant.

The table holds many keys with one active, so rotation is a data change: insert a new `ACTIVE` row,
retire the old one, and both keep being published until the old one's tokens have expired.
`SigningKeys.reload()` is what picks the change up.

## Building and running

`./mvnw verify` on a clone is the gate — no monorepo, no docker, no prior install. It does need two
things a clone alone does not have: **the client submodule and a node**.

    git submodule update --init      # service/src/main/webui, or the build stops at
                                     # "No package.json found in Web UI directory"

Node must be on `PATH` at the platform's pin or newer (22.22.0), because `verify` runs `package` and
Quinoa shells out to the host's npm. Nothing downloads a toolchain for you — that is deliberate, and
the fix for a machine with no node is node, not a config key. `./mvnw test` still needs neither, as
Quinoa is disabled in test mode.

The suite takes a free port (`service/src/test/resources/application.properties` sets
`quarkus.http.test-port=0`), because on the deployment host 8081 is the platform's npm registry.

    ./mvnw verify                    # the @QuarkusTest suite
    ./mvnw verify -DskipITs=false    # plus IdpPackagedSurfaceIT, against the fast-jar
    ./mvnw verify -Dnative           # plus the same IT, against the GraalVM binary

The suite opens a real PostgreSQL — zonky's binaries, resolved as ordinary Maven artifacts and
spawned as a child process. Still no docker.

`docker/Dockerfile` ships the native binary. Read its header before deploying: the container refuses
to boot without the `QITS_RESOURCE_DB_*` triple, and that is deliberate.

## What is not here yet

**Per-context scoping beyond claims and Git refs.** A commissioned credential is narrowed by the
claims and Git refs its commission states, and its roles are its kind's own, fixed in code
(`CommissionRoles`), or none at all. Every token's audience is `qits-platform`, so narrowing where
a token may be presented is not a lever any more; narrowing what it may do is roles and claims.

**Authorization.** Roles are stored, reported by introspection and delivered to every service, and
**nothing enforces one yet**. Which route demands which role is a later plan, together with
per-context scoping on dynamic clients.

**Invites for user #2, and an account page.** The register-token API already has the shape an invite
needs — a session-authenticated user minting one — but the UX is undecided, and there is no listing
of a user's own authenticators or sessions to remove one from.

**Sliding session renewal, and "remember me".** The TTL is absolute. Logging in again is one
ceremony, so this is a comfort question rather than a blocker.

**An authorization-code flow for third-party apps.** Nothing first-party needs it — the UI is
first-party and the edge terminates its session — but the issuer core is ready if it ever comes.
Note that `qits-idp-plan.md`'s phase 3 described users arriving as an OAuth dance against this
service with the session at the gateway; that is superseded by `user-authentication-plan.md`, and
phase 2 also landed differently from that sketch (no lease TTL, no granting template).
