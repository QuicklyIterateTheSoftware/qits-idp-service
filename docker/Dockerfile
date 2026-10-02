# qits-platform-idp as a GraalVM-native container IMAGE — the same shape as its siblings'
# docker/Dockerfile: a Mandrel builder stage compiles the binary, a minimal runtime stage carries
# only it.
#
# This file is not how the binary is built; it is how the binary is SHIPPED. `.sdkmanrc` names a
# GraalVM (25.0.2-graalce), so `sdk env && ./mvnw package -Dnative` produces
# `service/target/qits-idp` with no container involved.
#
# Build from the repo root:
#
#     docker build -t qits/idp:latest -f docker/Dockerfile .
#
# THERE IS A CLIENT NOW, and it is NOT built here — it arrives in the build context already built.
# The whole of why is with the mvnw line below, where the five flags that arrange it live.
#
# --- this image does NOT run with an empty environment, and that is not a packaging bug ------------
# `docker run --rm qits/idp:latest` dies before the HTTP listener: the `idp` jar ships its datasource
# as ${QITS_RESOURCE_DB_URL} and its two siblings with NO fallback, so an unset triple leaves the
# expression unresolvable and the process stops at Flyway. IT IS DELIBERATELY LEFT THAT WAY (the
# qits-ci stance), and here the stake is higher than for any sibling:
#
#   THE SIGNING KEY LIVES IN THAT DATABASE. An idp that came up healthy against a store nobody meant
#   would generate a new keypair, and the next redeploy another one — invalidating every token in
#   flight, everywhere, with nothing in any log to say why. A container that refuses to start is the
#   failure you see; one that starts on a store of its own invention is the failure that hides for a
#   week.
#
# The triple is NOT set by hand. `.config/qits/deployments.yml` declares `resources: postgresql:db`,
# and qits-platform-deployments creates the role and the database on the tier's postgres before this
# container starts and injects all three; at bootstrap, before any deployer exists, the CLI does the
# same over plain JDBC. What a `docker run` by hand looks like, and what those two produce:
#
#   docker run \
#     -e QITS_RESOURCE_DB_URL=jdbc:postgresql://prod-qits-oci-postgresql:5432/qits_platform_idp \
#     -e QITS_RESOURCE_DB_USERNAME=qits_platform_idp \
#     -e QITS_RESOURCE_DB_PASSWORD=... \
#     -e QITS_IDP_CLIENT_PROD_QITS_CI_SECRET=... \
#     ...
#
# No volume, and that is the change: the store is a database on another host now, so this container
# keeps nothing that has to outlive it.
#
# --- what else a deployment owns ------------------------------------------------------------------
#
#   QITS_IDP_CLIENT_<ID>_SECRET
#                           EVERY STATIC CLIENT SHIPS WITHOUT A SECRET AND IS THEREFORE UNUSABLE.
#                           That is the safe direction — a blank secret is refused, never accepted —
#                           but it also means an idp nobody configured issues nothing at all, and
#                           the only symptom is `invalid_client` in the caller's log. The client ids
#                           are the names each service is DIALED by: prod-qits-ci,
#                           qits-platform-artifacts, prod-qits-workspaces.
#   QITS_DOMAIN             the platform's domain. The `iss` of every token is DERIVED from it —
#                           https://idp.qits.<domain>, never configured (qits-730) — as is the
#                           whole browser boundary. qits-deployments sets it on every container.
#   QITS_OBSERVABILITY_URL  where OTLP export goes; absent qits-observability, the exporter logs a
#                           warning per export loudly enough to bury real lines
#                           (OTEL_SDK_DISABLED=true is the escape hatch).
#
# This image needs no docker socket and no git. It dials exactly one host — the postgres its
# datasource names — and otherwise only answers the callers that dial it.
#
# --- stage `build`: native-compile ----------------------------------------------------------------
# The builder JDK MUST be 25: native-image cannot read bytecode newer than its own JDK, and this
# project targets release 25.
#
# The mirror vhost, like every sibling's FROM, not the bare upstream this file used to spell: the
# platform builder resolves the committed reference through its own registry config, and a bare
# `quay.io/…` there would dial upstream directly — the loud form of a pull the offline posture
# forbids. A developer's `docker build` resolves the same spelling through the host daemon exactly
# as before. The tag is upstream's, unchanged.
FROM mirror.dev.localhost:8080/quay/quarkus/ubi9-quarkus-mandrel-builder-image:jdk-25 AS build
USER root
WORKDIR /src

# Fetch the Maven distribution first, keyed only on the wrapper files, so a source-only change does
# not re-download it.
COPY mvnw .
COPY .mvn/ .mvn/
RUN ./mvnw --version

# The whole reactor, not a module list. `-am` builds `service`'s dependency from source —
# `qits-idp-domain` is a version this repo never publishes, so a builder container with an empty
# ~/.m2 has nowhere else to get it. `.dockerignore` is what keeps this cheap.
COPY . .

# Tests are skipped because `./mvnw verify` on a clone is their gate (AGENTS.md); stopping at
# `package` rather than `verify` keeps IdpPackagedSurfaceIT out of the image build. Cap
# native-image RAM so the build is deterministic on small machines.
#
# --- node, and the three command overrides: why the client is NOT built here ----------------------
# The two `package-manager-install` flags give this stage a node: the Mandrel builder image ships
# none at all, and Quinoa shells out to npm regardless. They live here rather than in
# application.properties on purpose — a local or CI `mvnw` build must use the node on PATH, so that
# no build silently downloads a toolchain. The version is the PLATFORM pin (22.22.0), and it does
# not have to match the step container's node, because this stage does not build the bundle.
#
# service/src/main/webui is qits-platform-spa-idp, and it depends on @qits/ui-components. That
# package exists ONLY on the platform's own npm registry (qits-artifacts). A RUN step in a docker
# build reaches the public internet — Maven Central, npmjs.org, nodejs.org — and reaches the
# platform registry by NO address: not the qits-net alias, not registry.dev.localhost:8080, not
# host.docker.internal. So the install cannot happen here.
#
# It does not merely fail, it fails unreadably. The SPA commits an .npmrc pointing at the edge's
# registry vhosts (right for a developer on the deployment host), npm ranks a project .npmrc above
# ~/.npmrc, and npm's answer to a registry that never connects is `Exit handler never called!` — its
# own internal-error text, naming neither the registry nor the address. That is what a build here
# looks like; it is not a hint that something is retryable.
#
# The bundle is therefore built BEFORE this image, by the pipeline step in
# .config/qits/ci-post-receive.yml, which runs on qits-net where the registry is reachable, and
# arrives in the build context as service/src/main/webui/dist/ (see .dockerignore, which stops
# excluding exactly that path for this reason). `--version` is the null command: it proves the
# package manager is really there and does nothing else.
#
# THIS DOES NOT FAIL QUIETLY. The `test -f` below stops a context with no bundle before the
# multi-minute native compile, and Quinoa's own build-dir check would stop it after. A forgotten
# `npm run build` in the step is a red build, not an idp that ships without its client. The same
# guard covers a context whose webui submodule is NOT initialised: it has no bundle either, and
# stops here rather than at Quinoa's `No package.json found in Web UI directory`.
#
# --- and why the bundle is copied onto itself first -----------------------------------------------
# Quinoa does not copy build-dir into target/quinoa/build, it MOVES it, and overlayfs cannot rename
# a directory that still lives in a LOWER image layer. It answers EXDEV, the JDK falls back to its
# cross-file-store path, and that path refuses a non-empty directory — the build dies seconds in
# with `DirectoryNotEmptyException: …/dist/qits-platform-spa-idp/browser`, which names the source and
# explains nothing. A builder stage that *creates* dist itself is immune by accident, because dist
# is then already in the upper layer; ours arrives by COPY, so it is not.
#
# One `cp` re-materialises it in the layer that is about to move it. It has to be in THIS `RUN` and
# not a tidier one of its own — a layer boundary is exactly what it is undoing.
#
# --- where the two qits jars come from ------------------------------------------------------------
# This repo depends on qits-db-core (PatientPgDriver) and qits-arch-rules, which live only on the
# platform's own Maven repository. The CI recipe passes the address the step container can reach, and
# `.qits-maven-settings.xml` mirrors the `qits-maven` repository id onto it — an exact id match,
# which is what gets past Maven's external:http:* blocker without permitting arbitrary HTTP
# repositories. The ARG default is the developer-host address, so a plain host-side `docker build`
# still works.
ARG QITS_MAVEN_REPOSITORY_URL=http://registry.dev.localhost:8080/artifacts/maven/maven
ENV QITS_MAVEN_REPOSITORY_URL=$QITS_MAVEN_REPOSITORY_URL
#
# --- and where Maven Central is mirrored, when it is ----------------------------------------------
# The pipeline passes the platform's pull-through (qits-platform-mirror's central proxy; the FROM
# lines above name upstream directly, so this is the one mirrored hop in this file); EMPTY — the
# default — means direct Maven Central.
# `.qits-maven-settings.xml` activates its central-proxy profile only on a non-empty value, so a
# bootstrap or hand build that passes nothing resolves exactly as it always did.
ARG QITS_MAVEN_CENTRAL_URL=
ENV QITS_MAVEN_CENTRAL_URL=$QITS_MAVEN_CENTRAL_URL
#
# --- and the credential that answers the registry's 401 -------------------------------------------
# Once reads through the edge are gated, that resolve needs one. It arrives as two BuildKit secret
# mounts, which reach THIS `RUN`'s environment and nothing else — not a layer, not the image
# history. A `--build-arg` would be recorded there, on an image anyone can pull, which is the whole
# reason this is a mount. `.qits-maven-settings.xml` reads the pair as the `qits-maven-network`
# server. This service mints those clients; its own build consumes one like every other repository's.
#
# Absent secrets leave both variables empty and the resolve anonymous — today's state, and a
# developer host's permanently, because Maven sends credentials only when a repository answers 401.
#
# FILE FORM (`/run/secrets/<id>`, read into the command's own environment below), never the `env=`
# mount form these two lines used to carry. `env=` needs a dockerfile frontend the BUILDER chooses,
# and since the builds moved to the platform's buildkitd the frontend is the builder's to pick, not
# this file's; the bare file mount is served identically by every frontend version.
RUN --mount=type=secret,id=qits-client-id \
    --mount=type=secret,id=qits-client-secret \
    export QITS_MAVEN_AUTH_USR="$(cat /run/secrets/qits-client-id 2>/dev/null || true)"; \
    export QITS_MAVEN_AUTH_PSW="$(cat /run/secrets/qits-client-secret 2>/dev/null || true)"; \
    d=service/src/main/webui/dist/qits-platform-spa-idp/browser; \
    test -f "$d/index.html" || { \
      echo "No built client SPA at $d." >&2; \
      echo "The build context must carry one: run 'npm ci && npm run build'" >&2; \
      echo "in service/src/main/webui first — this stage cannot, see the Quinoa flags above." >&2; \
      exit 1; }; \
    cp -a "$d" "$d.layer" && rm -rf "$d" && mv "$d.layer" "$d" && \
    ./mvnw -B -ntp -s .qits-maven-settings.xml -pl service -am package -Dnative -DskipTests \
      -Dqits.maven.repository.url="$QITS_MAVEN_REPOSITORY_URL" \
      -Dquarkus.native.native-image-xmx=4g \
      -Dquarkus.quinoa.package-manager-install=true \
      -Dquarkus.quinoa.package-manager-install.node-version=22.22.0 \
      -Dquarkus.quinoa.package-manager-command.install=--version \
      -Dquarkus.quinoa.package-manager-command.ci=--version \
      -Dquarkus.quinoa.package-manager-command.build=--version \
      org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeBom \
      -DoutputFormat=json -DoutputName=sbom -DschemaVersion=1.6 \
      -Dcyclonedx.skipNotDeployed=false
# cyclonedx.skipNotDeployed=false is LOAD-BEARING, measured on qits-artifacts-service's first SBOM
# release (2026.902.45658): the service module skips maven-deploy — it ships as this image, not as a
# jar — and the plugin SKIPS deploy-skipping modules by default, with a green build and one INFO
# line. The sbom stage's COPY then fails on a file nothing wrote. The spelling matters too: the bare
# -DskipNotDeployed=false is silently ignored; only the cyclonedx.-prefixed one reaches the plugin.

# --- sbom -----------------------------------------------------------------------------------------
# The service module's CycloneDX document, exported so the release step can PUT it to the platform's
# SBOM store. A stage rather than a layer of the runtime image, and BEFORE the runtime stage on
# purpose: the last stage is what a plain `docker build` builds, and that must stay the image. The
# release step reaches this one with `--target sbom --output type=local` using the SAME args and
# secrets as the image build, so every layer above is a cache hit and the export costs seconds.
# `makeBom` rides on the mvnw invocation above rather than a second one, for the same cache reason —
# one RUN, one layer, one truth.
FROM scratch AS sbom
COPY --from=build /src/service/target/sbom.json /sbom.json

# --- runtime --------------------------------------------------------------------------------------
# The mirror vhost for the same reason as the builder stage's.
FROM mirror.dev.localhost:8080/redhat/ubi9/ubi-minimal:9.6
WORKDIR /work

# curl, so the container answers a docker healthcheck — the deployer injects one at `docker run`
# and polls it through `docker inspect`, and the probe runs INSIDE the container.
# UBI minimal already supplies curl-minimal; assert it is present without installing the
# conflicting full curl package.
RUN curl --version >/dev/null

# `quarkus.package.output-name` names the binary `qits-idp` (no -runner suffix), so the process is
# identifiable in `ps`/`docker top`. That name is spelled a third time in service/pom.xml as
# failsafe's `native.image.path`; all three move together.
COPY --from=build --chown=1001:root /src/service/target/qits-idp /work/qits-idp
RUN chmod +x /work/qits-idp

EXPOSE 8080
USER 1001

# Quarkus binds 127.0.0.1 outside dev mode, which inside a container means nothing can reach it —
# not the gateway, not a peer on qits-net.
ENTRYPOINT ["/work/qits-idp", "-Dquarkus.http.host=0.0.0.0"]
