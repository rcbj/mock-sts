# The mock STS: sixteen protocol families in one small Node service. See README.md.
#
# Pinned to Node 24.16.0 via nvm rather than an official node image, which is what
# the project this was extracted from does for all of its services.
FROM ubuntu:latest

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Create app directory
WORKDIR /usr/src/sts

RUN apt-get update
RUN apt-get -y install curl \
        jq \
        wget \
        unzip \
        util-linux \
        bsdextrautils

# Install NVM
ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN set -o pipefail && curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash

# Load NVM and install Node.js
RUN . $NVM_DIR/nvm.sh && nvm version && echo -e ". $NVM_DIR/nvm.sh\nexport PATH=\$NVM_DIR/versions/node/\$(nvm version)/bin:\$PATH" >> ~/.bashrc
RUN cat ~/.bashrc

RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

# add node and npm to path so the commands are available
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

# confirm installation
RUN node -v
RUN npm -v

# Install dependencies (package-lock.json is optional; wildcard copies it when
# present so `npm ci`-style reproducibility works once a lock is committed).
COPY package*.json ./
# The LDAP server's library is `"ldapjs": "file:node-ldapjs"` — the git SUBMODULE,
# not a registry package — so it has to be in the build context BEFORE npm runs or
# the install fails with EUNSUPPORTEDPROTOCOL/ENOENT naming a path rather than a
# submodule. It is copied here, ahead of the source, so that editing this service
# does not invalidate the install layer.
#
# An UNINITIALISED SUBMODULE IS AN EMPTY DIRECTORY, and this is where that shows
# up: the COPY succeeds, npm installs a package with no main, and the failure
# arrives at runtime as `Cannot find module 'ldapjs'` from ldap_server.js. Run
# `git submodule update --init --recursive` — --recursive because this repository
# is itself a submodule of the parent project, and a plain --init there stops one
# level short of this one.
#
# .npmrc carries `omit=dev`, and it is load-bearing rather than tidiness: npm
# installs the devDependencies of a `file:` dependency, and ldapjs's are tap and
# eslint — some 200 packages and a dozen advisories that have nothing to do with
# this service. The flag below says the same thing twice on purpose, so that a
# build which loses the .npmrc does not quietly start shipping them.
COPY .npmrc ./
COPY node-ldapjs ./node-ldapjs
RUN npm install --omit=dev && npm cache clean --force

# THE WHOLE SOURCE TREE IN ONE LINE, and that is deliberate rather than lazy.
#
# The service is a shell: server.js requires the other modules and listens, so a
# module that never reaches the image is not a missing feature but a
# MODULE_NOT_FOUND before anything binds the port — the container never answers
# /healthcheck and every STS-backed job in the parent project's suite fails on a
# timeout that says nothing about the cause.
#
# This used to be `COPY *.js ./` plus one line each for contexts, protos and env,
# and the wildcard's comment said why: a per-file list would have to be edited
# every time a module was added, and forgetting is silent until the containerized
# run. The 2026-08-23 reorganisation moved every module into a subdirectory
# (common/, oauth-oidc/, kerberos/, ldap/, scim/, spiffe/, admin-ui/, mgmt-api/
# and the rest), which put that exact trap back one level up: a per-DIRECTORY
# list has the same failure, and a new protocol family is a likelier thing to add
# than a new sibling of server.js ever was.
#
# So the context is copied whole and .dockerignore decides what is in it. That is
# the only arrangement in which adding a directory cannot be forgotten. Three
# things ride along that are read AT REQUIRE TIME and whose absence is a service
# that does not start rather than a degraded feature, which is the reason to be
# sure they are here:
#
#   common/vendored/contexts  the JSON-LD contexts bbs2023.js loads at module
#                             scope. They are a SIBLING of that module because it
#                             is a byte-identical copy of the parent project's
#                             and resolves path.join(__dirname, 'contexts') — so
#                             they move when it moves and the file is not edited.
#   spiffe/protos             the SPIFFE project's own workloadapi.proto and the
#                             spire-api-sdk's, read by spiffe/spiffe_grpc.js at
#                             module scope. Verbatim: the wire matching what a
#                             real client expects is the entire reason
#                             @grpc/grpc-js is a dependency here.
#   env                       the appconfig files. CONFIG_FILE selects one.
#
# node_modules, .git, the documentation and the CI definitions are excluded in
# .dockerignore; node-ldapjs is copied above, ahead of the install, and copying
# it again here is a no-op on identical content.
COPY . ./
# ---------------------------------------------------------------------------
# AND THE SUITE BACK OUT AGAIN, WHICH .dockerignore USED TO DO.
#
# `tests/` is in the build context since 2026-08-29 and it is not here by
# choice: ONE context serves two images — this one and the test runner
# (tests/Dockerfile, built by docker-compose-run-tests.yml), which is nothing
# BUT the suite and needs the whole source tree besides, because ten of its
# jobs require this service's own modules. A context has one ignore file, and
# the per-Dockerfile ignore file that would give it two is a BuildKit feature
# that the legacy builder silently ignores. See .dockerignore, where the
# failure that taught this is written down.
#
# So the exclusion moved here, where the reason sits beside the instruction.
# The tests assert this repository's MODULE CONTRACTS by requiring the modules
# directly — they are a property of the source tree rather than of the running
# service, this image exists to run `server.js`, and nothing in it would ever
# call them. `npm test` inside this image therefore does not work, exactly as
# deliberately as before; package.json is copied for its dependency list.
#
# **`xacml-pep` GOES THE SAME WAY, SINCE 2026-09-05, AND FOR THE SAME REASON
# ONE STEP FURTHER OUT.** That directory is a SECOND CONTAINER — a remote XACML
# Policy Enforcement Point with its own Dockerfile, its own package.json and
# its own thirty-line `common/helpers.js` shim. `server.js` requires none of
# it and nothing in this image ever could. It is in the context because THAT
# image is built from this same context (its Dockerfile copies the engine out
# of `xacml/` at build time, which is what keeps one copy of the evaluator in
# the tree), and a context has one ignore file — so the exclusion belongs here
# beside its reason rather than in `.dockerignore`, where it would break the
# very build it exists for.
#
# The shim is the specific thing worth not shipping: it is a file called
# `common/helpers.js` that exports two functions, and a copy of it inside an
# image whose real `common/helpers.js` is the identity service's is a trap
# laid for whoever next reads a stack trace.
RUN rm -rf ./tests ./xacml-pep
# The service selects its configuration (log level) with CONFIG_FILE, the same
# way api and client do. The compose files override this per stack.
#
# The path is RELATIVE and it is resolved against the package root rather than
# against the directory of whichever module read it — see common/config_file.js.
# Before the reorganisation every reader sat in the package root and that was
# true by accident; it is now true on purpose, and this string did not have to
# change.
ENV CONFIG_FILE=./env/local.js

# 8081 is the HTTP service. The rest are the listeners that are NOT HTTP and so
# are not on it: 88 is the KDC (TCP and UDP), 389 the LDAP directory, 636 the
# same directory over TLS, 8443 the TLS endpoint that asks for a client
# certificate and 9443 the one that requires it. EXPOSE documents them; each
# compose file decides which it publishes.
#
# The four raw-socket ports were named in that sentence long before they were
# listed below it, which made the sentence false in the direction that matters:
# somebody reading the image for what it offers saw three HTTP-family ports and
# concluded the KDC and the directory were not in it. They are listed now, and
# EXPOSE is metadata only — it publishes nothing, so the compose files still
# decide, and `docker run -P` is the one command that reads it.
#
# 636 is a SEPARATE SOCKET rather than an option on 389 (ldapjs chooses between a
# net.Server and a tls.Server at construction), and the two bind independently:
# either can be up while the other is not, which is why GET /ldap reports them
# separately. A compose file that publishes 389 and not 636 offers a directory a
# TLS client cannot reach, with nothing in the image to say why.
EXPOSE 8081
EXPOSE 88/tcp
EXPOSE 88/udp
EXPOSE 389
EXPOSE 636
EXPOSE 8443
EXPOSE 9443
# The two SPIFFE gRPC listeners over TCP: 8092 is the Workload API and 8181 the
# SPIRE Server API. 8181 rather than SPIRE's own 8081 because that is this
# service's HTTP port, so a client configured for a real spire-server has one
# thing to change and it is named on GET /spiffe.
#
# THE WORKLOAD API'S UNIX SOCKET IS NOT A PORT and cannot be EXPOSEd: it is at
# spiffe.workloadSocket (`/tmp/spire-agent/public/api.sock`, SPIRE's own path)
# INSIDE the container, and it is what SPIFFE_ENDPOINT_SOCKET means to every real
# client. To reach it from the host or from another container, mount the
# directory as a volume — publishing 8092 is the alternative, and it needs the
# client pointed at `tcp://host:8092` explicitly.
EXPOSE 8092
EXPOSE 8181
CMD [ "node", "server.js" ]
