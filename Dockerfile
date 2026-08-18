# The mock STS: eight protocol families in one small Node service. See README.md.
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

# The service is eleven modules, and server.js is only the shell that requires the
# other ten and listens. They are copied as a GROUP for exactly the reason the
# individual COPY lines below exist for their files: a module left out is not a
# missing feature, it is a MODULE_NOT_FOUND at startup, so the container never
# listens and every STS-backed job in the suite fails on a timeout that says
# nothing about the cause. This wildcard is deliberate — a per-file list here
# would have to be edited every time a module is added, and forgetting is silent
# until the containerized run.
COPY *.js ./
# The JSON-LD contexts the bbs-2023 cryptosuite (bbs2023.js, copied above) loads AT
# REQUIRE TIME. Mandatory: the module reads them at module scope, so a missing one is
# not a degraded feature — the service does not start at all. In the parent project
# these live in the client's tree and bbs2023.js looks there first; here they are a
# sibling directory, which is that function's second candidate.
COPY contexts ./contexts
# The service selects its configuration (log level) with CONFIG_FILE, the same
# way api and client do. The compose files override this per stack.
COPY env ./env
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
CMD [ "node", "server.js" ]
