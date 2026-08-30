# tests/Dockerfile — THE TEST RUNNER AS A CONTAINER.
#
# This is the image `docker-compose-run-tests.yml` builds for the `tests`
# service: node, a Chrome, this whole repository, and both node_modules trees.
# It runs tests/run-tests-in-container.sh, which drives all twenty-three jobs
# against the `sts` service beside it on the compose network and writes the
# report to a bind mount. Nothing on the host is needed but docker.
#
# It is this repository's answer to ../id-proto-debugger/tests/Dockerfile, and
# it is about eight hundred lines shorter for one reason: that image is
# assembled COPY by COPY out of a repository whose tests, borrowed modules and
# vendored client files live in five directories, and it hit Docker's 125-layer
# limit doing it. Here the tests ARE this repository — tests/ and tests/vendored/
# are committed files of this checkout — so one `COPY . ./` is the whole of it.
#
# ---------------------------------------------------------------------------
# WHY THE WHOLE REPOSITORY AND NOT JUST tests/.
#
# Three of the four kinds of job in this image reach outside that directory:
#
#   * the ten IN-PROCESS jobs (tests/*.js) require the service's own modules —
#     common/crypto.js, common/realms.js, the two map renderers, the Kerberos
#     codecs — because asserting a module contract is what they are for;
#   * five of the thirteen VENDORED protocol jobs load service modules too, and
#     find them through MOCK_STS_DIR, which run-report.js sets to the
#     repository root;
#   * `npm install` at the root needs package.json, package-lock.json, .npmrc
#     AND the node-ldapjs SUBMODULE, since `"ldapjs": "file:node-ldapjs"`.
#
# So this image is the source tree plus a browser. What it is NOT is the SERVICE
# under test: that is the `sts` container, built from the repository root's own
# Dockerfile, and the two are deliberately separate images so that a job here
# cannot accidentally drive an in-process copy of the code it is meant to be
# testing over HTTP.
#
# ---------------------------------------------------------------------------
# THE IGNORE FILE IS THE ROOT'S, SHARED WITH THE SERVICE IMAGE, AND THAT IS
# WHY THE SERVICE IMAGE DELETES tests/ IN ITS OWN Dockerfile.
#
# One build context serves both images and a context has exactly one ignore
# file. BuildKit would allow two — it prefers <dockerfile>.dockerignore beside
# the Dockerfile — and that WAS the arrangement here for exactly one build: the
# legacy builder ignores such a file completely, so on a machine whose docker
# has no buildx plugin this image failed with `COPY failed: no source files
# were specified` on a directory sitting right there in the checkout. A message
# naming neither the builder nor the ignore file.
#
# So `tests` is in the context for both, and ../Dockerfile removes it from the
# service image with an `rm` that carries its own reason. The guard after the
# COPY below is what a context missing the suite says instead of failing later
# inside node.
# ---------------------------------------------------------------------------
FROM ubuntu:latest

# replace shell with bash so we can source files (the nvm install below needs it)
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# apt-get update and apt-get install are ONE RUN on purpose, and splitting them
# apart breaks this build on a schedule nothing in this repository controls. A
# `RUN apt-get update` of its own is a LAYER, and Docker reuses it for as long
# as every instruction above it is unchanged — so the package index baked into
# that layer goes on naming versions that archive.ubuntu.com has already
# dropped from the pool, and every -updates/-security package in the list 404s
# at once. The step that fails is the INSTALL, which reads as a broken mirror
# and is not one. Joined, the two cannot disagree.
#
# WHAT EACH GROUP IS FOR:
#
#   curl, wget, unzip   fetching nvm and Chrome below, and the readiness probe
#                       in run-tests-in-container.sh.
#   ca-certificates     TLS to the download hosts; ubuntu:latest has it, and
#                       naming it means a slimmer base later cannot silently
#                       take it away.
#   libnss3 … xdg-utils Chrome's own shared-library dependencies. Chrome for
#                       Testing is a ZIP rather than a .deb, so nothing pulls
#                       them in for us: without them the browser exits before
#                       it prints anything and selenium reports only that the
#                       session could not be created.
#   fonts-liberation    metric-compatible Arial. The console job asserts
#                       nothing about geometry today, but a headless Chrome
#                       with NO font package at all renders boxes, and a
#                       screenshot taken to read a failure is then unreadable.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install curl \
        wget \
        unzip \
        jq \
        ca-certificates \
        fonts-liberation \
        libatomic1 \
        libasound2t64 \
        libatk-bridge2.0-0 \
        libgtk-4-1 \
        libnss3 \
        xdg-utils

# The same WORKDIR as the service image, so a path read out of a log here means
# the same thing as one read out of the `sts` container's log.
WORKDIR /usr/src/sts

# Install NVM, and the SAME node the service image installs. That is the point
# of naming a version rather than taking a node: base image — a suite that runs
# on a different node from the service it drives can pass on a syntax the
# service cannot parse.
ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN set -o pipefail && curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash
RUN . $NVM_DIR/nvm.sh && nvm version && echo -e ". $NVM_DIR/nvm.sh\nexport PATH=\$NVM_DIR/versions/node/\$(nvm version)/bin:\$PATH" >> ~/.bashrc
RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH
RUN node -v && npm -v

# ---------------------------------------------------------------------------
# CHROME AND CHROMEDRIVER, PINNED, AND INSTALLED ABOVE THE SOURCE COPY.
#
# Above it because a layer's cache key includes its parent: with this below the
# COPY, editing one line of one test would re-download ~200 MB of browser.
#
# THE VERSION IS NOT THE PARENT PROJECT'S, AND THAT IS DELIBERATE. That image
# pins 121.0.6167.85, and its own comments explain what it works around there
# (Web Crypto Ed25519 behind a flag). The one browser job here —
# tests/vendored/sts_admin_console.js — reads status codes and headers through
# WEBDRIVER BiDi (`network.responseCompleted`), because `default-src 'none'` on
# the console is the thing under test and blocks a `fetch()` from the page. BiDi
# network events are a recent Chrome, so this pins a current stable one instead.
# The version and the driver version are the SAME string on purpose: a
# chromedriver that does not match its browser fails at session creation with a
# message about a version, which is at least the truth, and a mismatch of one
# major is the commonest way a browser job "suddenly" stops working.
#
# The download host is Google's own Chrome-for-Testing bucket. The parent uses
# edgedl.me.gvt1.com, which redirects here.
ENV CHROME_VERSION=152.0.7977.64
RUN wget -q -O chrome-linux64.zip https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip && \
    unzip -q chrome-linux64.zip && \
    rm chrome-linux64.zip && \
    mv chrome-linux64 /opt/chrome/ && \
    ln -s /opt/chrome/chrome /usr/local/bin/chrome && \
    ln -s /opt/chrome/chrome /usr/local/bin/google-chrome && \
    wget -q -O chromedriver-linux64.zip https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chromedriver-linux64.zip && \
    unzip -q -j chromedriver-linux64.zip chromedriver-linux64/chromedriver && \
    rm chromedriver-linux64.zip && \
    mv chromedriver /usr/local/bin/ && \
    chrome --version && chromedriver --version

# ---------------------------------------------------------------------------
# THE TWO node_modules TREES, AND THEY ARE TWO FOR THE REASON tests/package.json
# ARGUES AT LENGTH.
#
# The root package carries `omit=dev` in .npmrc — it is what keeps ldapjs's ~200
# test packages out of the service image — so a devDependency added there for
# the suite would be SILENTLY not installed. The test dependencies (commander,
# selenium-webdriver, the @noble pins the vendored wallet modules verify
# against) therefore live in tests/package.json, one directory down, where
# `omit=dev` does not reach them.
#
# Both installs happen BEFORE the source copy so that editing a test does not
# reinstall either tree. node-ldapjs is copied first for the same reason and
# because `"ldapjs": "file:node-ldapjs"` cannot resolve without it: an
# uninitialised submodule is an EMPTY DIRECTORY, npm installs a package with no
# `main`, and the failure arrives much later as `Cannot find module 'ldapjs'` —
# a message naming a package rather than a checkout. The guard after the copy
# is what turns that into a sentence.
COPY package*.json ./
COPY .npmrc ./
COPY node-ldapjs ./node-ldapjs
RUN if [ ! -f node-ldapjs/package.json ]; then \
      echo "node-ldapjs/ is EMPTY in the build context. It is a git submodule," >&2; \
      echo "and this repository is itself one, so it needs:" >&2; \
      echo "    git submodule update --init --recursive" >&2; \
      echo "Without it npm installs a package with no main and the jobs that" >&2; \
      echo "load the directory die with Cannot find module 'ldapjs'." >&2; \
      exit 1; \
    fi
RUN npm install --omit=dev && npm cache clean --force
COPY tests/package*.json ./tests/
RUN npm install --prefix ./tests && npm cache clean --force

# The repository. The root .dockerignore decides what is in it — see the header
# — and the guard is what a context missing the suite says instead of failing
# eighty lines later inside node with a message about a module.
COPY . ./
RUN if [ ! -f tests/tools/run-report.js ]; then \
      echo "tests/ is missing from the build context, so there is nothing" >&2; \
      echo "for this image to run. Something has put tests/ back into the" >&2; \
      echo "repository root's .dockerignore — it must NOT be there: that file" >&2; \
      echo "is shared with the service image, which removes the directory" >&2; \
      echo "itself instead (see ../Dockerfile's rm and .dockerignore's own" >&2; \
      echo "comment for the builder reason)." >&2; \
      exit 1; \
    fi

# The report is written here and bind-mounted out by the compose file. Created
# in the image so that a run with NO mount still writes somewhere real rather
# than failing at the end of a passing suite.
RUN mkdir -p tests/report

# ---------------------------------------------------------------------------
# The jobs' own settings, as environment rather than as arguments, so that
# `docker compose run tests <anything>` still gets them.
#
# CONFIG_FILE is the appconfig layer the JOBS read for a log level, not the
# service's — run-report.js overrides it per protocol job to ./env/local.js
# relative to tests/vendored/. This one is for the runner itself.
ENV CONFIG_FILE=./env/local.js
# Where the service is, on the compose network. run-tests-in-container.sh passes
# it to run-report.js as --service-url and waits for it first; the compose file
# sets it too, and this default is what makes a hand-run `docker run` on the
# same network work with nothing else said.
# https since 2026-08-30: the service's main port is TLS on every stack in this
# repository. The certificate is regenerated on every start of that service, so
# there is deliberately no anchor for it in this image — run-report.js fetches
# it once the service answers and hands it to each job as NODE_EXTRA_CA_CERTS
# and STS_SPKI_PIN (tests/tools/trust.js). Baking one in would be a truststore
# that is wrong for every run after the one that built it.
ENV STS_TEST_SERVICE_URL=https://sts:8081

CMD [ "./tests/run-tests-in-container.sh" ]
