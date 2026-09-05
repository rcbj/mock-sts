# ===========================================================================
# THE REMOTE XACML POLICY ENFORCEMENT POINT (phase five).
#
# **THE BUILD CONTEXT IS THE REPOSITORY ROOT, NOT THIS DIRECTORY**, and that
# is the whole reason this file is worth reading. The seven engine modules are
# copied out of `xacml/` at BUILD time, so there is exactly one copy of the
# XACML evaluator in this tree and this image cannot drift from it.
#
#   docker build -f xacml-pep/Dockerfile -t rcbj/xacml-pep .
#
# `docker-compose.yml` sets `context: .` and `dockerfile: xacml-pep/Dockerfile`
# for the same reason. Building from inside this directory fails on the first
# COPY, which is the right way for it to fail: the alternative would be an
# image containing a stale, checked-in copy of the engine.
#
# ---------------------------------------------------------------------------
# WHY NOT A CHECKED-IN COPY, AND WHY NOT A PACKAGE.
#
# `engine.js`'s header argues both at length. In short: a checked-in copy is
# not like `common/vendored/`, because those are another repository's files and
# the drift is between two projects — these would be copies of files in the
# same tree, edited in the same commits, stale the first time somebody fixed a
# combining algorithm. And an npm package would put a release step between
# editing a function and watching the PEP decide differently, which is the loop
# this whole repository is arranged around.
#
# ---------------------------------------------------------------------------
# THE SEVEN MODULES ARE NAMED INDIVIDUALLY AND NOT `COPY xacml/ ./xacml/`.
#
# That looks like the fragile choice — a list to forget — and it is the safe
# one here for two reasons. A whole-directory copy would put `xacml.js`,
# `xacml_admin.js` and `xacml_pep_registry.js` in the image, and every one of
# those requires `common/app.js`, `admin-ui/admin.js` or `common/config.js`;
# they would sit there unloadable, waiting for somebody to require one and get
# a stack trace about express in a container that has no express. And the list
# CANNOT go stale: `tests/xacml_pep.js` parses these COPY lines and asserts
# they name exactly `engine.js`'s `MODULES`, so a module added to the engine
# and not to this file fails the suite naming both.
#
# That is this repository's own version of the standing obligation CLAUDE.md
# records the parent project having for its `sts/` COPY set — enforced here
# rather than written down and remembered.
# ===========================================================================
FROM node:22-alpine

WORKDIR /usr/src/pep

# THE DEPENDENCIES FIRST, so that editing a source file below re-runs neither
# the install nor the download. Three packages: @xmldom/xmldom for the policy
# reader, bunyan for the logger the engine's style rules assume, and nothing
# else — a PEP that had pulled in the mock's dependency set would be evidence
# that the shim below is not doing its job.
COPY xacml-pep/package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund

# THE ENGINE. Seven modules, in dependency order, matching engine.js's MODULES
# exactly — see the header for what enforces that.
COPY xacml/xacml_model.js ./xacml/
COPY xacml/xacml_datatypes.js ./xacml/
COPY xacml/xacml_functions.js ./xacml/
COPY xacml/xacml_validate.js ./xacml/
COPY xacml/xacml_xml.js ./xacml/
COPY xacml/xacml_pdp.js ./xacml/
COPY xacml/xacml_json.js ./xacml/

# THE SHIM. `xacml-pep/common/helpers.js` is what `../common/helpers` resolves
# to from `/usr/src/pep/xacml/`, and it exports `log` and `xmlEscape` and
# nothing else. An engine module that grew a dependency on the mock's config
# table, crypto module or realm registry does not degrade here — it throws at
# load. That file argues why that is the point of the container rather than an
# inconvenience.
COPY xacml-pep/common/ ./common/

COPY xacml-pep/engine.js ./engine.js
COPY xacml-pep/sync.js ./sync.js
COPY xacml-pep/pep.js ./pep.js

EXPOSE 9090

# LIVENESS ONLY, AND IT DOES NOT ASK WHETHER THE POLICY IS CURRENT — `pep.js`
# argues that where the endpoint is: a PEP holding a stale copy is working, and
# a healthcheck that failed on staleness would turn a PDP outage into a restart
# loop, which is an outage of its own.
#
# `node -e` rather than curl, the same probe shape the mock's own compose file
# uses and for the same reason: it depends on nothing but the runtime the
# service already needs, and it fails on a non-200 rather than merely on a
# closed port.
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=10s \
  CMD node -e "require('http').get({host:'localhost',port:process.env.PEP_PORT||9090,path:'/healthcheck'},function(r){process.exit(r.statusCode===200?0:1)}).on('error',function(){process.exit(1)})"

CMD ["node", "pep.js"]
