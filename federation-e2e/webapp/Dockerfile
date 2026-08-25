# The mock web application: a hello-world page behind an OpenID Connect sign-in.
#
# TWO LINES OF SUBSTANCE, because the application has NO DEPENDENCIES — there is
# no npm install, no lockfile and no network access needed at build time. That is
# a property of the application rather than of this file; see the header of
# server.js for why a relying party built out of a library would prove less about
# the provider it is pointed at.
FROM node:22-alpine

WORKDIR /app
COPY package.json server.js ./

# The port the application listens on INSIDE the container. The compose file
# decides what it is published as, and OIDC_REDIRECT_URI has to name the
# published one, because a BROWSER is what visits it.
EXPOSE 3000

# Same shape as the STS image's probe, and for the same reason: it fails on a
# non-200 rather than merely on a closed port, so a container that is listening
# and broken is reported as broken.
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=5s \
  CMD node -e "require('http').get({host:'localhost',port:process.env.PORT||3000,path:'/healthz'},function(r){process.exit(r.statusCode===200?0:1)}).on('error',function(){process.exit(1)})"

CMD [ "node", "server.js" ]
