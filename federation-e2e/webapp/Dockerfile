# The mock web application: a hello-world page behind an OpenID Connect sign-in.
#
# THREE LINES OF SUBSTANCE. The application has NO OIDC LIBRARY — see the header
# of server.js for why a relying party built out of one would prove less about
# the provider it is pointed at — and it has exactly one dependency: bunyan,
# because this repository logs through bunyan everywhere and a container whose
# output is console.log is the one place a run cannot be filtered by level.
#
# That install is what the stack already pays for the two identity services (the
# STS image runs `npm install` as well), so the build needs a registry either
# way; it is only THIS image that used to be reachable without one.
FROM node:22-alpine

WORKDIR /app
COPY package.json server.js ./
RUN npm install --omit=dev

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
