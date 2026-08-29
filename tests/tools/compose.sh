#
# tests/tools/compose.sh — how this repository's two launchers talk to docker.
#
# SOURCED, never run: it defines two functions and sets nothing. Both
# ./local-run-tests.sh (which brings up ONE service and drives it from this
# machine) and ./docker-run-tests.sh (which brings up the service AND the tests
# container and drives nothing itself) need exactly the same two answers —
# which compose command is on this machine, and how to hand it the variables
# a compose file substitutes — so they are here rather than in both.
#
# It lives in tests/tools/ for the reason everything else in this directory
# does: tools/ is NOT tests. run.js's discovery rule walks tests/*.js and would
# otherwise have to be told to skip a file, and it is a `.sh` besides.
#
# THE CONTRACT WITH A CALLER, because these two read and write globals rather
# than taking arguments:
#
#   DOCKER_SUDO    set by resolveCompose(); "" or "yes".
#   COMPOSE_CMD    set by resolveCompose(); "docker compose" or
#                  "docker-compose".
#   COMPOSE_ENV    an ARRAY the caller fills with NAME=value strings before
#                  calling docker_compose(). May be unset; the expansions
#                  below tolerate that under `set -u`.
#
# A caller that forgets to call resolveCompose() first gets an empty
# COMPOSE_CMD and a shell error naming nothing, so both launchers call it once
# and check its return value.
#

# Which docker compose, and does it need sudo? Both answered by RUNNING the
# thing rather than by looking for a group in `id -nG`, which is neither
# necessary (a rootless daemon needs no group) nor sufficient (a group added
# since this shell logged in is not in this shell's credentials).
resolveCompose()
{
  if docker info > /dev/null 2>&1;
  then
    DOCKER_SUDO=""
  elif sudo -n docker info > /dev/null 2>&1;
  then
    # PASSWORDLESS sudo only. An interactive `sudo` here would sit waiting for
    # a password in the middle of what a person started and walked away from,
    # and would hang a CI agent outright.
    DOCKER_SUDO="yes"
  else
    return 1
  fi

  if [ -n "${DOCKER_SUDO}" ];
  then
    if sudo -n docker compose version > /dev/null 2>&1;
    then
      COMPOSE_CMD="docker compose"
      return 0
    fi
  elif docker compose version > /dev/null 2>&1;
  then
    COMPOSE_CMD="docker compose"
    return 0
  fi
  # The v1 standalone binary, still what some machines have.
  if command -v docker-compose > /dev/null 2>&1;
  then
    COMPOSE_CMD="docker-compose"
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# One compose command, with the variables the compose file substitutes.
#
# THEY ARE NAMED ON THE COMMAND LINE RATHER THAN EXPORTED, and that is two
# decisions in one. `sudo` EMPTIES the environment, so an exported variable
# reaches compose as unset and the file substitutes its default with nothing
# said — which is how the parent project's stack spent months ignoring every
# tuning variable it was handed. And `CONFIG_FILE` is a variable the tests in
# this repository read too, so exporting the container's copy of it would
# change what every in-process job loads.
# ---------------------------------------------------------------------------
docker_compose()
{
  if [ -n "${DOCKER_SUDO}" ];
  then
    sudo ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} ${COMPOSE_CMD} "$@"
    return $?
  fi
  env ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} ${COMPOSE_CMD} "$@"
  return $?
}
