# home/

The front door. One module, two routes, one image:

| File | What it is |
|---|---|
| `home.js` | `GET /` — the page — and `GET /logo.png`, the only image this service serves. |
| `assets/debugger-logo.png` | That image. A DERIVATIVE of the parent project's artwork, not a copy of it — see below. |

It is a directory of its own rather than a route in `common/`, and the entry
test that file states is the reason: *a file lands there because more than one
family needs it*. Nothing needs this one. It is also not a candidate for the
package root, where there are exactly two modules and both earn it.

## What this page is for, and the one rule it must keep

Until 2026-08-24 the root of this service was an unrouted path, so the answer to
the one URL a person types first was Express's `Cannot GET /`. That is a true
statement about the router and a useless one about the service: this port
answers well over a hundred endpoints across sixteen protocol families and none
of them was discoverable from `/`.

So the page is a **signpost**: the logo, the name, the version, one sentence
about what this service is, the warning that it verifies nothing, and four
links — the repository, its issues, the documentation site, and `/admin` on this
instance.

**IT LISTS NO ENDPOINTS AND MUST NOT START.** `GET /admin/sts-metadata` builds
that list by walking the running Express router, so it cannot go stale by
omission, and the parent project's `tests/sts_metadata.js` fails on drift in
either direction. A hand-written set of highlights here would be a second,
unchecked copy of it — wrong within a month, on the page most likely to be read
first and least likely to be re-read. `docs/endpoints.md` makes the same
argument for the documentation site. Link to the thing that generates the list.

The same goes for anything else this service already publishes about itself:
`GET /oauth2/rfc9700`, `GET /spiffe`, `GET /ldap`, `GET /tls`. A summary of one
of those on the front page is a summary that will disagree with it.

## The four links

Three are written out as constants rather than derived. `package.json` carries no
`repository` member, and adding one so that this page could compute three URLs
from it would make a reader open two files to answer *where does this link go*.
The documentation URL is GitHub Pages' arrangement of the same repository —
`.github/workflows/pages.yml` builds `docs/` and `docs/_config.yml` sets
`baseurl: /mock-sts` — so **changing the repository changes all three and that
baseurl together**.

The fourth, `/admin`, is **relative on purpose**. This service is reached as
localhost, as `sts` on a compose network and through a published port;
`baseUrlOf()` exists because documents carrying absolute URLs have to follow the
request, and a same-origin link does not have to know any of that.

Its one sentence about signing in is read from `admin.authRequired` **per
request**, not captured at require time, because a settings form and the
management API can turn that setting off while the process runs. A front page
promising a sign-in screen over a console that is open is the kind of small lie
that costs somebody ten minutes.

## The image

`GET /logo.png` serves the file from disk. Four things about it:

* **It is a route, not `express.static()`.** One file does not need a static
  middleware, and a middleware mounted at the root would sit in front of every
  route registered after this module for the rest of the process's life — rule 1
  in the root `CLAUDE.md`.
* **It is read once, at require time**, and a failure to read it is RECORDED
  rather than thrown, for the reason the four socket-owning modules start their
  listeners from `listen()`: a `require` that throws takes the whole service
  down, and a missing decoration is the least important thing that could go
  wrong here. With no image the page is drawn without one and the route answers
  **404 in its own words**. That last part is load-bearing for the link check in
  `tests/sts_metadata.js`, which fails on Express's `Cannot GET` and passes on an
  endpoint answering for itself.
* **It sits on a BLACK band, and that is not a style choice.** The artwork is
  white lettering with a dark outline, a green wordmark and a pale-blue mark,
  drawn for a dark ground; on the card's own background the "IYA CYBER SECURITY"
  half all but disappears. The parent project ships a black-backed copy of the
  same artwork on its error pages for the same reason.
* **It is a derivative and therefore NOT in `common/vendored/`.** That
  directory's rule is that its files are byte-identical to the parent's, and two
  of the parent's tests hold them to it. This one was produced from
  `client/public/images/oauth2oidcdebugger+iyasec-logo-transparent.png` (2172 ×
  724, 745 kB) with:

  ```bash
  convert <source> -resize 720x -strip PNG32:debugger-logo.png
  convert debugger-logo.png -colors 256 PNG8:debugger-logo.png
  optipng -o5 debugger-logo.png
  ```

  720px is twice the width it is drawn at, so it stays sharp on a 2× display,
  and 256 colours takes it to 31 kB. Re-run those three lines if the parent's
  artwork changes.

## No script and no external resource

`app.js` sets `script-src 'none'` service-wide and this page needs no exception:
it has no behaviour. Its one `<style>` block is covered by the
`style-src 'unsafe-inline'` several pages here already rely on, and the image is
same-origin, which `img-src 'self' data:` already allows. A page that fetched a
font from a CDN would need the policy widened for a decoration — so it does not.
Four pages here have a script on them and each had to argue for it separately;
this is not a fifth.
