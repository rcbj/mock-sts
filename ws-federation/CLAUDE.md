# ws-federation/

WS-Federation 1.2, the passive requestor profile, plus a mock relying party at
`/wsfed/rp` that verifies a sign-in response check by check. One file.

4. **`wsfed.js` must stay after `oauth2.js` in the require order**, and that is a
   dependency rather than a preference: it signs users in to the browser session
   `oauth2.js` owns, through the `startSession` / `sessionOf` / `endSession` it
   exports, so that single sign-on works across the two protocols. The dependency is
   one-way — `oauth2.js` knows nothing about WS-Federation — which is what keeps it
   out of the cycles rule 2 exists to avoid. Do not give WS-Federation a session store
   of its own to "decouple" them: two stores would each look correct alone and never
   see each other, and the symptom is a sign-on that silently is not single.


## It has a sign-in screen of its own, deliberately

WS-Federation still has a sign-in screen of its own, deliberately: section
13.2.1 lets the sign-in request arrive as a cross-site form POST, which
`SameSite=Lax` keeps a session cookie off, and routing that through a redirect
chain would lose the request. It lands in the SAME session, which is what makes
single sign-on between the two protocols work. Pointing it at this service is the
obvious next move and is not done yet.

---

## `wauth` is refused rather than faked

* **WS-Federation's `wauth` is refused rather than faked.** A relying party demanding
  multi-factor against a password-only session gets an error and two ways forward, not
  an assertion claiming a second factor that did not happen. It is the one thing in
  this profile that could trivially have been faked, and faking it would have taught a
  relying party something false about how a person signed in. Likewise `wreqptr` is
  never dereferenced: fetching a URL handed over in a query parameter is a
  server-side request forgery with a specification citation attached.

Note also `authnMethodsFor()`, which used to test for `hwk` and call a
passwordless sign-in a two-factor one. Anything reading `hwk` to mean "two
factors" is wrong for the reason `../authn/CLAUDE.md` gives; this now tests for
`hwk` AND `pwd`.

## Both of this module's Maps are per trust realm, and one of them was a hole

`pendingSignIns` (the sign-in request the screen interrupted) and `rpContexts`
(the `wctx` values the mock relying party minted) were plain `Map`s until
2026-08-25, and the first was a realm-isolation hole rather than an
untidiness. `POST /wsfed/login` looks a sign-in up by the id on the form, so an
id minted at `/realm/acme/wsfed` was found by the DEFAULT realm's handler, which
then called `startSession()` and issued the response with the default realm's
key and issuer for a request that began in `acme`. It was verified by hand
before the fix — the cross-realm POST answered 303 rather than "this sign-in
form has expired" — and after it, both.

`realmSupport()` publishes this family as `full` and says single sign-on with
OAuth "does not cross realms"; the store now agrees with the claim. `rpContexts`
followed for a quieter reason worth stating rather than inheriting: `/wsfed/rp`
answers under every realm prefix, so there is one mock relying party per realm,
and a `wctx` minted by one being recognised by another would make the check that
Map exists for — did my own value come back? — answer yes across a boundary the
rest of the profile does not cross.

## The autopost page is one of the three scripted pages

Section 13.2.1's sign-in response is a self-submitting form, so
`/wsfed/autopost.js` is named in a relaxed `script-src`. It carries a REAL SUBMIT
BUTTON as well, labelled for a person, because with the script blocked the button
is the whole mechanism. See the root `CLAUDE.md`.

## There is no test for this in either repository

The mock relying party makes it look covered — but a person has to click it and
read the page. What a test would add is the negatives: an altered `wctx`, `wauth`
demanding a factor the session never had, `wfresh` read as seconds rather than
minutes, a SAML 1.1 signature whose reference does not resolve because
`AssertionID` was not named. A passive requestor that issues a good token to a
working relying party looks finished and proves almost nothing.
