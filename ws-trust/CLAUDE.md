# ws-trust/

WS-Trust 1.0 through 1.4, at `/wstrust`. One file.

**ONE PARSER ANSWERS ALL FOUR VERSIONS**, and that is not a simplification. The
trust namespace alone has four versions in use, so `firstByLocal()` and
`textByLocal()` in `../common/helpers.js` match on LOCAL NAME WITH THE NAMESPACE
IGNORED. That is what lets one `RST` parser serve WS-Trust 1.0–1.4 instead of
four, and it is why those two functions are in `common/` rather than here — the
other two readers are `../ws-federation/wsfed.js`'s `wreq` and the `wresult` the
mock relying party is POSTed.

It asks `../saml/saml2.js` for the assertion it puts in an `RSTR`; it records the
`AppliesTo` as a relying party through `../common/applications.js`, and a
`AppliesTo` handed a SAML 2.0 assertion is BOTH a WS-Trust relying party AND that
assertion's service provider, so `seen()` is passed a LIST rather than called
twice — two calls would count two authentications for one act.

---

## `OnBehalfOf` and `ActAs` are TWO mechanisms now, not one with two spellings

`delegatedSubject()` used to collapse them with a `||`, and for everything that
reads it that was right — the token issued is identical either way, because this
service polices nothing. It is wrong for `/admin/delegation`, where the
difference is the whole point:

* **`wst:OnBehalfOf`** (1.3 §9.2) asks for a token ABOUT somebody. The relying
  party is handed an ordinary sign-in and cannot tell a middle tier was involved.
  IMPERSONATION.
* **`wst14:ActAs`** (1.4 §9.3) is composite by definition: the token is about
  the named subject AND says the requester is acting. DELEGATION.

So that function returns which element it found, `authenticate()` carries it out
on a `delegation` member (with the REQUESTER, who is the intermediary of the
chain and is the one party `subject` deliberately does not name), and
`handleRst()` records the act — there rather than in `authenticate()`, because
that is the first line at which the token exists and the only place that knows
the `AppliesTo`, which is the TARGET of the chain. A request carrying BOTH
elements is attributed to `OnBehalfOf`, the order the `||` always had, and the
row says so rather than choosing silently.

## The act names APPLICATIONS, not URLs, and it names what it was delegated WITH

Two things were added to that record on 2026-08-27 and both exist to make a
CHAIN of these hops readable — a person signs in to a web application over SAML
2.0, the application exchanges the assertion for one addressed to an ESB, and
the ESB exchanges that for one addressed to a back end. Neither changes what is
issued; both change what the console can draw.

* **The `AppliesTo` is resolved through the registry.** `applications`
  `.forAppliesTo()` reads `wstrustAppliesTo` and then `samlEntityId`, and the
  act is filed against whichever application registered the address, with the
  address itself kept in the sentence beside it. Without it the target of hop
  one is a box called `https://esb.example.com` and the intermediary of hop two
  is a box called `esb`, so a chain draws as two unconnected halves. This is
  `oauth2.js`'s `forAudience()` lookup arriving through a second protocol, and
  it has the same three properties: it is a lookup and not a permission, it is
  not case-folded, and it does not fall back to the identifier.
* **The token inside `<wst:OnBehalfOf>` is recorded as CONSUMED**, by its
  `ID` / `AssertionID` (or the `KeyIdentifier` that references it).
  `/admin/tokens/credential` joins what one act produced to what the next
  consumed, on the identifier and on nothing else — so until this was read,
  every WS-Trust lineage stopped one generation in, at the requester's
  WS-Security credential, which this service never issued and cannot name. That
  wall is still recorded beside the followable one, because "it began somewhere
  this register cannot name" and "this is where it began" are different answers.

The requester also carries an `application` where this registry already holds an
entry under the name it authenticated as. It stays a LOOKUP: an unknown name
leaves the slot empty and the party is drawn from `presented`, as before.

**Neither is authorized by anything here, and the row says that too**, in the
same field where a Kerberos row names an attribute on an account. Do not tidy
that sentence into an em dash: the asymmetry between a policed family and an
unpoliced one is the most useful thing on that page. What this service does NOT
do is put the composite fact into an `ActAs` token — nothing in the assertion
says a middle tier acted — and the row states that as a gap in the mock rather
than in the profile.

---

## Two rules about where a credential is read, and both were learnt the hard way

**"The observer is installed" is not the same claim as "this protocol calls the
funnel", and WS-Trust is what that cost.** Three of its paths accepted a
credential without ever reaching `recordAuthentication()`, so each produced
somebody who had authenticated here and appeared on no page and in no
directory: `Validate` and `Cancel` answered above the `authenticate()` call, a
request carrying both a UsernameToken and an `OnBehalfOf` returned at the
delegation branch before the UsernameToken had been looked at, and a `Renew`
with no security header read the assertion out of its own `RenewTarget` and
recorded that as the credential. Two rules come out of it and both generalise
to the next family: authenticate ABOVE the branch on the operation rather than
inside the branches that happen to need a subject, and look for a credential in
`wsse:Security` — anywhere else, only OUTSIDE the elements that hold somebody
else's token, since a document with four identities in it answers "which comes
first" and not "who is asking".

## There is no test for this in either repository

The parent project has `tests/wstrust.js` and
`tests/wstrust_schema_validate.js`, which drive the DEBUGGER's client side
against this endpoint. Nothing tests this module on its own, and the negatives
are where the value is: `Validate` and `Cancel` answering above the
`authenticate()` call, a document carrying both a UsernameToken and an
`OnBehalfOf`, a `Renew` with no security header. See the root `CLAUDE.md`'s Tests
section.
