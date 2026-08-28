# common/vendored/

**Every file in this directory is somebody else's. DO NOT EDIT THEM HERE.**

They are byte-identical copies of files in the parent project
(`../oauth2-oidc-debugger`), and two of the parent's tests exist to keep them
that way — `tests/krb5_codec_sync.js` compares the Kerberos codec, and
`tests/bbs2023_cryptosuite.js` drives BOTH implementations of the cryptosuite
against the same vectors. A local "improvement" here is not a change to this
service, it is a divergence between two halves of one exchange, and the symptom
arrives as a signature that does not verify rather than as a diff.

| File | Why it is vendored |
|---|---|
| `x509.js` | Certificate building and parsing. `node-forge`, which `helpers.js` and `tls/tls_server.js` use, **cannot sign with an EC key at all**, and SPIFFE issues P-256. |
| `key_material.js` | Key generation and JWK/PEM conversion. What `x509.js` rests on. |
| `jose_jwe.js` | JWE, for the same reason. |
| `crypto_bytes.js` | The byte-level helpers those three rest on. |
| `bbs2023.js` | The bbs-2023 Data Integrity cryptosuite, for `ldp_vc`. |
| `xmldsig.js` | **XML Signature and XML Encryption, and since 2026-08-27 the signer behind every signed document this service emits.** It is not a library somebody found — it is the OTHER END of most of these exchanges: the debugger signs, verifies, encrypts and decrypts with this exact file on its WS-Trust, SAML and Digital Signature pages. Both ends of a SAML exchange now canonicalize with the same code, which matters because a disagreement about c14n is invisible until it is a signature that verifies on one side and not the other. |
| `contexts/` | The three JSON-LD contexts `bbs2023.js` reads. |

**`contexts/` is inside this directory because `bbs2023.js` resolves
`path.join(__dirname, 'contexts')`.** That is the whole reason it moved here in
the 2026-08-23 reorganisation rather than staying at the package root: the
alternative was editing a vendored file, which is the one thing this directory
forbids. Its first candidate — `path.join(__dirname, '..', 'client', 'src',
'contexts')` — is the parent project's layout and resolves to nothing here,
which is exactly what that `existsSync` guard is for.

Nothing in here requires anything outside this directory, and that is what makes
the copies possible: `x509.js` requires `./jose_jwe` and `./key_material`,
`jose_jwe.js` requires `./crypto_bytes`, `key_material.js` requires
`./jose_jwe`, `bbs2023.js` requires nothing local at all, and `xmldsig.js`
requires nothing local either — only `bunyan` and `node-forge`. The
reorganisation did not have to touch a single line in this directory.

The four PKI modules are read from `spiffe/spiffe_ca.js`; `bbs2023.js` from
`common/helpers.js` and the three `oid4vc/` modules that sign; `xmldsig.js` from
`common/crypto.js` and from nothing else.

---

## `xmldsig.js` NEEDS TWO GLOBALS AND WILL NOT SAY SO

It is the parent project's BROWSER code, where `DOMParser` and `XMLSerializer`
are ambient. Node has neither. `common/crypto.js` installs `@xmldom/xmldom` as
both **before it requires this file**, which is what `api/server.js` does over
there for the same file — so it is the established way to run it server-side
rather than something invented here.

**The ordering is load-bearing and the failure is misleading.** Nothing is
captured at require time, so a `require` that happened first would load
perfectly and then fail on the first signature with `DOMParser is not defined`,
which names neither the file nor the real problem. Require this module only
through `common/crypto.js`.

`genId()` in there also uses `window.crypto` and would throw in node. Nothing
here calls it — `helpers.js` has its own — and it is exported, so do not start.

`kerberos/krb5_spnego.js` is vendored too and is NOT here — it sits beside the
Kerberos codec it belongs to, for the reason `kerberos/CLAUDE.md` gives.

---

## The JSON-LD contexts are load-bearing

`bbs2023.js` reads the three files in `contexts/` **at require time, at module
scope**. A missing one is not a degraded feature — the service does not start. They
are vendored rather than fetched because Data Integrity signs canonicalized
statements, so a one-byte difference in a context fails every signature later and
looks like a crypto bug.

`bbs2023.js` resolves two layouts: `../client/src/contexts` (its position in the
parent project) and `./contexts` (this repo). Do not simplify that away — it is what
let the file be copied here unchanged.

