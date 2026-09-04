'use strict';
//
// File: xacml_pip.js
//
// ---------------------------------------------------------------------------
// THE POLICY INFORMATION POINT: WHERE AN ATTRIBUTE THE REQUEST DID NOT CARRY
// COMES FROM.
//
// XACML's architecture has the PDP ask for attributes it needs and a PIP
// answer. Here the PIP is the EMBEDDED DIRECTORY: a designator in the
// access-subject category is looked up on the entry of the person the request
// names, and any attribute that entry holds can be returned. That is the whole
// of phase one of this component, deliberately — no LDAP filter language, no
// second source, no caching policy.
//
// ---------------------------------------------------------------------------
// THE ONE RULE THAT MATTERS, AND IT IS ABOUT WHAT "NOT THERE" MEANS.
//
// An attribute the directory does not hold returns an EMPTY BAG. Not false,
// not null, not an error. Whether that empty bag ends the decision is settled
// by `MustBePresent` on the designator and by the function it is handed to —
// and NOT here:
//
//   `string-one-and-only` on an empty bag   → Indeterminate
//   `string-is-in` on an empty bag          → False
//   a designator with MustBePresent="true"  → Indeterminate
//
// Getting this backwards is the classic PIP defect and it fails in the
// permissive direction: a PIP that returned `false` for a missing attribute
// makes the first case decide something instead of refusing to, and a policy
// that should have been Indeterminate returns Permit. So this file never
// invents a value, never substitutes a default, and never converts an absence
// into a presence. `xacml_pdp.js`'s `resolveDesignator()` is the only place an
// empty bag becomes an error, and it does so because the policy asked.
//
// ---------------------------------------------------------------------------
// THE REQUEST WINS OVER THE DIRECTORY, AND THAT ORDERING IS DELIBERATE.
//
// `xacml_pdp.js` consults this resolver only when the request carried nothing
// for that designator. A PEP that asserted an attribute is describing THIS
// REQUEST; the directory is describing the world. Where they disagree the
// request is the more specific claim, and a PIP that overrode it would make a
// PEP unable to say anything about the transaction in front of it.
//
// ---------------------------------------------------------------------------
// WHO THE REQUEST IS ABOUT.
//
// The subject is `urn:oasis:names:tc:xacml:1.0:subject:subject-id` in the
// access-subject category, and it may be a bare name (`bob`), a DN, or a
// certificate subject — all three of which `ldap_server.js`'s `locateEntry()`
// already knows how to resolve, which is exactly why this file calls that
// rather than building a fourth lookup. A request with no subject-id gets an
// empty bag for every subject attribute; it does not get an error, because a
// resource-only or environment-only decision is perfectly ordinary.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const model = require('./xacml_model');
const datatypes = require('./xacml_datatypes');

// Installed by `ldap/ldap_server.js` at require time, the way every other
// consumer of the directory receives it. See `xacml_store.js`'s header for why
// this is an inverted install rather than a require.
let directory = null;
let warnedAboutNoDirectory = false;

function setDirectory(fns) {
  log.debug('Entering setDirectory().');
  directory = fns || null;
  log.debug('Leaving setDirectory(). The PIP ' +
            (directory ? 'has the directory.' : 'has none.'));
}

function available() {
  if (directory) {
    return true;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('xacml: the embedded directory was never loaded, so the PIP ' +
             'answers nothing. Every decision then sees only the attributes ' +
             'the REQUEST carried, which is the pure-XACML behaviour the ' +
             'conformance suite runs under and is not a failure.');
  }
  return false;
}

// ---------------------------------------------------------------------------
// AN ATTRIBUTE NAME THIS PIP WILL LOOK FOR ON AN ENTRY.
//
// A designator's AttributeId is a URI and a directory attribute is a short
// name, so something has to bridge them. Two forms are accepted and NOTHING
// else is guessed:
//
//   * a bare name — `mail`, `departmentNumber`, `employeeType` — used as it
//     stands. This is what a policy author writes and what the PAP's editor
//     will offer from the directory's own schema.
//   * the URN prefix this service uses for its own attributes,
//     `urn:sts-mock:xacml:attribute:<name>`, so that a policy which wants to
//     be explicit about where an attribute comes from can be.
//
// A standard XACML URI like `urn:oasis:names:tc:xacml:1.0:subject:subject-id`
// is NOT mapped to a directory attribute. It names the subject, the request
// carries it, and inventing a directory lookup for it would let a policy
// silently read a different subject-id from the one being decided about.
// ---------------------------------------------------------------------------
const ATTRIBUTE_PREFIX = 'urn:sts-mock:xacml:attribute:';

function directoryAttributeFor(attributeId) {
  log.debug('Entering directoryAttributeFor(). id=' + attributeId);
  const id = String(attributeId || '');
  if (id.indexOf(ATTRIBUTE_PREFIX) === 0) {
    const name = id.slice(ATTRIBUTE_PREFIX.length);
    log.debug('Leaving directoryAttributeFor(). Prefixed: ' + name);
    return name || null;
  }
  if (/^[A-Za-z][A-Za-z0-9;-]*$/.test(id)) {
    log.debug('Leaving directoryAttributeFor(). A bare name.');
    return id;
  }
  log.debug('Leaving directoryAttributeFor(). Not a directory attribute.');
  return null;
}

// The subject the request is about, or null. Read out of the request rather
// than out of any session: a PDP decides about the subject the PEP named, and
// this service's own sign-on session is a different thing that has no business
// influencing somebody else's authorization question.
function subjectOf(request) {
  log.debug('Entering subjectOf().');
  let found = null;
  request.categories.forEach(function (category) {
    if (found || category.category !== model.CATEGORY.ACCESS_SUBJECT) {
      return;
    }
    category.attributes.forEach(function (attribute) {
      if (found || attribute.attributeId !== model.ATTRIBUTE.SUBJECT_ID) {
        return;
      }
      if (attribute.values.length) {
        found = attribute.values[0].lexical;
      }
    });
  });
  log.debug('Leaving subjectOf(). ' + (found ? found : 'none'));
  return found;
}

// An attribute off a directory entry, matched without regard to case. See the
// call site for why this is not `attributes[name]`.
function attributeOf(attributes, name) {
  if (!attributes) {
    return null;
  }
  const wanted = String(name).toLowerCase();
  const keys = Object.keys(attributes);
  for (let i = 0; i < keys.length; i += 1) {
    if (keys[i].toLowerCase() === wanted) {
      return attributes[keys[i]];
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// THE RESOLVER `xacml_pdp.js` IS HANDED.
//
// Returns an array of PARSED values at the designator's declared datatype, or
// an empty array. Never null, never a bag — the PDP wraps it, because the PDP
// owns the bag's type and a resolver that built one could disagree with the
// designator about what type it just returned.
// ---------------------------------------------------------------------------
function resolverFor(request) {
  log.debug('Entering resolverFor().');
  // Resolved once per decision, not once per designator: a policy that reads
  // six attributes about one person must not be able to see six different
  // people because somebody wrote to the directory in between.
  let entry;
  let looked = false;

  function subjectEntry() {
    if (looked) {
      return entry;
    }
    looked = true;
    entry = null;
    if (!available()) {
      return null;
    }
    const subject = subjectOf(request);
    if (!subject) {
      log.debug('resolverFor(): the request names no subject-id, so no ' +
                'entry is looked up.');
      return null;
    }
    const located = directory.locateEntry(subject);
    entry = located && located.stored ? located.stored : null;
    return entry;
  }

  return function resolve(designator) {
    log.debug('Entering resolve(). id=' + designator.attributeId);
    if (designator.category !== model.CATEGORY.ACCESS_SUBJECT) {
      // ONLY the subject category, in this phase. A resource or environment
      // attribute has no entry to be looked up on, and answering them out of
      // the person's entry would be an attribute appearing in a category it
      // does not belong to — which a policy author cannot see and cannot
      // debug.
      log.debug('Leaving resolve(). Not a subject attribute.');
      return [];
    }
    const name = directoryAttributeFor(designator.attributeId);
    if (!name) {
      log.debug('Leaving resolve(). Not a directory attribute name.');
      return [];
    }
    const stored = subjectEntry();
    if (!stored) {
      log.debug('Leaving resolve(). No entry for the subject.');
      return [];
    }
    // CASE-INSENSITIVELY, because LDAP attribute type names are (RFC 4512)
    // and this directory normalises them to lower case on the way in. A
    // lookup for the camel-case name a policy author wrote — `employeeType`,
    // which is the standard inetOrgPerson spelling — finds nothing on an
    // entry that plainly has it. The same mistake in `xacml_store.js` made
    // the whole repository read back empty; here it is quieter and worse,
    // because a missing attribute is a legitimate answer, so the PDP simply
    // decides as though the person had no roles and says nothing at all.
    const raw = attributeOf(stored.attributes, name);
    if (raw === undefined || raw === null) {
      log.debug('Leaving resolve(). The entry does not hold it.');
      return [];
    }
    const list = Array.isArray(raw) ? raw : [raw];
    const values = [];
    list.forEach(function (item) {
      try {
        values.push(datatypes.parseValue(designator.dataType, String(item)));
      } catch (error) {
        // A directory value that will not parse at the type the POLICY asked
        // for is DROPPED, with a warning, rather than making the decision
        // Indeterminate. The directory is schemaless — anything can be written
        // into any attribute — so a policy asking for `employeeNumber` as an
        // integer will meet a non-numeric one eventually, and one bad value
        // among five must not take the other four with it. What it costs is
        // that a wholly unparseable attribute looks exactly like a missing
        // one; the warning is the only place that difference is visible, and
        // it names both the attribute and the type.
        log.warn('xacml: the directory value "' + item + '" on attribute "' +
                 name + '" is not a valid ' + designator.dataType +
                 ', so it is not returned to the PDP: ' + error.message);
      }
    });
    log.debug('Leaving resolve(). ' + values.length + ' value(s).');
    return values;
  };
}

module.exports = {
  setDirectory: setDirectory,
  resolverFor: resolverFor,
  directoryAttributeFor: directoryAttributeFor,
  subjectOf: subjectOf,
  available: available,
  ATTRIBUTE_PREFIX: ATTRIBUTE_PREFIX
};
