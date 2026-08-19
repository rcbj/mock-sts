//
// File: admin_api_explorer.js
//
// ---------------------------------------------------------------------------
// THIS FILE RUNS IN A BROWSER. It is not a node module, nothing requires it,
// and it is the only script this service serves.
//
// admin_api_docs.js reads it off disk at require time and GET /admin-api/docs/
// explorer.js sends it verbatim, which is why it is a file rather than a string
// constant in that module: a 400-line program inside a JavaScript string is a
// program nobody can read a diff of.
//
// Two consequences follow from where it runs, and both are exemptions from this
// repository's code style rather than oversights:
//
//   * **No bunyan, and no Entering/Leaving logs.** There is no `require` here
//     and no logger to reach. What a log line would have said is on the page
//     instead: every call shows its status, its timing and its whole response
//     body, and a failure shows the error where the response would have been.
//     This is the same exemption the parent project grants to `extension/src/*`
//     and to anything handed to `driver.executeScript`.
//   * **It is served under a RELAXED Content-Security-Policy** — `script-src
//     'self'` on this one page, where every other page in this service has
//     `script-src 'none'`. That is why this is a separate resource and not an
//     inline block: `'self'` is enough for a file and `'unsafe-inline'` would
//     have been required for a block, and `'unsafe-inline'` is the clause that
//     would make the relaxation matter.
//
// It builds every node with createElement and textContent and never assigns
// innerHTML. The spec it renders is this service's own, so that is belt and
// braces rather than a control — but the response bodies it displays are not
// necessarily, and those go through the same path.
// ---------------------------------------------------------------------------
(function () {
  'use strict';

  var root = document.getElementById('app');
  var SPEC_URL = root.getAttribute('data-spec');

  // --- small DOM helpers ----------------------------------------------------
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function add(parent, child) {
    parent.appendChild(child);
    return child;
  }

  // The three pieces of Markdown the descriptions in the document actually use:
  // a blank line between paragraphs, **bold**, and `code`. Rendered by walking
  // the text and creating nodes, rather than by building a string of markup —
  // the whole page is written that way, and a "just this once" innerHTML is how
  // a page that renders a response body stops being safe.
  function inline(parent, text) {
    var pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
    var last = 0;
    var match = pattern.exec(text);
    while (match) {
      if (match.index > last) {
        parent.appendChild(
          document.createTextNode(text.slice(last, match.index)));
      }
      var piece = match[0];
      if (piece.charAt(0) === '`') {
        add(parent, el('code', '', piece.slice(1, -1)));
      } else {
        add(parent, el('strong', '', piece.slice(2, -2)));
      }
      last = match.index + piece.length;
      match = pattern.exec(text);
    }
    if (last < text.length) {
      parent.appendChild(document.createTextNode(text.slice(last)));
    }
  }

  function prose(parent, text, className) {
    String(text || '').split('\n\n').forEach(function (para) {
      if (!para.trim()) {
        return;
      }
      inline(add(parent, el('p', className || 'prose')), para.trim());
    });
  }

  // --- the spec -------------------------------------------------------------
  function operationsOf(spec) {
    var out = [];
    Object.keys(spec.paths).forEach(function (path) {
      Object.keys(spec.paths[path]).forEach(function (method) {
        var operation = spec.paths[path][method];
        out.push({
          method: method.toUpperCase(),
          path: path,
          operation: operation,
          tag: (operation.tags || ['Other'])[0]
        });
      });
    });
    return out;
  }

  function tagsOf(spec, operations) {
    // The document's own order, then anything an operation named that the tag
    // list did not — so a tag added to an operation and forgotten in the list
    // still gets a section rather than vanishing.
    var order = (spec.tags || []).map(function (t) { return t.name; });
    operations.forEach(function (row) {
      if (order.indexOf(row.tag) < 0) {
        order.push(row.tag);
      }
    });
    return order;
  }

  function describedBy(spec, name) {
    var found = (spec.tags || []).filter(function (t) {
      return t.name === name;
    })[0];
    return found ? found.description : '';
  }

  // --- one operation --------------------------------------------------------
  function bodyExampleOf(operation) {
    var content = operation.requestBody && operation.requestBody.content;
    var schema = content && content['application/json'] &&
                 content['application/json'].schema;
    if (!schema) {
      return null;
    }
    var examples = schema.examples || [];
    return JSON.stringify(examples.length ? examples[0] : {}, null, 2);
  }

  function curlFor(method, url, body) {
    var parts = ["curl -i -X " + method + " '" + url + "'"];
    if (body !== null && body !== undefined && body !== '') {
      parts.push("-H 'Content-Type: application/json'");
      // Single quotes inside a single-quoted shell word have to be closed,
      // escaped and reopened. The bodies here rarely contain one, and a curl
      // line that silently would not run is worse than a long one.
      parts.push("-d '" + String(body).replace(/'/g, "'\\''") + "'");
    }
    return parts.join(' \\\n  ');
  }

  function urlFor(row, inputs) {
    var query = [];
    Object.keys(inputs).forEach(function (name) {
      var value = inputs[name].value;
      if (value === '') {
        return;
      }
      query.push(encodeURIComponent(name) + '=' + encodeURIComponent(value));
    });
    return row.path + (query.length ? '?' + query.join('&') : '');
  }

  function renderResult(into, status, ms, text) {
    into.textContent = '';
    var head = add(into, el('div', 'resulthead'));
    var cls = status >= 200 && status < 300 ? 'ok'
            : (status === 0 ? 'err' : 'bad');
    add(head, el('span', 'status ' + cls, status === 0 ? 'failed' : status));
    add(head, el('span', 'ms', ms + ' ms'));
    var pretty = text;
    try {
      pretty = JSON.stringify(JSON.parse(text), null, 2);
    } catch (e) {
      // Not JSON — an HTML error page, or a script. Shown as it arrived, which
      // is the useful thing when the answer was not the expected shape.
      pretty = text;
    }
    add(into, el('pre', 'body', pretty));
  }

  function renderOperation(row, spec) {
    var wrap = el('div', 'op');
    var head = add(wrap, el('button', 'ophead'));
    head.setAttribute('type', 'button');
    add(head, el('span', 'method m-' + row.method.toLowerCase(), row.method));
    add(head, el('span', 'path', row.path));
    add(head, el('span', 'summary', row.operation.summary || ''));

    var detail = add(wrap, el('div', 'opbody'));
    detail.style.display = 'none';
    head.addEventListener('click', function () {
      detail.style.display = detail.style.display === 'none' ? 'block' : 'none';
    });

    prose(detail, row.operation.description);

    var form = add(detail, el('div', 'form'));
    var inputs = {};
    (row.operation.parameters || []).forEach(function (parameter) {
      var line = add(form, el('div', 'field'));
      var id = row.operation.operationId + '-' + parameter.name;
      var label = add(line, el('label', '', parameter.name));
      label.setAttribute('for', id);
      var input = add(line, el('input', ''));
      input.setAttribute('type', 'text');
      input.setAttribute('id', id);
      if (parameter.schema && parameter.schema.default !== undefined) {
        input.setAttribute('placeholder', String(parameter.schema.default));
      }
      inputs[parameter.name] = input;
      prose(line, parameter.description, 'hint');
    });

    var bodyBox = null;
    var example = bodyExampleOf(row.operation);
    if (example !== null) {
      var bodyField = add(form, el('div', 'field wide'));
      add(bodyField, el('label', '', 'request body (JSON)'));
      bodyBox = add(bodyField, el('textarea', ''));
      bodyBox.value = example;
      bodyBox.setAttribute('spellcheck', 'false');
      bodyBox.setAttribute('rows', String(
        Math.min(12, example.split('\n').length + 1)));
    }

    var controls = add(detail, el('div', 'controls'));
    var run = add(controls, el('button', 'run', 'Try it'));
    run.setAttribute('type', 'button');
    var curlLine = add(detail, el('pre', 'curl'));
    var result = add(detail, el('div', 'result'));

    function refreshCurl() {
      curlLine.textContent = curlFor(row.method,
                                     location.origin + urlFor(row, inputs),
                                     bodyBox ? bodyBox.value : null);
    }
    Object.keys(inputs).forEach(function (name) {
      inputs[name].addEventListener('input', refreshCurl);
    });
    if (bodyBox) {
      bodyBox.addEventListener('input', refreshCurl);
    }
    refreshCurl();

    run.addEventListener('click', function () {
      var url = urlFor(row, inputs);
      var options = { method: row.method, headers: {} };
      if (bodyBox) {
        options.headers['Content-Type'] = 'application/json';
        options.body = bodyBox.value;
      }
      result.textContent = '';
      add(result, el('div', 'pending', 'calling ' + row.method + ' ' + url +
                                       ' …'));
      var started = Date.now();
      fetch(url, options).then(function (response) {
        return response.text().then(function (text) {
          renderResult(result, response.status, Date.now() - started, text);
        });
      }).catch(function (error) {
        // Shown rather than logged, for the reason at the top of this file: the
        // page is the only place a person is looking.
        renderResult(result, 0, Date.now() - started, String(error));
      });
    });
    return wrap;
  }

  // --- the page -------------------------------------------------------------
  function render(spec) {
    root.textContent = '';
    var operations = operationsOf(spec);

    var header = add(root, el('header', 'head'));
    add(header, el('h1', '', spec.info.title));
    var meta = add(header, el('p', 'meta'));
    add(meta, el('span', 'version', 'v' + spec.info.version));
    add(meta, el('span', 'count', operations.length + ' operations'));
    var specLink = add(meta, el('a', '', 'OpenAPI document'));
    specLink.setAttribute('href', SPEC_URL);
    var consoleLink = add(meta, el('a', '', 'the console this mirrors'));
    consoleLink.setAttribute('href', '/admin');

    prose(header, spec.info.description, 'lede');

    var filterRow = add(root, el('div', 'filter'));
    var filterLabel = add(filterRow, el('label', '', 'filter'));
    filterLabel.setAttribute('for', 'filter');
    var filter = add(filterRow, el('input', ''));
    filter.setAttribute('id', 'filter');
    filter.setAttribute('type', 'text');
    filter.setAttribute('placeholder', 'revoke, claims, /users …');

    var sections = [];
    tagsOf(spec, operations).forEach(function (tag) {
      var rows = operations.filter(function (row) { return row.tag === tag; });
      if (!rows.length) {
        return;
      }
      var section = add(root, el('section', 'tag'));
      add(section, el('h2', '', tag));
      prose(section, describedBy(spec, tag), 'tagnote');
      var nodes = rows.map(function (row) {
        return { row: row, node: add(section, renderOperation(row, spec)) };
      });
      sections.push({ section: section, nodes: nodes });
    });

    filter.addEventListener('input', function () {
      var needle = filter.value.trim().toLowerCase();
      sections.forEach(function (entry) {
        var visible = 0;
        entry.nodes.forEach(function (item) {
          var hay = (item.row.method + ' ' + item.row.path + ' ' +
                     (item.row.operation.summary || '')).toLowerCase();
          var shown = !needle || hay.indexOf(needle) >= 0;
          item.node.style.display = shown ? 'block' : 'none';
          if (shown) {
            visible += 1;
          }
        });
        entry.section.style.display = visible ? 'block' : 'none';
      });
    });
  }

  fetch(SPEC_URL).then(function (response) {
    return response.json();
  }).then(render).catch(function (error) {
    root.textContent = '';
    add(root, el('h1', '', 'The OpenAPI document could not be read'));
    add(root, el('pre', 'body', SPEC_URL + '\n\n' + String(error)));
  });
}());
