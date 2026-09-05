Copyright (c) 2026 Iya CyberSecurity Solutions, LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## One subtree is not MIT

`xacml/conformance/` holds the OASIS XACML 3.0 conformance test suite, taken
from [`authzforce/core`](https://github.com/authzforce/core) and **licensed
under Apache-2.0**, not under the MIT licence above. Its own `LICENSE` file
sits beside it and `xacml/conformance/PROVENANCE.md` records the full chain —
OASIS XACML TC, then AT&T (April 2014, MIT), then AuthzForce — together with
the one link in that chain that public sources do not establish.

Nothing else in this repository is affected. The MIT licence above covers every
other file.
