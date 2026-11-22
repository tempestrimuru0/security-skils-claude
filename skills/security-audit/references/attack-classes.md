# Attack Classes and Surfaces

Use this list in reconnaissance (to find surfaces) and hunting (to check each surface). Each class names the question to ask. Mark a surface × class pair as covered only after you have actually checked it.

## Heading to slug map

Use the slug in `class` and in `fingerprint` (see [findings-schema.md](findings-schema.md)).

| Heading below | Slug |
|---|---|
| Injection | `injection` |
| Access control | `access-control` |
| Authentication and sessions | `authentication` |
| Client-side | `client-side` |
| Server-side request forgery | `ssrf` |
| Files and paths | `files-and-paths` |
| Cryptography | `cryptography` |
| Availability | `availability` |
| Supply chain and CI | `supply-chain` |
| Memory safety | `memory-safety` |
| Secrets and config (new) | `secrets-and-config`, `config`, `information-disclosure` |

Hard-coded keys and credentials go to `secrets-and-config`, not `cryptography`. CORS, cookie flags and security headers go to `config`. Stack traces and verbose errors go to `information-disclosure`.

## Surfaces to enumerate

| Surface | Examples |
|---|---|
| HTTP routes | REST/GraphQL handlers, middleware order, admin routes |
| Authentication | login, token issuance and verification, session cookies, password reset |
| Authorization | ownership checks, role checks, tenant scoping |
| Input parsers | JSON/XML/YAML, file uploads, archives, image or document parsing |
| Data layer | raw SQL, ORM query builders, NoSQL queries, search syntax |
| Outbound requests | URL fetchers, webhooks, image proxies, SSRF-prone features |
| Templates and output | HTML rendering, Markdown, email templates, logs |
| Files and paths | file read/write, path joins, archive extraction, temp files |
| Commands | `exec`, `spawn`, shell strings, build hooks |
| Secrets and config | hard-coded keys, default credentials, debug flags, `.env` handling |
| Dependencies and CI | lockfiles, GitHub Actions, release scripts, install scripts |
| Local IPC | sockets, named pipes, deep links, message handlers |

## Attack classes

**Injection**
- SQL/NoSQL/LDAP/XPath injection: is user input concatenated into a query instead of parameterized?
- OS command injection: is user input placed in a shell string, or passed as an argument to `sh -c`?
- Template injection: can the user control the template source or the expression language?
- Header and log injection: can newlines or delimiters forge headers or log entries?

**Access control**
- Missing authorization: is the handler reachable without the check that its neighbors have?
- IDOR: is an object ID from the request used without checking that the caller owns it?
- Tenant bleed: does a query, cache key, or search index omit the tenant identifier?
- Privilege escalation through mass assignment: can the request set `role`, `isAdmin`, `ownerId`?
- Confused deputy: does a privileged service act on a user-supplied target without checking the user's rights?

**Authentication and sessions**
- Token validation gaps: missing signature check, accepting `alg: none`, not checking expiry or audience.
- Session fixation, predictable tokens, tokens that survive logout or password change.
- Weak comparison of secrets (non-constant-time) where timing is observable.
- Password reset flows: token reuse, token not bound to the user, reset link leaking via `Referer`.

**Client-side**
- Stored or reflected XSS: untrusted data rendered as HTML, `innerHTML`, `dangerouslySetInnerHTML`, `v-html`.
- Open redirects and unsafe `postMessage` handling (missing origin check).
- Prototype pollution through recursive merges of untrusted objects.
- CSRF on state-changing requests without tokens or `SameSite` cookies.

**Server-side request forgery**
- User-supplied URLs fetched server-side without an allowlist, with redirects followed to internal addresses (`169.254.169.254`, `localhost`, private ranges).
- DNS rebinding: the host is checked once but resolved again at fetch time.

**Files and paths**
- Path traversal: `..`, absolute paths, or symlinks escaping the intended directory.
- Unsafe archive extraction (zip slip).
- Unsafe deserialization (pickle, Java serialization, YAML `load` without a safe loader, `eval` of data).

**Cryptography**
- Hard-coded keys, IVs or nonces reused, ECB mode, MD5/SHA-1 for security decisions, `Math.random` or `rand()` for tokens.
- Missing certificate validation (`rejectUnauthorized: false`, `verify=False`).

**Availability (only when it has a real consequence)**
- Unbounded input size, regex with catastrophic backtracking on attacker input, unbounded recursion, missing timeouts on outbound calls.
- An async request handler that throws with no try/catch and no `unhandledRejection` policy: one request can stop the process.
- Request bodies buffered with no byte cap.
- Outbound requests with no timeout or response-size cap (note them; record only when the effect on a shared process is real).
- Report only when one request or a small number of requests can take a shared service down. Do not test live services.

**Supply chain and CI**
- GitHub Actions: `pull_request_target` with checkout of untrusted code, untrusted input in `run:` expressions, unpinned third-party actions with write permissions.
- Install scripts that fetch and run remote code.
- Secrets printed to logs or passed to forked-PR workflows.

**Memory safety (native code)**
- Buffer overflows, integer overflow before allocation, use-after-free, double free, unchecked return values from allocators.
- Use AddressSanitizer in a sandboxed build to confirm, not as a substitute for reading the code.

## Obvious things to check on every audit

- Hard-coded secrets and credentials in source, config and git history.
- Debug modes or verbose error pages enabled in production config.
- Default admin accounts or default passwords.
- Dependencies with known CVEs in the lockfile (note the version; do not assert exploitability without checking the call path).
- CORS set to `*` together with credentials, or with any origin reflected.
- Plaintext password storage or comparison, in the database or in code.
- Default or seeded credentials that exist in source.
- Debug or environment-dump endpoints, especially when gated only by a key that is also in source.
