# findings.json Format

`findings.json` is an array of records. Every record has one `verdict`:

| verdict | Meaning | Required fields |
|---|---|---|
| `confirmed` | Source trace is complete and the result is established | `severity`, `source_trace`, `impact`, `fix` |
| `needs_validation` | A specific hypothesis is blocked by a fact you cannot see | `unresolved_fact`, `validation_plan` |
| `rejected` | Disproved. Kept so the same claim is not raised again | `rejection_reason` |

## Common fields (all verdicts)

```json
{
  "id": "SA-001",
  "fingerprint": "src/routes/export.ts:42:path-traversal",
  "title": "Path traversal in export download",
  "verdict": "confirmed",
  "class": "files-and-paths",
  "surface": "HTTP route GET /api/export/:name"
}
```

- `id`: unique within the run, format `SA-NNN`. Every record needs one, including `rejected` and `needs_validation`.
- `fingerprint`: `<repo-relative-path>:<line>:<class-slug>`. The last segment must equal `class`. Must be unique across records.
- `class`: one of the slugs below. Use the slug exactly; the validator rejects other spellings.
- `surface`: the entry point or component, e.g. `HTTP route POST /login`. Required on every record.

### Class slugs

| Slug | Use for |
|---|---|
| `injection` | SQL, NoSQL, OS command, template, header/log injection |
| `access-control` | IDOR, missing authorization, tenant bleed, mass assignment |
| `authentication` | token and session validation, password handling, reset flows |
| `client-side` | XSS, postMessage, prototype pollution, CSRF |
| `ssrf` | server-side fetches of attacker-supplied URLs |
| `files-and-paths` | path traversal, archive extraction, unsafe deserialization |
| `cryptography` | weak primitives, weak randomness, certificate validation |
| `secrets-and-config` | hard-coded keys or credentials, secrets in source, debug endpoints that expose them |
| `config` | CORS, cookie flags, security headers, debug mode, default settings |
| `information-disclosure` | stack traces, verbose errors, internal data in responses |
| `availability` | unbounded input, crashes from one request, missing timeouts |
| `supply-chain` | dependencies, CI workflows, release and install scripts |
| `memory-safety` | native code: overflows, use-after-free |
| `other` | anything that does not fit; explain in `summary` |

## confirmed

```json
{
  "id": "SA-001",
  "fingerprint": "src/routes/export.ts:42:files-and-paths",
  "title": "Path traversal in export download",
  "verdict": "confirmed",
  "class": "files-and-paths",
  "surface": "HTTP route GET /api/export/:name",
  "severity": "high",
  "source_trace": [
    { "file": "src/routes/export.ts", "line": 42, "note": "name taken from req.params without validation" },
    { "file": "src/storage.ts", "line": 17, "note": "path.join(BASE, name) with no containment check" }
  ],
  "attacker": "unauthenticated user with access to the export endpoint",
  "impact": "reads any file readable by the server process, including config with secrets",
  "reproduction": "Not executed (source-only audit). Expected: request name='../secret.txt' returns the file's contents.",
  "fix": "Resolve the path and verify it stays inside BASE before reading; reject names containing path separators"
}
```

`reproduction` is optional. Use it to describe a check you ran in a sandbox, or write "Not executed" when the audit was source-only. It never requires you to run target code.

Rules:
- `source_trace` has at least one entry and every `line` must point to real code.
- `severity` is one of `critical`, `high`, `medium`, `low`, `informational`.
- `impact` states the demonstrated result, not the worst case you imagine.

## needs_validation

```json
{
  "id": "SA-002",
  "fingerprint": "src/proxy.ts:9:access-control",
  "title": "Client-supplied X-User-Id may be trusted",
  "verdict": "needs_validation",
  "class": "access-control",
  "surface": "edge proxy forwarding to the API",
  "source_trace": [ { "file": "src/proxy.ts", "line": 9, "note": "forwards X-User-Id header" } ],
  "unresolved_fact": "Whether the edge proxy strips X-User-Id from external requests (config not in repo)",
  "validation_plan": "Check the proxy config in the deployment repo; or send a request with a dummy header to a staging copy you own"
}
```

Rules: no `severity` field. The `unresolved_fact` must be one specific question.

## rejected

```json
{
  "id": "SA-003",
  "fingerprint": "src/api/users.ts:88:access-control",
  "title": "Possible IDOR on user lookup",
  "verdict": "rejected",
  "class": "access-control",
  "surface": "HTTP route GET /api/users/:id",
  "rejection_reason": "The query filters by req.user.tenantId on line 84, so the object is always scoped to the caller"
}
```

## Coverage

Also keep a coverage record (`coverage.md`, or a section of `REPORT.md` if outputs are restricted). Use a matrix: one row per surface, one column per class slug that applies, and each cell one of `C` (checked), `-` (not checked), `X` (out of scope), `N/A` (class does not apply to this surface). Add a short list below the matrix for cross-cutting checks (for example, "obvious things" from attack-classes.md). Anything not marked `C` is not covered.

```markdown
| Surface | injection | access-control | authentication | files-and-paths | ... |
|---|---|---|---|---|---|
| POST /login | C | N/A | C | N/A | ... |
| GET /files | N/A | - | N/A | C | ... |
```
