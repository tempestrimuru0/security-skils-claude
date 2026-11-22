# Search Patterns

Start hunting with these. A pattern is a lead, not a finding: open the code around each hit, follow the data from its source to the sink, and check for validation on the way. Use them with Grep (or `rg`) over the scope paths.

Each pattern gives: what it finds, and the class slug to use.

## Injection

| Pattern (regex) | Finds | Class |
|---|---|---|
| `(SELECT\|INSERT\|UPDATE\|DELETE).*\$\{` | SQL built with a template literal | `injection` |
| `(SELECT\|INSERT\|UPDATE\|DELETE).*" *\+` | SQL built by string concatenation | `injection` |
| `(query\|execute\|raw)\(\s*f?["'].*(\{\|%s\|\+)` | Python/JS SQL with interpolation | `injection` |
| `exec\(\|execSync\(\|spawn\(.*shell\|os\.system\|subprocess.*shell=True` | shell execution (check whether input reaches it) | `injection` |
| `eval\(\|new Function\(\|vm\.run` | dynamic code execution | `injection` |
| `\$where\|\$regex\|find\(\s*req\.` | NoSQL operator injection | `injection` |
| `render_template_string\|Template\(` with user data | server-side template injection | `injection` |

## Client-side

| Pattern | Finds | Class |
|---|---|---|
| `innerHTML\|outerHTML\|dangerouslySetInnerHTML\|v-html\|document\.write` | HTML sinks | `client-side` |
| `res\.send\(.*req\.(query\|params\|body)\|<h1>.*\$\{` | unescaped user data in responses | `client-side` |
| `postMessage\|addEventListener\(["']message` | message handlers (check origin check) | `client-side` |
| `__proto__\|constructor\.prototype\|merge\(` | prototype pollution risk | `client-side` |

## Access control and authentication

| Pattern | Finds | Class |
|---|---|---|
| route definitions (`app\.(get\|post\|put\|delete\|patch)\(`, `@app\.route`, `router\.`) | every endpoint: check each for an auth middleware or check | `access-control` |
| `req\.params\.id\|params\[.id.\]\|findById\(\|findOne\(\{ *id` | object lookups by client ID (check ownership) | `access-control` |
| `role\s*[!=]==?\s*['"]admin\|isAdmin` | role checks: where does the role come from? | `access-control` |
| `jwt\.decode\|verify\(.*algorithms\|alg.*none` | token handling | `authentication` |
| `cookie\|Set-Cookie\|localStorage\.setItem.*token` | session storage (check flags) | `config` / `authentication` |
| `password\s*===\|password ==\|==.*password` | password comparison (plaintext? timing?) | `authentication` |

## Files, paths and outbound requests

| Pattern | Finds | Class |
|---|---|---|
| `readFile\|createReadStream\|sendFile\|open\(` with `req\.\|params\|query\|body` | file access with user input | `files-and-paths` |
| `path\.join\(.*req\.\|os\.path\.join\(.*request` | path building (check containment) | `files-and-paths` |
| `extractAll\|extractall\|unzip\|tar\.x` | archive extraction (zip slip) | `files-and-paths` |
| `fetch\(\|axios\.\|http\.get\|requests\.get\|urlopen\|curl_exec` with user input | server-side requests | `ssrf` |
| `pickle\.loads\|yaml\.load\(\|unserialize\(\|ObjectInputStream` | unsafe deserialization | `files-and-paths` |

## Secrets and configuration

| Pattern | Finds | Class |
|---|---|---|
| `(api[_-]?key\|secret\|token\|password\|passwd)\s*[:=]\s*['"][^'"]{6,}` | hard-coded credentials | `secrets-and-config` |
| `sk_live_\|AKIA[0-9A-Z]{16}\|ghp_[A-Za-z0-9]{36}\|-----BEGIN .*PRIVATE KEY` | known secret formats | `secrets-and-config` |
| `process\.env\|os\.environ` dumped to a response | environment disclosure | `information-disclosure` |
| `Access-Control-Allow-Origin.*\*\|Origin.*reflect\|credentials.*true` | CORS | `config` |
| `DEBUG\s*=\s*True\|debug:\s*true\|NODE_ENV.*development` | debug mode | `config` |
| `verify\s*=\s*False\|rejectUnauthorized:\s*false\|InsecureSkipVerify` | disabled certificate checks | `cryptography` |
| `stack\|traceback\|err\.stack` in responses | verbose errors | `information-disclosure` |

## Cryptography

| Pattern | Finds | Class |
|---|---|---|
| `md5\|sha1\|DES\|RC4\|ECB` | weak primitives (check the use: password hashing or only checksums?) | `cryptography` |
| `Math\.random\|random\.random\|rand\(\)` near `token\|key\|id` | weak randomness | `cryptography` |

## Supply chain and CI

| Pattern | Finds | Class |
|---|---|---|
| `pull_request_target` in `.github/workflows/` | privileged workflow on untrusted code | `supply-chain` |
| `\$\{\{ *github\.event\.(issue\|pull_request\|comment)` in `run:` | expression injection | `supply-chain` |
| `curl .*\| *(sh\|bash)\|wget .*\| *sh` | remote code in install scripts | `supply-chain` |

## Sessions, identity and seeded data

| Pattern | Finds | Class |
|---|---|---|
| `Buffer\.from\(.*['"]base64['"]\)` or `atob\(` on a cookie or header value | identity taken from unsigned encoding | `authentication` |
| `split\(['"]:['"]\)` on decoded tokens | token fields trusted without a signature | `authentication` |
| `INSERT INTO .*VALUES.*['"][^'"]*(pass\|pwd\|secret)` or seeded rows with literal passwords | default or seeded credentials | `secrets-and-config` |
| `SELECT \*` or `SELECT .*password` on a response path | password columns returned to callers | `information-disclosure` |

## Availability and request handling

| Pattern | Finds | Class |
|---|---|---|
| `async \(req, res\)` or `async function handler` with no `try` | throws become unhandled rejections | `availability` |
| `data \+= chunk\|body \+= \|\.on\(['"]data['"]` without a byte cap | unbounded body buffering | `availability` |
| `fetch\(\|axios\.\|requests\.get\(` with no `timeout`/`signal` | outbound calls without limits | `availability` |
| `new URL\(` and `pathname` used as a value | not percent-decoded: payloads must avoid spaces, which changes exploit shape. Note it in the record | `injection` |
| `===?\s*secret\|!==?\s*(key\|secret\|token)` | comparison of secrets (timing is rarely practical; record as rejected unless the leak is practical) | `cryptography` |

## After the hits

For each hit, record one line: `file:line`, pattern, and "source reaches sink? yes / no / unknown". Only "yes" and "unknown" move forward. "Unknown" becomes `needs_validation` if the missing fact is outside the repo, otherwise keep reading.
