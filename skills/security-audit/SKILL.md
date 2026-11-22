---
name: security-audit
description: Security review of codebases, APIs, services and CLI tools. Use for security questions and focused reviews (guidance mode), or for a complete audit or pen-test of a repository with written reports (full audit mode). Triggers on "security audit", "find vulnerabilities", "security review", "pen test this code", "is this code safe".
---

# Security Audit

Find vulnerabilities that cross a real trust boundary, prove them from source, and recommend the smallest fix. This is a defensive, source-first workflow. A suspicion without a concrete attacker, asset and impact is not a finding.

## Modes

- **Guidance mode** (default): answers security questions, reviews a specific file or function, explains a vulnerability class. Do not create output directories or run the full workflow.
- **Full audit mode**: used when the user asks for a complete audit, a full or end-to-end review, a pen test of a codebase, or a written report. Run the workflow below and write the report files.

If the request could mean either mode, ask one short question before creating files.

## Universal rules

1. **Read-only by default.** Reading source is always allowed. Do not modify the target code.
2. **No live targets.** Do not send traffic to deployed systems, third-party services, production identities or other people's data. Use dummy data and local fixtures only.
3. **Run code only in a sandbox.** If you need to execute target code (tests, a small harness, a fuzzer), do it in an isolated environment with no external network, a minimal environment variable set, and resource limits. If you cannot guarantee that, do not run the code: record the check as `needs_validation` with a plan.
4. **Do not invent controls.** Deployment settings, proxies, WAF rules and identity policies that are not visible in the repo are unknown, not absent. Record them as `needs_validation` with the exact fact that is missing.
5. **Stop at the minimum proof.** A wrong return value, an unauthorized dummy record or a sanitizer hit is enough. Do not build persistence, exploit chains or concealment.

## Profiles

Pick one profile in full audit mode and state it in the report.

- **quick**: surfaces with direct input only (routes, parsers, exec, outbound fetches, file access) and the obvious-things list. Use for a first look or a small target.
- **standard** (default): every surface in the surface table, checked against every class in [references/attack-classes.md](references/attack-classes.md).
- **deep**: standard, plus a second pass over each `confirmed` and `rejected` record to confirm the decision from source again, and a check of every trust boundary for cross-boundary paths.

If the user restricts the output files, skip `architecture.md` and put its content into `REPORT.md` under "Coverage".

## Full audit workflow

1. **Reconnaissance.** Map entry points (HTTP routes, CLI args, file parsers, IPC, message queues, webhooks), trust boundaries (what is authenticated, what is tenant-scoped, what is privileged) and the sensitive assets. Write `architecture.md` (optional when outputs are restricted, see Profiles). See [references/attack-classes.md](references/attack-classes.md) for the surface checklist.
2. **Hunting.** Start with the grep patterns in [references/search-patterns.md](references/search-patterns.md) to get leads, then go through each surface against the attack classes. Record every suspicion as a candidate with a fingerprint (`file:line:class`). Keep a coverage matrix: which surface × class pair was checked, and which was not. Never claim a repo is "secure" from one pass. List every route and entry point you found, even those with no findings: a missing row in the coverage matrix is how real bugs get skipped.
3. **Candidate validation.** For each candidate, try to disprove it: is the input really attacker-controlled? is there a check further up the call stack? is the code reachable? Candidates that survive become `confirmed`, the ones that cannot be resolved become `needs_validation`, and the disproved ones become `rejected` with a reason.
4. **Structured output.** Write all records to `findings.json` following [references/findings-schema.md](references/findings-schema.md), then run `node <skill-dir>/scripts/validate-findings.cjs <path-to-findings.json> --repo <repo-root>` with absolute paths. The `--repo` flag also checks that every cited file exists, every line is in range, and every `quote` appears on its line. A made-up line number fails here. Do not write the report until the validator passes. The parent runs the validator. A subagent returns its JSON in its reply and does not run the validator, so the parent must validate it after saving it.

Split by fix, not by symptom. Two issues get separate records when they need separate code changes, even if they share a file or a theme. Two symptoms of one missing check get one record: if a forgeable session enables both an admin bypass and account access, that is one fix (verify the session server-side), so write one record and list the symptoms in its `impact`. Count severity once per fix.

Example: a `/debug` route that dumps environment variables and a hard-coded API key in the source are separate records. The route needs to be removed; the key needs to be rotated and moved out of source.

Data exposure behind a check that is itself broken is a separate record when its fix is different. Example: an admin route that returns password columns has a broken session check (fix: verify the session) and a data-exposure problem (fix: stop returning the column). Write both. If the admin route's only defect is the forgeable session, one record is enough.
5. **Independent check.** For each `confirmed` record, confirm the cited lines match the code. If you read the whole file in this session and the cited lines are in that read, you may check them from that read. Otherwise re-read just those lines. Never check from memory. Fix any mismatch before reporting.
6. **Report.** Write `REPORT.md` from [references/report-template.md](references/report-template.md). Start with the coverage statement: what was audited, what was not, and the profile used. Every severity claim must match the impact in its record.

If the target is not a git repository, write `Commit reviewed: N/A (not a git repository)` and list the audited files instead.

### Subagents

If you are running as a subagent, do not write the shared run files (`REPORT.md`, `findings.json`, `architecture.md`). Return them as text in your final message, and the parent agent writes them. Say so in your reply if you could not write a file.

## Quality gate before `confirmed`

Before you mark a candidate `confirmed`, answer all five questions from the source. If any answer is "no" or "I don't know", the record is `needs_validation` or `rejected`, not `confirmed`.

1. **Attacker:** can a principal with the stated privileges send the input? Name the principal.
2. **Source to sink:** did you read every step from the input to the dangerous operation, with file and line?
3. **No control in between:** did you check the middleware, the validators, the framework defaults and the callers? Name the control you looked for and where.
4. **Result:** is the impact one you can state concretely (what data, what action, what code runs)?
5. **Scope:** is it inside the repo and the stated scope, and does it need no live system to prove?

## Severity

Only `confirmed` findings get a severity. Use these anchors:

- **critical**: an unauthenticated attacker gets code execution, full data-store access, or takeover of arbitrary accounts.
- **high**: an attacker fully bypasses an explicit control with real consequences (auth bypass, cross-tenant read or write, stored XSS affecting other users, authenticated RCE, arbitrary file read, SSRF that returns the response body).
- **medium**: a real boundary violation with limited scope or uncommon preconditions. Typical cases: reflected XSS that needs a victim to click a link, a crash that one request can trigger but that restarts or affects only the requester, SSRF that returns no body.
- **low**: disclosure of non-secret internals, or an effect that needs significant effort for little gain.
- **informational**: a minor observation that is useful mainly as part of a larger chain, or a hardening issue with no demonstrated impact.

Discriminator for high vs medium: does the demonstrated result fully defeat a control for an action that matters? If you cannot name the concrete damage, lower the severity.

Calibration cases that come up often:
- A known or default credential that logs in as an admin is **critical**, the same as an authentication bypass to admin. A default credential for an ordinary user is **high**.
- A SQL injection that reads one row per request (for example through an id in the path) is **high**. It becomes **critical** when it bypasses authentication or can write, or when it can read arbitrary tables in a single request.
- Unbounded buffering of request bodies is **medium** when one request can exhaust memory of a shared process. Count it under availability, not under injection.

Availability: a crash counts only when the impact is shared. An unhandled exception that takes down a process serving other users is at least medium. One that only fails the requester is informational.

Browser and platform defaults (cookie `SameSite` behaviour, CORS handling by browsers, TLS defaults) are not in the repository. If a finding depends on them, record it as `needs_validation`, not `confirmed`.

## Benchmarking the skill

To check that changes to this skill improve results, run it on a target with a known answer key, then score:

```bash
node <skill-dir>/scripts/score-run.cjs findings.json expected.json
```

The answer key format is described in `scripts/score-run.cjs`. Never show the answer key to the agent that performs the audit: it turns the test into a copy exercise. Track recall and false positives across runs, and only keep a change to the skill if it improves one without hurting the other.

## Anti-patterns

- Presenting missing best practices (no CSP, no rate limit) as vulnerabilities without a reachable attack.
- Treating intended same-user actions as a privilege issue.
- Assigning severity to `needs_validation` records.
- Writing a report before the validator passes, or letting the prose and the JSON disagree.
- Claiming full coverage after a quick or partial pass.
- Guessing how a proxy, CDN or identity provider behaves when its config is not in the repo.

## Fix recommendations

For each `confirmed` finding, name the invariant that must hold and the narrowest change that enforces it at the last trusted decision point. Add a regression test where possible. Describe the fix; do not apply it unless the user asks.
