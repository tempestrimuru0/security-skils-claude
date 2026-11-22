# REPORT.md Template

```markdown
# Security Audit: <repository name>

- Commit reviewed: <sha> (<clean | dirty worktree>), or `N/A (not a git repository)`
- Audited files: <list of files read; required for single-file or small targets>
- Subagent note: <if any part was done by a subagent, say which, and that the parent validated its output>
- Benchmark: <only for benchmark runs: answer key used, and the score>

- Profile: <quick | standard | deep>
- Scope: <whole repository | paths listed>
- Date: <YYYY-MM-DD>

## Coverage

State what was checked and what was not. Example:
- Checked: all HTTP routes in `src/routes/`, input parsers, outbound fetches.
- Not checked: `native/` (out of scope), deployment configuration (not in repo).
- This is one pass. It is not a claim that the repository is free of vulnerabilities.

## Summary

| Severity | Count |
|---|---|
| critical | 0 |
| high | 1 |
| medium | 2 |
| low | 0 |
| informational | 1 |

Needs validation: <n> items (see below). Rejected candidates: <n>.

## Findings

For each confirmed finding, in severity order:

### SA-001: <title> (high)

- Location: `src/routes/export.ts:42`
- Class: files and paths
- Attacker: <who>
- Impact: <what they can do, demonstrated>
- Evidence: <source trace summary, with file:line references>
- Fix: <invariant to enforce, narrowest change, regression test>

## Needs validation

| ID | Question | How to settle it |
|---|---|---|
| SA-010 | Does the proxy strip `X-User-Id`? | Check the deployment config |

## Notes

Anything the owner should know that is not a vulnerability: hardening suggestions, dependency versions to watch, and so on. Keep them clearly separate from findings.
```
