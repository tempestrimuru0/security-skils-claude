# security-audit (Claude Code skill)

by rimu

A Claude Code skill that turns the agent into a source-first security reviewer. It is built for defensive review of code you own or are authorized to review.

## What it does

Two modes:

- **Guidance mode** (default): security questions and focused reviews of a file or function.
- **Full audit mode**: a complete audit of a repository with a written report, a structured `findings.json`, and a validator that checks the output against the real source.

Every finding has one of three verdicts:

| Verdict | Meaning |
|---|---|
| `confirmed` | Source trace is complete. Has a severity. |
| `needs_validation` | A specific fact is missing (for example, a deployment setting not in the repo). No severity. |
| `rejected` | Disproved, with a reason. Kept so the same claim is not raised again. |

A `confirmed` finding must pass a five-question quality gate (attacker, source to sink, no control in between, concrete result, scope) before it is accepted.

## Contents

```
skills/security-audit/
├── SKILL.md                          # skill instructions (loaded by Claude Code)
├── references/
│   ├── attack-classes.md             # surfaces and attack classes to check
│   ├── search-patterns.md            # grep patterns to find leads, per class
│   ├── findings-schema.md            # findings.json format and class slugs
│   └── report-template.md            # REPORT.md template
└── scripts/
    ├── validate-findings.cjs         # schema validator; --repo checks cited locations
    ├── score-run.cjs                 # benchmark: scores a run against an answer key
    └── *.test.cjs                    # tests (node --test)
```

## Install

Copy the skill folder into your Claude Code skills directory:

```powershell
# user-level (all projects)
Copy-Item -Recurse skills\security-audit "$HOME\.claude\skills\security-audit"
```

Then ask Claude Code, for example: `security audit this codebase` or `find vulnerabilities in ./src`.

## Validate

```bash
node skills/security-audit/scripts/validate-findings.cjs path/to/findings.json --repo path/to/repo
```

Without `--repo`, only the schema is checked. With `--repo`, the validator also checks that every cited file exists, every line is in range, and every `quote` appears on its line. A made-up line number fails this check.

## Benchmark

`score-run.cjs` compares a run with an answer key you write for a target with known vulnerabilities:

```bash
node skills/security-audit/scripts/score-run.cjs findings.json expected.json
```

It reports recall for major and minor items, the list of missed items, and any `confirmed` findings that are not in the key (check those by hand: they may be real findings missing from the key).

The benchmark target is not included in this repository. It contains intentionally vulnerable code, which can trigger secret scanners. Write your own target and key to test the skill.

## Tests

```bash
node --test skills/security-audit/scripts/*.test.cjs
```

Requires Node.js 18 or newer. No npm dependencies. Tested on Node 24.

## Acknowledgements

The structure (operating modes, verdict model, validation before reporting) was inspired by [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT). The text and the code here are original and much smaller in scope.

## Responsible use

This skill is for defensive review of code you own or are authorized to review. It does not test live systems and does not produce exploits for deployed services.

## License

MIT (see LICENSE).
