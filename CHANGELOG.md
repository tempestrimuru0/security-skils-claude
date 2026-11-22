# Changelog

## Unreleased

- Validator `--repo` option: checks that cited files exist, lines are in range, and quotes appear on the cited line.
- Benchmark scorer `score-run.cjs` with tests, for recall and unlisted-finding reporting against an answer key.
- Class slugs extended: `secrets-and-config`, `config`, `information-disclosure`. Headings in `attack-classes.md` map to slugs.
- Fingerprint suffix must equal the class.
- Quality gate before `confirmed` (five questions).
- Profiles (`quick`, `standard`, `deep`) defined.
- Severity calibration cases for default credentials, single-row SQL reads and unbounded buffering.
- Separation by fix rather than by symptom.
- Grep patterns for each class (`references/search-patterns.md`).
- Subagents return output as text; the parent validates.
- CI workflow running the tests on Node 18, 20, 22 and 24.
