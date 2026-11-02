# Contributing

Work from the directory containing `SKILL.md`, `scripts/`, and `tests/`. Runtime analysis uses the Python standard library; no dependency installation or build step is required.

## Changes

- Explain the concrete input and expected behavior. Keep changes focused on the layer that owns the behavior.
- Use English identifiers, paths, diagnostics, and code. Keep README.md and README.zh-CN.md synchronized with implementation changes; update SKILL.md and the relevant references when operational details change.
- Keep analysis instructions in the root SKILL.md and references. The single-file online entry only acquires or reuses a local project checkout and hands off to that checkout's main Skill; synchronize it when acquisition requirements change.
- Add synthetic fixtures for parser, rule, cache, user-isolation, and failure-state changes. Do not commit real APKs, personal device dumps, extracted secrets, reports, or decompiled source.
- Preserve the static-only boundary: no target execution, traffic capture, endpoint probes, implicit downloads during analysis, or device-setting changes. The explicitly selected online entry may acquire this project only; it must not upload analysis inputs or install dependencies.
- Keep unknown, partial, failed, cancelled, and deferred work explicit. Co-occurrence must not be promoted to dataflow evidence.
- Keep runtime dependencies in the standard library unless a concrete need justifies a separate dependency decision.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

With Ruff already available:

```sh
ruff check --no-cache --target-version py310 scripts tests
ruff format --check --no-cache --target-version py310 scripts tests
```

For parser or rule semantics changes, update the relevant engine or rule version so cached facts cannot silently outlive their meaning. Include the affected input path, result changes, checks run, and remaining limitations in the pull request.

## Reporting issues

Use the repository's issue tracker for reproducible, non-sensitive issues. Include the Python version, command options, expected result, stage status, and a sanitized minimal fixture where possible. Avoid uploading full device snapshots or proprietary APKs. If private reporting is enabled for the destination repository, use it for sensitive disclosures.

## License

Contributions are distributed under the project's [MIT license](LICENSE). Preserve applicable copyright and attribution notices.
