# Contributing

Contributions are welcome: bug fixes, tests, documentation, and small
well-scoped features.

## Ground rules

- Python 3.9+ standard library only. This project's promise is zero
  dependencies, so pull requests must not add any.
- All tests must pass, and new behaviour needs new tests:

```bash
python3 -m unittest discover -s tests
```

- Match the existing style: type hints, docstrings on public
  functions, and plain language in user-facing text.
- Test files and payloads in this project are harmless markers for
  authorised security testing. Contributions must keep it that way:
  no working shells, exploit payloads, or credential theft code.

## Process

1. Open an issue first for anything larger than a small fix, so the
   approach can be agreed before you write code.
2. Fork, branch, and open a pull request against `main`.
3. In the pull request, describe what changed, why, and how you
   tested it.

## Reporting security issues

Do not open a public issue for a vulnerability in this tool itself.
See SECURITY.md for how to report it privately.
