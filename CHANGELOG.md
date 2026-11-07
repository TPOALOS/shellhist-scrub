# Changelog

## 1.1.0

- fish history (`fish_history`) is supported, including in-place scrubbing
- New rules: `zip -P`/`7z -p`, `redis-cli -a`, `ssh-keygen -N`, `openssl -passin/-passout`, GitLab, npm, PyPI, SendGrid, Stripe, Google and Anthropic/OpenAI-style keys
- `--scrub` is now atomic (temp file + replace) and keeps the file mode
- `--json` report (secret values stay masked) and `--list-rules`
- Fix: `openssl -pass pass:$VAR` / `env:` / `file:` sources are no longer reported as secrets
- Installable with pip (`shellhist-scrub` command), CI on Linux and macOS

## 1.0.0

Initial release.
