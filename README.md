# shellhist-scrub

Find, and optionally mask, **secrets you typed into your shell**. Passwords, tokens and
credentials passed on the command line stay in `~/.zsh_history` and `~/.bash_history`
indefinitely. shellhist-scrub reports them with the value hidden and can replace the
values with `***` in place. One file, standard library only.

## Usage

```bash
python3 shellhist_scrub.py                 # check ~/.zsh_history, ~/.bash_history (report only)
python3 shellhist_scrub.py ~/.zsh_history  # a specific file
python3 shellhist_scrub.py --scrub         # mask the values in place
python3 shellhist_scrub.py --json          # machine-readable report (secret values stay masked)
python3 shellhist_scrub.py --list-rules
# or: pip install git+https://github.com/TPOALOS/shellhist-scrub && shellhist-scrub
```

Report-only is the default and never modifies anything. Example output (values are
never printed):

```
/home/me/.zsh_history:1042 [curl-user] curl -u admin:*** https://api.example.com/v1
/home/me/.zsh_history:1311 [env-secret] export DB_PASSWORD=***
/home/me/.bash_history:88 [url-credentials] git clone https://bob:***@git.example.com/r.git
```

With `--scrub`, each affected entry keeps its command but the secret becomes `***`.
Before writing, a backup (`<file>.bak-<timestamp>`, permissions `600`) is created
**and contains the original secrets**, so delete it once you have checked the result
(`shred -u` or `rm`). Close your shells first; a running shell can overwrite the file when it exits.

## What it finds

`curl -u user:pass`, `Authorization`/API-key headers, URLs with embedded credentials,
`--password`/`--token`/`--secret` style flags, `mysql -pSECRET`, `sshpass -p`,
`docker login -p`, `htpasswd -b`, `echo ... | sudo -S`, `zip -P` / `7z -p`, `redis-cli -a`, `ssh-keygen -N`,
`openssl -passin/-passout pass:...`, `gpg --passphrase`, `export TOKEN=...`-style assignments, and well-known token
formats (AWS, GitHub, GitLab, Slack, npm, PyPI, SendGrid, Stripe, Google, Anthropic/OpenAI-style keys, JWT).
Values that are variable references or secret sources (`$TOKEN`, `$(pass show x)`, `openssl -pass env:KEY`, `file:`, `fd:`) are ignored.

Handles zsh extended history (`: timestamp:duration;command`), **fish** history (`~/.local/share/fish/fish_history`),
multi-line commands and bash timestamp lines, and preserves non-UTF-8 bytes. `--scrub` writes the new file next to the
original and swaps it in atomically, so an interruption cannot leave a truncated history. Exit codes: `0` clean (or scrubbed),
`1` findings, `2` error.

## Limits

Pattern based: it can miss secrets and can mask harmless values. A secret containing
spaces may be only partly masked. If a secret was ever typed, treat it as exposed and
**rotate it**; scrubbing history does not undo that. To stop recording such commands,
start them with a space (`setopt HIST_IGNORE_SPACE` / `HISTCONTROL=ignorespace`).

## Tests

Tests use throwaway files and never touch your real history:

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
