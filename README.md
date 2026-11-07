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
`docker login -p`, `htpasswd -b`, `echo ... | sudo -S`, `export TOKEN=...`-style
assignments, and well-known token formats (AWS keys, GitHub, Slack, JWT).
Values that are variable references (`$TOKEN`, `$(pass show x)`) are ignored.

Handles zsh extended history (`: timestamp:duration;command`), multi-line commands and
bash timestamp lines, and preserves non-UTF-8 bytes. Exit codes: `0` clean (or scrubbed),
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
