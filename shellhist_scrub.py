#!/usr/bin/env python3
"""shellhist-scrub - find (and optionally mask) secrets typed into your shell history.

Passwords on the command line (curl -u, --password=, mysql -pSECRET, export TOKEN=...,
URLs with credentials, API tokens ...) stay in ~/.zsh_history and ~/.bash_history
forever. This tool reports them with the secret value hidden, and with --scrub
replaces the values by *** in place (a private backup is written first).
Standard library only. Exit code 0 = clean (or scrubbed), 1 = findings, 2 = error.
"""
import argparse
import os
import re
import sys
import time

__version__ = "1.0.0"
ENC = dict(encoding="utf-8", errors="surrogateescape")
ZSH_ENTRY = re.compile(r"^: \d+:\d+;")
SECRET_WORDS = r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY|PASSPHRASE)"

# (rule name, compiled regex, index of the group that holds the secret)
RULES = [
    ("curl-user", re.compile(r"\s(?:-u|--user)[\s=]+['\"]?[^\s:'\"]+:([^\s'\"]+)"), 1),
    ("auth-header", re.compile(
        r"(?i)(?:authorization|x-api-key|x-auth-token|api-key|x-access-token)\s*:\s*(?:bearer\s+|basic\s+|token\s+)?([^\s'\"]{6,})"), 1),
    ("url-credentials", re.compile(r"://[^/\s:@'\"]+:([^/\s@'\"]+)@"), 1),
    ("password-flag", re.compile(
        r"(?i)\s--?(?:password|passwd|pass|pwd|passphrase|token|secret|api-?key|apikey)[= ]['\"]?([^\s'\"][^\s'\"]*)"), 1),
    ("mysql-password", re.compile(r"\b(?:mysql|mysqldump|mysqladmin)\b[^|;&\n]*?\s-p([^\s'\"-][^\s'\"]*)"), 1),
    ("sshpass", re.compile(r"\bsshpass\s+-p\s*['\"]?([^\s'\"]+)"), 1),
    ("docker-login", re.compile(r"\bdocker\s+login\b[^|;&\n]*?\s-p\s*['\"]?([^\s'\"]+)"), 1),
    ("htpasswd", re.compile(r"\bhtpasswd\s+-\w*b\w*\s+\S+\s+\S+\s+([^\s'\"]+)"), 1),
    ("echo-sudo", re.compile(r"\becho\s+['\"]?([^\s'\"|]+)['\"]?\s*\|\s*sudo\s+-S"), 1),
    ("env-secret", re.compile(r"(?i)\b[A-Za-z_]*" + SECRET_WORDS + r"[A-Za-z_]*=['\"]?([^\s'\";|&]{4,})"), 1),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"), 0),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}"), 0),
]


def skip_value(v):
    return v.startswith(("$", "<", "*", "`", "(")) or v in ("-", "")


def mask(command):
    """Return (masked_command, [rule names that matched])."""
    hits = []
    for name, rx, grp in RULES:
        spans = []
        for m in rx.finditer(command):
            if skip_value(m.group(grp)):
                continue
            spans.append(m.span(grp))
        if spans:
            hits.append(name)
            for a, b in reversed(spans):
                command = command[:a] + "***" + command[b:]
    return command, hits


def entries(lines):
    """Group raw lines into logical history entries: list of (first_lineno, [raw lines])."""
    out, cur, start = [], [], 0
    for no, line in enumerate(lines, 1):
        if not cur:
            start = no
        cur.append(line)
        body = line.rstrip("\n")
        if body.endswith("\\") and not body.endswith("\\\\"):
            continue
        out.append((start, cur))
        cur = []
    if cur:
        out.append((start, cur))
    return out


def split_prefix(first_line):
    """Separate zsh's ': ts:dur;' prefix from the command text."""
    m = ZSH_ENTRY.match(first_line)
    return (first_line[:m.end()], first_line[m.end():]) if m else ("", first_line)


def analyze(lines):
    """Return (findings, new_lines). findings: (lineno, rules, masked_preview)."""
    findings, new_lines = [], []
    for start, raw in entries(lines):
        prefix, first = split_prefix(raw[0])
        text = first + "".join(raw[1:])
        masked, hits = mask(text.rstrip("\n"))
        if hits:
            ending = "\n" if text.endswith("\n") else ""
            findings.append((start, hits, masked.replace("\n", " ")))
            new_lines.extend((prefix + masked + ending).splitlines(True))
        else:
            new_lines.extend(raw)
    return findings, new_lines


def read_lines(path):
    with open(path, **ENC) as fh:
        return fh.readlines()


def scrub_file(path):
    """Mask secrets in `path` in place; returns (findings, backup_path or None)."""
    lines = read_lines(path)
    findings, new_lines = analyze(lines)
    backup = None
    if findings:
        backup = "%s.bak-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", **ENC) as fh:
            fh.writelines(lines)
        mode = os.stat(path).st_mode & 0o777
        with open(path, "w", **ENC) as fh:
            fh.writelines(new_lines)
        os.chmod(path, mode)
    return findings, backup


def default_files():
    home = os.path.expanduser("~")
    cands = [os.environ.get("HISTFILE", ""), os.path.join(home, ".zsh_history"),
             os.path.join(home, ".bash_history")]
    seen, out = set(), []
    for c in cands:
        if c and os.path.isfile(c) and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find and mask secrets in shell history (values never printed).")
    ap.add_argument("files", nargs="*", help="history files (default: ~/.zsh_history, ~/.bash_history)")
    ap.add_argument("--scrub", action="store_true",
                    help="replace secret values with *** in place (a backup with mode 600 is written first)")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    files = args.files or default_files()
    if not files:
        print("shellhist-scrub: no history files found", file=sys.stderr)
        return 2
    total = 0
    for path in files:
        try:
            if args.scrub:
                findings, backup = scrub_file(path)
            else:
                findings, backup = analyze(read_lines(path))[0], None
        except OSError as exc:
            print("shellhist-scrub: %s" % exc, file=sys.stderr)
            return 2
        total += len(findings)
        for lineno, rules, preview in findings:
            shown = preview if len(preview) <= 100 else preview[:97] + "..."
            print("%s:%d [%s] %s" % (path, lineno, ",".join(rules), shown))
        if backup:
            print("shellhist-scrub: masked %d entr%s in %s (backup: %s)" % (
                len(findings), "y" if len(findings) == 1 else "ies", path, backup), file=sys.stderr)
    print("shellhist-scrub: %d entr%s with secrets" % (total, "y" if total == 1 else "ies"), file=sys.stderr)
    return 0 if (args.scrub or not total) else 1


if __name__ == "__main__":
    sys.exit(main())
