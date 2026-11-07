import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

import shellhist_scrub as ss

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # secretscan:ignore


def masked(cmd):
    return ss.mask(cmd)


class MaskTests(unittest.TestCase):
    def check(self, cmd, secret, rule):
        out, hits = ss.mask(cmd)
        self.assertNotIn(secret, out, cmd)
        self.assertIn(rule, hits, cmd)
        self.assertIn("***", out)

    def test_rules(self):
        self.check("curl -u admin:s3cr3tpw https://api.example.com", "s3cr3tpw", "curl-user")
        self.check("curl -H 'Authorization: Bearer abcdef123456' https://x", "abcdef123456", "auth-header")
        self.check('curl -H "X-Api-Key: k1k2k3k4k5" https://x', "k1k2k3k4k5", "auth-header")
        self.check("git clone https://bob:pa55w0rd@git.example.com/r.git", "pa55w0rd", "url-credentials")  # secretscan:ignore
        self.check("tool --password=hunter2hunter2 run", "hunter2hunter2", "password-flag")
        self.check("tool --token abc12345 run", "abc12345", "password-flag")
        self.check("mysql -u root -pS3cretPw db", "S3cretPw", "mysql-password")
        self.check("sshpass -p 'my pass' ssh host", "my", "sshpass")
        self.check("docker login -u me -p dockerpw123 registry.example.com", "dockerpw123", "docker-login")
        self.check("echo hunter22 | sudo -S ls", "hunter22", "echo-sudo")
        self.check("export DB_PASSWORD=supersecret1", "supersecret1", "env-secret")
        self.check("API_TOKEN='abcd1234efgh' ./run.sh", "abcd1234efgh", "env-secret")
        self.check("aws configure set aws_access_key_id %s" % AWS, AWS, "aws-key")
        self.check("echo %s" % GH, GH, "github-token")

    def test_prefix_kept_for_context(self):
        out, _ = ss.mask("curl -u admin:s3cr3tpw https://api.example.com")
        self.assertEqual(out, "curl -u admin:*** https://api.example.com")

    def test_safe_commands_untouched(self):
        for cmd in ("ls -la", "git commit -m 'fix'", "export PATH=$PATH:/usr/bin",
                    "export API_TOKEN=$(pass show api)", "export DB_PASSWORD=$DB_PW",
                    "docker login --password-stdin", "cat token.txt", "ssh -p 2222 host",
                    "mysql -u root -p", "tool --password-file /etc/x"):
            self.assertEqual(ss.mask(cmd), (cmd, []), cmd)

    def test_idempotent(self):
        once, _ = ss.mask("tool --password=hunter2hunter2")
        self.assertEqual(ss.mask(once), (once, []))


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(text)
        return p

    def test_zsh_extended_format_and_multiline(self):
        text = (": 1700000000:0;ls -la\n"
                ": 1700000001:0;curl -u admin:s3cr3tpw \\\n  https://api.example.com\n"
                ": 1700000002:0;echo done\n")
        findings, new = ss.analyze(text.splitlines(True))
        self.assertEqual([f[0] for f in findings], [2])
        joined = "".join(new)
        self.assertIn(": 1700000001:0;curl -u admin:***", joined)
        self.assertNotIn("s3cr3tpw", joined)
        self.assertIn(": 1700000002:0;echo done\n", joined)

    def test_bash_timestamps_pass_through(self):
        text = "#1700000000\nexport TOKEN=abcd1234\n#1700000001\nls\n"
        findings, new = ss.analyze(text.splitlines(True))
        self.assertEqual(len(findings), 1)
        self.assertEqual(new[0], "#1700000000\n")
        self.assertEqual(new[1], "export TOKEN=***\n")

    def test_scrub_creates_private_backup_and_keeps_mode(self):
        p = self.write("hist", "ls\ntool --password=hunter2hunter2\n")
        os.chmod(p, 0o600)
        findings, backup = ss.scrub_file(p)
        self.assertEqual(len(findings), 1)
        with open(p) as fh:
            self.assertEqual(fh.read(), "ls\ntool --password=***\n")
        with open(backup) as fh:
            self.assertIn("hunter2hunter2", fh.read())
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_clean_file_not_rewritten(self):
        p = self.write("hist", "ls\npwd\n")
        findings, backup = ss.scrub_file(p)
        self.assertEqual((findings, backup), ([], None))

    def test_non_utf8_bytes_preserved(self):
        p = os.path.join(self.dir, "hist")
        with open(p, "wb") as fh:
            fh.write(b"echo \xff\xfe\ntool --password=hunter2hunter2\n")
        ss.scrub_file(p)
        with open(p, "rb") as fh:
            data = fh.read()
        self.assertTrue(data.startswith(b"echo \xff\xfe\n"))
        self.assertIn(b"--password=***", data)

    def test_cli_exit_codes_and_no_secret_in_report(self):
        import io
        from unittest import mock
        p = self.write("hist", "tool --password=hunter2hunter2\n")
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            self.assertEqual(ss.main([p]), 1)
        self.assertNotIn("hunter2hunter2", buf.getvalue())
        self.assertEqual(ss.main([p, "--scrub"]), 0)
        self.assertEqual(ss.main([p]), 0)
        self.assertEqual(ss.main([os.path.join(self.dir, "missing")]), 2)


def tok(*parts):
    return "".join(parts)


class NewRuleTests(unittest.TestCase):
    def check(self, cmd, rule, secret):
        out, hits = ss.mask(cmd)
        self.assertIn(rule, hits, cmd) if rule else self.assertTrue(hits, cmd)
        self.assertNotIn(secret, out, cmd)
        self.assertIn("***", out)

    def test_zip_and_7z(self):
        self.check("zip -P hunter2pw backup.zip dir/", "zip-password", "hunter2pw")
        self.check("unzip -P hunter2pw backup.zip", "zip-password", "hunter2pw")
        self.check("7z a -phunter2pw out.7z dir", "zip-password", "hunter2pw")

    def test_redis_cli(self):
        self.check("redis-cli -h db -a hunter2pw ping", "redis-auth", "hunter2pw")

    def test_ssh_keygen_passphrase(self):
        self.check("ssh-keygen -t ed25519 -N hunter2pw -f key", "keygen-passphrase", "hunter2pw")
        self.check("ssh-keygen -t ed25519 -N 'hunter2pw' -f key", "keygen-passphrase", "hunter2pw")

    def test_ssh_keygen_empty_passphrase_is_not_a_secret(self):
        self.assertEqual(ss.mask('ssh-keygen -t ed25519 -N "" -f key')[1], [])

    def test_openssl_pass(self):
        self.check("openssl enc -aes-256-cbc -pass pass:hunter2pw -in a -out b", None, "hunter2pw")
        self.check("openssl pkcs12 -export -passout pass:hunter2pw -out x.p12", "openssl-pass", "hunter2pw")
        self.check("openssl rsa -in k.pem -passin pass:hunter2pw", "openssl-pass", "hunter2pw")

    def test_openssl_pass_sources_that_are_not_secrets(self):
        for src in ("pass:$KEYVAR", "env:KEYVAR", "file:/run/secrets/key", "fd:3", "stdin"):
            cmd = "openssl enc -aes-256-cbc -pass %s -in a" % src
            self.assertEqual(ss.mask(cmd), (cmd, []), cmd)

    def test_gpg_passphrase(self):
        self.check("gpg --batch --passphrase hunter2pw -c file", None, "hunter2pw")
        self.check("gpg --batch --passphrase=hunter2pw -c file", None, "hunter2pw")

    def test_new_token_formats(self):
        values = {
            "gitlab-token": tok("glpat-", "abcdEFGH1234ijklMNOP5678"),  # secretscan:ignore
            "npm-token": tok("npm_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),  # secretscan:ignore
            "sendgrid-key": tok("SG.", "a" * 22, ".", "b" * 43),
            "ai-api-key": tok("sk-ant-", "api03-abcdEFGH1234ijklMNOP5678"),  # secretscan:ignore
            "stripe-key": tok("sk_live_", "a" * 24),
        }
        for rule, value in values.items():
            self.check("echo %s > token.txt" % value, rule, value)

    def test_harmless_commands_untouched(self):
        for cmd in ("zip -r backup.zip dir/", "redis-cli ping", "ssh-keygen -t ed25519", "gpg --list-keys",
                    "openssl enc -aes-256-cbc -pass pass:$KEYVAR -in a", "ls -la", "git status"):
            self.assertEqual(ss.mask(cmd), (cmd, []), cmd)

    def test_rule_names_are_unique(self):
        names = [n for n, _, _ in ss.RULES]
        self.assertEqual(len(names), len(set(names)))


FISH = ("- cmd: ls -la\n  when: 1700000000\n"
        "- cmd: curl -u admin:hunter2pw https://api.example.com\n  when: 1700000001\n"
        "  paths:\n    - /tmp\n"
        "- cmd: export DB_PASSWORD=hunter2pw\n  when: 1700000002\n"
        "- cmd: echo one\\ntwo\n  when: 1700000003\n")


class FishTests(unittest.TestCase):
    def test_detection(self):
        self.assertTrue(ss.is_fish("/x/fish_history", []))
        self.assertTrue(ss.is_fish("/x/other", ["- cmd: ls\n"]))
        self.assertFalse(ss.is_fish("/x/.zsh_history", [": 1:0;ls\n"]))
        self.assertFalse(ss.is_fish("/x/.bash_history", []))

    def test_findings_and_line_numbers(self):
        findings, new = ss.analyze(FISH.splitlines(True), fish=True)
        self.assertEqual([(no, rules) for no, rules, _ in findings], [(3, ["curl-user"]), (7, ["env-secret"])])
        self.assertTrue(all("hunter2pw" not in p for _, _, p in findings))
        self.assertEqual(len(new), len(FISH.splitlines(True)))

    def test_only_cmd_lines_change(self):
        lines = FISH.splitlines(True)
        _, new = ss.analyze(lines, fish=True)
        changed = [i for i, (a, b) in enumerate(zip(lines, new)) if a != b]
        self.assertEqual(changed, [2, 6])
        self.assertEqual(new[2], "- cmd: curl -u admin:*** https://api.example.com\n")
        self.assertEqual(new[3], "  when: 1700000001\n")

    def test_scrub_file_in_place(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "fish_history")
            with open(p, "w") as fh:
                fh.write(FISH)
            findings, backup = ss.scrub_file(p)
            with open(p) as fh:
                text = fh.read()
            with open(backup) as fh:
                original = fh.read()
        self.assertEqual(len(findings), 2)
        self.assertNotIn("hunter2pw", text)
        self.assertIn("when: 1700000001", text)
        self.assertEqual(original, FISH)

    def test_default_files_include_fish(self):
        with tempfile.TemporaryDirectory() as home:
            fish = os.path.join(home, ".local", "share", "fish")
            os.makedirs(fish)
            open(os.path.join(fish, "fish_history"), "w").close()
            with mock.patch.dict(os.environ, {"HOME": home, "HISTFILE": "", "XDG_DATA_HOME": ""}):
                self.assertEqual(ss.default_files(), [os.path.join(fish, "fish_history")])

    def test_xdg_data_home_is_honoured(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as xdg:
            os.makedirs(os.path.join(xdg, "fish"))
            p = os.path.join(xdg, "fish", "fish_history")
            open(p, "w").close()
            with mock.patch.dict(os.environ, {"HOME": home, "HISTFILE": "", "XDG_DATA_HOME": xdg}):
                self.assertEqual(ss.default_files(), [p])


class AtomicScrubTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._t.name, ".zsh_history")
        with open(self.path, "w") as fh:
            fh.write(": 1700000000:0;export API_TOKEN=hunter2pw\n: 1700000001:0;ls\n")
        os.chmod(self.path, 0o600)

    def tearDown(self):
        self._t.cleanup()

    def test_no_temp_files_left_behind(self):
        ss.scrub_file(self.path)
        leftovers = [n for n in os.listdir(self._t.name) if n.startswith(".shellhist-")]
        self.assertEqual(leftovers, [])

    def test_mode_preserved(self):
        os.chmod(self.path, 0o640)
        ss.scrub_file(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o640)

    def test_failed_write_keeps_original_and_cleans_up(self):
        with open(self.path) as fh:
            original = fh.read()
        with mock.patch("os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                ss.scrub_file(self.path)
        with open(self.path) as fh:
            self.assertEqual(fh.read(), original)
        self.assertEqual([n for n in os.listdir(self._t.name) if n.startswith(".shellhist-")], [])

    def test_backup_is_private_and_holds_original(self):
        _, backup = ss.scrub_file(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        with open(backup) as fh:
            self.assertIn("hunter2pw", fh.read())

    def test_clean_file_is_not_touched(self):
        with open(self.path, "w") as fh:
            fh.write(": 1:0;ls\n")
        before = os.stat(self.path).st_mtime_ns
        findings, backup = ss.scrub_file(self.path)
        self.assertEqual((findings, backup, os.stat(self.path).st_mtime_ns), ([], None, before))


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ss.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class JsonCliTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._t.name, ".bash_history")
        with open(self.path, "w") as fh:
            fh.write("ls\ncurl -u admin:hunter2pw https://api.example.com\n")

    def tearDown(self):
        self._t.cleanup()

    def test_json_report_never_contains_secrets(self):
        code, out, _ = run_main(self.path, "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertNotIn("hunter2pw", out)
        self.assertEqual(data[0]["findings"], [{"line": 2, "rules": ["curl-user"],
                                                "preview": "curl -u admin:*** https://api.example.com"}])
        self.assertFalse(data[0]["scrubbed"])

    def test_json_scrub_reports_backup(self):
        code, out, _ = run_main(self.path, "--json", "--scrub")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertTrue(data[0]["scrubbed"])
        self.assertTrue(os.path.exists(data[0]["backup"]))

    def test_clean_file_json(self):
        with open(self.path, "w") as fh:
            fh.write("ls\n")
        code, out, _ = run_main(self.path, "--json")
        self.assertEqual((code, json.loads(out)[0]["findings"]), (0, []))

    def test_list_rules(self):
        code, out, _ = run_main("--list-rules")
        self.assertEqual(code, 0)
        self.assertIn("curl-user", out.split())
        self.assertIn("zip-password", out.split())

    def test_missing_file_and_no_default_files(self):
        self.assertEqual(run_main("/nonexistent/hist")[0], 2)
        with mock.patch.object(ss, "default_files", return_value=[]):
            self.assertEqual(run_main()[0], 2)

    def test_text_output_unchanged(self):
        _, out, _ = run_main(self.path)
        self.assertEqual(out.strip(), "%s:2 [curl-user] curl -u admin:*** https://api.example.com" % self.path)


if __name__ == "__main__":
    unittest.main()
