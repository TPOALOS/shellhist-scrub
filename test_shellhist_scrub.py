import os
import stat
import tempfile
import unittest

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
        self.check("git clone https://bob:pa55w0rd@git.example.com/r.git", "pa55w0rd", "url-credentials")
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


if __name__ == "__main__":
    unittest.main()
