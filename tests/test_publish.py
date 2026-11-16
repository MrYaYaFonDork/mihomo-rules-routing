import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.publish import publish_snapshot


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def product(root, name):
    root.mkdir()
    files = {"mihomo/geosite/" + name + ".mrs": b"binary",
             "rule-providers.yaml": b"providers", "README.md": b"readme",
             "THIRD_PARTY.md": b"licenses", "GUIDE.md": b"guide"}
    for path, content in files.items():
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)
    (root / "manifest.json").write_text(json.dumps({
        "outputs": {path: hashlib.sha256(content).hexdigest() for path, content in files.items()}}))


def send(root, remote, work_dir):
    digest = hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()
    return publish_snapshot(root, remote, work_dir, expected_manifest_sha256=digest)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="publish-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote.git"
        self.remote.mkdir()
        git(self.remote, "init", "--bare", "-q")
        self.seed = self.root / "seed"
        self.seed.mkdir()
        git(self.seed, "init", "-q")
        git(self.seed, "config", "user.name", "test")
        git(self.seed, "config", "user.email", "test@example.invalid")
        (self.seed / "main.txt").write_text("main")
        git(self.seed, "add", "main.txt")
        git(self.seed, "commit", "-qm", "main")
        git(self.seed, "push", "-q", str(self.remote), "HEAD:refs/heads/main")
        self.main = git(self.remote, "rev-parse", "refs/heads/main")

    def test_new_and_replacement_are_single_root_without_stale_files(self):
        first, second = self.root / "first", self.root / "second"
        product(first, "Old")
        product(second, "New@!+")
        send(first, str(self.remote), self.root)
        send(second, str(self.remote), self.root)
        self.assertEqual(git(self.remote, "rev-list", "--count", "refs/heads/rules"), "1")
        self.assertEqual(len(git(self.remote, "rev-list", "--parents", "-n", "1", "refs/heads/rules").split()), 1)
        tree = git(self.remote, "ls-tree", "-r", "--name-only", "refs/heads/rules").splitlines()
        self.assertIn("mihomo/geosite/New@!+.mrs", tree)
        self.assertNotIn("mihomo/geosite/Old.mrs", tree)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/main"), self.main)

    def test_git_url_rewrites_cannot_redirect_any_publish_operation(self):
        src = self.root / "product"
        product(src, "A")
        for mode in ("pushInsteadOf", "insteadOf", "env-pushInsteadOf", "env-insteadOf",
                     "system-pushInsteadOf", "system-insteadOf"):
            with self.subTest(mode=mode):
                intended = self.root / (mode + "-intended.git")
                redirected = self.root / (mode + "-redirected.git")
                intended.mkdir()
                redirected.mkdir()
                git(intended, "init", "--bare", "-q")
                git(redirected, "init", "--bare", "-q")
                config = self.root / (mode + ".gitconfig")
                key = "url." + str(redirected) + "." + mode.removeprefix("env-").removeprefix("system-")
                overrides = {"GIT_SSH_COMMAND": "ssh -o BatchMode=yes"}
                if mode.startswith("env-"):
                    overrides.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": key,
                                      "GIT_CONFIG_VALUE_0": str(intended)})
                else:
                    git(self.root, "config", "--file", str(config), key, str(intended))
                    if mode.startswith("system-"):
                        overrides.update({"GIT_CONFIG_SYSTEM": str(config), "GIT_CONFIG_NOSYSTEM": "0"})
                    else:
                        overrides["GIT_CONFIG_GLOBAL"] = str(config)
                original_run = subprocess.run
                commands = []
                def observe(args, **kwargs):
                    if "env" in kwargs:
                        commands.append(args[1])
                        self.assertEqual(kwargs["env"]["GIT_SSH_COMMAND"], "ssh -o BatchMode=yes")
                    return original_run(args, **kwargs)
                with patch.dict(os.environ, overrides), patch("scripts.publish.subprocess.run", side_effect=observe):
                    send(src, str(intended), self.root)
                    send(src, str(intended), self.root)
                self.assertIn("fetch", commands)
                self.assertEqual(subprocess.run(
                    ["git", "show-ref", "--verify", "--quiet", "refs/heads/rules"],
                    cwd=intended).returncode, 0, "rules must be published to the intended repository")
                self.assertNotEqual(subprocess.run(
                    ["git", "show-ref", "--verify", "--quiet", "refs/heads/rules"],
                    cwd=redirected).returncode, 0)

    def test_git_askpass_environment_survives_without_token_in_argv(self):
        src = self.root / "askpass-product"
        product(src, "A")
        original = subprocess.run
        commands = []
        def run(args, **kwargs):
            if "env" in kwargs:
                commands.append(args)
                self.assertEqual(kwargs["env"]["GIT_ASKPASS"], "/tmp/dummy-askpass")
                self.assertEqual(kwargs["env"]["GH_TOKEN"], "dummy-only-secret")
                self.assertNotIn("dummy-only-secret", " ".join(args))
            return original(args, **kwargs)
        with patch.dict(os.environ, {"GIT_ASKPASS": "/tmp/dummy-askpass", "GH_TOKEN": "dummy-only-secret"}), \
                patch("scripts.publish.subprocess.run", side_effect=run):
            result = send(src, str(self.remote), self.root)
        self.assertNotIn("dummy-only-secret", json.dumps(result))
        self.assertIn(["git", "config", "http.followRedirects", "false"], commands)

    def test_race_preserves_competing_rules_on_create_and_replace(self):
        src = self.root / "product"
        product(src, "A")
        for exists in (False, True):
            if exists:
                git(self.seed, "push", "-q", str(self.remote), "HEAD:refs/heads/rules")
            else:
                git(self.remote, "update-ref", "-d", "refs/heads/rules")
            (self.seed / "main.txt").write_text("competing " + str(exists))
            git(self.seed, "add", "main.txt")
            git(self.seed, "commit", "-qm", "competing")
            competing = git(self.seed, "rev-parse", "HEAD")
            original = subprocess.run
            def intercept(args, **kwargs):
                if len(args) > 1 and args[1] == "push" and any("--force-with-lease=" in a for a in args):
                    git(self.seed, "push", "-q", "--force", str(self.remote), "HEAD:refs/heads/rules")
                return original(args, **kwargs)
            with self.subTest(exists=exists), patch("scripts.publish.subprocess.run", side_effect=intercept):
                with self.assertRaises(subprocess.CalledProcessError):
                    send(src, str(self.remote), self.root)
            self.assertEqual(git(self.remote, "rev-parse", "refs/heads/rules"), competing)
            self.assertEqual(git(self.remote, "rev-parse", "refs/heads/main"), self.main)

    def test_rejects_tampering_bad_paths_symlinks_and_git_error(self):
        for defect in ("hash", "path", "symlink", "extra"):
            root = self.root / defect
            product(root, "A")
            manifest = json.loads((root / "manifest.json").read_text())
            if defect == "hash":
                (root / "README.md").write_text("tampered")
            elif defect == "path":
                manifest["outputs"]["../escape"] = "0" * 64
                (root / "manifest.json").write_text(json.dumps(manifest))
            elif defect == "symlink":
                (root / "README.md").unlink()
                (root / "README.md").symlink_to(root / "THIRD_PARTY.md")
            else:
                (root / "unexpected").write_text("x")
            with self.subTest(defect=defect), self.assertRaises((ValueError, OSError)):
                send(root, str(self.remote), self.root)
        valid = self.root / "valid"
        product(valid, "A")
        with self.assertRaises(subprocess.CalledProcessError):
            send(valid, str(self.root / "not-a-repository"), self.root)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/main"), self.main)
        self.assertNotEqual(subprocess.run(["git", "show-ref", "--verify", "--quiet", "refs/heads/rules"],
                                           cwd=self.remote).returncode, 0)

    def test_rejects_replaced_manifest_and_corrupted_copy_before_push(self):
        src = self.root / "product"
        product(src, "A")
        with self.assertRaisesRegex(ValueError, "manifest"):
            publish_snapshot(src, str(self.remote), self.root, expected_manifest_sha256="0"*64)
        write = Path.write_bytes
        def corrupt(path, content):
            if path.name == "README.md" and path.parent.name.startswith("publish-"):
                content = b"corrupt"
            return write(path, content)
        with patch.object(Path, "write_bytes", corrupt):
            with self.assertRaisesRegex(ValueError, "copied output hash"):
                send(src, str(self.remote), self.root)
        def corrupt_manifest(path, content):
            if path.name == "manifest.json" and path.parent.name.startswith("publish-"):
                content = b"{}"
            return write(path, content)
        with patch.object(Path, "write_bytes", corrupt_manifest):
            with self.assertRaisesRegex(ValueError, "copied manifest"):
                send(src, str(self.remote), self.root)
        self.assertNotEqual(subprocess.run(["git", "show-ref", "--verify", "--quiet", "refs/heads/rules"],
                                           cwd=self.remote).returncode, 0)


if __name__ == "__main__":
    unittest.main()
