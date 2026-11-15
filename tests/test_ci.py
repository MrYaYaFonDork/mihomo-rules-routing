import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import re
import base64
import urllib.error
import subprocess
import io
import email.message
from types import SimpleNamespace

import yaml
from scripts import ci
from scripts.build import providers_yaml


def fixture(root):
    root = Path(root)
    (root / "rules").mkdir()
    sources, providers, outputs = [], {}, {}
    for source in json.loads(Path("config/sets.json").read_text()):
        name = re.sub(r"[^a-z0-9]+", "-", source.lower()).strip("-")
        path = f"rules/{name}.mrs"
        (root / path).write_bytes(b"synthetic")
        outputs[path] = hashlib.sha256(b"synthetic").hexdigest()
        sources.append({"source": source, "sha256": "1" * 64, "providers": [name],
                        "count": 1, "behavior": "domain", "format": "mrs"})
        providers[name] = {"type": "http", "behavior": "domain", "format": "mrs",
                           "path": "./" + path, "url": "https://example.test/" + path,
                           "interval": 86400}
    content = providers_yaml(providers).encode()
    (root / "rule-providers.yaml").write_bytes(content)
    outputs["rule-providers.yaml"] = hashlib.sha256(content).hexdigest()
    manifest = {"source_origin": "authenticated_download", "upstream_commit": "a" * 40,
                "ci_fingerprint": "b" * 64, "sources": sources, "outputs": outputs,
                "tools": {name: {"version": info["version"], "binary_sha256": info["binary_sha256"]}
                          for name, info in json.loads(Path("config/tools.json").read_text()).items()}}
    (root / "manifest.json").write_text(json.dumps(manifest))
    return manifest


class CiTests(unittest.TestCase):
    def test_api_rejects_redirect_before_external_request_or_404(self):
        for redirect in (301, 302, 303, 307, 308):
            requests = []
            def https_open(handler, request):
                requests.append((request.full_url, request.get_header("Authorization")))
                headers = email.message.Message()
                if len(requests) == 1:
                    headers["Location"] = "https://other.example.test/missing"
                    status = redirect
                else:
                    status = 404
                response = urllib.response.addinfourl(io.BytesIO(b""), headers, request.full_url, status)
                response.msg = "mock"
                return response
            with patch.object(urllib.request.HTTPSHandler, "https_open", https_open):
                with self.assertRaises(urllib.error.HTTPError) as error:
                    ci.api("repos/owner/repo/branches/rules", "dummy-only", missing=True)
            self.assertEqual(error.exception.code, redirect)
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0][1], "Bearer dummy-only")

    def test_publish_existing_new_and_git_failure_without_git_execution(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            root = Path(tmp)
            product = root / "product"
            product.mkdir()
            fixture(product)
            for status in (0, 2, 128):
                checkout = root / str(status)
                checkout.mkdir()
                calls = []
                def git(args, **kwargs):
                    calls.append(args)
                    if args[1] == "ls-remote":
                        return SimpleNamespace(returncode=status, stdout="")
                    if args[1] == "diff":
                        return SimpleNamespace(returncode=1, stdout="")
                    return SimpleNamespace(returncode=0, stdout="")
                with patch.object(ci.subprocess, "run", side_effect=git):
                    if status == 128:
                        with self.assertRaises(subprocess.CalledProcessError):
                            ci.publish(product, checkout, "a" * 40, "b" * 64)
                        self.assertFalse(any(cmd[1] == "push" for cmd in calls))
                    else:
                        ci.publish(product, checkout, "a" * 40, "b" * 64)
                        self.assertTrue(any(cmd[1] == "push" for cmd in calls))
                        self.assertEqual(any(cmd[1] == "fetch" for cmd in calls), status == 0)

    def test_publish_stops_on_fetch_or_push_failure(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            root = Path(tmp)
            product = root / "product"
            product.mkdir()
            fixture(product)
            for failure in ("fetch", "push"):
                checkout = root / failure
                checkout.mkdir()
                calls = []
                def git(args, **kwargs):
                    calls.append(args[1])
                    return SimpleNamespace(returncode=(128 if args[1] == failure else
                                                      1 if args[1] == "diff" else 0), stdout="")
                with patch.object(ci.subprocess, "run", side_effect=git):
                    with self.assertRaises(subprocess.CalledProcessError):
                        ci.publish(product, checkout, "a" * 40, "b" * 64)
                if failure == "fetch":
                    self.assertNotIn("push", calls)

    def test_prepare_branch_absent_and_api_failure(self):
        def fake(path, token, missing=False):
            if path.endswith("/commits/sing"):
                return {"sha": "a" * 40}
            if path.endswith("/branches/rules"):
                return None
            return {}
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            with patch.object(ci, "api", side_effect=fake):
                self.assertTrue(ci.prepare("owner/repo", "token", Path(tmp))["changed"])
            with patch.object(ci, "api", side_effect=urllib.error.HTTPError("https://api.github.com", 403, "denied", {}, None)):
                with self.assertRaises(urllib.error.HTTPError):
                    ci.prepare("owner/repo", "token", Path(tmp))
            def branch_error(path, token, missing=False):
                if path.endswith("/branches/rules"):
                    raise urllib.error.HTTPError("https://api.github.com", 500, "error", {}, None)
                return fake(path, token, missing)
            with patch.object(ci, "api", side_effect=branch_error):
                with self.assertRaises(urllib.error.HTTPError):
                    ci.prepare("owner/repo", "token", Path(tmp))

    def test_prepare_pins_and_validates_published_files_before_skip(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            tmp = Path(tmp)
            src = tmp / "source"
            src.mkdir()
            fixture(src)
            files = {str(p.relative_to(src)): p.read_bytes() for p in src.rglob("*") if p.is_file()}
            ids = {path: f"{i:040x}" for i, path in enumerate(files, 1)}
            def fake(path, token, missing=False):
                if path.endswith("/commits/sing"):
                    return {"sha": "a" * 40}
                if path.endswith("/branches/rules"):
                    return {"commit": {"sha": "d" * 40}}
                if "/git/commits/" in path:
                    self.assertIn("d" * 40, path)
                    return {"tree": {"sha": "e" * 40}}
                if "/git/trees/" in path:
                    self.assertIn("e" * 40, path)
                    return {"truncated": False, "tree": [
                        {"path": name, "type": "blob", "mode": "100644", "sha": ids[name]}
                        for name in files]}
                if "/git/blobs/" in path:
                    name = next(n for n in files if ids[n] == path.rsplit("/", 1)[-1])
                    return {"encoding": "base64", "size": len(files[name]),
                            "content": base64.b64encode(files[name]).decode()}
                return {}
            with patch.object(ci, "api", side_effect=fake), patch.object(ci, "fingerprint", return_value="b" * 64):
                self.assertFalse(ci.prepare("owner/repo", "token", tmp)["changed"])
                name = next(n for n in files if n.startswith("rules/"))
                original = files.pop(name)
                with self.assertRaises((ValueError, OSError)):
                    ci.prepare("owner/repo", "token", tmp)
                files[name] = b"tampered"
                with self.assertRaises(ValueError):
                    ci.prepare("owner/repo", "token", tmp)
                files[name] = original
                original_manifest = files["manifest.json"]
                files["manifest.json"] = b"not json"
                with self.assertRaises(ValueError):
                    ci.prepare("owner/repo", "token", tmp)
                files["manifest.json"] = original_manifest
            with patch.object(ci, "api", side_effect=fake), patch.object(ci, "fingerprint", return_value="c" * 64):
                self.assertTrue(ci.prepare("owner/repo", "token", tmp)["changed"])
            new_root = tmp / "new-root"
            (new_root / "config").mkdir(parents=True)
            sets = json.loads(Path("config/sets.json").read_text())
            sets[0] = "geo/geosite/replacement.srs"
            (new_root / "config/sets.json").write_text(json.dumps(sets))
            (new_root / "config/tools.json").write_bytes(Path("config/tools.json").read_bytes())
            with patch.object(ci, "ROOT", new_root), patch.object(ci, "api", side_effect=fake), patch.object(ci, "fingerprint", return_value="c" * 64):
                with self.assertRaises(ValueError):
                    ci.validate(src)
                self.assertTrue(ci.prepare("owner/repo", "token", tmp)["changed"])
                with patch.object(ci, "fingerprint", return_value="b" * 64):
                    self.assertTrue(ci.prepare("owner/repo", "token", tmp)["changed"])
                name = next(n for n in files if n.startswith("rules/"))
                files[name] = b"corrupt"
                with self.assertRaises(ValueError):
                    ci.prepare("owner/repo", "token", tmp)

    def test_workflow_limits_upload_and_write_to_approved_runs(self):
        doc = yaml.load(Path(".github/workflows/build.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertIn("schedule", doc["on"])
        self.assertIn("workflow_dispatch", doc["on"])
        self.assertEqual(set(doc["on"]), {"schedule", "workflow_dispatch"})
        self.assertEqual(doc["concurrency"]["cancel-in-progress"], "false")
        self.assertEqual(doc["jobs"]["build"]["permissions"]["contents"], "read")
        self.assertEqual(doc["jobs"]["publish"]["permissions"]["contents"], "write")
        self.assertIn("commit", doc["jobs"]["build"]["outputs"])
        self.assertIn("fingerprint", doc["jobs"]["build"]["outputs"])
        publish = doc["jobs"]["publish"]["steps"][-1]
        self.assertIn('needs.build.outputs.commit', publish["env"]["EXPECTED_COMMIT"])
        self.assertIn('needs.build.outputs.fingerprint', publish["env"]["EXPECTED_FINGERPRINT"])
        self.assertIn('--commit "$EXPECTED_COMMIT"', publish["run"])
        self.assertIn('--fingerprint "$EXPECTED_FINGERPRINT"', publish["run"])
        self.assertIn("LICENSING_PROVENANCE_APPROVED", doc["jobs"]["publish"]["if"])
        uploads = [step for step in doc["jobs"]["build"]["steps"] if "upload-artifact@" in step.get("uses", "")]
        self.assertEqual(len(uploads), 1)
        self.assertIn("LICENSING_PROVENANCE_APPROVED", uploads[0]["if"])
        self.assertIn("rules/*", uploads[0]["with"]["path"])
        self.assertNotIn("scripts/", uploads[0]["with"]["path"])
        for job in doc["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^[^@]+@[0-9a-f]{40}$")

    def test_fingerprint_changes_with_inputs(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            path = Path(tmp) / "input"
            path.write_text("a")
            first = ci.fingerprint("a" * 40, "https://example.test", [path])
            self.assertNotEqual(first, ci.fingerprint("b" * 40, "https://example.test", [path]))
            path.write_text("b")
            self.assertNotEqual(first, ci.fingerprint("a" * 40, "https://example.test", [path]))
            self.assertNotEqual(first, ci.fingerprint("a" * 40, "https://other.example.test", [path]))

    def test_validate_rejects_tampering_extras_and_traversal(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            root = Path(tmp)
            manifest = fixture(root)
            ci.validate(root)
            path = root / next(iter(manifest["outputs"]))
            path.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                ci.validate(root)
            path.write_bytes(b"synthetic")
            (root / "extra").write_text("extra")
            with self.assertRaises(ValueError):
                ci.validate(root)
            (root / "extra").unlink()
            manifest["outputs"]["../escape"] = "0" * 64
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                ci.validate(root)

    def test_rejects_incomplete_manifest_and_expected_mismatch(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            root = Path(tmp)
            manifest = fixture(root)
            ci.validate(root, expected_commit="a" * 40, expected_fingerprint="b" * 64)
            for commit, fingerprint in (("c" * 40, "b" * 64), ("a" * 40, "c" * 64)):
                with self.assertRaises(ValueError):
                    ci.validate(root, expected_commit=commit, expected_fingerprint=fingerprint)
            manifest["sources"].pop()
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                ci.validate(root)

    def test_rejects_invalid_metadata_and_provider_correspondence(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            root = Path(tmp)
            manifest = fixture(root)
            manifest["tools"]["mihomo"]["binary_sha256"] = "bad"
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                ci.validate(root)
            manifest = fixture_reset = json.loads((root / "manifest.json").read_text())
            fixture_reset["tools"]["mihomo"]["binary_sha256"] = json.loads(Path("config/tools.json").read_text())["mihomo"]["binary_sha256"]
            provider_file = root / "rule-providers.yaml"
            data = provider_file.read_text().replace("behavior: \"domain\"", "behavior: \"ipcidr\"", 1)
            provider_file.write_text(data)
            fixture_reset["outputs"]["rule-providers.yaml"] = hashlib.sha256(data.encode()).hexdigest()
            (root / "manifest.json").write_text(json.dumps(fixture_reset))
            with self.assertRaises(ValueError):
                ci.validate(root)

    def test_publish_requires_fingerprint(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing") as tmp:
            root = Path(tmp)
            manifest = fixture(root)
            manifest.pop("ci_fingerprint")
            (root / "manifest.json").write_text(json.dumps(manifest))
            ci.validate(root, unstamped=True)
            with self.assertRaises(ValueError):
                ci.validate(root)


if __name__ == "__main__":
    unittest.main()
