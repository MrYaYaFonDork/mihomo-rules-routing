import subprocess
import hashlib
import json
import io
import os
import email.message
import urllib.error
import urllib.request
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import native


class NativeTests(unittest.TestCase):
    def test_equal_sets_with_different_order_duplicates_and_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / "native.mrs", root / "converted.mrs"
            first.write_bytes(b"native")
            second.write_bytes(b"converted")

            def run(args, **kwargs):
                self.assertEqual(args[:4], ["mihomo", "convert-ruleset", "domain", "mrs"])
                self.assertTrue(kwargs["check"])
                self.assertTrue(kwargs["capture_output"])
                self.assertGreater(kwargs["timeout"], 0)
                output = "a.example\nb.example\na.example\n" if args[4] == str(first) else "b.example\na.example\n"
                Path(args[5]).write_text(output)

            with patch("scripts.native.subprocess.run", side_effect=run):
                self.assertTrue(native.reuse_equal(first, second, "domain", "mihomo", root))
            self.assertEqual(first.read_bytes(), b"native")
            self.assertEqual(second.read_bytes(), b"converted")

    def test_unequal_sets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def run(args, **kwargs):
                Path(args[5]).write_text("1.0.0.0/8\n" if args[4] == "a" else "2.0.0.0/8\n")
            with patch("scripts.native.subprocess.run", side_effect=run):
                self.assertFalse(native.reuse_equal("a", "b", "ipcidr", "mihomo", root))

    def test_rejects_wrong_behavior_without_running_cli(self):
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.native.subprocess.run") as run:
            with self.assertRaises(ValueError):
                native.reuse_equal("a", "b", "classical", "mihomo", tmp)
            run.assert_not_called()

    def test_cli_failure_is_fatal_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / "native.mrs", root / "converted.mrs"
            first.write_bytes(b"corrupt")
            second.write_bytes(b"converted")
            with patch("scripts.native.subprocess.run", side_effect=subprocess.CalledProcessError(1, "mihomo")):
                with self.assertRaises(subprocess.CalledProcessError):
                    native.reuse_equal(first, second, "domain", "mihomo", root)
            self.assertEqual(first.read_bytes(), b"corrupt")
            self.assertEqual(second.read_bytes(), b"converted")

    def test_missing_decoded_output_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.native.subprocess.run"):
            with self.assertRaises(FileNotFoundError):
                native.reuse_equal("a", "b", "domain", "mihomo", tmp)


class NativeCatalogTests(unittest.TestCase):
    META = "MetaCubeX/meta-rules-dat"
    RF = "runetfreedom/russia-blocked-geoip"
    SNAPSHOT = {META: "a" * 40, RF: "b" * 40}
    GEO, SITE, IP = "c" * 40, "d" * 40, "e" * 40
    BLOB = b"native"

    def tree(self, sha, entries, truncated=False):
        return json.dumps({"sha": sha, "tree": entries, "truncated": truncated}).encode()

    def branch(self, path, sha):
        return {"path": path, "type": "tree", "mode": "040000", "sha": sha}

    def blob(self, path, content=None):
        content = self.BLOB if content is None else content
        sha = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        return {"path": path, "type": "blob", "mode": "100644", "sha": sha, "size": len(content)}

    def fixtures(self):
        return {
            f"https://api.github.com/repos/{self.META}/git/trees/{'a' * 40}": self.tree("a" * 40, [self.branch("geo", self.GEO)]),
            f"https://api.github.com/repos/{self.META}/git/trees/{self.GEO}": self.tree(self.GEO, [self.branch("geosite", self.SITE), self.branch("geoip", self.IP)]),
            f"https://api.github.com/repos/{self.META}/git/trees/{self.SITE}?recursive=1": self.tree(self.SITE, [self.blob("google.mrs")]),
            f"https://api.github.com/repos/{self.META}/git/trees/{self.IP}?recursive=1": self.tree(self.IP, [self.blob("ru.mrs")]),
            f"https://api.github.com/repos/{self.RF}/git/trees/{'b' * 40}?recursive=1": self.tree("b" * 40, [self.branch("mrs", self.GEO), self.blob("mrs/ru-blocked.mrs"), self.blob("mrs/ru-blocked-community.mrs"), self.blob("mrs/re-filter.mrs")]),
            f"https://raw.githubusercontent.com/{self.META}/{'a' * 40}/geo/geosite/google.mrs": self.BLOB,
            f"https://raw.githubusercontent.com/{self.META}/{'a' * 40}/geo/geoip/ru.mrs": self.BLOB,
            f"https://raw.githubusercontent.com/{self.RF}/{'b' * 40}/mrs/ru-blocked.mrs": self.BLOB,
            f"https://raw.githubusercontent.com/{self.RF}/{'b' * 40}/mrs/ru-blocked-community.mrs": self.BLOB,
            f"https://raw.githubusercontent.com/{self.RF}/{'b' * 40}/mrs/re-filter.mrs": self.BLOB,
        }

    def test_equal_reuses_verified_blob_and_caches_alias_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out.mrs"
            calls = []
            fixtures = self.fixtures()
            def fetch(url, limit):
                calls.append(url)
                return fixtures[url]
            with patch("scripts.native._fetch", side_effect=fetch), patch("scripts.native.reuse_equal", return_value=True) as proof:
                catalog = native.NativeCatalog(self.SNAPSHOT, "mihomo", root)
                out.write_bytes(b"converted")
                result = catalog.maybe_reuse("geo/geosite/google.srs", out, "domain")
                self.assertEqual(result, {"repo": self.META, "commit": "a" * 40, "path": "geo/geosite/google.mrs", "input_sha256": hashlib.sha256(self.BLOB).hexdigest(), "method": "native_mrs"})
                self.assertEqual(out.read_bytes(), self.BLOB)
                out.write_bytes(b"converted")
                catalog.maybe_reuse("russia/runetfreedom/sing-box/rule-set-geosite/geosite-google.srs", out, "domain")
                self.assertEqual(out.read_bytes(), self.BLOB)
                self.assertEqual(proof.call_count, 1)
                self.assertEqual(len(calls), 6)

    def test_fallbacks_do_not_change_output(self):
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.native._fetch", side_effect=lambda url, limit: self.fixtures()[url]), patch("scripts.native.reuse_equal", return_value=False):
            root = Path(tmp)
            out = root / "out.mrs"
            out.write_bytes(b"converted")
            catalog = native.NativeCatalog(self.SNAPSHOT, "mihomo", root)
            for source, behavior, reason in (("geo/geosite/google.srs", "domain", "not equivalent"),
                                             ("geo/geosite/missing.srs", "domain", "candidate absent"),
                                             ("geo/geosite/google.srs", "ipcidr", "behavior mismatch"),
                                             ("other/list.srs", "domain", "no candidate mapping"),
                                             ("geo/geosite/google.srs", "classical", "classical behavior")):
                with self.subTest(reason=reason):
                    self.assertEqual(catalog.maybe_reuse(source, out, behavior)["reason"], reason)
                    self.assertEqual(out.read_bytes(), b"converted")

    def test_invalid_metadata_is_fatal(self):
        for kind in ("truncated", "sha", "unsafe", "duplicate", "badblob"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                fixtures = self.fixtures()
                url = f"https://api.github.com/repos/{self.META}/git/trees/{self.SITE}?recursive=1"
                entries = [self.blob("google.mrs")]
                if kind == "unsafe":
                    entries = [self.blob("../evil.mrs")]
                if kind == "duplicate":
                    entries *= 2
                if kind == "badblob":
                    entries[0]["size"] = -1
                fixtures[url] = self.tree("f" * 40 if kind == "sha" else self.SITE, entries, kind == "truncated")
                with patch("scripts.native._fetch", side_effect=lambda url, limit: fixtures[url]), self.assertRaises(ValueError):
                    native.NativeCatalog(self.SNAPSHOT, "mihomo", tmp)

    def test_corrupt_download_and_proof_error_are_fatal(self):
        for kind in ("hash", "size", "proof"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                out = root / "out"
                out.write_bytes(b"converted")
                fixtures = self.fixtures()
                url = f"https://raw.githubusercontent.com/{self.META}/{'a' * 40}/geo/geosite/google.mrs"
                if kind == "hash":
                    fixtures[url] = b"broken"
                if kind == "size":
                    fixtures[url] = b"x"
                with patch("scripts.native._fetch", side_effect=lambda url, limit: fixtures[url]), patch("scripts.native.reuse_equal", side_effect=subprocess.CalledProcessError(1, "mihomo")):
                    catalog = native.NativeCatalog(self.SNAPSHOT, "mihomo", root)
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        catalog.maybe_reuse("geo/geosite/google.srs", out, "domain")
                self.assertEqual(out.read_bytes(), b"converted")

    def test_mapping_and_snapshot_validation(self):
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.native._fetch", side_effect=lambda url, limit: self.fixtures()[url]), patch("scripts.native.reuse_equal", return_value=True):
            with self.assertRaises(ValueError):
                native.NativeCatalog({**self.SNAPSHOT, self.RF: "invalid"}, "mihomo", tmp)
            catalog = native.NativeCatalog(self.SNAPSHOT, "mihomo", tmp)
            out = Path(tmp) / "out"
            for source, behavior, path in (
                ("geo/geoip/ru.srs", "ipcidr", "geo/geoip/ru.mrs"),
                ("geo/geoip/blocked@ru.srs", "ipcidr", "mrs/ru-blocked.mrs"),
                ("geo/geoip/blocked-community@ru.srs", "ipcidr", "mrs/ru-blocked-community.mrs"),
                ("geo/geoip/re-filter@ru.srs", "ipcidr", "mrs/re-filter.mrs"),
                ("russia/runetfreedom/sing-box/rule-set-geoip/geoip-re-filter.srs", "ipcidr", "mrs/re-filter.mrs"),
            ):
                out.write_bytes(b"converted")
                self.assertEqual(catalog.maybe_reuse(source, out, behavior)["path"], path)

    def test_fetch_enforces_status_size_timeout_and_no_redirect(self):
        class Response(io.BytesIO):
            status = 200
        response = Response(b"123")
        with patch("scripts.native.urllib.request.build_opener") as make:
            make.return_value.open.return_value = response
            self.assertEqual(native._fetch("https://example.test", 3), b"123")
            self.assertIsInstance(make.call_args.args[0], native._NoRedirect)
            make.return_value.open.assert_called_once_with("https://example.test", timeout=45)
        for status, content in ((200, b"1234"), (404, b"")):
            response = Response(content)
            response.status = status
            with patch("scripts.native.urllib.request.build_opener") as make:
                make.return_value.open.return_value = response
                with self.assertRaises(ValueError):
                    native._fetch("https://example.test", 3)
        self.assertIsNone(native._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test"))

    def test_fetch_token_only_to_github_api_and_never_follows_redirect(self):
        from scripts import build
        self.assertIs(build._fetch, native._fetch)
        requests = []
        def https_open(handler, request):
            requests.append((request.full_url, request.get_header("Authorization")))
            headers = email.message.Message()
            headers["Location"] = "https://elsewhere.test/not-found"
            response = urllib.response.addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
            response.msg = "mock"
            return response
        with patch.dict(os.environ, {"GH_TOKEN": "test-only-secret"}), \
                patch.object(urllib.request.HTTPSHandler, "https_open", https_open):
            for url in ("https://api.github.com/repos/org/repo", "https://raw.githubusercontent.com/org/repo",
                        "https://api.github.com.evil.test/x", "https://api.github.com:443/x"):
                with self.subTest(url=url), self.assertRaises(urllib.error.HTTPError) as error:
                    native._fetch(url, 10)
                self.assertNotIn("test-only-secret", str(error.exception))
        self.assertEqual([h for _, h in requests], ["Bearer test-only-secret", None, None, None])
        self.assertTrue(all("test-only-secret" not in url for url, _ in requests))
        self.assertEqual(len(requests), 4)
        with patch.dict(os.environ, {"GH_TOKEN": "secret\nleak"}):
            with self.assertRaises(ValueError) as error:
                native._fetch("https://api.github.com/repos/org/repo", 10)
            self.assertNotIn("secret", str(error.exception))

    def test_unsafe_source_and_network_error_are_fatal(self):
        fixtures = self.fixtures()
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.native._fetch", side_effect=lambda url, limit: fixtures[url]):
            out = Path(tmp) / "out"
            out.write_bytes(b"converted")
            catalog = native.NativeCatalog(self.SNAPSHOT, "mihomo", tmp)
            with self.assertRaises(ValueError):
                catalog.maybe_reuse("geo/geosite/../google.srs", out, "domain")
            with patch("scripts.native._fetch", side_effect=OSError("network")):
                with self.assertRaises(OSError):
                    catalog.maybe_reuse("geo/geosite/google.srs", out, "domain")
            self.assertEqual(out.read_bytes(), b"converted")

    def test_non_mrs_metadata_and_recursive_hierarchy_are_validated(self):
        good = [self.branch("dir", self.GEO), self.branch("dir/sub", self.IP),
                self.blob("dir/sub/file.txt"), self.blob("dir/sub/file.mrs")]
        broken = [
            [dict(self.blob("note.txt"), sha="bad")],
            [dict(self.blob("note.txt"), mode="040000")],
            [dict(self.blob("note.txt"), size=-1)],
            [dict(self.blob("note.txt"), type="commit", mode="160000")],
            [dict(self.blob("note.txt"), mode="120000")],
            [self.blob("dir/sub/file.mrs")],
            [self.blob("dir"), self.blob("dir/file.mrs")],
            [self.branch("dir", self.GEO), self.blob("dir/sub/file.mrs")],
        ]
        url = f"https://api.github.com/repos/{self.META}/git/trees/{self.SITE}?recursive=1"
        with tempfile.TemporaryDirectory() as tmp:
            for entries in [good, *broken]:
                fixtures = self.fixtures()
                fixtures[url] = self.tree(self.SITE, entries)
                with self.subTest(entries=entries), patch("scripts.native._fetch", side_effect=lambda url, limit: fixtures[url]):
                    if entries == good:
                        native.NativeCatalog(self.SNAPSHOT, "mihomo", tmp)
                    else:
                        with self.assertRaises(ValueError):
                            native.NativeCatalog(self.SNAPSHOT, "mihomo", tmp)

    def test_output_mode_is_preserved_on_success_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.native._fetch", side_effect=lambda url, limit: self.fixtures()[url]):
            out = Path(tmp) / "out"
            out.write_bytes(b"converted")
            out.chmod(0o4754)
            catalog = native.NativeCatalog(self.SNAPSHOT, "mihomo", tmp)
            with patch("scripts.native.reuse_equal", side_effect=subprocess.CalledProcessError(1, "mihomo")):
                with self.assertRaises(subprocess.CalledProcessError):
                    catalog.maybe_reuse("geo/geosite/google.srs", out, "domain")
            self.assertEqual(out.read_bytes(), b"converted")
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o4754)
            with patch("scripts.native.reuse_equal", return_value=True), patch("scripts.native.os.fchmod", side_effect=OSError("chmod failed")):
                with self.assertRaises(OSError):
                    catalog.maybe_reuse("geo/geosite/google.srs", out, "domain")
            self.assertEqual(out.read_bytes(), b"converted")
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o4754)
            with patch("scripts.native.reuse_equal", return_value=True):
                catalog.maybe_reuse("geo/geosite/google.srs", out, "domain")
            self.assertEqual(out.read_bytes(), self.BLOB)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o4754)
