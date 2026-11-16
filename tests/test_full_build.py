import hashlib
import json
import tempfile
import unittest
import io
import tarfile
import sys
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

from scripts.build import build

SNAPSHOTS = {"MetaCubeX/meta-rules-dat": "c" * 40,
             "runetfreedom/russia-blocked-geoip": "d" * 40}


class FullBuildTests(unittest.TestCase):
    def test_wildcard_remainder_with_empty_labels_is_dropped(self):
        from scripts.build import normalize_full_rules
        values = ["+..example.com", "+.example..com", "*..example.com"]
        for field in ("domain", "domain_suffix"):
            with self.subTest(field=field):
                rules, report = normalize_full_rules([{field: values}])
                self.assertEqual(rules, [])
                self.assertEqual([item["value"] for item in report["dropped"]], values)
                self.assertTrue(all(item["reason"] == "invalid domain" for item in report["dropped"]))

    def test_plus_prefix_is_suffix_and_rejects_broad_values(self):
        from scripts.build import normalize_full_rules
        for field in ("domain", "domain_suffix"):
            with self.subTest(field=field):
                rules, report = normalize_full_rules([{field: ["+.EXAMPLE.COM", "+.Пример.РФ", "+.com"]}])
                self.assertEqual(rules, [{"domain_suffix": ["example.com", "xn--e1afmkfd.xn--p1ai"]}])
                self.assertEqual(report["dropped"], [{"field": field, "value": "+.com", "reason": "wildcard too broad"}])

    def test_exact_domain_with_leading_dot_is_dropped_not_fatal(self):
        from scripts.build import normalize_full_rules
        rules, report = normalize_full_rules([{"domain": [".example.com", "ok.example"]}])
        self.assertEqual(rules, [{"domain": ["ok.example"]}])
        self.assertEqual(report["dropped"], [{"field": "domain", "value": ".example.com", "reason": "invalid domain"}])
        with self.assertRaisesRegex(ValueError, "invalid IP network"):
            normalize_full_rules([{"domain": ".example.com", "ip_cidr": "bad"}])

    def test_adguard_decompile_exclusion_is_limited_to_known_error_and_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config/tools.json").write_text(json.dumps({
                "sing-box": {"version": "v", "binary_sha256": "x"},
                "mihomo": {"version": "v", "binary_sha256": "x"}}))
            for name in ("README.md", "GUIDE.md"):
                (root / name).write_text(name)
            known = b"unable to decompile binary AdGuard rules to rule-set."
            cases = [("AdGuard/HostlistsRegistry/a.srs", known, True),
                     ("AdGuard/HostlistsRegistry/a.srs", b"\x1b[31mFATAL\x1b[0m[0000] " + known + b"\n", True),
                     ("AdGuard/HostlistsRegistry/a.srs", b"FATAL[0000] " + known + b"\nextra error\n", False),
                     ("AdGuard/HostlistsRegistry/a.srs", known + b" extra error", False),
                     ("other/a.srs", known, False),
                     ("AdGuard/HostlistsRegistry/a.srs", b"other error", False)]
            for index, (source, stderr, allowed) in enumerate(cases):
                file = root / source
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"x")
                blob = hashlib.sha1(b"blob 1\0x").hexdigest()
                catalog = {source: (blob, 1)}
                def run(args, **kwargs):
                    raise subprocess.CalledProcessError(1, args, stderr=stderr)
                with self.subTest(source=source, stderr=stderr), \
                     patch("scripts.build.ROOT", root), patch("scripts.build.verify_sha256"), \
                     patch("scripts.build.check_version", return_value={}), \
                     patch("scripts.build.NativeCatalog"), patch("scripts.build.subprocess.run", side_effect=run):
                    args = (root, root / f"out{index}", root, root / "sing", root / "mihomo",
                            "a" * 40, "https://example.test")
                    if allowed:
                        build(*args, full_catalog=catalog, native_snapshots=SNAPSHOTS)
                        excluded = json.loads((root / f"out{index}/manifest.json").read_text())["excluded"]
                        self.assertEqual(excluded[0]["git_blob"], blob)
                        self.assertEqual(excluded[0]["reason"], "sing-box cannot decompile binary AdGuard rules")
                    else:
                        with self.assertRaises(subprocess.CalledProcessError):
                            build(*args, full_catalog=catalog, native_snapshots=SNAPSHOTS)

    def test_normalizes_domains_recursively_and_reports_drops(self):
        from scripts.build import normalize_full_rules
        rules = [{"type": "logical", "mode": "or", "invert": True, "rules": [
            {"domain": ["EXAMPLE.COM.", "*.Пример.РФ", '"bad.example']},
            {"domain_suffix": [".EXAMPLE.COM.", "x,y"]},
            {"domain_keyword": "KeepCase", "ip_cidr": "192.0.2.0/24", "process_name": "App"},
            {"domain": "bad,name"},
        ]}]
        result, report = normalize_full_rules(rules)
        children = result[0]["rules"]
        self.assertEqual(children[0]["domain"], ["example.com"])
        self.assertEqual(children[0]["domain_suffix"], ["xn--e1afmkfd.xn--p1ai"])
        self.assertEqual(children[1]["domain_suffix"], [".example.com"])
        self.assertEqual(children[2], {"domain_keyword": "KeepCase", "ip_cidr": "192.0.2.0/24", "process_name": "App"})
        self.assertTrue(result[0]["invert"])
        self.assertEqual(len(children), 3)
        self.assertEqual(len(report["dropped"]), 3)
        self.assertEqual(report["removed_rules"], 1)
        self.assertGreater(report["changed"]["lower"], 0)
        self.assertGreater(report["changed"]["trailing_dot"], 0)
        self.assertGreater(report["changed"]["wildcard"], 0)
        self.assertGreater(report["changed"]["idna"], 0)

    def test_normalization_does_not_hide_invalid_fields(self):
        from scripts.build import normalize_full_rules
        for extra in ({"unknown": "x"}, {"ip_cidr": "bad"}, {"domain_regex": "(?=x)"},
                      {"process_name": []}, {"domain_suffix": []}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                normalize_full_rules([{"domain": '"bad.example', **extra}])

    def test_normalization_removes_empty_rules(self):
        from scripts.build import normalize_full_rules
        rules, report = normalize_full_rules([{"domain": '"bad.example'}])
        self.assertEqual(rules, [])
        self.assertEqual(report["dropped"][0]["value"], '"bad.example')
        self.assertEqual(report["removed_rules"], 1)

    def test_malformed_domains_are_dropped_without_repair(self):
        from scripts.build import normalize_full_rules
        values = ['"certr.ru', '"med-brat.com', '"sertifikat-med-3.org',
                  'dokumentam24.ru,', 'krak%e1%ba%b9n.com', 'spravkasrochno.ru\\vse-spravki',
                  '..пример.рф']
        rules, report = normalize_full_rules([{"domain_suffix": values}])
        self.assertEqual(rules, [])
        self.assertEqual([item["value"] for item in report["dropped"]], values)

    def test_build_records_normalization_and_emits_normalized_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config/tools.json").write_text(json.dumps({
                "sing-box": {"version": "v", "binary_sha256": "x"},
                "mihomo": {"version": "v", "binary_sha256": "x"}}))
            for name in ("README.md", "GUIDE.md"):
                (root / name).write_text(name)
            (root / "a.srs").write_bytes(b"x")
            catalog = {"a.srs": (hashlib.sha1(b"blob 1\0x").hexdigest(), 1)}
            payloads = []
            def run(args, **kwargs):
                if "decompile" in args:
                    Path(args[-1]).write_text(json.dumps({"version": 1, "rules": [
                        {"domain": ["EXAMPLE.COM.", "*.Пример.РФ", "bad,"]}]}))
                else:
                    payloads.append(Path(args[-2]).read_text())
                    Path(args[-1]).write_bytes(b"mrs")
            with patch("scripts.build.ROOT", root), patch("scripts.build.verify_sha256"), \
                 patch("scripts.build.check_version", return_value={}), \
                 patch("scripts.build.NativeCatalog") as native, patch("scripts.build.subprocess.run", side_effect=run):
                native.return_value.maybe_reuse.return_value = {"method": "converted_srs", "reason": "candidate absent"}
                build(root, root / "out", root, root / "sing", root / "mihomo", "a"*40,
                      "https://example.test", full_catalog=catalog, native_snapshots=SNAPSHOTS)
            report = json.loads((root / "out/manifest.json").read_text())["sources"][0]["normalization"]
            self.assertEqual(report["dropped"], [{"field": "domain", "value": "bad,", "reason": "invalid domain"}])
            self.assertIn('"example.com"', payloads[0])
            self.assertIn('"+.xn--e1afmkfd.xn--p1ai"', payloads[0])

    def test_fetch_catalog_checks_commit_root_against_tree_entries(self):
        from scripts import build as module
        blob = hashlib.sha1(b"blob 1\0x").hexdigest()
        payload = b"100644 a.srs\0" + bytes.fromhex(blob)
        root_sha = hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
        commit = "a" * 40
        commit_obj = {"sha": commit, "tree": {"sha": root_sha}}
        tree = {"sha": commit, "truncated": False, "tree": [
            {"path": "a.srs", "mode": "100644", "type": "blob", "sha": blob, "size": 1}]}
        def fetch(url, limit):
            return json.dumps(commit_obj if "/commits/" in url else tree).encode()
        with patch.object(module, "_fetch", side_effect=fetch):
            self.assertEqual(module.fetch_catalog(commit), {"a.srs": (blob, 1)})
            tree["tree"][0]["sha"] = "b" * 40
            with self.assertRaisesRegex(ValueError, "tree hash"):
                module.fetch_catalog(commit)

    def test_trusted_full_catalog_must_equal_anchored_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            anchored = {"a.srs": ("a" * 40, 1), "b.srs": ("b" * 40, 1)}
            for supplied in ({"a.srs": ("a" * 40, 1)}, {"a.srs": ("f" * 40, 1), "b.srs": ("b" * 40, 1)}):
                for origin in ("git_blob_verified", "authenticated_download"):
                    with self.subTest(supplied=supplied, origin=origin), \
                         patch("scripts.build.fetch_catalog", return_value=anchored), \
                         patch("scripts.build.verify_sha256") as verify:
                        with self.assertRaisesRegex(ValueError, "catalog"):
                            build(root, root / "out", root, root / "sing", root / "mihomo", "a" * 40,
                                  "https://example.test", origin, full_catalog=supplied, native_snapshots=SNAPSHOTS)
                        verify.assert_not_called()
    def test_full_existing_output_rejected_before_tool_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for kind in ("directory", "dangling", "regular"):
                out = root / kind
                if kind == "directory":
                    out.mkdir()
                elif kind == "dangling":
                    out.symlink_to(root / "missing")
                else:
                    out.write_text("keep")
                with self.subTest(kind=kind), patch("scripts.build.verify_sha256") as verify:
                    with self.assertRaises(FileExistsError):
                        build(root, out, root, root / "sing", root / "mihomo", "a" * 40,
                              "https://example.test", full_catalog={})
                    verify.assert_not_called()

    def test_rename_noreplace_race_and_success(self):
        from scripts.build import rename_noreplace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage, out = root / "stage", root / "out"
            stage.mkdir()
            (stage / "data").write_text("new")
            out.mkdir()
            (out / "data").write_text("old")
            with self.assertRaises(FileExistsError):
                rename_noreplace(stage, out)
            self.assertEqual((out / "data").read_text(), "old")
            self.assertTrue(stage.exists())
            (out / "data").unlink()
            out.rmdir()
            rename_noreplace(stage, out)
            self.assertFalse(stage.exists())
            self.assertEqual((out / "data").read_text(), "new")

    @patch("scripts.build.NativeCatalog")
    def test_full_build_preserves_names_and_excludes_invalid_domain(self, native):
        native.return_value.maybe_reuse.return_value = {"method": "converted_srs", "reason": "candidate absent"}
        with tempfile.TemporaryDirectory(prefix="full-test-") as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            for name in ("README.md", "GUIDE.md"):
                (root / name).write_text(name)
            (root / "config/tools.json").write_text(json.dumps({
                "sing-box": {"version": "v", "binary_sha256": "x"},
                "mihomo": {"version": "v", "binary_sha256": "x"}}))
            paths = ["geo/geosite/a@!cn.srs", "geo/geosite/invalid.srs"]
            for path in paths:
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(path.encode())
            blobs = {path: (hashlib.sha1(b"blob " + str(len(path)).encode() + b"\0" + path.encode()).hexdigest(), len(path))
                     for path in paths}
            approved = ["invalid domain", blobs[paths[1]][0]]
            (root / "config/exclusions.json").write_text(json.dumps({paths[1]: approved}))
            def run(args, **kwargs):
                if "decompile" in args:
                    name = Path(args[-3]).name
                    value = "*.bad" if name == "invalid.srs" else "ok.example"
                    Path(args[-1]).write_text(json.dumps({"version": 1, "rules": [{"domain": value}]}))
                else:
                    Path(args[-1]).write_bytes(b"mrs")
            from scripts.build import rename_noreplace
            with patch("scripts.build.fetch_catalog", return_value=blobs), patch("scripts.build.ROOT", root), patch("scripts.build.verify_sha256"), \
                    patch("scripts.build.check_version", return_value={}), \
                    patch("scripts.build.subprocess.run", side_effect=run), \
                    patch("scripts.build.rename_noreplace", wraps=rename_noreplace) as commit:
                build(root, root / "out", root, root / "sing", root / "mihomo",
                      "a" * 40, "https://example.test/rules", "authenticated_download",
                      full_catalog=blobs, native_snapshots=SNAPSHOTS)
                self.assertEqual(commit.call_count, 1)
            manifest = json.loads((root / "out/manifest.json").read_text())
            self.assertEqual(len(manifest["sources"]), 2)
            self.assertEqual(len(manifest["excluded"]), 1)
            self.assertEqual(manifest["excluded"][0]["source"], paths[1])
            self.assertEqual(manifest["excluded"][0]["reason"], "no rules after normalization")
            self.assertEqual(manifest["excluded"][0]["normalization"]["dropped"][0]["value"], "*.bad")
            self.assertTrue((root / "out/mihomo/geosite/a@!cn.mrs").is_file())
            self.assertIn("a%40%21cn.mrs", (root / "out/rule-providers.yaml").read_text())
            with patch("scripts.build.fetch_catalog", return_value=blobs), patch("scripts.build.ROOT", root), patch("scripts.build.verify_sha256"), \
                    patch("scripts.build.check_version", return_value={}), \
                    patch("scripts.build.subprocess.run", side_effect=run), \
                    patch("scripts.build.validate_full_rules", side_effect=ValueError("bad condition")):
                with self.assertRaisesRegex(ValueError, r"geo/geosite/a@!cn\.srs: bad condition"):
                    build(root, root / "failed", root, root / "sing", root / "mihomo",
                          "a" * 40, "https://example.test/rules", "authenticated_download",
                          full_catalog=blobs, native_snapshots=SNAPSHOTS)
                self.assertFalse((root / "failed").exists())
            def race(stage, target):
                target.mkdir()
                (target / "other").write_text("keep")
                rename_noreplace(stage, target)
            with patch("scripts.build.fetch_catalog", return_value=blobs), patch("scripts.build.ROOT", root), patch("scripts.build.verify_sha256"), \
                    patch("scripts.build.check_version", return_value={}), \
                    patch("scripts.build.subprocess.run", side_effect=run), \
                    patch("scripts.build.rename_noreplace", side_effect=race) as commit:
                with self.assertRaises(FileExistsError):
                    build(root, root / "race", root, root / "sing", root / "mihomo",
                          "a" * 40, "https://example.test/rules", "authenticated_download",
                          full_catalog=blobs, native_snapshots=SNAPSHOTS)
                self.assertEqual(commit.call_count, 1)
                self.assertEqual((root / "race/other").read_text(), "keep")
            with patch("scripts.build.fetch_catalog", return_value=blobs), patch("scripts.build.ROOT", root), patch("scripts.build.verify_sha256"), \
                    patch("scripts.build.check_version", return_value={}), \
                    patch("scripts.build.subprocess.run", side_effect=run):
                (root / paths[1]).write_bytes(b"corrupt")
                with self.assertRaises(ValueError):
                    build(root, root / "rejected", root, root / "sing", root / "mihomo",
                          "a" * 40, "https://example.test/rules", "authenticated_download",
                          full_catalog=blobs, native_snapshots=SNAPSHOTS)
                self.assertFalse((root / "rejected").exists())

    def test_full_build_rejects_corrupt_blob(self):
        from scripts.build import verify_blob
        with self.assertRaises(ValueError):
            verify_blob(b"corrupt", "0" * 40, 7)

    def test_unknown_condition_is_not_hidden_by_invalid_domain(self):
        from scripts.build import validate_full_rules
        with self.assertRaisesRegex(ValueError, "unknown rule field"):
            validate_full_rules([{"domain": "*.invalid"}, {"future_field": "value"}])
        self.assertEqual(validate_full_rules([{"domain": "*.invalid"}]), "invalid domain")

    def test_unsupported_regex_is_not_hidden_by_invalid_domain(self):
        from scripts.build import validate_full_rules
        with self.assertRaisesRegex(ValueError, "unsupported regex"):
            validate_full_rules([{"domain": "*.invalid", "domain_regex": "(?=unsupported)"}])

    def test_invalid_domain_delimiters_do_not_hide_other_errors(self):
        from scripts.build import validate_full_rules, convert_rule
        for key in ("domain", "domain_suffix"):
            for value in ("bad.example,", "bad(example)"):
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(ValueError, "^invalid domain$"):
                        convert_rule({key: value})
                    self.assertEqual(validate_full_rules([{key: [value, "*.invalid"]}]), "invalid domain")
        for extra, error in (({"future_field": "x"}, "unknown rule field"),
                             ({"domain_regex": "(?=unsupported)"}, "unsupported regex"),
                             ({"ip_cidr": "not-an-ip"}, "invalid IP network"),
                             ({"process_name": "bad,name"}, "invalid rule value"),
                             ({"domain_keyword": "bad,name"}, "invalid rule value"),
                             ({"domain_suffix": 42}, "expected nonempty list of strings"),
                             ({"domain_suffix": ""}, "invalid rule value")):
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, error):
                validate_full_rules([{"domain": "*.invalid", **extra}])

    def test_invalid_domain_does_not_hide_empty_or_invalid_conditions_in_either_order(self):
        from scripts.build import validate_full_rules
        for extra in ({"process_name": []}, {"domain_suffix": []}, {"ip_cidr": []},
                      {"process_name": 42}, {"ip_cidr": "not-an-ip"},
                      {"domain_suffix": ["*.invalid", ""]}):
            for rule in ({"domain": "*.invalid", **extra}, {**extra, "domain": "*.invalid"}):
                with self.subTest(rule=rule), self.assertRaises(ValueError):
                    validate_full_rules([rule])
        self.assertEqual(validate_full_rules([{"domain": ["*.invalid", "bad.example,"]}]),
                         "invalid domain")

    def test_archive_rejects_links_and_corrupt_members(self):
        from scripts.build import extract_catalog
        with tempfile.TemporaryDirectory(prefix="full-test-") as tmp:
            root = Path(tmp)
            path = "geo/geosite/a.srs"
            data = b"abc"
            sha = hashlib.sha1(b"blob 3\0" + data).hexdigest()
            for kind in ("good", "link", "corrupt"):
                archive = root / "archive.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    info = tarfile.TarInfo("snapshot/" + path)
                    if kind == "link":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/etc/passwd"
                        tar.addfile(info)
                    else:
                        content = b"bad" if kind == "corrupt" else data
                        info.size = len(content)
                        tar.addfile(info, io.BytesIO(content))
                dest = root / kind
                dest.mkdir()
                if kind == "good":
                    extract_catalog(archive, {path: (sha, 3)}, dest)
                    self.assertEqual((dest / path).read_bytes(), data)
                else:
                    with self.assertRaises(ValueError):
                        extract_catalog(archive, {path: (sha, 3)}, dest)

    def test_archive_rejects_missing_and_duplicate_sources(self):
        from scripts.build import extract_catalog
        with tempfile.TemporaryDirectory(prefix="full-test-") as tmp:
            root = Path(tmp)
            archive = root / "archive.tar.gz"
            path, data = "geo/geosite/a.srs", b"abc"
            sha = hashlib.sha1(b"blob 3\0" + data).hexdigest()
            for count in (0, 2):
                with tarfile.open(archive, "w:gz") as tar:
                    for _ in range(count):
                        info = tarfile.TarInfo("snapshot/" + path)
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                with self.subTest(count=count), self.assertRaises(ValueError):
                    extract_catalog(archive, {path: (sha, len(data))}, root)

    def test_native_glue_manifest_docs_and_failure(self):
        with tempfile.TemporaryDirectory(prefix="glue-") as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config/tools.json").write_text(json.dumps({
                "sing-box": {"version": "v", "binary_sha256": "x"},
                "mihomo": {"version": "v", "binary_sha256": "x"}}))
            (root / "config/exclusions.json").write_text("{}")
            for name in ("README.md", "GUIDE.md"):
                (root / name).write_text(name)
            paths = ["geo/geosite/a.srs", "geo/geosite/b.srs", "geo/geosite/c.srs"]
            for path in paths:
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(path.encode())
            blobs = {p: (hashlib.sha1(b"blob " + str(len(p)).encode() + b"\0" + p.encode()).hexdigest(), len(p)) for p in paths}
            def run(args, **kwargs):
                if "decompile" in args:
                    name = Path(args[-3]).name
                    rule = {"domain_keyword": "example"} if name == "c.srs" else {"domain": "ok.example"}
                    Path(args[-1]).write_text(json.dumps({"version": 1, "rules": [rule]}))
                else:
                    Path(args[-1]).write_bytes(b"converted")
            def reuse(source, target, behavior):
                self.assertEqual(behavior, "domain")
                self.assertEqual(os.stat(native.call_args.args[2]).st_dev, os.stat(target.parent).st_dev)
                if source == paths[0]:
                    target.write_bytes(b"native")
                    return {"method": "native_mrs", "repo": "MetaCubeX/meta-rules-dat",
                            "commit": "c" * 40, "path": "geo/geosite/a.mrs",
                            "input_sha256": hashlib.sha256(b"native").hexdigest()}
                return {"method": "converted_srs", "reason": "not equivalent"}
            with patch("scripts.build.fetch_catalog", return_value=blobs), patch("scripts.build.ROOT", root), patch("scripts.build.verify_sha256"), \
                 patch("scripts.build.check_version", return_value={}), patch("scripts.build.subprocess.run", side_effect=run), \
                 patch("scripts.build.NativeCatalog") as native:
                native.return_value.maybe_reuse.side_effect = reuse
                build(root, root / "out", root, root / "sing", root / "mihomo", "a" * 40,
                      "https://example.test", "git_blob_verified", full_catalog=blobs, native_snapshots=SNAPSHOTS)
                self.assertEqual(native.return_value.maybe_reuse.call_count, 2)
                manifest = json.loads((root / "out/manifest.json").read_text())
                self.assertEqual(manifest["native_snapshots"], SNAPSHOTS)
                self.assertEqual(manifest["source_origin"], "git_blob_verified")
                a, b, c = manifest["sources"]
                self.assertEqual(a["sha256"], hashlib.sha256(paths[0].encode()).hexdigest())
                self.assertEqual(a["method"], "native_mrs")
                self.assertEqual(a["native"]["input_sha256"], manifest["outputs"][a["output"]])
                self.assertEqual((root / "out" / a["output"]).read_bytes(), b"native")
                self.assertEqual(b["native_reason"], "not equivalent")
                self.assertEqual(c["native_reason"], "classical behavior")
                for name in ("README.md", "GUIDE.md"):
                    self.assertEqual(manifest["outputs"][name], hashlib.sha256((root / name).read_bytes()).hexdigest())
                native.return_value.maybe_reuse.side_effect = RuntimeError("proof failed")
                with self.assertRaisesRegex(RuntimeError, "proof failed"):
                    build(root, root / "failed", root, root / "sing", root / "mihomo", "a" * 40,
                          "https://example.test", "git_blob_verified", full_catalog=blobs, native_snapshots=SNAPSHOTS)
                self.assertFalse((root / "failed").exists())

    def test_cli_requires_valid_snapshots_before_side_effects(self):
        from scripts import build as module
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = ["build.py", "--full", "--commit", "a" * 40, "--output", str(root / "out"),
                    "--work-dir", str(root / "work"), "--sing-box", "s", "--mihomo", "m"]
            for data in (None, {}, {**SNAPSHOTS, "MetaCubeX/meta-rules-dat": "bad"}):
                options = list(args)
                if data is not None:
                    path = root / "snapshots.json"
                    path.write_text(json.dumps(data))
                    options += ["--native-snapshots", str(path)]
                with self.subTest(data=data), patch.object(sys, "argv", options), \
                     patch.object(module, "download") as download, patch.object(module, "_fetch") as fetch:
                    with self.assertRaises((ValueError, SystemExit)):
                        module.main()
                    download.assert_not_called()
                    fetch.assert_not_called()
                    self.assertFalse((root / "work").exists())

    def test_cli_full_cache_origin_and_selected_local_origin(self):
        from scripts import build as module
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "snapshots.json"
            path.write_text(json.dumps(SNAPSHOTS))
            tree = {"sha": "a" * 40, "truncated": False, "tree": [
                {"path": "geo/geosite/a.srs", "type": "blob", "mode": "100644",
                 "sha": "f" * 40, "size": 3}]}
            def fetch(commit):
                self.assertEqual(commit, "a" * 40)
                return {"geo/geosite/a.srs": ("f" * 40, 3)}
            base = ["build.py", "--commit", "a" * 40, "--source-dir", str(root),
                    "--output", str(root / "out"), "--work-dir", str(root / "work"),
                    "--sing-box", "s", "--mihomo", "m"]
            with patch.object(module, "fetch_catalog", side_effect=fetch), patch.object(module, "build") as build_mock:
                with patch.object(sys, "argv", base + ["--full", "--native-snapshots", str(path)]):
                    module.main()
                self.assertEqual(build_mock.call_args.args[7], "git_blob_verified")
                self.assertEqual(build_mock.call_args.kwargs["full_catalog"]["geo/geosite/a.srs"], ("f" * 40, 3))
                self.assertEqual(build_mock.call_args.kwargs["native_snapshots"], SNAPSHOTS)
                with patch.object(sys, "argv", base):
                    module.main()
                self.assertEqual(build_mock.call_args.args[7], "local/unverified")
                self.assertIsNone(build_mock.call_args.kwargs["full_catalog"])

    def test_selected_mode_rejects_verified_cache_origin(self):
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.build.verify_sha256") as verify:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                build(root, root / "out", root, root / "sing", root / "mihomo",
                      "a" * 40, "https://example.test", "git_blob_verified")
            verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
