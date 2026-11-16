import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import re
import urllib.error
import subprocess
import io
import email.message
import tarfile
import sys
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


def anchored_tree(entries, commit):
    entries = [dict(item) for item in entries]
    dirs = set()
    for item in entries:
        parent = Path(item["path"]).parent
        while str(parent) != ".":
            dirs.add(str(parent))
            parent = parent.parent
    nodes = {item["path"]: item for item in entries}
    for name in dirs:
        nodes[name] = {"path": name, "mode": "040000", "type": "tree", "sha": ""}
    for directory in sorted(dirs | {""}, key=lambda p: p.count("/") + bool(p), reverse=True):
        children = [(path.rpartition("/")[2], item) for path, item in nodes.items()
                    if path.rpartition("/")[0] == directory]
        children.sort(key=lambda pair: pair[0].encode() + (b"/" if pair[1]["type"] == "tree" else b""))
        payload = b"".join((item["mode"].lstrip("0") + " " + name).encode() + b"\0" +
                           bytes.fromhex(item["sha"]) for name, item in children)
        sha = hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
        if directory:
            nodes[directory]["sha"] = sha
        else:
            root_sha = sha
    return {"sha": commit, "tree": {"sha": root_sha}}, {"sha": commit, "truncated": False, "tree": list(nodes.values())}


class CiTests(unittest.TestCase):
    def test_prepare_historical_full_snapshot_rejects_invalid_tree_and_archives(self):
        snapshots = {"MetaCubeX/meta-rules-dat": "c"*40,
                     "runetfreedom/russia-blocked-geoip": "d"*40}
        with tempfile.TemporaryDirectory(prefix="ci-real-history-") as tmp:
            root = Path(tmp)
            source = root / "source"
            target = source / "mihomo/geosite/A+!.mrs"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"synthetic")
            path, name = "mihomo/geosite/A+!.mrs", "mihomo/geosite/A+!"
            document = providers_yaml({name: {"type": "http", "behavior": "domain",
                "format": "mrs", "path": "./" + path,
                "url": "https://example.test/mihomo/geosite/A%2B%21.mrs", "interval": 86400}})
            (source / "rule-providers.yaml").write_text(document)
            for doc in ("README.md", "THIRD_PARTY.md"):
                (source / doc).write_text(doc)
            outputs = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in source.rglob("*") if p.is_file()}
            manifest = {"source_origin": "authenticated_download", "upstream_commit": "a"*40,
                "ci_fingerprint": "b"*64, "native_snapshots": snapshots, "excluded": [],
                "tools": {n: {"version": t["version"], "binary_sha256": t["binary_sha256"]}
                          for n, t in json.loads(Path("config/tools.json").read_text()).items()},
                "sources": [{"source": "geo/geosite/A+!.srs", "sha256": "3"*64,
                             "git_blob": "4"*40, "providers": [name], "count": 1,
                             "behavior": "domain", "format": "mrs", "output": path,
                             "method": "converted_srs", "native_reason": "equivalence not established"}],
                "outputs": outputs}
            (source / "manifest.json").write_text(json.dumps(manifest))
            files = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
            entries = [{"path": p, "type": "blob", "mode": "100644", "size": len(data),
                        "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
                       for p, data in files.items()]
            commit, tree = anchored_tree(entries, "e"*40)
            tree["sha"] = commit["tree"]["sha"]
            mode = {"value": "good"}

            def published_tree():
                if mode["value"] != "historical-hash":
                    return commit, tree
                revised = [dict(item) for item in entries]
                doc = next(item for item in revised if item["path"] == "README.md")
                payload = b"tampered"
                doc["size"] = len(payload)
                doc["sha"] = hashlib.sha1(b"blob 8\0" + payload).hexdigest()
                new_commit, new_tree = anchored_tree(revised, "e"*40)
                new_tree["sha"] = new_commit["tree"]["sha"]
                return new_commit, new_tree

            def fake_api(path, token, missing=False):
                if path.endswith("/git/ref/heads/sing"):
                    return {"object": {"sha": "a"*40}}
                if path.endswith("/git/ref/heads/meta"):
                    return {"object": {"sha": "c"*40}}
                if path.endswith("/git/ref/heads/release"):
                    return {"object": {"sha": "d"*40}}
                if path.endswith("/branches/rules"):
                    return {"commit": {"sha": "e"*40}}
                if "/git/commits/" in path:
                    return published_tree()[0]
                if "/git/trees/" in path:
                    current_tree = published_tree()[1]
                    result = {**current_tree, "tree": list(current_tree["tree"])}
                    if mode["value"] == "empty-tree":
                        result["tree"].append({"path": "unexpected", "type": "tree",
                                               "mode": "040000", "sha": "f"*40})
                    return result
                return {}

            def archive(repo, sha, token):
                stream = io.BytesIO()
                current = mode["value"]
                with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                    for index, (name, data) in enumerate(files.items()):
                        if index == 0 and current == "missing":
                            continue
                        member_name = "snapshot/" + name
                        if index == 0 and current == "traversal":
                            member_name = "snapshot/../escape"
                        elif index == 0 and current == "absolute":
                            member_name = "/absolute"
                        elif index == 1 and current == "prefix":
                            member_name = "other/" + name
                        info = tarfile.TarInfo(member_name)
                        if index == 0 and current in ("symlink", "hardlink"):
                            info.type = tarfile.SYMTYPE if current == "symlink" else tarfile.LNKTYPE
                            info.linkname = "elsewhere"
                            tar.addfile(info)
                            continue
                        payload = b"tampered" if current == "historical-hash" and name == "README.md" else data
                        if index == 0 and current == "size":
                            payload += b"x"
                        if index == 0 and current == "blob":
                            payload = bytes([payload[0] ^ 1]) + payload[1:]
                        info.size = len(payload)
                        tar.addfile(info, io.BytesIO(payload))
                        if index == 0 and current == "duplicate":
                            tar.addfile(info, io.BytesIO(payload))
                    if current == "extra":
                        info = tarfile.TarInfo("snapshot/extra")
                        info.size = 1
                        tar.addfile(info, io.BytesIO(b"x"))
                return stream.getvalue()

            with patch.object(ci, "api", side_effect=fake_api), \
                    patch.object(ci, "download_published_archive", side_effect=archive), \
                    patch.object(ci, "full_fingerprint", return_value="b"*64), \
                    patch.object(ci, "validate", wraps=ci.validate) as validate:
                self.assertFalse(ci.prepare("owner/repo", "token", root)["changed"])
                self.assertTrue(validate.call_args.kwargs["historical"])
                unsigned = dict(manifest)
                unsigned.pop("ci_fingerprint")
                files["manifest.json"] = json.dumps(unsigned).encode()
                entries[:] = [{"path": p, "type": "blob", "mode": "100644", "size": len(data),
                               "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
                              for p, data in files.items()]
                commit, tree = anchored_tree(entries, "e"*40)
                tree["sha"] = commit["tree"]["sha"]
                self.assertTrue(ci.prepare("owner/repo", "token", root)["changed"])
                self.assertTrue(validate.call_args.kwargs["unstamped"])
                mode["value"] = "historical-hash"
                with self.assertRaisesRegex(ValueError, "output hash"):
                    ci.prepare("owner/repo", "token", root)
                mode["value"] = "good"
                files["manifest.json"] = json.dumps({**unsigned, "ci_fingerprint": "invalid"}).encode()
                entries[:] = [{"path": p, "type": "blob", "mode": "100644", "size": len(data),
                               "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
                              for p, data in files.items()]
                commit, tree = anchored_tree(entries, "e"*40)
                tree["sha"] = commit["tree"]["sha"]
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    ci.prepare("owner/repo", "token", root)
                files["manifest.json"] = json.dumps(manifest).encode()
                entries[:] = [{"path": p, "type": "blob", "mode": "100644", "size": len(data),
                               "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
                              for p, data in files.items()]
                commit, tree = anchored_tree(entries, "e"*40)
                tree["sha"] = commit["tree"]["sha"]
                for defect in ("symlink", "hardlink", "traversal", "absolute", "duplicate",
                               "missing", "extra", "empty-tree", "prefix", "size", "blob", "historical-hash"):
                    mode["value"] = defect
                    with self.subTest(defect=defect), self.assertRaises((ValueError, OSError)):
                        ci.prepare("owner/repo", "token", root)

    def test_prepare_full_pins_and_validates_one_archive_before_skip(self):
        snapshots = {"MetaCubeX/meta-rules-dat": "c"*40, "runetfreedom/russia-blocked-geoip": "d"*40}
        state = {"branch": True, "truncated": False, "corrupt": False, "fingerprint": "b"*64}
        contents = {"manifest.json": b'{"ci_fingerprint": "fixture"}', "rule-providers.yaml": b"providers"}
        def fake_api(path, token, missing=False):
            if path == "repos/KaringX/karing-ruleset/git/ref/heads/sing":
                return {"object": {"sha": "a"*40}}
            if path == "repos/MetaCubeX/meta-rules-dat/git/ref/heads/meta":
                return {"object": {"sha": "c"*40}}
            if path == "repos/runetfreedom/russia-blocked-geoip/git/ref/heads/release":
                return {"object": {"sha": "d"*40}}
            if path.endswith("/branches/rules"):
                return {"commit": {"sha": "e"*40}} if state["branch"] else None
            if "/git/commits/" in path:
                return {"tree": {"sha": "f"*40}}
            if "/git/trees/" in path:
                return {"sha": "f"*40, "truncated": state["truncated"], "tree": [
                    {"path": name, "type": "blob", "mode": "100644", "size": len(data),
                     "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
                    for name, data in contents.items()]}
            return {}
        def archive(repo, sha, token):
            self.assertEqual(sha, "e"*40)
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                for name, data in contents.items():
                    payload = b"tampered" if state["corrupt"] and name == "manifest.json" else data
                    info = tarfile.TarInfo("snapshot/" + name)
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
            return stream.getvalue()
        with tempfile.TemporaryDirectory(prefix="ci-prepare-") as tmp, \
                patch.object(ci, "api", side_effect=fake_api), \
                patch.object(ci, "download_published_archive", side_effect=archive) as download, \
                patch.object(ci, "full_fingerprint", return_value="b"*64), \
                patch.object(ci, "validate", side_effect=lambda *a, **k: {
                    "excluded": [], "ci_fingerprint": state["fingerprint"], "upstream_commit": "a"*40,
                    "native_snapshots": snapshots}):
            state["branch"] = False
            result = ci.prepare("owner/repo", "token", tmp)
            self.assertTrue(result["changed"])
            self.assertEqual(json.loads(result["native_snapshots"]), snapshots)
            download.assert_not_called()
            state["branch"] = True
            self.assertFalse(ci.prepare("owner/repo", "token", tmp)["changed"])
            state["fingerprint"] = "0"*64
            self.assertTrue(ci.prepare("owner/repo", "token", tmp)["changed"])
            state["truncated"] = True
            with self.assertRaises(ValueError):
                ci.prepare("owner/repo", "token", tmp)
            state["truncated"] = False
            state["corrupt"] = True
            with self.assertRaises(ValueError):
                ci.prepare("owner/repo", "token", tmp)
            state["corrupt"] = False
            with patch.object(ci, "validate", side_effect=ValueError("invalid historical manifest")):
                with self.assertRaisesRegex(ValueError, "invalid historical manifest"):
                    ci.prepare("owner/repo", "token", tmp)

    def test_publish_validates_then_calls_orphan_helper_with_checked_manifest_hash(self):
        with tempfile.TemporaryDirectory(prefix="ci-publish-") as tmp:
            root = Path(tmp)
            fixture(root)
            digest = hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()
            snapshots = {"MetaCubeX/meta-rules-dat": "c"*40, "runetfreedom/russia-blocked-geoip": "d"*40}
            with patch.object(ci, "validate", return_value={"excluded": []}) as validate, \
                    patch.object(ci, "publish_snapshot") as publish, \
                    patch.object(ci.subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout="/tmp/local-remote.git\n")), \
                    patch.dict("os.environ", {"TMPDIR": tmp}):
                ci.publish(root, root, "a"*40, "b"*64, expected_native_snapshots=snapshots)
                self.assertEqual(validate.call_args.kwargs["expected_native_snapshots"], snapshots)
                self.assertEqual(publish.call_args.args, (root, "/tmp/local-remote.git", tmp))
                self.assertEqual(publish.call_args.kwargs["expected_manifest_sha256"], digest)

    def test_selected_manifest_rejects_verified_cache_origin(self):
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
            root = Path(tmp)
            manifest = fixture(root)
            manifest["source_origin"] = "git_blob_verified"
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "origin"):
                ci.validate(root, historical=True)

    def test_cli_passes_native_snapshots_to_validate_stamp_and_publish(self):
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
            root = Path(tmp)
            snapshots = {"MetaCubeX/meta-rules-dat": "c"*40, "runetfreedom/russia-blocked-geoip": "d"*40}
            path = root / "snapshots.json"
            path.write_text(json.dumps(snapshots))
            (root / "manifest.json").write_text("{}")
            for command in ("validate", "stamp", "publish"):
                args = ["ci.py", command, "--output", str(root), "--native-snapshots", str(path)]
                if command == "publish":
                    args += ["--commit", "a"*40, "--fingerprint", "b"*64]
                with self.subTest(command=command), patch.object(sys, "argv", args), \
                        patch.dict("os.environ", {"COMMIT": "a"*40, "FINGERPRINT": "b"*64}), \
                        patch.object(ci, "validate", return_value={}) as validate, \
                        patch.object(ci, "publish") as publish:
                    ci.main()
                    if command == "publish":
                        self.assertEqual(publish.call_args.kwargs["expected_native_snapshots"], snapshots)
                    else:
                        self.assertTrue(all(c.kwargs["expected_native_snapshots"] == snapshots for c in validate.call_args_list))

    def test_full_historical_snapshot_checks_mapping_and_exclusions(self):
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
            root = Path(tmp)
            (root / "mihomo/geosite").mkdir(parents=True)
            path = "mihomo/geosite/A+!.mrs"
            (root / path).write_bytes(b"synthetic")
            providers = {"mihomo/geosite/A+!": {
                "type": "http", "behavior": "domain", "format": "mrs",
                "path": "./" + path, "url": "https://example.test/mihomo/geosite/A%2B%21.mrs",
                "interval": 86400}}
            data = providers_yaml(providers).encode()
            (root / "rule-providers.yaml").write_bytes(data)
            excluded = {"source": "bad.srs", "sha256": "1"*64, "git_blob": "2"*40, "reason": "invalid domain"}
            source = {"source": "geo/geosite/A+!.srs", "sha256": "3"*64, "git_blob": "4"*40,
                      "providers": ["mihomo/geosite/A+!"], "count": 1, "behavior": "domain",
                      "format": "mrs", "output": path, "method": "converted_srs",
                      "native_reason": "equivalence not established"}
            manifest = {"source_origin": "authenticated_download", "upstream_commit": "a"*40,
                        "native_snapshots": {"MetaCubeX/meta-rules-dat": "c"*40,
                                             "runetfreedom/russia-blocked-geoip": "d"*40},
                        "ci_fingerprint": "b"*64, "sources": [source, excluded], "excluded": [excluded],
                        "outputs": {path: hashlib.sha256(b"synthetic").hexdigest(),
                                    "rule-providers.yaml": hashlib.sha256(data).hexdigest()},
                        "tools": {name: {"version": item["version"], "binary_sha256": item["binary_sha256"]}
                                  for name, item in json.loads(Path("config/tools.json").read_text()).items()}}
            for name in ("README.md", "THIRD_PARTY.md"):
                (root / name).write_text(name)
                manifest["outputs"][name] = hashlib.sha256(name.encode()).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            ci.validate(root, historical=True)
            commit_object, tree = anchored_tree([{"path": s["source"], "type": "blob", "mode": "100644",
                "sha": s["git_blob"], "size": 1} for s in manifest["sources"]], "a"*40)
            with patch.object(ci, "load_exclusions", return_value={excluded["source"]: [excluded["reason"], excluded["git_blob"]]}), \
                    patch.dict("os.environ", {"GH_TOKEN": "test"}), \
                    patch.object(ci, "api", side_effect=lambda path, token: commit_object if "/commits/" in path else tree):
                with self.assertRaisesRegex(ValueError, "invalid outputs"):
                    ci.validate(root, expected_native_snapshots=manifest["native_snapshots"])
            (root / "GUIDE.md").write_text("GUIDE.md")
            manifest["outputs"]["GUIDE.md"] = hashlib.sha256(b"GUIDE.md").hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            ci.validate(root, historical=True)
            manifest["source_origin"] = "git_blob_verified"
            (root / "manifest.json").write_text(json.dumps(manifest))
            ci.validate(root, historical=True)
            manifest["source_origin"] = "authenticated_download"
            snapshots = {"MetaCubeX/meta-rules-dat": "c"*40,
                         "runetfreedom/russia-blocked-geoip": "d"*40}
            missing_snapshots = dict(manifest)
            missing_snapshots.pop("native_snapshots")
            (root / "manifest.json").write_text(json.dumps(missing_snapshots))
            with self.assertRaisesRegex(ValueError, "native snapshots"):
                ci.validate(root, historical=True)
            for bad in ({"MetaCubeX/meta-rules-dat": "c"*40}, {**snapshots, "MetaCubeX/meta-rules-dat": "bad"}):
                invalid = {**manifest, "native_snapshots": bad}
                (root / "manifest.json").write_text(json.dumps(invalid))
                with self.assertRaisesRegex(ValueError, "native snapshots"):
                    ci.validate(root, historical=True)
            (root / "manifest.json").write_text(json.dumps(manifest))
            native_manifest = json.loads(json.dumps(manifest))
            native_manifest["native_snapshots"] = snapshots
            native_source = native_manifest["sources"][0]
            native_source.pop("native_reason")
            native_source.update({"method": "native_mrs", "native": {
                "repo": "MetaCubeX/meta-rules-dat", "commit": "c"*40,
                 "path": "geo/geosite/A+!.mrs", "input_sha256": hashlib.sha256(b"synthetic").hexdigest()}})
            (root / "manifest.json").write_text(json.dumps(native_manifest))
            ci.validate(root, historical=True)
            native_source["native"]["input_sha256"] = "e"*64
            (root / "manifest.json").write_text(json.dumps(native_manifest))
            with self.assertRaisesRegex(ValueError, "native.*hash"):
                ci.validate(root, historical=True)
            native_source["native"]["input_sha256"] = hashlib.sha256(b"synthetic").hexdigest()
            (root / "manifest.json").write_text(json.dumps(native_manifest))
            native_source["native"].update({"repo": "untrusted/repo", "commit": None})
            (root / "manifest.json").write_text(json.dumps(native_manifest))
            with self.assertRaisesRegex(ValueError, "native provenance"):
                ci.validate(root, historical=True)
            native_source["native"].update({"repo": "MetaCubeX/meta-rules-dat", "commit": "c"*40})
            native_source["native"]["path"] = "../escape.mrs"
            (root / "manifest.json").write_text(json.dumps(native_manifest))
            with self.assertRaisesRegex(ValueError, "native provenance"):
                ci.validate(root, historical=True)
            native_source["native"]["path"] = "geo/geosite/A+!.mrs"
            (root / "manifest.json").write_text(json.dumps(native_manifest))
            with self.assertRaisesRegex(ValueError, "native snapshots"):
                ci.validate(root)
            native_commit, native_tree = anchored_tree([
                {"path": s["source"], "type": "blob", "mode": "100644",
                 "sha": s["git_blob"], "size": 1} for s in native_manifest["sources"]], "a"*40)
            with patch.dict("os.environ", {"GH_TOKEN": "test"}), patch.object(ci, "api", side_effect=lambda path, token: native_commit if "/commits/" in path else native_tree), \
                    patch.object(ci, "load_exclusions", return_value={excluded["source"]: [excluded["reason"], excluded["git_blob"]]}):
                ci.validate(root, expected_native_snapshots=snapshots)
                entry = next(item for item in native_tree["tree"] if item["path"] == source["source"])
                original_sha = entry["sha"]
                entry["sha"] = "f" * 40
                with self.assertRaisesRegex(ValueError, "tree hash"):
                    ci.validate(root, expected_native_snapshots=snapshots)
                entry["sha"] = original_sha
                native_manifest["source_origin"] = "git_blob_verified"
                (root / "manifest.json").write_text(json.dumps(native_manifest))
                ci.validate(root, expected_native_snapshots=snapshots)
                (root / "README.md").write_text("modified")
                with self.assertRaisesRegex(ValueError, "output hash"):
                    ci.validate(root, expected_native_snapshots=snapshots)
                (root / "README.md").write_text("README.md")
                native_manifest["source_origin"] = "authenticated_download"
                (root / "manifest.json").write_text(json.dumps(native_manifest))
                with self.assertRaisesRegex(ValueError, "native snapshots"):
                    ci.validate(root)
                with patch.object(ci, "_candidate", return_value=None):
                    ci.validate(root, historical=True)
                    with self.assertRaisesRegex(ValueError, "native provenance"):
                        ci.validate(root, expected_native_snapshots=snapshots)
                with self.assertRaisesRegex(ValueError, "native snapshots"):
                    ci.validate(root, expected_native_snapshots={**snapshots, "MetaCubeX/meta-rules-dat": "f"*40})
            native_source["native"]["commit"] = "f"*40
            (root / "manifest.json").write_text(json.dumps(native_manifest))
            with self.assertRaises(ValueError):
                ci.validate(root, historical=True)
            (root / "manifest.json").write_text(json.dumps(manifest))
            commit_obj, tree = anchored_tree([
                {"path": source["source"], "type": "blob", "mode": "100644", "sha": "4"*40, "size": 1},
                {"path": excluded["source"], "type": "blob", "mode": "100644", "sha": "2"*40, "size": 1}], "a"*40)
            policy = {excluded["source"]: [excluded["reason"], excluded["git_blob"]]}
            with patch.dict("os.environ", {"GH_TOKEN": "test"}), patch.object(ci, "api", side_effect=lambda path, token: commit_obj if "/commits/" in path else tree), \
                    patch.object(ci, "load_exclusions", return_value=policy):
                with self.assertRaisesRegex(ValueError, "native snapshots"):
                    ci.validate(root)
                ci.validate(root, expected_native_snapshots=snapshots)
                policy.clear()
                with self.assertRaisesRegex(ValueError, "unapproved exclusion"):
                    ci.validate(root, expected_native_snapshots=snapshots)
                policy[excluded["source"]] = [excluded["reason"], excluded["git_blob"]]
                manifest["tools"]["mihomo"]["binary_sha256"] = "f" * 64
                (root / "manifest.json").write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, "tool"):
                    ci.validate(root, expected_native_snapshots=snapshots)
                manifest["tools"]["mihomo"]["binary_sha256"] = json.loads(Path("config/tools.json").read_text())["mihomo"]["binary_sha256"]
                (root / "manifest.json").write_text(json.dumps(manifest))
                tree["tree"].pop()
                with self.assertRaises(ValueError):
                    ci.validate(root, expected_native_snapshots=snapshots)
            alias = {"source": "geosite/A+!.srs", "sha256": "5"*64,
                     "git_blob": "6"*40, "reason": "invalid domain"}
            manifest["sources"].append(alias)
            manifest["excluded"].append(alias)
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "duplicate source"):
                ci.validate(root, historical=True)
            manifest["sources"].pop()
            manifest["excluded"].pop()
            (root / "manifest.json").write_text(json.dumps(manifest))
            (root / "mihomo/empty").mkdir()
            with self.assertRaisesRegex(ValueError, "unexpected artifact"):
                ci.validate(root, historical=True)
            (root / "mihomo/empty").rmdir()
            manifest["excluded"] = []
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                ci.validate(root, historical=True)

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

    def test_published_archive_rejects_redirect_without_sending_authorization(self):
        requests = []
        def https_open(handler, request):
            requests.append((request.full_url, request.get_header("Authorization")))
            headers = email.message.Message()
            headers["Location"] = "https://other.example.test/archive"
            response = urllib.response.addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
            response.msg = "mock"
            return response
        with patch.object(urllib.request.HTTPSHandler, "https_open", https_open):
            with self.assertRaises(urllib.error.HTTPError):
                ci.download_published_archive("owner/repo", "a"*40, "dummy-only")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][1], "Bearer dummy-only")
        self.assertNotIn("dummy-only", requests[0][0])

    def test_private_archive_authorization_only_targets_expected_origin(self):
        requests = []
        def https_open(handler, request):
            requests.append(request)
            response = urllib.response.addinfourl(io.BytesIO(b"archive"), email.message.Message(),
                                                   request.full_url, 200)
            response.msg = "mock"
            return response
        with patch.object(urllib.request.HTTPSHandler, "https_open", https_open):
            self.assertEqual(ci.download_published_archive("owner/repo", "a"*40, "dummy-only"), b"archive")
        self.assertEqual(requests[0].full_url, "https://codeload.github.com/owner/repo/tar.gz/" + "a"*40)
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer dummy-only")
        self.assertNotIn("dummy-only", requests[0].full_url)

    def test_publish_existing_new_and_git_failure_without_git_execution(self):
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
            root = Path(tmp)
            fixture(root)
            with patch.object(ci, "publish_snapshot") as publisher:
                with self.assertRaisesRegex(ValueError, "only full"):
                    ci.publish(root, root, "a"*40, "b"*64)
                publisher.assert_not_called()

    def test_publish_stops_on_fetch_or_push_failure(self):
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
            root = Path(tmp)
            fixture(root)
            with patch.object(ci, "validate", return_value={"excluded": []}), \
                    patch.object(ci.subprocess, "run", return_value=SimpleNamespace(stdout="/tmp/remote\n")), \
                    patch.object(ci, "publish_snapshot", side_effect=subprocess.CalledProcessError(1, "git")), \
                    patch.dict("os.environ", {"TMPDIR": tmp}):
                with self.assertRaises(subprocess.CalledProcessError):
                    ci.publish(root, root, "a"*40, "b"*64)

    def test_prepare_branch_absent_and_api_failure(self):
        def fake(path, token, missing=False):
            if "/git/ref/heads/" in path:
                return {"object": {"sha": "a" * 40}}
            if path.endswith("/branches/rules"):
                return None
            return {}
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
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
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
            def fake(path, token, missing=False):
                if "/git/ref/heads/" in path:
                    return {"object": {"sha": "a" * 40}}
                if path.endswith("/branches/rules"):
                    return {"commit": {"sha": "d" * 40}}
                if "/git/commits/" in path:
                    return {"tree": {"sha": "e" * 40}}
                if "/git/trees/" in path:
                    return {"sha": "e" * 40, "truncated": False, "tree": []}
                return {}
            with patch.object(ci, "api", side_effect=fake), \
                    patch.object(ci, "download_published_archive",
                                 side_effect=urllib.error.HTTPError("https://codeload.github.com", 403, "denied", {}, None)):
                with self.assertRaises(urllib.error.HTTPError):
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
        self.assertIn("product/mihomo", uploads[0]["with"]["path"])
        for name in ("rule-providers.yaml", "manifest.json", "README.md", "THIRD_PARTY.md", "GUIDE.md"):
            self.assertIn("product/" + name, uploads[0]["with"]["path"])
        steps = doc["jobs"]["build"]["steps"]
        build = next(step for step in steps if step.get("name") == "Build and validate offline")
        self.assertIn("--full", build["run"])
        self.assertIn("github.token", build["env"]["GH_TOKEN"])
        self.assertIn("--native-snapshots", build["run"])
        self.assertIn("scripts/integration_check.py", build["run"])
        self.assertIn("GIT_ASKPASS", publish["run"])
        self.assertIn("native-snapshots", publish["run"])
        self.assertIn('github.token', publish["env"]["GH_TOKEN"])
        self.assertNotIn("${{ github.token }}", publish["run"])
        self.assertIn("http.followRedirects", Path("scripts/publish.py").read_text())
        for job in doc["jobs"].values():
            checkout = next(s for s in job["steps"] if "actions/checkout@" in s.get("uses", ""))
            self.assertEqual(checkout["with"]["persist-credentials"], "false")
        self.assertNotIn("scripts/", uploads[0]["with"]["path"])
        for job in doc["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^[^@]+@[0-9a-f]{40}$")

    def test_fingerprint_changes_with_inputs(self):
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
            path = Path(tmp) / "input"
            path.write_text("a")
            first = ci.fingerprint("a" * 40, "https://example.test", [path])
            self.assertNotEqual(first, ci.fingerprint("b" * 40, "https://example.test", [path]))
            path.write_text("b")
            self.assertNotEqual(first, ci.fingerprint("a" * 40, "https://example.test", [path]))
            self.assertNotEqual(first, ci.fingerprint("a" * 40, "https://other.example.test", [path]))

    def test_full_fingerprint_covers_all_inputs_and_requires_files(self):
        with tempfile.TemporaryDirectory(prefix="ci-fingerprint-") as tmp:
            root = Path(tmp)
            paths = ["config/tools.json", "config/exclusions.json", "scripts/catalog.py",
                     "scripts/build.py", "scripts/native.py", "scripts/ci.py",
                     "scripts/fetch_tools.py", "scripts/integration_check.py", "scripts/publish.py",
                     ".github/workflows/build.yml", "README.md", "THIRD_PARTY.md", "GUIDE.md"]
            for name in paths:
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(name)
            snapshots = {"MetaCubeX/meta-rules-dat": "c"*40, "runetfreedom/russia-blocked-geoip": "d"*40}
            with patch.object(ci, "ROOT", root):
                first = ci.full_fingerprint("a"*40, snapshots, "https://example.test")
                self.assertNotEqual(first, ci.full_fingerprint("b"*40, snapshots, "https://example.test"))
                self.assertNotEqual(first, ci.full_fingerprint("a"*40, snapshots, "https://other.test"))
                for repo in snapshots:
                    changed = {**snapshots, repo: "e"*40}
                    self.assertNotEqual(first, ci.full_fingerprint("a"*40, changed, "https://example.test"))
                for name in paths:
                    file = root / name
                    file.write_text(name + "changed")
                    self.assertNotEqual(first, ci.full_fingerprint("a"*40, snapshots, "https://example.test"), name)
                    file.write_text(name)
                (root / paths[0]).unlink()
                with self.assertRaises(FileNotFoundError):
                    ci.full_fingerprint("a"*40, snapshots, "https://example.test")

    def test_validate_rejects_tampering_extras_and_traversal(self):
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
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
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
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
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
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
        with tempfile.TemporaryDirectory(prefix="ci-test-") as tmp:
            root = Path(tmp)
            manifest = fixture(root)
            manifest.pop("ci_fingerprint")
            (root / "manifest.json").write_text(json.dumps(manifest))
            ci.validate(root, unstamped=True)
            with self.assertRaises(ValueError):
                ci.validate(root)


if __name__ == "__main__":
    unittest.main()
