import unittest
import hashlib
import gzip
import json
import io
import os
from contextlib import redirect_stderr
import tempfile
from unittest.mock import patch
from pathlib import Path

from scripts.build import convert_rule, classical_lines, build, payload_yaml, translate_regex, providers_yaml, check_version
from scripts.fetch_tools import verify_sha256


class ConversionTests(unittest.TestCase):
    def test_suffix_apex_and_subdomain_are_distinct(self):
        self.assertEqual(convert_rule({"domain_suffix": ["example.com", ".example.org"]}),
                         "OR,((DOMAIN-SUFFIX,example.com),(AND,((DOMAIN-SUFFIX,example.org),(NOT,((DOMAIN,example.org))))))")

    def test_address_alternatives_are_conjoined_with_process(self):
        self.assertEqual(convert_rule({"domain": ["example.com"], "ip_cidr": ["192.0.2.0/24"], "process_name": ["app"]}),
                         "AND,((OR,((DOMAIN,example.com),(IP-CIDR,192.0.2.0/24))),(PROCESS-NAME,app))")

    def test_invert_wraps_whole_logical_group(self):
        self.assertEqual(convert_rule({"type": "logical", "mode": "or", "invert": True, "rules": [
            {"domain": "example.com"}, {"domain_keyword": "example"}]}),
            "NOT,((OR,((DOMAIN,example.com),(DOMAIN-KEYWORD,example))))")

    def test_ipv6_and_ipv4(self):
        self.assertEqual(classical_lines({"ip_cidr": ["192.0.2.0/24", "2001:db8::/32"]}),
                         ["IP-CIDR,192.0.2.0/24", "IP-CIDR,2001:db8::/32"])

    def test_logical_and_preserved(self):
        self.assertEqual(convert_rule({"type": "logical", "mode": "and", "rules": [
            {"domain": "example.com"}, {"process_name": "app"}]}),
            "AND,((DOMAIN,example.com),(PROCESS-NAME,app))")

    def test_unknown_condition_and_empty_rule_rejected(self):
        for rule in ({"unexpected": ["x"]}, {}, {"domain": []}, {"domain": 1}):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                convert_rule(rule)

    def test_address_only_emits_separate_lines(self):
        self.assertEqual(classical_lines({"domain": ["a.example", "b.example"]}),
                         ["DOMAIN,a.example", "DOMAIN,b.example"])

    def test_payload_uses_mihomo_block_yaml(self):
        self.assertEqual(payload_yaml(["a.example", "b.example"]),
                         'payload:\n  - "a.example"\n  - "b.example"\n')

    def test_provider_config_uses_block_yaml(self):
        self.assertEqual(providers_yaml({"example": {"type": "file"}}),
                         'rule-providers:\n  example:\n    type: "file"\n')

    def test_top_level_regex_keeps_quantifier_comma(self):
        self.assertEqual(classical_lines({"domain_regex": r"^[a-z]{2,6}\.example$"}),
                         [r"DOMAIN-REGEX,^[a-z]{2,6}\.example$"])

    def test_regex_ascii_character_classes(self):
        self.assertEqual(translate_regex(r"^\w\d\S$"), r"^[0-9A-Za-z_][0-9][^\t\n\f\r ]$")
        for pattern in (r"^[\w]$", "a, b", "^A$", r"^\s$"):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                translate_regex(pattern)

    def test_wrong_tool_version_rejected(self):
        with self.assertRaises(ValueError):
            check_version("/bin/echo", ["wrong"], "1.2.3")

    def test_posix_regex_rejected(self):
        for value in ("^[[:digit:]]+$", "^[^[:digit:]]+$"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                translate_regex(value)

    def test_exact_domain_with_leading_dot_rejected(self):
        with self.assertRaises(ValueError):
            convert_rule({"domain": ".example.com"})

    def test_untrusted_binary_not_executed(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing/task1") as tmp:
            root = Path(tmp)
            marker = root / "marker"
            tool = root / "evil"
            tool.write_text(f"#!/bin/sh\ntouch '{marker}'\necho '1.14.4'\n")
            tool.chmod(0o755)
            with self.assertRaises(ValueError):
                build(root, root / "out", root, tool, tool, "a" * 40, "https://example.invalid")
            self.assertFalse(marker.exists())

    def test_build_empty_rule_and_provenance_and_cleanup(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing/task1") as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config/sets.json").write_text('["source.srs"]')
            (root / "config/tools.json").write_text(json.dumps({
                "sing-box": {"version": "v", "binary_sha256": "x"},
                "mihomo": {"version": "v", "binary_sha256": "x"}}))
            (root / "source.srs").write_bytes(b"srs")
            output = root / "out"
            output.mkdir()
            (output / "old").write_text("old")
            rules = [{"domain": "example.com"}, {}]

            def run(args, **kwargs):
                if "decompile" in args:
                    Path(args[-1]).write_text(json.dumps({"version": 1, "rules": rules}))
                else:
                    Path(args[-1]).write_bytes(b"mrs")

            with patch("scripts.build.ROOT", root), patch("scripts.build.verify_sha256"), \
                    patch("scripts.build.check_version", return_value={}), \
                    patch("scripts.build.subprocess.run", side_effect=run):
                with self.assertRaises(ValueError):
                    build(root, output, root, root / "sing", root / "mihomo", "a" * 40, "https://example.invalid")
                self.assertEqual((output / "old").read_text(), "old")
                rules.pop()
                import shutil
                original_rmtree = shutil.rmtree
                def rmtree(path, *args, **kwargs):
                    if Path(path).name == ".out.old":
                        raise PermissionError("cleanup failed")
                    return original_rmtree(path, *args, **kwargs)
                warning = io.StringIO()
                with patch("scripts.build.shutil.rmtree", side_effect=rmtree), redirect_stderr(warning):
                    try:
                        build(root, output, root, root / "sing", root / "mihomo", "a" * 40, "https://example.invalid")
                    except PermissionError:
                        self.fail("cleanup failure must not report committed build as failed")
                self.assertIn("output committed", warning.getvalue())
                manifest = json.loads((output / "manifest.json").read_text())
                self.assertNotIn("upstream_commit", manifest)
                self.assertEqual(manifest["source_origin"], "local/unverified")
                self.assertEqual(manifest["claimed_commit"], "a" * 40)
                self.assertTrue((root / ".out.old/old").exists())
                with self.assertRaises(FileExistsError):
                    build(root, output, root, root / "sing", root / "mihomo", "a" * 40, "https://example.invalid")
                original_rmtree(root / ".out.old")
                build(root, output, root, root / "sing", root / "mihomo", "a" * 40,
                      "https://example.invalid", source_origin="authenticated_download")
                remote = json.loads((output / "manifest.json").read_text())
                self.assertEqual(remote["source_origin"], "authenticated_download")
                self.assertEqual(remote["upstream_commit"], "a" * 40)
                self.assertNotIn("claimed_commit", remote)

    def test_integration_waits_until_every_provider_loaded(self):
        from scripts.integration_check import providers_ready
        expected = {"a": ("classical", 2), "b": ("domain", 3)}
        self.assertFalse(providers_ready({"a": {"ruleCount": 2}, "b": {"ruleCount": 0}}, expected))
        self.assertTrue(providers_ready({"a": {"ruleCount": 2}, "b": {"ruleCount": 1}}, expected))
        with self.assertRaises(ValueError):
            providers_ready({"a": {"ruleCount": 1}, "b": {"ruleCount": 1}}, expected)

    def test_integration_rejects_classical_parser_warning(self):
        from scripts.integration_check import check_log
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing/task1") as tmp:
            log = Path(tmp) / "log"
            log.write_text("WARN parse classical rule [bad] error\n")
            with self.assertRaises(ValueError):
                check_log(log)

    def test_inside_refuses_invalid_or_same_namespace_before_any_subprocess(self):
        from scripts.integration_check import main
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing/task1") as tmp:
            current = os.open("/proc/self/ns/net", os.O_RDONLY)
            regular = os.open("/dev/null", os.O_RDONLY)
            try:
                for extra in ([], ["--namespace-fd", str(current)],
                              ["--namespace-fd", str(regular)], ["--namespace-fd", "999999"]):
                    args = ["integration_check.py", "--inside", "--output", tmp,
                            "--mihomo", tmp, "--work-dir", tmp] + extra
                    with self.subTest(extra=extra), patch("sys.argv", args), \
                            patch("scripts.integration_check.verify_sha256"), \
                            patch("scripts.integration_check.subprocess.run") as run, \
                            patch("scripts.integration_check.run_inside") as inside, \
                            redirect_stderr(io.StringIO()):
                        with self.assertRaises(ValueError):
                            main()
                        inside.assert_not_called()
                        run.assert_not_called()
            finally:
                os.close(current)
                os.close(regular)

    def test_checksum_rejects_modified_archive(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing/task1") as tmp:
            path = Path(tmp) / "archive"
            path.write_bytes(b"data")
            verify_sha256(path, hashlib.sha256(b"data").hexdigest())
            with self.assertRaises(ValueError):
                verify_sha256(path, "0" * 64)

    def test_fetch_rejects_bad_unpacked_hash_before_replacement(self):
        from scripts.fetch_tools import fetch_tools
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing/task1") as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            archive = gzip.compress(b"new-binary", mtime=0)
            (root / "config/tools.json").write_text(json.dumps({"mihomo": {
                "version": "v", "url": "https://example.invalid",
                "sha256": hashlib.sha256(archive).hexdigest(), "binary_sha256": "0" * 64}}))
            out = root / "tools"
            out.mkdir()
            (out / "mihomo").write_bytes(b"old-binary")
            def download_fixture(url, path):
                Path(path).write_bytes(archive)
            with patch("scripts.fetch_tools.ROOT", root), patch("scripts.fetch_tools.download", side_effect=download_fixture):
                with self.assertRaises(ValueError):
                    fetch_tools(out)
            self.assertEqual((out / "mihomo").read_bytes(), b"old-binary")

    def test_failed_build_preserves_previous_output(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode/mihomo-rules-routing/task1") as tmp:
            root = Path(tmp)
            output = root / "out"
            output.mkdir()
            (output / "old").write_text("keep")
            with self.assertRaises(Exception):
                build(source_dir=root / "missing", output=output, work_dir=root,
                      sing_box=root / "missing-tool", mihomo=root / "missing-tool",
                      commit="a" * 40, base_url="https://example.invalid/rules")
            self.assertEqual((output / "old").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
