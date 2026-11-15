import unittest
import hashlib

from scripts.catalog import inventory, output_stem


class CatalogTests(unittest.TestCase):
    def test_anchored_tree_checks_contents_and_hierarchy(self):
        from scripts.catalog import anchored_inventory
        blob = hashlib.sha1(b"blob 1\0x").hexdigest()
        payload = b"100644 a.srs\0" + bytes.fromhex(blob)
        child = hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
        root_payload = b"40000 dir\0" + bytes.fromhex(child)
        root = hashlib.sha1(b"tree " + str(len(root_payload)).encode() + b"\0" + root_payload).hexdigest()
        commit = "a" * 40
        commit_data = {"sha": commit, "tree": {"sha": root}}
        entries = [{"path": "dir", "mode": "040000", "type": "tree", "sha": child},
                   {"path": "dir/a.srs", "mode": "100644", "type": "blob", "sha": blob, "size": 1}]
        tree = {"sha": commit, "truncated": False, "tree": entries}
        self.assertEqual(anchored_inventory(commit, commit_data, tree), {"dir/a.srs": (blob, 1)})
        for bad in ([entries[1]], [entries[0], {**entries[1], "sha": "b" * 40}],
                    [entries[0], entries[1], entries[1]],
                    [{**entries[0], "type": "blob", "mode": "100644", "size": 1}, entries[1]],
                    [entries[0], {**entries[1], "path": "dir/../a.srs"}],
                    [entries[0], {**entries[1], "size": True}]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                anchored_inventory(commit, commit_data, {**tree, "tree": bad})
        with self.assertRaises(ValueError):
            anchored_inventory(commit, {**commit_data, "sha": "b" * 40}, tree)

    def test_distinct_names_and_namespaces_are_preserved(self):
        self.assertEqual(output_stem("geo/geosite/apple@!cn.srs"),
                         "mihomo/geosite/apple@!cn")
        self.assertEqual(output_stem("geo/geosite/apple@cn.srs"),
                         "mihomo/geosite/apple@cn")
        self.assertEqual(output_stem("ACL4SSR/Ruleset/Claude.srs"),
                         "mihomo/acl/Ruleset/Claude")
        self.assertEqual(output_stem("AdGuard/HostlistsRegistry/hagezi_pro++.srs"),
                         "mihomo/AdGuard/HostlistsRegistry/hagezi_pro++")
        self.assertEqual(output_stem("ACL4SSR.srs"), "mihomo/ACL4SSR")

    def test_catalog_keeps_every_srs_and_rejects_incomplete_tree(self):
        tree = {"truncated": False, "tree": [
            {"path": "geo/geosite/apple@!cn.srs", "type": "blob", "mode": "100644"},
            {"path": "geo/geosite/apple@cn.srs", "type": "blob", "mode": "100644"},
            {"path": "README.md", "type": "blob", "mode": "100644"},
        ]}
        self.assertEqual(inventory(tree), [
            "geo/geosite/apple@!cn.srs", "geo/geosite/apple@cn.srs"])
        with self.assertRaises(ValueError):
            inventory({**tree, "truncated": True})

    def test_catalog_rejects_unsafe_or_duplicate_paths(self):
        for path in ("../escape.srs", "geo/../escape.srs", "/absolute.srs",
                     "geo//empty.srs"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                output_stem(path)
        entry = {"path": "geo/geosite/a.srs", "type": "blob", "mode": "100644"}
        with self.assertRaises(ValueError):
            inventory({"truncated": False, "tree": [entry, entry]})
        with self.assertRaises(ValueError):
            inventory({"truncated": False, "tree": [{**entry, "mode": "120000"}]})

    def test_full_inventory_requires_valid_blob_hash_and_size(self):
        from scripts.catalog import pinned_inventory
        entry = {"path": "geo/geosite/a.srs", "type": "blob", "mode": "100644",
                 "sha": "a" * 40, "size": 7}
        tree = {"truncated": False, "tree": [entry]}
        self.assertEqual(pinned_inventory(tree), {"geo/geosite/a.srs": ("a" * 40, 7)})
        for bad in ({**entry, "sha": "x" * 40}, {**entry, "size": -1},
                    {**entry, "size": True}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                pinned_inventory({"truncated": False, "tree": [bad]})


if __name__ == "__main__":
    unittest.main()
