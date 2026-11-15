"""Validate a complete Karing Git tree and preserve rule-set identities."""

import re
import hashlib


def output_stem(source):
    if (not isinstance(source, str)
            or not re.fullmatch(r"[A-Za-z0-9_@!+.-]+(?:/[A-Za-z0-9_@!+.-]+)*\.srs", source)
            or any(part in (".", "..") for part in source.split("/"))):
        raise ValueError("invalid SRS path")
    stem = source[:-4]
    for prefix, namespace in (("geo/geosite/", "geosite/"),
                              ("geo/geoip/", "geoip/"),
                              ("ACL4SSR/", "acl/")):
        if stem.startswith(prefix):
            return "mihomo/" + namespace + stem[len(prefix):]
    return "mihomo/" + stem


def inventory(tree):
    if not isinstance(tree, dict) or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
        raise ValueError("incomplete tree")
    sources, outputs = set(), set()
    for entry in tree["tree"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid tree entry")
        path = entry["path"]
        if not path.endswith(".srs"):
            continue
        if entry.get("type") != "blob" or entry.get("mode") != "100644":
            raise ValueError("invalid SRS entry")
        stem = output_stem(path)
        if path in sources or stem in outputs:
            raise ValueError("duplicate source or output")
        sources.add(path)
        outputs.add(stem)
    if not sources:
        raise ValueError("empty SRS inventory")
    return sorted(sources)


def pinned_inventory(tree):
    paths = set(inventory(tree))
    result = {}
    for entry in tree["tree"]:
        if entry["path"] not in paths:
            continue
        sha, size = entry.get("sha"), entry.get("size")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha) or type(size) is not int or not 0 <= size <= 20 * 1024 * 1024:
            raise ValueError("invalid SRS blob metadata")
        result[entry["path"]] = (sha, size)
    return result


def anchored_inventory(commit, commit_object, tree):
    if (not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or not isinstance(commit_object, dict) or commit_object.get("sha") != commit
            or not isinstance(commit_object.get("tree"), dict)):
        raise ValueError("invalid commit object")
    root_sha = commit_object["tree"].get("sha")
    if (not isinstance(root_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", root_sha)
            or not isinstance(tree, dict) or tree.get("sha") != commit
            or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list)):
        raise ValueError("invalid anchored tree")
    entries = {}
    for item in tree["tree"]:
        if not isinstance(item, dict):
            raise ValueError("invalid tree entry")
        path, mode, kind, sha = (item.get(key) for key in ("path", "mode", "type", "sha"))
        if (not isinstance(path, str)
                or not re.fullmatch(r"[A-Za-z0-9_@!+.-]+(?:/[A-Za-z0-9_@!+.-]+)*", path)
                or any(part in (".", "..") for part in path.split("/")) or path in entries
                or (kind, mode) not in (("tree", "040000"), ("blob", "100644"), ("blob", "100755"))
                or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
                or (kind == "blob" and (type(item.get("size")) is not int or item["size"] < 0))):
            raise ValueError("invalid tree entry")
        entries[path] = item
    children = {"": []}
    children.update({path: [] for path, item in entries.items() if item["type"] == "tree"})
    for path, item in entries.items():
        parent, _, name = path.rpartition("/")
        if parent not in children:
            raise ValueError("invalid tree hierarchy")
        children[parent].append((name, item))
    for parent in sorted(children, key=lambda name: name.count("/") + bool(name), reverse=True):
        items = sorted(children[parent], key=lambda pair: pair[0].encode() + (b"/" if pair[1]["type"] == "tree" else b""))
        payload = b"".join((item["mode"].lstrip("0") + " " + name).encode() + b"\0" +
                           bytes.fromhex(item["sha"]) for name, item in items)
        digest = hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
        if digest != (root_sha if not parent else entries[parent]["sha"]):
            raise ValueError("Git tree hash mismatch")
    return pinned_inventory(tree)
