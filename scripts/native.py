"""Compare already verified native and converted Mihomo rule sets."""

import subprocess
import tempfile
import hashlib
import json
import os
import re
import stat
import urllib.parse
import urllib.request
from pathlib import Path

META = "MetaCubeX/meta-rules-dat"
RF = "runetfreedom/russia-blocked-geoip"
MAX_BLOB = 20 * 1024 * 1024
MAX_TREE = 32 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}")
SAFE_PATH = re.compile(r"[A-Za-z0-9_@!+.-]+(?:/[A-Za-z0-9_@!+.-]+)*")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch(url, limit):
    opener = urllib.request.build_opener(_NoRedirect())
    token = os.environ.get("GH_TOKEN")
    target = urllib.parse.urlsplit(url)
    if token and target.scheme == "https" and target.netloc == "api.github.com":
        if not re.fullmatch(r"[A-Za-z0-9._~-]+", token):
            raise ValueError("invalid GitHub token")
        url = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with opener.open(url, timeout=45) as response:
        if response.status != 200:
            raise ValueError("unexpected HTTP status")
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("download too large")
        return data


def _safe_path(path):
    return (isinstance(path, str) and SAFE_PATH.fullmatch(path)
            and all(part not in (".", "..") for part in path.split("/")))


def _tree(repo, sha, recursive=False):
    url = f"https://api.github.com/repos/{repo}/git/trees/{sha}"
    data = json.loads(_fetch(url + ("?recursive=1" if recursive else ""), MAX_TREE))
    if (not isinstance(data, dict) or data.get("sha") != sha
            or data.get("truncated") is not False or not isinstance(data.get("tree"), list)):
        raise ValueError("invalid or incomplete native tree")
    entries = {}
    for item in data["tree"]:
        if not isinstance(item, dict) or not _safe_path(item.get("path")) or item["path"] in entries:
            raise ValueError("invalid or duplicate native path")
        path = item["path"]
        kind, mode, blob_sha = item.get("type"), item.get("mode"), item.get("sha")
        if ((kind, mode) not in (("tree", "040000"), ("blob", "100644"), ("blob", "100755"))
                or not isinstance(blob_sha, str) or not SHA.fullmatch(blob_sha)
                or (not recursive and "/" in path)):
            raise ValueError("invalid native tree entry")
        if kind == "blob" and (type(item.get("size")) is not int or item["size"] < 0):
            raise ValueError("invalid native blob size")
        if path.endswith(".mrs"):
            if kind != "blob" or mode != "100644" or item["size"] > MAX_BLOB:
                raise ValueError("invalid native blob metadata")
        entries[path] = item
    if recursive:
        for path in entries:
            if "/" in path:
                parent = path.rsplit("/", 1)[0]
                if parent not in entries or entries[parent]["type"] != "tree":
                    raise ValueError("invalid native tree hierarchy")
    return entries


def _subtree(entries, name):
    item = entries.get(name)
    if (not isinstance(item, dict) or item.get("type") != "tree" or item.get("mode") != "040000"
            or not isinstance(item.get("sha"), str) or not SHA.fullmatch(item["sha"])):
        raise ValueError("invalid native subtree")
    return item["sha"]


def _candidate(source):
    if not _safe_path(source) or not source.endswith(".srs"):
        raise ValueError("invalid source path")
    aliases = {"blocked@ru": "ru-blocked", "blocked-community@ru": "ru-blocked-community",
               "re-filter@ru": "re-filter"}
    for name, target in aliases.items():
        if source == f"geo/geoip/{name}.srs":
            return RF, f"mrs/{target}.mrs", "ipcidr"
    for prefix, repo, dest, behavior in (
        ("geo/geosite/", META, "geo/geosite/", "domain"),
        ("geo/geoip/", META, "geo/geoip/", "ipcidr"),
        ("russia/runetfreedom/sing-box/rule-set-geoip/geoip-", RF, "mrs/", "ipcidr"),
        ("russia/runetfreedom/sing-box/rule-set-geosite/geosite-", META, "geo/geosite/", "domain"),
    ):
        if source.startswith(prefix):
            name = source[len(prefix):-4]
            if name and "/" not in name:
                return repo, dest + name + ".mrs", behavior
    return None


class NativeCatalog:
    def __init__(self, snapshot, mihomo, work_dir):
        if (not isinstance(snapshot, dict) or set(snapshot) != {META, RF}
                or any(not isinstance(sha, str) or not SHA.fullmatch(sha) for sha in snapshot.values())):
            raise ValueError("invalid native snapshot")
        self.snapshot = snapshot.copy()
        self.mihomo = mihomo
        self.work_dir = Path(work_dir)
        root = _tree(META, snapshot[META])
        geo = _tree(META, _subtree(root, "geo"))
        self.inventory = {}
        for name in ("geosite", "geoip"):
            subtree = _tree(META, _subtree(geo, name), True)
            self.inventory.update({(META, f"geo/{name}/{path}"): item
                                   for path, item in subtree.items() if path.endswith(".mrs")})
        rf = _tree(RF, snapshot[RF], True)
        self.inventory.update({(RF, path): item for path, item in rf.items() if path.endswith(".mrs")})
        self.blobs = {}
        self.proofs = {}

    def maybe_reuse(self, source, converted_mrs, behavior):
        if behavior == "classical":
            return {"method": "converted_srs", "reason": "classical behavior"}
        if behavior not in ("domain", "ipcidr"):
            raise ValueError("invalid behavior")
        candidate = _candidate(source)
        if candidate is None:
            return {"method": "converted_srs", "reason": "no candidate mapping"}
        if candidate[2] != behavior:
            return {"method": "converted_srs", "reason": "behavior mismatch"}
        if candidate[:2] not in self.inventory:
            return {"method": "converted_srs", "reason": "candidate absent"}
        repo, path, _ = candidate
        commit = self.snapshot[repo]
        key = repo, commit, path
        if key not in self.blobs:
            item = self.inventory[(repo, path)]
            url = f"https://raw.githubusercontent.com/{repo}/{commit}/" + urllib.parse.quote(path, safe="/")
            raw = _fetch(url, item["size"])
            if (len(raw) != item["size"] or
                    hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != item["sha"]):
                raise ValueError("native blob hash or size mismatch")
            self.blobs[key] = raw
        raw = self.blobs[key]
        converted = Path(converted_mrs)
        proof_key = key, behavior, hashlib.sha256(converted.read_bytes()).hexdigest()
        if proof_key not in self.proofs:
            with tempfile.TemporaryDirectory(dir=self.work_dir, prefix="native-candidate-") as tmp:
                native_file = Path(tmp) / "native.mrs"
                native_file.write_bytes(raw)
                self.proofs[proof_key] = reuse_equal(native_file, converted, behavior, self.mihomo, self.work_dir)
        if not self.proofs[proof_key]:
            return {"method": "converted_srs", "reason": "not equivalent"}
        result = {"repo": repo, "commit": commit, "path": path,
                  "input_sha256": hashlib.sha256(raw).hexdigest(), "method": "native_mrs"}
        name = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.work_dir, prefix=".native-", delete=False) as output:
                name = output.name
                output.write(raw)
                output.flush()
                os.fchmod(output.fileno(), stat.S_IMODE(converted.stat().st_mode))
            os.replace(name, converted)
        finally:
            if name is not None and os.path.exists(name):
                os.unlink(name)
        return result


def reuse_equal(native_mrs, converted_mrs, behavior, mihomo, work_dir):
    if behavior not in ("domain", "ipcidr"):
        raise ValueError("unsupported MRS behavior")
    with tempfile.TemporaryDirectory(dir=work_dir, prefix="native-proof-") as tmp:
        sets = []
        for index, source in enumerate((native_mrs, converted_mrs)):
            output = Path(tmp) / f"{index}.txt"
            subprocess.run([str(mihomo), "convert-ruleset", behavior, "mrs",
                            str(source), str(output)], check=True, capture_output=True,
                           timeout=60)
            sets.append({(behavior, line) for line in output.read_text(encoding="utf-8").splitlines()})
        return sets[0] == sets[1]
