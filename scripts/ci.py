"""Small, fail-closed helpers for the rules workflow."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
import urllib.parse
import tempfile
import subprocess
import tarfile
import yaml
try:
    from scripts.catalog import output_stem, anchored_inventory
    from scripts.build import normalize_full_rules
    from scripts.native import _candidate, _safe_path
    from scripts.publish import publish_snapshot
except ModuleNotFoundError:
    from catalog import output_stem, anchored_inventory
    from build import normalize_full_rules
    from native import _candidate, _safe_path
    from publish import publish_snapshot

ROOT = Path(__file__).resolve().parent.parent


def fingerprint(commit, base_url, paths):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid upstream commit")
    digest = hashlib.sha256()
    for value in [commit.encode(), base_url.encode()] + [Path(p).read_bytes() for p in paths]:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def full_fingerprint(commit, native_snapshots, base_url):
    if (not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or not isinstance(native_snapshots, dict)
            or set(native_snapshots) != {"MetaCubeX/meta-rules-dat", "runetfreedom/russia-blocked-geoip"}
            or any(not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
                   for sha in native_snapshots.values())
            or not isinstance(base_url, str) or not base_url.startswith("https://")):
        raise ValueError("invalid fingerprint inputs")
    paths = ("config/tools.json", "scripts/catalog.py", "scripts/build.py",
             "scripts/native.py", "scripts/ci.py", "scripts/fetch_tools.py", "scripts/integration_check.py",
             "scripts/publish.py", ".github/workflows/build.yml", "README.md", "GUIDE.md")
    fields = [b"full", commit.encode(), base_url.encode()]
    for repo, sha in sorted(native_snapshots.items()):
        fields.extend((repo.encode(), sha.encode()))
    fields.extend((ROOT / path).read_bytes() for path in paths)
    digest = hashlib.sha256()
    for field in fields:
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    return digest.hexdigest()


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError("duplicate provider key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def validate(root, unstamped=False, expected_commit=None, expected_fingerprint=None, historical=False,
             expected_native_snapshots=None):
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text())
    if "excluded" in manifest:
        return validate_full(root, manifest, unstamped, expected_commit, expected_fingerprint, historical,
                             expected_native_snapshots)
    keys = {"source_origin", "upstream_commit", "tools", "sources", "outputs"}
    if not isinstance(manifest, dict) or set(manifest) != keys | (set() if unstamped else {"ci_fingerprint"}):
        raise ValueError("invalid manifest schema")
    if manifest.get("source_origin") != "authenticated_download" or not re.fullmatch(
            r"[0-9a-f]{40}", manifest.get("upstream_commit", "")):
        raise ValueError("invalid origin")
    commit = manifest["upstream_commit"]
    fp = manifest.get("ci_fingerprint")
    if unstamped:
        if fp is not None:
            raise ValueError("already stamped")
    elif not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{64}", fp):
        raise ValueError("missing fingerprint")
    if expected_commit is not None and commit != expected_commit:
        raise ValueError("unexpected upstream commit")
    if expected_fingerprint is not None and fp != expected_fingerprint:
        raise ValueError("unexpected fingerprint")
    tool_config = json.loads((ROOT / "config/tools.json").read_text())
    tools = manifest["tools"]
    if not isinstance(tools, dict) or set(tools) != set(tool_config):
        raise ValueError("invalid tools")
    for name, tool in tools.items():
        if (not isinstance(tool, dict) or set(tool) != {"version", "binary_sha256"}
                or not isinstance(tool["binary_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", tool["binary_sha256"])
                or not isinstance(tool["version"], str) or not tool["version"]):
            raise ValueError("invalid tool metadata")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or len(sources) != 46:
        raise ValueError("invalid sources")
    mapping = {}
    for source in sources:
        if (not isinstance(source, dict) or set(source) != {"source", "sha256", "providers", "count", "behavior", "format"}
                or not isinstance(source.get("source"), str)
                or not re.fullmatch(r"[A-Za-z0-9_@-]+(?:/[A-Za-z0-9_@-]+)*\.srs", source["source"])):
            raise ValueError("unknown source")
        name = re.sub(r"[^a-z0-9]+", "-", source["source"].lower()).strip("-")
        behavior, fmt = source.get("behavior"), source.get("format")
        if (name in mapping or source.get("providers") != [name] or
                not isinstance(source.get("sha256"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", source["sha256"]) or
                type(source.get("count")) is not int or source["count"] <= 0 or
                (behavior, fmt) not in (("domain", "mrs"), ("ipcidr", "mrs"), ("classical", "yaml"))):
            raise ValueError("invalid source metadata")
        mapping[name] = (source["source"], behavior, fmt)
    if not historical:
        expected_sources = json.loads((ROOT / "config/sets.json").read_text())
        if len(expected_sources) != 46 or len(set(expected_sources)) != 46 or {s[0] for s in mapping.values()} != set(expected_sources):
            raise ValueError("missing or unknown source")
    outputs = manifest.get("outputs")
    expected_paths = {"rules/" + name + "." + info[2] for name, info in mapping.items()}
    if not isinstance(outputs, dict) or set(outputs) != expected_paths | {"rule-providers.yaml"}:
        raise ValueError("invalid outputs")
    for path, expected in outputs.items():
        if not (path == "rule-providers.yaml" or re.fullmatch(r"rules/[a-z0-9-]+\.(mrs|yaml)", path)):
            raise ValueError("invalid output path")
        file = root / path
        if file.is_symlink() or not file.is_file() or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("invalid output")
        if hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise ValueError("output hash mismatch")
    if (root / "rules").is_symlink():
        raise ValueError("symlink rules directory")
    actual = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    if actual != set(outputs) | {"manifest.json"} or (root / "manifest.json").is_symlink():
        raise ValueError("unexpected artifact content")
    provider_doc = yaml.load((root / "rule-providers.yaml").read_text(), Loader=UniqueLoader)
    if not isinstance(provider_doc, dict) or set(provider_doc) != {"rule-providers"}:
        raise ValueError("invalid provider document")
    providers = provider_doc["rule-providers"]
    if not isinstance(providers, dict) or set(providers) != set(mapping):
        raise ValueError("invalid provider names")
    for name, (_, behavior, fmt) in mapping.items():
        provider = providers[name]
        path = "rules/" + name + "." + fmt
        if (not isinstance(provider, dict) or set(provider) != {"type", "behavior", "format", "path", "url", "interval"}
                or provider["type"] != "http" or provider["behavior"] != behavior
                or provider["format"] != fmt or provider["path"] != "./" + path
                or not isinstance(provider["url"], str) or not provider["url"].startswith("https://")
                or not provider["url"].endswith("/" + path) or provider["interval"] != 86400):
            raise ValueError("invalid provider definition")
    return manifest


def validate_full(root, manifest, unstamped, expected_commit, expected_fingerprint, historical,
                  expected_native_snapshots):
    keys = {"source_origin", "upstream_commit", "tools", "sources", "excluded", "outputs", "native_snapshots"}
    snapshots = manifest.get("native_snapshots")
    if (not isinstance(snapshots, dict) or set(snapshots) !=
                {"MetaCubeX/meta-rules-dat", "runetfreedom/russia-blocked-geoip"}
                or any(not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
                       for sha in snapshots.values())
                or (not historical and snapshots != expected_native_snapshots)):
        raise ValueError("invalid native snapshots")
    if set(manifest) != keys | (set() if unstamped else {"ci_fingerprint"}):
        raise ValueError("invalid manifest schema")
    commit, fp = manifest["upstream_commit"], manifest.get("ci_fingerprint")
    if (manifest["source_origin"] not in ("authenticated_download", "git_blob_verified")
            or not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or (not unstamped and (not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{64}", fp)))
            or (expected_commit is not None and commit != expected_commit)
            or (expected_fingerprint is not None and fp != expected_fingerprint)):
        raise ValueError("invalid origin or fingerprint")
    tool_config = json.loads((ROOT / "config/tools.json").read_text())
    tools = manifest["tools"]
    if not isinstance(tools, dict) or set(tools) != set(tool_config):
        raise ValueError("invalid tools")
    for name, tool in tools.items():
        if (not isinstance(tool, dict) or set(tool) != {"version", "binary_sha256"}
                or not isinstance(tool["version"], str) or not tool["version"]
                or not isinstance(tool["binary_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", tool["binary_sha256"])):
            raise ValueError("invalid tool metadata")
        if not historical and (tool["binary_sha256"] != tool_config[name]["binary_sha256"]
                or not re.search(r"(?<![0-9.])v?" + re.escape(tool_config[name]["version"]) +
                                 r"(?![0-9.])", tool["version"])):
            raise ValueError("unexpected tool metadata")
    if not isinstance(manifest["sources"], list) or not manifest["sources"] or not isinstance(manifest["excluded"], list):
        raise ValueError("invalid sources")
    mapping, seen, stems, exclusions = {}, set(), set(), []
    for source in manifest["sources"]:
        if not isinstance(source, dict):
            raise ValueError("invalid source")
        stem = output_stem(source.get("source"))
        if source["source"] in seen or stem in stems:
            raise ValueError("duplicate source")
        seen.add(source["source"])
        stems.add(stem)
        if (not isinstance(source.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
                or not isinstance(source.get("git_blob"), str) or not re.fullmatch(r"[0-9a-f]{40}", source["git_blob"])):
            raise ValueError("invalid source hash")
        normalization = source.get("normalization")
        if normalization is not None:
            if (not isinstance(normalization, dict) or set(normalization) != {"changed", "dropped", "removed_rules"}
                    or not isinstance(normalization["changed"], dict)
                    or set(normalization["changed"]) - {"lower", "trailing_dot", "wildcard", "idna"}
                    or any(type(count) is not int or count <= 0 for count in normalization["changed"].values())
                    or not isinstance(normalization["dropped"], list)
                    or type(normalization["removed_rules"]) is not int or normalization["removed_rules"] < 0
                    or not (normalization["changed"] or normalization["dropped"])):
                raise ValueError("invalid normalization")
            for dropped in normalization["dropped"]:
                if (not isinstance(dropped, dict) or set(dropped) != {"field", "value", "reason"}
                        or dropped["field"] not in ("domain", "domain_suffix")
                        or not isinstance(dropped["value"], str)
                        or dropped["reason"] not in ("invalid domain", "invalid idna", "wildcard too broad")):
                    raise ValueError("invalid normalization")
                if not historical:
                    try:
                        _, result = normalize_full_rules([{dropped["field"]: dropped["value"]}])
                    except ValueError as exc:
                        raise ValueError("invalid normalization") from exc
                    if result["dropped"] != [dropped]:
                        raise ValueError("invalid normalization")
        if "reason" in source:
            reason = source["reason"]
            fields = {"source", "sha256", "git_blob", "reason"}
            if reason == "no rules after normalization":
                fields.add("normalization")
                allowed = normalization is not None and bool(normalization["dropped"]) and normalization["removed_rules"] > 0
            else:
                allowed = (reason == "sing-box cannot decompile binary AdGuard rules"
                           and source["source"].startswith("AdGuard/HostlistsRegistry/"))
                if historical and reason in ("invalid domain", "sing-box cannot decompile binary AdGuard rules"):
                    allowed = True
            if set(source) != fields or not allowed:
                raise ValueError("invalid exclusion")
            exclusions.append(source)
            continue
        method = source.get("method")
        details = {"native"} if method == "native_mrs" else {"native_reason"}
        if (set(source) != {"source", "sha256", "git_blob", "providers", "count", "behavior", "format",
                            "output", "method"} | details | ({"normalization"} if normalization is not None else set())
                or source["providers"] != [stem] or type(source["count"]) is not int or source["count"] <= 0
                or (source["behavior"], source["format"]) not in (("domain", "mrs"), ("ipcidr", "mrs"), ("classical", "yaml"))
                or source["output"] != stem + "." + source["format"]):
            raise ValueError("invalid source metadata")
        if method == "native_mrs":
            native = source["native"]
            if (snapshots is None or not isinstance(native, dict) or set(native) != {"repo", "commit", "path", "input_sha256"}
                    or not isinstance(native["repo"], str) or native["repo"] not in snapshots
                    or not _safe_path(native["path"])
                    or not native["path"].endswith(".mrs")
                    or (not historical and _candidate(source["source"]) != (native["repo"], native["path"], source["behavior"]))
                    or source["format"] != "mrs" or snapshots.get(native["repo"]) != native["commit"]
                    or not isinstance(native["input_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", native["input_sha256"])):
                raise ValueError("invalid native provenance")
        elif method != "converted_srs" or source["native_reason"] not in (
                "equivalence not established", "classical behavior", "no candidate mapping",
                "behavior mismatch", "candidate absent", "not equivalent"):
            raise ValueError("invalid conversion provenance")
        mapping[stem] = source
    if exclusions != manifest["excluded"]:
        raise ValueError("invalid exclusions")
    outputs = manifest["outputs"]
    expected_outputs = {s["output"] for s in mapping.values()} | {"rule-providers.yaml", "README.md"}
    if historical and isinstance(outputs, dict) and "THIRD_PARTY.md" in outputs:
        expected_outputs.add("THIRD_PARTY.md")
    if not historical or "THIRD_PARTY.md" not in expected_outputs or (isinstance(outputs, dict) and "GUIDE.md" in outputs):
        expected_outputs.add("GUIDE.md")
    if not isinstance(outputs, dict) or set(outputs) != expected_outputs:
        raise ValueError("invalid outputs")
    for source in mapping.values():
        if source["method"] == "native_mrs" and source["native"]["input_sha256"] != outputs[source["output"]]:
            raise ValueError("native output hash mismatch")
    for path, digest in outputs.items():
        file = root / path
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or file.is_symlink() or not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            raise ValueError("invalid output hash")
    actual = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    if actual != set(outputs) | {"manifest.json"} or (root / "manifest.json").is_symlink():
        raise ValueError("unexpected artifact content")
    expected_dirs = {str(parent) for path in outputs for parent in Path(path).parents if str(parent) != "."}
    if {str(p.relative_to(root)) for p in root.rglob("*") if p.is_dir()} != expected_dirs:
        raise ValueError("unexpected artifact directory")
    doc = yaml.load((root / "rule-providers.yaml").read_text(), Loader=UniqueLoader)
    if not isinstance(doc, dict) or set(doc) != {"rule-providers"} or not isinstance(doc["rule-providers"], dict) or set(doc["rule-providers"]) != set(mapping):
        raise ValueError("invalid providers")
    for name, source in mapping.items():
        provider, path = doc["rule-providers"][name], source["output"]
        if (not isinstance(provider, dict) or set(provider) != {"type", "behavior", "format", "path", "url", "interval"}
                or provider["type"] != "http" or provider["behavior"] != source["behavior"]
                or provider["format"] != source["format"] or provider["path"] != "./" + path
                or not isinstance(provider["url"], str) or not provider["url"].startswith("https://")
                or not provider["url"].endswith("/" + urllib.parse.quote(path, safe="/"))
                or provider["interval"] != 86400):
            raise ValueError("invalid provider definition")
    if not historical:
        commit_object = api(f"repos/KaringX/karing-ruleset/git/commits/{commit}", os.environ["GH_TOKEN"])
        tree = api(f"repos/KaringX/karing-ruleset/git/trees/{commit}?recursive=1", os.environ["GH_TOKEN"])
        catalog = anchored_inventory(commit, commit_object, tree)
        if set(catalog) != seen or any(catalog[s["source"]][0] != s["git_blob"] for s in manifest["sources"]):
            raise ValueError("catalog mismatch")
    return manifest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(path, token, missing=False):
    request = urllib.request.Request("https://api.github.com/" + path,
        headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
                 "User-Agent": "mihomo-rules-routing"})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            if response.status != 200 or not response.geturl().startswith("https://api.github.com/"):
                raise ValueError("unexpected API response")
            data = response.read(30 * 1024 * 1024 + 1)
            if len(data) > 30 * 1024 * 1024:
                raise ValueError("API response too large")
            return json.loads(data)
    except urllib.error.HTTPError as exc:
        if missing and exc.code == 404 and exc.url == request.full_url:
            return None
        raise


def download_published_archive(repo, sha, token):
    if (not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            or any(part in (".", "..") for part in repo.split("/"))
            or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
            or not isinstance(token, str) or not token or "\n" in token or "\r" in token):
        raise ValueError("invalid archive request")
    url = f"https://codeload.github.com/{repo}/tar.gz/{sha}"
    request = urllib.request.Request(url, headers={"User-Agent": "mihomo-rules-routing",
                                                  "Authorization": "Bearer " + token})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("unexpected archive response")
        data = response.read(300 * 1024 * 1024 + 1)
        if len(data) > 300 * 1024 * 1024:
            raise ValueError("archive too large")
        return data


def prepare(repo, token, scratch):
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            or any(part in (".", "..") for part in repo.split("/"))):
        raise ValueError("invalid repository")
    api("repos/" + repo, token)
    def revision(project, branch):
        value = api(f"repos/{project}/git/ref/heads/{branch}", token)["object"]["sha"]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError("invalid revision")
        return value
    commit = revision("KaringX/karing-ruleset", "sing")
    snapshots = {"MetaCubeX/meta-rules-dat": revision("MetaCubeX/meta-rules-dat", "meta"),
                 "runetfreedom/russia-blocked-geoip": revision("runetfreedom/russia-blocked-geoip", "release")}
    base = f"https://raw.githubusercontent.com/{repo}/rules"
    value = full_fingerprint(commit, snapshots, base)
    branch = api("repos/" + repo + "/branches/rules", token, missing=True)
    previous = None
    if branch is not None:
        sha = branch["commit"]["sha"]
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("invalid branch commit")
        tree_sha = api(f"repos/{repo}/git/commits/{sha}", token)["tree"]["sha"]
        if not isinstance(tree_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
            raise ValueError("invalid tree SHA")
        tree = api(f"repos/{repo}/git/trees/{tree_sha}?recursive=1", token)
        if tree.get("sha") != tree_sha or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
            raise ValueError("incomplete tree")
        files, dirs = {}, set()
        for entry in tree["tree"]:
            name = entry.get("path")
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_@!+.-]+(?:/[A-Za-z0-9_@!+.-]+)*", name)
                    or any(part in (".", "..") for part in name.split("/")) or name in files or name in dirs):
                raise ValueError("invalid tree path")
            if entry.get("type") == "tree" and entry.get("mode") == "040000":
                dirs.add(name)
            elif (entry.get("type") == "blob" and entry.get("mode") == "100644"
                  and isinstance(entry.get("sha"), str) and re.fullmatch(r"[0-9a-f]{40}", entry["sha"])
                  and type(entry.get("size")) is int and 0 <= entry["size"] <= 20 * 1024 * 1024):
                files[name] = (entry["sha"], entry["size"])
            else:
                raise ValueError("invalid tree entry")
        if len(files) > 50000 or sum(size for _, size in files.values()) > 1024 * 1024 * 1024:
            raise ValueError("published tree too large")
        expected_dirs = {str(parent) for name in files for parent in Path(name).parents if str(parent) != "."}
        if dirs != expected_dirs:
            raise ValueError("invalid published tree directories")
        archive = download_published_archive(repo, sha, token)
        with tempfile.TemporaryDirectory(dir=scratch, prefix="published-") as tmp:
            root, seen, prefix = Path(tmp), set(), None
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
                for member in tar:
                    parts = member.name.rstrip("/").split("/")
                    if not parts[0] or any(part in (".", "..") for part in parts):
                        raise ValueError("invalid archive path")
                    if prefix is None:
                        prefix = parts[0]
                    if parts[0] != prefix:
                        raise ValueError("invalid archive prefix")
                    name = "/".join(parts[1:])
                    if not name and member.isdir():
                        continue
                    if member.isdir() and name in dirs:
                        continue
                    if not member.isfile() or name not in files or name in seen:
                        raise ValueError("unexpected archive entry")
                    blob, size = files[name]
                    if member.size != size:
                        raise ValueError("archive size mismatch")
                    data = tar.extractfile(member).read(size + 1)
                    if len(data) != size or hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest() != blob:
                        raise ValueError("archive blob mismatch")
                    dest = root / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(data)
                    seen.add(name)
            if seen != set(files):
                raise ValueError("archive missing files")
            unstamped = "ci_fingerprint" not in json.loads((root / "manifest.json").read_text())
            previous = validate(root, historical=True, unstamped=unstamped)
    return {"commit": commit, "base_url": base, "fingerprint": value,
            "native_snapshots": json.dumps(snapshots, sort_keys=True, separators=(",", ":")),
            "changed": previous is None or "excluded" not in previous
                       or "ci_fingerprint" not in previous or previous["ci_fingerprint"] != value
                       or previous["upstream_commit"] != commit
                       or previous["native_snapshots"] != snapshots}


def publish(product, checkout, commit, fingerprint_value, expected_native_snapshots=None):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint_value):
        raise ValueError("invalid expected metadata")
    manifest_hash = hashlib.sha256((Path(product) / "manifest.json").read_bytes()).hexdigest()
    manifest = validate(product, expected_commit=commit, expected_fingerprint=fingerprint_value,
                        expected_native_snapshots=expected_native_snapshots)
    if "excluded" not in manifest:
        raise ValueError("only full snapshots may be published")
    if hashlib.sha256((Path(product) / "manifest.json").read_bytes()).hexdigest() != manifest_hash:
        raise ValueError("manifest changed during validation")
    command = ["git", "config", "--local", "--get", "remote.origin.url"]
    result = subprocess.run(command, cwd=checkout, text=True, capture_output=True, check=True)
    remote = result.stdout.strip()
    return publish_snapshot(product, remote, os.environ["TMPDIR"], expected_manifest_sha256=manifest_hash)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["prepare", "stamp", "validate", "publish"])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--fingerprint")
    parser.add_argument("--unstamped", action="store_true")
    parser.add_argument("--native-snapshots", type=Path)
    args = parser.parse_args()
    snapshots = json.loads(args.native_snapshots.read_text()) if args.native_snapshots else None
    if args.command == "prepare":
        result = prepare(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"], os.environ["TMPDIR"])
        with open(os.environ["GITHUB_OUTPUT"], "a") as out:
            for key, value in result.items():
                out.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
    elif args.command == "stamp":
        manifest_path = args.output / "manifest.json"
        manifest = validate(args.output, unstamped=True, expected_commit=os.environ["COMMIT"],
                            expected_native_snapshots=snapshots)
        value = os.environ["FINGERPRINT"]
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid fingerprint")
        manifest["ci_fingerprint"] = value
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        validate(args.output, expected_commit=os.environ["COMMIT"], expected_fingerprint=value,
                 expected_native_snapshots=snapshots)
    elif args.command == "publish":
        if not args.commit or not args.fingerprint:
            parser.error("publish requires --commit and --fingerprint")
        publish(args.output, Path.cwd(), args.commit, args.fingerprint, expected_native_snapshots=snapshots)
    else:
        validate(args.output, unstamped=args.unstamped, expected_commit=args.commit,
                 expected_fingerprint=args.fingerprint, expected_native_snapshots=snapshots)


if __name__ == "__main__":
    main()
