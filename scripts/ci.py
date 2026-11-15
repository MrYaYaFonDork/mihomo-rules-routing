"""Small, fail-closed helpers for the rules workflow."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
import tempfile
import subprocess
import shutil
import yaml

ROOT = Path(__file__).resolve().parent.parent


def fingerprint(commit, base_url, paths):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid upstream commit")
    digest = hashlib.sha256()
    for value in [commit.encode(), base_url.encode()] + [Path(p).read_bytes() for p in paths]:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
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


def validate(root, unstamped=False, expected_commit=None, expected_fingerprint=None, historical=False):
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text())
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


def prepare(repo, token, scratch):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("invalid repository")
    commit = api("repos/KaringX/karing-ruleset/commits/sing", token)["sha"]
    base = f"https://raw.githubusercontent.com/{repo}/rules"
    paths = [ROOT / p for p in ("config/tools.json", "config/sets.json",
             "scripts/build.py", "scripts/fetch_tools.py", "scripts/integration_check.py",
             "scripts/ci.py", ".github/workflows/build.yml")]
    value = fingerprint(commit, base, paths)
    api("repos/" + repo, token)
    branch = api("repos/" + repo + "/branches/rules", token, missing=True)
    previous = None
    if branch is not None:
        sha = branch["commit"]["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("invalid branch commit")
        tree_sha = api(f"repos/{repo}/git/commits/{sha}", token)["tree"]["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
            raise ValueError("invalid tree SHA")
        tree = api(f"repos/{repo}/git/trees/{tree_sha}?recursive=1", token)
        if tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
            raise ValueError("incomplete tree")
        with tempfile.TemporaryDirectory(dir=scratch, prefix="published-") as tmp:
            root = Path(tmp)
            seen = set()
            for entry in tree["tree"]:
                name = entry["path"]
                if name == "rules" and entry["type"] == "tree" and entry["mode"] == "040000":
                    continue
                if (name in seen or entry["type"] != "blob" or entry["mode"] != "100644"
                        or not (name in ("manifest.json", "rule-providers.yaml")
                                or re.fullmatch(r"rules/[a-z0-9-]+\.(mrs|yaml)", name))
                        or not re.fullmatch(r"[0-9a-f]{40}", entry["sha"])):
                    raise ValueError("invalid tree entry")
                seen.add(name)
                blob = api(f"repos/{repo}/git/blobs/{entry['sha']}", token)
                if blob.get("encoding") != "base64" or type(blob.get("size")) is not int or not 0 <= blob["size"] <= 20 * 1024 * 1024:
                    raise ValueError("invalid blob")
                content = base64.b64decode(blob["content"].replace("\n", "").replace("\r", ""), validate=True)
                if len(content) != blob["size"]:
                    raise ValueError("invalid blob size")
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(content)
            previous = validate(root, historical=True)
    current_sources = json.loads((ROOT / "config/sets.json").read_text())
    if len(current_sources) != 46 or len(set(current_sources)) != 46:
        raise ValueError("invalid current sources")
    return {"commit": commit, "base_url": base, "fingerprint": value,
            "changed": previous is None or previous["ci_fingerprint"] != value
                       or previous["upstream_commit"] != commit
                       or {s["source"] for s in previous["sources"]} != set(current_sources)}


def publish(product, checkout, commit, fingerprint_value):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint_value):
        raise ValueError("invalid expected metadata")
    manifest = validate(product, expected_commit=commit, expected_fingerprint=fingerprint_value)
    manifest_hash = hashlib.sha256((Path(product) / "manifest.json").read_bytes()).hexdigest()
    def git(*args, allowed=(0,)):
        command = ["git", *args]
        result = subprocess.run(command, cwd=checkout, text=True, capture_output=True)
        if result.returncode not in allowed:
            raise subprocess.CalledProcessError(result.returncode, command)
        return result
    git("config", "user.name", "github-actions[bot]")
    git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    branch = git("ls-remote", "--exit-code", "--heads", "origin", "refs/heads/rules", allowed=(0, 2))
    if branch.returncode == 0:
        git("fetch", "origin", "refs/heads/rules")
        git("switch", "-c", "rules", "FETCH_HEAD")
    else:
        git("switch", "--orphan", "rules")
        git("rm", "-rf", "--ignore-unmatch", ".")
    tracked = git("ls-files").stdout.splitlines()
    if any(not re.fullmatch(r"(rules/[a-z0-9-]+\.(mrs|yaml)|rule-providers\.yaml|manifest\.json)", p) for p in tracked):
        raise ValueError("unexpected file in rules branch")
    git("rm", "-rf", "--ignore-unmatch", "rules", "rule-providers.yaml", "manifest.json")
    shutil.copytree(Path(product) / "rules", Path(checkout) / "rules")
    for name in ("rule-providers.yaml", "manifest.json"):
        if os.path.lexists(Path(checkout) / name):
            raise ValueError("unexpected untracked file")
        shutil.copy2(Path(product) / name, Path(checkout) / name)
    for name, expected in {**manifest["outputs"], "manifest.json": manifest_hash}.items():
        target = Path(checkout) / name
        if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise ValueError("copied output mismatch")
    rule_files = {str(p.relative_to(checkout)) for p in (Path(checkout) / "rules").rglob("*")
                  if p.is_file() or p.is_symlink()}
    if rule_files != set(manifest["outputs"]) - {"rule-providers.yaml"}:
        raise ValueError("unexpected copied output")
    git("add", "rules", "rule-providers.yaml", "manifest.json")
    if git("diff", "--cached", "--quiet", allowed=(0, 1)).returncode == 1:
        git("commit", "-m", "Update generated rules")
        git("push", "origin", "HEAD:refs/heads/rules")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["prepare", "stamp", "validate", "publish"])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--fingerprint")
    parser.add_argument("--unstamped", action="store_true")
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"], os.environ["TMPDIR"])
        with open(os.environ["GITHUB_OUTPUT"], "a") as out:
            for key, value in result.items():
                out.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
    elif args.command == "stamp":
        manifest_path = args.output / "manifest.json"
        manifest = validate(args.output, unstamped=True, expected_commit=os.environ["COMMIT"])
        value = os.environ["FINGERPRINT"]
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid fingerprint")
        manifest["ci_fingerprint"] = value
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        validate(args.output, expected_commit=os.environ["COMMIT"], expected_fingerprint=value)
    elif args.command == "publish":
        if not args.commit or not args.fingerprint:
            parser.error("publish requires --commit and --fingerprint")
        publish(args.output, Path.cwd(), args.commit, args.fingerprint)
    else:
        validate(args.output, unstamped=args.unstamped, expected_commit=args.commit, expected_fingerprint=args.fingerprint)


if __name__ == "__main__":
    main()
