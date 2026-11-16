"""Build selected Karing SRS rule providers using pinned sing-box and Mihomo."""

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile
import urllib.parse

try:
    from scripts.fetch_tools import download, ROOT, verify_sha256
    from scripts.catalog import anchored_inventory, output_stem
    from scripts.native import NativeCatalog, META, RF, _fetch
except ModuleNotFoundError:
    from fetch_tools import download, ROOT, verify_sha256
    from catalog import anchored_inventory, output_stem
    from native import NativeCatalog, META, RF, _fetch


def payload_yaml(entries):
    return "payload:\n" + "".join("  - " + json.dumps(item, ensure_ascii=False) + "\n" for item in entries)


def rename_noreplace(source, target):
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError as exc:
        raise OSError("renameat2 unavailable") from exc
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(target))


def providers_yaml(providers):
    return "rule-providers:\n" + "".join(
        "  " + (name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else json.dumps(name)) + ":\n" + "".join(
            "    " + key + ": " + json.dumps(value, ensure_ascii=False) + "\n"
            for key, value in fields.items())
        for name, fields in providers.items())


def check_version(binary, args, version):
    text = subprocess.run([str(binary), *args], check=True, capture_output=True,
                          text=True, timeout=30).stdout.splitlines()[0]
    if not re.search(r"(?<![0-9.])v?" + re.escape(version) + r"(?![0-9.])", text):
        raise ValueError(f"unexpected tool version: {text}")
    return {"version": text, "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest()}


def translate_regex(value):
    if (not isinstance(value, str) or not value or value != value.strip()
            or re.search(r"\s,|,\s|[\r\n]", value) or "(?" in value
            or any(token in value for token in ("[:", "[.", "[="))):
        raise ValueError("unsupported regex syntax or whitespace")
    out = []
    inside = False
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\":
            if i + 1 >= len(value):
                raise ValueError("incomplete regex escape")
            nxt = value[i + 1]
            replacements = {"w": "[0-9A-Za-z_]", "d": "[0-9]", "S": r"[^\t\n\f\r ]"}
            if nxt in replacements:
                if inside:
                    raise ValueError("unsupported regex escape in character class")
                out.append(replacements[nxt])
            elif nxt.isalnum():
                raise ValueError("unsupported regex escape")
            else:
                out.append("\\" + nxt)
            i += 2
            continue
        if char.isupper() or ord(char) > 127:
            raise ValueError("unsupported regex uppercase or non-ASCII")
        if char == "[":
            inside = True
        elif char == "]":
            inside = False
        out.append(char)
        i += 1
    try:
        if re.search(value, "", flags=re.ASCII):
            raise ValueError("regex matches empty host")
    except re.error as exc:
        raise ValueError("invalid or unsupported regex") from exc
    return "".join(out)


def classical_lines(rule):
    address = {"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"}
    if isinstance(rule, dict) and set(rule) <= address | {"type"} and rule.get("type", "default") == "default":
        lines = []
        for key in address:
            if key in rule:
                values = rule[key] if isinstance(rule[key], list) else [rule[key]]
                if not values:
                    raise ValueError("empty match")
                if key == "domain_regex":
                    lines.extend("DOMAIN-REGEX," + translate_regex(value) for value in values)
                else:
                    lines.extend(convert_rule({key: value}) for value in values)
        if not lines:
            raise ValueError("empty match")
        return sorted(lines)
    return [convert_rule(rule)]


def verify_blob(raw, sha, size):
    header = b"blob " + str(len(raw)).encode() + b"\0"
    if len(raw) != size or hashlib.sha1(header + raw).hexdigest() != sha:
        raise ValueError("Git blob hash or size mismatch")


def extract_catalog(archive, catalog, destination):
    seen, prefix, total = set(), None, 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            parts = member.name.split("/")
            if not parts[0] or any(part in (".", "..") for part in parts):
                raise ValueError("invalid archive path")
            if prefix is None:
                prefix = parts[0]
            if parts[0] != prefix or not (member.isfile() or member.isdir()):
                raise ValueError("invalid archive member")
            total += member.size
            if total > 1024 * 1024 * 1024:
                raise ValueError("archive too large")
            source = "/".join(parts[1:])
            if not source.endswith(".srs"):
                continue
            if source not in catalog or source in seen or not member.isfile():
                raise ValueError("unexpected SRS archive member")
            sha, size = catalog[source]
            if member.size != size:
                raise ValueError("Git blob size mismatch")
            raw = tar.extractfile(member).read(size + 1)
            verify_blob(raw, sha, size)
            target = destination / source
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            seen.add(source)
    if seen != set(catalog):
        raise ValueError("archive missing SRS")


def validate_full_rules(rules):
    reason = None
    domain_errors = ("invalid domain", "exact domain cannot start with a dot")
    def check(rule):
        nonlocal reason
        try:
            classical_lines(rule)
        except ValueError as exc:
            if str(exc) not in domain_errors:
                raise
            reason = "invalid domain"
            if isinstance(rule, dict) and rule.get("type") == "logical":
                for child in rule.get("rules", []):
                    check(child)
            elif isinstance(rule, dict):
                for key, values in rule.items():
                    if key in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "process_name"):
                        try:
                            classical_lines({key: values})
                            continue
                        except ValueError as field_error:
                            if str(field_error) not in domain_errors:
                                raise
                        for value in values if isinstance(values, list) else [values]:
                            try:
                                classical_lines({key: value})
                            except ValueError as item_error:
                                if str(item_error) not in domain_errors:
                                    raise
    for rule in rules:
        check(rule)
    return reason


def normalize_full_rules(rules):
    validate_full_rules(rules)
    report = {"changed": {}, "dropped": [], "removed_rules": 0}

    def normalize(rule):
        rule = dict(rule)
        if rule.get("type") == "logical":
            rule["rules"] = [result for child in rule["rules"] if (result := normalize(child)) is not None]
            if not rule["rules"]:
                report["removed_rules"] += 1
                return None
            return rule
        domains, suffixes = [], []
        for field, target in (("domain", domains), ("domain_suffix", suffixes)):
            if field not in rule:
                continue
            values = rule.pop(field)
            for value in values if isinstance(values, list) else [values]:
                original = value
                kinds = []
                value = value.lower()
                if value != original:
                    kinds.append("lower")
                if value.endswith(".") and not value.endswith(".."):
                    value = value[:-1]
                    kinds.append("trailing_dot")
                wildcard = "*" in value or value.startswith("+.")
                reason = None
                if wildcard:
                    labels = value.lstrip(".").split(".")
                    rest = (labels[max(i for i, label in enumerate(labels) if "*" in label) + 1:]
                            if "*" in value else labels[1:])
                    if not all(rest):
                        reason = "invalid domain"
                    elif len(rest) < 2:
                        reason = "wildcard too broad"
                    else:
                        value = ".".join(rest)
                        kinds.append("wildcard")
                if reason is None and not value.isascii():
                    try:
                        lead = "." if value.startswith(".") else ""
                        value = lead + ".".join(label.encode("idna").decode("ascii")
                                                for label in (value[1:] if lead else value).split("."))
                        kinds.append("idna")
                    except UnicodeError:
                        reason = "invalid idna"
                key = "domain_suffix" if wildcard else field
                if reason is None:
                    try:
                        convert_rule({key: value})
                    except ValueError:
                        reason = "invalid domain"
                if reason:
                    report["dropped"].append({"field": field, "value": original, "reason": reason})
                else:
                    (suffixes if wildcard else target).append(value)
                    for kind in kinds:
                        report["changed"][kind] = report["changed"].get(kind, 0) + 1
        if domains:
            rule["domain"] = domains
        if suffixes:
            rule["domain_suffix"] = suffixes
        if not set(rule) - {"type", "invert"}:
            report["removed_rules"] += 1
            return None
        return rule

    normalized = [result for rule in rules if (result := normalize(rule)) is not None]
    for rule in normalized:
        classical_lines(rule)
    return normalized, report


def validate_native_snapshots(snapshots):
    if (not isinstance(snapshots, dict) or set(snapshots) != {META, RF}
            or any(not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
                   for sha in snapshots.values())):
        raise ValueError("invalid native snapshots")


def fetch_catalog(commit):
    base = "https://api.github.com/repos/KaringX/karing-ruleset/git/"
    commit_object = json.loads(_fetch(base + "commits/" + commit, 1024 * 1024))
    tree = json.loads(_fetch(base + "trees/" + commit + "?recursive=1", 30 * 1024 * 1024))
    return anchored_inventory(commit, commit_object, tree)


def build(source_dir, output, work_dir, sing_box, mihomo, commit, base_url, source_origin="local/unverified", full_catalog=None, native_snapshots=None):
    source_dir, output, work_dir = map(Path, (source_dir, output, work_dir))
    if full_catalog is not None and os.path.lexists(output):
        raise FileExistsError("full output already exists")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be 40 lowercase hexadecimal characters")
    if not base_url.startswith("https://"):
        raise ValueError("base URL must use HTTPS")
    if full_catalog is not None:
        validate_native_snapshots(native_snapshots)
        if source_origin in ("git_blob_verified", "authenticated_download") and full_catalog != fetch_catalog(commit):
            raise ValueError("catalog differs from anchored inventory")
    elif native_snapshots is not None or source_origin == "git_blob_verified":
        raise ValueError("native snapshots and verified cache require full mode")
    sets = sorted(full_catalog) if full_catalog is not None else json.loads((ROOT / "config/sets.json").read_text())
    tools = json.loads((ROOT / "config/tools.json").read_text())
    if source_origin not in ("local/unverified", "authenticated_download", "git_blob_verified"):
        raise ValueError("invalid source origin")
    verify_sha256(sing_box, tools["sing-box"]["binary_sha256"])
    verify_sha256(mihomo, tools["mihomo"]["binary_sha256"])
    tool_info = {
        "sing-box": check_version(sing_box, ["version"], tools["sing-box"]["version"]),
        "mihomo": check_version(mihomo, ["-v"], tools["mihomo"]["version"])
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work_dir, prefix="build-") as tmp:
        tmp = Path(tmp)
        stage = tmp / "output"
        stage.mkdir()
        native_catalog = NativeCatalog(native_snapshots, mihomo, tmp) if full_catalog is not None else None
        if full_catalog is None:
            (stage / "rules").mkdir(parents=True)
        providers, sources, excluded = {}, [], []
        for source in sets:
            file = source_dir / source
            raw = file.read_bytes()
            if full_catalog is not None:
                verify_blob(raw, *full_catalog[source])
            decoded = tmp / "decoded.json"
            try:
                subprocess.run([str(sing_box), "rule-set", "decompile", str(file),
                                "-o", str(decoded)], check=True, capture_output=True)
            except subprocess.CalledProcessError as exc:
                if (full_catalog is None or not source.startswith("AdGuard/HostlistsRegistry/")
                        or not re.fullmatch(
                            rb"(?:(?:FATAL|\x1b\[31mFATAL\x1b\[0m)\[[0-9]{4,}\] )?"
                            rb"unable to decompile binary AdGuard rules to rule-set\.\n?", exc.stderr)):
                    raise
                reason = "sing-box cannot decompile binary AdGuard rules"
                item = {"source": source, "sha256": hashlib.sha256(raw).hexdigest(),
                        "git_blob": full_catalog[source][0], "reason": reason}
                sources.append(item)
                excluded.append(item)
                continue
            data = json.loads(decoded.read_text())
            if (set(data) != {"version", "rules"} or data["version"] not in (1, 2) or
                    not isinstance(data["rules"], list) or not data["rules"] or
                    any(not isinstance(rule, dict) for rule in data["rules"])):
                raise ValueError(f"{source}: invalid rule set")
            identifier = output_stem(source) if full_catalog is not None else re.sub(r"[^a-z0-9]+", "-", source.lower()).strip("-")
            if identifier in providers:
                raise ValueError("duplicate provider ID")
            rules = data["rules"]
            normalization = None
            try:
                if full_catalog is not None:
                    rules, normalization = normalize_full_rules(rules)
            except ValueError as exc:
                raise ValueError(f"{source}: {exc}") from exc
            if full_catalog is not None and not rules:
                item = {"source": source, "sha256": hashlib.sha256(raw).hexdigest(),
                         "git_blob": full_catalog[source][0], "reason": "no rules after normalization",
                         "normalization": normalization}
                sources.append(item)
                excluded.append(item)
                continue
            if full_catalog is None:
                for rule in rules:
                    classical_lines(rule)
            keys = set().union(*(r.keys() for r in rules))
            if keys <= {"domain", "domain_suffix"}:
                behavior = "domain"
                entries = []
                for rule in rules:
                    for key, values in rule.items():
                        values = values if isinstance(values, list) else [values]
                        if not values:
                            raise ValueError("empty values")
                        for value in values:
                            convert_rule({key: value})
                            entries.append(value if key == "domain" else
                                           (value if value.startswith(".") else "+." + value))
            elif keys == {"ip_cidr"}:
                behavior = "ipcidr"
                entries = []
                for rule in rules:
                    values = rule["ip_cidr"]
                    values = values if isinstance(values, list) else [values]
                    if not values:
                        raise ValueError("empty values")
                    for value in values:
                        convert_rule({"ip_cidr": value})
                        entries.append(value)
            else:
                behavior = "classical"
                entries = [line for rule in rules for line in classical_lines(rule)]
            if not entries:
                raise ValueError("empty output")
            ext = "yaml" if behavior == "classical" else "mrs"
            rel = f"{identifier}.{ext}" if full_catalog is not None else f"rules/{identifier}.{ext}"
            target = stage / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = payload_yaml(sorted(entries))
            if behavior == "classical":
                target.write_text(payload, encoding="utf-8")
                native_result = {"method": "converted_srs", "reason": "classical behavior"}
            else:
                yaml = tmp / "payload.yaml"
                yaml.write_text(payload, encoding="utf-8")
                subprocess.run([str(mihomo), "convert-ruleset", behavior, "yaml",
                                str(yaml), str(target)], check=True, capture_output=True)
                if full_catalog is not None:
                    native_result = native_catalog.maybe_reuse(source, target, behavior)
            providers[identifier] = {"type": "http", "behavior": behavior,
                                     "format": "yaml" if ext == "yaml" else "mrs",
                                     "path": "./" + rel,
                                     "url": base_url.rstrip("/") + "/" + (urllib.parse.quote(rel, safe="/") if full_catalog is not None else rel),
                                     "interval": 86400}
            sources.append({"source": source, "sha256": hashlib.sha256(raw).hexdigest(),
                            "providers": [identifier], "count": len(entries),
                            "behavior": behavior, "format": providers[identifier]["format"]})
            if full_catalog is not None:
                sources[-1].update({"git_blob": full_catalog[source][0],
                                      "output": rel, "method": native_result["method"]})
                if normalization["changed"] or normalization["dropped"]:
                    sources[-1]["normalization"] = normalization
                if native_result["method"] == "native_mrs":
                    sources[-1]["native"] = {key: native_result[key] for key in ("repo", "commit", "path", "input_sha256")}
                else:
                    sources[-1]["native_reason"] = native_result["reason"]
        (stage / "rule-providers.yaml").write_text(providers_yaml(providers))
        if full_catalog is not None:
            for name in ("README.md", "GUIDE.md"):
                shutil.copyfile(ROOT / name, stage / name)
        hashes = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(stage.rglob("*")) if p.is_file()}
        manifest = {"source_origin": source_origin,
                    "claimed_commit" if source_origin == "local/unverified" else "upstream_commit": commit,
                     "tools": tool_info, "sources": sources, "outputs": hashes}
        if full_catalog is not None:
            manifest["excluded"] = excluded
            manifest["native_snapshots"] = native_snapshots
        (stage / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        if full_catalog is not None:
            with tempfile.TemporaryDirectory(dir=output.parent, prefix=".full-stage-") as staging:
                candidate = Path(staging) / "product"
                shutil.copytree(stage, candidate)
                rename_noreplace(candidate, output)
            return
        # Preserve the old output until all transformations have completed.
        replacement = output.parent / ("." + output.name + ".new")
        backup = output.parent / ("." + output.name + ".old")
        if replacement.exists() or backup.exists():
            raise FileExistsError("stale output transaction; inspect before retrying")
        try:
            shutil.copytree(stage, replacement)
            if output.exists():
                os.replace(output, backup)
            try:
                os.replace(replacement, output)
            except BaseException:
                if backup.exists():
                    os.replace(backup, output)
                raise
        finally:
            if replacement.exists():
                shutil.rmtree(replacement)
        if backup.exists():
            try:
                shutil.rmtree(backup)
            except OSError as exc:
                print(f"warning: output committed; manually inspect and remove backup {backup}: {exc}", file=sys.stderr)


def _combine(operator, terms):
    if not terms:
        raise ValueError("empty match")
    if len(terms) == 1 and operator != "NOT":
        return terms[0]
    return operator + ",(" + ",".join("(" + term + ")" for term in terms) + ")"


def convert_rule(rule):
    if not isinstance(rule, dict):
        raise ValueError("rule must be an object")
    invert = rule.get("invert", False)
    if not isinstance(invert, bool):
        raise ValueError("invert must be boolean")
    if rule.get("type", "default") == "logical":
        if set(rule) - {"type", "mode", "rules", "invert"}:
            raise ValueError("unknown logical field")
        mode = rule.get("mode")
        children = rule.get("rules")
        if mode not in ("and", "or") or not isinstance(children, list) or not children:
            raise ValueError("invalid logical rule")
        result = _combine(mode.upper(), [convert_rule(child) for child in children])
    else:
        names = {"domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX",
                 "domain_keyword": "DOMAIN-KEYWORD",
                 "ip_cidr": "IP-CIDR", "process_name": "PROCESS-NAME"}
        if rule.get("type", "default") != "default" or set(rule) - (set(names) | {"type", "invert"}):
            raise ValueError("unknown rule field")
        address, process = [], []
        for key, name in names.items():
            if key not in rule:
                continue
            values = rule[key]
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list) or not values:
                raise ValueError("expected nonempty list of strings")
            for value in values:
                if not isinstance(value, str) or not value:
                    raise ValueError("invalid rule value")
                if key in ("domain", "domain_suffix") and not re.fullmatch(r"\.?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", value):
                    raise ValueError("invalid domain")
                if any(char in value for char in ",\r\n()"):
                    raise ValueError("invalid rule value")
                if key == "domain" and value.startswith("."):
                    raise ValueError("exact domain cannot start with a dot")
                if key == "ip_cidr":
                    try:
                        ipaddress.ip_network(value, strict=False)
                    except ValueError as exc:
                        raise ValueError("invalid IP network") from exc
                if key == "domain_suffix" and value.startswith("."):
                    if len(value) == 1:
                        raise ValueError("empty domain suffix")
                    domain = value[1:]
                    term = _combine("AND", ["DOMAIN-SUFFIX," + domain,
                                             _combine("NOT", ["DOMAIN," + domain])])
                else:
                    term = name + "," + value
                (process if key == "process_name" else address).append(term)
        groups = [_combine("OR", group) for group in (address, process) if group]
        result = _combine("AND", groups)
    return _combine("NOT", [result]) if invert else result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True, help="40-character Karing sing branch commit")
    parser.add_argument("--source-dir", type=Path, help="existing snapshot directory; omit to download")
    parser.add_argument("--full", action="store_true", help="build all SRS in the pinned Git tree")
    parser.add_argument("--native-snapshots", type=Path, help="JSON file with pinned native commits (full mode)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--base-url", default="https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("commit must be 40 lowercase hexadecimal characters")
    if args.full:
        if not args.native_snapshots:
            parser.error("--full requires --native-snapshots")
        snapshots = json.loads(args.native_snapshots.read_text())
        validate_native_snapshots(snapshots)
    else:
        if args.native_snapshots:
            parser.error("--native-snapshots requires --full")
        snapshots = None
    if args.full and os.path.lexists(args.output):
        raise FileExistsError("full output already exists")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="sources-") as tmp:
        source_dir = args.source_dir or Path(tmp)
        catalog = None
        if args.full:
            catalog = fetch_catalog(args.commit)
        if not args.source_dir:
            if catalog is not None:
                archive = Path(tmp) / "snapshot.tar.gz"
                download("https://codeload.github.com/KaringX/karing-ruleset/tar.gz/" +
                         args.commit, archive, limit=300 * 1024 * 1024)
                extract_catalog(archive, catalog, source_dir)
            else:
                for source in json.loads((ROOT / "config/sets.json").read_text()):
                    target = source_dir / source
                    target.parent.mkdir(parents=True, exist_ok=True)
                    url = ("https://raw.githubusercontent.com/KaringX/karing-ruleset/" +
                           args.commit + "/" + urllib.parse.quote(source, safe="/"))
                    download(url, target, limit=20 * 1024 * 1024)
        build(source_dir, args.output, args.work_dir, args.sing_box.resolve(),
              args.mihomo.resolve(), args.commit, args.base_url,
              ("git_blob_verified" if args.source_dir and args.full else
               "local/unverified" if args.source_dir else "authenticated_download"),
              full_catalog=catalog, native_snapshots=snapshots)


if __name__ == "__main__":
    main()
