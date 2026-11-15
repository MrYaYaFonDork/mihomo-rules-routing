"""Build selected Karing SRS rule providers using pinned sing-box and Mihomo."""

import argparse
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
import urllib.parse

try:
    from scripts.fetch_tools import download, ROOT, verify_sha256
except ModuleNotFoundError:
    from fetch_tools import download, ROOT, verify_sha256


def payload_yaml(entries):
    return "payload:\n" + "".join("  - " + json.dumps(item, ensure_ascii=False) + "\n" for item in entries)


def providers_yaml(providers):
    return "rule-providers:\n" + "".join(
        "  " + name + ":\n" + "".join(
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


def build(source_dir, output, work_dir, sing_box, mihomo, commit, base_url, source_origin="local/unverified"):
    source_dir, output, work_dir = map(Path, (source_dir, output, work_dir))
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be 40 lowercase hexadecimal characters")
    if not base_url.startswith("https://"):
        raise ValueError("base URL must use HTTPS")
    sets = json.loads((ROOT / "config/sets.json").read_text())
    tools = json.loads((ROOT / "config/tools.json").read_text())
    if source_origin not in ("local/unverified", "authenticated_download"):
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
        (stage / "rules").mkdir(parents=True)
        providers, sources = {}, []
        for source in sets:
            file = source_dir / source
            raw = file.read_bytes()
            decoded = tmp / "decoded.json"
            subprocess.run([str(sing_box), "rule-set", "decompile", str(file),
                            "-o", str(decoded)], check=True, capture_output=True)
            data = json.loads(decoded.read_text())
            if (set(data) != {"version", "rules"} or data["version"] not in (1, 2) or
                    not isinstance(data["rules"], list) or not data["rules"] or
                    any(not isinstance(rule, dict) for rule in data["rules"])):
                raise ValueError(f"{source}: invalid rule set")
            identifier = re.sub(r"[^a-z0-9]+", "-", source.lower()).strip("-")
            if identifier in providers:
                raise ValueError("duplicate provider ID")
            rules = data["rules"]
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
            rel = f"rules/{identifier}.{ext}"
            target = stage / rel
            payload = payload_yaml(sorted(entries))
            if behavior == "classical":
                target.write_text(payload, encoding="utf-8")
            else:
                yaml = tmp / "payload.yaml"
                yaml.write_text(payload, encoding="utf-8")
                subprocess.run([str(mihomo), "convert-ruleset", behavior, "yaml",
                                str(yaml), str(target)], check=True, capture_output=True)
            providers[identifier] = {"type": "http", "behavior": behavior,
                                     "format": "yaml" if ext == "yaml" else "mrs",
                                     "path": "./" + rel,
                                     "url": base_url.rstrip("/") + "/" + rel,
                                     "interval": 86400}
            sources.append({"source": source, "sha256": hashlib.sha256(raw).hexdigest(),
                            "providers": [identifier], "count": len(entries),
                            "behavior": behavior, "format": providers[identifier]["format"]})
        (stage / "rule-providers.yaml").write_text(providers_yaml(providers))
        hashes = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(stage.rglob("*")) if p.is_file()}
        manifest = {"source_origin": source_origin,
                    "claimed_commit" if source_origin == "local/unverified" else "upstream_commit": commit,
                    "tools": tool_info, "sources": sources, "outputs": hashes}
        (stage / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
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
                if (not isinstance(value, str) or not value or
                        any(char in value for char in ",\r\n()")):
                    raise ValueError("invalid rule value")
                if key in ("domain", "domain_suffix") and not re.fullmatch(r"\.?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", value):
                    raise ValueError("invalid domain")
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
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--base-url", default="https://raw.githubusercontent.com/MrALDAP/mihomo-rules-routing/rules")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("commit must be 40 lowercase hexadecimal characters")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="sources-") as tmp:
        source_dir = args.source_dir or Path(tmp)
        if not args.source_dir:
            for source in json.loads((ROOT / "config/sets.json").read_text()):
                target = source_dir / source
                target.parent.mkdir(parents=True, exist_ok=True)
                url = ("https://raw.githubusercontent.com/KaringX/karing-ruleset/" +
                       args.commit + "/" + urllib.parse.quote(source, safe="/"))
                download(url, target, limit=20 * 1024 * 1024)
        build(source_dir, args.output, args.work_dir, args.sing_box.resolve(),
              args.mihomo.resolve(), args.commit, args.base_url,
              "local/unverified" if args.source_dir else "authenticated_download")


if __name__ == "__main__":
    main()
