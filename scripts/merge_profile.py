"""Add the approved Karing rules to a separate Remnawave profile."""
import argparse
import json
import os
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROXY = '🌍 Прокси'
AUTO = '⚡ Авто'

# Paths are the source identities in the Task 1 manifest, not guessed provider IDs.
REJECT = '''ACL4SSR/BanAD ACL4SSR/BanProgramAD ACL4SSR/BanADCompany geo/geosite/category-ads geo/geosite/malware geo/geosite/phishing geo/geosite/cryptominers geo/geoip/malware geo/geoip/phishing'''.split()
DIRECT = '''geo/geosite/apple geo/geosite/apple@ads geo/geosite/apple-dev geo/geosite/apple-pki geo/geosite/apple-update ACL4SSR/Epic ACL4SSR/Origin ACL4SSR/Sony ACL4SSR/Nintendo ACL4SSR/Steam geo/geosite/microsoft geo/geosite/microsoft-dev geo/geosite/microsoft-pki'''.split()
AUTOMATIC = '''geo/geosite/google-play ACL4SSR/GoogleFCM geo/geosite/discord ACL4SSR/Discord'''.split()
PROXIED = '''geo/geosite/youtube ACL4SSR/Gemini geo/geosite/google geo/geoip/google geo/geosite/tiktok geo/geosite/instagram geo/geoip/netflix geo/geosite/netflix ACL4SSR/Whatsapp geo/geosite/whatsapp geo/geoip/telegram geo/geosite/telegram ACL4SSR/Claude geo/geoip/openai geo/geosite/openai geo/geoip/github geo/geosite/github geo/geoip/blocked@ru geo/geoip/blocked-community@ru geo/geosite/blocked@ru'''.split()
GROUPS = [
    ('ACL4SSR/BanAD geo/geosite/category-ads', []),
    ('ACL4SSR/BanProgramAD ACL4SSR/BanADCompany', []),
    ('geo/geosite/malware geo/geosite/phishing geo/geosite/cryptominers geo/geoip/malware geo/geoip/phishing', []),
    ('geo/geosite/apple geo/geosite/apple@ads geo/geosite/apple-dev geo/geosite/apple-pki geo/geosite/apple-update', []),
    ('geo/geosite/youtube', ['DOMAIN,twoseven.xyz,' + PROXY, 'PROCESS-NAME,com.google.android.youtube,' + PROXY]),
    ('ACL4SSR/Gemini', []),
    ('geo/geosite/google-play', ['PROCESS-NAME,com.android.vending,' + AUTO]),
    ('ACL4SSR/GoogleFCM', []),
    ('geo/geosite/google geo/geoip/google', []),
    ('geo/geosite/tiktok', []),
    ('geo/geosite/instagram', []),
    ('geo/geoip/netflix geo/geosite/netflix', []),
    ('geo/geosite/discord ACL4SSR/Discord', ['PROCESS-NAME,Update.exe,' + AUTO, 'PROCESS-NAME,Discord.exe,' + AUTO]),
    ('geo/geosite/whatsapp ACL4SSR/Whatsapp', ['PROCESS-NAME,com.whatsapp,' + PROXY]),
    ('geo/geoip/telegram geo/geosite/telegram', ['PROCESS-NAME,org.telegram.messenger.web,' + PROXY, 'PROCESS-NAME,org.telegram.messenger,' + PROXY]),
    ('ACL4SSR/Claude', []),
    ('geo/geoip/openai geo/geosite/openai', []),
    ('geo/geoip/github geo/geosite/github', []),
    ('ACL4SSR/Epic ACL4SSR/Origin ACL4SSR/Sony ACL4SSR/Nintendo ACL4SSR/Steam',
     ['DOMAIN-KEYWORD,twitch,DIRECT'] + [f'PROCESS-NAME,{name},DIRECT' for name in
      'GF2_Exilium.exe ZFGameBrowser.exe PCLauncher.exe steamwebhelper.exe steam.exe deadlock.exe'.split()]),
    ('geo/geoip/blocked@ru geo/geoip/blocked-community@ru geo/geosite/blocked@ru', []),
    ('geo/geosite/microsoft geo/geosite/microsoft-dev geo/geosite/microsoft-pki', []),
]


class StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError('duplicate YAML key')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_yaml(text):
    if any(isinstance(t, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)) for t in yaml.scan(text)):
        raise ValueError('YAML anchors and aliases are not supported')
    return yaml.load(text, Loader=StrictLoader)


def merge(base_text, manifest, providers_text, private):
    base = load_yaml(base_text)
    provider_doc = load_yaml(providers_text)
    nodes = yaml.compose(base_text)
    if not isinstance(base, dict) or not isinstance(provider_doc, dict) or not isinstance(nodes, yaml.MappingNode):
        raise ValueError('expected YAML mappings')
    providers = provider_doc.get('rule-providers')
    existing = base.get('rule-providers')
    rules = base.get('rules')
    groups = base.get('proxy-groups')
    if not isinstance(providers, dict) or not isinstance(existing, dict) or not isinstance(rules, list) or not all(isinstance(r, str) for r in rules) or not isinstance(groups, list):
        raise ValueError('invalid profile structure')
    names = [g.get('name') for g in groups if isinstance(g, dict)]
    if len(names) != len(groups) or len(names) != len(set(names)) or not {PROXY, AUTO}.issubset(names):
        raise ValueError('missing or duplicate proxy groups')
    categories = {name + '.srs': target for entries, target in [(REJECT, 'REJECT'), (DIRECT, 'DIRECT'), (AUTOMATIC, AUTO), (PROXIED, PROXY)] for name in entries}
    expected = json.loads((ROOT / 'config/sets.json').read_text())
    if len(categories) != 46 or set(categories) != set(expected):
        raise ValueError('route mapping mismatch')
    entries = manifest.get('sources') if isinstance(manifest, dict) else None
    if not isinstance(entries, list) or len(entries) != 46:
        raise ValueError('manifest must contain 46 sources')
    mapping = {}
    used = set()
    for entry in entries:
        if not isinstance(entry, dict): raise ValueError('invalid source')
        source, ids = entry.get('source'), entry.get('providers')
        if source not in categories or source in mapping or not isinstance(ids, list) or not ids or not all(isinstance(i, str) and re.fullmatch(r'[a-zA-Z0-9_-]+', i) for i in ids):
            raise ValueError('invalid source mapping')
        for name in ids:
            definition = providers.get(name)
            if name in used or not isinstance(definition, dict) or definition.get('behavior') != entry.get('behavior') or (entry.get('format') and definition.get('format', 'yaml') != entry['format']):
                raise ValueError('invalid provider mapping')
            used.add(name)
        mapping[source] = ids
    if set(mapping) != set(categories) or set(providers) != used or used.intersection(existing):
        raise ValueError('missing, extra, or conflicting providers')
    if not isinstance(private, list) or not all(isinstance(x, str) and len(x) <= 253 and re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in private):
        raise ValueError('invalid private exact-domain input')
    anchors = ['IP-CIDR6,::/0,REJECT-DROP,no-resolve', 'RULE-SET,torrent-clients,REJECT-DROP', 'RULE-SET,ads,REJECT-DROP', 'RULE-SET,ru-direct,DIRECT', 'MATCH,🌍 Прокси']
    if any(rules.count(a) != 1 for a in anchors): raise ValueError('missing or duplicate rule anchor')
    positions = [rules.index(a) for a in anchors]
    if positions != sorted(positions) or positions[-1] != len(rules) - 1:
        raise ValueError('unexpected anchor order')
    node_map = {k.value: (k, v) for k, v in nodes.value}
    pk, pn = node_map['rule-providers']
    rk, rn = node_map['rules']
    if not isinstance(pn, yaml.MappingNode) or pn.flow_style or not isinstance(rn, yaml.SequenceNode) or rn.flow_style:
        raise ValueError('expected block providers and rules')
    if any(not isinstance(n, yaml.ScalarNode) or n.start_mark.line != n.end_mark.line for n in rn.value):
        raise ValueError('expected single-line rules')
    if base_text.count('proxies: # LEAVE THIS LINE!') != 1:
        raise ValueError('missing Remnawave proxies marker')
    grouped = [source + '.srs' for sources, _ in GROUPS for source in sources.split()]
    if len(grouped) != len(categories) or set(grouped) != set(categories):
        raise ValueError('group mapping mismatch')
    security = []
    service = [f'DOMAIN,{name},DIRECT' for name in dict.fromkeys(private)]
    service.append('PROCESS-NAME,qbittorrent.exe,DIRECT')
    for sources, extra in GROUPS:
        for source in sources.split():
            source += '.srs'
            for name in mapping[source]:
                item = f'RULE-SET,{name},{categories[source]}'
                (security if categories[source] == 'REJECT' else service).append(item)
        service.extend(extra)
    # Preserve existing source text, including Remnawave comments and all original settings.
    lines = base_text.splitlines(keepends=True)
    prefixes = [re.match(r'^([ ]*)- +', lines[n.start_mark.line]) for n in rn.value]
    if any(p is None for p in prefixes) or len({p.group(1) for p in prefixes}) != 1:
        raise ValueError('unexpected rule indentation')
    indent = prefixes[0].group(1)
    line_rules = lambda items: ''.join(indent + '- ' + json.dumps(item, ensure_ascii=False) + '\n' for item in items)
    provider_lines = yaml.safe_dump(providers, allow_unicode=True, sort_keys=False, default_flow_style=False)
    provider_lines = ''.join('  ' + line for line in provider_lines.splitlines(keepends=True))
    torrent_node = rn.value[positions[1]]
    torrent_line = torrent_node.start_mark.line
    line = lines[torrent_line]
    if line.count(anchors[1]) != 1: raise ValueError('unexpected torrent rule representation')
    lines[torrent_line] = line.replace(anchors[1], 'RULE-SET,torrent-clients,DIRECT')
    inserts = [(pn.end_mark.line, provider_lines), (torrent_line, line_rules(security)), (rn.value[positions[3]].start_mark.line, line_rules(service))]
    for index, content in sorted(inserts, reverse=True):
        lines.insert(index, content)
    result = ''.join(lines)
    parsed = load_yaml(result)
    expected_rules = rules.copy()
    expected_rules[positions[1]] = 'RULE-SET,torrent-clients,DIRECT'
    expected_rules[positions[3]:positions[3]] = service
    expected_rules[positions[1]:positions[1]] = security
    expected_base = dict(base)
    expected_base['rules'] = expected_rules
    expected_base['rule-providers'] = {**existing, **providers}
    if parsed != expected_base:
        raise ValueError('generated profile validation failed')
    return result


def main():
    parser = argparse.ArgumentParser()
    for name in ('base', 'build', 'private', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in {args.base.resolve(), args.private.resolve(), (args.build / 'manifest.json').resolve(), (args.build / 'rule-providers.yaml').resolve()}:
        raise ValueError('output overlaps an input')
    if args.output.resolve().is_relative_to(args.build.resolve()):
        raise ValueError('output inside build directory')
    text = merge(args.base.read_text(), json.loads((args.build / 'manifest.json').read_text()),
                 (args.build / 'rule-providers.yaml').read_text(), json.loads(args.private.read_text()))
    data = text.encode('utf-8')
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    info = None
    try:
        info = os.fstat(fd)
        remaining = memoryview(data)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise OSError('short write')
            remaining = remaining[count:]
        closing, fd = fd, None
        os.close(closing)
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if info is not None:
            try:
                current = os.stat(args.output, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                    os.unlink(args.output)
            except OSError:
                pass
        raise


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        print(f'merge failed: {exc}', file=sys.stderr)
        sys.exit(1)
