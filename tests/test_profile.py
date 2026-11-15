import json
import copy
import os
import resource
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TMP = '/tmp/opencode/mihomo-rules-routing'
SETS = json.loads((ROOT / 'config/sets.json').read_text())


class ProfileTests(unittest.TestCase):
    def setUp(self):
        Path(TMP).mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=TMP)
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name)
        self.build = self.p / 'build'
        self.build.mkdir()
        self.sources = [{'source': name, 'providers': [f'synthetic-{i}'], 'behavior': 'domain', 'format': 'yaml'} for i, name in enumerate(SETS)]
        self.providers = {f'synthetic-{i}': {'type': 'file', 'behavior': 'domain', 'path': f'./synthetic-{i}.yaml'} for i in range(46)}
        self.write_build()
        self.base = {'remnawave': {'synthetic': True}, 'dns': {'enable': True}, 'tun': {'enable': False}, 'proxies': [],
                     'proxy-groups': [{'name': n, 'type': 'select', 'proxies': ['DIRECT']} for n in ('🌍 Прокси', '⚡ Авто')],
                     'rule-providers': {'existing': {'type': 'file', 'path': './existing.yaml', 'behavior': 'domain'}},
                     'rules': ['DOMAIN,original.example,DIRECT', 'IP-CIDR6,::/0,REJECT-DROP,no-resolve',
                               'RULE-SET,torrent-clients,REJECT-DROP', 'AND,((NETWORK,UDP),(DST-PORT,443)),REJECT-DROP',
                               'RULE-SET,ads,REJECT-DROP', 'RULE-SET,ru-direct,DIRECT', 'MATCH,🌍 Прокси']}
        self.write_base()
        (self.p / 'private.json').write_text(json.dumps(['private.example']))

    def write_base(self):
        text = yaml.safe_dump(self.base, allow_unicode=True, sort_keys=False)
        (self.p / 'base.yaml').write_text(text.replace('proxies: []', 'proxies: # LEAVE THIS LINE!\n  []', 1))

    def write_build(self):
        (self.build / 'manifest.json').write_text(json.dumps({'sources': self.sources}))
        (self.build / 'rule-providers.yaml').write_text(yaml.safe_dump({'rule-providers': self.providers}))

    def run_merge(self, success=True, error=None):
        cmd = [sys.executable, str(ROOT / 'scripts/merge_profile.py'), '--base', str(self.p / 'base.yaml'),
               '--build', str(self.build), '--private', str(self.p / 'private.json'), '--output', str(self.p / 'out.yaml')]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return yaml.safe_load((self.p / 'out.yaml').read_text())
        self.assertNotEqual(result.returncode, 0)
        if error:
            self.assertIn(error, result.stderr)
        self.assertFalse((self.p / 'out.yaml').exists())

    def test_preserves_base_and_all_routes(self):
        result = self.run_merge()
        self.assertIn('proxies: # LEAVE THIS LINE!', (self.p / 'out.yaml').read_text())
        for key in ('remnawave', 'dns', 'tun', 'proxies', 'proxy-groups'):
            self.assertEqual(result[key], self.base[key])
        self.assertEqual(result['rule-providers'], {**self.base['rule-providers'], **self.providers})
        rules = result['rules']
        old = [r.replace('torrent-clients,REJECT-DROP', 'torrent-clients,DIRECT') for r in self.base['rules']]
        self.assertEqual([r for r in rules if r in old], old)
        reject = {'ACL4SSR/BanAD.srs', 'ACL4SSR/BanProgramAD.srs', 'ACL4SSR/BanADCompany.srs', 'geo/geosite/category-ads.srs', 'geo/geosite/malware.srs', 'geo/geosite/phishing.srs', 'geo/geosite/cryptominers.srs', 'geo/geoip/malware.srs', 'geo/geoip/phishing.srs'}
        direct = {'geo/geosite/apple.srs', 'geo/geosite/apple@ads.srs', 'geo/geosite/apple-dev.srs', 'geo/geosite/apple-pki.srs', 'geo/geosite/apple-update.srs', 'ACL4SSR/Epic.srs', 'ACL4SSR/Origin.srs', 'ACL4SSR/Sony.srs', 'ACL4SSR/Nintendo.srs', 'ACL4SSR/Steam.srs', 'geo/geosite/microsoft.srs', 'geo/geosite/microsoft-dev.srs', 'geo/geosite/microsoft-pki.srs'}
        auto = {'geo/geosite/google-play.srs', 'ACL4SSR/GoogleFCM.srs', 'geo/geosite/discord.srs', 'ACL4SSR/Discord.srs'}
        for i, source in enumerate(SETS):
            target = 'REJECT' if source in reject else 'DIRECT' if source in direct else '⚡ Авто' if source in auto else '🌍 Прокси'
            rule = f'RULE-SET,synthetic-{i},{target}'
            self.assertEqual(rules.count(rule), 1, source)
            idx = rules.index(rule)
            if source in reject:
                self.assertLess(rules.index(old[1]), idx)
                self.assertLess(idx, rules.index(old[2]))
            else:
                self.assertLess(rules.index(old[4]), idx)
                self.assertLess(idx, rules.index(old[5]))
        for rule in ['DOMAIN,private.example,DIRECT', 'DOMAIN,twoseven.xyz,🌍 Прокси', 'DOMAIN-KEYWORD,twitch,DIRECT',
                     *[f'PROCESS-NAME,{p},{target}' for target, names in [('🌍 Прокси', ['com.google.android.youtube', 'com.whatsapp', 'org.telegram.messenger.web', 'org.telegram.messenger']), ('⚡ Авто', ['com.android.vending', 'Update.exe', 'Discord.exe']), ('DIRECT', ['GF2_Exilium.exe', 'ZFGameBrowser.exe', 'PCLauncher.exe', 'steamwebhelper.exe', 'steam.exe', 'deadlock.exe', 'qbittorrent.exe'])] for p in names]]:
            self.assertLess(rules.index(old[4]), rules.index(rule))
            self.assertLess(rules.index(rule), rules.index(old[5]))
        self.assertEqual(rules[-1], 'MATCH,🌍 Прокси')

    def test_service_groups_obey_first_match(self):
        rules = self.run_merge()['rules']
        ids = {name: f'synthetic-{i}' for i, name in enumerate(SETS)}
        def route(host, process, hits):
            for rule in rules:
                parts = rule.split(',')
                if len(parts) != 3:
                    continue
                kind, value, action = parts
                if ((kind == 'RULE-SET' and value in {ids[h] for h in hits}) or
                    (kind == 'DOMAIN' and value == host) or
                    (kind == 'DOMAIN-KEYWORD' and value in host) or
                    (kind == 'PROCESS-NAME' and value == process)):
                    return action
            return None
        cases = [
            ('private.example', '', ['geo/geosite/youtube.srs'], 'DIRECT'),
            ('private.example', '', ['geo/geoip/blocked@ru.srs'], 'DIRECT'),
            ('private.example', '', ['geo/geosite/malware.srs'], 'REJECT'),
            ('anything.example', 'qbittorrent.exe', ['geo/geosite/youtube.srs'], 'DIRECT'),
            ('anything.example', 'qbittorrent.exe', ['geo/geosite/malware.srs'], 'REJECT'),
            ('twoseven.xyz', '', ['geo/geosite/google-play.srs'], '🌍 Прокси'),
            ('other.example', 'com.google.android.youtube', ['geo/geosite/google-play.srs'], '🌍 Прокси'),
            ('other.example', 'com.android.vending', ['geo/geosite/google.srs'], '⚡ Авто'),
            ('other.example', 'Discord.exe', ['geo/geosite/whatsapp.srs'], '⚡ Авто'),
            ('other.example', 'com.whatsapp', ['geo/geosite/microsoft.srs'], '🌍 Прокси'),
            ('other.example', 'org.telegram.messenger', ['ACL4SSR/Steam.srs'], '🌍 Прокси'),
            ('twitch.example', '', ['geo/geoip/blocked@ru.srs'], 'DIRECT'),
            ('other.example', 'steam.exe', ['geo/geoip/blocked@ru.srs'], 'DIRECT'),
        ]
        for host, process, hits, expected in cases:
            with self.subTest(host=host, process=process, hits=hits):
                self.assertEqual(route(host, process, hits), expected)
        def index(source):
            return next(i for i, rule in enumerate(rules) if rule.startswith('RULE-SET,' + ids[source] + ','))
        self.assertLess(index('geo/geosite/apple.srs'), index('geo/geosite/youtube.srs'))
        self.assertLess(index('geo/geosite/youtube.srs'), index('ACL4SSR/Gemini.srs'))
        self.assertLess(index('ACL4SSR/Gemini.srs'), index('geo/geosite/google-play.srs'))
        self.assertLess(index('geo/geosite/google-play.srs'), index('ACL4SSR/GoogleFCM.srs'))
        self.assertLess(index('ACL4SSR/GoogleFCM.srs'), index('geo/geosite/google.srs'))
        self.assertLess(index('ACL4SSR/Steam.srs'), index('geo/geoip/blocked@ru.srs'))
        self.assertLess(index('geo/geoip/blocked@ru.srs'), index('geo/geosite/microsoft.srs'))
        ordered = '''ACL4SSR/BanAD geo/geosite/category-ads ACL4SSR/BanProgramAD ACL4SSR/BanADCompany
            geo/geosite/malware geo/geosite/phishing geo/geosite/cryptominers geo/geoip/malware geo/geoip/phishing
            geo/geosite/apple geo/geosite/apple@ads geo/geosite/apple-dev geo/geosite/apple-pki geo/geosite/apple-update
            geo/geosite/youtube ACL4SSR/Gemini geo/geosite/google-play ACL4SSR/GoogleFCM geo/geosite/google
            geo/geoip/google geo/geosite/tiktok geo/geosite/instagram geo/geoip/netflix geo/geosite/netflix
            geo/geosite/discord ACL4SSR/Discord geo/geosite/whatsapp ACL4SSR/Whatsapp geo/geoip/telegram
            geo/geosite/telegram ACL4SSR/Claude geo/geoip/openai geo/geosite/openai geo/geoip/github
            geo/geosite/github ACL4SSR/Epic ACL4SSR/Origin ACL4SSR/Sony ACL4SSR/Nintendo ACL4SSR/Steam
            geo/geoip/blocked@ru geo/geoip/blocked-community@ru geo/geosite/blocked@ru
            geo/geosite/microsoft geo/geosite/microsoft-dev geo/geosite/microsoft-pki'''.split()
        positions = [index(name + '.srs') for name in ordered]
        self.assertEqual(len(positions), 46)
        self.assertEqual(positions, sorted(positions))

    def test_missing_ram_parent_is_created(self):
        parent = self.p / 'not-yet-created'
        nested = ProfileTests('test_preserves_base_and_all_routes')
        with mock.patch.dict(globals(), {'TMP': str(parent)}):
            try:
                nested.setUp()
                self.assertTrue(parent.is_dir())
            finally:
                nested.doCleanups()

    def test_conflicts_and_bad_inputs_leave_output_untouched(self):
        cases = ('provider', 'anchor', 'anchor-order', 'duplicate-anchor', 'group', 'duplicate-group', 'private', 'mapping', 'source', 'yaml-alias', 'marker')
        for case in cases:
            with self.subTest(case=case):
                oldbase = yaml.safe_load(yaml.safe_dump(self.base, allow_unicode=True))
                oldsources = json.loads(json.dumps(self.sources))
                if case == 'provider': self.base['rule-providers']['synthetic-0'] = {}
                if case == 'anchor': self.base['rules'].remove('RULE-SET,ads,REJECT-DROP')
                if case == 'anchor-order': self.base['rules'][2], self.base['rules'][4] = self.base['rules'][4], self.base['rules'][2]
                if case == 'duplicate-anchor': self.base['rules'].insert(1, 'RULE-SET,ads,REJECT-DROP')
                if case == 'group': self.base['proxy-groups'].pop()
                if case == 'duplicate-group': self.base['proxy-groups'].append(copy.deepcopy(self.base['proxy-groups'][0]))
                if case == 'private': (self.p / 'private.json').write_text('["*.example.com"]')
                if case == 'mapping': self.sources[0]['providers'] = self.sources[1]['providers']
                if case == 'source': self.sources[0]['source'] = self.sources[1]['source']
                self.write_base(); self.write_build()
                if case == 'marker':
                    path = self.p / 'base.yaml'
                    path.write_text(path.read_text().replace(' # LEAVE THIS LINE!', ''))
                if case == 'yaml-alias':
                    with (self.p / 'base.yaml').open('a') as f: f.write('\nextra: &test foo\nother: *test\n')
                errors = {'provider': 'missing, extra, or conflicting providers', 'anchor': 'missing or duplicate rule anchor',
                          'anchor-order': 'unexpected anchor order', 'duplicate-anchor': 'missing or duplicate rule anchor',
                          'group': 'missing or duplicate proxy groups', 'duplicate-group': 'missing or duplicate proxy groups',
                          'private': 'invalid private exact-domain input', 'mapping': 'invalid provider mapping',
                          'source': 'invalid source mapping', 'yaml-alias': 'YAML anchors and aliases',
                          'marker': 'missing Remnawave proxies marker'}
                self.run_merge(False, errors[case])
                self.base, self.sources = oldbase, oldsources
                (self.p / 'private.json').write_text('["private.example"]')

    def test_output_rejects_symlink_and_is_private(self):
        target = self.p / 'target'
        target.write_text('do not overwrite')
        (self.p / 'out.yaml').symlink_to(target)
        cmd = [sys.executable, str(ROOT / 'scripts/merge_profile.py'), '--base', str(self.p / 'base.yaml'),
               '--build', str(self.build), '--private', str(self.p / 'private.json'), '--output', str(self.p / 'out.yaml')]
        self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
        self.assertEqual(target.read_text(), 'do not overwrite')
        (self.p / 'out.yaml').unlink()
        self.run_merge()
        self.assertEqual(os.stat(self.p / 'out.yaml').st_mode & 0o777, 0o600)

    def test_existing_output_is_never_replaced(self):
        path = self.p / 'out.yaml'
        path.write_bytes(b'previous output')
        path.chmod(0o600)
        before = path.read_bytes()
        cmd = [sys.executable, str(ROOT / 'scripts/merge_profile.py'), '--base', str(self.p / 'base.yaml'),
               '--build', str(self.build), '--private', str(self.p / 'private.json'), '--output', str(path)]
        self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_hardlink_and_directory_outputs_are_never_replaced(self):
        path = self.p / 'out.yaml'
        target = self.p / 'target'
        target.write_bytes(b'keep')
        os.link(target, path)
        cmd = [sys.executable, str(ROOT / 'scripts/merge_profile.py'), '--base', str(self.p / 'base.yaml'),
               '--build', str(self.build), '--private', str(self.p / 'private.json'), '--output', str(path)]
        self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
        self.assertEqual(target.read_bytes(), b'keep')
        path.unlink()
        path.mkdir()
        self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
        self.assertTrue(path.is_dir())

    def test_write_failure_removes_only_new_incomplete_file(self):
        path = self.p / 'out.yaml'
        sentinel = self.p / 'sentinel'
        sentinel.write_bytes(b'keep')
        def limit_file():
            resource.setrlimit(resource.RLIMIT_FSIZE, (1, 1))
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        cmd = [sys.executable, str(ROOT / 'scripts/merge_profile.py'), '--base', str(self.p / 'base.yaml'),
               '--build', str(self.build), '--private', str(self.p / 'private.json'), '--output', str(path)]
        self.assertNotEqual(subprocess.run(cmd, capture_output=True, preexec_fn=limit_file).returncode, 0)
        self.assertFalse(path.exists())
        self.assertEqual(sentinel.read_bytes(), b'keep')

    def test_close_failure_removes_new_file(self):
        from scripts import merge_profile
        path = self.p / 'out.yaml'
        argv = ['merge_profile', '--base', str(self.p / 'base.yaml'), '--build', str(self.build),
                '--private', str(self.p / 'private.json'), '--output', str(path)]
        close = os.close
        def fail_close(fd):
            close(fd)
            raise OSError('simulated close failure')
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(merge_profile.os, 'close', fail_close):
            with self.assertRaises(OSError):
                merge_profile.main()
        self.assertFalse(path.exists())

    def test_write_failure_keeps_replacement_inode(self):
        from scripts import merge_profile
        path = self.p / 'out.yaml'
        original = self.p / 'created'
        argv = ['merge_profile', '--base', str(self.p / 'base.yaml'), '--build', str(self.build),
                '--private', str(self.p / 'private.json'), '--output', str(path)]
        def fail_after_replace(fd, data):
            path.rename(original)
            path.write_bytes(b'replacement')
            raise OSError('simulated write failure')
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(merge_profile.os, 'write', fail_after_replace):
            with self.assertRaises(OSError):
                merge_profile.main()
        self.assertEqual(path.read_bytes(), b'replacement')
        self.assertTrue(original.exists())


if __name__ == '__main__': unittest.main()
