# Mihomo rules library

Individual rule-provider sets for Mihomo, built from a pinned snapshot of [Karing ruleset](https://github.com/KaringX/karing-ruleset). The catalog and provenance of the sets are described in `manifest.json`; ready-to-use definitions are in `rule-providers.yaml` on the `rules` branch.

## Sources

The primary input is SRS from [KaringX/karing-ruleset, `sing` branch](https://github.com/KaringX/karing-ruleset/tree/sing); the pinned commit is recorded in `manifest.json`. Karing's build process is described in its [workflow](https://github.com/KaringX/karing-ruleset/blob/workflow/.github/workflows/run.yml). It combines:

- [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master) (`master`): Clash `.list` files are converted to ACL.
- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat/tree/sing) (`sing`) and [hiddify/hiddify-geo](https://github.com/hiddify/hiddify-geo/tree/rule-set) (`rule-set`).
- [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules/tree/rule-set) (`rule-set`): missing sets, with `ir` overwritten.
- [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat/tree/release) (`release`): `blocked@ru` and other sets.
- [savely-krasovsky/antizapret-sing-box](https://github.com/savely-krasovsky/antizapret-sing-box): antizapret.
- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters): additions to `BanAD`.
- [d3ward/toolz](https://github.com/d3ward/toolz): `adblock_data.json` for `BanADCompany`.
- [AdGuard HostlistsRegistry](https://adguardteam.github.io/HostlistsRegistry/assets/filters.json): AdGuard filter catalog.

Prebuilt Mihomo MRS files from [MetaCubeX/meta-rules-dat, `meta` branch](https://github.com/MetaCubeX/meta-rules-dat/tree/meta) and [runetfreedom/russia-blocked-geoip](https://github.com/runetfreedom/russia-blocked-geoip/tree/release) (`release`) are used only when their contents are proven equivalent to the converted Karing input. The build tools are [sing-box](https://github.com/SagerNet/sing-box) and [mihomo](https://github.com/MetaCubeX/mihomo); their versions and hashes are listed in [config/tools.json](config/tools.json).

## Quick start

The links point to this repository; if you publish your own copy, replace the owner and repository name. Raw links work only if the repository is public and the `rules` branch has been published. Replace `PROXY` with the name of an existing proxy group in your profile; `DIRECT` and `REJECT` are built-in policies. Merge these sections into the existing ones in your profile rather than creating a second `rules` or `rule-providers` section.

The ready-to-use example below blocks ads and dangerous sites, routes local domain names (`geosite/private`) and private IP ranges (`geoip/private`) directly, routes services and resources blocked in Russia through a proxy, routes Russian resources directly, and ends with a catch-all rule. Order matters: the first matching rule applies. If ad blocking interferes with a site, remove the corresponding rule.

```yaml
rule-providers:
  mihomo/geosite/category-ads-all:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/category-ads-all.yaml
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/category-ads-all.yaml
    interval: 86400
  mihomo/acl/BanAD:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/acl/BanAD.yaml
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/acl/BanAD.yaml
    interval: 86400
  mihomo/geosite/malware:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/malware.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/malware.mrs
    interval: 86400
  mihomo/geosite/phishing:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/phishing.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/phishing.mrs
    interval: 86400
  mihomo/geosite/cryptominers:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/cryptominers.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/cryptominers.mrs
    interval: 86400
  mihomo/geosite/private:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/private.yaml
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/private.yaml
    interval: 86400
  mihomo/geoip/private:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./mihomo/geoip/private.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geoip/private.mrs
    interval: 86400
  mihomo/geosite/youtube:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/youtube.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/youtube.mrs
    interval: 86400
  mihomo/geosite/telegram:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/telegram.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/telegram.mrs
    interval: 86400
  mihomo/geoip/telegram:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./mihomo/geoip/telegram.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geoip/telegram.mrs
    interval: 86400
  mihomo/geosite/discord:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/discord.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/discord.mrs
    interval: 86400
  mihomo/geosite/google:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/google.yaml
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/google.yaml
    interval: 86400
  mihomo/geosite/openai:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/openai.yaml
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/openai.yaml
    interval: 86400
  mihomo/geosite/anthropic:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/anthropic.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/anthropic.mrs
    interval: 86400
  mihomo/geosite/google-gemini:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/google-gemini.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/google-gemini.mrs
    interval: 86400
  mihomo/geosite/steam:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/steam.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/steam.mrs
    interval: 86400
  mihomo/geosite/epicgames:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/epicgames.yaml
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/epicgames.yaml
    interval: 86400
  mihomo/geosite/blocked@ru:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/blocked@ru.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/blocked%40ru.mrs
    interval: 86400
  mihomo/geoip/blocked@ru:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./mihomo/geoip/blocked@ru.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geoip/blocked%40ru.mrs
    interval: 86400
  mihomo/geosite/category-ru:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/category-ru.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geosite/category-ru.mrs
    interval: 86400
  mihomo/geoip/ru:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./mihomo/geoip/ru.mrs
    url: https://raw.githubusercontent.com/MrYaYaFonDork/mihomo-rules-routing/rules/mihomo/geoip/ru.mrs
    interval: 86400
rules:
- RULE-SET,mihomo/geosite/category-ads-all,REJECT
- RULE-SET,mihomo/acl/BanAD,REJECT
- RULE-SET,mihomo/geosite/malware,REJECT
- RULE-SET,mihomo/geosite/phishing,REJECT
- RULE-SET,mihomo/geosite/cryptominers,REJECT
- RULE-SET,mihomo/geosite/private,DIRECT
- RULE-SET,mihomo/geoip/private,DIRECT,no-resolve
- RULE-SET,mihomo/geosite/youtube,PROXY
- RULE-SET,mihomo/geosite/telegram,PROXY
- RULE-SET,mihomo/geoip/telegram,PROXY,no-resolve
- RULE-SET,mihomo/geosite/discord,PROXY
- RULE-SET,mihomo/geosite/google,PROXY
- RULE-SET,mihomo/geosite/openai,PROXY
- RULE-SET,mihomo/geosite/anthropic,PROXY
- RULE-SET,mihomo/geosite/google-gemini,PROXY
- RULE-SET,mihomo/geosite/steam,PROXY
- RULE-SET,mihomo/geosite/epicgames,PROXY
- RULE-SET,mihomo/geosite/blocked@ru,PROXY
- RULE-SET,mihomo/geoip/blocked@ru,PROXY,no-resolve
- RULE-SET,mihomo/geosite/category-ru,DIRECT
- RULE-SET,mihomo/geoip/ru,DIRECT,no-resolve
- MATCH,DIRECT
```

For details on setup, verification, and troubleshooting, see [GUIDE.md](GUIDE.md) (in Russian).

## Legal notice

This project is non-commercial and was created exclusively for personal use. It is not affiliated with, endorsed by, or supported by the authors of the upstream rule sets.

The project author claims no rights, including exclusive rights or copyright, in the third-party rule sets, lists of domain names and IP addresses, or other third-party data distributed on the `rules` branch. All rights to that data belong to the respective rights holders listed in the "Sources" section and are governed by the terms of their licenses. Publication in this repository does not grant any rights or licenses to that data.

The materials are provided "as is", without any warranties, express or implied, including warranties of completeness, accuracy, fitness for a particular purpose, and non-infringement of third-party rights. The author is not liable for any direct or indirect damages arising from the use of, or inability to use, the materials. Users are responsible for complying with the source licenses and applicable law.

If you are a rights holder and believe that materials have been published in violation of your rights, open an issue in this repository: the relevant data will be removed.

## For developers

A full build requires Python, `unshare`, `ip`, and the pinned tools listed in `config/tools.json`; run tests with `python -m unittest discover -s tests`. See `scripts/build.py --help` and `scripts/integration_check.py --help`. Mihomo validation runs in a separate network namespace.

The workflow rebuilds the data daily and on manual dispatch. Artifact upload and publication are allowed only when `LICENSING_PROVENANCE_APPROVED=true`; the variable itself does not confirm upstream rights. The `rules` branch is an orphan snapshot; rolling back requires rebuilding and verifying the desired revisions.
