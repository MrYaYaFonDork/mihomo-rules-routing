[English](README.md) | Русский

# Библиотека правил Mihomo

Отдельные наборы rule-provider для Mihomo, собранные из закреплённого снимка [Karing ruleset](https://github.com/KaringX/karing-ruleset). Каталог и происхождение наборов описаны в `manifest.json`, готовые определения — в `rule-providers.yaml` ветки `rules`.

## Источники

Основной вход — SRS из [KaringX/karing-ruleset, ветка `sing`](https://github.com/KaringX/karing-ruleset/tree/sing); закреплённый коммит записывается в `manifest.json`. Порядок сборки Karing описан в его [процессе сборки](https://github.com/KaringX/karing-ruleset/blob/workflow/.github/workflows/run.yml). Он объединяет:

- [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master) (`master`): Clash `.list` преобразуются в ACL.
- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat/tree/sing) (`sing`) и [hiddify/hiddify-geo](https://github.com/hiddify/hiddify-geo/tree/rule-set) (`rule-set`).
- [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules/tree/rule-set) (`rule-set`): недостающие наборы, при этом `ir` перезаписывается.
- [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat/tree/release) (`release`): `blocked@ru` и другие наборы.
- [savely-krasovsky/antizapret-sing-box](https://github.com/savely-krasovsky/antizapret-sing-box): antizapret.
- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters): дополнение `BanAD`.
- [d3ward/toolz](https://github.com/d3ward/toolz): `adblock_data.json` для `BanADCompany`.
- [AdGuard HostlistsRegistry](https://adguardteam.github.io/HostlistsRegistry/assets/filters.json): каталог фильтров AdGuard.

Готовые Mihomo MRS из [MetaCubeX/meta-rules-dat, ветка `meta`](https://github.com/MetaCubeX/meta-rules-dat/tree/meta) и [runetfreedom/russia-blocked-geoip](https://github.com/runetfreedom/russia-blocked-geoip/tree/release) (`release`) используются только при доказанном совпадении содержимого с преобразованным входом Karing. Инструменты сборки — [sing-box](https://github.com/SagerNet/sing-box) и [mihomo](https://github.com/MetaCubeX/mihomo); их версии и хеши указаны в [config/tools.json](config/tools.json).

## Быстрый старт

Ссылки ведут в этот репозиторий; если вы публикуете свою копию, замените владельца и имя. Raw-ссылки работают, только если репозиторий публичный и ветка `rules` опубликована. Замените `PROXY` на имя существующей прокси-группы в вашем профиле; `DIRECT` и `REJECT` — встроенные политики. Объедините эти разделы с существующими в профиле, не создавая второй `rules` или `rule-providers`.

Ниже готовый пример: блокировки рекламы и опасных сайтов, локальные доменные имена (`geosite/private`) и частные IP-диапазоны (`geoip/private`) напрямую, сервисы через прокси, заблокированные в РФ ресурсы через прокси, российские ресурсы напрямую и завершающее правило. Порядок важен: срабатывает первое совпадение. Если блокировка рекламы мешает сайту, уберите соответствующее правило.

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

Подробнее о подключении, проверке и устранении ошибок — [GUIDE.md](GUIDE.md).

## Правовая информация

Проект некоммерческий и создан исключительно для личного использования. Он не связан с авторами исходных наборов правил, не одобрен и не поддерживается ими.

Автор проекта не претендует на какие-либо права, в том числе исключительные и авторские, на наборы правил, списки доменов и IP-адресов и другие данные третьих лиц, распространяемые в ветке `rules`. Все права на них принадлежат соответствующим правообладателям, перечисленным в разделе «Источники», и регулируются условиями их лицензий. Публикация в этом репозитории не означает предоставления каких-либо прав или лицензий на эти данные.

Материалы предоставляются «как есть», без каких-либо гарантий, явных или подразумеваемых, включая гарантии полноты, точности, пригодности для определённой цели и отсутствия нарушений прав третьих лиц. Автор не несёт ответственности за любые убытки, прямые или косвенные, возникшие в связи с использованием или невозможностью использования материалов. Пользователь самостоятельно отвечает за соблюдение лицензий источников и применимого законодательства.

Если вы правообладатель и считаете, что материалы размещены с нарушением ваших прав, создайте обращение в этом репозитории: соответствующие данные будут удалены.

## Для разработчиков

Полная сборка требует Python, `unshare`, `ip` и закреплённых инструментов из `config/tools.json`; тесты запускаются командой `python -m unittest discover -s tests`. См. `scripts/build.py --help` и `scripts/integration_check.py --help`. Проверка Mihomo выполняется в отдельном сетевом пространстве имён.

Процесс пересобирает данные ежедневно и при ручном запуске. Загрузка артефакта и публикация разрешены только при `LICENSING_PROVENANCE_APPROVED=true`; сама переменная не подтверждает права на исходные данные. Ветка `rules` — снимок без родительского коммита; для отката требуется заново собрать и проверить нужные ревизии.
