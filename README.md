# Библиотека правил Mihomo

Отдельные наборы rule-provider для Mihomo, собранные из закреплённого снимка [Karing ruleset](https://github.com/KaringX/karing-ruleset). Каталог и происхождение наборов описаны в `manifest.json`, готовые определения — в `rule-providers.yaml` ветки `rules`.

## Быстрый старт

Замените `<owner>/<repo>` в каждом URL на владельца и имя своего доступного репозитория с опубликованной веткой `rules`. Замените `PROXY` на имя существующей прокси-группы в вашем профиле; `DIRECT` и `REJECT` — встроенные политики. Объедините эти разделы с существующими в профиле, не создавая второй `rules` или `rule-providers`.

Ниже готовый пример: блокировки рекламы и опасных сайтов, локальные доменные имена (`geosite/private`) и частные IP-диапазоны (`geoip/private`) напрямую, сервисы через прокси, заблокированные в РФ ресурсы через прокси, российские ресурсы напрямую и завершающее правило. Порядок важен: срабатывает первое совпадение. Если блокировка рекламы мешает сайту, уберите соответствующее правило.

```yaml
rule-providers:
  mihomo/geosite/category-ads-all:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/category-ads-all.yaml
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/category-ads-all.yaml
    interval: 86400
  mihomo/acl/BanAD:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/acl/BanAD.yaml
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/acl/BanAD.yaml
    interval: 86400
  mihomo/geosite/malware:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/malware.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/malware.mrs
    interval: 86400
  mihomo/geosite/phishing:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/phishing.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/phishing.mrs
    interval: 86400
  mihomo/geosite/cryptominers:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/cryptominers.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/cryptominers.mrs
    interval: 86400
  mihomo/geosite/private:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/private.yaml
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/private.yaml
    interval: 86400
  mihomo/geoip/private:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./mihomo/geoip/private.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geoip/private.mrs
    interval: 86400
  mihomo/geosite/youtube:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/youtube.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/youtube.mrs
    interval: 86400
  mihomo/geosite/telegram:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/telegram.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/telegram.mrs
    interval: 86400
  mihomo/geoip/telegram:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./mihomo/geoip/telegram.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geoip/telegram.mrs
    interval: 86400
  mihomo/geosite/discord:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/discord.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/discord.mrs
    interval: 86400
  mihomo/geosite/google:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/google.yaml
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/google.yaml
    interval: 86400
  mihomo/geosite/openai:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/openai.yaml
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/openai.yaml
    interval: 86400
  mihomo/geosite/anthropic:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/anthropic.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/anthropic.mrs
    interval: 86400
  mihomo/geosite/google-gemini:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/google-gemini.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/google-gemini.mrs
    interval: 86400
  mihomo/geosite/steam:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/steam.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/steam.mrs
    interval: 86400
  mihomo/geosite/epicgames:
    type: http
    behavior: classical
    format: yaml
    path: ./mihomo/geosite/epicgames.yaml
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/epicgames.yaml
    interval: 86400
  mihomo/geosite/blocked@ru:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/blocked@ru.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/blocked%40ru.mrs
    interval: 86400
  mihomo/geoip/blocked@ru:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./mihomo/geoip/blocked@ru.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geoip/blocked%40ru.mrs
    interval: 86400
  mihomo/geosite/category-ru:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/category-ru.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geosite/category-ru.mrs
    interval: 86400
  mihomo/geoip/ru:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./mihomo/geoip/ru.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/mihomo/geoip/ru.mrs
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

## Для разработчиков

Полная сборка требует Python, `unshare`, `ip` и закреплённых инструментов из `config/tools.json`; тесты запускаются командой `python -m unittest discover -s tests`. См. `scripts/build.py --help` и `scripts/integration_check.py --help`. Проверка Mihomo выполняется в отдельном network namespace.

Workflow пересобирает данные ежедневно и вручную. Артефакт и публикация разрешены только при `LICENSING_PROVENANCE_APPROVED=true`; сама переменная не подтверждает права upstream. Ветка `rules` — orphan-снимок; для отката требуется заново собрать и проверить нужные revisions. Перед распространением проверьте происхождение и права в [THIRD_PARTY.md](THIRD_PARTY.md).
