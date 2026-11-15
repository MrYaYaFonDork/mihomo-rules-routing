# Karing → Mihomo: наборы правил

Локальная сборка 46 выбранных SRS Karing в rule-provider Mihomo (MRS или
classical YAML) с публикацией готовых ссылок. Список источников —
`config/sets.json`; текущий снимок дал 35 MRS и 11 classical YAML. Репозиторий
содержит только пересобранные списки, ссылки на них, конвертер, проверки, CI и
документацию по подключению; профили и шаблоны клиентов здесь не хранятся. Это
не универсальный переводчик sing-box: неизвестные или неподдержанные условия
останавливают сборку.

`output/` — локальный, исключённый из Git результат. Публичные raw URL пока не
опубликованы и будут недоступны до открытия репозитория и отдельной публикации.
Не помещайте личные профили, домены, подписки или токены в репозиторий.

## Локально: Linux amd64

Нужны Python 3, `unshare` и `ip`; версии и SHA-256 официальных sing-box и
Mihomo закреплены в `config/tools.json`. Все временные файлы и venv ниже — в RAM
при условии, что `/tmp` смонтирован как tmpfs. Если это не так, используйте
другой tmpfs и учтите фиксированный путь в тестах.

```sh
mkdir -p /tmp/opencode/mihomo-rules-routing/task1
export TMPDIR=/tmp/opencode/mihomo-rules-routing
python3 -m venv "$TMPDIR/venv"
"$TMPDIR/venv/bin/pip" install --no-cache-dir -r requirements.txt
"$TMPDIR/venv/bin/python" -m unittest discover -s tests -v
"$TMPDIR/venv/bin/python" scripts/fetch_tools.py --destination "$TMPDIR/tools"
```

Выберите проверенный 40-символьный commit ветки `sing` Karing и установите его
в переменную `COMMIT`. Укажите реальный будущий публичный base URL, например
`https://example.test/rules`, вместо placeholder; он записывается в providers.
Для сборки из одного commit без локальных источников:

```sh
COMMIT=0123456789abcdef0123456789abcdef01234567
"$TMPDIR/venv/bin/python" scripts/build.py --commit "$COMMIT" \
  --base-url https://example.test/rules --output "$TMPDIR/product" \
  --work-dir "$TMPDIR/work" --sing-box "$TMPDIR/tools/sing-box" \
  --mihomo "$TMPDIR/tools/mihomo"
"$TMPDIR/venv/bin/python" scripts/integration_check.py --output "$TMPDIR/product" \
  --work-dir "$TMPDIR/work" --mihomo "$TMPDIR/tools/mihomo"
```

Commit выше — только пример, замените его существующим. Сборка без `--source-dir`
скачивает все файлы по HTTPS из указанного commit, отмечая origin как
`authenticated_download`; это не проверка криптографической подписи commit.
С `--source-dir` используется локальный снимок, origin будет `local/unverified`:
само значение `--commit` не доказывает происхождение файлов. При ошибке сборки
предыдущий output сохраняется. Offline integration требует работающего отдельного
network namespace; при отказе системы проверка не считается пройденной.
Неотмеченный CI-отпечатком локальный authenticated output можно дополнительно
проверить командой `"$TMPDIR/venv/bin/python" scripts/ci.py validate --unstamped --output "$TMPDIR/product"`;
проверка публикации отдельно требует fingerprint и ожидаемый upstream commit.

## Как подключить GeoSite/GeoIP/ACL в Mihomo

Сборка выдаёт четыре вида файлов: `rules/*.mrs` (бинарные domain/ipcidr),
`rules/*.yaml` (classical, если в наборе есть keyword/regex или смешанные
условия), `rule-providers.yaml` (готовый блок `rule-providers:` для всех 46
наборов) и `manifest.json` (соответствие исходного SRS Karing → ID provider,
behavior, format, число правил, SHA-256).

Шаг 1. Найдите ID нужного набора в `manifest.json` (поле `providers`).
Не угадывайте ID: он получается из пути источника, например
`geo/geosite/youtube.srs` → `geo-geosite-youtube-srs`,
`geo/geoip/blocked@ru.srs` → `geo-geoip-blocked-ru-srs`,
`ACL4SSR/Claude.srs` → `acl4ssr-claude-srs`.

Шаг 2. Скопируйте определение из `rule-providers.yaml` в раздел
`rule-providers:` своего конфига без изменений `behavior` и `format`.
MRS бывает только `domain` или `ipcidr`; classical — только `format: yaml`.
`<owner>/<repo>` — замените на свой репозиторий, где опубликована ветка `rules`.

```yaml
rule-providers:
  geo-geosite-youtube-srs:          # GeoSite → domain + MRS
    type: http
    behavior: domain
    format: mrs
    path: ./rules/geo-geosite-youtube-srs.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/rules/geo-geosite-youtube-srs.mrs
    interval: 86400
  geo-geoip-telegram-srs:           # GeoIP → ipcidr + MRS
    type: http
    behavior: ipcidr
    format: mrs
    path: ./rules/geo-geoip-telegram-srs.mrs
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/rules/geo-geoip-telegram-srs.mrs
    interval: 86400
  geo-geosite-google-srs:           # набор с regex → classical YAML
    type: http
    behavior: classical
    format: yaml
    path: ./rules/geo-geosite-google-srs.yaml
    url: https://raw.githubusercontent.com/<owner>/<repo>/rules/rules/geo-geosite-google-srs.yaml
    interval: 86400
```

При необходимости в provider можно добавить поле `proxy: <имя группы>`: тогда
набор скачивается/обновляется через эту группу или прокси (поле описано в
[документации Mihomo](https://wiki.metacubex.one/en/config/rule-providers/)).

Шаг 3. Сошлитесь на provider в `rules:` через `RULE-SET,<ID>,<политика>`.
Политика — существующая группа вашего конфига (в примерах `PROXY`) или `DIRECT`/`REJECT`.
Mihomo применяет первое совпавшее правило, поэтому блокировки ставьте выше
разрешающих, точные исключения — выше широких наборов, `MATCH` — последним:

```yaml
rules:
  - RULE-SET,acl4ssr-banad-srs,REJECT
  - RULE-SET,geo-geosite-youtube-srs,PROXY
  - RULE-SET,geo-geoip-telegram-srs,PROXY
  - RULE-SET,geo-geosite-google-srs,PROXY
  - MATCH,PROXY
```

Для `ipcidr` можно добавить `,no-resolve` (`RULE-SET,geo-geoip-telegram-srs,PROXY,no-resolve`):
тогда правило не вызывает DNS-резолв домена, но проверяет уже известный IP.
Не добавляйте его везде механически — иначе запросы по домену могут пройти мимо
IP-набора.

Особенности:

- URL работают только после публикации ветки `rules` в **открытом**
  репозитории. Из приватного репозитория клиент raw-файлы не скачает.
- Для локальной проверки без сети укажите `type: file` и `path` к файлу из `output/rules/`.
- Это **не** встроенные `GEOSITE,…`/`GEOIP,…` Mihomo: те читают `geosite.dat`/
  `geoip.dat` (`geox-url`) из других баз. `GEOSITE,youtube` и
  `RULE-SET,geo-geosite-youtube-srs` могут различаться по содержимому.
- После изменения конфига проверьте `mihomo -t -d <каталог> -f config.yaml` и
  убедитесь, что у каждого provider ненулевой `ruleCount` (`GET /providers/rules`
  контроллера). Ошибочные classical-строки Mihomo пропускает с предупреждением.

### Добавить новый набор Karing в сборку

Сейчас список закреплён ровно на 46 источниках, и это число проверяется в
скриптах. Чтобы добавить, например, `geo/geosite/spotify.srs`, нужно:

1. Проверить, что файл есть в ветке `sing` KaringX/karing-ruleset на
   выбранном commit, и проверить его лицензию/происхождение (`THIRD_PARTY.md`).
2. Добавить путь в `config/sets.json`.
3. Заменить число 46 в `scripts/ci.py` и `scripts/integration_check.py`.
4. Пересобрать, выполнить тесты и `integration_check.py`. Неизвестные
   поля sing-box остановят сборку — это ожидаемо, не обходите это.

Готовые чужие наборы Mihomo (MRS/YAML с другим URL) можно подключить напрямую
шагами 2–3, не меняя сборку.

## Обновления и права

Workflow рассчитан на ежедневный и ручной запуск; actions закреплены SHA,
инструменты — версиями и хешами. Сборка read-only, право записи выделено
отдельной публикации. При неизменном fingerprint лишний commit не создаётся.
По умолчанию license/provenance gate закрыт **и для upload-artifact, и для push**.
Переменная `LICENSING_PROVENANCE_APPROVED` не устанавливается проектом; её
возможное включение требует отдельного решения о правах. Личное некоммерческое
использование само по себе не разрешает публичную перепубликацию объединённых
наборов; подробности — `THIRD_PARTY.md`. Build в Actions уже проходил успешно; upload и публикация пропускаются, пока
gate закрыт.

Providers могут обновляться независимо; чтение нескольких стабильных URL не
транзакционно. Локально можно вернуть проверенный сохранённый снимок; удалённый
откат допустим только после отдельного разрешения обычным новым commit известного
снимка, без force push и переписывания истории.

## Проверка на клиенте

Импорт конфигурации не означает работающую маршрутизацию. После подключения
наборов выполните `mihomo -t`, убедитесь, что все providers загрузились с
ненулевым `ruleCount`, и проверьте нужные домены/IP на своём клиенте. Правила
по приложениям и работа TUN/DNS зависят от клиента и платформы.

**About:** Проверенная локальная сборка выбранных правил Karing для Mihomo с
закрытой по умолчанию публикацией.
