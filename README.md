# Karing → Mihomo для Remnawave

Локальная сборка 46 выбранных SRS Karing в rule-provider Mihomo, затем
добавление правил в отдельный полный YAML-шаблон Remnawave для FlClashX
(Windows, Android, Linux) и Clash Mi (iOS). Список источников — `config/sets.json`;
текущий снимок дал 35 MRS и 11 classical YAML. Это не универсальный переводчик
sing-box: неизвестные или неподдержанные условия останавливают сборку.

`output/` — локальный, исключённый из Git результат. Публичные raw URL пока не
опубликованы и будут недоступны до открытия репозитория и отдельной публикации.
Не помещайте личный профиль, домены, подписку или токены в репозиторий.

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

Подготовьте локально JSON-массив exact-доменов, например `["private.example"]`,
в закрытом файле вне репозитория. Исходный YAML и JSON остаются неизменными.
Укажите существующие пути и **новое**, ещё не занятое имя результата:

```sh
"$TMPDIR/venv/bin/python" scripts/merge_profile.py \
  --base /path/to/original.yaml --build "$TMPDIR/product" \
  --private /path/to/private.json --output /path/to/new-profile.yaml
```

Merger запрещает перезапись, не публикует профиль и сохраняет исходный текст,
кроме согласованных добавлений и замены маршрута torrent-clients.

## Маршрутизация

Новые защитные REJECT и исходный ads стоят выше личных exact DOMAIN → DIRECT;
личные исключения стоят выше сервисных и GFW правил. Правила групп сохраняют
OR-смысл и порядок; Microsoft и torrents — DIRECT, blocked@ru выше широкого
российского DIRECT, в конце `MATCH,🌍 Прокси`. Исходный torrent-clients DIRECT
расположен выше существующих UDP443/ads и может обходить их; новые защитные
REJECT стоят выше torrent. Это не kill switch.

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

```yaml
rule-providers:
  geo-geosite-youtube-srs:          # GeoSite → domain + MRS
    type: http
    behavior: domain
    format: mrs
    path: ./rules/geo-geosite-youtube-srs.mrs
    url: https://raw.githubusercontent.com/MrALDAP/mihomo-rules-routing/rules/rules/geo-geosite-youtube-srs.mrs
    interval: 86400
  geo-geoip-telegram-srs:           # GeoIP → ipcidr + MRS
    type: http
    behavior: ipcidr
    format: mrs
    path: ./rules/geo-geoip-telegram-srs.mrs
    url: https://raw.githubusercontent.com/MrALDAP/mihomo-rules-routing/rules/rules/geo-geoip-telegram-srs.mrs
    interval: 86400
  geo-geosite-google-srs:           # набор с regex → classical YAML
    type: http
    behavior: classical
    format: yaml
    path: ./rules/geo-geosite-google-srs.yaml
    url: https://raw.githubusercontent.com/MrALDAP/mihomo-rules-routing/rules/rules/geo-geosite-google-srs.yaml
    interval: 86400
```

Шаг 3. Сошлитесь на provider в `rules:` через `RULE-SET,<ID>,<политика>`.
Политика — существующая группа (`🌍 Прокси`, `⚡ Авто`) или `DIRECT`/`REJECT`.
Mihomo применяет первое совпавшее правило, поэтому блокировки ставьте выше
разрешающих, точные исключения — выше широких наборов, `MATCH` — последним:

```yaml
rules:
  - RULE-SET,acl4ssr-banad-srs,REJECT
  - RULE-SET,geo-geosite-youtube-srs,🌍 Прокси
  - RULE-SET,geo-geoip-telegram-srs,🌍 Прокси
  - RULE-SET,geo-geosite-google-srs,🌍 Прокси
  - MATCH,🌍 Прокси
```

Для `ipcidr` можно добавить `,no-resolve` (`RULE-SET,geo-geoip-telegram-srs,🌍 Прокси,no-resolve`):
тогда правило не вызывает DNS-резолв домена, но проверяет уже известный IP.
Не добавляйте его везде механически — иначе запросы по домену могут пройти мимо
IP-набора.

Особенности:

- URL работают только после публикации ветки `rules` в **открытом**
  репозитории. Из приватного репозитория клиент raw-файлы не скачает.
- Для локальной проверки без сети укажите `type: file` и `path` к файлу из `output/rules/`.
- В шаблоне Remnawave сохраните строку `proxies: # LEAVE THIS LINE!`. Готовое
  слияние со всеми 46 наборами делает `scripts/merge_profile.py` (см. выше).
- Это **не** встроенные `GEOSITE,…`/`GEOIP,…` Mihomo: те читают `geosite.dat`/
  `geoip.dat` (`geox-url`) из других баз. `GEOSITE,youtube` и
  `RULE-SET,geo-geosite-youtube-srs` могут различаться по содержимому.
- После изменения конфига проверьте `mihomo -t -d <каталог> -f config.yaml` и
  убедитесь, что у каждого provider ненулевой `ruleCount` (`GET /providers/rules`
  контроллера). Ошибочные classical-строки Mihomo пропускает с предупреждением.

### Добавить новый набор Karing в сборку

Сейчас список закреплён ровно на 46 источниках, и это число проверяется в
нескольких местах. Чтобы добавить, например, `geo/geosite/spotify.srs`, нужно:

1. Проверить, что файл есть в ветке `sing` KaringX/karing-ruleset на
   выбранном commit, и проверить его лицензию/происхождение (`THIRD_PARTY.md`).
2. Добавить путь в `config/sets.json`.
3. Назначить маршрут в `scripts/merge_profile.py`: добавить набор в один из
   списков `REJECT`/`DIRECT`/`AUTOMATIC`/`PROXIED` и в `GROUPS` на нужное место
   (порядок в `GROUPS` определяет порядок правил).
4. Заменить число 46 в `scripts/ci.py`, `scripts/integration_check.py`,
   `scripts/merge_profile.py` и в тестах (`tests/test_profile.py`).
5. Пересобрать, выполнить тесты, `integration_check.py` и merger. Неизвестные
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
наборов; подробности — `THIRD_PARTY.md`. Actions пока не запускались.

Providers могут обновляться независимо; чтение нескольких стабильных URL не
транзакционно. Локально можно вернуть проверенный сохранённый снимок; удалённый
откат допустим только после отдельного разрешения обычным новым commit известного
снимка, без force push и переписывания истории.

## Проверка на устройствах

Исходный шаблон, YAML после обработки панелью и фактически применённая клиентом
конфигурация — разные вещи. Импорт не означает включённый VPN. Android-правила
package требуют доступных метаданных приложения; include/exclude-package относится
к входу трафика, а не к выбору outbound. На iOS работа process-правил не
гарантирована. TUN/DNS overlays и расход памяти требуют проверки на устройстве.
Версия Remnawave пользователя неизвестна: UA и ResponseRules здесь не меняются.

Для ориентира на 2026-11-15: [FlClashX v0.5.6](https://github.com/pluralplay/FlClashX/releases/tag/v0.5.6)
по go.mod использует core 1.19.34; последняя наблюдавшаяся
[Clash Mi v1.0.32.1803](https://github.com/KaringX/clashmi/releases/tag/v1.0.32.1803), версия
core iOS не подтверждена.

Ручной checklist для Windows, Android, Linux и iOS:

1. Проверить фактический ответ подписки и применённую конфигурацию; не отправлять
   никому секреты ответа, ссылки подписки и персональные данные.
2. После холодного старта убедиться в загрузке всех providers.
3. Проверить пересечения personal DIRECT, блокировок и сервисов, приложения,
   DNS и TUN; затем маршруты после обновления и переподключения.

Панель, сеть и устройства в этой работе не проверялись.

**About:** Проверенная локальная сборка выбранных правил Karing для Mihomo и
шаблона Remnawave с закрытой по умолчанию публикацией.
