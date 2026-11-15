# Библиотека правил Karing для Mihomo

Библиотека содержит отдельные rule-provider-файлы Mihomo, построенные из одного
закреплённого снимка SRS проекта [Karing](https://github.com/KaringX/karing-ruleset).
Пути и регистр имён сохраняются: например, `geo/geosite/youtube.srs` становится
`mihomo/geosite/youtube.mrs`. GeoIP располагается в `mihomo/geoip/`, ACL4SSR —
в `mihomo/acl/`, остальные каталоги сохраняют свои пространства имён.

Чистые domain и ipcidr наборы выпускаются как MRS; смешанные и classical
правила — как YAML. `rule-providers.yaml` содержит готовые определения,
`manifest.json` — источники, поведение, хеши, число правил и исключения.
Неподдерживаемые источники исключаются только по точным записям в
`config/exclusions.json`; новый неподдерживаемый источник или изменившийся
закреплённый blob останавливает сборку до пересмотра политики. Прежнее
обследование дало 4942 provider и 65 исключений; это не подтверждение текущей
полной сборки, фактические значения смотрите в её manifest.

Для MRS builder может использовать `native_mrs` только после проверки
эквивалентности с преобразованным SRS; иначе применяется `converted_srs` с
причиной fallback. Native revisions и происхождение фиксируются в manifest.

## Использование

После публикации ветки `rules` в доступном репозитории скопируйте определение
нужного provider из `rule-providers.yaml`. Например, замените `OWNER/REPO` на
путь своего репозитория:

```yaml
rule-providers:
  mihomo/geosite/youtube:
    type: http
    behavior: domain
    format: mrs
    path: ./mihomo/geosite/youtube.mrs
    url: https://raw.githubusercontent.com/OWNER/REPO/rules/mihomo/geosite/youtube.mrs
    interval: 86400
```

Чтобы применить этот provider, добавьте правило:

```yaml
rules:
  - RULE-SET,mihomo/geosite/youtube,PROXY
```

Замените `PROXY` на нужную политику или группу своего конфига.

Для символов в имени URL кодируется: `@` → `%40`, `!` → `%21`, `+` → `%2B`;
имя provider и локальный путь сохраняют исходные символы. Проверьте формат и
behavior конкретного файла в manifest, а после подключения — загрузку provider
и его ненулевой `ruleCount` в Mihomo.

## Сборка и проверка

Для Linux нужны Python, `unshare`, `ip` и закреплённые инструменты из
`config/tools.json`. Создайте RAM-каталог и укажите существующие SHA снимков:

```sh
export TMPDIR=/tmp/opencode/mihomo-rules-routing
mkdir -p "$TMPDIR"
python3 -m venv "$TMPDIR/venv"
"$TMPDIR/venv/bin/pip" install -r requirements.txt
"$TMPDIR/venv/bin/python" -m unittest discover -s tests
"$TMPDIR/venv/bin/python" scripts/fetch_tools.py --destination "$TMPDIR/tools"
```

Создайте `$TMPDIR/native-snapshots.json` с настоящими 40-символьными SHA:

```json
{"MetaCubeX/meta-rules-dat":"META_COMMIT_SHA","runetfreedom/russia-blocked-geoip":"RF_COMMIT_SHA"}
```

Замените `KARING_COMMIT_SHA` и URL на актуальные значения:

```sh
"$TMPDIR/venv/bin/python" scripts/build.py --full \
  --commit KARING_COMMIT_SHA --native-snapshots "$TMPDIR/native-snapshots.json" \
  --base-url https://raw.githubusercontent.com/OWNER/REPO/rules \
  --output "$TMPDIR/product" --work-dir "$TMPDIR/work" \
  --sing-box "$TMPDIR/tools/sing-box" --mihomo "$TMPDIR/tools/mihomo"
"$TMPDIR/venv/bin/python" scripts/integration_check.py --output "$TMPDIR/product" \
  --work-dir "$TMPDIR/work" --mihomo "$TMPDIR/tools/mihomo"
```

`--output` для полной сборки должен быть новым путём. Проверка запускает Mihomo
в отдельном network namespace и проверяет все providers порциями; при
недоступности изоляции она завершается ошибкой.

## Обновления и права

Workflow запускается ежедневно и вручную. Загрузка артефакта и публикация
разрешены только при `LICENSING_PROVENANCE_APPROVED=true`; настройка переменной
сама по себе не подтверждает upstream-права. Ветка `rules` содержит один
orphan-снимок: для возврата к прежним данным требуется пересобрать и проверить
известные revisions. Проверьте происхождение и права перед распространением;
подробности — в [THIRD_PARTY.md](THIRD_PARTY.md).
