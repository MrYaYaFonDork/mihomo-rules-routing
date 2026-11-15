# Karing → Mihomo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: subagent-driven-development.

**Goal:** Дополнить личный профиль Remnawave 46 наборами Karing без потери политики.
**Architecture:** Строгая локальная сборка SRS→Mihomo; отдельные публичные артефакты
и локальный личный профиль; публикация только после разрешения.
**Tech Stack:** Python 3, unittest, официальный sing-box и Mihomo, GitHub Actions.
**Spec:** `specs/rules-routing/spec.md`, `design.md` в этом change.

## Global Constraints

- Никаких commit/push/публикации/изменений панели без отдельного разрешения.
- Один writer; остальные read-only; подагентам запрещено дальнейшее делегирование.
- Оригинальный профиль, SSH-ключи и host trust не изменять и не читать private key.
- Личные домены/узлы/подписки не включать в публичный проект.
- Только /tmp/opencode/mihomo-rules-routing для временных файлов.
- Неизвестные условия останавливают сборку, никаких скрытых пропусков.
- Матрица клиентов: FlClashX Windows/Android/Linux, Clash Mi iOS.
- Лицензии и отсутствие runtime-проверок обозначать честно.

## Review Focus

1. Семантика ведущей точки domain_suffix и смешанных AND/OR/invert — Task 1.
2. Ошибка сети/SRS в середине 46 наборов не повреждает прошлый вывод — Task 1.
3. Реальные данные могут содержать неподдержанные условия — Task 1 integration.
4. Широкие DIRECT могут затенять новую политику — Task 2 порядок/сохранение.
5. CI secrets/permissions и открытый license gate — Task 2 workflow review.

### Task 1: Конвертер и проверенная локальная сборка

**Files:** создать `config/sets.json`, `config/tools.json`, `scripts/build.py`,
`scripts/fetch_tools.py`, `tests/test_build.py`, при необходимости небольшие fixtures.
**Interfaces:** CLI `python3 scripts/build.py --help`; точные остальные аргументы
и Python API выбирает исполнитель, фиксирует в отчёте для Task 2.
Вывод: `rules/`, `rule-providers.yaml`, `manifest.json` внутри отдельного output.
В manifest — относительные пути; конвертер не должен знать личные маршруты.

- [x] Написать unit tests: domain/suffix (apex/subdomain/leading dot), keyword,
  process, IPv4/IPv6, logical AND/OR/invert, mixed fields, unknown field,
  некорректные типы/пустой матч, детерминизм, безопасный отказ.
- [x] Выполнить `python3 -m unittest discover -s tests -v`, получить RED.
- [x] Реализовать минимальные поддержанные преобразования и CLI, закрепить
  инструменты и SHA-256 по официальным источникам; скачать их только в RAM.
- [x] Повторить unit tests до GREEN.
- [x] Выполнить реальную конвертацию 46 SRS одного commit и `mihomo -t`
  с синтетическим config и локальными providers; отчёт включает поля/числа.
- [x] Независимый review спецификации и качества; устранить важные замечания.

Проверено 2026-11-15: 22 unit tests PASS; 46 providers, classical counts
совпадают, parser warnings нет. Reviewer закрыл F1–F6 и исправление изоляции,
spec/quality PASS. RED/GREEN описан исполнителем; часть регрессий проверялась
временным возвратом дефектного кода, не все написаны до первого исправления.

### Task 2: Автоматизация, README и отдельный личный шаблон

**Dependencies:** Task 1 прошла review. **Files:** `.github/workflows/build.yml`,
`README.md`, `THIRD_PARTY.md`, `.gitignore`, `scripts/merge_profile.py`,
`tests/test_profile.py`, при необходимости `requirements.txt`.
Локальный вывод: `../snippets/remnawave-mihomo-global-karing.yaml`.
**Interfaces:** потребляет CLI/выходы Task 1. Конкретные имена взять из отчёта
Task 1, не заводить второй конвертер. Секретные личные exact domains передаются
локальному merger отдельно, не в исходниках публичного проекта.

- [x] Написать тесты сохранения providers/groups/DNS/TUN/directives и исходных
  rules с единственной заменой torrent-clients; новых маршрутов, приоритетов,
  финального MATCH и отсутствия private данных в публичных файлах.
- [x] Выполнить unit tests до реализации и зафиксировать RED.
- [x] Реализовать merger и создать отдельный локальный профиль. Личные
  исключения получить от primary; исходник не изменять.
  Task2a принят: 32 unit tests PASS; sanitized `mihomo -t` PASS; независимый
  review после исправления приоритетов и негативных тестов spec/quality PASS.
  Личный DIRECT выше сервисов/GFW по отдельному уточнению пользователя,
  но ниже защитных правил и ads. Локальный профиль обновлён из проверенного
  RAM-результата с проверкой неизменности собственного старого draft; SHA-256
  `016863b5f3202f31ef7a21d64b228c49cf2664d6c7ed1e9bbb1c4cf6e33bdb3c`.
- [x] Создать workflow с pinned actions/tools, отдельными правами build/publish,
  concurrency, одним commit вывода и закрытым по умолчанию license gate.
- [x] Написать русский README и THIRD_PARTY с фактическими источниками,
  командами, использованием, обновлением, откатом, About и ограничениями.
- [x] Проверить unit/integration, `mihomo -t` санитизированного профиля,
   неизменность хеша исходника; независимый review.
   Task2b: 43 unit tests PASS; offline 46-provider integration PASS;
   scoped review закрыл Important замечания о целостности snapshot и redirects.
   Minor о точках в будущих именах источников передан в whole-project review;
   текущие 46 имён не затронуты. Реальные Actions/публикация не запускались.

### Task 3: Итоговая приёмка и передача

**Files:** обновить только этот checklist после реальных проверок.
- [x] Primary повторяет полные tests и integration, сверяет 46 наборов и профиль.
  2026-11-15: 43 unit PASS; offline integration 46 providers PASS; санитизированный
  профиль `mihomo -t` PASS (60 providers); хеш исходника неизменен.
- [x] `OPENSPEC_TELEMETRY=0 openspec validate --all --strict --json`.
  1/1 passed, 0 issues.
- [x] Независимый whole-project review с двумя вердиктами: spec и quality.
  spec PASS, quality PASS, без Critical/Important. После review primary исправил
  две неверные ссылки на релизы клиентов в README (проверены, HTTP 200).
- [x] Сохранить проверенную проектную сводку через Wiki MCP.
  Projects/karing-mihomo-правила-для-remnawave-flclashx-и-clash-mi.md и запись
  в log.md; GET и повторная индексация подтверждены.
- [x] Передать пользователю результаты и запросить разрешение на следующий
  внешний этап: commit/push/Actions и/или проверку панели/устройств.
- [x] После сохранения результатов удалить только временные файлы этой задачи.
  Удалены /tmp/opencode/mihomo-rules-routing (495 MB) и __pycache__.
