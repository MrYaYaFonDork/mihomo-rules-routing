# Karing → Mihomo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: subagent-driven-development.

**Goal:** Получить 46 наборов Karing в форматах Mihomo со ссылками, без профилей клиентов.
**Architecture:** Строгая локальная сборка SRS→Mihomo; отдельные публичные артефакты;
публикация только после разрешения.
**Tech Stack:** Python 3, unittest, официальный sing-box и Mihomo, GitHub Actions.
**Spec:** `specs/rules-routing/spec.md`, `design.md` в этом change.

## Global Constraints

- Никаких commit/push/публикации/изменений панели без отдельного разрешения.
- Один writer; остальные read-only; подагентам запрещено дальнейшее делегирование.
- SSH-ключи и host trust не изменять и не читать private key.
- Личные домены/узлы/подписки не включать в публичный проект.
- Только /tmp/opencode/mihomo-rules-routing для временных файлов.
- Неизвестные условия останавливают сборку, никаких скрытых пропусков.
- Лицензии и отсутствие runtime-проверок обозначать честно.

## Review Focus

1. Семантика ведущей точки domain_suffix и смешанных AND/OR/invert — Task 1.
2. Ошибка сети/SRS в середине 46 наборов не повреждает прошлый вывод — Task 1.
3. Реальные данные могут содержать неподдержанные условия — Task 1 integration.
4. CI secrets/permissions и открытый license gate — Task 2 workflow review.

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

### Task 2: Автоматизация и README

**Dependencies:** Task 1 прошла review. **Files:** `.github/workflows/build.yml`,
`README.md`, `THIRD_PARTY.md`, `.gitignore`, `requirements.txt`.
**Interfaces:** потребляет CLI/выходы Task 1. Конкретные имена взять из отчёта
Task 1, не заводить второй конвертер.

- [x] Создать workflow с pinned actions/tools, отдельными правами build/publish,
  concurrency, одним commit вывода и закрытым по умолчанию license gate.
- [x] Написать русский README и THIRD_PARTY с фактическими источниками,
  командами, использованием, обновлением, откатом, About и ограничениями.
- [x] Проверить unit/integration; независимый review.
   Task2b: 43 unit tests PASS; offline 46-provider integration PASS;
   scoped review закрыл Important замечания о целостности snapshot и redirects.
   Minor о точках в будущих именах источников передан в whole-project review;
   текущие 46 имён не затронуты. Реальные Actions/публикация не запускались.

### Task 3: Итоговая приёмка и передача

**Files:** обновить только этот checklist после реальных проверок.
- [x] Primary повторяет полные tests и integration, сверяет 46 наборов.
  2026-11-15: 43 unit PASS; offline integration 46 providers PASS; профиль-проверки
  вынесены в Task 4.
- [x] `OPENSPEC_TELEMETRY=0 openspec validate --all --strict --json`.
  1/1 passed, 0 issues.
- [x] Независимый whole-project review с двумя вердиктами: spec и quality.
  spec PASS, quality PASS, без Critical/Important. После review primary исправил
  ссылки в README.
- [x] Сохранить проверенную проектную сводку через Wiki MCP.
  Проектная заметка и запись в log.md; GET и повторная индексация подтверждены.
- [x] Передать пользователю результаты и запросить разрешение на следующий
  внешний этап: commit/push/Actions и/или проверку панели/устройств.
- [x] После сохранения результатов удалить только временные файлы этой задачи.
  Удалены /tmp/opencode/mihomo-rules-routing (495 MB) и __pycache__.

### Task 4: Исключить профиль Remnawave

**Files:** удалить `scripts/merge_profile.py`, `tests/test_profile.py`; обновить
`README.md`, `THIRD_PARTY.md`, этот change.
- [x] Удалить merger и его тесты; в остальных файлах не осталось ссылок на них.
- [x] README и OpenSpec очищены от профиля Remnawave, личных маршрутов и клиентов.
- [x] Unit tests, `ci.py validate --unstamped`, `openspec validate --all --strict`
  выполнены после удаления: 34 unit tests OK, `ci.py validate --unstamped
  --output output` exit 0, `openspec validate --all --strict` 1/1.

Build в GitHub Actions прошёл после коммита 16553e5 (подтверждено пользователем);
upload/публикация пропущены закрытым gate. Отметка «не запускались» в Task 2
относится к моменту приёмки Task 2.
