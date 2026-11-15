# Проектирование

## Цель и ограничения

Нужна воспроизводимая конвертация ровно 46 наборов, а не копирование всех geodata.
Первичный источник — фактические SRS ветки sing KaringX/karing-ruleset в одном
зафиксированном commit. JSON рядом может отсутствовать или отличаться.
Оригинал `../snippets/remnawave-mihomo-global-use.yaml`
не изменять. Новое имя — `remnawave-mihomo-global-karing.yaml` в том же snippets.
Локальный профиль не включать в публичный проект.

## Подходы

1. Взять аналогичные готовые Mihomo-наборы: проще, но они не обязательно совпадают
   с преобразованными и объединёнными Karing. Не выбран.
2. Декомпилировать реальные SRS официальным sing-box, строго преобразовать и
   скомпилировать подходящие наборы официальным Mihomo. Выбран как сохраняющий
   нужный источник.
3. Воспроизвести весь workflow Karing: лишний объём и новые расхождения. Не выбран.

## Контракт сборки

Python стандартная библиотека; unittest. Не добавлять библиотеку YAML ради записи:
JSON является YAML, либо минимальная безопасная сериализация нужного payload.
Для чтения личного YAML допустим уже установленный PyYAML в имеющемся окружении
или явно закреплённая зависимость, если иначе корректно разобрать его нельзя.
Скрипты и API — минимальные, интерфейсы конкретизируются в Task 1 перед Task 2.
Инструменты закреплены версиями и SHA-256 официальных архивов, загрузки HTTPS
с timeout, проверкой HTTP-статуса и ограничением объёма. Всё временное — в
`/tmp/opencode/mihomo-rules-routing/`; не выполнять полученные скрипты upstream.

Сборка сначала пишет новый отдельный staging. Неизвестное поле, неподдержанный
regex/логика, повреждённый SRS или ошибка скачивания останавливают всю сборку.
Нельзя выбрасывать поля, превращать AND в OR, игнорировать invert. Поддержка
встречающихся полей первична; для остальных — понятная ошибка, не универсальный
фреймворк. Точно сохранить семантику domain_suffix (включая ведущую точку),
domain, ip_cidr, logical AND/OR/NOT, process_name и domain_keyword, если встречаются.
MRS только там, где набор представим без потерь как domain или ipcidr. Classical
YAML сохраняет смешанные правила и логические выражения. Не добавлять no-resolve
глобально. Успешная сборка содержит rules/, rule-providers.yaml, manifest.json.
Manifest: upstream SHA, SHA-256 входов/выходов, версии инструментов и количества.
При ошибке старый опубликованный результат не трогается. Повторная сборка
одинаковых входов должна давать одинаковые выходы.

## Наборы и маршруты

Ниже источник `acl` означает ACL4SSR/<name>.srs, `geosite` —
geo/geosite/<name>.srs, `geoip` — geo/geoip/<name>.srs.

| Группа | Наборы | Назначение |
|---|---|---|
| Adblock | acl:BanAD; geosite:category-ads | REJECT |
| AdblockPlus | acl:BanProgramAD,BanADCompany | REJECT |
| malware | geosite:malware,phishing,cryptominers; geoip:malware,phishing | REJECT |
| Apple | geosite:apple,apple@ads,apple-dev,apple-pki,apple-update | DIRECT |
| YouTube | geosite:youtube | 🌍 Прокси |
| Gemini | acl:Gemini | 🌍 Прокси |
| Google Play | geosite:google-play | ⚡ Авто |
| FCM | acl:GoogleFCM | ⚡ Авто |
| Google | geosite:google; geoip:google | 🌍 Прокси |
| TikTok | geosite:tiktok | 🌍 Прокси |
| Instagram | geosite:instagram | 🌍 Прокси |
| Netflix | geoip:netflix; geosite:netflix | 🌍 Прокси |
| Discord | geosite:discord; acl:Discord | ⚡ Авто |
| WhatsApp | geosite:whatsapp; acl:Whatsapp | 🌍 Прокси |
| Telegram | geoip:telegram; geosite:telegram | 🌍 Прокси |
| Claude | acl:Claude | 🌍 Прокси |
| OpenAI | geoip:openai; geosite:openai | 🌍 Прокси |
| GitHub | geoip:github; geosite:github | 🌍 Прокси |
| Game | acl:Epic,Origin,Sony,Nintendo,Steam | DIRECT |
| GFW | geoip:blocked@ru,blocked-community@ru; geosite:blocked@ru | 🌍 Прокси |
| Microsoft | geosite:microsoft,microsoft-dev,microsoft-pki | DIRECT |

Внутри пользовательских групп объединение OR. Сохранить исходные правила и списки,
кроме согласованного torrent-clients: REJECT-DROP → DIRECT. Остальные изменения
только добавляют правила. Глобальный IPv6 REJECT-DROP и UDP443 REJECT-DROP оставить.
Исходные bootstrap/private исключения и их семантику не менять. Новые REJECT
перед добавленными DIRECT/VPN; blocked@ru перед ru-direct/category-ru.
Новые сервисные правила должны быть достижимы до широкого ru-direct.
Личные DIRECT исключения из предыдущей политики хранятся только локально,
не помещаются в openspec, fixtures или README публичного проекта.
Уточнение пользователя после review: личные exact DOMAIN → DIRECT выше всех
добавленных сервисных и GFW-наборов, но ниже новых защитных REJECT и исходного
ads. Размещать их в начале сервисного блока перед ru-direct. Если их IP совпал
с blocked@ru, личный DIRECT побеждает — это согласованное исключение.
Дополнительные DOMAIN/PROCESS-NAME/keyword правила размещать внутри своей
группы из таблицы, сохраняя порядок групп и OR-смысл при первом совпадении.
qbittorrent.exe → DIRECT, как согласованное torrent-исключение, поставить перед
добавленными сервисными наборами, но ниже защитных блокировок и исходного ads.
Последний маршрут строго `MATCH,🌍 Прокси`. Все исходные proxy-groups/DNS/TUN,
директивы Remnawave и `proxies: # LEAVE THIS LINE!` сохранить.

Дополнительные правила: exact DOMAIN twoseven.xyz → 🌍 Прокси; DOMAIN-KEYWORD
twitch → DIRECT. PROCESS-NAME: com.google.android.youtube → 🌍 Прокси;
com.android.vending → ⚡ Авто; Update.exe,Discord.exe → ⚡ Авто;
com.whatsapp,org.telegram.messenger.web,org.telegram.messenger → 🌍 Прокси;
GF2_Exilium.exe,ZFGameBrowser.exe,PCLauncher.exe,steamwebhelper.exe,steam.exe,
deadlock.exe,qbittorrent.exe → DIRECT. Не считать process/package правила
работающими на iOS без фактической проверки.

## Автоматизация и документация

Actions: daily + workflow_dispatch, фиксированные SHA используемых actions,
read-only build job; contents:write только у publish job, без deploy key.
Concurrency сериализует публикации. Ветка вывода `rules`, стабильные raw URLs,
один обычный commit всех прошедших проверку артефактов; без force-push.
Не допускать публикацию при ошибке, неизвестном формате или неготовом license gate.
Неизменившийся upstream и инструменты/скрипты не должны создавать лишних commits.
Клиентское чтение нескольких URL не транзакционно — честно указать это ограничение.

README по-русски: назначение, Karing→Mihomo→Remnawave→клиенты, 46 наборов,
сборка/тесты/загрузка/обновление/откат, ограничения платформ и порядок правил,
проверка rendered и effective config. About — текст, не изменение GitHub settings.
Не ставить одну лицензию на чужие данные. Отдельно описать CC BY-SA ACL4SSR,
CC BY-NC-SA d3ward и неопределённость merged BanAD и Karing contributions.
Некоммерческое использование подтверждено, но это не доказательство всех прав
на публичную перепубликацию. По умолчанию публикация заблокирована до явного
решения по provenance/лицензиям; локальные сборки разрешены.

## Приёмка

Unit tests на корректные/ошибочные преобразования, детерминизм, неразрушающий
отказ; интеграционная конвертация всех 46 SRS, `mihomo -t` с синтетическими
узлами и локальными providers, тест сохранения исходного профиля/порядка правил.
Оригинальный файл сравнить побайтно/по хешу до и после. Не активировать TUN
и не отправлять реальный пользовательский трафик для локальной валидации.
Независимые review после Task 1, после Task 2 и итоговый review.
На устройствах, в панели, публичные URLs и Actions после push проверить
отдельно с участием пользователя. Без этих проверок не обещать runtime успех.
