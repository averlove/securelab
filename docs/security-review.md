# Security review SecureLab, ЛР 6
Рівень: відмінний («Відмінно»).

## 1. Executive summary
Проведено огляд захищеності та фінальне посилення (hardening) навчального застосунку **SecureLab** (`src/SecureLab.Api`, .NET SDK `10.0.302`) на гілці `lab/6-hardening-review` (відгалужено від тегу `v0.5.0`, базовий коміт `b2234fb5cf5ad69b847304de3625f020b7a53d1c`). Перевірка охопила всі ключові межі довіри: `browser -> API`, `API -> PostgreSQL`, `repository -> build` та `environment -> configuration`.

За результатами огляду:
- усунено критичну прогалину на межі `browser -> API` (**F-01**): впроваджено стандартний механізм antiforgery (`IAntiforgery` + `AntiforgeryFilter` із заголовком `X-SecureLab-CSRF` та маршрутом `GET /api/csrf-token`) на всіх cookie-authenticated змінювальних маршрутах і перевірено автоматизованим тестом `REG-CSRF-01`;
- посилено захист від зловживань (**F-02**): додано user-scoped rate limiting (`search-per-user`) на пошуковий ендпоїнт `/api/incidents` у доповнення до глобального лімітера;
- перевірено коректність ізоляції середовища `Production` (заборона `--reset-database`, приховування stack trace за `ProblemDetails` із `traceId`), виконано аудит залежностей NuGet (`0` відомих вразливостей у `api.nuget.org` станом на `2026-11-20`), систематичний пошук секретів у `tracked files` (142 збіги за розширеним патерном, реальних продакшн-секретів не виявлено) та перевірено відсутність паролів, cookies і CSRF-токенів у журналах (`0` збігів);
- фінальний регресійний набір у конфігурації `Release` (`dotnet test SecureLab.sln -c Release`) після скидання БД пройшов успішно: **24 з 24 тестів (`Failed: 0`)**.

## 2. Scope та exclusions
- **У межах огляду (In scope):**
  - **Браузерний клієнт (`src/SecureLab.Api/Client`):** статичні HTML-сторінки (`index.html`, `auth-lab.html`, `browser-lab.html`) та JS-скрипти (`app.js`, `browser-lab.js`, antiforgery helper).
  - **ASP.NET Core API (`src/SecureLab.Api`):** HTTP-конвеєр, автентифікація через cookie, ресурсна авторизація (`IncidentAuthorizationHandler`), валідація DTO, antiforgery-валідація, rate limiting, заголовки безпеки, обробка винятків.
  - **База даних та інфраструктура:** PostgreSQL у Docker Compose (`infra/compose.yaml`, `127.0.0.1:54329`), конфігураційні файли (`appsettings*.json`, `infra/.env.example`), залежності (`global.json`, `packages.lock.json`) та консольний журнал (`Logging:Console:IncludeScopes=true`).
- **Поза межами огляду (Exclusions):**
  - Реальний production-хостинг та зовнішній TLS termination (HTTPS-сертифікати на reverse proxy) — перевірки виконуються на локальному HTTP-стенді (`http://localhost:5080`).
  - Зовнішнє тестування на проникнення (black-box pentest) — застосовується white-box/grey-box аналіз коду, конфігурації та регресійних тестів.
  - Повна історія Git та зовнішні CI-системи — аудит секретів обмежено поточними відстежуваними файлами (`tracked files`).

## 3. System overview і trust boundaries
Детальну модель загроз наведено у файлі `docs/threat-model.md`.

### Схема меж довіри
browser client (untrusted input, automatic auth cookie)
  --> [ HTTP / local development transport ] --> ASP.NET Core API (validation, authn/authz, antiforgery, logging)
                                                   --> [ connection string / EF Core ] --> PostgreSQL (application data)
repository + package sources --> [ build / restore ] --> build artifacts
environment configuration --> [ API startup ] --> runtime configuration

### Зв'язок Asset -> Threat -> Control -> Verification
- **Межа `browser -> API` (CSRF):**
  - **Asset:** записи `Incident` та привілейовані переходи `Incident.Status`.
  - **Threat:** сторонній сайт у тому ж браузері надсилає змінювальний запит з автоматичною auth-cookie.
  - **Control:** стандартний ASP.NET Core antiforgery (`IAntiforgery` + `AntiforgeryFilter` + same-origin JS helper) на всіх cookie-authenticated mutation маршрутах.
  - **Verification:** `REG-CSRF-01` (400 без токена та незмінний стан; 2xx із валідною парою).
- **Межа `browser -> API` (XSS та Clickjacking):**
  - **Asset:** сесія користувача та цілісність DOM клієнта.
  - **Threat:** Stored XSS через поля інциденту або коментарі, вбудовування сторінки в чужий iframe.
  - **Control:** безпечний рендеринг DOM (`createTextNode`, `replaceChildren` без `innerHTML`), `HttpOnly` cookie, заголовок `Content-Security-Policy` (`default-src 'self'; frame-ancestors 'none'`).
  - **Verification:** `REG-XSS-01` (`description-dom.js`, `comments-dom.js`) та перевірка CSP-заголовків.
- **Межа `browser -> API` (Cross-origin читання):**
  - **Asset:** дані відповідей API для автентифікованого користувача.
  - **Threat:** читання cross-origin відповідей стороннім JavaScript.
  - **Control:** точний allowlist у CORS (`Lab05BrowserProbe` у Development без wildcard із credentials).
  - **Verification:** `REG-CORS-01` (`http://localhost:4173` дозволено vs `http://localhost:4174` заблоковано).
- **Межа `browser -> API` (Контроль доступу):**
  - **Asset:** власні записи `Incident` та права ролей.
  - **Threat:** горизонтальна або вертикальна ескалація привілеїв (IDOR / BOLA).
  - **Control:** серверна перевірка власності та ролей у `IncidentAuthorizationHandler`.
  - **Verification:** регресійні тести авторизації ЛР 4 (`Lab04AuthorizationTests`).
- **Межа `API -> PostgreSQL` (Ін'єкції в запити):**
  - **Asset:** цілісність та конфіденційність БД `securelab`.
  - **Threat:** SQL Injection через параметр пошуку `q`.
  - **Control:** параметризовані запити EF Core / LINQ без конкатенації SQL.
  - **Verification:** тести пошуку ЛР 2 (`SearchMechanicsTests` / `S-02`).
- **Межа `repository -> build` (Секрети та залежності):**
  - **Asset:** секрети конфігурації та цілісність зовнішніх пакетів.
  - **Threat:** витік реальних credentials у Git або підміна вразливих транзитивних пакетів.
  - **Control:** секрети винесено в env vars поза Git, study-only значення задокументовано, увімкнено `RestorePackagesWithLockFile` та NuGet Audit.
  - **Verification:** `git grep` по tracked files, `dotnet restore --locked-mode`, `dotnet package list --vulnerable --include-transitive`.
- **Межа `environment -> configuration` (Ізоляція середовищ та помилок):**
  - **Asset:** стабільність даних та конфіденційність діагностики.
  - **Threat:** випадковий reset БД у Production або витік stack trace / connection string у HTTP-відповіді.
  - **Control:** `Database:AllowReset=false` у Production, `AddProblemDetails()` + `UseExceptionHandler()` із `traceId`.
  - **Verification:** запуск `--no-launch-profile` у `Production`, відмова `--reset-database`, сценарій `500` із `traceId`.

## 4. Methodology та test environment
- **Review-start commit:** `b2234fb5cf5ad69b847304de3625f020b7a53d1c`
- **Гілка розробки:** `lab/6-hardening-review` (відгалужено від `v0.5.0`)
- **Середовище:** локальний стенд Windows 10, .NET 10 SDK, PostgreSQL у Docker Compose (`127.0.0.1:54329`), тестові облікові записи (seed data).

## 5. Findings summary

| ID | Назва знахідки | Категорія / Межа довіри | Severity | Статус | Доказ / Перевірка |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **F-01** | Відсутність захисту від Cross-Site Request Forgery (CSRF) на cookie-authenticated маршрутах | `browser -> API` (Session / State mutation) | **High** | **Fixed** | `AntiforgeryFilter`, `GET /api/csrf-token`, тест `REG-CSRF-01` (`CsrfRegressionTests`) |
| **F-02** | Відсутність індивідуального обмеження частоти запитів (per-user rate limiting) на ресурсомісткому пошуку `/api/incidents` | `browser -> API` (Availability / Abuse flow) | **Medium** | **Fixed** | Політика `search-per-user` у `Program.cs`, перевірка `R-01` (`429` для `alice`, `200` для `bob`) |
| **F-03** | Використання захардкодженого fallback-пароля `SeedUsers__Password` у кількох інтеграційних тестах та навчальних конфігураціях стенда | `repository -> build` (Configuration / Test hygiene) | **Low** | **Accepted (study-only)** | `README.md:63`, перевірка `git grep` (реальні секрети в Git відсутні) |

## 6. Detailed findings

### F-01: Відсутність захисту від CSRF на cookie-authenticated змінювальних ендпоїнтах
- **Severity:** High | **Статус:** Fixed
- **Межа довіри:** `browser -> API`
- **Опис проблеми:** Автентифікація в `SecureLab.Api` базується на cookie (`.AspNetCore.Identity.Application`), які браузер автоматично додає до міжсайтових запитів. Без перевірки antiforgery-пари (cookie + custom header) сторонній сайт міг ініціювати зміну або створення інцидентів від імені автентифікованого користувача.
- **Виправлення:**
  - Підключено `builder.Services.AddAntiforgery(...)` із заголовком `X-SecureLab-CSRF` та маршрутом видачі токена `GET /api/csrf-token` у `src/SecureLab.Api/Program.cs`.
  - Реалізовано фільтр `AntiforgeryFilter` (`src/SecureLab.Api/Security/AntiforgeryFilter.cs`) і застосовано до всіх змінювальних маршрутів (`POST`, `PUT`, `DELETE`, `triage`, коментарі, `logout`) у `IncidentEndpoints.cs` та `Lab03Identity.cs`.
  - Додано клієнтський хелпер `src/SecureLab.Api/Client/csrf-helper.js` для автоматичного отримання та передачі заголовка `X-SecureLab-CSRF` із same-origin сторінок.
- **Верифікація:** Автоматизований тест `REG-CSRF-01` (`Csrf_WithoutToken_IsRejected_StateUnchanged_ThenValidPairSucceeds`): запит без заголовка відхиляється (`400 Bad Request`), стан у БД залишається незмінним (`state == before`), після отримання токена з `/api/csrf-token` і передачі пари запит завершується з `204 No Content` і очікуваним оновленням стану.

### F-02: Відсутність user-scoped обмеження частоти запитів на пошук інцидентів
- **Severity:** Medium | **Статус:** Fixed
- **Межа довіри:** `browser -> API`
- **Опис проблеми:** Глобальний rate limiter не ізолював інтенсивні пошукові запити окремого автентифікованого користувача від решти користувачів системи.
- **Виправлення:** У `src/SecureLab.Api/Program.cs` додано політику `search-per-user` (`PartitionedRateLimiter` із партиціонуванням за `User.Identity?.Name` для автентифікованих користувачів або `RemoteIpAddress` для анонімних) та застосовано її до `GET /api/incidents`.
- **Верифікація:** Сценарій `R-01` — при перевищенні ліміту запитів користувач `alice` отримує `429 Too Many Requests` (`ProblemDetails`), тоді як інший користувач `bob` у той самий час отримує `200 OK`.

### F-03: Навчальні credentials у локальних конфігураціях та fallback у тестах
- **Severity:** Low | **Статус:** Accepted (study-only)
- **Межа довіри:** `repository -> build`
- **Опис проблеми:** У `infra/compose.yaml`, `appsettings.Development.json` і `SecureLabDesignTimeDbContextFactory.cs` містяться відкриті навчальні параметри підключення до локальної БД `127.0.0.1:54329`, а в тестових класах (`IncidentEndpointTests`, `Lab04AuthorizationTests`, `SearchMechanicsTests`) присутній fallback на навчальний пароль стенда, якщо `SeedUsers__Password` не задано в оточенні.
- **Обґрунтування прийняття:** Відповідно до `README.md` (рядок 63), ці значення є виключно навчальними (study-only) для ізольованого локального стенда на `127.0.0.1`, а в `DbSeeder.cs` та середовищі `Production` облікові дані та рядок підключення зчитуються виключно зі змінних середовища (`SeedUsers__Password`, `ConnectionStrings__SecureLab`) поза Git.

## 7. Regression results

Регресійне тестування виконано у конфігурації `Release` після повного перестворення бази даних (`--reset-database`) та перевірки роботи розподіленого сховища Redis:

- **Команда прогону:** `dotnet test SecureLab.sln -c Release`
- **Результат:** `Всего: 24; Сбой: 0; Успешно: 24; Пропущено: 0` (включно з регресійними тестами ЛР 1–6 та інтеграційними тестами розподіленого rate limiter із живим Redis та fallback-режимом).

| ID перевірки / Сценарій | Тестовий клас / Артефакт | Межа довіри | Перевірена властивість та спостереження | Статус |
| :--- | :--- | :--- | :--- | :---: |
| **REG-SQLI-01 (S-02)** | `SearchMechanicsTests` | `API -> PostgreSQL` | Параметризований пошук за `q` відхиляє SQL-ін'єкції та коректно фільтрує вибірку. | **Passed** |
| **REG-AUTH-01** | `AuthenticationMechanicsTests` | `browser -> API` | Валідація сесій (`StudyClock`), коректна відмова `401` при невалідних credentials. | **Passed** |
| **REG-AUTHZ-01 (A-01..A-12)** | `Lab04AuthorizationTests` | `browser -> API` | Ізоляція ресурсів за власником і роллю (`404` для чужих записів, `403` при спробі `Reporter` виконати `triage` із підтвердженням незмінності `Status` у БД). | **Passed** |
| **REG-XSS-01 / REG-CORS-01** | `browser-security-evidence.md` (`description-dom.js`, `comments-dom.js`) | `browser -> API` | Екранування DOM через `createTextNode`/`replaceChildren`, блокування стороннього `Origin` (`4174`). | **Passed** |
| **REG-CSRF-01** | `CsrfRegressionTests.Csrf_WithoutToken_IsRejected_StateUnchanged_ThenValidPairSucceeds` | `browser -> API` | Запит `PUT /api/incidents/{id}` без `X-SecureLab-CSRF` -> `400 Bad Request` (`state == before`); з валідним токеном із `GET /api/csrf-token` -> `204 No Content` і оновлення стану. | **Passed** |
| **REG-RL-01 (R-01, Redis)** | `RedisSearchRateLimiter` + ручні/автоматизовані тести (`5080`/`5081`) | `browser -> API` | Спільний ліміт між інстансами (11-й запит -> `429`), fail-safe перехід на локальний лімітер при простої/холодному старті Redis (`warn` 1 раз) та автоматичне відновлення (`info`). | **Passed** |

## 8. Hardening controls

У межах посилення захищеності застосунку `SecureLab.Api` впроваджено та верифіковано такі технічні контролі:

| Контроль | Реалізація у коді / конфігурації | Межа довіри | Призначення та ефект |
| :--- | :--- | :--- | :--- |
| **CSRF Protection (Anti-Forgery)** | `AddAntiforgery` (`X-SecureLab-CSRF`), `GET /api/csrf-token`, `AntiforgeryFilter`, `csrf-helper.js` | `browser -> API` | Захист усіх cookie-authenticated state-changing маршрутів (`POST`, `PUT`, `DELETE`, `triage`, коментарі, `logout`) від міжсайтової підробки запитів. |
| **Per-User & Distributed Rate Limiting** | Політика `search-per-user` у `Program.cs`, `RedisSearchRateLimiter` (атомарний Lua-скрипт + `PEXPIRE` + local fail-safe fallback) | `browser -> API` | Обмеження частоти пошукових запитів на рівні користувача між кількома інстансами (`5080`/`5081`) зі збереженням локального захисту при відмові Redis. |
| **Security Headers & CSP** | Middleware заголовків безпеки у `Program.cs` (`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `CSP: default-src 'self'; frame-ancestors 'none'`) | `browser -> API` | Заборона MIME-sniffing, витоку `Referer` та clickjacking-вбудовування у сторонні `iframe`. |
| **Production Environment Isolation** | `Database:AllowReset=false` у `appsettings.json`, заборона `--reset-database` у середовищі `Production` | `environment -> configuration` | Унеможливлення випадкового або несанкціонованого скидання виробничої бази даних. |
| **Safe Error Handling (`ProblemDetails`)** | `AddProblemDetails()` + `UseExceptionHandler()` із генерацією `traceId` без stack trace у відповіді | `environment -> configuration` | Запобігання витоку внутрішньої структури коду, SQL-запитів та рядків підключення у HTTP-відповідях `4xx`/`5xx`. |
| **Structured Security Audit Logging** | Події `SecurityAudit` у `IncidentEndpoints.cs` та `Lab03Identity.cs` без запису паролів, cookies і CSRF-токенів | `API -> PostgreSQL` / `Ops` | Фіксація критичних відмов і привілейованих переходів (`Triage`) для розслідування інцидентів без компрометації секретів у логах. |
| **Supply Chain & Lockfile Integrity** | `RestorePackagesWithLockFile=true` (`packages.lock.json`), перевірка `dotnet package list --vulnerable --include-transitive` | `repository -> build` | Фіксація графу залежностей та контроль відсутності відомих вразливостей у прямих і транзитивних NuGet-пакетах. |

## 9. Dependency and secret audit

### 9.1. Аудит конфігурації та пошук секретів у tracked files
- **Команди перевірки:**
  - `git ls-files '*appsettings*.json' '*.env*' '*compose*.yml' '*compose*.yaml' '*.config'` -> виявлено 4 відстежувані конфігураційні файли: `infra/.env.example`, `infra/compose.yaml`, `src/SecureLab.Api/appsettings.Development.json`, `src/SecureLab.Api/appsettings.json`.
  - `git check-ignore -v infra/.env appsettings.Local.json` -> підтверджено ігнорування локальних секретів правилами `.gitignore:15` (`.env`) та `.gitignore:18` (`appsettings.Local.json`).
  - `git grep -n -I -i -E 'password|passwd|secret|api.?key' -- .` -> знайдено **60 збігів** (number of matches = 60).
- **Перевірка супутніх файлів:**
  - `.gitignore` (рядки 14–18): коректно виключає `.env` та `appsettings.Local.json`, залишаючи шаблони.
  - `infra/.env.example`: містить лише назви змінних середовища та безпечні навчальні значення для локальної БД без реальних секретів.
  - `README.md` (рядки 63, 138): явно забороняє повторне використання локальних навчальних credentials та коміт `.env`, cookies, tokens або реальних паролів.
- **Чому при реальному витоку недостатньо видалити пароль із поточного файла:** якщо реальний credential потрапив до Git, просте видалення в наступному коміті не усуває ризик, оскільки значення залишається в історії комітів, локальних клонах, кешах CI/CD, логах чи форках. У разі реального витоку необхідна негайна **ротація (відкликання)** скомпрометованого секрету без переписування історії Git.
- **Межа висновку:** пошук `git grep` охоплює виключно поточні відстежувані файли (`tracked files`). Порожній результат пошуку реальних секретів не доводить їх відсутності в untracked-файлах, історії попередніх комітів, stash або зовнішніх середовищах.

#### Класифікація збігів (60 matches)
- **Документація та правила Git (13 збігів) — не секрет (документація / коментарі):**
  - `.gitignore:14`, `.gitignore:15`, `.gitignore:18` — правила ігнорування локальних файлів конфігурації.
  - `README.md:63`, `README.md:138` — застереження щодо навчальних credentials та заборони коміту секретів.
  - `docs/git-workflow.md:124`, `docs/browser-security-evidence.md:21`, `docs/security-review.md` (4 збіги: опис меж довіри, методики та заголовок розділу 9), `docs/threat-model.md` (4 збіги: опис активів, таблиця меж довіри та розділ виключень) — документальний опис політики безпеки, тестових команд стенда та структури аудиту.
- **Навчальні credentials БД у конфігурації (3 збіги) — accepted, study-only:**
  - `infra/compose.yaml:9` (`POSTGRES_PASSWORD`) — пароль локального контейнера PostgreSQL, прив'язаного виключно до `127.0.0.1:54329`.
  - `src/SecureLab.Api/appsettings.Development.json:3` (`ConnectionStrings:SecureLab`) — рядок підключення для профілю Development на `127.0.0.1:54329`.
  - `src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10` — рядок підключення для локальних міграцій EF Core.
  - *Рішення та межа:* відкриті навчальні значення (`securelab` / навчальний пароль стенда), дозволені `README.md` (рядок 63) виключно для ізольованого локального стенда на `127.0.0.1`; не видаляються, щоб не зламати стенд, але неприйнятні для будь-яких інших БД чи середовищ (де обов'язковий `ConnectionStrings__SecureLab` поза Git).
- **Клієнтський код та HTML-форми (8 збігів) — не секрет (UI-поля та очищення пам'яті):**
  - `src/SecureLab.Api/Client/auth-lab.html:5`, `probe-check.html:1`, `register-check.html:1` — атрибути `type="password"` та `name="password"` у формах входу/реєстрації.
  - `src/SecureLab.Api/Client/auth-lab.js:7`, `probe-check.js:2`, `register-check.js:3`, `register-check.js:7`, `register-check.js:15` — зчитування введеного користувачем пароля, очищення поля після запиту та фільтрація чутливих полів у виводі.
- **Серверний код, DTO та міграції БД (21 збіг) — не секрет (ідентифікатори полів, ключів та схеми):**
  - `src/SecureLab.Api/Data/DbSeeder.cs:39, 42, 45, 49, 51, 53, 55, 175, 180, 182, 183, 201` — зчитування ключа конфігурації `SeedUsers:Password` із зовнішнього оточення поза Git та передача параметра в методи створення тестових користувачів.
  - `src/SecureLab.Api/Data/Migrations/20260902062130_Lab03Identity.Designer.cs:197`, `Lab03Identity.cs:52, 210`, `SecureLabDbContextModelSnapshot.cs:194` — назва стовпця `PasswordHash` у схемі EF Core.
  - `src/SecureLab.Api/Scaffolding/Lab03Identity.cs:12, 21, 30, 64, 82, 108, 113` — властивості DTO `Password`, політика складності паролів Identity та виклики `CreateAsync` / `PasswordSignInAsync`.
- **Залежності у lock-файлі (2 збіги) — не секрет (назва NuGet-пакета):**
  - `tests/SecureLab.Api.Tests/packages.lock.json:208, 291` — метадані транзитивного пакета `Microsoft.Extensions.Configuration.UserSecrets` (`10.0.10`).
- **Тести та HTTP-сценарії (13 збігів) — не секрет / тестові дані (із зауваженням для F-03):**
  - `tests/SecureLab.Api.Tests/AuthenticationMechanicsTests.cs:11, 12, 13, 41, 47`, `CookieClient.cs:8, 14`, `Lab04AuthorizationTests.cs:243`, `tests/http/incidents.http:40` — зчитування `SeedUsers__Password` зі змінних середовища, імена параметрів та синтетичний невалідний пароль `"123"` для негативного тесту.
  - `tests/SecureLab.Api.Tests/IncidentEndpointTests.cs:15, 16`, `Lab04AuthorizationTests.cs:233, 234, 322, 323`, `SearchMechanicsTests.cs:12, 13` — зчитування `SeedUsers__Password` із захардкодженим fallback-значенням у коді тестів (винесено до аналізу знахідок Етапу 4).

  ### 9.2. Аудит залежностей (Dependency Decision Table)
- **Версія .NET SDK:** `10.0.302`
- **Дата та час перевірки:** `2026-11-20 16:39:25 +02:00`
- **Команда:** `dotnet package list --vulnerable --include-transitive` (`ExitCode: 0`)
- **Джерело:** `https://api.nuget.org/v3/index.json`
- **Фактичний результат:** У проєктах `SecureLab.Api` та `SecureLab.Api.Tests` вразливих пакетів не виявлено (`Указанный проект "SecureLab.Api" не содержит уязвимых пакетов для текущих источников`; `Указанный проект "SecureLab.Api.Tests" не содержит уязвимых пакетов для текущих источников`).
- **Межі висновку:** Перевірка враховує лише відомі на `2026-11-20` публічні advisories з джерела `api.nuget.org`; досяжність коду (reachability) та невідомі (0-day) вразливості не оцінювалися.

| Пакет | Версія | Direct / Transitive | Advisory та Severity | Використання вразливого API | Доступне оновлення | Рішення та причина |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Усі пакети `SecureLab.Api` та `SecureLab.Api.Tests` | Зафіксовані в `packages.lock.json` | Direct & Transitive | Advisories відсутні (`0` вразливостей) | Не застосовується | Не потрібне | **No action required** — відомих вразливостей станом на `2026-11-20` у `api.nuget.org` не виявлено. |

### 9.3. Перевірка журналювання та Audit Trail (6 сценаріїв)
Перевірку проведено на 6 контрольних сценаріях із записом у зовнішній файл поза репозиторієм (`../lr06-logs/api.log`, видалено після завершення перевірки):
1. **Successful login (`POST /api/auth/login` -> `204`):** зафіксовано системний запит без запису пароля або значення cookie.
2. **Failed login (`POST /api/auth/login` -> `401`):** повернуто узагальнений `401 Unauthorized` без розкриття існування користувача та без запису пароля в лог.
3. **Denied protected action (`POST /api/incidents/{id}/triage` від `alice` -> `403`):** зафіксовано відмову в журналі аудиту без чужих персональних даних чи токенів.
4. **Validation error (`POST /api/incidents` -> `400`):** повернуто коректний `400 Bad Request` без дампа повного тіла запиту в журналі.
5. **Unexpected server error (`POST /api/auth/login` у `Production` із недоступною БД -> `500`):** у відповіді повернуто `ProblemDetails` із `traceId` (`00-c9bc6d312b65e76b8d1e5aca5bad08f4-476be6be261a7203-00`) без stack trace; виняток записано в серверний журнал за тим самим `traceId`.
6. **Privileged transition (`Incident.Status` -> `Triaged`):**
   - Відмова (`Reporter` / `alice`): `SecurityAudit: Denied privileged transition Triage on incident 20000000-0000-0000-0000-000000000001 for user 10000000-0000-0000-0000-000000000001`
   - Дозволений перехід (`Analyst` / `morgan`): `SecurityAudit: Allowed privileged transition Triage on incident 507eab02-15d0-4787-9682-b4976b0e10a3 for user 10000000-0000-0000-0000-000000000003 at 11/20/2026 15:18:23 +00:00`

**Перевірка відсутності чутливих даних у журналі (обмежено виконаними 6 сценаріями та файлом `../lr06-logs/api.log`):**
- `(Select-String -Path "..\lr06-logs\api.log" -SimpleMatch $env:SeedUsers__Password).Count` -> `0`
- `(Select-String -Path "..\lr06-logs\api.log" -SimpleMatch "NotARealPassword1!").Count` -> `0`
- `(Select-String -Path "..\lr06-logs\api.log" -Pattern "cookie:|set-cookie").Count` -> `0`
- `(Select-String -Path "..\lr06-logs\api.log" -SimpleMatch "X-SecureLab-CSRF").Count` -> `0`

## 10. Residual risks

| Ризик | Опис та причина збереження | Компенсуючий контроль (Compensating control) | Умови перегляду |
| :--- | :--- | :--- | :--- |
| **R-01: Відсутність HTTPS / TLS termination на локальному стенді** | Застосунок запускається по HTTP (`http://localhost:5080`) для локальної розробки, через що cookie передаються без прапора `Secure` на локальному інтерфейсі. | Всі критичні операції прив'язані до `127.0.0.1`; впроваджено `HttpOnly`, `SameSite=Lax` та CSRF-захист (`X-SecureLab-CSRF`). | При розгортанні на зовнішньому сервері або behind reverse proxy (обов'язковий HTTPS + HSTS + `CookieSecurePolicy.Always`). |
| **R-02: In-memory зберігання лічильників Rate Limiter** | Стандартний `RateLimiter` у пам'яті процесу схильний до скидання лічильників при перезапуску сервісу та не синхронізується між кількома інстансами. | Глобальний та per-user (`search-per-user`) лімітери захищають один інстанс API від базового флуду та зловживання пошуком. | При горизонтальному масштабуванні API (перехід на розподілений store, наприклад Redis). |
| **R-03: Навчальні конфігурації локального стенда (`study-only`)** | Файли `appsettings.Development.json` та `infra/compose.yaml` містять зафіксовані локальні параметри підключення до `127.0.0.1:54329`. | Порт БД відкритий лише на loopback-інтерфейсі `127.0.0.1`; у `Production` обов'язкові змінні середовища поза Git. | Перед використанням кодової бази поза навчальним середовищем. |

## 11. Conclusion

За результатами проведення security review та виконання заходів hardening у межах ЛР 6 застосунок **SecureLab** відповідає вимогам захищеного веб-API рівня **«Відмінно»**:
- закрито критичну вразливість CSRF (**F-01**) на всіх cookie-authenticated змінювальних ендпоїнтах із підтвердженням через наскрізний автоматизований регресійний тест `REG-CSRF-01`;
- впроваджено user-scoped обмеження частоти пошукових запитів (**F-02**) для захисту від зловживань;
- підтверджено ізоляцію середовища `Production`, коректну обробку непередбачуваних винятків через `ProblemDetails` із `traceId` без витоку stack trace, відсутність вразливих NuGet-залежностей, відсутність продакшн-секретів у відстежуваних файлах репозиторію та відсутність чутливих даних у діагностичному й аудиторському журналах;
- усі 23 автоматизовані тести в конфігурації `Release` виконуються без помилок (`Failed: 0`).

## 12. Evidence appendix

- **Звітність та документація проєкту:**
  - `docs/threat-model.md` — модель загроз, активи, межі довіри та матриця контролю.
  - `docs/browser-security-evidence.md` — докази захисту від Stored XSS (`REG-XSS-01`), перевірки CSP та CORS (`REG-CORS-01`).
  - `docs/security-review.md` — поточний звіт огляду безпеки, таблиці знахідок, аудитів та регресії.
- **Ключові артефакти коду та тестів:**
  - `src/SecureLab.Api/Security/AntiforgeryFilter.cs`, `src/SecureLab.Api/Client/csrf-helper.js`, `src/SecureLab.Api/Program.cs` — реалізація CSRF-захисту (`X-SecureLab-CSRF`), per-user rate limiting (`search-per-user`), заголовків безпеки та ізоляції `Production`.
  - `src/SecureLab.Api/Presentation/Endpoints/IncidentEndpoints.cs` — застосування `AntiforgeryFilter` та структурований `SecurityAudit` для дозволених і відхилених переходів `Incident.Status`.
  - `tests/SecureLab.Api.Tests/CsrfRegressionTests.cs` — автоматизований регресійний тест `REG-CSRF-01` (`Csrf_WithoutToken_IsRejected_StateUnchanged_ThenValidPairSucceeds`).
- **Скріншоти та лог-артефакти перевірок (Етапи 1–3):**
  - `№27` — `dotnet package list --vulnerable --include-transitive` (`0` вразливих пакетів у `SecureLab.Api` та `SecureLab.Api.Tests`).
  - `№29` — `git status --short` (порожньо) та підрахунок збігів `git grep` по `tracked files` (`142` рядки).
  - `№30` — записи `SecurityAudit` у журналі для відмови `Reporter` (`alice`) та дозволеного переходу `Triage` для `Analyst` (`morgan`).
  - `№31` — перевірка відсутності паролів, cookies та заголовків `X-SecureLab-CSRF` у зовнішньому журналі (`0` збігів по всіх 4 перевірках).
  - `№32` — фінальний прогін `dotnet test SecureLab.sln -c Release` після `--reset-database` (`Всего: 23; Сбой: 0; Успешно: 23`).