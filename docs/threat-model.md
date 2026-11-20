# Threat Model — SecureLab (Baseline 2-A)

## 1. Версія та середовище
- **Review-start commit:** `<REVIEW_START_HASH>`
- **Профілі запуску:** `Development` (`Properties/launchSettings.json`) та `Production-like` (`--no-launch-profile -c Release`)
- **Відновлення даних:** `dotnet run --project src/SecureLab.Api -- --reset-database` (дозволено виключно в `Development` при `Database:AllowReset=true`)
- **Технологічний стек:** .NET 10 SDK, ASP.NET Core Minimal API, EF Core, PostgreSQL (Docker Compose), Vanilla JS клієнт (`src/SecureLab.Api/Client`)
- **Облікові дані:** виключно штучні тестові акаунти (Alice, Bob, Morgan тощо)

## 2. Компоненти в межах огляду
- **Браузерний клієнт (`Client`):** статичні сторінки (`index.html`, `auth-lab.html`, `browser-lab.html`) та JS-скрипти (`app.js`, `browser-lab.js`, antiforgery helper).
- **API (`SecureLab.Api`):** HTTP-конвеєр, автентифікація на основі cookie, ресурсна авторизація (`IncidentAuthorizationHandler`), валідація вхідних даних, antiforgery-фільтр, rate limiting, заголовки безпеки.
- **База даних (`PostgreSQL`):** локальний контейнер із `infra/compose.yaml` (порт `127.0.0.1:54329`).
- **Конфігурація та залежності:** `appsettings*.json`, `infra/compose.yaml`, `infra/.env.example`, `global.json`, `packages.lock.json`.
- **Журнали (Logs):** консольний sink застосунку (`Logging:Console:IncludeScopes=true`) та події аудиту.

## 3. Активи (Assets)
- **Облікові дані та сесії:** хеші паролів у БД, cookie автентифікації (`HttpOnly`, `SameSite`).
- **Записи інцидентів (`Incident`):** конфіденційність та цілісність власних записів користувачів (`OwnerUserId`).
- **Привілейовані переходи стану:** зміна статусу інциденту (`Incident.Status`), доступна лише уповноваженим ролям (наприклад, `Analyst` / `Morgan`).
- **Журнали аудиту та діагностики:** цілісність та відсутність витоку секретів/токенів у логах.
- **Секрети конфігурації:** позарепозиторні змінні (`SeedUsers:Password`, `ConnectionStrings:SecureLab`).

## 4. Суб’єкти (Subjects)
- **Anonymous visitor:** неавтентифікований користувач (доступ до `/health`, статики, `/api/auth/login`).
- **Authenticated user (Reporter):** автентифікований користувач із базовими правами створення та перегляду власних інцидентів.
- **Privileged user (Analyst / Morgan):** користувач із правами зміни статусу інцидентів (`Incident.Status`) згідно з `docs/access-matrix.md`.
- **Local developer:** розробник із доступом до репозиторію, Docker Compose та локального термінала.

## 5. Точки входу (Entry points)
- **Публічні маршрути:** `POST /api/auth/login`, `GET /health`, статичні файли клієнта (`/`).
- **Автентифіковані читання:** `GET /api/me` (або `/api/auth/session-check`), `GET /api/incidents`, `GET /api/incidents/{id}`, `GET /api/incidents/search?q=...`.
- **Змінювальні маршрути (State-changing):** `POST /api/auth/logout`, `POST /api/incidents`, маршрути оновлення/видалення/зміни статусу `Incident` (детальний перелік у таблиці периметра `security-review.md`).
- **Інфраструктурні входи:** змінні середовища при старті API, відновлення NuGet-пакетів (`dotnet restore --locked-mode`), запис подій у консоль.

## 6. Межі довіри (Trust boundaries)

```text
browser client (untrusted input, automatic auth cookie)
  ──[ HTTP / local development transport ]──> ASP.NET Core API (validation, authn/authz, antiforgery, logging)
                                                ──[ connection string / EF Core ]──> PostgreSQL (application data)
repository + package sources ──[ build / restore ]──> build artifacts
environment configuration ──[ API startup ]──> runtime configuration