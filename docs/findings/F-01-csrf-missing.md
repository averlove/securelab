# F-01: Відсутність захисту від CSRF на cookie-authenticated змінювальних маршрутах

- **Статус:** Fixed
- **Актив:** Записи `Incident`, коментарі до інцидентів та привілейовані переходи стану `Incident.Status`
- **Компонент:** `src/SecureLab.Api/Program.cs`, `src/SecureLab.Api/Security/AntiforgeryFilter.cs`, `src/SecureLab.Api/Presentation/Endpoints/IncidentEndpoints.cs`, `src/SecureLab.Api/Scaffolding/Lab03Identity.cs`, `src/SecureLab.Api/Client/csrf-helper.js`
- **Пріоритет:** P1 (Impact: High × Likelihood: High)
- **Сценарій регресії:** `REG-CSRF-01` (`CsrfRegressionTests.Csrf_WithoutToken_IsRejected_StateUnchanged_ThenValidPairSucceeds`)

## Передумови і межі огляду
- **Review-start commit:** `b2234fb5cf5ad69b847304de3625f020b7a53d1c`
- **Середовище:** Windows 10, .NET SDK `10.0.302`, локальний HTTP-стенд `http://localhost:5080`, PostgreSQL (`127.0.0.1:54329`)
- **Тестові акаунти:** `alice` (`Reporter`, ID `10000000-0000-0000-0000-000000000001`), `morgan` (`Analyst`, ID `10000000-0000-0000-0000-000000000003`)
- **Reset-команда:** `dotnet run --project src/SecureLab.Api -- --reset-database`
- **Маршрути:** `POST /api/incidents`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `POST /api/incidents/{id}/comments`, `POST /api/auth/logout`
- **Виключення:** Захист покладається на модель same-origin браузера та вимагає відсутності XSS на тому самому origin (`http://localhost:5080`).

## Відтворення
1. Запустити `SecureLab.Api` до впровадження `AntiforgeryFilter` та виконати вхід користувача `alice` (`POST /api/auth/login`), зберігши cookie `.AspNetCore.Identity.Application`.
2. Надіслати змінювальний запит `PUT /api/incidents/20000000-0000-0000-0000-000000000001` із cookie сесії, але **без** заголовка `X-SecureLab-CSRF` та без antiforgery cookie.
3. **Expected:** Відмова `400 Bad Request` (`ProblemDetails`) без зміни стану інциденту в БД.
4. **Actual (до виправлення):** Запит приймався API (`204 No Content`), а заголовок і опис інциденту змінювалися в БД.

## Вплив і ймовірність
- **Статус перевірки:** спостережено локально та підтверджено автоматизованим інтеграційним тестом.
- **Impact (High):** Неавторизована модифікація або створення інцидентів та привілейованих переходів стану (`triage`) від імені автентифікованого користувача (`Reporter` або `Analyst`).
- **Likelihood (High):** Браузер автоматично додає cookie автентифікації до міжсайтових запитів; експлуатація можлива зі сторонньої веб-сторінки без знання пароля жертви.

## Першопричина
У `src/SecureLab.Api/Program.cs` використовувалася cookie-автентифікація ASP.NET Core Identity, проте сервіс `IAntiforgery` не був зареєстрований, а змінювальні Minimal API ендпоїнти не мали фільтра перевірки пари токенів (antiforgery cookie + custom request header).

## Виправлення
- У `src/SecureLab.Api/Program.cs` зареєстровано `AddAntiforgery` із кастомним заголовком `X-SecureLab-CSRF` та додано захищений маршрут видачі токена `GET /api/csrf-token`.
- Реалізовано `AntiforgeryFilter` (`src/SecureLab.Api/Security/AntiforgeryFilter.cs`) із поверненням стандартизованого `400 Bad Request` (`ProblemDetails`) при відсутності або невалідності токена, і підключено його до всіх змінювальних маршрутів.
- Додано `src/SecureLab.Api/Client/csrf-helper.js` для автоматичного отримання та підстановки `X-SecureLab-CSRF` на клієнтських сторінках.
- **Чому усуває причину:** Сторонній origin не може прочитати значення токена з `GET /api/csrf-token` через Same-Origin Policy і не може підробити кастомний заголовок `X-SecureLab-CSRF` у простому cross-site запиті.

## Retest
- Повторено негативний сценарій у тесті `REG-CSRF-01` (`PUT /api/incidents/{id}` з валідною сесійною cookie, але без `X-SecureLab-CSRF`).
- **Фактичний результат:** API повернув `400 Bad Request` (`Antiforgery token is missing or invalid.`), а перевірка стану в БД підтвердила `state == before`.

## Positive regression
- У другій частині сценарію `REG-CSRF-01` виконано `GET /api/csrf-token` у межах сесії та повторено `PUT /api/incidents/{id}` із заголовком `X-SecureLab-CSRF`.
- **Фактичний результат:** API повернув `204 No Content`, а подальший `GET /api/incidents/{id}` підтвердив оновлення ресурсу в БД.

## Залишковий ризик
Antiforgery-механізм не захищає від дій, ініційованих скриптом на тому самому origin у разі виникнення XSS-вразливості (компенсується безпечним рендерингом DOM через `createTextNode` та заголовком `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`).

## Доказ
- **Тест:** `REG-CSRF-01` (`tests/SecureLab.Api.Tests/CsrfRegressionTests.cs`)
- **Команда:** `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~Csrf_WithoutToken_IsRejected_StateUnchanged_ThenValidPairSucceeds"`
- **Ресурс:** `20000000-0000-0000-0000-000000000001` (перевірено на локальному стенді без виведення значень cookies або токенів).