# F-03: Вимкнений механізм блокування облікового запису (Account Lockout) при повторних невдалих спробах входу

- **Статус:** Fixed
- **Актив:** Облікові записи користувачів (`AspNetUsers`) та механізм автентифікації `POST /api/auth/login`
- **Компонент:** `src/SecureLab.Api/Scaffolding/Lab03Identity.cs`
- **Пріоритет:** P2 (Impact: Medium × Likelihood: Medium)
- **Сценарій регресії:** `REG-AUTH-01` (`AuthenticationMechanicsTests.Login_RepeatedFailures_LocksOutAccount_WithoutAffectingOtherUsers`)

## Передумови і межі огляду
- **Review-start commit:** `b2234fb5cf5ad69b847304de3625f020b7a53d1c`
- **Середовище:** Windows 10, .NET SDK `10.0.302`, локальний HTTP-стенд `http://localhost:5080`, PostgreSQL (`127.0.0.1:54329`)
- **Тестові акаунти:** `alice` (`Reporter`), `bob` (`Reporter`), ізольований тестовий акаунт `lockout_probe_*`
- **Reset-команда:** `dotnet run --project src/SecureLab.Api -- --reset-database`
- **Маршрут:** `POST /api/auth/login`
- **Виключення:** Захист поширюється на локальну автентифікацію за паролем через ASP.NET Core Identity.

## Відтворення
1. Запустити `SecureLab.Api` до виправлення `Lab03Identity.cs` (де передавалося `lockoutOnFailure: false`).
2. Виконати 5 поспіль запитів `POST /api/auth/login` для користувача `alice` із хибним паролем (`WrongPassword123!`), витримавши інтервал оновлення вікна `GlobalLimiter`.
3. На 6-му кроці надіслати `POST /api/auth/login` для `alice` із **правильним** паролем.
4. **Expected:** Після 5 невдалих спроб обліковий запис тимчасово блокується, і 6-та спроба навіть із правильним паролем відхиляється зі статусом `401 Unauthorized` без розкриття статусу блокування.
5. **Actual (до виправлення):** Усі 5 невдалих спроб повернули `401 Unauthorized`, а 6-та спроба з правильним паролем одразу успішно автентифікувала користувача (`204 No Content`), підтвердивши повну відсутність account lockout.

## Вплив і ймовірність
- **Статус перевірки:** спостережено локально та закріплено автоматизованим регресійним тестом.
- **Impact (Medium):** Підвищений ризик компрометації облікових записів методом перебору паролів (brute-force / credential stuffing) при обході IP-лімітування (наприклад, із розподілених адрес).
- **Likelihood (Medium):** Ендпоїнт `POST /api/auth/login` є публічним (не потребує попередньої автентифікації) та доступний будь-якому клієнту.

## Першопричина
У `src/SecureLab.Api/Scaffolding/Lab03Identity.cs` (рядок 93) виклик `signIn.PasswordSignInAsync(input.UserName, input.Password, isPersistent: false, lockoutOnFailure: false)` явно передавав `lockoutOnFailure: false`, а в `AddIdentity` не були задані параметри `options.Lockout.AllowedForNewUsers`, `MaxFailedAccessAttempts` та `DefaultLockoutTimeSpan`.

## Виправлення
- У `src/SecureLab.Api/Scaffolding/Lab03Identity.cs` в конфігурації `AddIdentity` встановлено:
  - `options.Lockout.AllowedForNewUsers = true;`
  - `options.Lockout.MaxFailedAccessAttempts = 5;`
  - `options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);`
- У `POST /api/auth/login` змінено прапор у `PasswordSignInAsync` на `lockoutOnFailure: true`.
- Додано автоматизований тест `Login_RepeatedFailures_LocksOutAccount_WithoutAffectingOtherUsers` (`REG-AUTH-01`) у `tests/SecureLab.Api.Tests/AuthenticationMechanicsTests.cs`.
- **Чому усуває причину:** Після 5 невдалих спроб входу ASP.NET Core Identity встановлює `LockoutEnd` у БД для конкретного облікового запису і відхиляє подальші спроби входу протягом 5 хвилин, повертаючи однаковий `401 Unauthorized` без user/lockout enumeration.

## Retest
- Після застосування виправлення виконано 5 невдалих спроб входу `POST /api/auth/login` для `alice` (`WrongPassword123!`), після чого виконано 6-й запит із правильним паролем (`Pa$$w0rD$ecure1`).
- **Фактичний результат:** API відхилив 6-ту спробу зі статусом `401 Unauthorized` (скріншот `№35`), а також пройдено автоматизований тест `REG-AUTH-01`.

## Positive regression
- У стані, коли акаунт `alice` заблоковано, виконано вхід `POST /api/auth/login` від імені іншого користувача `bob` із правильним паролем та запит `GET /api/me`.
- **Фактичний результат:** Вхід `bob` завершився успішно (`204 No Content`), а `GET /api/me` повернув `200 OK` із профілем користувача (`userId: 10000000-0000-0000-0000-000000000002`, скріншот `№36`). Після `--reset-database` `alice` також входить без перешкод.

## Залишковий ризик
Блокування за іменем користувача не запобігає розподіленому перебору одного пароля по великій кількості різних акаунтів (password spraying) та може створити ризик тимчасового DoS для легітимного власника акаунту на 5 хвилин (пом'якшується глобальним rate limiter по IP та автоматичним розблокуванням через 5 хвилин).

## Доказ
- **Тест:** `REG-AUTH-01` (`tests/SecureLab.Api.Tests/AuthenticationMechanicsTests.cs`)
- **Команда:** `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~Login_RepeatedFailures_LocksOutAccount_WithoutAffectingOtherUsers"`
- **Скріншоти:** `№34` (до виправлення: `204` після 5 невдалих спроб), `№35` (retest після виправлення: `401`), `№36` (positive regression для `bob`: `204` + `200`).