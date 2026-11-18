# Докази безпеки браузера (DEL-01)

Рівень: **відмінний («Відмінно»)** (накопичувальний: охоплює вимоги рівнів «Задовільно», «Добре» та «Відмінно»).

## Стенд і Git-стан (Для всіх)

- **ОС, browser/version, API/probe origins:** Windows 10 Home Version 22H2 (Build 19045.6466), Opera GX 139.0.6053.63 (64-bit, Chromium); API та штатний клієнт — `http://localhost:5080`, дозволений probe — `http://localhost:4173`, недозволений probe — `http://localhost:4174`.
- **Release / base_commit / entry_parent з receipt:** `release`: `lab-05-start-v1`, `base_commit`: `65f42548d877ec5b1af0535897e539a8368a150a`, `entry_parent`: `65f42548d877ec5b1af0535897e539a8368a150a` (базовий тег `v0.4.0`).
- **Vulnerable / fixed hashes, v0.5.0, main і спосіб передавання:**
  - `vulnerable_commit`: `7586700` (та `1a0878e` із seed-коментарем);
  - проміжний коміт XSS fix (Крок 2.11): `2306702` (`lab5: safe DOM rendering for description and comments`);
  - `fixed_commit`: *(заповнити коротким хешем після виконання `git commit` у Кроці 4.5)*;
  - підсумковий тег: `v0.5.0` (перенесення у гілку `main` через `git merge --ff-only`, передавання через приватний Git remote `origin` — `https://github.com/averlove/securelab.git`).
- **Механізм сеансу (`Application → Storage → Cookies → http://localhost:5080`):** назва cookie — `.AspNetCore.Cookies`, `Domain`: `localhost`, `Path`: `/`, `HttpOnly`: `true`, `SameSite`: `Lax`, `Secure`: `false` (локальний HTTP) — *значення `Value` не зберігається*.

## Гіпотеза й REG-XSS-01 (Для всіх)

- **Карта Description:** `docs/source-to-sink.md` (джерело: форма `#edit` → `elements.description` у `src/SecureLab.Api/Client/browser-lab.html` або `DbSeeder.cs`; API-запит: `POST /api/incidents`; сховище: PostgreSQL, таблиця `Incidents`, стовпець `Description`; проєкція та JSON: `GET /api/incidents/{id}` → `IncidentDetailsResponse.description`; клієнт: `load()` у `src/SecureLab.Api/Client/browser-lab.js`; вразливий sink: `document.querySelector("#description").innerHTML = current.description`; додатковий sink для коментарів: `paragraph.innerHTML = comment.text` у `browser-lab.js`).
- **Гіпотеза source → storage → response → sink/context:** Значення з поля «Опис нового інциденту» (`#edit` → `elements.description` у `browser-lab.html`) зберігається в PostgreSQL (`Incidents.Description`) без модифікації, повертається через JSON-відповідь `GET /api/incidents/{id}` (поле `description`) і до виправлення передавалося в `document.querySelector("#description").innerHTML` (`src/SecureLab.Api/Client/browser-lab.js`) як HTML-контекст; за наявності в тексті HTML-розмітки та inline-обробника `onerror` браузер парсить рядок як DOM-елемент `<img>` і виконує JavaScript у походженні `http://localhost:5080`.
- **Передумови, локальний користувач, Guid запису, marker із `resources/lab05-marker.txt`, команди reset/start і create/read:**
  - Застосунок запущено локально на `http://localhost:5080` (`$env:SeedUsers__Password="DevPassword123!"; dotnet run --project src/SecureLab.Api`, скидання БД через `--reset-database`).
  - Локальний користувач для створення запису — `alice` (крос-користувацьке відтворення — `morgan`, контроль авторизації — `bob`).
  - Канонічний однорядковий marker з `resources/lab05-marker.txt`: `<img src=x onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')">`.
  - Guid записів із marker: початковий запис — `b6a69d9b-a61a-4c47-80b0-6429f1c14612` (до reset БД); запис для регресії до/після fix — `8009f673-0931-4be1-9279-34d70dd0632e`.

| Спостереження | До fix (`7586700`) | Після fix (`2306702`) | Посилання на доказ |
|---|---|---|---|
| **Значення в БД/API** (`GET /api/incidents/{id}`) | `200 OK`, JSON `"description": "<img src=x onerror=\"document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')\">"` (зберігається в сирому вигляді) | `200 OK`, ідентичний JSON `"description": "<img src=x onerror=\"document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')\">"` (дані не змінено, змінено лише DOM-sink) | S09 (до fix) vs S18 (після fix) |
| **DOM основного Description** (`#description`) | Рядок розпарсено як HTML: усередині `<div id="description">` створено дочірній елемент `<img src="x" onerror="...">`; у Network фіксується невдалий запит до `/x` (`404`) | Усередині `<div id="description">` міститься один текстовий вузол у лапках; дочірній елемент `<img>` відсутній; запит до `/x` у Network не виконується | S10, S11 (до fix) vs S16, S18 (після fix) |
| **Дія marker** (`#lab05-marker-target`) | Обробник `onerror` виконався: `getAttribute("data-lab05-marker")` повертає `"executed"` | Обробник не виконується: `getAttribute("data-lab05-marker")` повертає `null` | S10, S11 (до fix) vs S16 (після fix) |
| **Апостроф/лапки, `5 < 7`, Unicode, HTML-like рядок** | Символи `<` та `>` у `5 < 7 і 9 > 3` та `<b>жирний</b>` інтерпретуються парсером HTML як теги | Усі символи (`O'Brien`, `"терміново"`, `5 < 7 і 9 > 3`, `Київ — Ω`, буквальний текст `<b>жирний</b> текст` та seed `...0003` із `<script>`) відображаються без змін як єдиний текстовий вузол без тегу `<b>` | S19, S20 |
| **Довжина за власними правилами ЛР 2** | Валідується сервером (до 4000 символів) | Тестовий опис на `3900` символів (`"А".repeat(3900)`) зберігається та коректно рендериться в DOM без помилок у Console | S20 (запис регресії) |
| **Вікно Morgan: GET і перевірка marker; контроль Bob** | `morgan` отримує публічний інцидент (`200 OK`) і у його сеансі спрацьовує `onerror` (`"executed"`); `bob` отримує `404` для приватного інцидента | `morgan` бачить рядок маркера як звичайний текст (`getAttribute("data-lab05-marker") === null`); контроль доступу для `bob` (`404`) збережено без змін | S11, S12 (до fix) та ретест `morgan` після fix |

- **Finding:**
  - **Актив:** клієнтський застосунок картки інциденту (`src/SecureLab.Api/Client/browser-lab.html` та `browser-lab.js`, origin `http://localhost:5080`), який обробляє дані інцидентів та коментарів у сеансах автентифікованих користувачів.
  - **Передумови:** автентифікований користувач (`alice` або інший автор) створює публічний інцидент або додає коментар, що містить HTML-розмітку з inline-обробником події (`onerror`), після чого інший користувач (`morgan`) відкриває картку цього інцидента.
  - **Першопричина:** використання небезпечного HTML-sink (`innerHTML`) замість безпечного текстового API (`createTextNode` / `textContent`) у `src/SecureLab.Api/Client/browser-lab.js` при рендерингу недовірених полів `current.description` та `comment.text`, що надійшли з REST API.
  - **Safe DOM diff:** у коміті `2306702` (`git diff -- src/SecureLab.Api/Client/browser-lab.js`, S15) обидва виклики `innerHTML` замінено на єдиний безпечний helper `renderPlainText(container, text)`, який використовує `container.replaceChildren(document.createTextNode(text ?? ""))`, та функцію `renderComments(container, comments)` на основі `DocumentFragment` і `replaceChildren()`.
  - **Retest:** підтверджено на записі `8009f673-0931-4be1-9279-34d70dd0632e` та seed-інциденті `20000000-0000-0000-0000-000000000001`: дані в БД/JSON залишилися незмінними (S18), розмітка відображається як текст (S16, S17), `data-lab05-marker` дорівнює `null`, а автоматичні DOM-тести проходять зі статусом `PASS` (S21, S22).
  - **Залишковий ризик:** захист на рівні DOM усуває вектор Stored XSS у `browser-lab.js`, але не замінює валідацію контексту при додаванні нових UI-елементів (наприклад, посилань `href`/`src` або інших сторінок клієнта), тому доповнюється Content Security Policy (CSP) як ешелонованим захистом (defense-in-depth).

### Повторювана процедура `REG-XSS-01` (Крок 4.3)

| Поле | Вміст |
|---|---|
| **Передумови** | `fixed_commit` (включно з `2306702`); `dotnet run --project src/SecureLab.Api -- --reset-database`; локальні користувачі `alice` та `morgan`; origin `http://localhost:5080` |
| **Вхід** | Точний однорядковий marker з `resources/lab05-marker.txt`: `<img src=x onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')">` (без секретів і зовнішніх хостів) |
| **Кроки** | 1) Вхід як `alice` (`auth-lab.html`) → створити інцидент із marker у `Description` (`browser-lab.html`) → прочитати його; 2) відкрити той самий Guid у вікні `morgan` та перевірити `#lab05-marker-target`; 3) відкрити seed-інцидент `20000000-0000-0000-0000-000000000001` із marker-коментарем; 4) запустити `tests/browser/description-dom.js` та `tests/browser/comments-dom.js` |
| **Очікуваний результат** | Marker видно як звичайний текст; у DOM — лише текстовий вузол (`childElementCount === 0`), елемент `<img>` відсутній; `#lab05-marker-target` не має атрибута `data-lab05-marker` (`null`); звичайний текст (`O'Brien`, `"терміново"`, `5 < 7`, `Київ — Ω`, `<b>жирний</b>`, 3900 символів) відображається коректно; значення в БД/JSON до і після fix ідентичне (S09 vs S18) |
| **Негативний контроль** | На `vulnerable_commit` (`7586700` / `1a0878e`) той самий marker створював `<img>` і виконував локальну дію (`data-lab05-marker="executed"`, S10, S13) |
| **Доказ** | Network/Elements/Console (`S16–S22`), файли `src/SecureLab.Api/Client/browser-lab.js`, `tests/browser/description-dom.js`, `tests/browser/comments-dom.js` |

## CORS і REG-CORS-01 (Для всіх)

### 1. Прогноз поведінки (Етап 3, крок 1 — заповнено до зміни policy)

| Сценарій | Чи доходить request до API? | Чи може JS прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | Так (`GET` / `POST` виконується на API) | Так | Запит відбувається в межах одного origin (`http://localhost:5080`), перевірка CORS не потрібна |
| simple GET 4173 → API | Так (`GET` надсилається на `5080` із заголовком `Origin: http://localhost:4173`) | Ні (без valid CORS policy) | Браузер надсилає simple-запит, але через Same-Origin Policy (SOP) блокує читання відповіді без `Access-Control-Allow-Origin` |
| simple GET 4174 → API | Так (`GET` надсилається на `5080` із заголовком `Origin: http://localhost:4174`) | Ні (origin не в allowlist) | Браузер надсилає запит до API, але блокує доступ JS до відповіді через SOP/CORS |
| curl / .http → API | Так (`200 OK`) | не застосовується | Це прямий HTTP-клієнт поза браузером, Same-Origin Policy та CORS у ньому не діють |
| preflighted 4173 → API («Добре / Відмінно») | Спочатку браузер надсилає `OPTIONS`; фактичний `GET` залежить від відповіді на preflight | Ні без успішного preflight (`Access-Control-Allow-Origin`, `Allow-Methods`, `Allow-Headers`) | Нестандартний заголовок `X-Lab-Cors-Probe` вимагає попередньої перевірки CORS preflight |

### 2. Фактична таблиця експериментів CORS та порівняння клієнтів (Кроки 3.4–3.6)

| Клієнт / Сценарій | Статус / API-evidence | Чи доступний response JS | Що застосовано | Докази |
|---|---|---|---|---|
| `same-origin 5080` | `200 OK` / `401` (фактичний статус API) | так | authn/authz API; CORS не потрібен | `browser-lab.html` (`http://localhost:5080`) |
| `browser з 4173` (simple `GET /health`) | `200 OK`, заголовок `Access-Control-Allow-Origin: http://localhost:4173` | так (`{status: 200, body: '{"status":"ready"}'}`) | CORS (`Lab05BrowserProbe`) + незалежні API-перевірки | S28 |
| `browser з 4173` (preflight `X-Lab-Cors-Probe`) | `OPTIONS /health?probe=2` → `204 No Content` (`Access-Control-Allow-Origin`, `Allow-Methods: GET`, `Allow-Headers: X-Lab-Cors-Probe`) + `GET` → `200 OK` | так (`{status: 200, body: '{"status":"ready"}'}`) | CORS preflight + фактичний запит | S29 |
| `browser з 4173` (credentials: сесія `alice` vs Incognito) | Із сесією `alice` + `.AllowCredentials()`: `200 OK` (`Access-Control-Allow-Credentials: true`); без `.AllowCredentials()`: `net::ERR_FAILED`; в Incognito без cookie: `401 Unauthorized` | так (при збігу origin + `AllowCredentials()`), інакше ні | CORS з exact origin + `.AllowCredentials()` + серверна автентифікація cookie | S27, S32, S34, S35 |
| `browser з 4174` (simple `GET /health` та `/api/incidents` з cookie `alice`) | На сервері `200 OK` (запит виконався), у відповіді відсутній `Access-Control-Allow-Origin`; у Console `net::ERR_FAILED 200 (OK)` | ні | SOP/CORS блокує читання відповіді; API-перевірки діють незалежно | S30, S33 |
| `browser з 4174` (preflight `X-Lab-Cors-Probe`) | `OPTIONS /health?probe=2` → `204 No Content` без заголовків `Access-Control-Allow-*`; фактичний `GET` браузером не надсилається | ні | CORS preflight зупиняє крос-доменний запит із кастомним заголовком | S31 |
| `curl.exe` (прямий запит і з `Origin: http://localhost:4174`) | `HTTP/1.1 200 OK` (`{"status":"ready"}`) в обох випадках; у другому відповідь без `Access-Control-*` | клієнт читає HTTP-відповідь напряму | API controls (authn/authz/validation), не SOP/CORS | S36 |

### 3. Кінцевий стан CORS-конфігурації та регресія `REG-CORS-01` (Кроки 3.7 та 4.3)

- **Статус політики:** Політика `"Lab05BrowserProbe"` у `src/SecureLab.Api/Program.cs` є виключно навчальним `Development`-стендом (`if (builder.Environment.IsDevelopment())` для `AddCors` та `if (app.Environment.IsDevelopment())` для `UseCors("Lab05BrowserProbe")`). У `Production` ця політика не реєструється і не підключається; навчальні origins не додаються в `appsettings*.json`.
- **Параметри політики (`v0.5.0`):** Дозволено лише один точний origin `http://localhost:4173` (без wildcard `*`), метод `GET`, кастомний заголовок `X-Lab-Cors-Probe` та `.AllowCredentials()`. Origin `http://localhost:4174` залишається негативним контролем і в політику не входить.
- **Відокремлення від штатної топології:** У штатному режимі клієнтська частина обслуговується як `same-origin` на `http://localhost:5080` (`UseDefaultFiles()` / `UseStaticFiles()`), де крос-доменні запити відсутні та CORS не застосовується.
- **Команди запуску локальних probe-стендів:**
  ```powershell
  # Термінал 2 — дозволений origin (4173):
  py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe

  # Термінал 3 — негативний контроль (4174):
  py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe