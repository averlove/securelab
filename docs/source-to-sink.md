# Власна карта source-to-sink

## Потік 1: `Incident.Description` (основний)

Стан/commit: вразливий стан зафіксовано на коміті `7586700` (тег `v0.4.0`), виправлено у `src/SecureLab.Api/Client/browser-lab.js`. Вхід/Guid запису: користувач `alice`, створений інцидент `b6a69d9b-a61a-4c47-80b0-6429f1c14612` (перевірено також у сеансі `morgan`, контроль `bob` → `404`).

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
| --- | --- | --- | --- |
| Source | `src/SecureLab.Api/Client/browser-lab.html` (`<form id="edit">`, `<textarea name="description">`) | Користувацький ввід у полі `description`: `<img src=x onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')">` | Недовірений зовнішній/користувацький ввід (Untrusted input); містить HTML-розмітку та обробник події `onerror` |
| Request | `src/SecureLab.Api/Client/browser-lab.js` (обробник `submit` форми `#edit`, рядки 20–25) | `POST /api/incidents`, JSON-тіло `{ title, description, severity, occurredAtUtc }` | Зафіксовано в DevTools Network (S09, `POST /api/incidents` → `201 Created`) |
| Validation/mapping | `src/SecureLab.Api/Endpoints/IncidentEndpoints.cs`, `CreateIncidentRequest` | Властивість `CreateIncidentRequest.Description` (`[Required]`, перевірка довжини без HTML-санітизації) | Сервер приймає довільний рядок як чисті текстові дані, не видаляючи `<` та `>` |
| Storage | `src/SecureLab.Api/Models/Incident.cs` | Колонка БД `Incidents.Description` (PostgreSQL через EF Core) | Зберігається у БД у незмінному сирому вигляді (`raw text`) |
| Response | `src/SecureLab.Api/Endpoints/IncidentEndpoints.cs`, `IncidentDetailsDto` | `GET /api/incidents/{id}` → JSON-поле `description` | `application/json; charset=utf-8` (S09, статус `200 OK`); у JSON рядок передається як дані без екранування HTML-символів |
| Client transform | `src/SecureLab.Api/Client/browser-lab.js` (функція `load()`, рядок 10) | Значення `current.description` із розпарсеного об'єкта відповіді `await response.json()` | Жодної трансформації, екранування чи санітизації на клієнті не виконується |
| Sink/context | `src/SecureLab.Api/Client/browser-lab.js` (функція `load()`, рядок 10) | `document.querySelector("#description").innerHTML = current.description` (усередині `<div id="description">`) | HTML-контекст (HTML body sink): браузер парсить рядок як розмітку DOM, створює `<img>` і виконує JS в `onerror` (доведено S10, S11: `data-lab05-marker="executed"`) |

---

## Потік 2: `IncidentComment.Text` (коментарі — рівень «Добре / Відмінно»)

Стан/commit: вразливий стан із seed-коментарем зафіксовано на коміті `1a0878e`, виправлено у `src/SecureLab.Api/Client/browser-lab.js`. Вхід/Guid запису: користувач `alice`, публічний seed-інцидент `20000000-0000-0000-0000-000000000001`, коментар `30000000-0000-0000-0000-000000000005` (автор `morgan`).

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
| --- | --- | --- | --- |
| Source | `src/SecureLab.Api/Data/DbSeeder.cs` (`SeedAsync`, константа `Lab05Marker`; у продукті — будь-який автор коментаря) | Поле `Text` об'єкта `IncidentComment` (`30000000-0000-0000-0000-000000000005`) зі значенням `<img src=x onerror="...">` | Недовірені дані (Untrusted input): містять HTML-тег і JS-подію `onerror` |
| Request | `src/SecureLab.Api/Client/browser-lab.js` (функція `load()`, рядок 5) | `GET /api/incidents/20000000-0000-0000-0000-000000000001` | Зафіксовано в DevTools Network (S13, статус `200 OK`) |
| Validation/mapping | `src/SecureLab.Api/Data/DbSeeder.cs` / DTO мапінг коментарів | Властивість `IncidentComment.Text` зберігається та мапиться без HTML-фільтрації | Дані трактуються сервером як звичайний текст (`plain text`) |
| Storage | `src/SecureLab.Api/Models/IncidentComment.cs` | Колонка БД `IncidentComments.Text` (PostgreSQL через EF Core) | Зберігається у БД у сирому вигляді (`raw text`) |
| Response | `src/SecureLab.Api/Endpoints/IncidentEndpoints.cs`, `IncidentCommentDto` | `GET /api/incidents/{id}` → масив JSON `comments[].text` | `application/json; charset=utf-8` (статус `200 OK`); містить неекрановані символи `<` та `>` у JSON-рядку |
| Client transform | `src/SecureLab.Api/Client/browser-lab.js` (цикл `for (const comment of current.comments ?? [])`, рядки 12–16) | Значення `comment.text` кожного елемента масиву `current.comments` | Жодної клієнтської санітизації або екранування перед вставкою у DOM не виконується |
| Sink/context | `src/SecureLab.Api/Client/browser-lab.js` (функція `load()`, рядок 14) | `paragraph.innerHTML = comment.text` (усередині новоствореного `<p>` в `<div id="comments">`) | HTML-контекст (HTML body sink): браузер інтерпретує `comment.text` як HTML-розмітку та виконує `onerror` (доведено S13: `data-lab05-marker="executed"`) |

---

## Інвентаризація sinks та обґрунтування виправлення (`browser-lab.js`)

- **`browser-lab.js:20` (`status.textContent = ...`)** → системний HTTP-статус → текстовий контекст → безпечно (`textContent`).
- **`browser-lab.js:23` (`renderPlainText(#title, current.title)`)** → назва інциденту (недовірений ввід) → текстовий вузол (`document.createTextNode` + `replaceChildren`) → безпечно.
- **`browser-lab.js:24` (`#description.innerHTML = current.description` → `renderPlainText(#description, current.description)`)** → опис інциденту (недовірений ввід) → раніше HTML-контекст (**вразливий sink, Stored XSS**, доведено S10, S11, S14 на записі `8009f673-0931-4be1-9279-34d70dd0632e`); HTML-форматування не потрібне, тому замінено на безпечний `renderPlainText` через `createTextNode` і `replaceChildren`.
- **`browser-lab.js:25` (`paragraph.innerHTML = comment.text` → `renderComments(#comments, current.comments)`)** → текст коментаря (недовірений ввід) → раніше HTML-контекст (**вразливий sink, Stored XSS**, доведено S13 на коментарі `30000000-0000-0000-0000-000000000005`); замінено на цикл із `renderPlainText(item, comment.text)` та `container.replaceChildren(fragment)`, що виключає парсинг HTML і дублювання при повторному рендері.
- **`browser-lab.js:26` (`#edit.elements.description.value = current.description`)** → опис інциденту → властивість `.value` елемента `<textarea>` → безпечно (DOM API `.value` не парсить HTML).