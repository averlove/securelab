function renderComments(box, comments) {
  box.replaceChildren();
  for (const c of comments) {
    const p = document.createElement("p");
    p.textContent = c.text;
    const hide = document.createElement("button");
    hide.textContent = "Сховати";
    hide.addEventListener("click", () => p.remove());
    p.append(" ", hide);
    box.append(p);
  }
  const note = document.createElement("small");
  note.textContent = "Оновлено";
  box.append(note);
}

function assert(cond, msg) {
  if (!cond) throw new Error(`FAIL: ${msg}`);
}

const testRows = [{ text: "<b>перший</b>" }, { text: "другий" }];
const testBox = document.createElement("div");
document.body.append(testBox);

renderComments(testBox, testRows);
assert(testBox.querySelectorAll("p").length === 2, "1-й render: 2 <p>");
assert(testBox.querySelectorAll("small").length === 1, "1-й render: 1 <small>");
assert(testBox.querySelectorAll("b").length === 0, "1-й render: 0 <b>");
assert(testBox.querySelectorAll("p")[0].textContent.startsWith("<b>перший</b>"), "текст 1-го комментария");

testBox.querySelector("p button").click();
assert(testBox.querySelectorAll("p").length === 1, "1-й клик: 1 <p>");
assert(testBox.querySelectorAll("small").length === 1, "1-й клик: 1 <small>");
assert(testBox.querySelectorAll("b").length === 0, "1-й клик: 0 <b>");
assert(testBox.querySelector("p").textContent.startsWith("другий"), "остался второй комментарий");

const buttons = testBox.querySelectorAll("p button");
buttons[buttons.length - 1].click();
assert(testBox.querySelectorAll("p").length === 0, "2-й клик: 0 <p>");
assert(testBox.querySelectorAll("small").length === 1, "2-й клик: 1 <small>");
assert(testBox.querySelectorAll("b").length === 0, "2-й клик: 0 <b>");

renderComments(testBox, testRows);
assert(testBox.querySelectorAll("p").length === 2, "re-render: 2 <p>");
assert(testBox.querySelectorAll("small").length === 1, "re-render: 1 <small>");
assert(testBox.querySelectorAll("b").length === 0, "re-render: 0 <b>");

console.log("PASS: REG-DOM-COMMENT-HIDE-RERENDER");
