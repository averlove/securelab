let current;
const id = () => encodeURIComponent(document.querySelector("#incident-id").value.trim());
const status = document.querySelector("#status");

function renderPlainText(container, text) {
  container.replaceChildren(document.createTextNode(text ?? ""));
}

function renderComments(container, comments) {
  const fragment = document.createDocumentFragment();
  for (const comment of comments ?? []) {
    const item = document.createElement("p");
    renderPlainText(item, comment.text);
    fragment.append(item);
  }
  container.replaceChildren(fragment);
}

async function load() {
  const response = await fetch(`/api/incidents/${id()}`);
  status.textContent = `GET: ${response.status}`;
  if (!response.ok) return;
  current = await response.json();
  renderPlainText(document.querySelector("#title"), current.title);
  renderPlainText(document.querySelector("#description"), current.description);
  renderComments(document.querySelector("#comments"), current.comments);
  document.querySelector("#edit").elements.description.value = current.description ?? "";
}

document.querySelector("#load").addEventListener("click", load);
document.querySelector("#edit").addEventListener("submit", async event => {
  event.preventDefault();
  const response = await fetch("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      title: event.currentTarget.elements.title.value,
      description: event.currentTarget.elements.description.value,
      severity: "Low",
      occurredAtUtc: new Date().toISOString()
    })
  });
  status.textContent = `POST: ${response.status}`;
  if (response.ok) {
    const created = await response.json();
    document.querySelector("#incident-id").value = created.id;
    await load();
  }
});