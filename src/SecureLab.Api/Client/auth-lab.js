const result = document.querySelector("#result");
document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(new FormData(form)))
  });
  form.elements.password.value = "";
  if (response.ok) window.SecureLabCsrf?.reset();
  result.textContent = `Login: ${response.status}`;
});
document.querySelector("#me").addEventListener("click", async () => {
  const response = await fetch("/api/me");
  result.textContent = `${response.status}: ${await response.text()}`;
});
document.querySelector("#logout").addEventListener("click", async () => {
  const response = await window.SecureLabCsrf.fetch("/api/auth/logout", { method: "POST" });
  if (response.ok) window.SecureLabCsrf?.reset();
  result.textContent = `Logout: ${response.status}`;
});