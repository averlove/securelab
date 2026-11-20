(() => {
  const HEADER_NAME = "X-SecureLab-CSRF";
  const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);
  let cachedToken = null;
  let pendingTokenPromise = null;

  function reset() {
    cachedToken = null;
    pendingTokenPromise = null;
  }

  async function getToken() {
    if (cachedToken) return cachedToken;
    if (!pendingTokenPromise) {
      pendingTokenPromise = fetch("/api/csrf-token", {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      })
        .then(async response => {
          if (!response.ok) throw new Error(`CSRF token error: ${response.status}`);
          const data = await response.json();
          cachedToken = data.token;
          return cachedToken;
        })
        .finally(() => { pendingTokenPromise = null; });
    }
    return pendingTokenPromise;
  }

  async function fetchWithCsrf(url, options = {}) {
    const method = (options.method ?? "GET").toUpperCase();
    const headers = new Headers(options.headers ?? {});
    if (!SAFE_METHODS.has(method)) {
      const token = await getToken();
      headers.set(HEADER_NAME, token);
    }
    return fetch(url, { ...options, method, credentials: "same-origin", headers });
    return fetch(url, { ...options, method, credentials: "same-origin", headers });
  }

  window.SecureLabCsrf = { fetch: fetchWithCsrf, getToken, reset };
})();