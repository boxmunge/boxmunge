// Passkey registration and sign-in for the version-check admin pages.
// Served from the service's own origin; the pages' CSP allows no other script.
"use strict";

(function () {
  const statusLine = document.getElementById("status");

  function show(message, isError) {
    statusLine.textContent = message;
    statusLine.className = isError ? "error" : "";
  }

  function toBytes(b64url) {
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  }

  function toB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let raw = "";
    for (const b of bytes) raw += String.fromCharCode(b);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "same-origin",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  }

  function descriptors(list) {
    return (list || []).map((d) => ({ ...d, id: toBytes(d.id) }));
  }

  async function register(form) {
    const code = form.elements.code.value;
    const options = await post("/v1/admin/register/options", { code });
    options.challenge = toBytes(options.challenge);
    options.user.id = toBytes(options.user.id);
    options.excludeCredentials = descriptors(options.excludeCredentials);
    const credential = await navigator.credentials.create({ publicKey: options });
    await post("/v1/admin/register/verify", {
      code,
      credential: {
        id: credential.id,
        rawId: toB64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toB64url(credential.response.clientDataJSON),
          attestationObject: toB64url(credential.response.attestationObject),
        },
      },
    });
    form.reset();
    show("Passkey registered. Registration is now closed.", false);
    const link = document.createElement("a");
    link.href = "/v1/admin/login";
    link.textContent = " Sign in";
    statusLine.append(link);
  }

  async function signIn(next) {
    const options = await post("/v1/admin/login/options", {});
    options.challenge = toBytes(options.challenge);
    options.allowCredentials = descriptors(options.allowCredentials);
    const credential = await navigator.credentials.get({ publicKey: options });
    const response = credential.response;
    await post("/v1/admin/login/verify", {
      credential: {
        id: credential.id,
        rawId: toB64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toB64url(response.clientDataJSON),
          authenticatorData: toB64url(response.authenticatorData),
          signature: toB64url(response.signature),
          userHandle: response.userHandle ? toB64url(response.userHandle) : null,
        },
      },
    });
    window.location.assign(next);
  }

  function run(action) {
    show("Waiting for your passkey…", false);
    action().catch((err) => show(err.message || String(err), true));
  }

  if (!window.PublicKeyCredential) {
    show("This browser does not support passkeys.", true);
    return;
  }
  const page = document.body.dataset.page;
  if (page === "register") {
    const form = document.getElementById("register");
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      run(() => register(form));
    });
  } else if (page === "login") {
    const next = document.body.dataset.next;
    document.getElementById("signin").addEventListener("click", () => run(() => signIn(next)));
  }
})();
