// Approval and enrollment pages of the bas broker. The page data comes from data-*
// attributes on <body>, which the broker writes.
"use strict";

const page = document.body.dataset;
const statusLine = document.getElementById("status");

function show(text, kind) {
  if (!statusLine) return;
  statusLine.textContent = text;
  statusLine.className = kind || "";
}

function toBytes(text) {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function toText(buffer) {
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const reply = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(reply.error || "HTTP " + response.status);
  return reply;
}

function setButtons(disabled) {
  for (const button of document.querySelectorAll("button")) button.disabled = disabled;
}

async function approve() {
  const valueField = document.getElementById("value");
  if (valueField && valueField.value === "") {
    show("Type the value first.", "error");
    return;
  }
  setButtons(true);
  try {
    show("Waiting for your passkey...");
    const options = await post(`/a/${page.id}/begin`);
    const publicKey = options.publicKey;
    publicKey.challenge = toBytes(publicKey.challenge);
    for (const allowed of publicKey.allowCredentials || []) allowed.id = toBytes(allowed.id);
    const credential = await navigator.credentials.get({ publicKey });
    const answer = {
      credential: {
        id: credential.id,
        rawId: toText(credential.rawId),
        type: credential.type,
        extensions: credential.getClientExtensionResults(),
        response: {
          authenticatorData: toText(credential.response.authenticatorData),
          clientDataJSON: toText(credential.response.clientDataJSON),
          signature: toText(credential.response.signature),
          userHandle: credential.response.userHandle
            ? toText(credential.response.userHandle)
            : null,
        },
      },
    };
    if (valueField) answer.value = valueField.value;
    const reply = await post(`/a/${page.id}/finish`, answer);
    if (valueField) valueField.value = "";
    if (reply.state === "approved") {
      if (reply.enroll_url) {
        show("Approved. Open this link on the device to enroll, within 15 minutes:", "ok");
        const link = document.createElement("a");
        link.href = reply.enroll_url;
        link.textContent = reply.enroll_url;
        statusLine.append(document.createElement("br"), link);
      } else {
        show("Approved and applied.", "ok");
      }
      for (const button of document.querySelectorAll("button")) button.remove();
    } else {
      show("Approved, but the change failed: " + (reply.error || reply.state), "error");
    }
  } catch (err) {
    show("Not approved: " + err.message, "error");
    setButtons(false);
  }
}

async function deny() {
  setButtons(true);
  try {
    await post(`/a/${page.id}/deny`);
    show("Denied.", "ok");
    for (const button of document.querySelectorAll("button")) button.remove();
  } catch (err) {
    show("Could not deny: " + err.message, "error");
    setButtons(false);
  }
}

async function enroll() {
  const labelField = document.getElementById("label");
  setButtons(true);
  try {
    show("Creating the passkey...");
    const options = await post(`/enroll/${page.token}/begin`, { label: labelField.value });
    const publicKey = options.publicKey;
    publicKey.challenge = toBytes(publicKey.challenge);
    publicKey.user.id = toBytes(publicKey.user.id);
    for (const excluded of publicKey.excludeCredentials || []) excluded.id = toBytes(excluded.id);
    const credential = await navigator.credentials.create({ publicKey });
    const transports = credential.response.getTransports
      ? credential.response.getTransports()
      : undefined;
    const reply = await post(`/enroll/${page.token}/finish`, {
      label: labelField.value,
      credential: {
        id: credential.id,
        rawId: toText(credential.rawId),
        type: credential.type,
        extensions: credential.getClientExtensionResults(),
        response: {
          attestationObject: toText(credential.response.attestationObject),
          clientDataJSON: toText(credential.response.clientDataJSON),
          transports,
        },
      },
    });
    let text = "Enrolled. This passkey can now approve bas requests.";
    if (reply.removed && reply.removed.length > 0) {
      text += " Removed: " + reply.removed.join(", ") + ".";
    }
    show(text, "ok");
    if (page.again === "1") {
      labelField.value = "";
      const button = document.getElementById("enroll");
      button.textContent = "Enroll another passkey";
      button.disabled = false;
    } else {
      for (const button of document.querySelectorAll("button")) button.remove();
    }
  } catch (err) {
    show("Not enrolled: " + err.message, "error");
    setButtons(false);
  }
}

if (page.page === "approve") {
  document.getElementById("approve")?.addEventListener("click", approve);
  document.getElementById("deny")?.addEventListener("click", deny);
} else if (page.page === "enroll") {
  document.getElementById("enroll")?.addEventListener("click", enroll);
}
