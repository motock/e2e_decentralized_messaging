// Thin UI wiring: every button calls a Tauri command that delegates straight into
// `core_crypto` / `core_storage` (src-tauri/src/commands.rs). No crypto or session logic lives
// here — this file only renders the command's success value or its typed error state
// (src-tauri/src/error.rs::ShellError), never a raw exception/panic message.
//
// Message text is rendered with `textContent` only. A message body is attacker-controlled
// (a peer chooses what to send), so it must never reach `innerHTML`.
const { invoke } = window.__TAURI__.core;

const output = document.getElementById("output");
const peerInput = document.getElementById("peer");
const messageList = document.getElementById("messages");
const composeForm = document.getElementById("compose");
const bodyInput = document.getElementById("body");
const composeError = document.getElementById("compose-error");
const deliveryStatus = document.getElementById("delivery-status");
const receiveButton = document.getElementById("receive");
const verificationState = document.getElementById("verification-state");
const safetyNumberInput = document.getElementById("safety-number");
const verifyButton = document.getElementById("verify");
const verificationError = document.getElementById("verification-error");

function renderError(err) {
  output.textContent = `error: ${err.kind}: ${err.message}`;
}

function renderSuccess(value) {
  output.textContent = `ok: ${JSON.stringify(value)}`;
}

function currentPeer() {
  return peerInput.value.trim();
}

function showComposeError(message) {
  composeError.textContent = message;
  composeError.hidden = false;
}

function clearComposeError() {
  composeError.textContent = "";
  composeError.hidden = true;
}

function showVerificationError(message) {
  verificationError.textContent = message;
  verificationError.hidden = false;
}

function clearVerificationError() {
  verificationError.textContent = "";
  verificationError.hidden = true;
}

// Render the conversation. An empty history shows an explicit empty state; a message that
// failed to decrypt shows a visible failure marker instead of an empty line.
function renderConversation(view) {
  messageList.replaceChildren();

  if (!view.messages || view.messages.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "no messages yet";
    messageList.appendChild(empty);
    return;
  }

  for (const message of view.messages) {
    const item = document.createElement("li");
    item.className = `message ${message.direction}`;
    if (message.decrypt_failed) {
      item.classList.add("decrypt-failed");
    }

    const meta = document.createElement("span");
    meta.className = "meta";
    const who = message.direction === "sent" ? "You" : "Them";
    meta.textContent = `${who} · ${new Date(message.unix_ts * 1000).toISOString()}`;

    const body = document.createElement("span");
    body.className = "body";
    body.textContent = message.decrypt_failed
      ? "<message could not be decrypted>"
      : message.body;

    item.appendChild(meta);
    item.appendChild(body);
    messageList.appendChild(item);
  }
}

function renderDelivery(view) {
  if (view.delivered) {
    deliveryStatus.textContent = "delivered to the relay";
  } else {
    deliveryStatus.textContent =
      "not delivered yet — no relay session with this peer";
  }
  deliveryStatus.hidden = false;
}

function renderVerification(state) {
  if (state.state === "verified") {
    verificationState.textContent = "verified";
  } else if (state.state === "key_changed_warning") {
    verificationState.textContent =
      `WARNING: the safety number changed (was ${state.previous}, now ${state.current}). ` +
      "Verify in person before trusting this contact again.";
  } else {
    verificationState.textContent = "unverified";
  }
}

async function loadConversation() {
  const peer = currentPeer();
  if (!peer) {
    return;
  }
  try {
    const view = await invoke("get_conversation_state", { peer });
    renderConversation(view);
  } catch (err) {
    showComposeError(`could not load conversation: ${err.kind}: ${err.message}`);
  }
}

async function loadVerification() {
  const peer = currentPeer();
  if (!peer) {
    return;
  }
  try {
    renderVerification(await invoke("get_verification_state", { peer }));
  } catch (err) {
    showVerificationError(`could not load verification state: ${err.kind}: ${err.message}`);
  }
}

document.getElementById("generate").addEventListener("click", async () => {
  try {
    const publicKeyBytes = await invoke("generate_identity");
    renderSuccess(publicKeyBytes);
  } catch (err) {
    renderError(err);
  }
});

document.getElementById("malformed").addEventListener("click", async () => {
  try {
    await invoke("establish_malformed_session");
    renderSuccess("unexpected success");
  } catch (err) {
    renderError(err);
  }
});

composeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearComposeError();

  const peer = currentPeer();
  const body = bodyInput.value;
  if (!peer) {
    showComposeError("choose a peer first");
    return;
  }
  if (body.length === 0) {
    showComposeError("message must not be empty");
    return;
  }

  try {
    const view = await invoke("send_message", { peer, body });
    bodyInput.value = "";
    renderConversation(view);
    renderDelivery(view);
  } catch (err) {
    // An oversized message is rejected by the core limit, never truncated.
    showComposeError(`could not send: ${err.kind}: ${err.message}`);
  }
});

receiveButton.addEventListener("click", async () => {
  clearComposeError();
  const peer = currentPeer();
  if (!peer) {
    showComposeError("choose a peer first");
    return;
  }

  try {
    const view = await invoke("receive_and_decrypt", { peer });
    renderConversation(view);
  } catch (err) {
    showComposeError(`could not receive: ${err.kind}: ${err.message}`);
  }
});

verifyButton.addEventListener("click", async () => {
  clearVerificationError();
  const peer = currentPeer();
  const input = safetyNumberInput.value.trim();
  if (!peer) {
    showVerificationError("choose a peer first");
    return;
  }
  if (!input) {
    showVerificationError("enter the safety number to compare");
    return;
  }

  try {
    renderVerification(await invoke("verify_safety_number", { peer, input }));
  } catch (err) {
    showVerificationError(`could not verify: ${err.kind}: ${err.message}`);
  }
});

peerInput.addEventListener("change", () => {
  loadConversation();
  loadVerification();
});

loadConversation();
loadVerification();
