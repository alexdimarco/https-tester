"use strict";

// Session capability, held only in page memory. Never written to storage.
let capability = "";
let runID = "";

const $ = (id) => document.getElementById(id);

function setStatus(msg, isError) {
  const el = $("status");
  el.textContent = msg || "";
  el.classList.toggle("error", !!isError);
}

async function api(method, path, body) {
  const headers = { "X-Capability": capability };
  const opts = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  const text = await resp.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch (_e) { data = { raw: text }; }
  }
  if (!resp.ok) {
    const msg = (data && data.error) ? data.error : ("request failed: " + resp.status);
    throw new Error(msg);
  }
  return data;
}

// Exchange the single-use bootstrap token (from the URL fragment) for a session
// capability, then remove it from the address bar immediately.
async function bootstrap() {
  const hash = window.location.hash || "";
  const m = hash.match(/(?:^#|&)b=([^&]+)/);
  const token = m ? decodeURIComponent(m[1]) : "";
  history.replaceState(null, "", window.location.pathname);
  if (!token) {
    setStatus("No launch token found. Re-open the workbench from the command that started it.", true);
    return false;
  }
  const resp = await fetch("/api/bootstrap", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bootstrap: token }),
  });
  if (!resp.ok) {
    setStatus("Could not establish a local session (the launch token may have already been used).", true);
    return false;
  }
  const data = await resp.json();
  capability = data.capability;
  return true;
}

async function loadCapabilities() {
  try {
    const caps = await api("GET", "/api/capabilities");
    $("buildInfo").textContent =
      "Local processing · " + caps.app_build + " · clients: " + (caps.clients || []).join(", ");
  } catch (e) {
    $("buildInfo").textContent = "Local processing";
  }
}

async function startRun() {
  const url = $("addr").value.trim();
  if (!url) { setStatus("Enter an HTTPS address first.", true); return; }
  setStatus("Validating and recording authorization…");
  try {
    const data = await api("POST", "/api/runs", {
      url,
      note: $("note").value.trim(),
      local_private_approved: $("allowPrivate").checked,
    });
    runID = data.run_id;
    const s = data.target_scope;
    $("scopeSummary").textContent =
      "Authority " + s.authority + " · addresses " +
      ((s.selected_addresses || []).join(", ") || "(none resolved)") +
      " · trust " + data.trust_mode;
    $("runSection").hidden = false;
    $("resultSection").hidden = false;
    renderRun(data);
    setStatus("Target authorized. Run the test when ready.");
  } catch (e) {
    setStatus(e.message, true);
  }
}

async function runNext() {
  if (!runID) return;
  $("nextBtn").disabled = true;
  setStatus("Running the verified HTTPS test…");
  try {
    const data = await api("POST", "/api/runs/" + runID + "/next", {});
    renderRun(data);
    setStatus("Test complete.");
  } catch (e) {
    setStatus(e.message, true);
  } finally {
    $("nextBtn").disabled = false;
  }
}

function renderRun(run) {
  const obsBox = $("observations");
  obsBox.replaceChildren();
  (run.observations || []).forEach((o) => obsBox.appendChild(renderObservation(o)));
  const findBox = $("findings");
  findBox.replaceChildren();
  (run.claims || []).forEach((c) => findBox.appendChild(renderClaim(c)));
}

function renderObservation(o) {
  const box = el("div", "obs");
  const head = el("div");
  const stage = el("span", "stage", String(o.stage || "").toUpperCase() + "  ");
  const outcome = el("span", "outcome " + (o.outcome || ""), o.outcome || "");
  head.append(stage, outcome);
  box.append(head);

  const dl = document.createElement("dl");
  const pairs = [
    ["version", o.negotiated_version],
    ["cipher", o.cipher_suite],
    ["group", o.group],
    ["alpn", o.application_protocol],
    ["verification", o.verification_status],
    ["http status", o.http_status ? String(o.http_status) : ""],
    ["error", o.raw_error_redacted],
  ];
  if (o.detail) {
    Object.keys(o.detail).sort().forEach((k) => pairs.push([k, o.detail[k]]));
  }
  (o.remaining_unknowns || []).forEach((u) => pairs.push(["not checked", u]));
  pairs.forEach(([k, v]) => {
    if (!v) return;
    dl.append(elDT(k), elDD(v));
  });
  if (dl.childNodes.length) box.append(dl);
  return box;
}

function renderClaim(c) {
  const box = el("div", "finding");
  box.append(el("div", "", c.statement || ""));
  box.append(el("div", "meta", (c.register || "") + " / " + (c.status || "") + " — scope: " + (c.scope || "")));
  (c.alternatives || []).forEach((a) => box.append(el("div", "meta", "alternative: " + a)));
  (c.unchecked_items || []).forEach((u) => box.append(el("div", "meta", "not checked: " + u)));
  if (c.next_discriminating_check) {
    box.append(el("div", "meta", "next check: " + c.next_discriminating_check));
  }
  return box;
}

async function preview(format) {
  if (!runID) return;
  setStatus("Rendering report…");
  try {
    const data = await api("POST", "/api/runs/" + runID + "/export", { format });
    $("reportSection").hidden = false;
    $("reportOut").textContent = data.content || "";
    setStatus("Report ready. Review before sharing.");
  } catch (e) {
    setStatus(e.message, true);
  }
}

async function shutdown() {
  setStatus("Shutting down…");
  try { await api("POST", "/api/shutdown", {}); } catch (_e) {}
  setStatus("The workbench has shut down. You can close this tab.");
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function elDT(t) { return el("dt", "", t); }
function elDD(t) { return el("dd", "", t); }

async function main() {
  $("startBtn").addEventListener("click", startRun);
  $("nextBtn").addEventListener("click", runNext);
  $("reportBtn").addEventListener("click", () => preview("text"));
  $("jsonBtn").addEventListener("click", () => preview("json"));
  $("shutdownBtn").addEventListener("click", shutdown);

  if (await bootstrap()) {
    await loadCapabilities();
    setStatus("Ready. Enter an HTTPS address to begin.");
  }
}

main();
