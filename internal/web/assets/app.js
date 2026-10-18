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

async function runProfile(profile, btn) {
  if (!runID) return;
  const buttons = document.querySelectorAll("[data-profile]");
  buttons.forEach((b) => (b.disabled = true));
  setStatus("Running test (" + (profile || "default") + ")…");
  try {
    const data = await api("POST", "/api/runs/" + runID + "/next", { profile });
    renderRun(data);
    setStatus("Test complete (" + (profile || "default") + ").");
  } catch (e) {
    setStatus(e.message, true);
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

// ---- plain-language maps (mirror the Go report) ----
const STAGE_LABEL = {
  input: "Address check", dns: "DNS lookup", tcp: "TCP connection",
  tls: "TLS handshake", certificate: "Certificate check", http: "HTTP response",
};
const OUTCOME_WORD = {
  pass: "worked", fail: "failed", inconclusive: "couldn't tell",
  not_tested: "not tested", unsupported_by_client: "this client can't do it",
  cancelled: "cancelled", internal_tool_error: "tool error",
};
const GROUP_NAME = {
  CurveP256: "P-256", CurveP384: "P-384", CurveP521: "P-521",
  X25519MLKEM768: "X25519 + ML-KEM-768 (hybrid post-quantum)",
  SecP256r1MLKEM768: "P-256 + ML-KEM-768 (hybrid post-quantum)",
  none_or_legacy_rsa_key_exchange: "none (legacy RSA key exchange)",
};
const ERROR_PLAIN = {
  certificate_invalid: "the certificate is expired or not yet valid",
  certificate_hostname_mismatch: "the certificate does not cover the address requested",
  certificate_unknown_authority: "the certificate's issuer is not trusted by this machine",
  timeout: "the server did not respond in time",
  tls_handshake_failure: "the TLS handshake was refused (for a single-group test, the server most likely does not accept that group)",
  tls_version_not_supported: "the server does not support that TLS version",
  connection_refused: "the connection was refused",
  network_unreachable: "the network path was unreachable",
};
const friendlyGroup = (g) => GROUP_NAME[g] || (g === "unknown" ? "" : g || "");

function renderRun(run) {
  const findBox = $("findings");
  findBox.replaceChildren();
  const claims = run.claims || [];
  if (!claims.length) {
    findBox.append(el("p", "scope", "No tests have been run yet. Pick a test above."));
  }
  claims.forEach((c) => findBox.appendChild(renderClaim(c, run)));

  const obsBox = $("observations");
  obsBox.replaceChildren();
  (run.observations || []).forEach((o) => obsBox.appendChild(renderObservation(o)));
}

function claimStatus(c, run) {
  const ids = new Set(c.supporting_observations || []);
  let httpPass = false, anyFail = false;
  (run.observations || []).forEach((o) => {
    if (!ids.has(o.id)) return;
    if (o.stage === "http" && o.outcome === "pass") httpPass = true;
    if (o.outcome === "fail" || o.outcome === "inconclusive") anyFail = true;
  });
  if (httpPass) return { word: "Worked", cls: "pass" };
  if (anyFail) return { word: "Failed", cls: "fail" };
  return { word: "Note", cls: "note" };
}

function renderClaim(c, run) {
  const box = el("div", "finding");
  const st = claimStatus(c, run);
  const head = el("div", "finding-head");
  head.append(el("span", "badge " + st.cls, st.word));
  head.append(el("span", "statement", c.statement || ""));
  box.append(head);

  const dl = document.createElement("dl");
  const rows = [];
  if (c.checked) rows.push(["We checked", c.checked]);
  (c.alternatives || []).forEach((a) => rows.push(["Could also be", a]));
  (c.unchecked_items || []).forEach((u) => rows.push(["Not established", u]));
  if (c.next_discriminating_check) rows.push(["Suggested next test", c.next_discriminating_check]);
  rows.forEach(([k, v]) => dl.append(elDT(k), elDD(v)));
  if (dl.childNodes.length) box.append(dl);
  return box;
}

function renderObservation(o) {
  const box = el("div", "obs");
  const head = el("div");
  head.append(el("span", "stage", (STAGE_LABEL[o.stage] || o.stage || "") + "  "));
  head.append(el("span", "outcome " + (o.outcome || ""), OUTCOME_WORD[o.outcome] || o.outcome || ""));
  box.append(head);

  const dl = document.createElement("dl");
  const pairs = [
    ["TLS version", o.negotiated_version],
    ["key exchange", friendlyGroup(o.group)],
    ["cipher", o.cipher_suite],
    ["protocol", o.application_protocol && o.application_protocol !== "none" ? o.application_protocol : ""],
    ["certificate", o.verification_status],
    ["HTTP status", o.http_status ? String(o.http_status) : ""],
    ["reason", ERROR_PLAIN[o.normalized_error] || ""],
    ["technical", o.raw_error_redacted],
  ];
  if (o.detail && o.detail.requested_profile) pairs.push(["tested profile", o.detail.requested_profile]);
  (o.remaining_unknowns || []).forEach((u) => pairs.push(["not checked", u]));
  pairs.forEach(([k, v]) => {
    if (!v) return;
    dl.append(elDT(k), elDD(v));
  });
  if (dl.childNodes.length) box.append(dl);
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
  document.querySelectorAll("[data-profile]").forEach((btn) => {
    btn.addEventListener("click", () => runProfile(btn.dataset.profile, btn));
  });
  $("reportBtn").addEventListener("click", () => preview("text"));
  $("jsonBtn").addEventListener("click", () => preview("json"));
  $("shutdownBtn").addEventListener("click", shutdown);

  if (await bootstrap()) {
    await loadCapabilities();
    setStatus("Ready. Enter an HTTPS address to begin.");
  }
}

main();
