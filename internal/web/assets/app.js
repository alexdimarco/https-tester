"use strict";

// Session capability, held only in page memory. Never written to storage.
let capability = "";
let runID = "";
let lastRun = null; // the most recent run snapshot, for naming downloads
let runIDB = "";    // the second server's run, used only for the comparison
let lastRunB = null;

const $ = (id) => document.getElementById(id);

function setStatus(msg, isError) {
  const el = $("status");
  el.textContent = msg || "";
  el.classList.toggle("error", !!isError);
}

// Immediate press feedback: the clicked button shows a spinner and (optionally)
// a "working" label, and stays full-opacity while its siblings dim — so it is
// obvious which action is running, even when the status line is scrolled away.
function setBusy(btn, label) {
  if (!btn) return;
  if (btn.dataset.label === undefined) btn.dataset.label = btn.textContent;
  btn.classList.add("is-busy");
  btn.setAttribute("aria-busy", "true");
  if (label) btn.textContent = label;
}
function clearBusy(btn) {
  if (!btn) return;
  btn.classList.remove("is-busy");
  btn.removeAttribute("aria-busy");
  if (btn.dataset.label !== undefined) {
    btn.textContent = btn.dataset.label;
    delete btn.dataset.label;
  }
}
// Wrap a standalone async button so a press immediately shows a busy state and
// the button is re-enabled once the work settles (the handler owns its errors).
function onClickBusy(btn, label, handler) {
  if (!btn) return;
  btn.addEventListener("click", async () => {
    if (btn.disabled) return;
    btn.disabled = true;
    setBusy(btn, label);
    try { await handler(); } finally { clearBusy(btn); btn.disabled = false; }
  });
}
// Guarded click binding by id: if the element is missing (e.g. an id was
// renamed), skip it rather than throwing and aborting the rest of main() —
// which would leave the page frozen with the launch token still in the URL.
function onClick(id, handler) {
  const b = $(id);
  if (b) b.addEventListener("click", handler);
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
    renderClientButtons(caps.adapters || []);
  } catch (e) {
    $("buildInfo").textContent = "Local processing";
  }
}

function renderClientButtons(adapters) {
  const box = $("clientActions");
  box.replaceChildren();
  const group = $("clientGroup");
  if (group) group.hidden = (adapters || []).length === 0;
  adapters.forEach((t) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "secondary";
    btn.dataset.profile = "client:" + t.name;
    btn.textContent = "Installed " + t.name + (t.available ? "" : " (unavailable)");
    btn.disabled = !t.available;
    if (!t.available) btn.dataset.unavailable = "1";
    btn.title = t.version || t.note || "";
    btn.addEventListener("click", () => runProfile(btn.dataset.profile, btn));
    box.append(btn);
  });
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
    $("summarySection").hidden = true;
    $("resultSection").hidden = false;
    $("assessSection").hidden = true;
    $("profSection").hidden = true;
    $("nginxSection").hidden = false;
    $("compareSection").hidden = false;
    renderRun(data);
    setStatus("Target authorized. Run the test when ready.");
  } catch (e) {
    setStatus(e.message, true);
  }
}

// setTestButtonsDisabled enables or disables the test buttons as a group. When
// re-enabling, a button marked unavailable (an installed client that is not
// present) stays disabled — so a completed run never turns a doomed
// "(unavailable)" button back into a clickable one.
function setTestButtonsDisabled(disabled) {
  document.querySelectorAll("[data-profile], #runAllBtn").forEach((b) => {
    if (!disabled && b.dataset.unavailable === "1") return;
    b.disabled = disabled;
  });
}

async function runProfile(profile, btn) {
  if (!runID) return;
  setTestButtonsDisabled(true);
  setBusy(btn); // spinner on the exact button pressed; keep its label for context
  setStatus("Running test (" + (profile || "default") + ")…");
  try {
    const data = await api("POST", "/api/runs/" + runID + "/next", { profile });
    renderRun(data);
    await loadSummary();
    await loadAssessment();
    await loadProfiles();
    setStatus("Test complete (" + (profile || "default") + ").");
  } catch (e) {
    setStatus(e.message, true);
  } finally {
    clearBusy(btn);
    setTestButtonsDisabled(false);
  }
}

// The core suite, in the order a reader builds up the picture: does HTTPS work,
// then each TLS version, then each single key-exchange group. Installed-client
// comparisons are deliberately left out — they answer a different question and
// depend on what is installed — so "run all" stays predictable.
const CORE_PROFILES = ["", "tls13", "tls12", "group:x25519", "group:p256", "group:p384"];

// runSuite runs the whole core suite against one run id, in order, calling
// onProgress(done, total, profile) before each test. Returns the final snapshot.
async function runSuite(id, onProgress) {
  let data = null;
  for (let i = 0; i < CORE_PROFILES.length; i++) {
    const p = CORE_PROFILES[i];
    if (onProgress) onProgress(i + 1, CORE_PROFILES.length, p);
    data = await api("POST", "/api/runs/" + id + "/next", { profile: p });
  }
  return data;
}

// runAll runs the whole core suite against Server A. The button shows a live
// count ("Running 3 of 6…") so progress is visible where it was pressed, and
// the views refresh once at the end rather than after each test.
async function runAll() {
  if (!runID) { setStatus("Authorize a target first.", true); return; }
  const btn = $("runAllBtn");
  setTestButtonsDisabled(true);
  setBusy(btn, "Starting…");
  try {
    const data = await runSuite(runID, (done, total, p) => {
      setStatus("Running test " + done + " of " + total + " (" + (p || "default") + ")…");
      btn.textContent = "Running " + done + " of " + total + "…";
    });
    if (data) renderRun(data);
    await loadSummary();
    await loadAssessment();
    await loadProfiles();
    setStatus("All core tests complete.");
  } catch (e) {
    setStatus(e.message, true);
  } finally {
    clearBusy(btn);
    setTestButtonsDisabled(false);
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
  lastRun = run;
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

async function loadSummary() {
  if (!runID) return;
  try {
    const s = await api("GET", "/api/runs/" + runID + "/summary");
    renderSummary(s);
  } catch (e) {
    // non-fatal: the summary is a convenience view
  }
}

// The badge class and word mirror the standing/issues, so the top-of-page
// summary reads the same as the exported report.
const STANDING_WORD = {
  "high-security": "High security",
  recommended: "Healthy",
  "below-baseline": "Below baseline",
  not_tested: "Not tested",
};
function summaryBadge(s) {
  if (s.issues && s.issues.length) return { cls: "fail", word: "Action needed" };
  if (s.standing === "high-security" || s.standing === "recommended") return { cls: "pass", word: STANDING_WORD[s.standing] };
  // Amber, not red: below-baseline-without-issues is "not a goal", not an error —
  // matching the ladder rung and the profile cards for the same state.
  if (s.standing === "below-baseline") return { cls: "consider", word: "Below baseline" };
  return { cls: "note", word: "Not tested" };
}
function connWordJS(state) {
  return state === "verified" ? "verified" : state === "failed" ? "not completed" : "not tested yet";
}

// The three named tiers, strongest first. The run's standing lights up one rung
// so the headline reads the same as the per-tier detail below it.
const TIERS = [
  { code: "high-security",  cls: "tier-high",  name: "Highest security", sub: "Modern — TLS 1.3 only, for high-value traffic" },
  { code: "recommended",    cls: "tier-good",  name: "Good security",    sub: "Intermediate — TLS 1.2 + 1.3, broad compatibility (recommended)" },
  { code: "below-baseline", cls: "tier-below", name: "Below the baseline", sub: "Widest-compatibility / legacy, a failed connection, or an observed issue" },
];
// Shared with the profile cards so the matched tier is highlighted there too.
let currentStanding = "not_tested";

function renderLadder(standing) {
  const wrap = el("div", "ladder");
  TIERS.forEach((t) => {
    const here = t.code === standing;
    const rung = el("div", "rung " + t.cls + (here ? " current" : ""));
    rung.append(el("span", "tier-name", t.name));
    rung.append(el("span", "tier-sub", t.sub));
    if (here) rung.append(el("span", "tier-here", "◄ observed here"));
    wrap.append(rung);
  });
  return wrap;
}

function renderSummary(s) {
  $("summarySection").hidden = false;
  currentStanding = s.standing || "not_tested";
  const box = $("summaryPanel");
  box.replaceChildren();

  const card = el("div", "finding");
  const b = summaryBadge(s);
  const head = el("div", "finding-head");
  head.append(el("span", "badge " + b.cls, b.word));
  head.append(el("span", "statement", s.headline || ""));
  card.append(head);

  // Tier placement: where the observed posture lands, strongest first.
  card.append(renderLadder(s.standing));
  if (s.standing === "not_tested") {
    card.append(el("p", "scope", "Run the default verified request to place the server on a tier."));
  }

  const dl = document.createElement("dl");
  const rows = [];
  if (s.connection_note) rows.push(["Connection", connWordJS(s.connection) + " — " + s.connection_note]);
  if (s.standing_label) rows.push(["Tier", s.standing_label]);
  if (s.standing_note) rows.push(["What it means / next", s.standing_note]);
  rows.forEach(([k, v]) => dl.append(elDT(k), elDD(v)));
  if (dl.childNodes.length) card.append(dl);

  if (s.issues && s.issues.length) {
    card.append(el("div", "assess-head", "Errors & concerns"));
    s.issues.forEach((i) => card.append(el("div", "assess-gap", "• " + i)));
  } else {
    card.append(el("p", "scope", "No errors or concerns were observed in the tests you ran."));
  }

  if (s.watch && s.watch.length) {
    const d = document.createElement("details");
    d.append(el("summary", "", "Also worth noting (" + s.watch.length + ")"));
    s.watch.forEach((w) => d.append(el("div", "assess-gap", "• " + w)));
    card.append(d);
  }

  card.append(el("p", "fineprint",
    "Tests run: " + (s.tests_run || 0) + " · security knowledge as of " + (s.knowledge_as_of || "unknown") + ". " + (s.caveat || "")));
  box.append(card);
}

async function loadAssessment() {
  if (!runID) return;
  try {
    const a = await api("GET", "/api/runs/" + runID + "/assessment");
    renderAssessment(a);
  } catch (e) {
    // non-fatal: the assessment is a convenience view
  }
}

function renderAssessment(a) {
  $("assessSection").hidden = false;
  $("assessMeta").textContent = "Security knowledge as of " + (a.knowledge_as_of || "unknown") + " (author baseline). " + (a.scope || "");
  const props = $("assessProps");
  props.replaceChildren();
  (a.properties || []).forEach((p) => {
    const box = el("div", "assess-prop sev-" + (p.severity || ""));
    const head = el("div", "assess-head");
    head.append(el("span", "badge " + (p.severity || ""), p.severity || ""));
    head.append(el("span", "statement", p.name + " — " + p.state));
    box.append(head);
    box.append(el("div", "assess-note", p.note || ""));
    props.append(box);
  });
  const gaps = $("assessGaps");
  gaps.replaceChildren();
  (a.not_tested || []).forEach((g) => {
    const d = el("div", "assess-gap");
    d.append(el("strong", "", g.name + ": "));
    d.append(document.createTextNode(g.why || ""));
    gaps.append(d);
  });

  const refs = $("assessRefs");
  refs.replaceChildren();
  (a.references || []).forEach((r) => {
    const d = el("div", "assess-gap");
    d.append(document.createTextNode(r.topic + " — " + r.cite + " "));
    if (r.url) {
      const link = document.createElement("a");
      link.href = r.url;
      link.target = "_blank";
      link.rel = "noreferrer noopener";
      link.textContent = r.url;
      d.append(link);
    }
    refs.append(d);
  });

  $("assessDisclaimer").textContent = a.disclaimer || "";
}

async function loadProfiles() {
  if (!runID) return;
  try {
    const d = await api("GET", "/api/runs/" + runID + "/profiles");
    renderProfiles(d.profiles || []);
  } catch (e) {
    // non-fatal
  }
}

// Border colour and short label per tier. Below-baseline uses amber, not red:
// the legacy tier is "not a goal", not an error in the server.
const STANDING_BORDER = { recommended: "info", "high-security": "info", "below-baseline": "consider" };
const STANDING_SHORT = { recommended: "Recommended", "high-security": "Highest security", "below-baseline": "Below baseline" };
// Plain-language word and badge colour for each per-tier check result.
const CHECK_PLAIN = {
  met:        { word: "Met", cls: "info" },
  unmet:      { word: "Not met in this run", cls: "attention" },
  not_tested: { word: "Not tested yet", cls: "note" },
  consider:   { word: "Policy choice", cls: "consider" },
};

function checkRow(c) {
  const plain = CHECK_PLAIN[c.status] || { word: c.status || "", cls: "note" };
  const row = el("div", "assess-gap");
  row.append(el("span", "badge " + plain.cls, plain.word));
  row.append(document.createTextNode(" " + c.expectation + (c.detail ? " — " + c.detail : "")));
  return row;
}

function renderProfiles(profiles) {
  $("profSection").hidden = false;
  const box = $("profiles");
  box.replaceChildren();
  profiles.forEach((p) => {
    // Mark the tier the observed posture matches. Below-baseline is shown on the
    // ladder instead, so the (always below-baseline) legacy card is not flagged.
    const isMatch = !!p.standing && p.standing === currentStanding && currentStanding !== "below-baseline";
    const card = el("div", "assess-prop sev-" + (STANDING_BORDER[p.standing] || "note") + (isMatch ? " match" : ""));
    const head = el("div", "assess-head");
    head.append(el("span", "badge " + (STANDING_BORDER[p.standing] || "note"), STANDING_SHORT[p.standing] || p.standing || ""));
    head.append(el("span", "statement", p.name || ""));
    if (isMatch) head.append(el("span", "match-tag", "◄ server lands here"));
    card.append(head);
    card.append(el("div", "assess-note", p.summary || ""));

    const checks = p.checks || [];
    const matches = checks.filter((c) => c.status === "met");
    const missing = checks.filter((c) => c.status !== "met");
    if (matches.length) {
      card.append(el("div", "assess-subhead", "How it matches"));
      matches.forEach((c) => card.append(checkRow(c)));
    }
    if (missing.length) {
      card.append(el("div", "assess-subhead", "What's missing / to confirm"));
      missing.forEach((c) => card.append(checkRow(c)));
    }
    card.append(el("div", "fineprint", "Source: " + (p.source || "")));
    box.append(card);
  });
}

async function reviewNginx() {
  if (!runID) return;
  const text = $("nginxText").value;
  if (!text.trim()) {
    setStatus("Paste some Nginx configuration or output first.", true);
    return;
  }
  setStatus("Reviewing configuration…");
  try {
    const review = await api("POST", "/api/runs/" + runID + "/imports", { kind: "nginx", text });
    renderNginx(review);
    setStatus("Configuration reviewed (operator-supplied; not the running server).");
  } catch (e) {
    setStatus(e.message, true);
  }
}

function renderNginx(review) {
  const box = $("nginxFindings");
  box.replaceChildren();
  const findings = review.findings || [];
  if (!findings.length) {
    box.append(el("p", "scope", "No ssl-related directives were recognized in the text."));
  }
  findings.forEach((f) => {
    const d = el("div", "assess-prop sev-" + (f.severity || ""));
    const head = el("div", "assess-head");
    head.append(el("span", "badge " + (f.severity || ""), f.severity || ""));
    head.append(el("span", "statement", f.topic || ""));
    d.append(head);
    d.append(el("div", "assess-note", f.detail || ""));
    box.append(d);
  });
  const notes = $("nginxNotes");
  notes.replaceChildren();
  (review.parse_errors || []).forEach((e) => notes.append(el("div", "", "parse note: " + e)));
  (review.notes || []).forEach((n) => notes.append(el("div", "", n)));
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

// downloadReport fetches the rendered export and saves it as a file on this
// machine. The content is produced locally and never leaves the loopback
// server. If the browser blocks the save, it falls back to an on-page preview
// the operator can copy.
async function downloadReport(format) {
  if (!runID) { setStatus("Start a test first.", true); return; }
  setStatus("Preparing download…");
  try {
    const data = await api("POST", "/api/runs/" + runID + "/export", { format });
    const isJson = format === "json";
    const name = reportFilename(isJson ? "json" : "txt");
    saveTextFile(data.content || "", name, isJson ? "application/json" : "text/plain");
    setStatus("Downloaded " + name + ". Results stay on this machine; review before sharing.");
  } catch (e) {
    setStatus("Could not save the file (" + e.message + "). Showing a preview to copy instead.", true);
    preview(format);
  }
}

function safeHost(h) {
  return (h || "server").replace(/[^A-Za-z0-9._-]/g, "_");
}
function fileStamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + "-" +
    p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
}
function reportFilename(ext) {
  let host = "report";
  if (lastRun && lastRun.target_scope && lastRun.target_scope.host) {
    host = lastRun.target_scope.host;
  }
  return "httpsdiag-" + safeHost(host) + "-" + fileStamp() + "." + ext;
}

function saveTextFile(content, filename, type) {
  const blob = new Blob([content], { type: type + ";charset=utf-8" });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

// ---- second-server comparison ----

function setCmpStatus(msg, isError) {
  const el = $("cmpStatus");
  if (!el) return;
  el.textContent = msg || "";
  el.classList.toggle("error", !!isError);
}

// startAndRunB authorizes the second server and runs the whole core suite
// against it, then renders the side-by-side. Server A is left untouched.
async function startAndRunB() {
  const url = $("cmpAddr").value.trim();
  if (!url) { setCmpStatus("Enter the second server's HTTPS address first.", true); return; }
  if (!runID) { setCmpStatus("Authorize and test Server A at the top of the page first.", true); return; }
  const btn = $("cmpRunBtn");
  btn.disabled = true;
  setBusy(btn, "Authorizing…");
  setCmpStatus("Authorizing Server B…");
  try {
    const data = await api("POST", "/api/runs", {
      url,
      note: $("cmpNote").value.trim(),
      local_private_approved: $("cmpAllowPrivate").checked,
    });
    runIDB = data.run_id;
    lastRunB = data;
    await runSuite(runIDB, (done, total, p) => {
      setCmpStatus("Server B — running test " + done + " of " + total + " (" + (p || "default") + ")…");
      btn.textContent = "Running " + done + " of " + total + "…";
    });
    setCmpStatus("Server B tested. Building the comparison…");
    await renderComparison();
    $("cmpResults").hidden = false;
    setCmpStatus("Comparison ready. It stays on this machine; review before sharing.");
  } catch (e) {
    setCmpStatus(e.message, true);
  } finally {
    clearBusy(btn);
    btn.disabled = false;
  }
}

// Tier → badge, matching the single-server summary badge wording. Below-baseline
// is amber (a posture that is "not a goal"), not red (an error).
function tierBadge(standing) {
  const map = {
    "high-security": { cls: "pass", word: "Highest security" },
    recommended: { cls: "pass", word: "Good security" },
    "below-baseline": { cls: "consider", word: "Below baseline" },
    not_tested: { cls: "note", word: "Not tested" },
  };
  return map[standing] || { cls: "note", word: standing || "" };
}
// Agreement → badge. "differs" is neutral amber (a difference is not an error);
// "can't compare" is grey (a gap to fill, not a fault).
const AGREE_BADGE = {
  same: { cls: "pass", word: "same" },
  differs: { cls: "consider", word: "differs" },
  incomparable: { cls: "note", word: "can't compare" },
};

async function renderComparison() {
  if (!runID || !runIDB) return;
  const c = await api("POST", "/api/compare", { a: runID, b: runIDB });
  const box = $("compareOut");
  box.replaceChildren();

  // Bottom line + the two servers' headline tiers.
  const card = el("div", "finding");
  const head = el("div", "finding-head");
  head.append(el("span", "badge note", "Bottom line"));
  head.append(el("span", "statement", c.verdict || ""));
  card.append(head);

  const sides = el("div", "compare-sides");
  [c.a, c.b].forEach((s) => {
    const col = el("div", "compare-side");
    col.append(el("span", "compare-side-label", "Server " + (s.label || "")));
    col.append(el("span", "statement", s.host || s.authority || ""));
    const tb = tierBadge(s.standing);
    col.append(el("span", "badge " + tb.cls, tb.word));
    sides.append(col);
  });
  card.append(sides);
  box.append(card);

  // The side-by-side table (scrolls horizontally on a narrow screen).
  const wrap = el("div", "compare-wrap");
  const table = el("table", "compare-table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  ["Dimension", "Server A", "Server B", "Agreement"].forEach((t) => {
    const th = document.createElement("th");
    th.textContent = t;
    htr.append(th);
  });
  thead.append(htr);
  table.append(thead);

  const tbody = document.createElement("tbody");
  (c.rows || []).forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = "agree-" + (r.agreement || "") + (r.note ? " has-note" : "");
    [r.dimension, r.a, r.b].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v || "";
      tr.append(td);
    });
    const ag = document.createElement("td");
    const ab = AGREE_BADGE[r.agreement] || { cls: "note", word: r.agreement || "" };
    ag.append(el("span", "badge " + ab.cls, ab.word));
    tr.append(ag);
    tbody.append(tr);
    if (r.note) {
      const ntr = document.createElement("tr");
      ntr.className = "compare-note-row";
      const ntd = document.createElement("td");
      ntd.colSpan = 4;
      ntd.className = "compare-note";
      ntd.textContent = "note: " + r.note;
      ntr.append(ntd);
      tbody.append(ntr);
    }
  });
  table.append(tbody);
  wrap.append(table);
  box.append(wrap);

  box.append(el("p", "fineprint",
    (c.caveat || "") + " Security knowledge as of " + (c.knowledge_as_of || "unknown") + "."));
}

async function refreshComparison() {
  setCmpStatus("Refreshing the comparison…");
  try {
    await renderComparison();
    setCmpStatus("Comparison refreshed.");
  } catch (e) {
    setCmpStatus(e.message, true);
  }
}

function compareFilename(ext) {
  const a = safeHost(lastRun && lastRun.target_scope && lastRun.target_scope.host);
  const b = safeHost(lastRunB && lastRunB.target_scope && lastRunB.target_scope.host);
  return "httpsdiag-compare-" + a + "-vs-" + b + "-" + fileStamp() + "." + ext;
}

async function downloadComparison(format) {
  if (!runID || !runIDB) { setCmpStatus("Test both servers first.", true); return; }
  setCmpStatus("Preparing the comparison download…");
  try {
    const data = await api("POST", "/api/compare", { a: runID, b: runIDB, format });
    const isJson = format === "json";
    const name = compareFilename(isJson ? "json" : "txt");
    saveTextFile(data.content || "", name, isJson ? "application/json" : "text/plain");
    setCmpStatus("Downloaded " + name + ". Results stay on this machine; review before sharing.");
  } catch (e) {
    setCmpStatus("Could not save the comparison (" + e.message + ").", true);
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
  // Bespoke handlers manage a whole group of buttons (and their own busy state).
  onClickBusy($("startBtn"), "Starting…", startRun);
  onClick("runAllBtn", runAll);
  document.querySelectorAll("[data-profile]").forEach((btn) => {
    btn.addEventListener("click", () => runProfile(btn.dataset.profile, btn));
  });
  onClick("cmpRunBtn", startAndRunB);

  // Standalone async buttons get immediate press feedback via the busy wrapper.
  onClickBusy($("reportBtn"), "Rendering…", () => preview("text"));
  onClickBusy($("dlTxtBtn"), "Preparing…", () => downloadReport("text"));
  onClickBusy($("dlJsonBtn"), "Preparing…", () => downloadReport("json"));
  onClickBusy($("nginxReviewBtn"), "Reviewing…", reviewNginx);
  onClickBusy($("cmpRefreshBtn"), "Refreshing…", refreshComparison);
  onClickBusy($("cmpDlTxtBtn"), "Preparing…", () => downloadComparison("text"));
  onClickBusy($("cmpDlJsonBtn"), "Preparing…", () => downloadComparison("json"));
  onClick("shutdownBtn", shutdown);

  if (await bootstrap()) {
    await loadCapabilities();
    setStatus("Ready. Enter an HTTPS address to begin.");
  }
}

main();
