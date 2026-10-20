"use strict";

// Session capability, held only in page memory. Never written to storage.
let capability = "";
let runID = "";
let lastRun = null; // the most recent run snapshot, for naming downloads

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
    await loadSummary();
    await loadAssessment();
    await loadProfiles();
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

function reportFilename(ext) {
  let host = "report";
  if (lastRun && lastRun.target_scope && lastRun.target_scope.host) {
    host = lastRun.target_scope.host;
  }
  host = host.replace(/[^A-Za-z0-9._-]/g, "_");
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  const stamp = d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + "-" +
    p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
  return "httpsdiag-" + host + "-" + stamp + "." + ext;
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
  $("dlTxtBtn").addEventListener("click", () => downloadReport("text"));
  $("dlJsonBtn").addEventListener("click", () => downloadReport("json"));
  $("nginxReviewBtn").addEventListener("click", reviewNginx);
  $("shutdownBtn").addEventListener("click", shutdown);

  if (await bootstrap()) {
    await loadCapabilities();
    setStatus("Ready. Enter an HTTPS address to begin.");
  }
}

main();
