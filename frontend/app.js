const state = {
  token: localStorage.getItem("pam_token"),
  user: null,
  view: "dashboard",
  selectedSession: null,
  selectedSessionCommands: [],
  selectedSecret: null,
  selectedSecretVersions: [],
  selectedSecretLogs: [],
  pendingMfaLogin: null,
  pendingStepUpAction: null,
  data: {},
};

const navItems = [
  ["dashboard", "Dashboard", "bi-speedometer2", "Privileged access overview", ["user", "approver", "admin"]],
  ["adminPanel", "Admin Panel", "bi-tools", "Application and policy management", ["admin"]],
  ["servers", "Servers", "bi-hdd-network", "Linux targets", ["user", "approver", "admin"]],
  ["accessGroups", "Access Management", "bi-people-fill", "Server groups, memberships, roles, permissions, and access matrix", ["user", "approver", "operator", "admin"]],
  ["users", "Users", "bi-people", "Accounts, groups, and effective access", ["approver", "operator", "admin"]],
  ["requests", "Access Requests", "bi-journal-check", "Requests and approvals", ["user", "approver", "admin"]],
  ["grants", "Active Access", "bi-key", "Current and historical grants", ["user", "approver", "admin"]],
  ["sessions", "Sessions", "bi-terminal", "SSH sessions and recordings", ["user", "approver", "admin"]],
  ["commands", "Commands", "bi-code-square", "Command history", ["user", "approver", "admin"]],
  ["gateway", "Gateway", "bi-diagram-3", "Gateway SSH connections and recordings", ["user", "approver", "admin"]],
  ["secrets", "Secrets", "bi-shield-lock", "Secrets vault metadata and audit", ["approver", "admin"]],
  ["secretRotation", "Secret Rotation", "bi-arrow-clockwise", "Secret rotation jobs", ["admin"]],
  ["policies", "Policies", "bi-sliders", "Access policy rules", ["admin"]],
  ["policyRules", "Policy Engine", "bi-shield-check", "Security policy engine rules", ["admin"]],
  ["policyTest", "Policy Test", "bi-clipboard-check", "Evaluate access and command risk", ["admin"]],
  ["riskEvents", "Risk Events", "bi-activity", "Risk scoring timeline", ["user", "approver", "admin"]],
  ["alerts", "Alerts", "bi-exclamation-triangle", "Open security alerts", ["user", "approver", "admin"]],
  ["audit", "Audit Logs", "bi-clipboard-data", "Administrative audit trail", ["admin"]],
  ["settings", "Settings", "bi-gear", "Runtime settings", ["user", "approver", "admin"]],
  ["mfaSettings", "MFA Settings", "bi-shield-lock", "TOTP and recovery codes", ["user", "approver", "admin"]],
  ["identityAdmin", "Identity Admin", "bi-person-badge", "Providers, users, groups, lockout", ["admin"]],
  ["authEvents", "Auth Events", "bi-clock-history", "Authentication and MFA timeline", ["admin"]],
];

const $ = (selector) => document.querySelector(selector);
const entityModal = new bootstrap.Modal($("#entityModal"));

function badge(status) {
  const map = {
    pending: "text-bg-warning",
    approved: "text-bg-primary",
    active: "text-bg-success",
    rejected: "text-bg-danger",
    revoked: "text-bg-secondary",
    expired: "text-bg-dark",
    failed: "text-bg-danger",
    closed: "text-bg-secondary",
    denied: "text-bg-danger",
    open: "text-bg-danger",
    acknowledged: "text-bg-warning",
    resolved: "text-bg-success",
    dismissed: "text-bg-secondary",
  };
  return `<span class="badge status-badge ${map[status] || "text-bg-light"}">${status || ""}</span>`;
}

function severityBadge(severity) {
  const map = { critical: "text-bg-danger", high: "text-bg-warning", medium: "text-bg-info", low: "text-bg-secondary", info: "text-bg-light" };
  return `<span class="badge ${map[severity] || "text-bg-light"}">${escapeHtml(severity || "info")}</span>`;
}

function toast(message, type = "success") {
  const el = document.createElement("div");
  el.className = `toast align-items-center text-bg-${type} border-0`;
  el.role = "alert";
  el.innerHTML = `<div class="d-flex"><div class="toast-body">${escapeHtml(message)}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>`;
  $("#toasts").appendChild(el);
  new bootstrap.Toast(el, { delay: 3500 }).show();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));
}

function fmt(value) {
  if (!value) return "";
  return new Date(value).toLocaleString();
}

async function api(path, options = {}) {
  const { auth = true, ...requestOptions } = options;
  const headers = { "Content-Type": "application/json", ...(requestOptions.headers || {}) };
  if (auth && state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { ...requestOptions, headers });
  if (res.status === 401 && auth) {
    localStorage.removeItem("pam_token");
    state.token = null;
    showLogin();
    throw new Error("Session expired");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = body.detail || body.message || `HTTP ${res.status}`;
    const err = new Error(typeof detail === "string" ? detail : detail.message || detail.code || `HTTP ${res.status}`);
    err.detail = detail;
    throw err;
  }
  const type = res.headers.get("content-type") || "";
  if (type.includes("text/csv")) return res.text();
  return res.json();
}

async function loadBaseData() {
  const [servers, requests, grants, sessions, commands, gatewayConnections, gatewayEvents, gatewayRecordings, settings] = await Promise.all([
    api("/api/servers"),
    api("/api/access-requests"),
    api("/api/access-grants"),
    api("/api/sessions"),
    api("/api/session-commands"),
    api("/api/gateway/connections"),
    api("/api/gateway/events"),
    api("/api/gateway/recordings"),
    api("/api/settings"),
  ]);
  const [riskEvents, alerts] = await Promise.all([api("/api/risk-events"), api("/api/alerts")]);
  let users = [], policies = [], audit = [], secrets = [], rotationJobs = [], policyRules = [], serverGroups = [], identityUsers = [], authEvents = [], accessGroups = [], permissionTemplates = [], permissionCatalog = [], mfaStatus = null, providers = [];
  providers = await api("/api/identity/providers").catch(() => []);
  mfaStatus = await api("/api/mfa/status").catch(() => null);
  [accessGroups, permissionTemplates, permissionCatalog] = await Promise.all([api("/api/server-groups"), api("/api/permission-templates"), api("/api/permissions")]);
  serverGroups = accessGroups;
  if (["approver", "operator", "admin"].includes(state.user.role)) {
    secrets = await api("/api/secrets");
    users = await api("/api/users");
    audit = await api("/api/audit-logs").catch(() => []);
  }
  if (state.user.role === "admin") {
    [policies, rotationJobs, policyRules, identityUsers, authEvents] = await Promise.all([api("/api/policies"), api("/api/secret-rotation/jobs"), api("/api/policy-rules"), api("/api/identity/users"), api("/api/identity/auth-events")]);
  }
  state.data = { servers, requests, grants, sessions, commands, gatewayConnections, gatewayEvents, gatewayRecordings, settings, users, policies, audit, secrets, rotationJobs, policyRules, riskEvents, alerts, serverGroups, accessGroups, permissionTemplates, permissionCatalog, identityUsers, authEvents, mfaStatus, providers };
}

function allowed(item) {
  const role = state.user.role === "approver" ? "operator" : state.user.role;
  const aliases = role === "operator" ? ["operator", "approver"] : [role];
  return aliases.some((value) => item[4].includes(value));
}

function renderNav() {
  $("#nav").innerHTML = navItems.filter(allowed).map(([id, label, icon]) => `
    <a class="nav-link ${state.view === id ? "active" : ""}" href="#" data-view="${id}">
      <i class="bi ${icon}"></i><span>${label}</span>
    </a>`).join("");
  $("#nav").querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      state.view = link.dataset.view;
      $(".sidebar").classList.remove("open");
      render();
    });
  });
}

function setTitle() {
  if (state.view === "sessionDetails") {
    $("#pageTitle").textContent = "Session Details";
    $("#pageHint").textContent = "Metadata, commands, sudo activity, and raw imported logs";
    return;
  }
  const item = navItems.find((x) => x[0] === state.view) || navItems[0];
  $("#pageTitle").textContent = item[1];
  $("#pageHint").textContent = item[3];
}

async function refresh(renderAfter = true) {
  await loadBaseData();
  if (renderAfter) render();
}

function table(headers, rows) {
  return `<div class="table-wrap"><div class="table-responsive"><table class="table table-hover align-middle">
    <thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
    <tbody>${rows.length ? rows.join("") : `<tr><td colspan="${headers.length}" class="text-secondary p-4">No records</td></tr>`}</tbody>
  </table></div></div>`;
}

function filterBox(id, placeholder = "Filter") {
  return `<input id="${id}" class="form-control" style="max-width:280px" placeholder="${placeholder}">`;
}

function applyClientFilter(inputId, rowSelector) {
  const input = $(`#${inputId}`);
  if (!input) return;
  const pageSize = 20;
  let page = 0;
  const controls = document.createElement("div");
  controls.className = "btn-group ms-auto";
  controls.innerHTML = `<button class="btn btn-outline-secondary btn-sm" type="button" data-page="prev">Previous</button><span class="btn btn-light btn-sm disabled page-label"></span><button class="btn btn-outline-secondary btn-sm" type="button" data-page="next">Next</button>`;
  input.parentElement?.appendChild(controls);
  const update = () => {
    const rows = [...document.querySelectorAll(rowSelector)];
    const matching = rows.filter((row) => row.textContent.toLowerCase().includes(input.value.toLowerCase()));
    const pages = Math.max(1, Math.ceil(matching.length / pageSize));
    page = Math.min(page, pages - 1);
    rows.forEach((row) => { row.style.display = "none"; });
    matching.slice(page * pageSize, (page + 1) * pageSize).forEach((row) => { row.style.display = ""; });
    controls.querySelector(".page-label").textContent = `${matching.length ? page + 1 : 0}/${matching.length ? pages : 0} Â· ${matching.length}`;
    controls.querySelector('[data-page="prev"]').disabled = page === 0;
    controls.querySelector('[data-page="next"]').disabled = page >= pages - 1;
  };
  input.addEventListener("input", () => { page = 0; update(); });
  controls.addEventListener("click", (event) => {
    const direction = event.target.dataset.page;
    if (direction === "prev") page--;
    if (direction === "next") page++;
    update();
  });
  update();
}

function renderDashboard() {
  const active = state.data.grants.filter((g) => g.status === "active");
  const latestAudit = (state.data.audit || []).slice(0, 6);
  const since24h = Date.now() - 24 * 60 * 60 * 1000;
  const activeSessions = state.data.sessions.filter((s) => s.status === "active");
  const activeGateway = state.data.gatewayConnections.filter((c) => c.status === "active");
  const gateway24h = state.data.gatewayConnections.filter((c) => new Date(c.started_at).getTime() >= since24h);
  const gatewayDenied = (state.data.gatewayEvents || []).filter((e) => e.event_type === "gateway_login_denied");
  const dueSecrets = (state.data.secrets || []).filter((s) => s.next_rotation_at && new Date(s.next_rotation_at).getTime() <= Date.now());
  const failedRotations = (state.data.rotationJobs || []).filter((j) => j.status === "failed");
  const commands24h = state.data.commands.filter((c) => new Date(c.executed_at).getTime() >= since24h);
  const sudo24h = commands24h.filter((c) => c.is_sudo);
  const riskyCommands24h = commands24h.filter((c) => (c.risk_score || 0) >= (state.data.settings?.medium_risk_score || 30));
  const openAlerts = (state.data.alerts || []).filter((a) => a.status === "open");
  const criticalAlerts = openAlerts.filter((a) => a.severity === "critical");
  const deniedPolicy24h = (state.data.riskEvents || []).filter((e) => e.event_type.includes("denied") && new Date(e.created_at).getTime() >= since24h);
  const importErrors = (state.data.audit || []).filter((a) => a.action === "session_log_import_failed").slice(0, 6);
  const topGatewayCommands = state.data.commands.filter((c) => c.source === "gateway").slice(0, 6);
  const metrics = [
    ["Active Access", active.length],
    ["Active Sessions", activeSessions.length],
    ["Active Gateway", activeGateway.length],
    ["Gateway 24h", gateway24h.length],
    ["Gateway Denied", gatewayDenied.length],
    ["Active Secrets", (state.data.secrets || []).filter((s) => s.status === "active").length],
    ["Due Secrets", dueSecrets.length],
    ["Failed Rotations", failedRotations.length],
    ["Sudo 24h", sudo24h.length],
    ["Risky Cmd 24h", riskyCommands24h.length],
    ["Open Alerts", openAlerts.length],
    ["Critical Alerts", criticalAlerts.length],
    ["Policy Denied 24h", deniedPolicy24h.length],
  ];
  $("#content").innerHTML = `
    <section class="metric-grid">${metrics.map(([label, value]) => `<div class="metric"><div class="value">${value}</div><div class="label">${label}</div></div>`).join("")}</section>
    <div class="row g-3">
      <div class="col-xl-6">${table(["Grant", "Server", "User", "Expires", "Status"], active.slice(0, 6).map((g) => `<tr><td>#${g.id}</td><td>${escapeHtml(g.server_hostname)}</td><td>${escapeHtml(g.username)}</td><td>${fmt(g.valid_to)}</td><td>${badge(g.status)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Request", "Server", "User", "Type", "Status"], state.data.requests.slice(0, 6).map((r) => `<tr><td>#${r.id}</td><td>${escapeHtml(r.server_hostname)}</td><td>${escapeHtml(r.username)}</td><td>${r.requested_access_type}</td><td>${badge(r.status)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Session", "User", "Server", "Duration", "Status"], state.data.sessions.slice(0, 6).map((s) => `<tr><td>#${s.id}</td><td>${escapeHtml(s.username)}</td><td>${escapeHtml(s.server_hostname)}</td><td>${s.duration_seconds || ""}s</td><td>${badge(s.status)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Command", "User", "sudo", "Time"], state.data.commands.slice(0, 6).map((c) => `<tr><td class="wrap"><code>${escapeHtml(c.command)}</code></td><td>${escapeHtml(c.linux_username)}</td><td>${c.is_sudo ? "yes" : "no"}</td><td>${fmt(c.executed_at)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Gateway Command", "Session", "Time"], topGatewayCommands.map((c) => `<tr><td class="wrap"><code>${escapeHtml(c.command)}</code></td><td>#${c.session_id}</td><td>${fmt(c.executed_at)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Gateway Event", "Message", "Time"], (state.data.gatewayEvents || []).slice(0, 6).map((e) => `<tr><td>${escapeHtml(e.event_type)}</td><td class="wrap">${escapeHtml(e.message)}</td><td>${fmt(e.created_at)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Secret", "Status", "Next Rotation"], (state.data.secrets || []).slice(0, 6).map((s) => `<tr><td>${escapeHtml(s.name)}</td><td>${badge(s.status)}</td><td>${fmt(s.next_rotation_at)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Rotation", "Secret", "Status"], (state.data.rotationJobs || []).slice(0, 6).map((j) => `<tr><td>#${j.id}</td><td>${escapeHtml(j.secret_name || j.secret_id)}</td><td>${badge(j.status)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Alert", "Severity", "Status", "Time"], openAlerts.slice(0, 6).map((a) => `<tr><td class="wrap">${escapeHtml(a.title)}</td><td>${severityBadge(a.severity)}</td><td>${badge(a.status)}</td><td>${fmt(a.created_at)}</td></tr>`))}</div>
      <div class="col-xl-6">${table(["Risk Event", "Score", "Severity", "Time"], (state.data.riskEvents || []).slice(0, 6).map((e) => `<tr><td class="wrap">${escapeHtml(e.message)}</td><td>${e.risk_score}</td><td>${severityBadge(e.severity)}</td><td>${fmt(e.created_at)}</td></tr>`))}</div>
      ${state.user.role === "admin" ? `<div class="col-xl-6">${table(["Import Error", "Grant", "Time"], importErrors.map((a) => `<tr><td class="wrap">${escapeHtml(a.message)}</td><td>${linkId("grant", a.grant_id)}</td><td>${fmt(a.created_at)}</td></tr>`))}</div>` : ""}
      ${state.user.role === "admin" ? `<div class="col-12">${table(["Action", "Message", "Time"], latestAudit.map((a) => `<tr><td>${escapeHtml(a.action)}</td><td class="wrap">${escapeHtml(a.message)}</td><td>${fmt(a.created_at)}</td></tr>`))}</div>` : ""}
    </div>`;
}

function renderAdminPanel() {
  const policyCount = (state.data.policies || []).length;
  const enabledPolicies = (state.data.policies || []).filter((p) => p.enabled).length;
  const policyRuleCount = (state.data.policyRules || []).length;
  const activeUsers = (state.data.users || []).filter((u) => u.is_active).length;
  const openAlerts = (state.data.alerts || []).filter((a) => a.status === "open").length;
  const sections = [
    ["Users", "users", "bi-people", activeUsers],
    ["Policies", "policies", "bi-sliders", `${enabledPolicies}/${policyCount}`],
    ["Policy Engine", "policyRules", "bi-shield-check", policyRuleCount],
    ["Policy Test", "policyTest", "bi-clipboard-check", ""],
    ["Server Groups", "serverGroups", "bi-collection", (state.data.serverGroups || []).length],
    ["Secrets", "secrets", "bi-shield-lock", (state.data.secrets || []).length],
    ["Secret Rotation", "secretRotation", "bi-arrow-clockwise", (state.data.rotationJobs || []).length],
    ["Alerts", "alerts", "bi-exclamation-triangle", openAlerts],
    ["Identity Admin", "identityAdmin", "bi-person-badge", (state.data.identityUsers || []).length],
    ["Audit Logs", "audit", "bi-clipboard-data", (state.data.audit || []).length],
    ["Runtime Settings", "settings", "bi-gear", ""],
    ["Auth Events", "authEvents", "bi-clock-history", (state.data.authEvents || []).length],
  ];
  $("#content").innerHTML = `
    <section class="metric-grid">
      <div class="metric"><div class="value">${activeUsers}</div><div class="label">Active users</div></div>
      <div class="metric"><div class="value">${enabledPolicies}</div><div class="label">Enabled policies</div></div>
      <div class="metric"><div class="value">${policyRuleCount}</div><div class="label">Policy rules</div></div>
      <div class="metric"><div class="value">${openAlerts}</div><div class="label">Open alerts</div></div>
    </section>
    <div class="table-wrap p-3">
      <div class="row g-2">
        ${sections.map(([label, view, icon, count]) => `
          <div class="col-sm-6 col-xl-4">
            <button class="btn btn-outline-primary w-100 d-flex justify-content-between align-items-center" data-admin-view="${view}">
              <span><i class="bi ${icon} me-2"></i>${label}</span>
              <span>${escapeHtml(count)}</span>
            </button>
          </div>`).join("")}
      </div>
    </div>`;
  document.querySelectorAll("[data-admin-view]").forEach((button) => {
    button.addEventListener("click", () => {
      state.view = button.dataset.adminView;
      render();
    });
  });
}

function renderServers() {
  const canAdmin = state.user.role === "admin";
  $("#content").innerHTML = `
    <div class="toolbar">
      ${filterBox("serverFilter", "Filter servers")}
      <button class="btn btn-primary ${canAdmin ? "" : "d-none"}" id="addServer"><i class="bi bi-plus-lg"></i> Add</button>
      <button class="btn btn-outline-primary" id="requestAccess"><i class="bi bi-key"></i> Request Access</button>
    </div>
    ${table(["Host", "IP", "Env", "Criticality", "Groups", "Owner", "SSH secret", "Gateway secret", "Rotation", "Direct", "Gateway", "Logging", "Recording", "Enabled", "Actions"], state.data.servers.map((s) => `
      <tr class="filter-row"><td>${escapeHtml(s.display_name || s.hostname)}<div class="small text-secondary">${escapeHtml(s.hostname)}</div></td><td>${escapeHtml(s.ip_address)}:${s.ssh_port}</td><td>${escapeHtml(s.environment)}</td><td>${escapeHtml(s.criticality)}</td><td>${(s.access_group_ids || []).map(serverGroupName).join(", ")}</td><td>${escapeHtml(s.owner)}</td>
      <td>${secretName(s.ssh_auth_secret_id || s.secret_ref_id)}</td><td>${secretName(s.gateway_secret_ref_id)}</td><td>${s.rotation_enabled ? "on" : "off"}</td><td>${s.direct_access_enabled ? "on" : "off"}</td><td>${s.gateway_enabled ? "on" : "off"}</td><td>${s.command_logging_enabled ? "on" : "off"}</td><td>${s.session_recording_enabled ? "on" : "off"}</td><td>${s.enabled ? "yes" : "no"}</td>
      <td class="text-nowrap">
        <button class="btn btn-sm btn-outline-primary" data-action="test-server" data-id="${s.id}" title="Test connection"><i class="bi bi-plug"></i></button>
        <button class="btn btn-sm btn-outline-secondary ${canAdmin ? "" : "d-none"}" data-action="edit-server" data-id="${s.id}" title="Edit"><i class="bi bi-pencil"></i></button>
        <button class="btn btn-sm btn-outline-warning ${canAdmin ? "" : "d-none"}" data-action="rotate-server-key" data-id="${s.id}" title="Rotate SSH key"><i class="bi bi-arrow-clockwise"></i></button>
        <button class="btn btn-sm btn-outline-danger ${canAdmin ? "" : "d-none"}" data-action="delete-server" data-id="${s.id}" title="Deactivate"><i class="bi bi-x-circle"></i></button>
      </td></tr>`))}`;
  applyClientFilter("serverFilter", ".filter-row");
  $("#requestAccess").onclick = () => openRequestModal();
  if (canAdmin) $("#addServer").onclick = () => openServerModal();
}

function secretName(id) {
  const item = (state.data.secrets || []).find((s) => s.id === id);
  return item ? escapeHtml(item.name) : "";
}

function serverGroupName(id) {
  const item = (state.data.serverGroups || []).find((g) => g.id === id);
  return item ? escapeHtml(item.name) : "";
}

function renderUsers() {
  const canCreate = state.user.role === "admin";
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("userFilter", "Filter users")}<button class="btn btn-primary ${canCreate ? "" : "d-none"}" id="addUser"><i class="bi bi-person-plus"></i> Add</button></div>
    ${table(["Username", "Email", "Global role", "Access groups", "MFA", "Active grants", "Active sessions", "Status", "Actions"], state.data.users.map((u) => `
      <tr class="filter-row"><td>${escapeHtml(u.username)}</td><td>${escapeHtml(u.email)}</td><td><span class="badge text-bg-secondary">${escapeHtml(u.role === "approver" ? "operator" : u.role)}</span></td><td class="wrap">${(u.access_groups || []).map((g) => `<span class="badge text-bg-light me-1">${escapeHtml(g.name)} · ${escapeHtml(g.role)}</span>`).join("") || "—"}</td><td>${u.mfa_enabled ? "enabled" : u.mfa_required ? "required" : "off"}</td><td>${u.active_grant_count || 0}</td><td>${u.active_session_count || 0}</td><td>${u.is_active ? badge("active") : badge("disabled")}</td>
      <td><button class="btn btn-sm btn-outline-primary" data-action="effective-user" data-id="${u.id}" title="Effective permissions"><i class="bi bi-shield-check"></i></button>
      <button class="btn btn-sm btn-outline-secondary ${canCreate ? "" : "d-none"}" data-action="edit-user" data-id="${u.id}" title="Edit"><i class="bi bi-pencil"></i></button>
      <button class="btn btn-sm btn-outline-warning ${canCreate ? "" : "d-none"}" data-action="revoke-user-grants" data-id="${u.id}" title="Revoke all grants"><i class="bi bi-key-fill"></i></button>
      <button class="btn btn-sm btn-outline-warning ${canCreate ? "" : "d-none"}" data-action="terminate-user-sessions" data-id="${u.id}" title="Terminate all sessions"><i class="bi bi-stop-circle"></i></button>
      <button class="btn btn-sm btn-outline-danger ${canCreate ? "" : "d-none"}" data-action="delete-user" data-id="${u.id}" title="Deactivate"><i class="bi bi-x-circle"></i></button></td></tr>`))}`;
  applyClientFilter("userFilter", ".filter-row");
  if (canCreate) $("#addUser").onclick = () => openUserModal();
}

const rbacPermissions = ["servers.view","servers.create","servers.edit","servers.delete","servers.test_connection","servers.assign_to_group","access.request","access.connect","access.connect_direct","access.connect_gateway","access.approve","access.reject","access.revoke","access.extend","access.limited_sudo","access.full_sudo","sessions.view_own","sessions.view_group","sessions.terminate","commands.view_own","commands.view_group","audit.view_group","audit.export","users.view_group","users.manage_group","groups.manage_members","groups.manage_servers","groups.manage_permissions","alerts.view","alerts.manage","secrets.use"];

function renderAccessGroups() {
  const canCreate = state.user.role === "admin";
  const canManage = ["admin", "operator", "approver"].includes(state.user.role);
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("accessGroupFilter", "Filter access groups")}<button id="addAccessGroup" class="btn btn-primary ${canCreate ? "" : "d-none"}"><i class="bi bi-plus-lg"></i> Add group</button></div>
    ${table(["Name", "Environment", "Users", "Servers", "Active grants", "Active sessions", "Controls", "Status", "Actions"], (state.data.accessGroups || []).map((g) => `
      <tr class="filter-row"><td><strong>${escapeHtml(g.name)}</strong><div class="small text-secondary">${escapeHtml(g.description)}</div></td><td>${escapeHtml(g.environment)}</td><td>${g.user_count}</td><td>${g.server_count}</td><td>${g.active_grant_count}</td><td>${g.active_session_count}</td><td class="small">${[g.require_approval?"approval":"",g.require_mfa?"MFA":"",g.require_gateway?"gateway":"",g.require_session_recording?"recording":""].filter(Boolean).join(", ") || "standard"}</td><td>${badge(g.is_active ? "active" : "disabled")}</td><td class="text-nowrap"><button class="btn btn-sm btn-outline-secondary ${canManage ? "" : "d-none"}" data-action="edit-access-group" data-id="${g.id}" title="Members and policy"><i class="bi bi-pencil"></i></button> <button class="btn btn-sm btn-outline-primary ${canManage ? "" : "d-none"}" data-action="permissions-access-group" data-id="${g.id}" title="Permission matrix"><i class="bi bi-grid-3x3-gap"></i></button> <button class="btn btn-sm btn-outline-danger ${canCreate ? "" : "d-none"}" data-action="delete-access-group" data-id="${g.id}" title="Delete or deactivate"><i class="bi bi-x-circle"></i></button></td></tr>`))}`;
  applyClientFilter("accessGroupFilter", ".filter-row");
  if (canCreate) $("#addAccessGroup").onclick = () => openAccessGroupModal();
}

function renderRequests() {
  const canApprove = ["approver", "operator", "admin"].includes(state.user.role);
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("requestFilter", "Filter requests")}<button class="btn btn-primary" id="newRequest"><i class="bi bi-plus-lg"></i> Request</button></div>
    ${table(["ID", "User", "Server", "Type", "Duration", "Risk", "Controls", "Reason", "Status", "Actions"], state.data.requests.map((r) => `
      <tr class="filter-row"><td>#${r.id}</td><td>${escapeHtml(r.username)}</td><td>${escapeHtml(r.server_hostname)}</td><td>${r.requested_access_type}</td><td>${r.requested_duration_minutes}m</td><td>${r.calculated_risk_score || 0}</td><td>${[r.approval_required ? "approval" : "", r.mfa_required ? "mfa" : "", r.session_recording_required ? "recording" : ""].filter(Boolean).join(", ")}</td><td class="wrap">${escapeHtml(r.reason)}</td><td>${badge(r.status)}</td>
      <td class="text-nowrap">
        <button class="btn btn-sm btn-outline-success ${canApprove && r.status === "pending" && r.user_id !== state.user.id ? "" : "d-none"}" data-action="approve-request" data-id="${r.id}" title="Approve"><i class="bi bi-check-lg"></i></button>
        <button class="btn btn-sm btn-outline-danger ${canApprove && r.status === "pending" && r.user_id !== state.user.id ? "" : "d-none"}" data-action="reject-request" data-id="${r.id}" title="Reject"><i class="bi bi-x-lg"></i></button>
      </td></tr>`))}`;
  applyClientFilter("requestFilter", ".filter-row");
  $("#newRequest").onclick = () => openRequestModal();
}

function renderGrants() {
  const canRevoke = ["approver", "operator", "admin"].includes(state.user.role);
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("grantFilter", "Filter grants")}</div>
    ${table(["ID", "User", "Server", "Mode", "Linux user", "Type", "Risk", "Monitoring", "Connect", "Valid to", "Status", "Actions"], state.data.grants.map((g) => `
      <tr class="filter-row"><td>#${g.id}</td><td>${escapeHtml(g.username)}</td><td>${escapeHtml(g.server_hostname)}</td><td>${escapeHtml(g.access_mode)}</td><td><code>${escapeHtml(g.linux_username)}</code></td><td>${g.access_type}</td><td>${g.calculated_risk_score || 0}</td><td>${escapeHtml(g.monitoring_level)}</td><td class="wrap"><code>${escapeHtml(connectionHint(g))}</code></td><td>${fmt(g.valid_to)}</td><td>${badge(g.status)}</td>
      <td class="text-nowrap">
        <button class="btn btn-sm btn-outline-primary ${canRevoke ? "" : "d-none"}" data-action="import-grant-logs" data-id="${g.id}" title="Import logs"><i class="bi bi-arrow-repeat"></i></button>
        <button class="btn btn-sm btn-outline-danger ${canRevoke && g.status === "active" ? "" : "d-none"}" data-action="revoke-grant" data-id="${g.id}" title="Revoke"><i class="bi bi-slash-circle"></i></button>
      </td></tr>`))}`;
  applyClientFilter("grantFilter", ".filter-row");
}

function connectionHint(g) {
  if (g.gateway_session_required) return g.gateway_connection_string || `ssh ${g.gateway_username || g.linux_username}@${state.data.settings.gateway_host} -p ${state.data.settings.gateway_port}`;
  const server = state.data.servers.find((s) => s.id === g.server_id);
  return server ? `ssh ${g.linux_username}@${server.ip_address} -p ${server.ssh_port}` : "";
}

function renderSessions() {
  $("#content").innerHTML = `
    <div class="toolbar">
      ${filterBox("sessionFilter", "Filter sessions")}
      <button class="btn btn-outline-secondary" id="exportSessions"><i class="bi bi-download"></i> Export CSV</button>
    </div>
    ${table(["ID", "Mode", "User", "Linux user", "Server", "Grant", "Client IP", "Target", "Target user", "Recording", "End reason", "Start", "Duration", "Status", "Commands", "Actions"], state.data.sessions.map((s) => `
      <tr class="filter-row"><td>#${s.id}</td><td>${escapeHtml(s.access_mode)}</td><td>${escapeHtml(s.username)}</td><td><code>${escapeHtml(s.linux_username)}</code></td><td>${escapeHtml(s.server_hostname)}</td><td>#${s.grant_id}</td><td>${escapeHtml(s.client_ip || s.source_ip)}</td><td>${escapeHtml(s.target_host || "")}</td><td>${escapeHtml(s.target_user || "")}</td><td>${s.recording_enabled ? "yes" : "no"}</td><td>${escapeHtml(s.termination_reason)}</td><td>${fmt(s.started_at)}</td><td>${s.duration_seconds || ""}s</td><td>${badge(s.status)}</td><td>${s.command_count ?? ""}</td>
      <td><button class="btn btn-sm btn-outline-primary" data-action="view-session" data-id="${s.id}" title="Details"><i class="bi bi-terminal"></i></button>
      <button class="btn btn-sm btn-outline-secondary ${s.session_record_path && !s.session_record_path.startsWith("session_id=") ? "" : "d-none"}" data-action="recording" data-id="${s.id}" title="Recording"><i class="bi bi-play-btn"></i></button></td></tr>`))}`;
  applyClientFilter("sessionFilter", ".filter-row");
  $("#exportSessions").onclick = () => downloadCsv("/api/sessions/export.csv", "sessions.csv");
}

function renderCommands(commands = state.data.commands) {
  $("#content").innerHTML = `
    <div class="toolbar">
      ${filterBox("commandFilter", "Filter commands")}
      <label class="form-check"><input id="sudoOnly" class="form-check-input" type="checkbox"> <span class="form-check-label">sudo only</span></label>
      <button class="btn btn-outline-secondary" id="exportCommands"><i class="bi bi-download"></i> Export CSV</button>
    </div>
    ${table(["User", "Server", "Session", "Grant", "Source", "Linux user", "Command", "Risk", "Severity", "PWD", "sudo", "Exit", "Time", "Raw"], commands.map((c) => `
      <tr class="filter-row" data-sudo="${c.is_sudo ? "1" : "0"}"><td>${escapeHtml(c.username || c.user_id)}</td><td>${escapeHtml(c.server_hostname || c.server_id)}</td><td>#${c.session_id}</td><td>#${c.grant_id}</td><td>${escapeHtml(c.source)}</td><td><code>${escapeHtml(c.linux_username)}</code></td><td class="wrap"><code>${escapeHtml(c.command)}</code></td><td>${c.risk_score || 0}</td><td>${severityBadge(c.risk_severity)}</td><td>${escapeHtml(c.working_directory)}</td><td>${c.is_sudo ? "yes" : "no"}</td><td>${c.exit_code ?? ""}</td><td>${fmt(c.executed_at)}</td><td class="raw-log">${escapeHtml(c.raw_log)}</td></tr>`))}`;
  applyClientFilter("commandFilter", ".filter-row");
  $("#sudoOnly").addEventListener("change", () => {
    document.querySelectorAll(".filter-row").forEach((row) => {
      row.style.display = $("#sudoOnly").checked && row.dataset.sudo !== "1" ? "none" : "";
    });
  });
  $("#exportCommands").onclick = () => downloadCsv("/api/session-commands/export.csv", "session_commands.csv");
}

function renderSessionDetails() {
  const s = state.selectedSession;
  const commands = state.selectedSessionCommands || [];
  const events = (state.data.gatewayEvents || []).filter((e) => e.session_id === s?.id);
  const riskEvents = (state.data.riskEvents || []).filter((e) => e.session_id === s?.id);
  const alerts = (state.data.alerts || []).filter((a) => a.session_id === s?.id);
  const recordings = (state.data.gatewayRecordings || []).filter((r) => r.session_id === s?.id);
  const connection = (state.data.gatewayConnections || []).find((c) => c.session_id === s?.id);
  if (!s) {
    state.view = "sessions";
    render();
    return;
  }
  $("#content").innerHTML = `
    <div class="toolbar">
      <button class="btn btn-outline-secondary" data-action="back-sessions"><i class="bi bi-arrow-left"></i> Sessions</button>
      ${filterBox("sessionCommandFilter", "Filter commands")}
      <label class="form-check"><input id="detailSudoOnly" class="form-check-input" type="checkbox"> <span class="form-check-label">sudo only</span></label>
    </div>
    <div class="table-wrap p-3 mb-3">
      <dl class="row mb-0">
        <dt class="col-sm-3">User</dt><dd class="col-sm-3">${escapeHtml(s.username)}</dd>
        <dt class="col-sm-3">Server</dt><dd class="col-sm-3">${escapeHtml(s.server_hostname)}</dd>
        <dt class="col-sm-3">Grant</dt><dd class="col-sm-3">#${s.grant_id}</dd>
        <dt class="col-sm-3">Access type</dt><dd class="col-sm-3">${escapeHtml(s.access_type)}</dd>
        <dt class="col-sm-3">Start</dt><dd class="col-sm-3">${fmt(s.started_at)}</dd>
        <dt class="col-sm-3">End</dt><dd class="col-sm-3">${fmt(s.ended_at)}</dd>
        <dt class="col-sm-3">Duration</dt><dd class="col-sm-3">${s.duration_seconds || ""}s</dd>
        <dt class="col-sm-3">Source IP</dt><dd class="col-sm-3">${escapeHtml(s.source_ip)}</dd>
        <dt class="col-sm-3">Status</dt><dd class="col-sm-3">${badge(s.status)}</dd>
        <dt class="col-sm-3">Mode</dt><dd class="col-sm-3">${escapeHtml(s.access_mode)}</dd>
        <dt class="col-sm-3">Gateway ID</dt><dd class="col-sm-3">${escapeHtml(s.gateway_session_id)}</dd>
        <dt class="col-sm-3">Target</dt><dd class="col-sm-3">${escapeHtml([s.target_user, s.target_host].filter(Boolean).join("@"))}</dd>
        <dt class="col-sm-3">Bytes</dt><dd class="col-sm-3">${connection ? `${connection.bytes_in} in / ${connection.bytes_out} out` : ""}</dd>
        <dt class="col-sm-3">Termination</dt><dd class="col-sm-3">${escapeHtml(s.termination_reason)}</dd>
        <dt class="col-sm-3">Recording</dt><dd class="col-sm-3">${recordings.map((r) => `<button class="btn btn-sm btn-link p-0" data-action="download-recording" data-id="${r.id}">${escapeHtml(r.recording_type)} ${r.size_bytes}b</button>`).join(", ")}</dd>
      </dl>
    </div>
    ${table(["Time", "Source", "Risk", "Severity", "PWD", "Command", "sudo", "Exit", "Preview", "Raw"], commands.map((c) => `
      <tr class="filter-row" data-sudo="${c.is_sudo ? "1" : "0"}"><td>${fmt(c.executed_at)}</td><td>${escapeHtml(c.source)}</td><td>${c.risk_score || 0}</td><td>${severityBadge(c.risk_severity)}</td><td>${escapeHtml(c.working_directory)}</td><td class="wrap"><code>${escapeHtml(c.command)}</code></td><td>${c.is_sudo ? "yes" : "no"}</td><td>${c.exit_code ?? ""}</td><td class="wrap">${escapeHtml(c.terminal_output_preview)}</td><td class="raw-log">${escapeHtml(c.raw_log)}</td></tr>`))}
    <div class="mt-3">${table(["Risk Event", "Score", "Severity", "Message", "Time"], riskEvents.map((e) => `<tr><td>${escapeHtml(e.event_type)}</td><td>${e.risk_score}</td><td>${severityBadge(e.severity)}</td><td class="wrap">${escapeHtml(e.message)}</td><td>${fmt(e.created_at)}</td></tr>`))}</div>
    <div class="mt-3">${table(["Alert", "Severity", "Status", "Message", "Time"], alerts.map((a) => `<tr><td>${escapeHtml(a.title)}</td><td>${severityBadge(a.severity)}</td><td>${badge(a.status)}</td><td class="wrap">${escapeHtml(a.message)}</td><td>${fmt(a.created_at)}</td></tr>`))}</div>
    <div class="mt-3">${table(["Gateway Event", "Message", "Time"], events.map((e) => `<tr><td>${escapeHtml(e.event_type)}</td><td class="wrap">${escapeHtml(e.message)}</td><td>${fmt(e.created_at)}</td></tr>`))}</div>`;
  applyClientFilter("sessionCommandFilter", ".filter-row");
  $("#detailSudoOnly").addEventListener("change", () => {
    document.querySelectorAll(".filter-row").forEach((row) => {
      row.style.display = $("#detailSudoOnly").checked && row.dataset.sudo !== "1" ? "none" : "";
    });
  });
}

function renderGateway() {
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("gatewayFilter", "Filter gateway")}<button class="btn btn-outline-primary" id="gatewayStepUp"><i class="bi bi-shield-check"></i> Verify MFA for Gateway</button></div>
    ${state.data.settings?.mfa_required_for_gateway ? `<div class="alert alert-warning">Przed polaczeniem SSH wykonaj MFA step-up dla Gateway Access.</div>` : ""}
    ${table(["ID", "User", "Server", "Gateway user", "Target", "Client", "Start", "End", "Status", "Bytes", "Reason", "Actions"], state.data.gatewayConnections.map((c) => `
      <tr class="filter-row"><td>#${c.id}</td><td>${escapeHtml(c.username || c.user_id)}</td><td>${escapeHtml(c.server_hostname || c.server_id)}</td><td><code>${escapeHtml(c.gateway_username)}</code></td><td>${escapeHtml(c.target_user)}@${escapeHtml(c.target_host)}:${c.target_port}</td><td>${escapeHtml(c.client_ip)}:${c.client_port || ""}</td><td>${fmt(c.started_at)}</td><td>${fmt(c.ended_at)}</td><td>${badge(c.status)}</td><td>${c.bytes_in}/${c.bytes_out}</td><td>${escapeHtml(c.termination_reason)}</td><td><button class="btn btn-sm btn-outline-danger ${c.status === "active" ? "" : "d-none"}" data-action="terminate-gateway" data-id="${c.id}" title="Terminate"><i class="bi bi-slash-circle"></i></button></td></tr>`))}
    <div class="mt-3">${table(["Recording", "User", "Server", "Size", "Checksum", "Actions"], state.data.gatewayRecordings.map((r) => `
      <tr class="filter-row"><td>#${r.id}</td><td>${escapeHtml(r.username || r.user_id)}</td><td>${escapeHtml(r.server_hostname || r.server_id)}</td><td>${r.size_bytes}</td><td class="wrap"><code>${escapeHtml(r.checksum_sha256)}</code></td><td><button class="btn btn-sm btn-outline-secondary" data-action="download-recording" data-id="${r.id}"><i class="bi bi-download"></i></button></td></tr>`))}</div>
    <div class="mt-3">${table(["Event", "User", "Server", "Message", "Time"], state.data.gatewayEvents.slice(0, 100).map((e) => `
      <tr class="filter-row"><td>${escapeHtml(e.event_type)}</td><td>${escapeHtml(e.username || e.user_id)}</td><td>${escapeHtml(e.server_hostname || e.server_id)}</td><td class="wrap">${escapeHtml(e.message)}</td><td>${fmt(e.created_at)}</td></tr>`))}</div>`;
  applyClientFilter("gatewayFilter", ".filter-row");
  $("#gatewayStepUp").onclick = () => openStepUpModal("gateway_login", "Gateway access requires MFA step-up");
}

function renderSecrets() {
  const canAdmin = state.user.role === "admin";
  $("#content").innerHTML = `
    <div class="toolbar">
      ${filterBox("secretFilter", "Filter secrets")}
      <button class="btn btn-primary ${canAdmin ? "" : "d-none"}" id="addSecret"><i class="bi bi-plus-lg"></i> Add</button>
    </div>
    ${table(["Name", "Type", "Backend", "Env", "Owner", "Fingerprint", "Version", "Status", "Last rotation", "Next rotation", "Actions"], (state.data.secrets || []).map((s) => `
      <tr class="filter-row"><td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.secret_type)}</td><td>${escapeHtml(s.backend_type)}</td><td>${escapeHtml(s.environment)}</td><td>${escapeHtml(s.owner)}</td><td class="wrap"><code>${escapeHtml(s.fingerprint)}</code></td><td>${s.version}</td><td>${badge(s.status)}</td><td>${fmt(s.last_rotated_at)}</td><td>${fmt(s.next_rotation_at)}</td>
      <td class="text-nowrap"><button class="btn btn-sm btn-outline-primary" data-action="view-secret" data-id="${s.id}" title="Details"><i class="bi bi-eye"></i></button>
      <button class="btn btn-sm btn-outline-secondary ${canAdmin ? "" : "d-none"}" data-action="edit-secret" data-id="${s.id}" title="Edit"><i class="bi bi-pencil"></i></button>
      <button class="btn btn-sm btn-outline-warning ${canAdmin ? "" : "d-none"}" data-action="rotate-secret" data-id="${s.id}" title="Rotate"><i class="bi bi-arrow-clockwise"></i></button>
      <button class="btn btn-sm btn-outline-danger ${canAdmin ? "" : "d-none"}" data-action="disable-secret" data-id="${s.id}" title="Disable"><i class="bi bi-x-circle"></i></button></td></tr>`))}`;
  applyClientFilter("secretFilter", ".filter-row");
  if (canAdmin) $("#addSecret").onclick = () => openSecretModal();
}

function renderSecretDetails() {
  const s = state.selectedSecret;
  if (!s) { state.view = "secrets"; render(); return; }
  $("#content").innerHTML = `
    <div class="toolbar"><button class="btn btn-outline-secondary" data-action="back-secrets"><i class="bi bi-arrow-left"></i> Secrets</button></div>
    <div class="table-wrap p-3 mb-3">
      <dl class="row mb-0">
        <dt class="col-sm-3">Name</dt><dd class="col-sm-3">${escapeHtml(s.name)}</dd>
        <dt class="col-sm-3">Type</dt><dd class="col-sm-3">${escapeHtml(s.secret_type)}</dd>
        <dt class="col-sm-3">Backend</dt><dd class="col-sm-3">${escapeHtml(s.backend_type)}</dd>
        <dt class="col-sm-3">Environment</dt><dd class="col-sm-3">${escapeHtml(s.environment)}</dd>
        <dt class="col-sm-3">Owner</dt><dd class="col-sm-3">${escapeHtml(s.owner)}</dd>
        <dt class="col-sm-3">Version</dt><dd class="col-sm-3">${s.version}</dd>
        <dt class="col-sm-3">Status</dt><dd class="col-sm-3">${badge(s.status)}</dd>
        <dt class="col-sm-3">Fingerprint</dt><dd class="col-sm-3 wrap"><code>${escapeHtml(s.fingerprint)}</code></dd>
      </dl>
    </div>
    ${table(["Version", "Fingerprint", "Status", "Created", "Activated", "Revoked", "Reason", "Actions"], state.selectedSecretVersions.map((v) => `
      <tr><td>${v.version}</td><td class="wrap"><code>${escapeHtml(v.fingerprint)}</code></td><td>${badge(v.status)}</td><td>${fmt(v.created_at)}</td><td>${fmt(v.activated_at)}</td><td>${fmt(v.revoked_at)}</td><td>${escapeHtml(v.rotation_reason)}</td><td><button class="btn btn-sm btn-outline-success ${state.user.role === "admin" ? "" : "d-none"}" data-action="activate-secret-version" data-secret="${s.id}" data-id="${v.id}"><i class="bi bi-check-lg"></i></button> <button class="btn btn-sm btn-outline-danger ${state.user.role === "admin" ? "" : "d-none"}" data-action="revoke-secret-version" data-secret="${s.id}" data-id="${v.id}"><i class="bi bi-x-lg"></i></button></td></tr>`))}
    <div class="mt-3">${table(["Action", "Context", "Success", "Message", "Time"], state.selectedSecretLogs.map((l) => `<tr><td>${escapeHtml(l.action)}</td><td>${escapeHtml(l.access_context)}</td><td>${l.success ? "yes" : "no"}</td><td class="wrap">${escapeHtml(l.message)}</td><td>${fmt(l.created_at)}</td></tr>`))}</div>`;
}

function renderSecretRotation() {
  $("#content").innerHTML = `
    <div class="toolbar"><button class="btn btn-outline-primary" id="runDueRotations"><i class="bi bi-play"></i> Run due</button></div>
    ${table(["Job", "Secret", "Server", "Type", "Status", "Started", "Finished", "Old", "New", "Error"], (state.data.rotationJobs || []).map((j) => `
      <tr><td>#${j.id}</td><td>${escapeHtml(j.secret_name || j.secret_id)}</td><td>${escapeHtml(j.server_hostname || j.server_id)}</td><td>${escapeHtml(j.job_type)}</td><td>${badge(j.status)}</td><td>${fmt(j.started_at)}</td><td>${fmt(j.finished_at)}</td><td class="wrap"><code>${escapeHtml(j.old_fingerprint)}</code></td><td class="wrap"><code>${escapeHtml(j.new_fingerprint)}</code></td><td class="wrap">${escapeHtml(j.error_message)}</td></tr>`))}`;
  $("#runDueRotations").onclick = async () => { await api("/api/secret-rotation/run-due", { method: "POST" }); toast("Done"); await refresh(); };
}

function renderPolicies() {
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("policyFilter", "Filter policies")}<button class="btn btn-primary" id="addPolicy"><i class="bi bi-plus-lg"></i> Add</button></div>
    ${table(["Name", "Role", "Env", "Type", "Max", "Approval", "Cmd log", "Recording", "Enabled", "Actions"], state.data.policies.map((p) => `
      <tr class="filter-row"><td>${escapeHtml(p.name)}</td><td>${p.role}</td><td>${p.environment}</td><td>${p.access_type}</td><td>${p.max_duration_minutes}m</td><td>${p.requires_approval ? "yes" : "no"}</td><td>${p.command_logging_required ? "yes" : "no"}</td><td>${p.session_recording_required ? "yes" : "no"}</td><td>${p.enabled ? "yes" : "no"}</td>
      <td><button class="btn btn-sm btn-outline-secondary" data-action="edit-policy" data-id="${p.id}" title="Edit"><i class="bi bi-pencil"></i></button>
      <button class="btn btn-sm btn-outline-danger" data-action="delete-policy" data-id="${p.id}" title="Disable"><i class="bi bi-x-circle"></i></button></td></tr>`))}`;
  applyClientFilter("policyFilter", ".filter-row");
  $("#addPolicy").onclick = () => openPolicyModal();
}

function renderPolicyRules() {
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("policyRuleFilter", "Filter rules")}<button class="btn btn-primary" id="addPolicyRule"><i class="bi bi-plus-lg"></i> Add</button></div>
    ${table(["Priority", "Name", "Type", "Env", "Role", "Access", "Risk", "Actions JSON", "Enabled", "Actions"], (state.data.policyRules || []).map((r) => `
      <tr class="filter-row"><td>${r.priority}</td><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.rule_type)}</td><td>${escapeHtml(r.environment)}</td><td>${escapeHtml(r.user_role)}</td><td>${escapeHtml(r.access_type)}</td><td>${r.risk_score_delta}</td><td class="wrap"><code>${escapeHtml(r.action_json)}</code></td><td>${r.enabled ? "yes" : "no"}</td>
      <td class="text-nowrap"><button class="btn btn-sm btn-outline-secondary" data-action="edit-policy-rule" data-id="${r.id}" title="Edit"><i class="bi bi-pencil"></i></button>
      <button class="btn btn-sm btn-outline-warning" data-action="${r.enabled ? "disable-policy-rule" : "enable-policy-rule"}" data-id="${r.id}" title="Toggle"><i class="bi bi-power"></i></button>
      <button class="btn btn-sm btn-outline-danger" data-action="delete-policy-rule" data-id="${r.id}" title="Delete"><i class="bi bi-x-circle"></i></button></td></tr>`))}`;
  applyClientFilter("policyRuleFilter", ".filter-row");
  $("#addPolicyRule").onclick = () => openPolicyRuleModal();
}

function renderPolicyTest() {
  const users = state.data.users || [];
  const servers = state.data.servers || [];
  $("#content").innerHTML = `
    <div class="table-wrap p-3">
      <div class="form-grid">
        <div><label class="form-label">User</label><select id="testUser" class="form-select">${users.map((u) => `<option value="${u.id}">${escapeHtml(u.username)} (${u.role})</option>`).join("")}</select></div>
        <div><label class="form-label">Server</label><select id="testServer" class="form-select">${servers.map((s) => `<option value="${s.id}">${escapeHtml(s.hostname)} (${s.environment})</option>`).join("")}</select></div>
        <div><label class="form-label">Access type</label><select id="testType" class="form-select"><option>ssh_only</option><option>limited_sudo</option><option>full_sudo</option></select></div>
        <div><label class="form-label">Duration</label><input id="testDuration" type="number" class="form-control" value="60"></div>
        <div class="span-2"><label class="form-label">Reason</label><input id="testReason" class="form-control" value="Maintenance validation"></div>
        <div class="span-2"><label class="form-label">Command</label><input id="testCommand" class="form-control" placeholder="sudo systemctl status nginx"></div>
      </div>
      <button class="btn btn-primary mt-3" id="runPolicyTest"><i class="bi bi-play"></i> Run</button>
    </div>
    <div id="policyTestResult" class="mt-3"></div>`;
  $("#runPolicyTest").onclick = async () => {
    const result = await api("/api/policy-rules/evaluate-test", { method: "POST", body: JSON.stringify({ user_id: Number(formValue("testUser")), server_id: Number(formValue("testServer")), access_type: formValue("testType"), duration: Number(formValue("testDuration")), reason: formValue("testReason"), command: formValue("testCommand") || null }) });
    $("#policyTestResult").innerHTML = table(["Allowed", "Risk", "Severity", "Controls", "MFA Context", "MFA Reason", "Matched Rules", "Message"], [`<tr><td>${result.allowed ? "yes" : "no"}</td><td>${result.risk_score}</td><td>${severityBadge(result.severity)}</td><td>${[result.requires_approval ? "approval" : "", result.requires_mfa ? "mfa" : "", result.requires_session_recording ? "recording" : "", result.requires_gateway ? "gateway" : ""].filter(Boolean).join(", ")}</td><td>${escapeHtml(result.mfa_context)}</td><td class="wrap">${escapeHtml(result.mfa_reason)}</td><td class="wrap">${escapeHtml((result.matched_rules || []).map((r) => r.name).join(", "))}</td><td class="wrap">${escapeHtml(result.message)}</td></tr>`]);
  };
}

function renderServerGroups() {
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("serverGroupFilter", "Filter groups")}<button class="btn btn-primary" id="addServerGroup"><i class="bi bi-plus-lg"></i> Add</button></div>
    ${table(["Name", "Environment", "Description", "Servers", "Actions"], (state.data.serverGroups || []).map((g) => {
      const members = (state.data.servers || []).filter((s) => s.server_group_id === g.id).map((s) => s.hostname).join(", ");
      return `<tr class="filter-row"><td>${escapeHtml(g.name)}</td><td>${escapeHtml(g.environment)}</td><td class="wrap">${escapeHtml(g.description)}</td><td class="wrap">${escapeHtml(members)}</td><td><button class="btn btn-sm btn-outline-secondary" data-action="edit-server-group" data-id="${g.id}"><i class="bi bi-pencil"></i></button> <button class="btn btn-sm btn-outline-danger" data-action="delete-server-group" data-id="${g.id}"><i class="bi bi-x-circle"></i></button></td></tr>`;
    }))}`;
  applyClientFilter("serverGroupFilter", ".filter-row");
  $("#addServerGroup").onclick = () => openServerGroupModal();
}

function renderRiskEvents() {
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("riskEventFilter", "Filter risk events")}<button class="btn btn-outline-secondary" id="exportRiskEvents"><i class="bi bi-download"></i> Export CSV</button></div>
    ${table(["ID", "Severity", "Score", "Type", "User", "Server", "Grant", "Session", "Command", "Message", "Time"], (state.data.riskEvents || []).map((e) => `
      <tr class="filter-row"><td>#${e.id}</td><td>${severityBadge(e.severity)}</td><td>${e.risk_score}</td><td>${escapeHtml(e.event_type)}</td><td>${linkId("user", e.user_id, e.username)}</td><td>${linkId("server", e.server_id, e.server_hostname)}</td><td>${linkId("grant", e.grant_id)}</td><td>${linkId("session", e.session_id)}</td><td>${e.command_id ? `#${e.command_id}` : ""}</td><td class="wrap">${escapeHtml(e.message)}</td><td>${fmt(e.created_at)}</td></tr>`))}`;
  applyClientFilter("riskEventFilter", ".filter-row");
  $("#exportRiskEvents").onclick = () => downloadCsv("/api/risk-events/export.csv", "risk_events.csv");
}

function renderAlerts() {
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("alertFilter", "Filter alerts")}<button class="btn btn-outline-secondary" id="exportAlerts"><i class="bi bi-download"></i> Export CSV</button></div>
    ${table(["ID", "Severity", "Status", "Type", "Title", "User", "Server", "Grant", "Session", "Message", "Time", "Actions"], (state.data.alerts || []).map((a) => `
      <tr class="filter-row"><td>#${a.id}</td><td>${severityBadge(a.severity)}</td><td>${badge(a.status)}</td><td>${escapeHtml(a.alert_type)}</td><td>${escapeHtml(a.title)}</td><td>${linkId("user", a.user_id, a.username)}</td><td>${linkId("server", a.server_id, a.server_hostname)}</td><td>${linkId("grant", a.grant_id)}</td><td>${linkId("session", a.session_id)}</td><td class="wrap">${escapeHtml(a.message)}</td><td>${fmt(a.created_at)}</td>
      <td class="text-nowrap"><button class="btn btn-sm btn-outline-warning ${a.status === "open" ? "" : "d-none"}" data-action="ack-alert" data-id="${a.id}" title="Acknowledge"><i class="bi bi-eye"></i></button>
      <button class="btn btn-sm btn-outline-success ${["open", "acknowledged"].includes(a.status) ? "" : "d-none"}" data-action="resolve-alert" data-id="${a.id}" title="Resolve"><i class="bi bi-check-lg"></i></button>
      <button class="btn btn-sm btn-outline-danger ${state.user.role === "admin" && a.status !== "dismissed" ? "" : "d-none"}" data-action="dismiss-alert" data-id="${a.id}" title="Dismiss"><i class="bi bi-x-lg"></i></button></td></tr>`))}`;
  applyClientFilter("alertFilter", ".filter-row");
  $("#exportAlerts").onclick = () => downloadCsv("/api/alerts/export.csv", "alerts.csv");
}

function renderMfaSettings() {
  const s = state.data.mfaStatus || {};
  $("#content").innerHTML = `
    <div class="toolbar">
      <button class="btn btn-primary" id="startMfaEnroll"><i class="bi bi-qr-code"></i> Enroll</button>
      <button class="btn btn-outline-primary" id="generateRecovery"><i class="bi bi-key"></i> Recovery codes</button>
      <button class="btn btn-outline-danger" id="disableMfa"><i class="bi bi-shield-x"></i> Disable</button>
    </div>
    <div class="table-wrap p-3">
      <dl class="row mb-0">
        <dt class="col-sm-4">MFA enabled</dt><dd class="col-sm-8">${s.enabled ? "yes" : "no"}</dd>
        <dt class="col-sm-4">MFA required</dt><dd class="col-sm-8">${s.required ? "yes" : "no"}</dd>
        <dt class="col-sm-4">Enrolled</dt><dd class="col-sm-8">${fmt(s.enrolled_at)}</dd>
        <dt class="col-sm-4">Last used</dt><dd class="col-sm-8">${fmt(s.last_used_at)}</dd>
        <dt class="col-sm-4">Recovery codes</dt><dd class="col-sm-8">${s.recovery_codes_remaining || 0}</dd>
      </dl>
    </div>
    <div id="mfaResult" class="mt-3"></div>`;
  $("#startMfaEnroll").onclick = async () => {
    const result = await api("/api/mfa/enroll/start", { method: "POST" });
    $("#mfaResult").innerHTML = `<div class="table-wrap p-3"><p class="mb-2"><strong>Provisioning URI</strong></p><p class="wrap"><code>${escapeHtml(result.provisioning_uri)}</code></p><p class="mb-2"><strong>Manual secret</strong></p><p><code>${escapeHtml(result.secret)}</code></p><div class="input-group"><input id="enrollCode" class="form-control" placeholder="TOTP code"><button id="verifyEnroll" class="btn btn-primary">Verify</button></div></div>`;
    $("#verifyEnroll").onclick = async () => { await api("/api/mfa/enroll/verify", { method: "POST", body: JSON.stringify({ code: formValue("enrollCode"), challenge_id: result.challenge_id }) }); toast("MFA enabled"); await refresh(); };
  };
  $("#generateRecovery").onclick = async () => {
    const result = await api("/api/mfa/recovery-codes/generate", { method: "POST" });
    $("#mfaResult").innerHTML = table(["Recovery codes"], result.codes.map((code) => `<tr><td><code>${escapeHtml(code)}</code></td></tr>`));
  };
  $("#disableMfa").onclick = () => modal("Disable MFA", `<label class="form-label">TOTP code</label><input id="disableMfaCode" class="form-control">`, () => api("/api/mfa/disable", { method: "POST", body: JSON.stringify({ code: formValue("disableMfaCode") }) }));
}

function renderIdentityAdmin() {
  $("#content").innerHTML = `
    <div class="toolbar"><button class="btn btn-outline-primary" id="syncLdap"><i class="bi bi-arrow-repeat"></i> LDAP sync</button></div>
    ${table(["User", "Provider", "External ID", "Role", "MFA", "Required", "Locked", "Last login", "Sync", "Actions"], (state.data.identityUsers || []).map((u) => `
      <tr><td>${escapeHtml(u.username)}</td><td>${escapeHtml(u.auth_provider)}</td><td class="wrap">${escapeHtml(u.external_id)}</td><td>${escapeHtml(u.role)}</td><td>${u.mfa_enabled ? "yes" : "no"}</td><td>${u.mfa_required ? "yes" : "no"}</td><td>${fmt(u.locked_until)}</td><td>${fmt(u.last_login_at)}</td><td>${fmt(u.last_identity_sync_at)}</td>
      <td class="text-nowrap"><button class="btn btn-sm btn-outline-primary" data-action="identity-resync" data-id="${u.id}" title="Resync"><i class="bi bi-arrow-repeat"></i></button>
      <button class="btn btn-sm btn-outline-warning" data-action="identity-lock" data-id="${u.id}" title="Lock"><i class="bi bi-lock"></i></button>
      <button class="btn btn-sm btn-outline-success" data-action="identity-unlock" data-id="${u.id}" title="Unlock"><i class="bi bi-unlock"></i></button>
      <button class="btn btn-sm btn-outline-danger" data-action="identity-reset-mfa" data-id="${u.id}" title="Reset MFA"><i class="bi bi-shield-x"></i></button></td></tr>`))}`;
  $("#syncLdap").onclick = async () => { await api("/api/identity/sync/ldap", { method: "POST" }); toast("LDAP sync completed"); await refresh(); };
}

function renderAuthEvents() {
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("authEventFilter", "Filter auth events")}</div>
    ${table(["Time", "User", "Provider", "Event", "Success", "IP", "Message"], (state.data.authEvents || []).map((e) => `
      <tr class="filter-row"><td>${fmt(e.created_at)}</td><td>${escapeHtml(e.username || e.user_id)}</td><td>${escapeHtml(e.provider)}</td><td>${escapeHtml(e.event_type)}</td><td>${e.success ? "yes" : "no"}</td><td>${escapeHtml(e.source_ip)}</td><td class="wrap">${escapeHtml(e.message)}</td></tr>`))}`;
  applyClientFilter("authEventFilter", ".filter-row");
}

function renderAudit() {
  $("#content").innerHTML = `
    <div class="toolbar">${filterBox("auditFilter", "Filter audit")}<button class="btn btn-outline-secondary" id="exportAudit"><i class="bi bi-download"></i> Export CSV</button></div>
    ${table(["ID", "Action", "User", "Server", "Request", "Grant", "Session", "Message", "IP", "Time"], state.data.audit.map((a) => `
      <tr class="filter-row"><td>#${a.id}</td><td>${escapeHtml(a.action)}</td><td>${linkId("user", a.user_id, a.username)}</td><td>${linkId("server", a.server_id, a.server_hostname)}</td><td>${linkId("request", a.request_id)}</td><td>${linkId("grant", a.grant_id)}</td><td>${linkId("session", a.session_id)}</td><td class="wrap">${escapeHtml(a.message)}</td><td>${escapeHtml(a.source_ip)}</td><td>${fmt(a.created_at)}</td></tr>`))}`;
  applyClientFilter("auditFilter", ".filter-row");
  $("#exportAudit").onclick = () => downloadCsv("/api/audit-logs/export.csv", "audit_logs.csv");
}

function linkId(type, id, label = null) {
  if (!id) return "";
  return `<button class="btn btn-sm btn-link p-0 align-baseline" data-action="jump-${type}" data-id="${id}">${escapeHtml(label || `#${id}`)}</button>`;
}

function renderSettings() {
  const s = state.data.settings;
  $("#content").innerHTML = `<div class="table-wrap p-3">
    <dl class="row mb-0">
      <dt class="col-sm-4">Executor mode</dt><dd class="col-sm-8"><span class="badge text-bg-info">${escapeHtml(s.executor_mode)}</span></dd>
      <dt class="col-sm-4">Session log import</dt><dd class="col-sm-8">${s.session_log_import_enabled ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Session log directory</dt><dd class="col-sm-8"><code>${escapeHtml(s.session_log_dir)}</code></dd>
      <dt class="col-sm-4">Scheduler interval</dt><dd class="col-sm-8">${s.scheduler_interval_seconds}s</dd>
      <dt class="col-sm-4">Access Mode</dt><dd class="col-sm-8">${escapeHtml(s.access_mode)}</dd>
      <dt class="col-sm-4">Gateway enabled</dt><dd class="col-sm-8">${s.gateway_enabled ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Gateway host</dt><dd class="col-sm-8"><code>${escapeHtml(s.gateway_host)}:${s.gateway_port}</code></dd>
      <dt class="col-sm-4">Gateway recording</dt><dd class="col-sm-8">${s.gateway_session_recording ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Gateway command logging</dt><dd class="col-sm-8">${s.gateway_command_logging ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Gateway idle timeout</dt><dd class="col-sm-8">${s.gateway_idle_timeout_seconds}s</dd>
      <dt class="col-sm-4">Gateway max session</dt><dd class="col-sm-8">${s.gateway_max_session_seconds}s</dd>
      <dt class="col-sm-4">Vault mode</dt><dd class="col-sm-8">${escapeHtml(s.vault_mode)}</dd>
      <dt class="col-sm-4">Secret rotation</dt><dd class="col-sm-8">${s.secret_rotation_enabled ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Rotation interval</dt><dd class="col-sm-8">${s.secret_rotation_interval_hours}h</dd>
      <dt class="col-sm-4">SSH key rotation</dt><dd class="col-sm-8">${s.ssh_key_rotation_enabled ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Policy engine</dt><dd class="col-sm-8">${s.policy_engine_enabled ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Risk engine</dt><dd class="col-sm-8">${s.risk_engine_enabled ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Alerts</dt><dd class="col-sm-8">${s.alerts_enabled ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Risk thresholds</dt><dd class="col-sm-8">medium ${s.medium_risk_score}, high ${s.high_risk_score}, critical ${s.critical_risk_score}</dd>
      <dt class="col-sm-4">Auto revoke on critical risk</dt><dd class="col-sm-8">${s.auto_revoke_on_critical_risk ? "enabled" : "disabled"}</dd>
      <dt class="col-sm-4">Auth providers</dt><dd class="col-sm-8">${escapeHtml(s.auth_providers)} (default ${escapeHtml(s.default_auth_provider)})</dd>
      <dt class="col-sm-4">Local authentication</dt><dd class="col-sm-8">${escapeHtml(s.local_auth_mode)}${s.local_auth_mode === "os" ? ` via PAM service <code>${escapeHtml(s.os_pam_service)}</code>` : ""}</dd>
      <dt class="col-sm-4">MFA</dt><dd class="col-sm-8">${s.mfa_enabled ? "enabled" : "disabled"}; issuer ${escapeHtml(s.mfa_issuer)}</dd>
      <dt class="col-sm-4">MFA policies</dt><dd class="col-sm-8">admin ${s.mfa_required_for_admin ? "on" : "off"}, prod ${s.mfa_required_for_prod ? "on" : "off"}, full_sudo ${s.mfa_required_for_full_sudo ? "on" : "off"}, gateway ${s.mfa_required_for_gateway ? "on" : "off"}, rotation ${s.mfa_required_for_secret_rotation ? "on" : "off"}</dd>
      <dt class="col-sm-4">LDAP / OIDC</dt><dd class="col-sm-8">LDAP ${s.ldap_enabled ? "enabled" : "disabled"}, OIDC ${s.oidc_enabled ? "enabled" : "disabled"}</dd>
    </dl>
    <div class="alert alert-warning mt-3 mb-0">For full sudo, bash history logging is not sufficient as a trust boundary. Prefer tlog, auditd, sudo I/O logs, or an SSH gateway.</div>
  </div>`;
}

function render() {
  renderNav();
  setTitle();
  const views = { dashboard: renderDashboard, adminPanel: renderAdminPanel, servers: renderServers, accessGroups: renderAccessGroups, users: renderUsers, requests: renderRequests, grants: renderGrants, sessions: renderSessions, sessionDetails: renderSessionDetails, commands: renderCommands, gateway: renderGateway, secrets: renderSecrets, secretDetails: renderSecretDetails, secretRotation: renderSecretRotation, policies: renderPolicies, policyRules: renderPolicyRules, policyTest: renderPolicyTest, serverGroups: renderServerGroups, riskEvents: renderRiskEvents, alerts: renderAlerts, mfaSettings: renderMfaSettings, identityAdmin: renderIdentityAdmin, authEvents: renderAuthEvents, audit: renderAudit, settings: renderSettings };
  (views[state.view] || renderDashboard)();
}

function formValue(id) {
  const el = document.getElementById(id);
  if (el.type === "checkbox") return el.checked;
  if (el.type === "number") return Number(el.value);
  return el.value;
}

function modal(title, body, onSave) {
  $("#entityModalTitle").textContent = title;
  $("#entityModalBody").innerHTML = body;
  $("#entityModalSave").onclick = async () => {
    try {
      await onSave();
      entityModal.hide();
      toast("Saved");
      await refresh();
    } catch (err) {
      toast(err.message, "danger");
    }
  };
  entityModal.show();
}

function openStepUpModal(context, reason, retry = null) {
  state.pendingStepUpAction = retry;
  modal("MFA Step-up", `
    <div class="alert alert-warning">${escapeHtml(reason || "MFA step-up required")}</div>
    <div><label class="form-label">Code</label><input id="stepUpCode" class="form-control" autocomplete="one-time-code"></div>
    <label class="form-check mt-2"><input id="stepUpRecovery" class="form-check-input" type="checkbox"> <span class="form-check-label">Use recovery code</span></label>`,
    async () => {
      const challenge = await api("/api/mfa/step-up", { method: "POST", body: JSON.stringify({ context, reason }) });
      await api("/api/mfa/verify", { method: "POST", body: JSON.stringify({ challenge_id: challenge.id, code: formValue("stepUpCode"), recovery_code: formValue("stepUpRecovery") }) });
      if (state.pendingStepUpAction) await state.pendingStepUpAction();
    }
  );
}

async function handleStepUpError(err, retry = null) {
  const detail = err.detail;
  if (detail && typeof detail === "object" && ["step_up_required", "mfa_enrollment_required"].includes(detail.code)) {
    if (detail.code === "mfa_enrollment_required") {
      toast(detail.message || "MFA enrollment required", "warning");
      state.view = "mfaSettings";
      render();
      return true;
    }
    openStepUpModal(detail.context, detail.message, retry);
    return true;
  }
  return false;
}

function openRequestModal() {
  modal("Request Access", `
    <div class="form-grid">
      <div><label class="form-label">Server</label><select id="reqServer" class="form-select">${state.data.servers.map((s) => `<option value="${s.id}">${escapeHtml(s.hostname)} (${escapeHtml(s.environment)})</option>`).join("")}</select></div>
      <div><label class="form-label">Access type</label><select id="reqType" class="form-select"><option>ssh_only</option><option>limited_sudo</option><option>full_sudo</option></select></div>
      <div><label class="form-label">Duration</label><select id="reqDuration" class="form-select"><option>15</option><option>30</option><option>60</option><option>120</option><option>240</option><option>480</option></select></div>
      <div class="span-2"><label class="form-label">Reason</label><textarea id="reqReason" class="form-control" rows="3">Maintenance task</textarea></div>
      <div class="span-2 alert alert-warning mb-0">Full sudo can bypass bash history logging. Prefer tlog, auditd, sudo I/O logs, or an SSH gateway for high-trust recording.</div>
    </div>`,
    () => api("/api/access-requests", { method: "POST", body: JSON.stringify({ server_id: Number(formValue("reqServer")), reason: formValue("reqReason"), requested_duration_minutes: Number(formValue("reqDuration")), requested_access_type: formValue("reqType") }) })
  );
}

function openServerModal(server = {}) {
  const secretOptions = `<option value="">None</option>${(state.data.secrets || []).map((s) => `<option value="${s.id}">${escapeHtml(s.name)} (${escapeHtml(s.backend_type)})</option>`).join("")}`;
  modal(server.id ? "Edit Server" : "Add Server", `
    <div class="form-grid">
      <div><label class="form-label">Hostname</label><input id="serverHostname" class="form-control" value="${escapeHtml(server.hostname || "")}"></div>
      <div><label class="form-label">Display name</label><input id="serverDisplayName" class="form-control" value="${escapeHtml(server.display_name || "")}"></div>
      <div><label class="form-label">IP address</label><input id="serverIp" class="form-control" value="${escapeHtml(server.ip_address || "")}"></div>
      <div><label class="form-label">SSH port</label><input id="serverPort" type="number" class="form-control" value="${server.ssh_port || 22}"></div>
      <div><label class="form-label">Environment</label><input id="serverEnv" class="form-control" value="${escapeHtml(server.environment || "dev")}"></div>
      <div><label class="form-label">Owner</label><input id="serverOwner" class="form-control" value="${escapeHtml(server.owner || "")}"></div>
      <div><label class="form-label">Criticality</label><select id="serverCriticality" class="form-select">${["low", "medium", "high", "critical"].map((v) => `<option ${server.criticality === v ? "selected" : ""}>${v}</option>`).join("")}</select></div>
      <div><label class="form-label">Risk level</label><select id="serverRisk" class="form-select">${["low", "medium", "high", "critical"].map((v) => `<option ${server.risk_level === v ? "selected" : ""}>${v}</option>`).join("")}</select></div>
      <div><label class="form-label">Admin user</label><input id="serverAdmin" class="form-control" value="${escapeHtml(server.ssh_admin_user || "root")}"></div>
      <div><label class="form-label">Authentication</label><select id="serverAuthType" class="form-select">${[["vault_secret","Vault secret"],["vault_key","Vault private key"],["agent","SSH agent"],["none","None"]].map(([value,label]) => `<option value="${value}" ${server.ssh_auth_type === value ? "selected" : ""}>${label}</option>`).join("")}</select></div>
      <div><label class="form-label">Gateway target user</label><input id="serverGatewayUser" class="form-control" value="${escapeHtml(server.gateway_target_user || "")}"></div>
      <div><label class="form-label">SSH auth secret</label><select id="serverSshSecret" class="form-select">${secretOptions}</select></div>
      <div><label class="form-label">Gateway secret</label><select id="serverGatewaySecret" class="form-select">${secretOptions}</select></div>
      <div class="span-2"><label class="form-label">Server groups</label><select id="serverAccessGroups" class="form-select" multiple size="5">${(state.data.accessGroups || []).map((g) => `<option value="${g.id}" ${(server.access_group_ids || []).includes(g.id) ? "selected" : ""}>${escapeHtml(g.name)} · ${escapeHtml(g.environment)}</option>`).join("")}</select><div class="form-text">Credentials and private keys must come from Secrets Vault; they are never entered here.</div></div>
      <div class="span-2"><label class="form-label">Description</label><textarea id="serverDescription" class="form-control">${escapeHtml(server.description || "")}</textarea></div>
      <div class="form-check"><input id="serverEnabled" class="form-check-input" type="checkbox" ${(server.enabled ?? true) ? "checked" : ""}><label class="form-check-label">Enabled</label></div>
      <div class="form-check"><input id="serverCmdLog" class="form-check-input" type="checkbox" ${(server.command_logging_enabled ?? true) ? "checked" : ""}><label class="form-check-label">Command logging</label></div>
      <div class="form-check"><input id="serverRecording" class="form-check-input" type="checkbox" ${server.session_recording_enabled ? "checked" : ""}><label class="form-check-label">Session recording</label></div>
      <div class="form-check"><input id="serverGateway" class="form-check-input" type="checkbox" ${(server.gateway_enabled ?? true) ? "checked" : ""}><label class="form-check-label">Gateway enabled</label></div>
      <div class="form-check"><input id="serverDirect" class="form-check-input" type="checkbox" ${(server.direct_access_enabled ?? true) ? "checked" : ""}><label class="form-check-label">Direct access enabled</label></div>
      <div class="form-check"><input id="serverRotation" class="form-check-input" type="checkbox" ${(server.rotation_enabled ?? true) ? "checked" : ""}><label class="form-check-label">Rotation enabled</label></div>
      <div class="form-check"><input id="serverReqApproval" class="form-check-input" type="checkbox" ${server.require_approval ? "checked" : ""}><label class="form-check-label">Require approval</label></div>
      <div class="form-check"><input id="serverReqRecording" class="form-check-input" type="checkbox" ${server.require_session_recording ? "checked" : ""}><label class="form-check-label">Require recording</label></div>
      <div class="form-check"><input id="serverReqMfa" class="form-check-input" type="checkbox" ${server.require_mfa ? "checked" : ""}><label class="form-check-label">Require MFA</label></div>
    </div>`,
    () => api(server.id ? `/api/servers/${server.id}` : "/api/servers", { method: server.id ? "PATCH" : "POST", body: JSON.stringify({ hostname: formValue("serverHostname"), display_name: formValue("serverDisplayName") || null, ip_address: formValue("serverIp"), ssh_port: formValue("serverPort"), environment: formValue("serverEnv"), owner: formValue("serverOwner"), description: formValue("serverDescription"), enabled: formValue("serverEnabled"), ssh_admin_user: formValue("serverAdmin"), ssh_auth_type: formValue("serverAuthType"), command_logging_enabled: formValue("serverCmdLog"), session_recording_enabled: formValue("serverRecording"), gateway_enabled: formValue("serverGateway"), gateway_target_user: formValue("serverGatewayUser"), gateway_auth_type: "key", direct_access_enabled: formValue("serverDirect"), ssh_auth_secret_id: Number(formValue("serverSshSecret")) || null, secret_ref_id: Number(formValue("serverSshSecret")) || null, gateway_secret_ref_id: Number(formValue("serverGatewaySecret")) || null, rotation_enabled: formValue("serverRotation"), risk_level: formValue("serverRisk"), criticality: formValue("serverCriticality"), access_group_ids: [...document.getElementById("serverAccessGroups").selectedOptions].map((item) => Number(item.value)), require_approval: formValue("serverReqApproval"), require_session_recording: formValue("serverReqRecording"), require_mfa: formValue("serverReqMfa") }) })
  );
  setTimeout(() => {
    if (server.ssh_auth_secret_id || server.secret_ref_id) $("#serverSshSecret").value = server.ssh_auth_secret_id || server.secret_ref_id;
    if (server.gateway_secret_ref_id) $("#serverGatewaySecret").value = server.gateway_secret_ref_id;
  });
}

function openUserModal(user = {}) {
  modal(user.id ? "Edit User" : "Add User", `
    <div class="form-grid">
      <div><label class="form-label">Username</label><input id="userUsername" class="form-control" value="${escapeHtml(user.username || "")}" ${user.id ? "disabled" : ""}></div>
      <div><label class="form-label">Email</label><input id="userEmail" class="form-control" value="${escapeHtml(user.email || "")}"></div>
      <div><label class="form-label">Role</label><select id="userRole" class="form-select">${["user", "operator", "admin"].map((r) => `<option ${(user.role === r || (user.role === "approver" && r === "operator")) ? "selected" : ""}>${r}</option>`).join("")}</select></div>
      <div><label class="form-label">Password</label><input id="userPassword" class="form-control" type="password"></div>
      <div><label class="form-label">Risk level</label><select id="userRisk" class="form-select">${["low", "medium", "high", "critical"].map((r) => `<option ${user.risk_level === r ? "selected" : ""}>${r}</option>`).join("")}</select></div>
      <div class="span-2"><label class="form-label">SSH public key</label><textarea id="userSshKey" class="form-control" rows="3">${escapeHtml(user.ssh_public_key || "")}</textarea></div>
      <div class="form-check"><input id="userActive" class="form-check-input" type="checkbox" ${(user.is_active ?? true) ? "checked" : ""}><label class="form-check-label">Active</label></div>
      <div class="form-check"><input id="userMfa" class="form-check-input" type="checkbox" ${user.mfa_enabled ? "checked" : ""}><label class="form-check-label">MFA enabled</label></div>
    </div>`,
    () => {
      const payload = { email: formValue("userEmail"), role: formValue("userRole"), is_active: formValue("userActive"), ssh_public_key: formValue("userSshKey"), mfa_enabled: formValue("userMfa"), risk_level: formValue("userRisk") };
      if (!user.id) payload.username = formValue("userUsername");
      if (formValue("userPassword")) payload.password = formValue("userPassword");
      return api(user.id ? `/api/users/${user.id}` : "/api/users", { method: user.id ? "PUT" : "POST", body: JSON.stringify(payload) });
    }
  );
}

function openPolicyModal(policy = {}) {
  modal(policy.id ? "Edit Policy" : "Add Policy", `
    <div class="form-grid">
      <div><label class="form-label">Name</label><input id="policyName" class="form-control" value="${escapeHtml(policy.name || "")}"></div>
      <div><label class="form-label">Role</label><select id="policyRole" class="form-select">${["user", "approver", "admin"].map((r) => `<option ${policy.role === r ? "selected" : ""}>${r}</option>`).join("")}</select></div>
      <div><label class="form-label">Environment</label><input id="policyEnv" class="form-control" value="${escapeHtml(policy.environment || "dev")}"></div>
      <div><label class="form-label">Access type</label><select id="policyType" class="form-select">${["ssh_only", "limited_sudo", "full_sudo"].map((r) => `<option ${policy.access_type === r ? "selected" : ""}>${r}</option>`).join("")}</select></div>
      <div><label class="form-label">Max duration</label><input id="policyMax" type="number" class="form-control" value="${policy.max_duration_minutes || 60}"></div>
      <div class="form-check mt-4"><input id="policyApproval" class="form-check-input" type="checkbox" ${(policy.requires_approval ?? true) ? "checked" : ""}><label class="form-check-label">Requires approval</label></div>
      <div class="form-check"><input id="policyCmd" class="form-check-input" type="checkbox" ${(policy.command_logging_required ?? true) ? "checked" : ""}><label class="form-check-label">Command logging required</label></div>
      <div class="form-check"><input id="policyRecording" class="form-check-input" type="checkbox" ${policy.session_recording_required ? "checked" : ""}><label class="form-check-label">Session recording required</label></div>
      <div class="form-check"><input id="policyEnabled" class="form-check-input" type="checkbox" ${(policy.enabled ?? true) ? "checked" : ""}><label class="form-check-label">Enabled</label></div>
    </div>`,
    () => api(policy.id ? `/api/policies/${policy.id}` : "/api/policies", { method: policy.id ? "PUT" : "POST", body: JSON.stringify({ name: formValue("policyName"), role: formValue("policyRole"), environment: formValue("policyEnv"), access_type: formValue("policyType"), max_duration_minutes: formValue("policyMax"), requires_approval: formValue("policyApproval"), command_logging_required: formValue("policyCmd"), session_recording_required: formValue("policyRecording"), enabled: formValue("policyEnabled") }) })
  );
}

function openPolicyRuleModal(rule = {}) {
  const condition = rule.condition_json || "{}";
  const action = rule.action_json || '{"require_approval": true}';
  modal(rule.id ? "Edit Policy Rule" : "Add Policy Rule", `
    <div class="form-grid">
      <div><label class="form-label">Name</label><input id="ruleName" class="form-control" value="${escapeHtml(rule.name || "")}"></div>
      <div><label class="form-label">Type</label><select id="ruleType" class="form-select">${["access_request", "approval", "grant", "session_start", "command", "gateway_login", "secret_use", "revoke"].map((t) => `<option ${rule.rule_type === t ? "selected" : ""}>${t}</option>`).join("")}</select></div>
      <div><label class="form-label">Priority</label><input id="rulePriority" type="number" class="form-control" value="${rule.priority || 100}"></div>
      <div><label class="form-label">Risk delta</label><input id="ruleRisk" type="number" class="form-control" value="${rule.risk_score_delta || 0}"></div>
      <div><label class="form-label">Environment</label><input id="ruleEnv" class="form-control" value="${escapeHtml(rule.environment || "")}" placeholder="prod or *"></div>
      <div><label class="form-label">User role</label><input id="ruleRole" class="form-control" value="${escapeHtml(rule.user_role || "")}" placeholder="user, approver, admin"></div>
      <div><label class="form-label">Server group</label><input id="ruleGroup" class="form-control" value="${escapeHtml(rule.server_group || "")}"></div>
      <div><label class="form-label">Access type</label><input id="ruleAccess" class="form-control" value="${escapeHtml(rule.access_type || "")}" placeholder="ssh_only, limited_sudo, full_sudo"></div>
      <div class="span-2"><label class="form-label">Description</label><textarea id="ruleDesc" class="form-control">${escapeHtml(rule.description || "")}</textarea></div>
      <div class="span-2"><label class="form-label">Condition JSON</label><textarea id="ruleCondition" class="form-control" rows="4">${escapeHtml(condition)}</textarea></div>
      <div class="span-2"><label class="form-label">Action JSON</label><textarea id="ruleAction" class="form-control" rows="4">${escapeHtml(action)}</textarea></div>
      <div class="form-check"><input id="ruleEnabled" class="form-check-input" type="checkbox" ${(rule.enabled ?? true) ? "checked" : ""}><label class="form-check-label">Enabled</label></div>
    </div>`,
    () => {
      JSON.parse(formValue("ruleCondition") || "{}");
      JSON.parse(formValue("ruleAction") || "{}");
      return api(rule.id ? `/api/policy-rules/${rule.id}` : "/api/policy-rules", { method: rule.id ? "PUT" : "POST", body: JSON.stringify({ name: formValue("ruleName"), description: formValue("ruleDesc"), rule_type: formValue("ruleType"), priority: Number(formValue("rulePriority")), enabled: formValue("ruleEnabled"), environment: formValue("ruleEnv") || null, user_role: formValue("ruleRole") || null, server_group: formValue("ruleGroup") || null, access_type: formValue("ruleAccess") || null, condition_json: formValue("ruleCondition") || null, action_json: formValue("ruleAction") || null, risk_score_delta: Number(formValue("ruleRisk")) }) });
    }
  );
}

function openServerGroupModal(group = {}) {
  const serverOptions = (state.data.servers || []).map((s) => `<option value="${s.id}" ${s.server_group_id === group.id ? "selected" : ""}>${escapeHtml(s.hostname)} (${escapeHtml(s.environment)})</option>`).join("");
  modal(group.id ? "Edit Server Group" : "Add Server Group", `
    <div class="form-grid">
      <div><label class="form-label">Name</label><input id="groupName" class="form-control" value="${escapeHtml(group.name || "")}"></div>
      <div><label class="form-label">Environment</label><input id="groupEnv" class="form-control" value="${escapeHtml(group.environment || "")}"></div>
      <div class="span-2"><label class="form-label">Servers</label><select id="groupServers" class="form-select" multiple size="6">${serverOptions}</select></div>
      <div class="span-2"><label class="form-label">Description</label><textarea id="groupDesc" class="form-control">${escapeHtml(group.description || "")}</textarea></div>
    </div>`,
    async () => {
      const saved = await api(group.id ? `/api/server-groups/${group.id}` : "/api/server-groups", { method: group.id ? "PUT" : "POST", body: JSON.stringify({ name: formValue("groupName"), environment: formValue("groupEnv") || null, description: formValue("groupDesc") }) });
      const selected = [...document.getElementById("groupServers").selectedOptions].map((option) => Number(option.value));
      for (const server of state.data.servers || []) {
        if (server.server_group_id === saved.id && !selected.includes(server.id)) await api(`/api/server-groups/${saved.id}/servers/${server.id}`, { method: "DELETE" });
        if (selected.includes(server.id)) await api(`/api/server-groups/${saved.id}/servers/${server.id}`, { method: "POST" });
      }
    }
  );
}

async function openAccessGroupModal(group = {}) {
  const [members, assignedServers, groupPermissions] = group.id ? await Promise.all([api(`/api/access-groups/${group.id}/users`).catch(() => []), api(`/api/access-groups/${group.id}/servers`).catch(() => []), api(`/api/access-groups/${group.id}/permissions`).catch(() => [])]) : [[], [], []];
  const memberIds = new Set(members.map((item) => item.user_id));
  const serverIds = new Set(assignedServers.map((item) => item.id));
  const userOptions = (state.data.users || []).map((u) => `<option value="${u.id}" ${memberIds.has(u.id) ? "selected" : ""}>${escapeHtml(u.username)} · ${escapeHtml(u.email)}</option>`).join("");
  const serverOptions = (state.data.servers || []).map((s) => `<option value="${s.id}" ${serverIds.has(s.id) ? "selected" : ""}>${escapeHtml(s.hostname)} · ${escapeHtml(s.environment)}</option>`).join("");
  const templateOptions = [`<option value="">Role defaults</option>`, ...(state.data.permissionTemplates || []).map((item) => `<option value="${item.id}">${escapeHtml(item.name)}</option>`)].join("");
  const copyOptions = `<option value="">Do not copy</option>${(state.data.accessGroups || []).filter((item) => item.id !== group.id).map((item) => `<option value="${item.id}">${escapeHtml(item.name)}</option>`).join("")}`;
  const relatedGrants = (state.data.grants || []).filter((item) => serverIds.has(item.server_id));
  const relatedSessions = (state.data.sessions || []).filter((item) => serverIds.has(item.server_id));
  const relatedAudit = (state.data.audit || []).filter((item) => serverIds.has(item.server_id) || String(item.metadata_json || "").includes(`\"group_id\": ${group.id}`));
  modal(group.id ? `Access group: ${group.name}` : "New access group", `
    <ul class="nav nav-tabs mb-3 flex-nowrap overflow-auto">${[["summary","Summary"],["users","Users"],["servers","Servers"],["policy","Access policy"],["permissions","Permissions"],["grants","Active grants"],["sessions","Sessions"],["audit","Audit log"]].map(([id,label], index) => `<li class="nav-item"><button type="button" class="nav-link ag-tab ${index ? "" : "active"}" data-ag-tab="${id}">${label}</button></li>`).join("")}</ul>
    <div class="form-grid">
      <div><label class="form-label">Name</label><input id="agName" class="form-control" value="${escapeHtml(group.name || "")}"></div>
      <div><label class="form-label">Environment</label><input id="agEnvironment" class="form-control" value="${escapeHtml(group.environment || "")}"></div>
      <div class="span-2"><label class="form-label">Description</label><textarea id="agDescription" class="form-control">${escapeHtml(group.description || "")}</textarea></div>
      <div><label class="form-label">Allowed access types</label><input id="agTypes" class="form-control" value="${escapeHtml(group.allowed_access_types || "ssh_only")}" placeholder="ssh_only,limited_sudo"></div>
      <div><label class="form-label">Allowed durations</label><input id="agDurations" class="form-control" value="${escapeHtml(group.allowed_durations || "30,60")}" placeholder="30,60,120"></div>
      <div><label class="form-label">Maximum grant (minutes)</label><input id="agMaxGrant" type="number" class="form-control" value="${group.max_grant_minutes || 60}"></div>
      <div><label class="form-label">Minimum reason length</label><input id="agReasonLength" type="number" class="form-control" value="${group.min_reason_length ?? 10}"></div>
      <div><label class="form-label">Allowed hours (UTC)</label><input id="agHours" class="form-control" value="${escapeHtml(group.allowed_hours || "")}" placeholder="8-18"></div>
      <div><label class="form-label">Allowed weekdays</label><input id="agWeekdays" class="form-control" value="${escapeHtml(group.allowed_weekdays || "0,1,2,3,4,5,6")}"></div>
      <div><label class="form-label">Max concurrent grants</label><input id="agMaxGrants" type="number" class="form-control" value="${group.max_concurrent_grants || 1}"></div>
      <div><label class="form-label">Max active sessions</label><input id="agMaxSessions" type="number" class="form-control" value="${group.max_active_sessions || 1}"></div>
      <div><label class="form-label">Copy policy and permissions from</label><select id="agCopySource" class="form-select">${copyOptions}</select></div>
      <div class="form-check"><input id="agActive" class="form-check-input" type="checkbox" ${(group.is_active ?? true) ? "checked" : ""}><label class="form-check-label">Active</label></div>
      <div class="form-check"><input id="agApproval" class="form-check-input" type="checkbox" ${(group.require_approval ?? true) ? "checked" : ""}><label class="form-check-label">Require approval</label></div>
      <div class="form-check"><input id="agMfa" class="form-check-input" type="checkbox" ${group.require_mfa ? "checked" : ""}><label class="form-check-label">Require MFA</label></div>
      <div class="form-check"><input id="agGateway" class="form-check-input" type="checkbox" ${group.require_gateway ? "checked" : ""}><label class="form-check-label">Require gateway</label></div>
      <div class="form-check"><input id="agDenyDirect" class="form-check-input" type="checkbox" ${group.deny_direct_ssh ? "checked" : ""}><label class="form-check-label">Deny direct SSH</label></div>
      <div class="form-check"><input id="agCommands" class="form-check-input" type="checkbox" ${(group.require_command_logging ?? true) ? "checked" : ""}><label class="form-check-label">Require command logging</label></div>
      <div class="form-check"><input id="agRecording" class="form-check-input" type="checkbox" ${group.require_session_recording ? "checked" : ""}><label class="form-check-label">Require recording</label></div>
      <div class="span-2 border-top pt-3"><label class="form-label">Users</label><select id="agUsers" class="form-select" multiple size="7">${userOptions}</select></div>
      <div><label class="form-label">Role for selected users</label><select id="agUserRole" class="form-select">${["user","operator","custom","auditor","group_admin"].map((role) => `<option>${role}</option>`).join("")}</select></div>
      <div><label class="form-label">Permission template</label><select id="agTemplate" class="form-select">${templateOptions}</select></div>
      <div class="span-2"><label class="form-label">Servers</label><select id="agServers" class="form-select" multiple size="7">${serverOptions}</select></div>
    </div>
    <div id="agRelatedPanels" class="d-none">
      <section data-ag-panel="permissions">${table(["Permission","Effect","Scope"], groupPermissions.map((item) => `<tr><td><code>${escapeHtml(item.permission)}</code></td><td>${badge(item.effect)}</td><td>${item.membership_id ? `membership #${item.membership_id}` : "group"}</td></tr>`))}</section>
      <section data-ag-panel="grants">${table(["ID","User","Server","Type","Valid to","Status"], relatedGrants.map((item) => `<tr><td>#${item.id}</td><td>${escapeHtml(item.username)}</td><td>${escapeHtml(item.server_hostname)}</td><td>${escapeHtml(item.access_type)}</td><td>${fmt(item.valid_to)}</td><td>${badge(item.status)}</td></tr>`))}</section>
      <section data-ag-panel="sessions">${table(["ID","User","Server","Started","Status"], relatedSessions.map((item) => `<tr><td>#${item.id}</td><td>${escapeHtml(item.username)}</td><td>${escapeHtml(item.server_hostname)}</td><td>${fmt(item.started_at)}</td><td>${badge(item.status)}</td></tr>`))}</section>
      <section data-ag-panel="audit">${table(["Time","Action","Actor","Message"], relatedAudit.slice(0,100).map((item) => `<tr><td>${fmt(item.created_at)}</td><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.username)}</td><td>${escapeHtml(item.message)}</td></tr>`))}</section>
    </div>`, async () => {
      const payload = {name:formValue("agName"),description:formValue("agDescription")||null,environment:formValue("agEnvironment")||null,is_active:formValue("agActive"),allowed_access_types:formValue("agTypes"),allowed_durations:formValue("agDurations"),max_grant_minutes:formValue("agMaxGrant"),min_reason_length:formValue("agReasonLength"),allowed_hours:formValue("agHours")||null,allowed_weekdays:formValue("agWeekdays"),max_concurrent_grants:formValue("agMaxGrants"),max_active_sessions:formValue("agMaxSessions"),require_approval:formValue("agApproval"),require_mfa:formValue("agMfa"),require_gateway:formValue("agGateway"),deny_direct_ssh:formValue("agDenyDirect"),require_command_logging:formValue("agCommands"),require_session_recording:formValue("agRecording")};
      const saved = await api(group.id ? `/api/access-groups/${group.id}` : "/api/access-groups", {method:group.id?"PATCH":"POST",body:JSON.stringify(payload)});
      const copySource = Number(formValue("agCopySource")) || null;
      if (copySource) await api(`/api/access-groups/${saved.id}/copy-settings/${copySource}`, {method:"POST"});
      const selectedUsers = [...document.getElementById("agUsers").selectedOptions].map((item) => Number(item.value));
      const selectedServers = [...document.getElementById("agServers").selectedOptions].map((item) => Number(item.value));
      const removedUsers = members.filter((item) => !selectedUsers.includes(item.user_id));
      for (const item of removedUsers) await api(`/api/access-groups/${saved.id}/users/${item.user_id}`, {method:"DELETE"});
      if (selectedUsers.length) await api(`/api/access-groups/${saved.id}/users`, {method:"POST",body:JSON.stringify({user_ids:selectedUsers,group_role:formValue("agUserRole"),permission_template_id:Number(formValue("agTemplate"))||null,is_active:true})});
      for (const item of assignedServers) if (!selectedServers.includes(item.id)) await api(`/api/access-groups/${saved.id}/servers/${item.id}`, {method:"DELETE"});
      if (selectedServers.length) await api(`/api/access-groups/${saved.id}/servers`, {method:"POST",body:JSON.stringify({server_ids:selectedServers})});
    });
  const fieldsByTab = {
    users: new Set(["agUsers", "agUserRole", "agTemplate"]),
    servers: new Set(["agServers"]),
    summary: new Set(["agName", "agEnvironment", "agDescription", "agActive"]),
  };
  const formChildren = [...document.querySelectorAll("#entityModalBody .form-grid > div")];
  const switchTab = (tab) => {
    document.querySelectorAll(".ag-tab").forEach((item) => item.classList.toggle("active", item.dataset.agTab === tab));
    const isRelated = ["permissions", "grants", "sessions", "audit"].includes(tab);
    $("#agRelatedPanels").classList.toggle("d-none", !isRelated);
    document.querySelectorAll("[data-ag-panel]").forEach((item) => item.classList.toggle("d-none", item.dataset.agPanel !== tab));
    formChildren.forEach((item) => {
      const inputId = item.querySelector("input,select,textarea")?.id;
      const visible = !isRelated && (tab === "policy" ? ![...fieldsByTab.summary, ...fieldsByTab.users, ...fieldsByTab.servers].includes(inputId) : fieldsByTab[tab]?.has(inputId));
      item.classList.toggle("d-none", !visible);
    });
  };
  document.querySelectorAll(".ag-tab").forEach((item) => item.addEventListener("click", () => switchTab(item.dataset.agTab)));
  switchTab("summary");
}

async function openPermissionMatrix(group) {
  const [rows, members] = await Promise.all([api(`/api/server-groups/${group.id}/permissions`), api(`/api/server-groups/${group.id}/users`)]);
  const effects = Object.fromEntries(rows.map((row) => [row.permission, row.effect]));
  const matrixPermissions = (state.data.permissionCatalog || []).map((item) => item.code);
  const memberData = await Promise.all(members.map(async (member) => {
    const [overrides, effective] = await Promise.all([api(`/api/server-groups/${group.id}/users/${member.user_id}/permissions`), api(`/api/server-groups/${group.id}/users/${member.user_id}/effective-permissions`)]);
    return {member, overrides:Object.fromEntries(overrides.map((row) => [row.permission,row.effect])), effective:Object.fromEntries(effective.map((row) => [row.permission,row]))};
  }));
  const picker = (permission, effect, scope, userId="") => `<select class="form-select form-select-sm permission-effect" data-permission="${permission}" data-scope="${scope}" data-user-id="${userId}"><option value="">Inherited</option><option value="allow" ${effect==="allow"?"selected":""}>Allow</option><option value="deny" ${effect==="deny"?"selected":""}>Deny</option></select>`;
  const head = `<th>Permission</th><th>Group</th>${memberData.map(({member}) => `<th>${escapeHtml(member.username)}<div class="small text-secondary">${escapeHtml(member.group_role)}</div></th>`).join("")}`;
  const body = matrixPermissions.map((permission) => `<tr><td><code>${escapeHtml(permission)}</code></td><td>${picker(permission,effects[permission],"group")}</td>${memberData.map(({member,overrides,effective}) => `<td>${picker(permission,overrides[permission],"user",member.user_id)}<div class="small ${effective[permission]?.effect === "allow" ? "text-success" : "text-danger"}">${effective[permission]?.effect || "deny"} · ${escapeHtml(effective[permission]?.source || "default_deny")}</div></td>`).join("")}</tr>`).join("");
  modal(`Access matrix: ${group.name}`, `<div class="alert alert-info">Deny always wins. Inherited shows the effective role/group result and its source.</div><div class="table-responsive"><table class="table table-sm align-middle"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`, async () => {
    const payload = [...document.querySelectorAll('.permission-effect[data-scope="group"]')].filter((item) => item.value).map((item) => ({permission:item.dataset.permission,effect:item.value}));
    await api(`/api/server-groups/${group.id}/permissions`, {method:"PUT",body:JSON.stringify(payload)});
    for (const {member} of memberData) {
      const overrides = [...document.querySelectorAll(`.permission-effect[data-user-id="${member.user_id}"]`)].filter((item) => item.value).map((item) => ({permission:item.dataset.permission,effect:item.value}));
      await api(`/api/server-groups/${group.id}/users/${member.user_id}/permissions`, {method:"PUT",body:JSON.stringify(overrides)});
    }
  });
}

async function showEffectivePermissions(user) {
  const rows = await api(`/api/users/${user.id}/effective-permissions`);
  modal(`Effective permissions: ${user.username}`, table(["Permission","Decision","Source group","Group role","Source","Reason"], rows.map((item) => `<tr><td><code>${escapeHtml(item.permission)}</code></td><td>${badge(item.effect)}</td><td>${escapeHtml(item.group_name)}</td><td>${escapeHtml(item.group_role)}</td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.reason)}</td></tr>`)), async () => {});
  $("#entityModalSave").classList.add("d-none");
  document.getElementById("entityModal").addEventListener("hidden.bs.modal", () => $("#entityModalSave").classList.remove("d-none"), {once:true});
}

function openSecretModal(secret = {}) {
  modal(secret.id ? "Edit Secret Metadata" : "Create Secret", `
    <div class="form-grid">
      <div><label class="form-label">Name</label><input id="secretName" class="form-control" value="${escapeHtml(secret.name || "")}"></div>
      <div><label class="form-label">Type</label><select id="secretType" class="form-select">${["ssh_private_key", "ssh_public_key", "password", "api_token", "gateway_host_key", "target_connection_key", "service_account_password", "generic"].map((t) => `<option ${secret.secret_type === t ? "selected" : ""}>${t}</option>`).join("")}</select></div>
      <div><label class="form-label">Backend</label><select id="secretBackend" class="form-select" ${secret.id ? "disabled" : ""}>${["local_encrypted", "file_reference", "external_vault"].map((t) => `<option ${secret.backend_type === t ? "selected" : ""}>${t}</option>`).join("")}</select></div>
      <div><label class="form-label">Environment</label><input id="secretEnv" class="form-control" value="${escapeHtml(secret.environment || "dev")}"></div>
      <div><label class="form-label">Owner</label><input id="secretOwner" class="form-control" value="${escapeHtml(secret.owner || "")}"></div>
      <div><label class="form-label">Public key</label><input id="secretPublic" class="form-control" value="${escapeHtml(secret.public_key || "")}"></div>
      <div class="span-2"><label class="form-label">File path / external ref</label><input id="secretRef" class="form-control" placeholder="${secret.id ? "Set a new reference" : ""}"></div>
      <div class="span-2"><label class="form-label">Secret value</label><textarea id="secretValue" class="form-control" rows="4" placeholder="Never shown again after save"></textarea></div>
      <div class="span-2"><label class="form-label">Description</label><textarea id="secretDesc" class="form-control">${escapeHtml(secret.description || "")}</textarea></div>
    </div>`,
    () => {
      const backend = formValue("secretBackend");
      const payload = { name: formValue("secretName"), secret_type: formValue("secretType"), backend_type: backend, environment: formValue("secretEnv"), owner: formValue("secretOwner"), description: formValue("secretDesc"), public_key: formValue("secretPublic") || null };
      if (backend === "file_reference") payload.file_path = formValue("secretRef");
      else if (backend === "external_vault") payload.external_ref = formValue("secretRef");
      if (formValue("secretValue")) payload.value = formValue("secretValue");
      return api(secret.id ? `/api/secrets/${secret.id}` : "/api/secrets", { method: secret.id ? "PUT" : "POST", body: JSON.stringify(payload) });
    }
  );
}

async function downloadCsv(path, filename) {
  let csv;
  try {
    csv = await api(path);
  } catch (err) {
    if (await handleStepUpError(err, () => downloadCsv(path, filename))) return;
    throw err;
  }
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function downloadFile(path, filename) {
  const headers = {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err = new Error(typeof body.detail === "object" ? body.detail.message : body.detail || `HTTP ${res.status}`);
    err.detail = body.detail;
    if (await handleStepUpError(err, () => downloadFile(path, filename))) return;
    throw err;
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

document.body.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const id = Number(button.dataset.id);
  const action = button.dataset.action;
  try {
    if (action === "test-server") await api(`/api/servers/${id}/test-connection`, { method: "POST" });
    if (action === "edit-server") openServerModal(state.data.servers.find((x) => x.id === id));
    if (action === "rotate-server-key") await api(`/api/secret-rotation/servers/${id}/rotate-ssh-key`, { method: "POST" });
    if (action === "delete-server") {
      if (!confirm("Deactivate this server?")) return;
      await api(`/api/servers/${id}`, { method: "DELETE" });
    }
    if (action === "edit-user") openUserModal(state.data.users.find((x) => x.id === id));
    if (action === "delete-user") {
      if (!confirm("Deactivate this user?")) return;
      await api(`/api/users/${id}`, { method: "DELETE" });
    }
    if (action === "revoke-user-grants") {
      if (!confirm("Revoke every active grant for this user?")) return;
      await api(`/api/users/${id}/revoke-grants`, {method:"POST"});
    }
    if (action === "terminate-user-sessions") {
      if (!confirm("Terminate every active session for this user?")) return;
      await api(`/api/users/${id}/terminate-sessions`, {method:"POST"});
    }
    if (action === "effective-user") { await showEffectivePermissions(state.data.users.find((x) => x.id === id)); return; }
    if (action === "edit-access-group") { await openAccessGroupModal(state.data.accessGroups.find((x) => x.id === id)); return; }
    if (action === "permissions-access-group") { await openPermissionMatrix(state.data.accessGroups.find((x) => x.id === id)); return; }
    if (action === "delete-access-group") {
      const group = state.data.accessGroups.find((x) => x.id === id);
      if (!confirm(`Delete or deactivate access group "${group.name}"?`)) return;
      await api(`/api/access-groups/${id}`, {method:"DELETE"});
    }
    if (action === "approve-request") await api(`/api/access-requests/${id}/approve`, { method: "POST", body: JSON.stringify({ approver_comment: "Approved from UI" }) });
    if (action === "reject-request") await api(`/api/access-requests/${id}/reject`, { method: "POST", body: JSON.stringify({ approver_comment: "Rejected from UI" }) });
    if (action === "import-grant-logs") await api(`/api/access-grants/${id}/import-logs`, { method: "POST" });
    if (action === "revoke-grant") await api(`/api/access-grants/${id}/revoke`, { method: "POST", body: JSON.stringify({ reason: "Revoked from UI" }) });
    if (action === "view-session") {
      state.selectedSession = await api(`/api/sessions/${id}`);
      const commands = await api(`/api/sessions/${id}/commands`);
      state.selectedSessionCommands = commands;
      state.view = "sessionDetails";
      renderNav();
      setTitle();
      renderSessionDetails();
      return;
    }
    if (action === "back-sessions") {
      state.view = "sessions";
      render();
      return;
    }
    if (action === "recording") {
      const result = await api(`/api/sessions/${id}/recording`);
      toast(result.detail ? `${result.detail.type}: ${result.detail.path}` : result.message, "info");
      return;
    }
    if (action === "edit-policy") openPolicyModal(state.data.policies.find((x) => x.id === id));
    if (action === "delete-policy") await api(`/api/policies/${id}`, { method: "DELETE" });
    if (action === "edit-policy-rule") openPolicyRuleModal(state.data.policyRules.find((x) => x.id === id));
    if (action === "enable-policy-rule") await api(`/api/policy-rules/${id}/enable`, { method: "POST" });
    if (action === "disable-policy-rule") await api(`/api/policy-rules/${id}/disable`, { method: "POST" });
    if (action === "delete-policy-rule") await api(`/api/policy-rules/${id}`, { method: "DELETE" });
    if (action === "edit-server-group") openServerGroupModal(state.data.serverGroups.find((x) => x.id === id));
    if (action === "delete-server-group") await api(`/api/server-groups/${id}`, { method: "DELETE" });
    if (action === "ack-alert") await api(`/api/alerts/${id}/acknowledge`, { method: "POST" });
    if (action === "resolve-alert") await api(`/api/alerts/${id}/resolve`, { method: "POST" });
    if (action === "dismiss-alert") await api(`/api/alerts/${id}/dismiss`, { method: "POST" });
    if (action === "jump-session") {
      state.selectedSession = await api(`/api/sessions/${id}`);
      state.selectedSessionCommands = await api(`/api/sessions/${id}/commands`);
      state.view = "sessionDetails";
      render();
      return;
    }
    if (action === "jump-grant") { state.view = "grants"; render(); return; }
    if (action === "jump-request") { state.view = "requests"; render(); return; }
    if (action === "jump-server") { state.view = "servers"; render(); return; }
    if (action === "jump-user" && state.user.role === "admin") { state.view = "users"; render(); return; }
    if (action === "terminate-gateway") await api(`/api/gateway/connections/${id}/terminate`, { method: "POST" });
    if (action === "download-recording") {
      await downloadFile(`/api/gateway/recordings/${id}/download`, `gateway_recording_${id}.log`);
      return;
    }
    if (action === "view-secret") {
      state.selectedSecret = await api(`/api/secrets/${id}`);
      state.selectedSecretVersions = await api(`/api/secrets/${id}/versions`);
      state.selectedSecretLogs = state.user.role === "admin" ? await api(`/api/secrets/${id}/access-logs`) : [];
      state.view = "secretDetails";
      render();
      return;
    }
    if (action === "edit-secret") openSecretModal(state.data.secrets.find((x) => x.id === id));
    if (action === "disable-secret") await api(`/api/secrets/${id}/disable`, { method: "POST" });
    if (action === "rotate-secret") await api(`/api/secrets/${id}/rotate`, { method: "POST" });
    if (action === "back-secrets") { state.view = "secrets"; render(); return; }
    if (action === "activate-secret-version") await api(`/api/secrets/${button.dataset.secret}/versions/${id}/activate`, { method: "POST" });
    if (action === "revoke-secret-version") await api(`/api/secrets/${button.dataset.secret}/versions/${id}/revoke`, { method: "POST" });
    if (action === "identity-resync") await api(`/api/identity/users/${id}/resync`, { method: "POST" });
    if (action === "identity-lock") await api(`/api/identity/users/${id}/lock`, { method: "POST" });
    if (action === "identity-unlock") await api(`/api/identity/users/${id}/unlock`, { method: "POST" });
    if (action === "identity-reset-mfa") await api(`/api/identity/users/${id}/reset-mfa`, { method: "POST" });
    if (!action.startsWith("edit-")) {
      toast("Done");
      await refresh();
    }
  } catch (err) {
    if (await handleStepUpError(err, async () => button.click())) return;
    toast(err.message, "danger");
  }
});

function showLogin() {
  $("#loginView").classList.remove("d-none");
  $("#appView").classList.add("d-none");
}

async function showApp() {
  state.user = await api("/api/auth/me");
  $("#currentUser").textContent = `${state.user.username} · ${state.user.role}`;
  $("#loginView").classList.add("d-none");
  $("#appView").classList.remove("d-none");
  await refresh();
}

function updateLoginProviderFields() {
  const oidc = $("#loginProvider").value === "oidc";
  $("#loginUsernameField").classList.toggle("d-none", oidc);
  $("#loginPasswordField").classList.toggle("d-none", oidc);
  $("#loginUsername").required = !oidc;
  $("#loginPassword").required = !oidc;
}

$("#loginProvider").addEventListener("change", updateLoginProviderFields);
updateLoginProviderFields();

$("#loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const provider = $("#loginProvider").value;
    if (provider === "oidc") {
      const result = await api("/api/auth/oidc/login", { auth: false });
      if (result.detail.url.startsWith("/api/")) {
        const token = await api(result.detail.url, { auth: false });
        state.token = token.access_token;
        localStorage.setItem("pam_token", state.token);
        await showApp();
        return;
      }
      window.location.href = result.detail.url;
      return;
    }
    const result = await api("/api/auth/login", { auth: false, method: "POST", body: JSON.stringify({ username: $("#loginUsername").value, password: $("#loginPassword").value, provider }) });
    if (result.mfa_required) {
      state.pendingMfaLogin = result;
      $("#loginForm").classList.add("d-none");
      $("#mfaLoginForm").classList.remove("d-none");
      return;
    }
    state.token = result.access_token;
    localStorage.setItem("pam_token", state.token);
    await showApp();
  } catch (err) {
    toast(err.message, "danger");
  }
});

$("#mfaLoginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await api("/api/mfa/verify", { auth: false, method: "POST", body: JSON.stringify({ mfa_token: state.pendingMfaLogin?.mfa_token, challenge_id: state.pendingMfaLogin?.challenge_id, code: $("#loginMfaCode").value, recovery_code: $("#loginRecoveryCode").checked }) });
    state.token = result.access_token;
    localStorage.setItem("pam_token", state.token);
    state.pendingMfaLogin = null;
    $("#mfaLoginForm").classList.add("d-none");
    $("#loginForm").classList.remove("d-none");
    await showApp();
  } catch (err) {
    toast(err.message, "danger");
  }
});

$("#logoutBtn").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } catch (_) {}
  localStorage.removeItem("pam_token");
  state.token = null;
  showLogin();
});

$("#themeToggle").addEventListener("click", () => {
  const html = document.documentElement;
  html.dataset.bsTheme = html.dataset.bsTheme === "dark" ? "light" : "dark";
});

$("#mobileMenu").addEventListener("click", () => $(".sidebar").classList.toggle("open"));

if (state.token) {
  showApp().catch(() => showLogin());
} else {
  showLogin();
}
