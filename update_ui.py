import re

with open("frontend/app.js", "r", encoding="utf-8") as f:
    content = f.read()

# Replace renderPolicies
new_render_policies = """
let selectedPolicyCategory = "Authentication & Access";
let selectedPolicyDef = null;
let selectedPolicyInst = null;

function renderPolicies() {
  const defs = state.data.policyDefinitions || [];
  const insts = state.data.policies || [];
  
  const categories = [...new Set(defs.map(d => d.category))].sort();
  if (!categories.includes(selectedPolicyCategory) && categories.length > 0) {
    selectedPolicyCategory = categories[0];
  }
  
  const filteredDefs = defs.filter(d => d.category === selectedPolicyCategory);
  
  // 3-panel layout: Left: Categories (25%), Middle: Policies (40%), Right: Details (35%)
  $("#content").innerHTML = `
    <div class="d-flex h-100 w-100" style="overflow: hidden; background: var(--bg); border: 1px solid var(--border); border-radius: 6px;">
      <!-- Categories Panel -->
      <div class="border-end" style="width: 25%; overflow-y: auto; background: var(--surface);">
        <div class="p-3 border-bottom text-muted fw-bold text-uppercase" style="font-size: 0.85rem;"><i class="bi bi-folder-fill me-2"></i>Categories</div>
        <div class="list-group list-group-flush">
          ${categories.map(c => `
            <button class="list-group-item list-group-item-action ${c === selectedPolicyCategory ? 'active' : ''}" 
                    onclick="selectedPolicyCategory='${escapeHtml(c)}'; selectedPolicyDef=null; renderPolicies();">
              <i class="bi bi-folder me-2"></i>${escapeHtml(c)}
            </button>
          `).join("")}
        </div>
      </div>
      
      <!-- Policies List Panel -->
      <div class="border-end d-flex flex-column" style="width: 40%; background: var(--bg);">
        <div class="p-3 border-bottom text-muted fw-bold text-uppercase d-flex justify-content-between align-items-center" style="font-size: 0.85rem;">
          <span><i class="bi bi-list-ul me-2"></i>Policies</span>
          <span class="badge bg-secondary">${filteredDefs.length}</span>
        </div>
        <div class="list-group list-group-flush flex-grow-1" style="overflow-y: auto;">
          ${filteredDefs.map(d => {
            // Find active policies for this definition
            const activeCount = insts.filter(i => i.policy_id === d.policy_id && i.status === 'enabled').length;
            const isSelected = selectedPolicyDef && selectedPolicyDef.policy_id === d.policy_id;
            return `
              <button class="list-group-item list-group-item-action ${isSelected ? 'active' : ''}"
                      onclick="selectedPolicyDef=${escapeHtml(JSON.stringify(d))}; selectedPolicyInst=null; renderPolicies();">
                <div class="fw-bold">${escapeHtml(d.name)}</div>
                <div class="d-flex justify-content-between align-items-center mt-1">
                  <small class="${isSelected ? 'text-white-50' : 'text-muted'}">${escapeHtml(d.policy_id)}</small>
                  ${activeCount > 0 ? `<span class="badge bg-success rounded-pill">${activeCount} active</span>` : `<span class="badge bg-secondary rounded-pill">Not configured</span>`}
                </div>
              </button>
            `;
          }).join("")}
          ${filteredDefs.length === 0 ? '<div class="p-4 text-center text-muted">No policies in this category</div>' : ''}
        </div>
      </div>
      
      <!-- Details Panel -->
      <div class="d-flex flex-column" style="width: 35%; background: var(--surface);">
        ${renderPolicyDetails(insts)}
      </div>
    </div>
  `;
}

function renderPolicyDetails(insts) {
  if (!selectedPolicyDef) {
    return `<div class="d-flex h-100 align-items-center justify-content-center text-muted"><div class="text-center"><i class="bi bi-sliders fs-1 mb-3 d-block"></i>Select a policy to view or edit details</div></div>`;
  }
  
  const d = selectedPolicyDef;
  const policyInsts = insts.filter(i => i.policy_id === d.policy_id).sort((a, b) => a.priority - b.priority);
  
  if (selectedPolicyInst !== null) {
      // Edit / Create Form
      const i = selectedPolicyInst;
      const isNew = !i.id;
      return `
        <div class="p-3 border-bottom d-flex justify-content-between align-items-center bg-light">
          <span class="fw-bold"><i class="bi ${isNew ? 'bi-plus-circle' : 'bi-pencil'} me-2"></i>${isNew ? 'New Rule' : 'Edit Rule'}</span>
          <button class="btn btn-sm btn-close" onclick="selectedPolicyInst=null; renderPolicies();"></button>
        </div>
        <div class="p-4 flex-grow-1" style="overflow-y: auto;">
          <form id="policyForm" onsubmit="event.preventDefault(); savePolicyInst();">
            <input type="hidden" id="pol_id" value="${i.id || ''}">
            <input type="hidden" id="pol_policy_id" value="${d.policy_id}">
            
            <div class="mb-3">
              <label class="form-label">Status</label>
              <select class="form-select" id="pol_status">
                <option value="enabled" ${i.status === 'enabled' ? 'selected' : ''}>Enabled</option>
                <option value="disabled" ${i.status !== 'enabled' ? 'selected' : ''}>Disabled</option>
              </select>
            </div>
            
            <div class="mb-3">
              <label class="form-label">Value (JSON format)</label>
              <textarea class="form-control font-monospace" id="pol_value_json" rows="3" required>${escapeHtml(i.value_json || JSON.stringify(d.default_value))}</textarea>
              <div class="form-text">Type: ${d.type}</div>
            </div>
            
            <div class="mb-3">
              <label class="form-label">Scope Type</label>
              <select class="form-select" id="pol_scope_type" onchange="document.getElementById('targetDiv').style.display = this.value === 'global' ? 'none' : 'block';">
                ${['global', 'user', 'group', 'resource', 'resource_type', 'protocol', 'gateway'].map(s => `<option value="${s}" ${i.scope_type === s ? 'selected' : ''}>${s}</option>`).join('')}
              </select>
            </div>
            
            <div class="mb-3" id="targetDiv" style="display: ${i.scope_type === 'global' ? 'none' : 'block'};">
              <label class="form-label">Scope Target</label>
              <input type="text" class="form-control" id="pol_scope_target" value="${escapeHtml(i.scope_target || '')}" placeholder="e.g. prod, admin-group, ssh">
            </div>
            
            <div class="mb-3">
              <label class="form-label">Priority</label>
              <input type="number" class="form-control" id="pol_priority" value="${i.priority || 100}" required min="1" max="999">
              <div class="form-text">Lower number = higher priority</div>
            </div>
            
            <div class="mb-3">
              <label class="form-label">Description</label>
              <input type="text" class="form-control" id="pol_description" value="${escapeHtml(i.description || '')}">
            </div>
            
            <button type="submit" class="btn btn-primary w-100"><i class="bi bi-save me-2"></i>Save Rule</button>
            ${!isNew ? `<button type="button" class="btn btn-outline-danger w-100 mt-2" onclick="deletePolicyInst(${i.id})"><i class="bi bi-trash me-2"></i>Delete Rule</button>` : ''}
          </form>
        </div>
      `;
  }
  
  return `
    <div class="p-4 border-bottom">
      <h5 class="fw-bold mb-2">${escapeHtml(d.name)}</h5>
      <p class="text-muted small mb-3">${escapeHtml(d.description)}</p>
      <div class="d-flex align-items-center mb-1"><span class="badge bg-light text-dark me-2 border">ID</span> <code>${escapeHtml(d.policy_id)}</code></div>
      <div class="d-flex align-items-center mb-1"><span class="badge bg-light text-dark me-2 border">Default</span> <code>${escapeHtml(JSON.stringify(d.default_value))}</code></div>
    </div>
    <div class="p-0 flex-grow-1" style="overflow-y: auto;">
      <div class="p-3 border-bottom d-flex justify-content-between align-items-center bg-light">
        <span class="fw-bold fs-6">Configured Rules</span>
        <button class="btn btn-sm btn-primary" onclick="selectedPolicyInst={scope_type: 'global', status: 'enabled'}; renderPolicies();"><i class="bi bi-plus-lg"></i> Add Rule</button>
      </div>
      <div class="list-group list-group-flush">
        ${policyInsts.map(i => `
          <button class="list-group-item list-group-item-action p-3" onclick="selectedPolicyInst=${escapeHtml(JSON.stringify(i))}; renderPolicies();">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <span class="badge ${i.status === 'enabled' ? 'bg-success' : 'bg-secondary'}">${i.status}</span>
              <span class="badge bg-info text-dark">Priority: ${i.priority}</span>
            </div>
            <div class="mb-2"><strong>Scope:</strong> ${i.scope_type === 'global' ? 'Global' : `${i.scope_type} = ${escapeHtml(i.scope_target)}`}</div>
            <div class="mb-2"><strong>Value:</strong> <code>${escapeHtml(i.value_json)}</code></div>
            ${i.description ? `<div class="text-muted small"><em>${escapeHtml(i.description)}</em></div>` : ''}
          </button>
        `).join("")}
        ${policyInsts.length === 0 ? '<div class="p-4 text-center text-muted">No rules configured. System will use default value.</div>' : ''}
      </div>
    </div>
  `;
}

async function savePolicyInst() {
  const id = $("#pol_id").value;
  const payload = {
    policy_id: $("#pol_policy_id").value,
    status: $("#pol_status").value,
    value_json: $("#pol_value_json").value,
    scope_type: $("#pol_scope_type").value,
    scope_target: $("#pol_scope_target").value || null,
    priority: parseInt($("#pol_priority").value, 10),
    description: $("#pol_description").value || null,
    exceptions_json: "[]"
  };
  
  try {
    JSON.parse(payload.value_json);
  } catch (e) {
    toast("Invalid JSON in Value", "danger");
    return;
  }
  
  if (payload.scope_type !== 'global' && !payload.scope_target) {
    toast("Scope target is required when scope type is not global", "danger");
    return;
  }

  if (id) {
    await api(`/api/policies/${id}`, { method: "PUT", body: JSON.stringify(payload) });
    toast("Rule updated");
  } else {
    await api("/api/policies", { method: "POST", body: JSON.stringify(payload) });
    toast("Rule created");
  }
  selectedPolicyInst = null;
  await refresh();
}

async function deletePolicyInst(id) {
  if (!confirm("Delete this rule?")) return;
  await api(`/api/policies/${id}`, { method: "DELETE" });
  toast("Rule deleted");
  selectedPolicyInst = null;
  await refresh();
}
"""

content = re.sub(r'function renderPolicies\(\) \{.*?(?=function renderPolicyRules\(\) \{)', new_render_policies, content, flags=re.DOTALL)

# Now remove the old functions renderPolicyRules, renderPolicyTest
content = re.sub(r'function renderPolicyRules\(\) \{.*?(?=function renderRiskEvents\(\) \{)', '', content, flags=re.DOTALL)

with open("frontend/app.js", "w", encoding="utf-8") as f:
    f.write(content)
