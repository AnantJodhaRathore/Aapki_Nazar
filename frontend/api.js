const API_BASE = "";

async function apiRequest(endpoint, options = {}) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        "Content-Type": "application/json",
        ...options.headers
      },
      ...options
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP error ${res.status}`);
    }

    const contentType = res.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      return await res.json();
    }
    return res;
  } catch (err) {
    console.error(`API Error on ${endpoint}:`, err.message);
    throw err;
  }
}

const api = {
  getDashboard: () => apiRequest("/dashboard"),
  getIncidents: (query = {}) => {
    const params = new URLSearchParams(query);
    return apiRequest(`/incidents?${params.toString()}`);
  },
  getIncidentById: (id) => apiRequest(`/incidents/${id}`),
  createIncident: (data) => apiRequest("/incidents", {
    method: "POST",
    body: JSON.stringify(data)
  }),
  updateIncident: (id, updates) => apiRequest(`/incidents/${id}`, {
    method: "PUT",
    body: JSON.stringify(updates)
  }),
  deleteIncident: (id) => apiRequest(`/incidents/${id}`, {
    method: "DELETE"
  }),
  addComment: (id, text, author = "Security-Analyst") => apiRequest(`/incidents/${id}/comments`, {
    method: "POST",
    body: JSON.stringify({ note: text, author })
  }),
  quickAction: (id, action, meta = {}) => apiRequest(`/incidents/${id}/quick-action`, {
    method: "POST",
    body: JSON.stringify({ action, ...meta })
  }),
  analyzeLogs: (logs) => apiRequest("/analyze-logs", {
    method: "POST",
    body: JSON.stringify({ logs })
  }),
  // Simulator Endpoints
  getSimulatorStatus: () => apiRequest("/api/simulator/status"),
  startSimulator: (interval = 1500, attackRatio = 0.35) => apiRequest("/api/simulator/start", {
    method: "POST",
    body: JSON.stringify({ interval, attackRatio })
  }),
  stopSimulator: () => apiRequest("/api/simulator/stop", {
    method: "POST"
  }),
  getRules: () => apiRequest("/api/rules"),
  containIncident: (id, ip) => apiRequest(`/api/containment/${id}/contain`, {
    method: "POST",
    body: JSON.stringify({ ip })
  })
};

window.api = api;
