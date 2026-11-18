let timelineChartInstance = null;
let vectorChartInstance = null;

// Chart default palette aligned to Aapki Nazar design system
const CHART_DEFAULTS = {
  grid: "rgba(255, 255, 255, 0.04)",
  tick: "#475569",
  label: "#64748b",
  font_ui: "Space Grotesk",
  font_mono: "JetBrains Mono"
};

function initCharts() {
  const ctxTimeline = document.getElementById("timelineChart");
  const ctxVector   = document.getElementById("vectorChart");
  if (!ctxTimeline || !ctxVector) return;

  const ctxT = ctxTimeline.getContext("2d");
  
  // Create beautiful gradients
  const gradientRed = ctxT.createLinearGradient(0, 0, 0, 350);
  gradientRed.addColorStop(0, "rgba(220, 38, 38, 0.35)");
  gradientRed.addColorStop(1, "rgba(220, 38, 38, 0.0)");

  const gradientPurple = ctxT.createLinearGradient(0, 0, 0, 350);
  gradientPurple.addColorStop(0, "rgba(139, 92, 246, 0.2)");
  gradientPurple.addColorStop(1, "rgba(139, 92, 246, 0.0)");

  // 1. Timeline — Threat Velocity Line Chart
  timelineChartInstance = new Chart(ctxTimeline, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Threats Blocked",
          data: [],
          borderColor: "#dc2626",
          backgroundColor: gradientRed,
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          pointHoverRadius: 6,
          pointBackgroundColor: "#dc2626",
          pointBorderColor: "#fff",
          pointBorderWidth: 2
        },
        {
          label: "Total Traffic",
          data: [],
          borderColor: "#8b5cf6",
          backgroundColor: gradientPurple,
          fill: true,
          tension: 0.4,
          borderWidth: 1.5,
          borderDash: [5, 5],
          pointRadius: 0,
          pointHoverRadius: 4,
          pointBackgroundColor: "#8b5cf6"
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          labels: {
            color: CHART_DEFAULTS.label,
            font: { family: CHART_DEFAULTS.font_ui, size: 11, weight: "500" },
            usePointStyle: true,
            boxWidth: 8,
            padding: 20
          }
        },
        tooltip: {
          backgroundColor: "rgba(17, 17, 20, 0.95)",
          borderColor: "rgba(139, 92, 246, 0.4)",
          borderWidth: 1,
          titleColor: "#f8fafc",
          bodyColor: "#cbd5e1",
          titleFont: { family: CHART_DEFAULTS.font_ui, size: 13, weight: "700" },
          bodyFont: { family: CHART_DEFAULTS.font_mono, size: 12 },
          padding: 12,
          cornerRadius: 8,
          boxPadding: 4,
          usePointStyle: true
        }
      },
      scales: {
        x: {
          grid: { color: CHART_DEFAULTS.grid, drawBorder: false, borderDash: [4, 4] },
          ticks: { color: CHART_DEFAULTS.tick, font: { family: CHART_DEFAULTS.font_mono, size: 10 }, maxRotation: 0, autoSkipPadding: 20 }
        },
        y: {
          grid: { color: CHART_DEFAULTS.grid, drawBorder: false },
          ticks: { color: CHART_DEFAULTS.tick, font: { family: CHART_DEFAULTS.font_mono, size: 10 }, padding: 10 },
          beginAtZero: true
        }
      }
    }
  });

  // 2. Attack Vector — Doughnut Chart
  vectorChartInstance = new Chart(ctxVector, {
    type: "doughnut",
    data: {
      labels: ["No Active Threats"],
      datasets: [
        {
          data: [1],
          backgroundColor: ["rgba(139, 92, 246, 0.15)"],
          borderWidth: 2,
          borderColor: "rgba(139, 92, 246, 0.3)",
          hoverOffset: 4,
          borderRadius: 4
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      layout: {
        padding: { top: 10, bottom: 10 }
      },
      plugins: {
        legend: {
          position: "right",
          labels: {
            color: CHART_DEFAULTS.label,
            font: { family: CHART_DEFAULTS.font_ui, size: 11.5, weight: "500" },
            usePointStyle: true,
            boxWidth: 8,
            padding: 14
          }
        },
        tooltip: {
          backgroundColor: "rgba(17, 17, 20, 0.95)",
          borderColor: "rgba(139, 92, 246, 0.4)",
          borderWidth: 1,
          titleColor: "#f8fafc",
          bodyColor: "#cbd5e1",
          titleFont: { family: CHART_DEFAULTS.font_ui, size: 13, weight: "700" },
          bodyFont: { family: CHART_DEFAULTS.font_mono, size: 12 },
          padding: 12,
          cornerRadius: 8,
          usePointStyle: true,
          boxPadding: 4,
          callbacks: {
            label: function(context) {
              const label = context.label || '';
              const value = context.raw || 0;
              if (label === "No Active Threats") return " No Active Threats";
              const dataset = context.dataset;
              const total = dataset.data.reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
              return ` ${label}: ${value} (${percentage}%)`;
            }
          }
        }
      },
      cutout: "75%"
    }
  });
}

function updateCharts(data) {
  if (!data) return;

  if (vectorChartInstance) {
    const breakdown = data.attackTypeBreakdown || {};
    const labels = Object.keys(breakdown);
    const values = Object.values(breakdown);

    const palette = [
      "#dc2626", "#8b5cf6", "#fb923c", "#fbbf24",
      "#38bdf8", "#334155", "#6d28d9", "#475569"
    ];

    if (data.total > 0 && labels.length > 0 && values.some(v => v > 0)) {
      vectorChartInstance.data.labels = labels;
      vectorChartInstance.data.datasets[0].data = values;
      vectorChartInstance.data.datasets[0].backgroundColor = labels.map((_, i) => palette[i % palette.length]);
      vectorChartInstance.data.datasets[0].borderWidth = 4;
      vectorChartInstance.data.datasets[0].borderColor = "#111114";
      vectorChartInstance.update("active");
    } else {
      vectorChartInstance.data.labels = ["No Active Threats"];
      vectorChartInstance.data.datasets[0].data = [1];
      vectorChartInstance.data.datasets[0].backgroundColor = ["rgba(139, 92, 246, 0.15)"];
      vectorChartInstance.data.datasets[0].borderWidth = 2;
      vectorChartInstance.data.datasets[0].borderColor = "rgba(139, 92, 246, 0.3)";
      vectorChartInstance.update("active");
    }
  }
}

// Velocity state
let lastTotal = null;
let lastThreats = null;

function pushRealtimeData(stats) {
  if (!timelineChartInstance || !stats) return;

  const currentTotal   = stats.totalGenerated || 0;
  const currentThreats = stats.threatsBlocked  || 0;

  const now = new Date();
  const timeLabel = now.toLocaleTimeString([], { hour12: false });
  const chart = timelineChartInstance;

  if (lastTotal === null) {
    lastTotal = currentTotal;
    lastThreats = currentThreats;
    chart.data.labels.push(timeLabel);
    chart.data.datasets[0].data.push(Math.max(0, currentThreats));
    chart.data.datasets[1].data.push(Math.max(1, currentTotal));
    chart.update("none");
    return;
  }

  const deltaTotal   = currentTotal   - lastTotal;
  const deltaThreats = currentThreats - lastThreats;

  lastTotal   = currentTotal;
  lastThreats = currentThreats;

  chart.data.labels.push(timeLabel);
  chart.data.datasets[0].data.push(Math.max(0, deltaThreats));
  chart.data.datasets[1].data.push(Math.max(0, deltaTotal));

  if (chart.data.labels.length > 30) {
    chart.data.labels.shift();
    chart.data.datasets[0].data.shift();
    chart.data.datasets[1].data.shift();
  }

  chart.update("none");
}

function resetCharts() {
  lastTotal = null;
  lastThreats = null;
  if (timelineChartInstance) {
    timelineChartInstance.data.labels = [];
    timelineChartInstance.data.datasets[0].data = [];
    timelineChartInstance.data.datasets[1].data = [];
    timelineChartInstance.update();
  }
  if (vectorChartInstance) {
    vectorChartInstance.data.labels = ["No Active Threats"];
    vectorChartInstance.data.datasets[0].data = [1];
    vectorChartInstance.data.datasets[0].backgroundColor = ["rgba(139, 92, 246, 0.15)"];
    vectorChartInstance.data.datasets[0].borderWidth = 2;
    vectorChartInstance.data.datasets[0].borderColor = "rgba(139, 92, 246, 0.3)";
    vectorChartInstance.update();
  }
}

window.initCharts = initCharts;
window.updateCharts = updateCharts;
window.pushRealtimeData = pushRealtimeData;
window.resetCharts = resetCharts;
