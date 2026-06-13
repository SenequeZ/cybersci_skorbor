const COLORS = [
  "#3dd6c6", "#6c8cff", "#ff6b6b", "#ffd166", "#c77dff",
  "#5ee06d", "#ff9f1c", "#48cae4", "#f72585",
];

const state = {
  meta: null,
  standings: [],
  projections: [],
  services: [],
  ticks: [],
  chart: null,
  autoRefresh: true,
  refreshTimer: null,
  totalTicks: null,
  minVulns: 1,
  serviceDetail: null,
  perServiceChart: null,
};

const STAT_LABELS = {
  benign_ok: "Benign OK",
  benign_fail: "Benign Fail",
  malicious_fail_for_team: "Malicious Hit",
  malicious_block: "Blocked",
  down: "Down",
  capped: "Capped",
  sigma: "Σ",
};

const STAT_COLS = [
  "benign_ok", "benign_fail", "malicious_fail_for_team",
  "malicious_block", "down", "capped", "sigma",
];

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function fmt(n, digits = 0) {
  if (n == null || Number.isNaN(n)) return "-";
  return Number(n).toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function setLoading(show) {
  $("#loading").classList.toggle("hidden", !show);
}

function showTab(name) {
  $$(".tab").forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === name));
  $$(".tab-panel").forEach((panel) => panel.classList.toggle("hidden", panel.id !== `tab-${name}`));
}

async function loadAll(force = false) {
  setLoading(true);
  const q = force ? "?refresh=true" : "";
  const pq = projectionQuery(force);
  try {
    const [meta, standings, projections, services, ticks, chartData] = await Promise.all([
      fetchJson(`/api/meta${q}`),
      fetchJson(`/api/standings${pq || q}`),
      fetchJson(`/api/projections${pq || q}`),
      fetchJson(`/api/services${q}`),
      fetchJson(`/api/ticks${q}`),
      fetchJson(`/api/chart${q}`),
    ]);

    state.meta = meta;
    state.standings = standings;
    state.projections = projections;
    state.services = services;
    state.ticks = ticks;

    renderHeader();
    renderStandings();
    renderProjections();
    renderServices();
    renderExplore();
    renderChart(chartData);
    populateTeamSelects();
    populateServiceSelect();
    if ($("#tab-per-service") && !$("#tab-per-service").classList.contains("hidden")) {
      await loadServiceDetail();
    }
  } catch (err) {
    console.error(err);
    $("#status-text").textContent = `Error: ${err.message}`;
  } finally {
    setLoading(false);
  }
}

function projectionQuery(force) {
  const params = new URLSearchParams();
  if (force) params.set("refresh", "true");
  if (state.totalTicks) params.set("total_ticks", state.totalTicks);
  if (state.minVulns > 1) params.set("min_vulns", state.minVulns);
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

function renderHeader() {
  $("#title-text").textContent = state.meta.title;
  $("#status-text").textContent = `${state.meta.status} · updated ${new Date(state.meta.scraped_at).toLocaleTimeString()}`;
}

function renderStandings() {
  const tbody = $("#standings-body");
  tbody.innerHTML = "";
  for (const row of state.standings) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="num">${row.place}</td>
      <td><span class="team-chip">T${row.team_id}</span> ${row.team_name}</td>
      <td class="num">${fmt(row.score)}</td>
      <td class="num">${fmt(row.ticks)}</td>
      <td class="num ${row.avg_per_tick > 0 ? "positive" : row.avg_per_tick < 0 ? "negative" : ""}">${fmt(row.avg_per_tick, 2)}</td>
      <td class="num ${row.projected_score > 0 ? "positive" : row.projected_score < 0 ? "negative" : ""}">${fmt(row.projected_score)}${row.cap_limited ? '<span class="muted" title="Capped at est. vulns × ±100">*</span>' : ""}</td>
      <td class="num ${row.last_5_tick_delta > 0 ? "positive" : row.last_5_tick_delta < 0 ? "negative" : ""}">
        ${row.last_5_tick_delta == null ? "-" : fmt(row.last_5_tick_delta)}
      </td>
    `;
    tr.style.cursor = "pointer";
    tr.addEventListener("click", () => openTeam(row.team_id));
    tbody.appendChild(tr);
  }
}

function renderProjections() {
  const tbody = $("#projections-body");
  tbody.innerHTML = "";
  for (const row of state.projections) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="num">${row.projected_place}</td>
      <td>${row.team_name}</td>
      <td class="num">${fmt(row.current_score)}</td>
      <td class="num ${row.avg_score_per_tick > 0 ? "positive" : row.avg_score_per_tick < 0 ? "negative" : ""}">${fmt(row.avg_score_per_tick, 2)}</td>
      <td class="num ${row.projected_final_score > 0 ? "positive" : row.projected_final_score < 0 ? "negative" : ""}">
        ${fmt(row.projected_final_score)}${row.cap_limited ? '<span class="muted" title="Uncapped: ' + fmt(row.projected_uncapped) + '">*</span>' : ""}
      </td>
      <td class="num muted">${row.cap_limited ? fmt(row.projected_uncapped) : "—"}</td>
      <td class="num">${fmt(row.ticks_completed)}</td>
      <td class="num">${fmt(row.ticks_remaining)}</td>
    `;
    tbody.appendChild(tr);
  }
}

function renderServices() {
  const tbody = $("#services-body");
  tbody.innerHTML = "";
  const sorted = [...state.services].sort((a, b) => b.total_sigma - a.total_sigma);
  if (!sorted.length || sorted.every((s) => s.ticks_seen === 0)) {
    tbody.innerHTML = `<tr><td colspan="13" class="muted">No tick data yet — service list will populate once competition starts.</td></tr>`;
    return;
  }
  for (const row of sorted) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${row.team_name}</td>
      <td>${row.service}</td>
      <td class="num">${fmt(row.total_sigma)}</td>
      <td class="num">${fmt(row.avg_sigma, 2)}</td>
      <td class="num">${fmt(row.malicious_block_total)}</td>
      <td class="num">${fmt(row.malicious_leak_total)}</td>
      <td class="num">${fmt(row.down_ticks)}</td>
      <td class="num">${fmt(row.win_rate * 100, 0)}%</td>
      <td class="num">${fmt(row.estimated_vulns)}</td>
      <td class="num">${fmt(row.streams_saturated)}</td>
      <td class="num">${fmt(row.points_capped_total)}</td>
      <td class="num">${fmt(row.cap_headroom_up)}</td>
      <td class="num">${fmt(row.cap_headroom_down)}</td>
    `;
    tbody.appendChild(tr);
  }
}

function renderExplore() {
  const teamFilter = Number($("#explore-team").value);
  const search = $("#explore-search").value.trim().toLowerCase();
  let rows = state.ticks;
  if (!Number.isNaN(teamFilter) && $("#explore-team").value !== "all") {
    rows = rows.filter((r) => r.team_id === teamFilter);
  }
  if (search) {
    rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(search));
  }

  const tbody = $("#explore-body");
  tbody.innerHTML = "";
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No rows match. Tick data appears once the competition starts.</td></tr>`;
    return;
  }

  const columns = Object.keys(rows[0]).filter((k) => !k.endsWith("_raw"));
  $("#explore-head").innerHTML = columns.map((c) => `<th>${c}</th>`).join("");

  for (const row of rows.slice(-200).reverse()) {
    const tr = document.createElement("tr");
    tr.innerHTML = columns
      .map((c) => `<td class="${typeof row[c] === "number" ? "num" : ""}">${row[c] ?? "-"}</td>`)
      .join("");
    tbody.appendChild(tr);
  }
}

function renderChart(chartData) {
  const canvas = $("#score-chart");
  const labels = new Set();
  const datasets = [];

  Object.entries(chartData.series || {}).forEach(([team, points], idx) => {
    points.forEach((p) => labels.add(p.time || p.tick));
  });

  const sortedLabels = [...labels];
  Object.entries(chartData.series || {}).forEach(([team, points], idx) => {
    const byKey = new Map(points.map((p) => [p.time || String(p.tick), p.score]));
    datasets.push({
      label: team,
      data: sortedLabels.map((l) => byKey.get(l) ?? null),
      borderColor: COLORS[idx % COLORS.length],
      backgroundColor: COLORS[idx % COLORS.length] + "33",
      tension: 0.2,
      spanGaps: true,
    });
  });

  if (state.chart) state.chart.destroy();
  state.chart = new Chart(canvas, {
    type: "line",
    data: { labels: sortedLabels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { labels: { color: "#e8eef7" } },
      },
      scales: {
        x: { ticks: { color: "#8b9bb4" }, grid: { color: "#2a3545" } },
        y: { ticks: { color: "#8b9bb4" }, grid: { color: "#2a3545" } },
      },
    },
  });
}

function populateServiceSelect() {
  const names = [...new Set(state.services.map((s) => s.service))].sort();
  const sel = $("#per-service-select");
  if (!sel || !names.length) return;
  const current = sel.value;
  sel.innerHTML = names.map((n) => `<option value="${n}">${n}</option>`).join("");
  if (current && names.includes(current)) sel.value = current;
  else if (names.length) sel.value = names[0];
}

function statCell(raw, value, capped, noComm, cappedDiscarded) {
  if (noComm || raw === "-") return `<td class="num muted">-</td>`;
  if (capped && cappedDiscarded != null && cappedDiscarded > 0) {
    const cls = value > 0 ? "positive" : value < 0 ? "negative" : "";
    const counted = value ?? 0;
    return `<td class="num ${cls}" title="${counted} counted, ${cappedDiscarded} capped off">${counted}<span class="capped">/${cappedDiscarded}</span></td>`;
  }
  if (capped && raw && String(raw).startsWith("/")) {
    return `<td class="num capped" title="All points capped">${raw}</td>`;
  }
  const cls = value > 0 ? "positive" : value < 0 ? "negative" : "";
  const display = raw !== "" && raw != null ? raw : fmt(value);
  return `<td class="num ${cls}">${display}</td>`;
}

async function loadServiceDetail() {
  const service = $("#per-service-select")?.value;
  const teamVal = $("#per-service-team")?.value;
  if (!service) return;

  const params = new URLSearchParams({ service });
  if (teamVal && teamVal !== "all") params.set("team_id", teamVal);

  state.serviceDetail = await fetchJson(`/api/service-detail?${params}`);
  renderPerService();
}

function renderPerService() {
  const data = state.serviceDetail;
  if (!data) return;

  const info = data.service_info || {};
  $("#per-service-title").textContent = info.name || $("#per-service-select").value;
  $("#per-service-meta").textContent = [info.address, info.description].filter(Boolean).join(" · ") || "No service metadata";

  const summaries = data.summaries || [];
  const totalsBody = $("#per-service-totals-body");
  totalsBody.innerHTML = "";
  if (!summaries.length) {
    totalsBody.innerHTML = `<tr><td colspan="5" class="muted">No data yet</td></tr>`;
  } else {
    for (const s of summaries.sort((a, b) => b.total_sigma - a.total_sigma)) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="team-chip">T${s.team_id}</span> ${s.team_name}</td>
        <td class="num ${s.total_sigma > 0 ? "positive" : s.total_sigma < 0 ? "negative" : ""}">${fmt(s.total_sigma)}</td>
        <td class="num">${fmt(s.avg_sigma, 2)}</td>
        <td class="num">${fmt(s.cap_headroom_up)}</td>
        <td class="num">${fmt(s.cap_headroom_down)}</td>
      `;
      tr.style.cursor = "pointer";
      tr.addEventListener("click", () => {
        $("#per-service-team").value = String(s.team_id);
        loadServiceDetail();
      });
      totalsBody.appendChild(tr);
    }
  }

  const agg = summaries.reduce(
    (acc, s) => ({
      sigma: acc.sigma + s.total_sigma,
      blocks: acc.blocks + s.malicious_block_total,
      leaks: acc.leaks + s.malicious_leak_total,
      down: acc.down + s.down_ticks,
    }),
    { sigma: 0, blocks: 0, leaks: 0, down: 0 }
  );
  $("#per-service-summary").innerHTML = [
    ["Total Σ", fmt(agg.sigma), agg.sigma],
    ["Blocks", fmt(agg.blocks), agg.blocks],
    ["Malicious hits", fmt(agg.leaks), agg.leaks],
    ["Down ticks", fmt(agg.down), agg.down],
    ["Cap", `±${data.caps?.per_vuln_max ?? 100}/vuln`, 0],
  ]
    .map(([label, val, num]) => {
      const cls = num > 0 ? "positive" : num < 0 ? "negative" : "";
      return `<div class="stat-card"><div class="label">${label}</div><div class="value ${cls}">${val}</div></div>`;
    })
    .join("");

  const rows = data.rows || [];
  const showServiceCol = !$("#per-service-select").value || $("#per-service-team").value === "all";

  $("#per-service-ticks-head").innerHTML = `
    <th class="num">Tick</th>
    <th>Time</th>
    ${showServiceCol ? "" : ""}
    <th>Team</th>
    ${STAT_COLS.map((c) => `<th class="num">${STAT_LABELS[c]}</th>`).join("")}
    <th class="num">Cum. Σ</th>
  `;

  const tbody = $("#per-service-ticks-body");
  tbody.innerHTML = "";
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="12" class="muted">No tick data for this filter</td></tr>`;
  } else {
    for (const row of [...rows].reverse()) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="num">${row.tick}</td>
        <td>${row.time || "-"}</td>
        <td><span class="team-chip">T${row.team_id}</span> ${row.team_name}</td>
        ${STAT_COLS.map((c) => statCell(row[`${c}_raw`], row[c], row[`${c}_capped`], row[`${c}_no_comm`], row[`${c}_capped_discarded`])).join("")}
        <td class="num ${row.cumulative_sigma > 0 ? "positive" : row.cumulative_sigma < 0 ? "negative" : ""}">${fmt(row.cumulative_sigma)}</td>
      `;
      tbody.appendChild(tr);
    }
  }

  renderPerServiceChart(rows);
}

function renderPerServiceChart(rows) {
  const canvas = $("#per-service-chart");
  if (!canvas) return;

  const byTeam = new Map();
  for (const row of rows) {
    const key = row.team_name;
    if (!byTeam.has(key)) byTeam.set(key, []);
    byTeam.get(key).push({ tick: row.tick, cumulative: row.cumulative_sigma });
  }

  const labels = [...new Set(rows.map((r) => r.tick))].sort((a, b) => a - b);
  const datasets = [];
  let idx = 0;
  for (const [team, points] of byTeam) {
    const byTick = new Map(points.map((p) => [p.tick, p.cumulative]));
    datasets.push({
      label: team,
      data: labels.map((t) => byTick.get(t) ?? null),
      borderColor: COLORS[idx % COLORS.length],
      backgroundColor: COLORS[idx % COLORS.length] + "33",
      tension: 0.2,
      spanGaps: true,
    });
    idx += 1;
  }

  if (state.perServiceChart) state.perServiceChart.destroy();
  state.perServiceChart = new Chart(canvas, {
    type: "line",
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { color: "#e8eef7" } } },
      scales: {
        x: { ticks: { color: "#8b9bb4" }, grid: { color: "#2a3545" } },
        y: { ticks: { color: "#8b9bb4" }, grid: { color: "#2a3545" } },
      },
    },
  });
}

function populateTeamSelects() {
  const options = (state.meta?.teams || [])
    .map((t) => `<option value="${t.id}">${t.name}</option>`)
    .join("");

  for (const sel of ["#team-select", "#compare-a", "#compare-b", "#explore-team", "#per-service-team"]) {
    const el = $(sel);
    const current = el.value;
    if (sel === "#explore-team" || sel === "#per-service-team") {
      el.innerHTML = `<option value="all">All teams</option>${options}`;
    } else if (sel === "#team-select") {
      el.innerHTML = options;
    } else {
      el.innerHTML = options;
    }
    if (current) el.value = current;
  }
}

async function openTeam(teamId) {
  showTab("team");
  $("#team-select").value = String(teamId);
  await loadTeamDetail(teamId);
}

async function loadTeamDetail(teamId) {
  const detail = await fetchJson(`/api/teams/${teamId}`);
  $("#team-title").textContent = detail.team_name;
  $("#team-meta").textContent = `${detail.ticks.length} ticks · latest score ${fmt(detail.latest_score)}`;

  const svcWrap = $("#team-services");
  svcWrap.innerHTML = (detail.services || [])
    .map((s) => `<div class="stat-card"><div class="label">${s.name}</div><div class="value">${s.address || "-"}</div></div>`)
    .join("");

  const tbody = $("#team-ticks-body");
  tbody.innerHTML = "";
  const ticks = detail.ticks || [];
  if (!ticks.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No ticks yet</td></tr>`;
    return;
  }

  const serviceNames = (detail.services || []).map((s) => s.name);
  $("#team-ticks-head").innerHTML = `
    <th>Tick</th><th>Time</th><th>Score</th>
    ${serviceNames.map((n) => `<th>${n} Σ</th>`).join("")}
  `;

  for (const tick of ticks.slice(-30).reverse()) {
    const tr = document.createElement("tr");
    const svcCells = serviceNames
      .map((name) => {
        const svc = tick.services?.[name];
        const sigma = svc?.sigma?.value ?? 0;
        return `<td class="num">${fmt(sigma)}</td>`;
      })
      .join("");
    tr.innerHTML = `
      <td class="num">${tick.tick}</td>
      <td>${tick.time}</td>
      <td class="num">${fmt(tick.score)}</td>
      ${svcCells}
    `;
    tbody.appendChild(tr);
  }
}

async function runCompare() {
  const a = $("#compare-a").value;
  const b = $("#compare-b").value;
  const data = await fetchJson(`/api/compare?a=${a}&b=${b}`);
  $("#compare-title").innerHTML = `<span>${data.team_a}</span> ${data.wins_a} – ${data.wins_b} <span>${data.team_b}</span> <span class="muted">(${data.ties} ties)</span>`;

  const tbody = $("#compare-body");
  tbody.innerHTML = "";
  if (!data.ticks.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">No overlapping ticks yet</td></tr>`;
    return;
  }
  for (const row of data.ticks.slice().reverse()) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="num">${row.tick}</td>
      <td class="num">${fmt(row.team_a_delta)}</td>
      <td class="num">${fmt(row.team_b_delta)}</td>
      <td>${row.winner}</td>
    `;
    tbody.appendChild(tr);
  }
}

function setupAutoRefresh() {
  clearInterval(state.refreshTimer);
  if (state.autoRefresh) {
    state.refreshTimer = setInterval(() => loadAll(false), 30000);
  }
}

function bindEvents() {
  $$(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      showTab(btn.dataset.tab);
      if (btn.dataset.tab === "per-service") loadServiceDetail();
    });
  });

  $("#refresh-btn").addEventListener("click", () => loadAll(true));
  $("#auto-refresh").addEventListener("change", (e) => {
    state.autoRefresh = e.target.checked;
    setupAutoRefresh();
  });

  $("#total-ticks").addEventListener("change", async (e) => {
    state.totalTicks = e.target.value ? Number(e.target.value) : null;
    await refreshProjections();
  });

  $("#min-vulns").addEventListener("change", async (e) => {
    state.minVulns = Math.max(1, Number(e.target.value) || 1);
    await refreshProjections();
  });

  async function refreshProjections() {
    const q = projectionQuery(false);
    state.projections = await fetchJson(`/api/projections${q}`);
    renderProjections();
    state.standings = await fetchJson(`/api/standings${q}`);
    renderStandings();
    state.services = await fetchJson(`/api/services`);
    renderServices();
  }

  $("#team-select").addEventListener("change", (e) => loadTeamDetail(Number(e.target.value)));
  $("#explore-team").addEventListener("change", renderExplore);
  $("#explore-search").addEventListener("input", renderExplore);
  $("#compare-btn").addEventListener("click", runCompare);
  $("#per-service-select").addEventListener("change", loadServiceDetail);
  $("#per-service-team").addEventListener("change", loadServiceDetail);
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  showTab("overview");
  await loadAll(false);
  await runCompare();
  setupAutoRefresh();
});
