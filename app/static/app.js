const $ = (s) => document.querySelector(s);

function applyTabs() {
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const view = btn.dataset.view;
      $("#view-topo").classList.toggle("hidden", view !== "topo");
      $("#view-arp").classList.toggle("hidden", view !== "arp");
      if (window.cyTopo) window.cyTopo.resize();
      if (window.cyArp) window.cyArp.resize();
    });
  });
}

function renderLegend(items) {
  const el = $("#legend");
  el.innerHTML = (items || [])
    .map(
      (i) =>
        `<div class="legend-row"><span class="swatch" style="background:${i.color}">${i.symbol || ""}</span>${i.label}</div>`
    )
    .join("");
}

function makeCy(container, payload) {
  const elements = [...(payload.nodes || []), ...(payload.edges || [])];
  const style = (payload.style || []).map((s) => {
    const st = { ...s };
    if (st.style && st.style.label === "data(label)") {
      /* keep */
    }
    return st;
  });
  return cytoscape({
    container,
    elements,
    style,
    layout: { name: "breadthfirst", directed: false, padding: 24, spacingFactor: 1.35 },
    minZoom: 0.2,
    maxZoom: 2.5,
  });
}

function showSelection(cy, target) {
  cy.on("tap", "node, edge", (evt) => {
    target.textContent = JSON.stringify(evt.target.data(), null, 2);
  });
}

async function loadTopo() {
  const seed = $("#seed").value.trim();
  const res = await fetch(`/api/v1/topology?seed=${encodeURIComponent(seed)}&demo=true`);
  const data = await res.json();
  if (window.cyTopo) window.cyTopo.destroy();
  window.cyTopo = makeCy($("#cy-topo"), data);
  showSelection(window.cyTopo, $("#topo-json"));
  renderLegend(data.legend && data.legend.nodes);
  const s = data.summary || {};
  $("#topo-summary").innerHTML = `
    <div><strong>${s.devices || 0}</strong> site devices · <strong>${s.links || 0}</strong> links</div>
    <div>${s.boundary || ""}</div>
    <div>Seed: ${data.seed}</div>
  `;
}

async function loadArp(params) {
  const qs = new URLSearchParams({ demo: "true", ...params });
  const res = await fetch(`/api/v1/arp?${qs.toString()}`);
  const data = await res.json();
  const v = $("#verdict");
  if (!data.found) {
    v.className = "red";
    v.textContent = data.message;
    $("#findings").innerHTML = "";
    $("#lan-json").textContent = "";
    $("#wan-json").textContent = "";
    $("#notes").innerHTML = "";
    return;
  }
  v.className = data.verdict.level;
  v.textContent = data.verdict.summary;
  $("#findings").innerHTML = (data.findings || [])
    .map((f) => `<li class="${f.severity}"><strong>${f.code}</strong> — ${f.detail}</li>`)
    .join("");
  $("#lan-json").textContent = JSON.stringify(data.lan, null, 2);
  $("#wan-json").textContent = JSON.stringify(data.wan, null, 2);
  $("#notes").innerHTML = (data.engineer_notes || []).map((n) => `<li>${n}</li>`).join("");
  if (window.cyArp) window.cyArp.destroy();
  window.cyArp = makeCy($("#cy-arp"), data);
}

function collectQuery() {
  const ip = $("#q-ip").value.trim();
  const mac = $("#q-mac").value.trim();
  const username = $("#q-user").value.trim();
  const hostname = $("#q-host").value.trim();
  const q = {};
  if (ip) q.ip = ip;
  if (mac) q.mac = mac;
  if (username) q.username = username;
  if (hostname) q.hostname = hostname;
  if (!Object.keys(q).length) q.ip = "10.20.10.45";
  return q;
}

applyTabs();
$("#btn-topo").addEventListener("click", loadTopo);
$("#btn-arp").addEventListener("click", () => loadArp(collectQuery()));
document.querySelectorAll(".chip").forEach((c) => {
  c.addEventListener("click", () => {
    $("#q-ip").value = c.dataset.ip;
    loadArp({ ip: c.dataset.ip });
  });
});
loadTopo();
