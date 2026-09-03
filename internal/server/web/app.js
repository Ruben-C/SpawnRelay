/* SpawnRelay management UI */
(() => {
  "use strict";
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const state = { tab: "clients", status: null, clients: [], groups: [], tokens: [], settings: null, timer: null, expanded: new Set() };

  // ---- API ----------------------------------------------------------------
  async function api(method, path, body) {
    const res = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
    });
    let data = null;
    try { data = await res.json(); } catch { /* no body */ }
    if (res.status === 401 && !path.endsWith("/auth/login")) { showLogin(); throw new Error("Session expired, please sign in again"); }
    if (!res.ok) throw new Error((data && data.error) || `${res.status} ${res.statusText}`);
    return data;
  }

  // ---- UI helpers ---------------------------------------------------------
  function toast(msg, isError) {
    const el = document.createElement("div");
    el.className = "toast" + (isError ? " error" : "");
    el.textContent = msg;
    $("#toasts").appendChild(el);
    setTimeout(() => el.remove(), isError ? 6000 : 3500);
  }
  const fail = (e) => toast(e.message || String(e), true);

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); toast("Copied to clipboard"); }
    catch { toast("Copy failed; select the text and copy manually", true); }
  }

  function openModal(html) { $("#modal-body").innerHTML = html; $("#modal").hidden = false; const f = $("#modal input, #modal select"); if (f) f.focus(); }
  function closeModal() { $("#modal").hidden = true; $("#modal-body").innerHTML = ""; }

  function confirmDialog(title, text, okLabel = "Delete") {
    return new Promise((resolve) => {
      openModal(`<h3>${esc(title)}</h3><p>${esc(text)}</p>
        <div class="form-actions"><button class="btn" data-modal="cancel">Cancel</button><button class="btn danger" data-modal="ok">${esc(okLabel)}</button></div>`);
      $("#modal-body").onclick = (ev) => {
        const b = ev.target.closest("[data-modal]");
        if (!b) return;
        closeModal(); resolve(b.dataset.modal === "ok");
      };
    });
  }

  const fmtBytes = (n) => { if (!n) return "0 B"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
  const fmtAgo = (iso) => { if (!iso) return "never"; const s = Math.max(0, (Date.now() - new Date(iso)) / 1000); if (s < 60) return "just now"; if (s < 3600) return `${Math.floor(s / 60)} min ago`; if (s < 86400) return `${Math.floor(s / 3600)} h ago`; return `${Math.floor(s / 86400)} d ago`; };
  const fmtDur = (sec) => { if (sec < 3600) return `${Math.floor(sec / 60)}m`; if (sec < 86400) return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`; return `${Math.floor(sec / 86400)}d ${Math.floor((sec % 86400) / 3600)}h`; };
  const badge = (proto) => `<span class="badge ${esc(proto)}">${esc(proto === "both" ? "TCP+UDP" : proto.toUpperCase())}</span>`;
  const fwLine = (fw) => {
    if (!fw) return "";
    switch (fw.state) {
      case "open": return `<div class="subtle ok">firewall: open</div>`;
      case "existing": return `<div class="subtle ok" title="An existing firewall rule already allows this port; SpawnRelay left it alone.">firewall: open (existing rule)</div>`;
      case "closed": return `<div class="subtle">firewall: closed</div>`;
      case "error": return `<div class="subtle err" title="${esc(fw.error || "")}">firewall: error</div>`;
      default: return "";
    }
  };

  // ---- views --------------------------------------------------------------
  function showLogin() { clearInterval(state.timer); $("#app").hidden = true; $("#login").hidden = false; $("input[name=password]", $("#login-form")).focus(); }
  function showApp() { $("#login").hidden = true; $("#app").hidden = false; }

  function renderStats() {
    const s = state.status; if (!s) return;
    $("#server-host").textContent = s.public_host;
    $("#stats").innerHTML = `
      <div class="stat"><div class="label">Clients online</div><div class="value">${s.clients_online} <span class="muted">/ ${s.clients_total}</span></div></div>
      <div class="stat"><div class="label">Port forwards</div><div class="value">${s.forward_groups_total} <span class="muted small">${s.forwards_total} port${s.forwards_total === 1 ? "" : "s"}</span></div></div>
      <div class="stat"><div class="label">Tunnel endpoint</div><div class="value mono copy" data-copy="${esc(s.tunnel_addr)}" title="Click to copy">${esc(s.tunnel_addr)}</div></div>
      <div class="stat"><div class="label">Uptime</div><div class="value">${fmtDur(s.uptime_seconds)} <span class="muted small">v${esc(s.version)}</span></div></div>`;
  }

  function versionCell(c) {
    const u = c.update || {};
    const v = c.client_version ? esc(c.client_version) : '<span class="muted">?</span>';
    let out = `<span class="mono">${v}</span>`;
    if (u.available) out += ' <span class="badge warn" title="Server is on ' + esc(u.server_version) + '">outdated</span>';
    else if (c.status.online && c.client_version && c.client_version !== u.server_version) out += ` <span class="badge off" title="${esc(u.reason || "")}">cannot update</span>`;
    const l = u.last;
    if (l) {
      if (l.state === "pending") out += `<div class="subtle" title="${esc(l.detail || "")}">updating to ${esc(l.target_version)}: ${esc(l.detail || "requested")}</div>`;
      else if (l.state === "failed") out += `<div class="subtle err" title="${esc(l.detail || "")}">update failed: ${esc(l.detail || "")}</div>`;
      else if (l.state === "done") out += `<div class="subtle ok">${esc(l.detail || "updated")} · ${fmtAgo(l.updated_at)}</div>`;
    }
    return out;
  }

  function renderClients() {
    const outdated = state.clients.filter((c) => c.update && c.update.available).length;
    const btn = $("#update-all");
    btn.hidden = outdated === 0;
    btn.textContent = `Update ${outdated} outdated client${outdated === 1 ? "" : "s"}`;
    const rows = state.clients.map((c) => `
      <tr>
        <td><span class="dot ${c.status.online ? "on" : "off"}"></span>${c.status.online ? "Online" : "Offline"}</td>
        <td><strong>${esc(c.name)}</strong><div class="subtle">${esc(c.hostname || "not connected yet")}${c.os ? ` · ${esc(c.os)}/${esc(c.arch)}` : ""}</div></td>
        <td>${versionCell(c)}</td>
        <td class="mono">${esc(c.status.online ? c.status.remote_addr : c.last_addr || "—")}</td>
        <td>${c.status.online ? `since ${fmtAgo(c.status.connected_at)}` : fmtAgo(c.last_seen_at)}</td>
        <td>${c.forward_group_count}</td>
        <td class="actions">
          ${c.update && c.update.available ? `<button class="btn small primary" data-action="update-client" data-id="${c.id}">Update</button>` : ""}
          <button class="btn small ${c.update && c.update.available ? "" : "primary"}" data-action="install" data-id="${c.id}">Install</button>
          <button class="btn small" data-action="new-forward" data-client="${c.id}">+ Forward</button>
          <button class="btn small" data-action="rename-client" data-id="${c.id}">Rename</button>
          <button class="btn small" data-action="rotate" data-id="${c.id}">Rotate token</button>
          <button class="btn small danger" data-action="delete-client" data-id="${c.id}">Delete</button>
        </td>
      </tr>`).join("");
    $("#clients-table").innerHTML = state.clients.length
      ? `<div class="table-wrap"><table><thead><tr><th>Status</th><th>Name</th><th>Version</th><th>Address</th><th>Seen</th><th>Forwards</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="card empty">No clients yet. Click <strong>Add client</strong> to create one and get its install command.</div>`;
  }

  const trafficCell = (st) => {
    st = st || {};
    const active = (st.active_tcp || 0) + (st.active_udp || 0);
    return `<span title="active connections">${active} active</span><div class="subtle">${st.total_connections || 0} total · ${fmtBytes(st.bytes_in)} in / ${fmtBytes(st.bytes_out)} out</div>`;
  };

  // A group's problems must show on the collapsed row, not only inside it.
  function groupWarning(g) {
    if (!g.enabled) return "";
    const st = g.stats || {}, fw = g.firewall || {};
    if (!st.listening) return `<span class="badge err" title="${esc(st.error || "A port could not be opened on the relay")}">not listening</span>`;
    if (fw.state === "error") return `<span class="badge err" title="${esc(fw.error || "")}">firewall error</span>`;
    return "";
  }

  function memberTable(g) {
    const rows = g.forwards.map((f) => {
      const st = f.stats || {};
      const listen = !f.enabled ? '<span class="muted">disabled</span>'
        : st.listening ? '<span class="ok">listening</span>'
        : `<span class="err" title="${esc(st.error || "")}">not listening</span>`;
      return `<tr>
        <td>${badge(f.protocol)}</td>
        <td class="mono"><span class="copy" data-copy="${esc(f.public_addr)}" title="Click to copy">${esc(f.public_addr)}</span></td>
        <td class="mono">${esc(f.target_host)}:${f.target_port}</td>
        <td>${listen}</td>
        <td>${fwLine(f.firewall) || '<span class="subtle">firewall: not managed</span>'}</td>
        <td>${trafficCell(st)}</td>
      </tr>`;
    }).join("");
    return `<table class="members"><thead><tr><th>Proto</th><th>Public address</th><th>Target</th><th>State</th><th>Firewall</th><th>Traffic</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  function renderForwards() {
    const clientById = Object.fromEntries(state.clients.map((c) => [c.id, c]));
    const rows = state.groups.map((g) => {
      const c = clientById[g.client_id];
      const online = c && c.status.online;
      const f0 = g.forwards[0];
      const multi = g.forwards.length > 1;
      const open = state.expanded.has(g.id);
      const portsCell = multi
        ? `<button class="chevron ${open ? "open" : ""}" data-action="expand-group" data-id="${g.id}" title="${open ? "Hide ports" : "Show ports"}" aria-expanded="${open}"></button><span class="mono">${esc(g.ports)}</span><div class="subtle">${g.forwards.length} ports</div>`
        : `${badge(f0.protocol)} <span class="mono">${f0.public_port}</span>`;
      const publicCell = multi
        ? `<span class="mono">${esc(g.public_host)}</span>${fwLine(g.firewall)}`
        : `<span class="mono copy" data-copy="${esc(f0.public_addr)}" title="Click to copy">${esc(f0.public_addr)}</span>${fwLine(f0.firewall)}`;
      const targetCell = multi ? esc(g.target_host) : `${esc(f0.target_host)}:${f0.target_port}`;
      let row = `<tr>
        <td><strong>${esc(g.name)}</strong>${g.enabled ? "" : ' <span class="badge off">disabled</span>'} ${groupWarning(g)}</td>
        <td><span class="dot ${online ? "on" : "off"}"></span>${esc(g.client_name || "?")}</td>
        <td>${portsCell}</td>
        <td>${publicCell}</td>
        <td class="mono">${targetCell}</td>
        <td>${trafficCell(g.stats)}</td>
        <td><button class="toggle ${g.enabled ? "on" : ""}" data-action="toggle-forward" data-id="${g.id}" data-enabled="${g.enabled}" title="${g.enabled ? "Disable" : "Enable"}"></button></td>
        <td class="actions">
          <button class="btn small" data-action="edit-forward" data-id="${g.id}">Edit</button>
          <button class="btn small danger" data-action="delete-forward" data-id="${g.id}">Delete</button>
        </td>
      </tr>`;
      if (multi && open) row += `<tr class="sub"><td colspan="8">${memberTable(g)}</td></tr>`;
      return row;
    }).join("");
    $("#forwards-table").innerHTML = state.groups.length
      ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Client</th><th>Ports</th><th>Public address</th><th>Target</th><th>Traffic</th><th>On</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="card empty">No forwards yet. ${state.clients.length ? "Click <strong>Add forward</strong> to expose a game server." : "Add a client first, then create a forward for it."}</div>`;
  }

  function renderTokens() {
    const rows = state.tokens.map((t) => `<tr>
      <td><strong>${esc(t.name)}</strong></td><td class="mono">${esc(t.prefix)}…</td>
      <td>${fmtAgo(t.created_at)}</td><td>${fmtAgo(t.last_used_at)}</td>
      <td class="actions"><button class="btn small danger" data-action="delete-token" data-id="${t.id}">Revoke</button></td></tr>`).join("");
    $("#tokens-table").innerHTML = state.tokens.length
      ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Token</th><th>Created</th><th>Last used</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="card empty">No API tokens. Create one to automate forwards from scripts.</div>`;
  }

  function renderSettings() {
    const s = state.status, st = state.settings; if (!s || !st) return;
    $("#settings-form input[name=public_host]").value = st.public_host || "";
    $("#detected-host").textContent = st.detected_public_host ? `Detected address: ${st.detected_public_host}` : "Could not detect an outbound address; set one explicitly.";
    const fwSel = $("#firewall-form select[name=firewall]");
    if (document.activeElement !== fwSel) {
      fwSel.innerHTML = (st.firewall_modes || ["auto", "off"]).map((m) => `<option value="${esc(m)}" ${m === st.firewall ? "selected" : ""}>${esc(FW_LABELS[m] || m)}</option>`).join("");
    }
    $("#firewall-status").innerHTML = fwStatusText(st.firewall_status);
    const au = $("#updates-form input[name=auto_update_clients]");
    if (document.activeElement !== au) au.checked = !!st.auto_update_clients;
    $("#updates-status").textContent = st.server_version === "dev"
      ? "This server runs a development build; automatic updates are paused until it runs a release version."
      : `Clients are updated to the server's version (${st.server_version}). Update the server first, then push.`;
    $("#server-info-list").innerHTML = `
      <dt>Version</dt><dd>${esc(s.version)} (${esc(s.os)}/${esc(s.arch)})</dd>
      <dt>Tunnel</dt><dd class="mono">${esc(s.tunnel_addr)}</dd>
      <dt>Fingerprint</dt><dd class="mono copy" data-copy="${esc(s.tunnel_fingerprint)}" title="Click to copy">${esc(s.tunnel_fingerprint)}</dd>
      <dt>Admin URL</dt><dd class="mono">${esc(s.admin_url)}</dd>
      <dt>Admin cert</dt><dd>${s.admin_self_signed ? "self-signed (browser warning expected)" : "custom certificate"}</dd>`;
  }

  const FW_LABELS = { auto: "Automatic (detect ufw, firewalld, nftables or iptables)", off: "Off (do not touch the firewall)", ufw: "ufw", firewalld: "firewalld", nftables: "nftables", iptables: "iptables" };

  function fwStatusText(fs) {
    if (!fs) return "";
    const line = (cls, text) => `<div class="${cls}">${text}</div>`;
    switch (fs.agent) {
      case "off": return line("muted", "Firewall management is off. The tunnel, management and forward ports must be opened by hand.");
      case "not installed": return line("warn-text", `Firewall agent not running (no socket at <span class="mono">${esc(fs.socket)}</span>). Re-run the server installer to add the <span class="mono">spawnrelay-firewall</span> service, or open ports by hand.`);
      case "unreachable": return line("err", `Firewall agent did not answer: ${esc(fs.error || "unknown error")}`);
    }
    let out = "";
    if (fs.backend === "none") out += line("warn-text", "Agent connected, but no active host firewall was detected. If this VPS uses a cloud security group, open the ports there.");
    else out += line("ok", `Agent connected · backend: ${esc(fs.backend)}${fs.active ? "" : " (inactive)"} · tunnel, management and every enabled forward port are kept open automatically${fs.last_sync ? ` · synced ${fmtAgo(fs.last_sync)}` : ""}`);
    if (fs.note) out += line("muted", esc(fs.note));
    if (fs.error) out += line("err", esc(fs.error));
    return out;
  }

  function render() {
    renderStats();
    if (state.tab === "clients") renderClients();
    if (state.tab === "forwards") renderForwards();
    if (state.tab === "tokens") renderTokens();
    if (state.tab === "settings") renderSettings();
  }

  async function refresh() {
    try {
      const jobs = [api("GET", "/api/v1/status"), api("GET", "/api/v1/clients")];
      if (state.tab === "forwards") jobs.push(api("GET", "/api/v1/forward-groups"));
      if (state.tab === "tokens") jobs.push(api("GET", "/api/v1/tokens"));
      if (state.tab === "settings") jobs.push(api("GET", "/api/v1/settings"));
      const [status, clients, extra] = await Promise.all(jobs);
      state.status = status; state.clients = clients;
      if (state.tab === "forwards") state.groups = extra;
      if (state.tab === "tokens") state.tokens = extra;
      if (state.tab === "settings") state.settings = extra;
      render();
    } catch (e) { if (!/sign in/.test(e.message)) fail(e); }
  }

  function setTab(tab) {
    state.tab = tab;
    document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
    document.querySelectorAll(".tab").forEach((s) => (s.hidden = s.id !== `tab-${tab}`));
    refresh();
  }

  // ---- modals -------------------------------------------------------------
  function installModal(c) {
    const i = c.install;
    const block = (title, cmd) => `<div class="cmd-block"><div class="cmd-head"><span>${esc(title)}</span><button class="btn small ghost" data-copy="${esc(cmd)}">Copy</button></div><pre class="cmd">${esc(cmd)}</pre></div>`;
    openModal(`<h3>Install client “${esc(c.name)}”</h3>
      <p class="muted">Run one of these on the machine that hosts your game servers. It downloads the client, pins this relay's certificate and installs a service that reconnects automatically.</p>
      ${block("Linux / macOS (as root)", i.linux)}
      ${block("Windows (elevated PowerShell)", i.windows)}
      ${block("Manual / any OS", i.manual)}
      <div class="form-actions"><button class="btn" data-modal="close">Close</button></div>`);
  }

  // Presets are port specs, so multi-port games fit the same table.
  const PRESETS = [
    ["Minecraft Java", "25565", "tcp"], ["Minecraft Bedrock", "19132", "udp"], ["Terraria", "7777", "tcp"],
    ["Valheim", "2456", "udp"], ["Palworld", "8211", "udp"], ["Factorio", "34197", "udp"], ["Rust", "28015", "both"],
    ["ARK: Survival", "7777", "udp"], ["Counter-Strike 2", "27015", "both"], ["Project Zomboid", "16261", "udp"],
    ["Enshrouded", "15636", "udp"], ["7 Days to Die", "26900", "both"], ["Satisfactory", "7777", "both"], ["Team Fortress 2", "27015", "both"],
  ];

  function forwardModal(g, presetClient) {
    const isEdit = !!g;
    g = g || { name: "", client_id: presetClient || (state.clients[0] && state.clients[0].id) || "", protocol: "tcp", ports: "", target_host: "127.0.0.1", enabled: true };
    const clientOpts = state.clients.map((c) => `<option value="${c.id}" ${c.id === g.client_id ? "selected" : ""}>${esc(c.name)}${c.status.online ? "" : " (offline)"}</option>`).join("");
    const presetOpts = PRESETS.map(([n, spec, pr]) => `<option value="${esc(spec)}|${pr}">${esc(n)} — ${esc(spec)} ${pr}</option>`).join("");
    openModal(`<h3>${isEdit ? "Edit forward" : "New forward"}</h3>
      <form id="forward-form">
        ${isEdit ? "" : `<label>Game preset (optional) <select name="preset"><option value="">Choose a game to fill in the ports…</option>${presetOpts}</select></label>`}
        <label>Name <input name="name" value="${esc(g.name)}" placeholder="e.g. Minecraft survival" maxlength="64"></label>
        <label>Client <select name="client_id" required>${clientOpts}</select></label>
        <div class="row">
          <label>Default protocol <select name="protocol">
            <option value="tcp" ${g.protocol === "tcp" ? "selected" : ""}>TCP</option>
            <option value="udp" ${g.protocol === "udp" ? "selected" : ""}>UDP</option>
            <option value="both" ${g.protocol === "both" ? "selected" : ""}>TCP + UDP</option></select></label>
          <label>Target host (from client) <input name="target_host" required value="${esc(g.target_host)}"></label>
        </div>
        <label>Ports (on relay) <input name="ports" class="mono" required value="${esc(g.ports)}" placeholder="e.g. 7780-7784/udp, 5673, 15673" spellcheck="false" autocomplete="off">
          <span class="hint">Ports or ranges separated by commas. Add <span class="mono">/tcp</span>, <span class="mono">/udp</span> or <span class="mono">/both</span> to override the default protocol and <span class="mono">&gt;port</span> to relay to a different port, e.g. <span class="mono">2000-2005/udp, 2009, 2011&gt;3011</span>. Up to 64 ports.</span></label>
        <label class="check"><input type="checkbox" name="enabled" ${g.enabled ? "checked" : ""}> Enabled</label>
        <div class="form-actions"><button class="btn" type="button" data-modal="close">Cancel</button><button class="btn primary" type="submit">${isEdit ? "Save" : "Create"}</button></div>
      </form>`);
    const form = $("#forward-form");
    const preset = form.querySelector("[name=preset]");
    if (preset) preset.onchange = () => {
      if (!preset.value) return;
      const [spec, proto] = preset.value.split("|");
      form.ports.value = spec; form.protocol.value = proto;
      if (!form.name.value) form.name.value = preset.options[preset.selectedIndex].text.split(" — ")[0];
    };
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      const body = {
        name: form.name.value.trim(), client_id: form.client_id.value, protocol: form.protocol.value,
        ports: form.ports.value.trim(), target_host: form.target_host.value.trim(), enabled: form.enabled.checked,
      };
      if (!body.name) delete body.name;
      try {
        if (isEdit) await api("PATCH", `/api/v1/forward-groups/${g.id}`, body); else await api("POST", "/api/v1/forward-groups", body);
        closeModal(); toast(isEdit ? "Forward saved" : "Forward created"); setTab("forwards");
      } catch (e) { fail(e); }
    };
  }

  function clientModal(c) {
    const isEdit = !!c;
    openModal(`<h3>${isEdit ? "Rename client" : "New client"}</h3>
      <form id="client-form">
        <label>Name <input name="name" required maxlength="64" value="${esc(c ? c.name : "")}" placeholder="e.g. basement-pc"></label>
        <div class="form-actions"><button class="btn" type="button" data-modal="close">Cancel</button><button class="btn primary" type="submit">${isEdit ? "Save" : "Create"}</button></div>
      </form>`);
    $("#client-form").onsubmit = async (ev) => {
      ev.preventDefault();
      const name = $("#client-form input[name=name]").value.trim();
      try {
        if (isEdit) { await api("PATCH", `/api/v1/clients/${c.id}`, { name }); closeModal(); toast("Client renamed"); refresh(); }
        else { const created = await api("POST", "/api/v1/clients", { name }); toast("Client created"); await refresh(); installModal(created); }
      } catch (e) { fail(e); }
    };
  }

  function tokenModal() {
    openModal(`<h3>Create API token</h3>
      <form id="token-form">
        <label>Name <input name="name" required maxlength="64" placeholder="e.g. panel-automation"></label>
        <div class="form-actions"><button class="btn" type="button" data-modal="close">Cancel</button><button class="btn primary" type="submit">Create</button></div>
      </form>`);
    $("#token-form").onsubmit = async (ev) => {
      ev.preventDefault();
      try {
        const t = await api("POST", "/api/v1/tokens", { name: $("#token-form input[name=name]").value.trim() });
        const example = `curl ${state.status.admin_self_signed ? "-k " : ""}-H "Authorization: Bearer ${t.token}" ${state.status.admin_url}/api/v1/forwards`;
        openModal(`<h3>Token created</h3>
          <p class="muted">Copy it now, it will not be shown again.</p>
          <div class="cmd-block"><div class="cmd-head"><span>Token</span><button class="btn small ghost" data-copy="${esc(t.token)}">Copy</button></div><pre class="cmd">${esc(t.token)}</pre></div>
          <div class="cmd-block"><div class="cmd-head"><span>Example</span><button class="btn small ghost" data-copy="${esc(example)}">Copy</button></div><pre class="cmd">${esc(example)}</pre></div>
          <div class="form-actions"><button class="btn primary" data-modal="close">Done</button></div>`);
        refresh();
      } catch (e) { fail(e); }
    };
  }

  // ---- actions ------------------------------------------------------------
  async function handleAction(btn) {
    const { action, id } = btn.dataset;
    const client = state.clients.find((c) => c.id === id);
    const grp = state.groups.find((g) => g.id === id);
    try {
      switch (action) {
        case "new-client": clientModal(); break;
        case "rename-client": clientModal(client); break;
        case "install": installModal(client || await api("GET", `/api/v1/clients/${id}`)); break;
        case "rotate":
          if (await confirmDialog("Rotate token?", `The current token for “${client.name}” stops working immediately and the client is disconnected. You will need to run the new install command on that machine.`, "Rotate")) {
            const c = await api("POST", `/api/v1/clients/${id}/rotate-token`); toast("Token rotated"); await refresh(); installModal(c);
          }
          break;
        case "update-client":
          if (await confirmDialog("Update client?", `Push ${client.update.server_version} to “${client.name}” (currently ${client.client_version || "unknown"})? The client downloads the new binary through its tunnel, verifies it and restarts itself; players are disconnected for a few seconds.`, "Update")) {
            await api("POST", `/api/v1/clients/${id}/update`); toast("Update requested"); refresh();
          }
          break;
        case "update-all": {
          const n = state.clients.filter((c) => c.update && c.update.available).length;
          if (await confirmDialog("Update all outdated clients?", `Push the server's version to ${n} client${n === 1 ? "" : "s"}. Each one restarts itself; players are disconnected for a few seconds.`, "Update all")) {
            const r = await api("POST", "/api/v1/clients/update-all");
            toast(`Update requested for ${r.requested} client${r.requested === 1 ? "" : "s"}${r.skipped.length ? `, ${r.skipped.length} skipped` : ""}`); refresh();
          }
          break;
        }
        case "delete-client":
          if (await confirmDialog("Delete client?", `Delete “${client.name}” and all ${client.forward_group_count} of its forwards (${client.forward_count} port${client.forward_count === 1 ? "" : "s"})? This cannot be undone.`)) {
            await api("DELETE", `/api/v1/clients/${id}`); toast("Client deleted"); refresh();
          }
          break;
        case "new-forward":
          if (!state.clients.length) { toast("Add a client first", true); break; }
          forwardModal(null, btn.dataset.client); break;
        case "edit-forward": forwardModal(grp); break;
        case "expand-group":
          if (state.expanded.has(id)) state.expanded.delete(id); else state.expanded.add(id);
          renderForwards(); break;
        case "toggle-forward":
          await api("PATCH", `/api/v1/forward-groups/${id}`, { enabled: btn.dataset.enabled !== "true" }); refresh(); break;
        case "delete-forward": {
          const n = grp.forwards.length;
          if (await confirmDialog("Delete forward?", `Delete “${grp.name}” (${n === 1 ? `port ${grp.forwards[0].public_port}` : `${n} ports: ${grp.ports}`})? Players will no longer be able to connect through it.`)) {
            await api("DELETE", `/api/v1/forward-groups/${id}`); toast("Forward deleted"); refresh();
          }
          break;
        }
        case "new-token": tokenModal(); break;
        case "delete-token":
          if (await confirmDialog("Revoke token?", "Anything using this token will stop working immediately.", "Revoke")) {
            await api("DELETE", `/api/v1/tokens/${id}`); toast("Token revoked"); refresh();
          }
          break;
      }
    } catch (e) { fail(e); }
  }

  document.addEventListener("click", (ev) => {
    const copy = ev.target.closest("[data-copy]");
    if (copy) { copyText(copy.dataset.copy); return; }
    const modalBtn = ev.target.closest("[data-modal=close]");
    if (modalBtn) { closeModal(); return; }
    if (ev.target === $("#modal")) { closeModal(); return; }
    const btn = ev.target.closest("[data-action]");
    if (btn) handleAction(btn);
  });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && !$("#modal").hidden) closeModal(); });
  $("#tabs").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (b) setTab(b.dataset.tab); });

  $("#login-form").onsubmit = async (ev) => {
    ev.preventDefault();
    const form = ev.target; const err = $("#login-error"); err.hidden = true;
    try {
      await api("POST", "/api/v1/auth/login", { username: form.username.value, password: form.password.value });
      form.password.value = ""; start();
    } catch (e) { err.textContent = e.message; err.hidden = false; }
  };
  $("#logout").onclick = async () => { try { await api("POST", "/api/v1/auth/logout"); } catch { /* ignore */ } showLogin(); };

  $("#settings-form").onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api("PUT", "/api/v1/settings", { public_host: ev.target.public_host.value.trim() }); toast("Settings saved"); refresh(); } catch (e) { fail(e); }
  };
  $("#firewall-form").onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api("PUT", "/api/v1/settings", { firewall: ev.target.firewall.value }); toast("Firewall setting saved"); refresh(); } catch (e) { fail(e); }
  };
  $("#updates-form").onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api("PUT", "/api/v1/settings", { auto_update_clients: ev.target.auto_update_clients.checked }); toast("Update setting saved"); refresh(); } catch (e) { fail(e); }
  };
  $("#password-form").onsubmit = async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    try {
      await api("POST", "/api/v1/auth/password", { current_password: f.current_password.value, new_password: f.new_password.value });
      f.reset(); toast("Password changed, please sign in again"); showLogin();
    } catch (e) { fail(e); }
  };

  function start() {
    showApp();
    setTab(state.tab);
    clearInterval(state.timer);
    state.timer = setInterval(refresh, 5000);
  }

  (async () => {
    try { await api("GET", "/api/v1/auth/me"); start(); }
    catch { showLogin(); }
  })();
})();
