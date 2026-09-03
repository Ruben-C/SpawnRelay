/* SpawnRelay management UI */
(() => {
  "use strict";
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const state = { tab: "clients", status: null, clients: [], forwards: [], tokens: [], settings: null, timer: null };

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

  // ---- views --------------------------------------------------------------
  function showLogin() { clearInterval(state.timer); $("#app").hidden = true; $("#login").hidden = false; $("input[name=password]", $("#login-form")).focus(); }
  function showApp() { $("#login").hidden = true; $("#app").hidden = false; }

  function renderStats() {
    const s = state.status; if (!s) return;
    $("#server-host").textContent = s.public_host;
    $("#stats").innerHTML = `
      <div class="stat"><div class="label">Clients online</div><div class="value">${s.clients_online} <span class="muted">/ ${s.clients_total}</span></div></div>
      <div class="stat"><div class="label">Port forwards</div><div class="value">${s.forwards_total}</div></div>
      <div class="stat"><div class="label">Tunnel endpoint</div><div class="value mono copy" data-copy="${esc(s.tunnel_addr)}" title="Click to copy">${esc(s.tunnel_addr)}</div></div>
      <div class="stat"><div class="label">Uptime</div><div class="value">${fmtDur(s.uptime_seconds)} <span class="muted small">v${esc(s.version)}</span></div></div>`;
  }

  function renderClients() {
    const rows = state.clients.map((c) => `
      <tr>
        <td><span class="dot ${c.status.online ? "on" : "off"}"></span>${c.status.online ? "Online" : "Offline"}</td>
        <td><strong>${esc(c.name)}</strong><div class="subtle">${esc(c.hostname || "not connected yet")}${c.os ? ` · ${esc(c.os)}/${esc(c.arch)}` : ""}</div></td>
        <td class="mono">${esc(c.status.online ? c.status.remote_addr : c.last_addr || "—")}</td>
        <td>${c.status.online ? `since ${fmtAgo(c.status.connected_at)}` : fmtAgo(c.last_seen_at)}</td>
        <td>${c.forward_count}</td>
        <td class="actions">
          <button class="btn small primary" data-action="install" data-id="${c.id}">Install</button>
          <button class="btn small" data-action="new-forward" data-client="${c.id}">+ Forward</button>
          <button class="btn small" data-action="rename-client" data-id="${c.id}">Rename</button>
          <button class="btn small" data-action="rotate" data-id="${c.id}">Rotate token</button>
          <button class="btn small danger" data-action="delete-client" data-id="${c.id}">Delete</button>
        </td>
      </tr>`).join("");
    $("#clients-table").innerHTML = state.clients.length
      ? `<div class="table-wrap"><table><thead><tr><th>Status</th><th>Name</th><th>Address</th><th>Seen</th><th>Forwards</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="card empty">No clients yet. Click <strong>Add client</strong> to create one and get its install command.</div>`;
  }

  function renderForwards() {
    const clientById = Object.fromEntries(state.clients.map((c) => [c.id, c]));
    const rows = state.forwards.map((f) => {
      const c = clientById[f.client_id];
      const online = c && c.status.online;
      const st = f.stats || {};
      const active = (st.active_tcp || 0) + (st.active_udp || 0);
      return `<tr>
        <td><strong>${esc(f.name)}</strong>${f.enabled ? "" : ' <span class="badge off">disabled</span>'}</td>
        <td><span class="dot ${online ? "on" : "off"}"></span>${esc(f.client_name || "?")}</td>
        <td>${badge(f.protocol)}</td>
        <td class="mono"><span class="copy" data-copy="${esc(f.public_addr)}" title="Click to copy">${esc(f.public_addr)}</span></td>
        <td class="mono">${esc(f.target_host)}:${f.target_port}</td>
        <td><span title="active connections">${active} active</span><div class="subtle">${st.total_connections || 0} total · ${fmtBytes(st.bytes_in)} in / ${fmtBytes(st.bytes_out)} out</div></td>
        <td><button class="toggle ${f.enabled ? "on" : ""}" data-action="toggle-forward" data-id="${f.id}" data-enabled="${f.enabled}" title="${f.enabled ? "Disable" : "Enable"}"></button></td>
        <td class="actions">
          <button class="btn small" data-action="edit-forward" data-id="${f.id}">Edit</button>
          <button class="btn small danger" data-action="delete-forward" data-id="${f.id}">Delete</button>
        </td>
      </tr>`;
    }).join("");
    $("#forwards-table").innerHTML = state.forwards.length
      ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Client</th><th>Proto</th><th>Public address</th><th>Target</th><th>Traffic</th><th>On</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
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
    $("#server-info-list").innerHTML = `
      <dt>Version</dt><dd>${esc(s.version)} (${esc(s.os)}/${esc(s.arch)})</dd>
      <dt>Tunnel</dt><dd class="mono">${esc(s.tunnel_addr)}</dd>
      <dt>Fingerprint</dt><dd class="mono copy" data-copy="${esc(s.tunnel_fingerprint)}" title="Click to copy">${esc(s.tunnel_fingerprint)}</dd>
      <dt>Admin URL</dt><dd class="mono">${esc(s.admin_url)}</dd>
      <dt>Admin cert</dt><dd>${s.admin_self_signed ? "self-signed (browser warning expected)" : "custom certificate"}</dd>`;
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
      if (state.tab === "forwards") jobs.push(api("GET", "/api/v1/forwards"));
      if (state.tab === "tokens") jobs.push(api("GET", "/api/v1/tokens"));
      if (state.tab === "settings") jobs.push(api("GET", "/api/v1/settings"));
      const [status, clients, extra] = await Promise.all(jobs);
      state.status = status; state.clients = clients;
      if (state.tab === "forwards") state.forwards = extra;
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

  const PRESETS = [
    ["Minecraft Java", 25565, "tcp"], ["Minecraft Bedrock", 19132, "udp"], ["Terraria", 7777, "tcp"],
    ["Valheim", 2456, "udp"], ["Palworld", 8211, "udp"], ["Factorio", 34197, "udp"], ["Rust", 28015, "both"],
    ["ARK: Survival", 7777, "udp"], ["Counter-Strike 2", 27015, "both"], ["Project Zomboid", 16261, "udp"],
    ["Enshrouded", 15636, "udp"], ["7 Days to Die", 26900, "both"], ["Satisfactory", 7777, "both"], ["Team Fortress 2", 27015, "both"],
  ];

  function forwardModal(f, presetClient) {
    const isEdit = !!f;
    f = f || { name: "", client_id: presetClient || (state.clients[0] && state.clients[0].id) || "", protocol: "tcp", public_port: "", target_host: "127.0.0.1", target_port: "", enabled: true };
    const clientOpts = state.clients.map((c) => `<option value="${c.id}" ${c.id === f.client_id ? "selected" : ""}>${esc(c.name)}${c.status.online ? "" : " (offline)"}</option>`).join("");
    const presetOpts = PRESETS.map(([n, p, pr]) => `<option value="${p}|${pr}">${esc(n)} — ${p} ${pr}</option>`).join("");
    openModal(`<h3>${isEdit ? "Edit forward" : "New forward"}</h3>
      <form id="forward-form">
        ${isEdit ? "" : `<label>Game preset (optional) <select name="preset"><option value="">Choose a game to fill in the port…</option>${presetOpts}</select></label>`}
        <label>Name <input name="name" value="${esc(f.name)}" placeholder="e.g. Minecraft survival" maxlength="64"></label>
        <label>Client <select name="client_id" required>${clientOpts}</select></label>
        <div class="row">
          <label>Protocol <select name="protocol">
            <option value="tcp" ${f.protocol === "tcp" ? "selected" : ""}>TCP</option>
            <option value="udp" ${f.protocol === "udp" ? "selected" : ""}>UDP</option>
            <option value="both" ${f.protocol === "both" ? "selected" : ""}>TCP + UDP</option></select></label>
          <label>Public port (on relay) <input name="public_port" type="number" min="1" max="65535" required value="${esc(f.public_port)}"></label>
        </div>
        <div class="row">
          <label>Target host (from client) <input name="target_host" required value="${esc(f.target_host)}"></label>
          <label>Target port <input name="target_port" type="number" min="1" max="65535" required value="${esc(f.target_port)}"></label>
        </div>
        <label class="check"><input type="checkbox" name="enabled" ${f.enabled ? "checked" : ""}> Enabled</label>
        <div class="form-actions"><button class="btn" type="button" data-modal="close">Cancel</button><button class="btn primary" type="submit">${isEdit ? "Save" : "Create"}</button></div>
      </form>`);
    const form = $("#forward-form");
    const preset = form.querySelector("[name=preset]");
    if (preset) preset.onchange = () => {
      if (!preset.value) return;
      const [port, proto] = preset.value.split("|");
      form.public_port.value = port; form.target_port.value = port; form.protocol.value = proto;
      if (!form.name.value) form.name.value = preset.options[preset.selectedIndex].text.split(" — ")[0];
    };
    form.public_port.oninput = () => { if (!isEdit && !form.target_port.dataset.touched) form.target_port.value = form.public_port.value; };
    form.target_port.oninput = () => { form.target_port.dataset.touched = "1"; };
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      const body = {
        name: form.name.value.trim(), client_id: form.client_id.value, protocol: form.protocol.value,
        public_port: Number(form.public_port.value), target_host: form.target_host.value.trim(),
        target_port: Number(form.target_port.value), enabled: form.enabled.checked,
      };
      if (!body.name) delete body.name;
      try {
        if (isEdit) await api("PATCH", `/api/v1/forwards/${f.id}`, body); else await api("POST", "/api/v1/forwards", body);
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
    const fwd = state.forwards.find((f) => f.id === id);
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
        case "delete-client":
          if (await confirmDialog("Delete client?", `Delete “${client.name}” and all ${client.forward_count} of its forwards? This cannot be undone.`)) {
            await api("DELETE", `/api/v1/clients/${id}`); toast("Client deleted"); refresh();
          }
          break;
        case "new-forward":
          if (!state.clients.length) { toast("Add a client first", true); break; }
          forwardModal(null, btn.dataset.client); break;
        case "edit-forward": forwardModal(fwd); break;
        case "toggle-forward":
          await api("PATCH", `/api/v1/forwards/${id}`, { enabled: btn.dataset.enabled !== "true" }); refresh(); break;
        case "delete-forward":
          if (await confirmDialog("Delete forward?", `Delete “${fwd.name}” (port ${fwd.public_port})? Players will no longer be able to connect through it.`)) {
            await api("DELETE", `/api/v1/forwards/${id}`); toast("Forward deleted"); refresh();
          }
          break;
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
