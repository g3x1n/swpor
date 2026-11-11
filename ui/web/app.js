/*
 * swpor 本机 Web 控制台前端（SPEC 9.5）。原生 JavaScript，无第三方依赖。
 *
 * 页面上的结果与执行轨迹全部来自后端转发的 porctl / porta / pord 实际输出；
 * 前端不实现任何算法。所有动态文本都用 textContent 写入，文件名等内容不会被当作 HTML 解析。
 */
"use strict";

/* ===================================================================== */
/* 基础工具                                                               */
/* ===================================================================== */

// 会话令牌：启动地址的 URL 片段 #token=...；读出后从地址栏去掉（截图里不出现令牌）
const TOKEN = (() => {
  const m = /(?:^|[#&])token=([0-9a-f]{64})/.exec(location.hash);
  let t = m ? m[1] : null;
  try {
    if (t) sessionStorage.setItem("swpor-token", t);
    else t = sessionStorage.getItem("swpor-token");
  } catch (e) { /* 存储不可用时只在本页有效 */ }
  if (m) history.replaceState(null, "", location.pathname);
  return t;
})();

/** 创建元素：h("div", {class: "x", onclick: f}, 子节点或字符串...) */
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked" || k === "disabled" || k === "selected") el[k] = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const SVG_NS = "http://www.w3.org/2000/svg";
const ICONS = {
  overview: "M3 12l9-8 9 8M5 10v10h5v-6h4v6h5V10",
  owner: "M12 12a4 4 0 100-8 4 4 0 000 8zM4 21a8 8 0 0116 0",
  server: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
  auditor: "M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-5-5M8 11l2 2 4-4",
  tamper: "M12 3l10 18H2zM12 10v5M12 18h.01",
  files: "M3 6h7l2 2h9v11H3z",
};
function icon(name) {
  const s = document.createElementNS(SVG_NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.8");
  s.setAttribute("stroke-linecap", "round");
  s.setAttribute("stroke-linejoin", "round");
  const p = document.createElementNS(SVG_NS, "path");
  p.setAttribute("d", ICONS[name]);
  s.append(p);
  return s;
}

function fmtBytes(n) {
  if (n === undefined || n === null) return "—";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)) + " " + u[i];
}
function fmtMs(ms) {
  if (ms === undefined || ms === null) return "—";
  return ms >= 1000 ? (ms / 1000).toFixed(2) + " s" : ms.toFixed(ms >= 100 ? 0 : 1) + " ms";
}
function fmtTime(t) {
  const d = new Date(t * 1000);
  return d.toLocaleTimeString("zh-CN", { hour12: false });
}
function fmtDateTime(t) {
  const d = new Date(t * 1000);
  return d.toLocaleString("zh-CN", { hour12: false });
}
function shortId(hex) { return hex ? hex.slice(0, 8) + "…" + hex.slice(-4) : "—"; }
function baseName(p) { return (p || "").split("/").pop(); }

function toast(msg, isErr) {
  const el = h("div", { class: "toast" + (isErr ? " err" : "") }, msg);
  document.getElementById("toasts").append(el);
  setTimeout(() => el.remove(), isErr ? 6000 : 3200);
}

/* ===================================================================== */
/* API                                                                    */
/* ===================================================================== */

async function api(path, body) {
  const opts = { headers: { "X-Swpor-Token": TOKEN || "" } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`);
  return data;
}

/** 提交一个任务并选中它；返回任务快照 */
async function runJob(path, body) {
  try {
    const job = await api(path, body);
    S.selected = job.id;
    S.details.set(job.id, job);
    await refreshJobs();
    return job;
  } catch (e) {
    toast(e.message, true);
    return null;
  }
}

function uploadFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload?name=" + encodeURIComponent(file.name));
    xhr.setRequestHeader("X-Swpor-Token", TOKEN || "");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    xhr.onload = () => {
      let d = null;
      try { d = JSON.parse(xhr.responseText); } catch (e) { d = null; }
      if (xhr.status === 200) resolve(d);
      else reject(new Error((d && d.error) || `HTTP ${xhr.status}`));
    };
    xhr.onerror = () => reject(new Error("上传失败（网络错误）"));
    xhr.send(file);
  });
}

async function download(path) {
  try {
    const r = await fetch("/api/download?path=" + encodeURIComponent(path),
      { headers: { "X-Swpor-Token": TOKEN || "" } });
    if (!r.ok) throw new Error(`下载失败：HTTP ${r.status}`);
    const url = URL.createObjectURL(await r.blob());
    const a = h("a", { href: url, download: baseName(path) });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (e) {
    toast(e.message, true);
  }
}

/* ===================================================================== */
/* 状态                                                                   */
/* ===================================================================== */

const S = {
  view: "overview",
  data: null,          // /api/state
  jobs: [],            // /api/jobs（摘要）
  details: new Map(),  // 任务 id → 完整快照
  selected: null,
  dataSig: "",
};
const F = {};          // 表单字段值，按字段 id 保存，重新渲染时恢复

const VIEWS = [
  ["overview", "概览"],
  ["owner", "数据所有者"],
  ["server", "存储服务端"],
  ["auditor", "第三方审计者"],
  ["tamper", "篡改实验"],
  ["files", "工作区"],
];

async function refreshState() {
  try {
    S.data = await api("/api/state");
  } catch (e) {
    toast("读取状态失败：" + e.message, true);
    return;
  }
  renderTopbar();
  const sig = JSON.stringify(S.data) + "|" + S.jobs.map((j) => j.id + j.status).join(",");
  if (sig !== S.dataSig) {
    S.dataSig = sig;
    renderView();
  }
}

async function refreshJobs() {
  let list;
  try { list = await api("/api/jobs"); } catch (e) { return; }
  const before = new Map(S.jobs.map((j) => [j.id, j.status]));
  S.jobs = list;
  let finished = false;
  const fetches = [];
  for (const j of list) {
    const was = before.get(j.id);
    const cached = S.details.get(j.id);
    const running = j.status === "running";
    if (was === "running" && !running) finished = true;
    // 选中的任务运行中时持续刷新；其他任务结束后取一次完整结果
    if ((j.id === S.selected && (running || !cached || cached.status === "running")) ||
        (!running && (!cached || cached.status === "running"))) {
      fetches.push(api("/api/jobs/" + j.id).then((d) => S.details.set(j.id, d)).catch(() => {}));
    }
  }
  await Promise.all(fetches);
  renderJobs();
  if (finished) await refreshState();
  else if (S.view === "overview" || S.view === "auditor" || S.view === "tamper") {
    const sig = JSON.stringify(S.data) + "|" + S.jobs.map((j) => j.id + j.status).join(",");
    if (sig !== S.dataSig) { S.dataSig = sig; renderView(); }
  }
}

let pollTimer = null;
async function poll() {
  clearTimeout(pollTimer);
  await refreshJobs();
  if (S.view === "server") await refreshState();
  const running = S.jobs.some((j) => j.status === "running");
  pollTimer = setTimeout(poll, running ? 600 : S.view === "server" ? 2000 : 4000);
}

/* ===================================================================== */
/* 表单辅助                                                               */
/* ===================================================================== */

function fval(id, def) { return F[id] !== undefined ? F[id] : def; }

function field(label, control, cls) {
  return h("label", { class: "field" + (cls ? " " + cls : "") }, h("span", {}, label), control);
}
function textInput(id, def, attrs) {
  return h("input", Object.assign({
    type: "text", id, value: fval(id, def),
    oninput: (e) => { F[id] = e.target.value; },
  }, attrs || {}));
}
function numInput(id, def, attrs) {
  return h("input", Object.assign({
    type: "number", id, value: fval(id, def),
    oninput: (e) => { F[id] = e.target.value; },
  }, attrs || {}));
}
/** options: [{value, label}]；当前值不在选项中时取第一个 */
function selectInput(id, options, def, onchange) {
  let cur = fval(id, def);
  if (!options.some((o) => o.value === cur)) cur = options.length ? options[0].value : "";
  F[id] = cur;
  const sel = h("select", {
    id, disabled: options.length === 0,
    onchange: (e) => { F[id] = e.target.value; if (onchange) onchange(e.target.value); },
  }, options.length ? options.map((o) => h("option", { value: o.value, selected: o.value === cur }, o.label))
    : h("option", { value: "" }, "（无）"));
  return sel;
}
function checkInput(id, label, def, disabled, onchange) {
  const on = !disabled && !!fval(id, def);
  return h("label", { class: "check" + (disabled ? " disabled" : "") },
    h("input", {
      type: "checkbox", id, checked: on, disabled,
      onchange: (e) => { F[id] = e.target.checked; if (onchange) onchange(); },
    }), label);
}
function intOf(id, def) {
  const v = String(fval(id, def)).trim();
  return /^[0-9]+$/.test(v) ? parseInt(v, 10) : NaN;
}

/* ---- 由状态导出的列表 ---- */

function keyFiles(kinds) {
  const out = [];
  for (const k of (S.data ? S.data.keys : [])) {
    for (const f of k.files) if (kinds.includes(f.kind)) out.push({ ...f, key: k.name, scheme: k.scheme });
  }
  return out;
}
const KIND_LABEL = { priv: "Priv 私钥", pub_sk: "Pub 私钥", pub_pk: "Pub 公钥" };
function keyOptions(kinds) {
  return keyFiles(kinds).map((f) => ({ value: f.path, label: `${f.key} / ${f.name}（${KIND_LABEL[f.kind]}）` }));
}
function tags() { return S.data ? S.data.tags : []; }
function tagByPath(p) { return tags().find((t) => t.path === p); }
function tagByFid(fid) { return tags().find((t) => t.info && t.info.file_id === fid); }
function serverAddr() {
  const s = S.data && S.data.server;
  return s && s.running ? s.address : "";
}

/** 为某个标签选择默认密钥：存储时使用的密钥优先，否则选同方案的第一个 */
function defaultKeyFor(tag, kinds) {
  const files = keyFiles(kinds);
  if (tag.meta && tag.meta.key && files.some((f) => f.path === tag.meta.key)) return tag.meta.key;
  const scheme = tag.info && tag.info.scheme;
  const f = files.find((x) => x.scheme === scheme);
  return f ? f.path : null;
}
/** 标签对应的存储位置参数 */
function targetFor(tag) {
  const m = tag.meta || {};
  if (m.target === "remote") return { target: "remote", server: m.server };
  return { target: "local" };
}
function locationLabel(tag) {
  const m = tag.meta || {};
  if (m.target === "remote") return "远程 " + m.server;
  return tag.local_stored ? "本地存储" : "本地（已删除）";
}

/* ---- 任务结果解读 ---- */

function jobBadge(j) {
  if (j.status === "running") return h("span", { class: "badge run" }, h("span", { class: "dot" }), "运行中");
  if (j.status === "cancelled") return h("span", { class: "badge warn" }, "已取消");
  if (j.status === "error") return h("span", { class: "badge fail" }, "启动失败");
  if (j.result === "PASS") return h("span", { class: "badge pass" }, "PASS");
  if (j.result === "FAIL") return h("span", { class: "badge fail" }, "FAIL");
  if (j.exit_code === 0) return h("span", { class: "badge pass" }, "成功");
  return h("span", { class: "badge fail" }, j.exit_meaning || "失败");
}
function argOf(cmd, name) {
  const i = (cmd || []).indexOf(name);
  return i >= 0 ? cmd[i + 1] : undefined;
}
/** 已结束的审计记录（porctl audit 与 porta），按时间倒序 */
function auditRecords(kinds) {
  const recs = [];
  for (const j of S.jobs) {
    if (!kinds.includes(j.kind) || j.status === "running") continue;
    const d = S.details.get(j.id);
    if (!d) continue;
    if (j.kind === "audit") {
      const o = d.outputs[d.outputs.length - 1];
      const tag = tagByPath(argOf(d.command, "--tag"));
      recs.push({
        time: d.started, job: d.id, by: "porctl audit", tag: tag ? tag.name : argOf(d.command, "--tag"),
        fid: tag && tag.info.file_id, result: o ? o.result : "ERROR", l: o && o.l,
        challenge: o && o.challenge, elapsed: o && o.elapsed_ms, proof: o && o.proof_bytes,
        error: !o ? (d.log[0] || d.exit_meaning) : null,
      });
    } else {
      for (const o of d.outputs) {
        const tag = tagByFid(o.file_id);
        recs.push({
          time: Date.parse(o.time) / 1000 || d.started, job: d.id, by: "porta",
          tag: tag ? tag.name : shortId(o.file_id), fid: o.file_id, result: o.result, l: o.l,
          challenge: o.challenge, elapsed: o.elapsed_ms, proof: o.proof_bytes, error: o.error,
        });
      }
    }
  }
  return recs.sort((a, b) => b.time - a.time);
}

/* ===================================================================== */
/* 外框：顶栏、导航、任务面板                                             */
/* ===================================================================== */

function renderTopbar() {
  const el = document.getElementById("topbar-status");
  el.replaceChildren();
  if (!S.data) return;
  const srv = S.data.server;
  append(el, [
    h("span", { class: "badge" }, "v" + S.data.version),
    h("span", { class: "badge" }, { darwin: "macOS", linux: "Linux", win32: "Windows" }[S.data.platform] || S.data.platform),
    srv.available
      ? (srv.running
        ? h("span", { class: "badge pass" }, h("span", { class: "dot" }), "pord 运行中 " + srv.address)
        : h("span", { class: "badge" }, "pord 未启动"))
      : h("span", { class: "badge" }, "本平台无 pord"),
  ]);
}

function renderNav() {
  const nav = document.getElementById("nav");
  nav.replaceChildren();
  const iconFor = { overview: "overview", owner: "owner", server: "server", auditor: "auditor", tamper: "tamper", files: "files" };
  VIEWS.forEach(([id, label], i) => {
    if (i === 4) nav.append(h("div", { class: "nav-sep" }));
    nav.append(h("button", {
      class: "nav-item" + (S.view === id ? " active" : ""),
      onclick: () => go(id),
    }, icon(iconFor[id]), label));
  });
  nav.append(h("div", { class: "nav-foot" }, "仅监听 127.0.0.1", h("br"), "结果来自 porctl / porta / pord 实际输出"));
}

function go(view) {
  S.view = view;
  try { sessionStorage.setItem("swpor-view", view); } catch (e) { /* 忽略 */ }
  renderNav();
  renderView();
  document.getElementById("main").scrollTop = 0;
  poll();
}

function renderJobs() {
  const root = document.getElementById("jobs");
  const running = S.jobs.filter((j) => j.status === "running").length;
  const list = h("div", { class: "job-list" });
  if (!S.jobs.length) list.append(h("div", { class: "empty" }, "还没有任务"));
  for (const j of S.jobs) {
    list.append(h("div", {
      class: "job-item" + (j.id === S.selected ? " sel" : ""),
      onclick: () => { S.selected = j.id; renderJobs(); refreshJobs(); },
    },
    h("div", { class: "jt", title: j.title }, `#${j.id} ${j.title}`),
    jobBadge(j),
    h("div", { class: "jm" }, `${fmtTime(j.started)} · ${fmtMs(j.elapsed_ms)}`)));
  }
  const keepScroll = root.querySelector(".job-list");
  const st = keepScroll ? keepScroll.scrollTop : 0;
  const detScroll = root.querySelector(".job-detail");
  const ds = detScroll ? detScroll.scrollTop : 0;
  root.replaceChildren(
    h("div", { class: "jobs-head" }, h("h2", {}, "任务与执行轨迹"),
      running ? h("span", { class: "badge run" }, h("span", { class: "dot" }), `${running} 个运行中`) : null),
    list,
    renderJobDetail());
  root.querySelector(".job-list").scrollTop = st;
  root.querySelector(".job-detail").scrollTop = ds;
}

/* ---- 任务详情：命令、结果、trace 时间线 ---- */

function renderJobDetail() {
  const box = h("div", { class: "job-detail" });
  const d = S.selected !== null ? S.details.get(S.selected) : null;
  if (!d) {
    box.append(h("div", { class: "empty" }, "选择一个任务查看命令、结果与执行轨迹（SPEC 9.4 trace 事件）"));
    return box;
  }
  box.append(
    h("h3", {}, `#${d.id} ${d.title}`),
    h("div", { class: "actions" }, jobBadge(d),
      d.exit_code !== null && d.exit_code !== undefined
        ? h("span", { class: "muted" }, `退出码 ${d.exit_code}（${d.exit_meaning}）`) : null,
      d.status === "running" ? h("button", {
        class: "btn small danger",
        onclick: async () => { try { await api(`/api/jobs/${d.id}/cancel`, {}); refreshJobs(); } catch (e) { toast(e.message, true); } },
      }, "取消") : null),
    h("div", { class: "cmd" }, "$ " + d.command.map((a) => (/[\s"']/.test(a) ? `"${a}"` : a)).join(" ")));

  const tl = timeline(d);
  if (tl.childElementCount) box.append(h("div", { class: "hint" }, "执行轨迹"), tl);
  const res = resultView(d);
  if (res) box.append(res);
  if (d.extra && d.extra.out) {
    box.append(h("div", { class: "actions" },
      h("button", { class: "btn small primary", onclick: () => download(d.extra.out) }, "下载恢复的文件"),
      h("span", { class: "mono muted" }, d.extra.out)));
  }
  if (d.log.length) box.append(h("div", { class: "hint" }, "程序输出"), h("pre", { class: "log" }, d.log.join("\n")));
  if (d.outputs.length) {
    box.append(h("details", { class: "raw" }, h("summary", {}, `--json 原始输出（${d.outputs.length} 行）`),
      h("pre", { class: "log" }, d.outputs.map((o) => JSON.stringify(o)).join("\n"))));
  }
  if (d.events.length) {
    box.append(h("details", { class: "raw" }, h("summary", {}, `trace 原始事件（保留 ${d.events.length} 条）`),
      h("pre", { class: "log" }, d.events.map((e) => JSON.stringify(e)).join("\n"))));
  }
  return box;
}

function chips(list, total) {
  const c = h("div", { class: "chips" }, list.map((i) => h("span", { class: "chip" }, i)));
  if (total !== undefined && total > list.length) c.append(h("span", { class: "chip" }, `… 共 ${total}`));
  return c;
}

function timeline(d) {
  const ol = h("ol", { class: "timeline" });
  const item = (title, t, body, cls) => ol.append(h("li", { class: cls || "" },
    h("div", { class: "tl-head" }, title, h("span", { class: "tl-t" }, t !== undefined ? "+" + fmtMs(t) : "")),
    body ? h("div", { class: "tl-body" }, body) : null));
  let n = 0, stripes = 0, stripeK = 0, stripeM = 0, lastTag = null, stripeT;
  const flushStripes = () => {
    if (stripes) item("纠删码编码", stripeT, `${stripes} 个 RS 条带（每条带 k = ${stripeK} 数据块 + m = ${stripeM} 校验块）`);
    stripes = 0;
  };
  const flushTag = () => {
    if (!lastTag) return;
    const done = (lastTag.i || 0) + 1;
    item("打标签 σᵢ", lastTag.t_ms, [`已完成 ${done} / ${n} 块`,
      h("div", { class: "progress" }, (() => { const b = h("div"); b.style.width = (n ? Math.min(100, (100 * done) / n) : 0) + "%"; return b; })())]);
    lastTag = null;
  };
  for (const e of d.events) {
    if (e.type !== "ec_stripe") flushStripes();
    if (e.type !== "tag_block" && e.type !== "ec_stripe") flushTag();
    switch (e.type) {
      case "file_split":
        n = e.n;
        item("分块", e.t_ms, `n = ${e.n} 块，每块 s = ${e.s} 个扇区（${fmtBytes(e.block_bytes)}），原文件 L = ${fmtBytes(e.L)}`);
        break;
      case "ec_stripe":
        if (!stripes) stripeT = e.t_ms;
        stripes++; stripeK = e.k; stripeM = e.m;
        break;
      case "tag_block":
        lastTag = e;
        break;
      case "tag_done":
        item("打标签完成", e.t_ms, `${e.n} 块，耗时 ${fmtMs(e.elapsed_ms)}`, "ok");
        break;
      case "challenge":
        item("生成挑战", e.t_ms, [`l = ${e.l}，模式 ${e.mode === "seed" ? "种子挑战（SPEC 3.5.2）" : "显式挑战（SPEC 3.5.1）"}`,
          e.indices ? chips(e.indices, e.l > e.indices.length ? e.l : undefined) : null]);
        break;
      case "prove_done":
        item("服务端生成证明", e.t_ms, `l = ${e.l}，s = ${e.s}，耗时 ${fmtMs(e.elapsed_ms)}，证明 ${fmtBytes(e.proof_bytes)}`);
        break;
      case "verify":
        item("验证", e.t_ms, [h("div", { class: "verdict " + (e.result === "PASS" ? "pass" : "fail") }, e.result),
          h("div", {}, `验证耗时 ${fmtMs(e.elapsed_ms)}`)], e.result === "PASS" ? "ok" : "bad");
        break;
      case "tamper":
        item("篡改块", e.t_ms, [`${e.count} 块，模式 ${e.mode}`, e.indices ? chips(e.indices, e.count) : null], "bad");
        break;
      default:
        item(e.type, e.t_ms, JSON.stringify(e));
    }
  }
  flushStripes();
  flushTag();
  return ol;
}

function kv(pairs) {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of pairs) if (v !== undefined && v !== null && v !== "") dl.append(h("dt", {}, k), h("dd", {}, v));
  return dl;
}

function resultView(d) {
  const o = d.outputs[d.outputs.length - 1];
  if (!o) return null;
  switch (d.kind) {
    case "store":
      return kv([["file_id", h("span", { class: "mono" }, o.file_id)], ["标签", d.extra.tag],
        ["分块", `n = ${o.n}，s = ${o.s}`], ["原文件大小", fmtBytes(o.L)],
        ["RS", o.rs_k ? `${o.rs_k}:${o.rs_m}` : "不使用"], ["位置", o.mode === "remote" ? "远程" : "本地"],
        ["总耗时", fmtMs(o.elapsed_ms)]]);
    case "audit":
      return kv([["结果", o.result], ["方案", o.scheme], ["挑战", `${o.challenge}，l = ${o.l}`],
        ["证明生成", fmtMs(o.prove_ms)], ["验证", fmtMs(o.verify_ms)], ["总耗时", fmtMs(o.elapsed_ms)],
        ["挑战大小", fmtBytes(o.challenge_bytes)], ["证明大小", fmtBytes(o.proof_bytes)]]);
    case "porta": {
      const t = h("table", { class: "tbl" }, h("tr", {}, ["时间", "文件", "结果", "l", "耗时"].map((x) => h("th", {}, x))));
      for (const r of d.outputs) {
        const tag = tagByFid(r.file_id);
        t.append(h("tr", {}, h("td", {}, (r.time || "").replace("T", " ").replace("Z", "")),
          h("td", {}, tag ? tag.name : shortId(r.file_id)),
          h("td", {}, h("span", { class: "badge " + (r.result === "PASS" ? "pass" : "fail") }, r.result)),
          h("td", { class: "num" }, r.l), h("td", { class: "num" }, fmtMs(r.elapsed_ms))));
      }
      return h("div", { class: "table-wrap" }, t);
    }
    case "tamper":
      return kv([["修改的块", `${o.modified} / ${o.n}`], ["模式", o.mode]]);
    case "retrieve":
      return kv([["结果", o.result]]);
    case "keygen":
      return kv([["方案", o.scheme], ["文件", (o.files || []).join("，")]]);
    default:
      return null;
  }
}

/* ===================================================================== */
/* 页面                                                                   */
/* ===================================================================== */

function renderView() {
  const main = document.getElementById("main");
  if (!S.data) return;
  // 重新渲染时保留焦点与光标位置
  const act = document.activeElement;
  const focusId = act && act.id && main.contains(act) ? act.id : null;
  const selStart = focusId && act.selectionStart !== undefined ? act.selectionStart : null;
  const scroll = main.scrollTop;
  const fn = { overview: viewOverview, owner: viewOwner, server: viewServer, auditor: viewAuditor, tamper: viewTamper, files: viewFiles }[S.view];
  main.replaceChildren(...fn());
  main.scrollTop = scroll;
  if (focusId) {
    const el = document.getElementById(focusId);
    if (el) {
      el.focus();
      try { if (selStart !== null) el.setSelectionRange(selStart, selStart); } catch (e) { /* number 输入框不支持 */ }
    }
  }
}

function pageHead(title, desc) {
  return h("div", { class: "page-head" }, h("h1", {}, title), desc ? h("p", {}, desc) : null);
}

/* ---------------- 概览 ---------------- */

function viewOverview() {
  const d = S.data;
  const recs = auditRecords(["audit", "porta"]);
  const pass = recs.filter((r) => r.result === "PASS").length;
  const fail = recs.filter((r) => r.result === "FAIL").length;
  const stat = (label, value, foot) => h("div", { class: "card stat" },
    h("div", { class: "label" }, label), h("div", { class: "value" }, value), h("div", { class: "foot" }, foot));
  const party = (ic, title, desc, kvs, view) => h("div", { class: "party", onclick: () => go(view) },
    h("div", { class: "ptitle" }, icon(ic), title), h("div", { class: "pdesc" }, desc),
    kvs.map((x) => h("div", { class: "pkv" }, x)));
  const link = (top, bottom, both) => h("div", { class: "link" }, h("span", {}, top),
    h("div", { class: "arrow" + (both ? " both" : "") }), h("span", {}, bottom));

  const has = (kind, pred) => S.jobs.some((j) => j.kind === kind && j.status !== "running" && (!pred || pred(j)));
  const steps = [
    ["生成密钥", "数据所有者生成 Priv 或 Pub 密钥（porctl keygen）", d.keys.length > 0, "owner"],
    ["上传数据文件", "把要外包存储的文件放进工作区", d.data.length > 0, "owner"],
    ["预处理与存储", "纠删码、打标签 σᵢ，存入服务端（porctl store）", d.tags.length > 0, "owner"],
    ["审计通过", "挑战 → 证明 → 验证，结果 PASS（porctl audit / porta）", pass > 0, "auditor"],
    ["篡改存储块", "在本地存储中按比例篡改（porctl tamper）", has("tamper", (j) => j.exit_code === 0), "tamper"],
    ["审计失败", "再次审计，验证等式不成立，结果 FAIL", fail > 0, "tamper"],
    ["恢复文件", "纠删码按擦除恢复原文件（porctl retrieve）", has("retrieve", (j) => j.exit_code === 0), "owner"],
  ];
  return [
    pageHead("概览", "本控制台以子进程调用 porctl、porta、pord，页面上的结果和执行轨迹都是这些程序的实际输出。"),
    h("div", { class: "grid grid-4" },
      stat("密钥", d.keys.length, `${d.keys.filter((k) => k.scheme === "priv").length} Priv · ${d.keys.filter((k) => k.scheme === "pub").length} Pub`),
      stat("已存储文件", d.tags.length, `本地 ${d.tags.filter((t) => t.local_stored).length} · 远程 ${d.tags.filter((t) => (t.meta || {}).target === "remote").length}`),
      stat("审计 PASS", pass, `共 ${recs.length} 次审计`),
      stat("审计 FAIL", fail, fail ? "检测到数据损坏" : "尚未检测到损坏")),
    h("div", { class: "card", style: null }, h("h2", {}, "三方模型", h("span", { class: "sub" }, "点击进入对应角色")),
      h("div", { class: "parties" },
        party("owner", "数据所有者", "持有私钥，预处理文件并生成标签，可审计、恢复。",
          [`密钥 ${d.keys.length} 个`, `数据文件 ${d.data.length} 个`], "owner"),
        link("M*、σᵢ、t", "检索 / 删除", true),
        party("server", "存储服务端 pord", "存储编码后的文件和标签，响应挑战生成证明。",
          [d.server.available ? (d.server.running ? `运行中 ${d.server.address}` : "未启动") : "本平台不可用",
            `服务端文件 ${d.server.files.length} 个`], "server"),
        link("挑战 Q", "证明 (μ, σ)", true),
        party("auditor", "第三方审计者 porta", "只持有公钥 pk 与文件标签 t，公开验证。",
          [`公钥 ${keyFiles(["pub_pk"]).length} 个`, `Pub 文件 ${d.tags.filter((t) => t.info.scheme === "pub").length} 个`], "auditor"))),
    h("div", { class: "grid grid-2" },
      h("div", { class: "card" }, h("h2", {}, "演示流程", h("span", { class: "sub" }, `${steps.filter((s) => s[2]).length} / ${steps.length} 完成`)),
        h("ol", { class: "steps" }, steps.map(([t, desc, done, v], i) => h("li", { class: done ? "done" : "" },
          h("span", { class: "step-no" }, done ? "✓" : i + 1),
          h("div", {}, h("div", { class: "step-title" }, t), h("div", { class: "step-desc" }, desc)),
          h("button", { class: "btn small", onclick: () => go(v) }, "前往"))))),
      h("div", { class: "card" }, h("h2", {}, "最近审计"), auditTable(recs.slice(0, 8)),
        h("div", { class: "actions" },
          h("button", { class: "btn small", onclick: () => runJob("/api/doctor", {}) }, "运行 porctl doctor 自检"),
          h("span", { class: "muted" }, "工作区：", h("span", { class: "mono" }, d.workspace))))),
  ];
}

function auditTable(recs) {
  if (!recs.length) return h("div", { class: "empty" }, "还没有审计记录");
  const t = h("table", { class: "tbl" }, h("tr", {}, ["时间", "文件", "审计方", "挑战", "结果", "耗时", "证明"].map((x) => h("th", {}, x))));
  for (const r of recs) {
    t.append(h("tr", { onclick: () => { S.selected = r.job; renderJobs(); refreshJobs(); } },
      h("td", { class: "num" }, fmtTime(r.time)),
      h("td", { title: r.fid || "" }, r.tag),
      h("td", { class: "muted" }, r.by),
      h("td", { class: "num" }, r.l ? `${r.challenge === "seed" ? "种子" : "显式"} l=${r.l}` : "—"),
      h("td", {}, h("span", { class: "badge " + (r.result === "PASS" ? "pass" : r.result === "FAIL" ? "fail" : "warn"), title: r.error || "" }, r.result || "ERROR")),
      h("td", { class: "num" }, fmtMs(r.elapsed)),
      h("td", { class: "num" }, r.proof ? fmtBytes(r.proof) : "—")));
  }
  return h("div", { class: "table-wrap" }, t);
}

/* ---------------- 数据所有者 ---------------- */

function viewOwner() {
  const d = S.data;
  return [
    pageHead("数据所有者", "生成密钥、上传文件并存储；之后可以审计、恢复或删除已存储的文件。私钥文件只保存在工作区，不会发送到浏览器。"),
    h("div", { class: "grid grid-2" }, cardKeys(), cardUpload()),
    cardStore(),
    cardStored(),
    d.out.length ? cardOut() : null,
  ];
}

function cardKeys() {
  const d = S.data;
  const list = d.keys.length ? h("table", { class: "tbl" },
    h("tr", {}, h("th", {}, "名称"), h("th", {}, "方案"), h("th", {}, "文件"), h("th", {})),
    d.keys.map((k) => h("tr", {},
      h("td", {}, k.name),
      h("td", {}, h("span", { class: "badge accent" }, k.scheme === "priv" ? "Priv" : "Pub")),
      h("td", { class: "mono muted" }, k.files.map((f) => f.name).join("  ")),
      h("td", {}, h("div", { class: "row-actions" }, h("button", {
        class: "btn small danger",
        onclick: () => removePath("keys/" + k.name, `删除密钥目录 keys/${k.name}？删除后用它存储的文件将无法审计和恢复。`),
      }, "删除")))))) : h("div", { class: "empty" }, "还没有密钥");
  return h("div", { class: "card" }, h("h2", {}, "密钥", h("span", { class: "sub" }, "porctl keygen")),
    list,
    h("div", { class: "form", style: null },
      field("方案", selectInput("kg-scheme", [{ value: "priv", label: "Priv（私有验证，SPEC 4.1）" }, { value: "pub", label: "Pub（公开验证，SPEC 4.2）" }], "priv")),
      field("名称", textInput("kg-name", "", { placeholder: "默认 priv-key / pub-key" }))),
    h("div", { class: "actions" }, h("button", {
      class: "btn primary",
      onclick: () => runJob("/api/keygen", { scheme: F["kg-scheme"], name: (F["kg-name"] || "").trim() || undefined }),
    }, "生成密钥")));
}

function cardUpload() {
  const d = S.data;
  const bar = h("div");
  const input = h("input", { type: "file", id: "up-file", multiple: true });
  const list = d.data.length ? h("table", { class: "tbl" },
    d.data.map((f) => h("tr", {}, h("td", {}, f.name), h("td", { class: "num muted" }, fmtBytes(f.size)),
      h("td", {}, h("div", { class: "row-actions" },
        h("button", { class: "btn small danger", onclick: () => removePath(f.path, `删除 ${f.path}？`) }, "删除")))))) :
    h("div", { class: "empty" }, "还没有数据文件");
  return h("div", { class: "card" }, h("h2", {}, "数据文件", h("span", { class: "sub" }, `上限 ${fmtBytes(d.max_upload)}`)),
    list,
    h("div", { class: "actions" }, input, h("button", {
      class: "btn primary",
      onclick: async (e) => {
        const files = Array.from(input.files || []);
        if (!files.length) { toast("请先选择文件", true); return; }
        e.target.disabled = true;
        try {
          for (const f of files) {
            await uploadFile(f, (p) => { bar.style.width = (p * 100).toFixed(1) + "%"; });
            toast(`已上传 ${f.name}`);
          }
        } catch (err) {
          toast(err.message, true);
        }
        e.target.disabled = false;
        await refreshState();
      },
    }, "上传")),
    h("div", { class: "upload-bar" }, bar));
}

function cardStore() {
  const keyOpts = keyOptions(["priv", "pub_sk"]);
  const dataOpts = S.data.data.map((f) => ({ value: f.path, label: `${f.name}（${fmtBytes(f.size)}）` }));
  const isPub = () => (F["st-key"] || "").endsWith("/pub.sk");
  const rsOpts = [
    { value: "", label: "默认 64:64" }, { value: "8:8", label: "8:8" }, { value: "16:16", label: "16:16" },
    { value: "32:32", label: "32:32" }, { value: "128:64", label: "128:64" }, { value: "none", label: "不使用纠删码" },
  ];
  const remote = fval("st-target", "local") === "remote";
  const rerender = () => renderView();
  return h("div", { class: "card" }, h("h2", {}, "预处理并存储", h("span", { class: "sub" }, "porctl store：纠删码 → 置乱 / 加密 → 分块 → 打标签")),
    keyOpts.length && dataOpts.length ? null : h("div", { class: "notice" }, "需要先生成 Priv 或 Pub 密钥，并上传数据文件。"),
    h("div", { class: "form" },
      field("密钥", selectInput("st-key", keyOpts, "", rerender)),
      field("数据文件", selectInput("st-input", dataOpts, "")),
      field("每块扇区数 s", numInput("st-s", "128", { min: 1, max: 65535 })),
      field("RS 编码 k:m", selectInput("st-rs", rsOpts, "")),
      field("存储位置", selectInput("st-target", [{ value: "local", label: "本地存储（工作区 store/）" }, { value: "remote", label: "远程服务端 pord" }], "local", rerender)),
      remote ? field("服务端地址", textInput("st-server", serverAddr(), { placeholder: "host:port" })) : null,
      h("div", { class: "field" }, h("span", {}, "选项"),
        h("div", { class: "actions", style: null },
          checkInput("st-perm", "秘密置乱", false, isPub()),
          checkInput("st-encrypt", "加密", false, isPub())))),
    isPub() ? h("p", { class: "hint" }, "Pub 方案不支持置乱与加密（SPEC 5）。") : null,
    h("div", { class: "actions" }, h("button", {
      class: "btn primary", disabled: !keyOpts.length || !dataOpts.length,
      onclick: () => {
        const s = intOf("st-s", "128");
        if (!(s >= 1 && s <= 65535)) { toast("s 应为 1～65535 的整数", true); return; }
        const body = { key: F["st-key"], input: F["st-input"], s, rs: F["st-rs"] || "", target: F["st-target"] };
        if (body.target === "remote") body.server = (fval("st-server", serverAddr()) || "").trim();
        if (!isPub()) { body.perm = !!F["st-perm"]; body.encrypt = !!F["st-encrypt"]; }
        runJob("/api/store", body);
      },
    }, "存储")));
}

function flagBadges(info) {
  const f = info.flags || {};
  return [f.rs ? h("span", { class: "badge" }, `RS ${info.rs_k}:${info.rs_m}`) : h("span", { class: "badge" }, "无 RS"),
    f.perm ? h("span", { class: "badge" }, "置乱") : null, f.encrypt ? h("span", { class: "badge" }, "加密") : null];
}

function cardStored() {
  const ts = tags();
  const body = ts.length ? h("div", { class: "table-wrap" }, h("table", { class: "tbl" },
    h("tr", {}, ["标签", "方案", "分块", "原文件", "编码", "位置", ""].map((x) => h("th", {}, x))),
    ts.map((t) => {
      const i = t.info || {};
      const key = defaultKeyFor(t, ["priv", "pub_sk", "pub_pk"]);
      const tgt = targetFor(t);
      const gone = tgt.target === "local" && !t.local_stored;
      return h("tr", {},
        h("td", { title: i.file_id || "" }, h("div", {}, t.name), h("div", { class: "mono muted" }, shortId(i.file_id))),
        h("td", {}, h("span", { class: "badge accent" }, i.scheme === "priv" ? "Priv" : "Pub")),
        h("td", { class: "num" }, `n=${i.n} s=${i.s}`),
        h("td", { class: "num" }, fmtBytes(i.L)),
        h("td", {}, h("div", { class: "chips" }, flagBadges(i))),
        h("td", {}, locationLabel(t)),
        h("td", {}, h("div", { class: "row-actions" },
          h("button", {
            class: "btn small primary", disabled: !key || gone,
            onclick: () => runJob("/api/audit", { key, tag: t.path, l: auditL(), seed_mode: !!F["ow-seed"], ...tgt }),
          }, "审计"),
          h("button", {
            class: "btn small", disabled: !key || gone,
            onclick: () => runJob("/api/retrieve", { key, tag: t.path, ...tgt }),
          }, "恢复"),
          h("button", {
            class: "btn small danger", disabled: gone,
            onclick: () => { if (confirm(`删除服务端上 ${t.name} 对应的存储（porctl delete）？`)) runJob("/api/delete", { tag: t.path, ...tgt }); },
          }, "删除存储"),
          h("button", {
            class: "btn small danger",
            onclick: () => removePath(t.path, `移除标签文件 ${t.path}？没有标签将无法再审计或恢复该文件。`),
          }, "移除标签"))));
    }))) : h("div", { class: "empty" }, "还没有存储文件");
  return h("div", { class: "card" }, h("h2", {}, "已存储的文件", h("span", { class: "sub" }, "porctl audit / retrieve / delete")),
    h("div", { class: "form" },
      field("挑战块数 l", numInput("ow-l", "128", { min: 1 })),
      h("div", { class: "field" }, h("span", {}, "挑战方式"), checkInput("ow-seed", "种子挑战（--seed-mode）", false))),
    h("p", { class: "hint" }, "审计和恢复默认使用存储时的密钥；Pub 文件也可以交给第三方审计者用公钥审计。"),
    body);
}
function auditL() {
  const l = intOf("ow-l", "128");
  return l >= 1 ? l : 128;
}

function cardOut() {
  return h("div", { class: "card" }, h("h2", {}, "恢复结果", h("span", { class: "sub" }, "工作区 out/")),
    h("table", { class: "tbl" }, S.data.out.map((f) => h("tr", {},
      h("td", {}, f.name), h("td", { class: "num muted" }, fmtBytes(f.size)), h("td", { class: "num muted" }, fmtDateTime(f.mtime)),
      h("td", {}, h("div", { class: "row-actions" },
        h("button", { class: "btn small primary", onclick: () => download(f.path) }, "下载"),
        h("button", { class: "btn small danger", onclick: () => removePath(f.path, `删除 ${f.path}？`) }, "删除")))))));
}

async function removePath(path, msg) {
  if (!confirm(msg)) return;
  try {
    await api("/api/remove", { path });
    toast("已删除 " + path);
  } catch (e) {
    toast(e.message, true);
  }
  await refreshState();
}

/* ---------------- 存储服务端 ---------------- */

function viewServer() {
  const s = S.data.server;
  const head = pageHead("存储服务端", "pord 存储编码后的文件 M* 与标签 t，响应挑战并生成证明（SPEC 8）。控制台启动的 pord 只监听 127.0.0.1，数据目录为工作区 srv/。");
  if (!s.available) {
    return [head, h("div", { class: "notice warn" },
      "本平台没有 pord：Windows 只做客户端（SPEC 2.1）。可以在“数据所有者”页面选择远程服务端并填写 Linux / macOS 上 pord 的地址。")];
  }
  const up = s.running && s.started ? Math.round(Date.now() / 1000 - s.started) : 0;
  const statusCard = h("div", { class: "card" }, h("h2", {}, "pord 进程",
    s.running ? h("span", { class: "badge pass" }, h("span", { class: "dot" }), "运行中") : h("span", { class: "badge" }, "未启动")),
  s.running ? kv([["监听地址", h("span", { class: "mono" }, s.address)], ["进程号", s.pid], ["线程数", s.threads],
    ["运行时间", `${Math.floor(up / 60)} 分 ${up % 60} 秒`], ["命令", h("span", { class: "mono" }, (s.command || []).join(" "))]])
    : h("div", {},
      s.exit_code !== undefined ? h("p", { class: "hint" }, `上次退出码 ${s.exit_code}`) : null,
      h("div", { class: "form" },
        field("端口（0 = 自动选择）", numInput("srv-port", "0", { min: 0, max: 65535 })),
        field("线程数", numInput("srv-threads", "4", { min: 1, max: 64 })))),
  h("div", { class: "actions" }, s.running
    ? h("button", { class: "btn danger", onclick: () => serverCall("/api/server/stop", {}) }, "停止 pord")
    : h("button", {
      class: "btn primary",
      onclick: () => {
        const port = intOf("srv-port", "0"), threads = intOf("srv-threads", "4");
        if (!(port >= 0 && port <= 65535) || !(threads >= 1 && threads <= 64)) { toast("端口或线程数超出范围", true); return; }
        serverCall("/api/server/start", { port, threads });
      },
    }, "启动 pord")));
  const files = h("div", { class: "card" }, h("h2", {}, "服务端存储的文件", h("span", { class: "sub" }, "srv/")),
    s.files.length ? h("table", { class: "tbl" }, s.files.map((fid) => {
      const t = tagByFid(fid);
      return h("tr", {}, h("td", { class: "mono" }, shortId(fid)), h("td", {}, t ? t.name : h("span", { class: "muted" }, "（无本地标签）")));
    })) : h("div", { class: "empty" }, "没有文件"));
  const evs = h("div", { class: "card" }, h("h2", {}, "服务端执行轨迹", h("span", { class: "sub" }, "logs/pord.trace.ndjson 最近 40 条")),
    s.events.length ? h("div", { class: "table-wrap" }, h("table", { class: "tbl" },
      h("tr", {}, h("th", {}, "事件"), h("th", {}, "内容")),
      s.events.slice().reverse().map((e) => {
        const { type, ...rest } = e;
        return h("tr", {}, h("td", {}, h("span", { class: "badge" }, type)), h("td", { class: "mono muted" }, JSON.stringify(rest)));
      }))) : h("div", { class: "empty" }, "暂无事件"));
  const log = h("div", { class: "card" }, h("h2", {}, "服务端日志", h("span", { class: "sub" }, "logs/pord.log")),
    s.log.length ? h("pre", { class: "log" }, s.log.join("\n")) : h("div", { class: "empty" }, "暂无日志"));
  return [head, h("div", { class: "grid grid-2" }, statusCard, files), evs, log];
}

async function serverCall(path, body) {
  try {
    await api(path, body);
  } catch (e) {
    toast(e.message, true);
  }
  await refreshState();
}

/* ---------------- 第三方审计者 ---------------- */

function viewAuditor() {
  const pkOpts = keyOptions(["pub_pk"]);
  const pubTags = tags().filter((t) => t.info.scheme === "pub");
  const sel = F["ta-tags"] || (F["ta-tags"] = {});
  const running = S.jobs.find((j) => j.kind === "porta" && j.status === "running");
  const chosen = pubTags.filter((t) => sel[t.path]);
  const locs = new Set(chosen.map((t) => JSON.stringify(targetFor(t))));
  const form = h("div", { class: "card" }, h("h2", {}, "发起审计", h("span", { class: "sub" }, "porta：只使用 pk 与 t")),
    h("p", { class: "hint" }, "第三方审计者只持有 Pub 公钥 pub.pk 和文件标签 t，不持有任何私钥（SPEC 4.2、9.4.1）。默认使用种子挑战。"),
    pkOpts.length ? null : h("div", { class: "notice" }, "需要先在“数据所有者”页面生成 Pub 密钥并存储文件。"),
    h("div", { class: "form" },
      field("公钥", selectInput("ta-pk", pkOpts, "")),
      field("挑战块数 l", numInput("ta-l", "128", { min: 1 })),
      field("轮数（0 = 一直运行）", numInput("ta-count", "1", { min: 0 })),
      field("间隔（秒）", numInput("ta-interval", "5", { min: 0 })),
      h("div", { class: "field" }, h("span", {}, "挑战方式"), checkInput("ta-explicit", "显式挑战（--explicit）", false))),
    h("div", { class: "hint" }, "选择要审计的文件（同一次审计的文件需位于同一存储位置）："),
    pubTags.length ? h("table", { class: "tbl" }, pubTags.map((t) => h("tr", {},
      h("td", {}, h("label", { class: "check" }, h("input", {
        type: "checkbox", checked: !!sel[t.path],
        onchange: (e) => { sel[t.path] = e.target.checked; renderView(); },
      }), t.name)),
      h("td", { class: "mono muted" }, shortId(t.info.file_id)),
      h("td", {}, locationLabel(t))))) : h("div", { class: "empty" }, "没有 Pub 方案的文件"),
    h("div", { class: "actions" },
      h("button", {
        class: "btn primary", disabled: !pkOpts.length || !chosen.length || locs.size !== 1 || !!running,
        onclick: () => {
          const l = intOf("ta-l", "128"), count = intOf("ta-count", "1"), interval = intOf("ta-interval", "5");
          if (!(l >= 1) || !(count >= 0) || !(interval >= 0)) { toast("参数应为非负整数", true); return; }
          runJob("/api/porta", { pk: F["ta-pk"], tags: chosen.map((t) => t.path), l, count, interval, explicit: !!F["ta-explicit"], ...targetFor(chosen[0]) });
        },
      }, "开始审计"),
      running ? h("button", {
        class: "btn danger",
        onclick: async () => { try { await api(`/api/jobs/${running.id}/cancel`, {}); refreshJobs(); } catch (e) { toast(e.message, true); } },
      }, "停止审计") : null,
      locs.size > 1 ? h("span", { class: "hint" }, "所选文件位于不同的存储位置，请分开审计。") : null));
  const recs = auditRecords(["porta"]);
  const hist = h("div", { class: "card" }, h("h2", {}, "审计日志", h("span", { class: "sub" }, `${recs.length} 条 · 同时追加到 logs/porta.log`)),
    auditTable(recs.slice(0, 50)));
  return [pageHead("第三方审计者", "公开验证：任何持有公钥的一方都可以审计 Pub 方案的文件，不需要数据所有者参与。"), form, hist];
}

/* ---------------- 篡改实验 ---------------- */

function viewTamper() {
  const local = tags().filter((t) => t.local_stored);
  const opts = local.map((t) => ({ value: t.path, label: `${t.name}（${t.info.scheme === "priv" ? "Priv" : "Pub"}，n = ${t.info.n}）` }));
  const tag = tagByPath(fval("tp-tag", opts.length ? opts[0].value : ""));
  const ratio = parseFloat(fval("tp-ratio", "0.1"));
  const form = h("div", { class: "card" }, h("h2", {}, "篡改本地存储", h("span", { class: "sub" }, "porctl tamper（仅用于测试与演示）")),
    opts.length ? null : h("div", { class: "notice" }, "只能篡改本地存储中的文件。请先在“数据所有者”页面以本地存储方式存储一个文件。"),
    h("div", { class: "form" },
      field("文件", selectInput("tp-tag", opts, "", () => renderView())),
      field("模式", selectInput("tp-mode", [
        { value: "flip", label: "flip：每块随机翻转 1 比特" },
        { value: "zero", label: "zero：整块置 0" },
        { value: "delete", label: "delete：删除（整块置 0）" }], "flip")),
      field(`比例 ${(ratio * 100).toFixed(1)}%`, h("input", {
        type: "range", id: "tp-ratio", min: 0, max: 1, step: 0.005, value: String(ratio),
        oninput: (e) => { F["tp-ratio"] = e.target.value; e.target.previousSibling.textContent = `比例 ${(parseFloat(e.target.value) * 100).toFixed(1)}%`; },
      })),
      field("随机种子（可选）", numInput("tp-seed", "", { min: 0, placeholder: "随机" }))),
    h("div", { class: "actions" },
      h("button", {
        class: "btn danger", disabled: !tag,
        onclick: () => {
          const seed = String(fval("tp-seed", "")).trim();
          if (seed && !/^[0-9]+$/.test(seed)) { toast("种子应为非负整数", true); return; }
          runJob("/api/tamper", { tag: tag.path, mode: F["tp-mode"], ratio: parseFloat(fval("tp-ratio", "0.1")), seed: seed || undefined });
        },
      }, "执行篡改"),
      h("button", {
        class: "btn primary", disabled: !tag || !defaultKeyFor(tag, ["priv", "pub_sk", "pub_pk"]),
        onclick: () => runJob("/api/audit", { key: defaultKeyFor(tag, ["priv", "pub_sk", "pub_pk"]), tag: tag.path, l: intOf("tp-l", "128") || 128, target: "local" }),
      }, "立即审计"),
      h("label", { class: "field" }, h("span", {}, "审计 l"), numInput("tp-l", "128", { min: 1 })),
      h("button", {
        class: "btn", disabled: !tag || !defaultKeyFor(tag, ["priv", "pub_sk", "pub_pk"]),
        onclick: () => runJob("/api/retrieve", { key: defaultKeyFor(tag, ["priv", "pub_sk", "pub_pk"]), tag: tag.path, target: "local" }),
      }, "尝试恢复")),
    h("p", { class: "hint" }, "检测概率：随机篡改比例为 ρ 时，l 个挑战块全部避开被篡改块的概率约为 (1 − ρ)ˡ，审计 FAIL 的概率约为 1 − (1 − ρ)ˡ（SPEC 10.2）。"),
    tag ? h("p", { class: "hint" }, `当前参数下理论检测概率约 ${((1 - Math.pow(1 - ratio, intOf("tp-l", "128") || 128)) * 100).toFixed(2)}%（l 不超过 n = ${tag.info.n} 时）。`) : null);
  return [pageHead("篡改实验", "模拟服务端丢失或损坏数据：篡改后再审计应得到 FAIL；在纠删码容错范围内仍可恢复原文件。"),
    form, tag ? blockMap(tag) : null];
}

/** 块状态图：标出最近一次篡改和最近一次审计挑战的块（trace 事件只列出前 64 个下标） */
function blockMap(tag) {
  const n = tag.info.n;
  const fid = tag.info.file_id;
  let tamper = null, chal = null, verdict = null;
  for (const j of S.jobs) {
    const d = S.details.get(j.id);
    if (!d || d.status === "running") continue;
    if (!tamper && d.kind === "tamper" && argOf(d.command, "--file-id") === fid) tamper = d;
    if (!chal && d.kind === "audit" && argOf(d.command, "--tag") === tag.path) chal = d;
  }
  const tset = new Set(), cset = new Set();
  let tcount = 0;
  if (tamper) for (const e of tamper.events) if (e.type === "tamper") { (e.indices || []).forEach((i) => tset.add(i)); tcount = e.count; }
  if (chal) for (const e of chal.events) {
    if (e.type === "challenge") (e.indices || []).forEach((i) => cset.add(i));
    if (e.type === "verify") verdict = e.result;
  }
  const card = h("div", { class: "card" }, h("h2", {}, "块状态", h("span", { class: "sub" }, `n = ${n}`)));
  if (n > 4096) {
    card.append(h("p", { class: "hint" }, "块数超过 4096，不绘制块图。"));
    return card;
  }
  const parity = tag.info.flags && tag.info.flags.rs ? (i) => (i % (tag.info.rs_k + tag.info.rs_m)) >= tag.info.rs_k : () => false;
  const grid = h("div", { class: "blocks" });
  for (let i = 0; i < n; i++) {
    const c = "blk" + (parity(i) ? " parity" : "") + (tset.has(i) ? " tampered" : "") + (cset.has(i) ? " challenged" : "");
    grid.append(h("div", { class: c, title: `块 ${i}` }));
  }
  card.append(
    h("p", { class: "hint" }, [
      tamper ? `最近一次篡改：#${tamper.id}，共 ${tcount} 块（图中标出前 ${tset.size} 个）。` : "还没有篡改记录。",
      chal ? ` 最近一次审计：#${chal.id}，${verdict || "?"}，图中标出前 ${cset.size} 个挑战块。` : " 还没有审计记录。",
      tag.info.flags && tag.info.flags.perm ? " 该文件启用了秘密置乱，块的位置与原文件无关。" : ""].join("")),
    grid,
    h("div", { class: "legend" },
      h("span", {}, h("i", { class: "blk" }), "数据块"),
      tag.info.flags && tag.info.flags.rs ? h("span", {}, h("i", { class: "blk parity" }), "校验块（按条带布局推算）") : null,
      h("span", {}, h("i", { class: "blk tampered" }), "被篡改"),
      h("span", {}, h("i", { class: "blk challenged" }), "被挑战"),
      h("span", {}, h("i", { class: "blk tampered challenged" }), "被篡改且被挑战")));
  return card;
}

/* ---------------- 工作区 ---------------- */

function viewFiles() {
  const d = S.data;
  const section = (title, sub, files, canDownload) => h("div", { class: "card" }, h("h2", {}, title, h("span", { class: "sub" }, sub)),
    files.length ? h("table", { class: "tbl" }, files.map((f) => h("tr", {},
      h("td", {}, f.name), h("td", { class: "num muted" }, fmtBytes(f.size)), h("td", { class: "num muted" }, fmtDateTime(f.mtime)),
      h("td", {}, h("div", { class: "row-actions" },
        canDownload ? h("button", { class: "btn small", onclick: () => download(f.path) }, "下载") : null,
        h("button", { class: "btn small danger", onclick: () => removePath(f.path, `删除 ${f.path}？`) }, "删除")))))) :
      h("div", { class: "empty" }, "空"));
  return [
    pageHead("工作区", "控制台读写的文件都在工作区的固定子目录中。"),
    h("div", { class: "card" }, kv([["路径", h("span", { class: "mono" }, d.workspace)],
      ["程序", Object.entries(d.programs).map(([k, v]) => `${k} ${v ? "✓" : "✗"}`).join("   ")]])),
    h("div", { class: "grid grid-2" },
      section("数据文件", "data/", d.data, true),
      section("标签", "tags/", d.tags, false),
      section("恢复结果", "out/", d.out, true),
      h("div", { class: "card" }, h("h2", {}, "其他目录"), kv([
        ["keys/", "密钥文件（私钥内容不会发送到浏览器）"], ["store/", "本地存储（--local）"],
        ["srv/", "控制台启动的 pord 的数据目录"], ["logs/", "pord 日志、trace、porta 审计日志"]]))),
  ];
}

/* ===================================================================== */
/* 启动                                                                   */
/* ===================================================================== */

async function boot() {
  if (!TOKEN) {
    document.getElementById("main").append(h("div", { class: "fatal" },
      h("h1", {}, "缺少会话令牌"),
      h("p", {}, "请使用 ui/server.py 启动时打印的完整地址（包含 #token=…）打开控制台。")));
    return;
  }
  try {
    const v = sessionStorage.getItem("swpor-view");
    if (v && VIEWS.some(([id]) => id === v)) S.view = v;
  } catch (e) { /* 忽略 */ }
  renderNav();
  renderJobs();
  await refreshState();
  if (!S.data) {
    document.getElementById("main").replaceChildren(h("div", { class: "fatal" },
      h("h1", {}, "无法连接后端"), h("p", {}, "令牌可能已失效（后端重启后会生成新令牌），请使用新打印的地址打开。")));
    return;
  }
  poll();
}

boot();
