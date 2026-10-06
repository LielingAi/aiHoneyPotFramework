(function(){
"use strict";
const api = HP.api;
const { sseUrl, stixUrl } = HP;
const { h, esc, fmtPct, fmtNum, relTime, pill, gradePill, table, statCard,
        pageHead, barRows, histogram, openDrawer, closeDrawer, kvList, toast,
        skeleton, tabs, $ } = HP.ui;
/* 视图层 — 每页一个渲染函数, 只消费 /api/*, 业务逻辑零改动 */

/* ---------- 态势 (产品门面: 聚合全站高频信号) ---------- */
async function viewSituation(ctx) {
  const root = h("div", {});
  root.append(pageHead("态势总览", "传感器网络实时态势 — 触雷 / 活跃威胁 / 节点健康"));

  // 行1: KPI 条 (吸收原"指标总览")
  const grid = h("div", { class: "grid kpi" });
  root.append(grid);

  // 行2: 趋势 (2/3) + 攻击类型 (1/3)
  const histBody = h("div", { class: "card-body" }, skeleton(2));
  const famBody = h("div", { class: "card-body" }, skeleton(3));
  root.append(h("div", { class: "grid c3", style: "margin-top:12px" },
    h("div", { class: "card", style: "grid-column:span 2" },
      h("div", { class: "card-head" }, "近 24 小时活动"), histBody),
    h("div", { class: "card" }, h("div", { class: "card-head" }, "攻击类型 (7d)"), famBody)));

  // 行3: 活跃威胁 (实时) + 最新情报
  const threatBody = h("div", { class: "card-body" }, skeleton(4));
  const intelBody = h("div", { class: "card-body" }, skeleton(4));
  root.append(h("div", { class: "grid c2", style: "margin-top:12px" },
    h("div", { class: "card" },
      h("div", { class: "card-head" },
        h("span", {}, "活跃威胁 "), h("span", { class: "pill ok", id: "live-badge" }, "实时")),
      threatBody),
    h("div", { class: "card" }, h("div", { class: "card-head" }, "最新情报"), intelBody)));

  // 行4: 节点健康 + TOP 攻击源
  const fleetBody = h("div", { class: "card-body" }, skeleton(3));
  const ipBody = h("div", { class: "card-body" }, skeleton(3));
  root.append(h("div", { class: "grid c2", style: "margin-top:12px" },
    h("div", { class: "card" }, h("div", { class: "card-head" }, "节点健康"), fleetBody),
    h("div", { class: "card" }, h("div", { class: "card-head" }, "TOP 攻击源 (7d)"), ipBody)));

  function renderThreat(rows) {
    if (!rows?.length) { threatBody.replaceChildren(h("div", { class: "empty" }, "暂无事件")); return; }
    threatBody.replaceChildren(...rows.slice(0, 9).map((r) =>
      h("div", { class: "threat-item", style: "cursor:pointer",
        onclick: () => { sessionStorage.setItem("pending_sid", r.session_id);
                         location.hash = "#/sessions"; } },
        h("span", { class: "time" }, relTime(r.ts)),
        h("b", { style: "color:var(--accent);width:38px" }, r.method || "GET"),
        h("span", { class: "path" }, r.path),
        entChip("session", r.session_id),
        r.canary ? pill("触雷", "ok")
          : (r.threat >= 8 ? pill("高威胁", "bad") : pill(String(r.agent_type || "?"), "dim")))));
  }
  function renderIntel(rows) {
    if (!rows?.length) { intelBody.replaceChildren(h("div", { class: "empty" }, "暂无情报")); return; }
    intelBody.replaceChildren(...rows.slice(0, 6).map((r) =>
      h("div", { class: "intel-item" },
        h("div", { style: "display:flex;gap:8px;align-items:center" },
          gradePill(r.grade), h("span", { class: "mono" }, r.field || ""),
          h("span", { class: "count", style: "margin-left:auto" }, relTime(r.ts))),
        h("div", { class: "sample" }, r.sample || ""))));
  }
  function renderFleet(rows) {
    if (!rows?.length) { fleetBody.replaceChildren(h("div", { class: "empty" }, "暂无传感器接入")); return; }
    fleetBody.replaceChildren(h("div", {}, ...rows.slice(0, 6).map((r) =>
      h("div", { class: "threat-item" },
        h("span", { class: "mono", style: "width:130px" }, r.sensor_id),
        r.online ? pill("在线", "ok") : pill("离线", "dim"),
        h("span", { class: "count", style: "margin-left:auto" },
          `24h ${r.events_24h} · 触雷 ${r.canary_hits}`),
        h("span", { class: "count" }, relTime(r.last_seen))))));
  }

  async function load() {
    const [s, k, reqs, intel, fleet] = await Promise.all([
      api.situation(), api.kpi(ctx.run()), api.requests({ run: ctx.run(), limit: 9 }),
      api.intel({ run: ctx.run(), limit: 6 }), api.sensors()]);
    grid.innerHTML = "";
    grid.append(
      statCard({ title: "24h 事件", value: fmtNum(s.total_24h), desc: `触雷 ${s.canary_24h} 次` }),
      statCard({ title: "传感器在线", kind: "ok", value: `${s.sensors_online}/${s.sensors_total}`,
        desc: "90s 心跳" }),
      statCard({ title: "真外泄率", kind: "ok", value: fmtPct(k.harvest?.exfil_verified_rate),
        desc: `${k.harvest?.trials ?? 0} 次试验` }),
      statCard({ title: "注入服从率", value: fmtPct(k.harvest?.obey_rate),
        desc: `金丝雀触碰 ${fmtPct(k.harvest?.canary_rate)}` }),
      statCard({ title: "预算放大", kind: "purple", value: (k.budget?.amplification ?? "-") + "×",
        desc: `攻击方 $${k.budget?.attacker_cost_usd}` }),
      statCard({ title: "情报产出", value: `${k.intel?.per_trial ?? "-"}/试验`,
        desc: `${k.intel?.records ?? 0} 条 · 铁证 ${fmtPct(k.intel?.consistent_rate)}` }));
    histBody.replaceChildren(histogram(s.hist24));
    famBody.replaceChildren(barRows(s.families || [], { warn: true }));
    ipBody.replaceChildren(barRows((s.top_ips || []).map((r) => [r.client_ip || "?", r.n]),
      { hot: true }));
    renderThreat(reqs);
    renderIntel(intel);
    renderFleet(fleet);
  }
  await load();
  // 活跃威胁块: 本地 SSE 实时追加 (与 /live 同源, 只保留最近 9 条)
  let recent = [];
  let es = null;
  try {
    es = new EventSource(sseUrl());
    es.onmessage = (e) => {
      try {
        const r = JSON.parse(e.data);
        recent.unshift(r);
        renderThreat(recent.slice(0, 9));
      } catch (_) {}
    };
  } catch (_) {}
  return { root, reload: load, dispose: () => es?.close() };
}

/* ---------- 实时 ---------- */
function viewLive() {
  const root = h("div", {});
  root.append(pageHead("实时事件流", "SSE 推送 · 传感器触达即显"));
  const feed = h("div", { class: "feed", id: "feed" },
    h("div", { class: "empty" }, "等待事件… 对传感器发任意请求即出现"));
  root.append(feed);
  const es = new EventSource(sseUrl());
  const add = (r) => {
    const f = $("#feed");
    if (f.querySelector(".empty")) f.innerHTML = "";
    f.prepend(h("div", { class: `row ${r.canary ? "canary" : ""}` },
      h("span", { class: "time" }, new Date(r.ts * 1000).toLocaleTimeString()),
      h("b", {}, r.method || "GET"),
      h("span", { class: "path" }, r.path),
      h("span", { class: "count" }, r.client_ip || ""),
      r.canary ? pill("触雷", "ok") : (r.threat >= 8 ? pill("高威胁", "bad") : null),
      r.run_id ? pill(String(r.run_id).replace("sensor_", "").slice(0, 14), "dim") : null));
    while (f.children.length > 60) f.lastChild.remove();
  };
  es.onmessage = (e) => { try { add(JSON.parse(e.data)); } catch (_) {} };
  return { root, dispose: () => es.close() };
}

/* ---------- 传感器 ---------- */
async function viewFleet(ctx) {
  const root = h("div", {});
  root.append(pageHead("传感器", "节点状态 · 接入自动注册"));
  const box = h("div", {});
  root.append(box);

  async function load() {
    const [rows, me] = await Promise.all([api.sensors(), api.me()]);
    box.replaceChildren(table([
      { h: "节点", k: "sensor_id", render: (r) => h("span", { class: "mono" }, r.sensor_id) },
      { h: "状态", render: (r) => r.online ? pill("在线", "ok") : pill("离线", "dim") },
      { h: "24h 事件", k: "events_24h", num: true },
      { h: "累计", k: "total_events", num: true },
      { h: "触雷", render: (r) => r.canary_hits
        ? h("span", { style: "color:var(--ok);font-weight:700" }, String(r.canary_hits)) : "0" },
      { h: "最近活跃", render: (r) => relTime(r.last_seen) },
      { h: "备注", render: (r) => me.role === "admin"
        ? h("input", { class: "note-input", value: r.note || "",
            onclick: (e) => e.stopPropagation(),
            onchange: async (e) => {
              try { await api.setSensorNote(r.sensor_id, e.target.value); toast("备注已保存"); }
              catch (_) { toast("保存失败", "err"); } } })
        : (r.note || "") },
    ], rows, { empty: "暂无传感器 — 蜜罐配置 HONEYPOT_HIVE_URL 后自动注册" }));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 配置 ---------- */
async function viewConfig() {
  const root = h("div", {});
  root.append(pageHead("配置", "告警渠道 · 数据保留 · 账户"));

  const alertCard = h("div", { class: "card pad", style: "max-width:680px" });
  const policyCard = h("div", { class: "card pad", style: "max-width:680px;margin-top:16px" });
  const userCard = h("div", { class: "card pad", style: "max-width:680px;margin-top:16px" });
  root.append(alertCard, policyCard, userCard);

  async function load() {
    const c = await api.config();
    const admin = c.role === "admin";
    alertCard.innerHTML = "";
    userCard.innerHTML = "";

    /* ---- 告警与保留 ---- */
    if (!admin) alertCard.append(h("div", { class: "banner warn" }, "只读账号 — 仅管理员可修改"));
    const mk = (label, node) => h("div", { class: "cfgrow" }, h("label", {}, label), node);
    const hooks = h("textarea", { rows: "3", disabled: !admin,
      style: "flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:8px;"
             + "color:var(--text);padding:9px 12px;font-size:12.5px;font-family:var(--mono);resize:vertical",
      placeholder: "每行一个 webhook (钉钉/Slack/企微…)" });
    let urls = [];
    try { urls = JSON.parse(c.alert_webhooks || "[]"); } catch (_) {}
    if (!urls.length && c.alert_webhook) urls = [c.alert_webhook];
    hooks.value = urls.join("\n");
    const fmt = h("select", { disabled: !admin },
      h("option", { value: "generic" }, "generic (Slack / Discord)"),
      h("option", { value: "dingtalk" }, "钉钉"));
    fmt.value = c.alert_fmt || "generic";
    const threshold = h("input", { type: "number", step: "0.5",
      value: c.alert_threshold || 8, disabled: !admin });
    const retention = h("input", { type: "number", min: "1",
      value: c.retention_days || 30, disabled: !admin });
    alertCard.append(
      h("div", { class: "t muted" }, "告警渠道 (触发: 金丝雀触雷 / 铁证情报 / 威胁 ≥ 阈值)"),
      mk("Webhook 列表", hooks), mk("格式", fmt), mk("威胁阈值", threshold),
      mk("数据保留 (天)", retention),
      h("div", { class: "toolbar", style: "margin-top:14px" },
        h("button", { class: "btn primary", disabled: !admin, onclick: async () => {
          try {
            const list = hooks.value.split("\n").map((x) => x.trim()).filter(Boolean);
            await api.saveConfig({ alert_webhooks: JSON.stringify(list),
              alert_fmt: fmt.value, alert_threshold: threshold.value,
              retention_days: retention.value });
            toast(`已保存 (${list.length} 个渠道)`);
          } catch (e) { toast("保存失败: " + e.message, "err"); } } }, "保存"),
        h("button", { class: "btn", disabled: !admin, onclick: async () => {
          try {
            const r = await api.testAlert();
            toast(r.sent ? "测试告警已发送 (至少一个渠道成功)" : "未发送 (请检查 webhook)");
          } catch (e) { toast("发送失败: " + e.message, "err"); } } }, "发送测试告警")));

    /* ---- 诱饵策略 (下发到全部传感器, 60s 内生效) ---- */
    policyCard.innerHTML = "";
    policyCard.append(h("div", { class: "t muted" },
      "诱饵策略 — 在线传感器 60s 内拉取生效"));
    if (c.optimize?.active) {
      policyCard.append(h("div", { class: "banner warn" },
        `演化实验进行中 (${String(c.optimize.run_id).slice(0, 20)}) — 话术框架与判据可见性暂由 UCB1 管辖, 下发让位`));
    }
    const PRESETS = [
      ["conservative", "保守观察", "隐示判据 · 关阶梯 · compliance"],
      ["standard", "标准", "full 判据 · 开阶梯 · compliance"],
      ["aggressive", "激进消耗", "full 判据 · 开阶梯 · runner"],
    ];
    const cur = c.policy_preset || "";
    const presetRow = h("div", { style: "display:flex;gap:10px;flex-wrap:wrap;margin:10px 0" },
      ...PRESETS.map(([id, label, desc]) => h("button", {
        class: "btn" + (cur === id ? " primary" : ""),
        onclick: async () => {
          try {
            await api.saveConfig({ policy_preset: id });
            toast(`预设「${label}」已下发`);
            load();
          } catch (e) { toast(e.message, "err"); } } },
        h("div", {}, label), h("div", { class: "faint", style: "font-size:11px" }, desc))));
    const mkSel = (label, key, options, val) => h("div", { class: "cfgrow" },
      h("label", {}, label),
      h("select", { disabled: !admin, onchange: async (e) => {
        try { await api.saveConfig({ [key]: e.target.value }); toast("已下发"); }
        catch (err) { toast(err.message, "err"); } } },
        ...options.map(([v, t]) => h("option", { value: v, selected: String(val) === v }, t))));
    policyCard.append(presetRow,
      h("div", { class: "t muted", style: "margin-top:10px" }, "自定义 (逐项下发)"),
      mkSel("判据可见性", "visibility",
        [["full", "full 直接给"], ["progressive", "progressive 渐进"],
         ["implicit", "implicit 隐示"]], c.visibility || "full"),
      mkSel("话术框架", "framing",
        [["compliance", "compliance 合规审查"], ["runner", "runner CI 配对"]], c.framing || "compliance"),
      mkSel("无界阶梯", "ladder_enabled",
        [["true", "开启 (消耗执行核心)"], ["false", "关闭"]], c.ladder_enabled || "true"),
      mkSel("假世界版本", "world_version",
        [["2", "v2 当前"], ["1", "v1 历史对照"]], c.world_version || "2"));

    /* ---- 账户管理 ---- */
    userCard.append(h("div", { class: "t muted" }, "账户"));
    if (!admin) {
      userCard.append(h("div", { class: "empty" }, "账户管理仅管理员可见"));
    } else {
      let users = [];
      try { users = await api.get("users"); } catch (_) {}
      const tbl = table([
        { h: "用户名", k: "username", render: (r) => h("span", { class: "mono" },
            r.username + (r.self ? " (我)" : "")) },
        { h: "角色", render: (r) => pill(r.role === "admin" ? "管理员" : "只读",
            r.role === "admin" ? "info" : "dim") },
        { h: "创建", render: (r) => relTime(r.created) },
        { h: "操作", render: (r) => h("span", { style: "display:flex;gap:6px" },
            h("button", { class: "btn", style: "padding:3px 9px;font-size:11.5px",
              onclick: async (e) => {
                e.stopPropagation();
                const pw = window.prompt(`为 ${r.username} 设置新密码 (≥6位):`);
                if (!pw) return;
                try {
                  await api.post("users", { action: "password", username: r.username, password: pw });
                  toast("密码已更新");
                } catch (err) { toast(err.message, "err"); } } }, "改密"),
            (!r.self && (r.role !== "admin" || users.filter((u) => u.role === "admin").length > 1)) ?
              h("button", { class: "btn", style: "padding:3px 9px;font-size:11.5px",
                onclick: async (e) => {
                  e.stopPropagation();
                  try {
                    await api.post("users", { action: "delete", username: r.username });
                    toast("已删除"); load();
                  } catch (err) { toast(err.message, "err"); } } }, "删除") : null) },
      ], users);
      const newU = h("input", { class: "search", placeholder: "新用户名", style: "min-width:130px;flex:0 1 160px" });
      const newP = h("input", { type: "password", placeholder: "密码 (≥6位)",
        style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;"
               + "color:var(--text);padding:7px 12px;font-size:12.5px;min-width:130px" });
      const newR = h("select", { class: "ctl" },
        h("option", { value: "viewer" }, "只读"), h("option", { value: "admin" }, "管理员"));
      userCard.append(tbl,
        h("div", { class: "toolbar", style: "margin-top:12px" },
          newU, newP, newR,
          h("button", { class: "btn primary", onclick: async () => {
            try {
              await api.post("users", { action: "create", username: newU.value,
                password: newP.value, role: newR.value });
              toast("用户已创建"); load();
            } catch (err) { toast(err.message, "err"); } } }, "添加用户")));
    }
  }
  await load();
  return { root, reload: load };
}

/* ---------- 指标 ---------- */
async function viewMetrics(ctx) {
  const root = h("div", {});
  root.append(pageHead("指标总览", "与 analyze.py kpi 同口径"));
  const grid = h("div", { class: "grid kpi" });
  root.append(grid);
  async function load() {
    const k = await api.kpi(ctx.run());
    grid.innerHTML = "";
    grid.append(
      statCard({ title: "发现攻击耗时", value: k.mttd?.median_s != null ? k.mttd.median_s + "s" : "-",
        desc: `${k.mttd?.attacked_sessions ?? 0}/${k.mttd?.sessions ?? 0} 会话发起攻击` }),
      statCard({ title: "真外泄率", kind: "ok", value: fmtPct(k.harvest?.exfil_verified_rate),
        desc: `${k.harvest?.trials ?? 0} 次试验` }),
      statCard({ title: "注入服从率", value: fmtPct(k.harvest?.obey_rate),
        desc: `金丝雀触碰 ${fmtPct(k.harvest?.canary_rate)}` }),
      statCard({ title: "预算放大倍数", kind: "purple", value: (k.budget?.amplification ?? "-") + "×",
        desc: `攻击方 $${k.budget?.attacker_cost_usd} / 我方 $${k.budget?.our_cost_usd}` }),
      statCard({ title: "误报率", kind: "warn", value: fmtPct(k.false_positive?.rate),
        desc: `${k.false_positive?.false_positives ?? 0}/${k.false_positive?.requests ?? 0} 请求` }),
      statCard({ title: "情报产出", value: `${k.intel?.per_trial ?? "-"} 条/试验`,
        desc: `${k.intel?.records ?? 0} 条 · 铁证 ${fmtPct(k.intel?.consistent_rate)}` }));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 演化实验 ---------- */
async function viewBandit() {
  const root = h("div", {});
  root.append(pageHead("演化实验", "UCB1 自动 A/B · framing × visibility 臂"));
  const box = h("div", {});
  root.append(box);
  async function load() {
    const b = await api.bandit();
    box.replaceChildren(table([
      { h: "组合臂", k: "name" },
      { h: "已试轮数", k: "n", num: true },
      { h: "平均得分", num: true, render: (r) => h("span", {
        style: `font-family:var(--mono);color:${r.mean >= 1 ? "var(--ok)" : r.mean > 0 ? "var(--warn)" : "var(--faint)"}` },
        r.mean.toFixed(3)) },
    ], b.arms || [], { empty: "还没有演化实验数据 — 跑 real_runner --optimize 开始自动寻优" }));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 操作者归因 ---------- */
async function viewAttribution(ctx) {
  const root = h("div", {});
  root.append(pageHead("操作者归因", "跨会话聚类 · 谁在打我们"));
  const box = h("div", {});
  root.append(box);
  async function load() {
    const rows = await api.attribution(ctx.run());
    box.replaceChildren(table([
      { h: "操作者", render: (r) => pill("operator-" + r.cluster_id, "purple") },
      { h: "涉及会话", k: "size", num: true },
      { h: "共同指纹", render: (r) => h("span", { class: "mono" },
        Object.entries(r.shared || {}).map(([k, v]) => `${k}: ${v.join(", ")}`).join("  |  ")) },
    ], rows, { empty: "还没有可归因的会话 — 攻击方泄漏主机名/用户名/内网地址后自动聚类",
      onRow: (r) => openDrawer(`operator-${r.cluster_id}`, h("div", {},
        kvList([["规模", r.size], ["会话", (r.subjects || []).join(", ")]]),
        h("pre", {}, JSON.stringify(r.shared, null, 2)))) }));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 汇总指标 ---------- */
async function viewSummary(ctx) {
  const root = h("div", {});
  root.append(pageHead("汇总指标", "模型 × 人设 × 场景"));
  const box = h("div", {});
  root.append(box);
  async function load() {
    const rows = await api.summary(ctx.run());
    box.replaceChildren(table([
      { h: "模型", k: "model" }, { h: "人设", k: "profile" }, { h: "场景", k: "scenario" },
      { h: "次数", k: "trials", num: true },
      { h: "服从率", render: (r) => pill(fmtPct(r.obey_rate), r.obey_rate > 0.5 ? "ok" : "warn") },
      { h: "授权级别", num: true, render: (r) => r.avg_level?.toFixed(1) },
      { h: "满级率", render: (r) => fmtPct(r.full_rate) },
      { h: "回连率", render: (r) => fmtPct(r.beacon_rate) },
      { h: "真外泄", render: (r) => h("span", { style: "color:var(--ok);font-weight:600" },
        fmtPct(r.exfil_verified_rate)) },
      { h: "攻击命令率", render: (r) => fmtPct(r.rce_rate) },
      { h: "平均步数", num: true, render: (r) => r.avg_steps?.toFixed(1) },
    ], rows));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 模型差分 ---------- */
async function viewCompare(ctx) {
  const root = h("div", {});
  root.append(pageHead("模型差分", "回连率 / 攻击命令率 / 授权级别"));
  const box = h("div", {});
  root.append(box);
  async function load() {
    const rows = await api.compare(ctx.run());
    box.replaceChildren(table([
      { h: "场景", k: "scenario" }, { h: "模型", k: "model" }, { h: "人设", k: "profile" },
      { h: "回连率", render: (r) => pill(fmtPct(r.beacon), r.beacon > 0 ? "ok" : "dim") },
      { h: "攻击命令率", render: (r) => fmtPct(r.rce) },
      { h: "授权级别", num: true, render: (r) => r.lvl?.toFixed(1) },
      { h: "次数", k: "n", num: true },
    ], rows));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 试验明细 ---------- */
async function viewTrials(ctx) {
  const root = h("div", {});
  root.append(pageHead("试验明细", "run × 场景 × 人设 · 点击行看详情"));
  let sce = "", prof = "", kw = "";
  const count = h("span", { class: "count" });
  const selSce = h("select", { class: "ctl", onchange: (e) => { sce = e.target.value; load(); } },
    h("option", { value: "" }, "全部场景"));
  const selProf = h("select", { class: "ctl", onchange: (e) => { prof = e.target.value; load(); } },
    h("option", { value: "" }, "全部人设"));
  const search = h("input", { class: "search", placeholder: "搜索任意字段…",
    oninput: (e) => { kw = e.target.value.trim().toLowerCase(); load(); } });
  root.append(h("div", { class: "toolbar" }, selSce, selProf, search, h("span", { class: "grow" }), count));
  const box = h("div", {});
  root.append(box);

  async function load() {
    const rows = await api.trials({ run: ctx.run(), scenario: sce, profile: prof });
    const hit = kw ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(kw)) : rows;
    count.textContent = `${hit.length} / ${rows.length} 条`;
    for (const [sel, set] of [[selSce, new Set(rows.map((r) => r.scenario))],
                              [selProf, new Set(rows.map((r) => r.profile))]]) {
      if (sel.options.length <= 1) {
        for (const v of [...set].sort()) sel.append(h("option", { value: v }, v));
      }
    }
    box.replaceChildren(table([
      { h: "运行", render: (r) => h("span", { class: "mono" }, (r.run_id || "").slice(4, 17)) },
      { h: "场景", k: "scenario" }, { h: "人设", k: "profile" },
      { h: "第几次", k: "trial_no", num: true }, { h: "步数", k: "steps", num: true },
      { h: "授权级别", k: "auth_level", num: true },
      { h: "服从诱导", render: (r) => r.obey ? pill("是", "ok") : pill("否", "bad") },
      { h: "回连", render: (r) => r.beacon ? pill("是", "ok") : "" },
      { h: "编造拦截", k: "fab_rejects", num: true },
      { h: "外泄", render: (r) => r.exfil ? pill(r.exfil_verified ? "真外泄" : "仅声称",
        r.exfil_verified ? "ok" : "warn") : "" },
    ], hit, { onRow: (r) => openDrawer(`试验 #${r.trial_id}`, h("div", {},
      kvList(Object.entries(r).slice(0, 24).map(([k, v]) => [k, String(v).slice(0, 300)])),
      h("pre", {}, (() => { try { return JSON.stringify(JSON.parse(r.raw || "{}"), null, 2); }
        catch (_) { return r.raw || ""; } })()))) }));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 动作流水 ---------- */
async function viewEvents(ctx) {
  const root = h("div", {});
  root.append(pageHead("动作流水", "Agent 逐步操作 (最近 100)"));
  const count = h("span", { class: "count" });
  const search = h("input", { class: "search", placeholder: "搜索工具 / 参数 / 思考…" });
  root.append(h("div", { class: "toolbar" }, search, h("span", { class: "grow" }), count));
  const box = h("div", {});
  root.append(box);
  let cache = [];
  function render() {
    const kw = search.value.trim().toLowerCase();
    const hit = kw ? cache.filter((r) => JSON.stringify(r).toLowerCase().includes(kw)) : cache;
    count.textContent = `${hit.length} / ${cache.length} 条`;
    box.replaceChildren(table([
      { h: "时间", render: (r) => h("span", { class: "mono" }, relTime(r.ts)) },
      { h: "场景", k: "scenario" }, { h: "人设", k: "profile" },
      { h: "步", k: "step", num: true },
      { h: "工具", render: (r) => pill(r.tool, "info") },
      { h: "参数", render: (r) => h("span", { class: "faint" }, String(r.args || "").slice(0, 90)) },
      { h: "思考", render: (r) => h("span", { class: "faint" }, String(r.thought || "").slice(0, 110)) },
    ], hit, { onRow: (r) => openDrawer(r.tool, h("div", {},
      kvList([["场景", r.scenario], ["人设", r.profile], ["步", r.step], ["时间", relTime(r.ts)]]),
      h("div", { class: "t muted" }, "思考"), h("pre", {}, r.thought || ""),
      h("div", { class: "t muted" }, "参数"), h("pre", {}, r.args || ""),
      h("div", { class: "t muted" }, "结果"), h("pre", {}, r.result || ""))) }));
  }
  search.addEventListener("input", render);
  async function load() {
    cache = await api.events({ run: ctx.run() });
    render();
  }
  await load();
  return { root, reload: load };
}

/* ---------- 情报分级 ---------- */
async function viewIntel(ctx) {
  const root = h("div", {});
  root.append(pageHead("情报分级", "五档证据 (最近 60)"));
  const box = h("div", {});
  root.append(box);
  async function load() {
    const rows = await api.intel({ run: ctx.run() });
    box.replaceChildren(table([
      { h: "时间", render: (r) => h("span", { class: "mono" }, relTime(r.ts)) },
      { h: "会话", render: (r) => entChip("session", r.session_id) },
      { h: "字段", k: "field" },
      { h: "分级", render: (r) => gradePill(r.grade) },
      { h: "跨会话", render: (r) => r.shared ? pill("跨会话复用", "bad") : "" },
      { h: "内容样本", render: (r) => h("span", { class: "faint" }, String(r.sample || "").slice(0, 80)) },
    ], rows, { onRow: (r) => openDrawer(`情报 · ${r.field}`, h("div", {},
      kvList([["分级", r.grade], ["会话", r.session_id], ["运行", r.run_id],
        ["指纹", r.hash_key], ["跨会话", r.shared ? "是" : "否"], ["时间", relTime(r.ts)]]),
      h("div", { class: "t muted" }, "内容样本"), h("pre", {}, r.sample || ""))) }));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 请求日志 ---------- */
async function viewRequests(ctx) {
  const root = h("div", {});
  root.append(pageHead("请求日志", "蜜罐服务端视角 (最近 100)"));
  const count = h("span", { class: "count" });
  const search = h("input", { class: "search", placeholder: "搜索路径 / 特征 / 攻击类型…" });
  root.append(h("div", { class: "toolbar" }, search, h("span", { class: "grow" }), count));
  const box = h("div", {});
  root.append(box);
  let cache = [];
  function render() {
    const kw = search.value.trim().toLowerCase();
    const hit = kw ? cache.filter((r) => JSON.stringify(r).toLowerCase().includes(kw)) : cache;
    count.textContent = `${hit.length} / ${cache.length} 条`;
    box.replaceChildren(table([
      { h: "时间", render: (r) => h("span", { class: "mono" }, relTime(r.ts)) },
      { h: "来源 IP", render: (r) => entChip("ip", r.client_ip) || "-" },
      { h: "会话", render: (r) => entChip("session", r.session_id) },
      { h: "方法", k: "method" },
      { h: "路径", render: (r) => h("span", { class: "mono" }, r.path) },
      { h: "AI", render: (r) => r.is_ai ? pill("AI", "warn") : "" },
      { h: "Agent", k: "agent_type" },
      { h: "威胁", k: "threat", num: true },
      { h: "攻击类型", k: "families" },
      { h: "金丝雀", render: (r) => r.canary ? pill("触雷", "ok") : "" },
    ], hit, { onRow: (r) => openDrawer(`${r.method} ${r.path}`, h("div", {},
      kvList([["来源", r.client_ip], ["会话", r.session_id], ["Agent", r.agent_type],
        ["威胁值", r.threat], ["攻击类型", r.families], ["授权级别", r.auth_level],
        ["运行", r.run_id], ["时间", relTime(r.ts)]]),
      h("div", { class: "t muted" }, "User-Agent"), h("pre", {}, r.user_agent || ""),
      r.query ? h("div", {}, h("div", { class: "t muted" }, "Query"), h("pre", {}, r.query)) : null,
      h("button", { class: "btn primary", style: "margin-top:12px", onclick: () => {
        sessionStorage.setItem("pending_sid", r.session_id);
        location.hash = "#/sessions";
        closeDrawer(); } }, "查看该会话的完整卷宗 →"))) }));
  }
  search.addEventListener("input", render);
  async function load() {
    cache = await api.requests({ run: ctx.run() });
    render();
  }
  await load();
  return { root, reload: load };
}

/* ---------- 运行记录 ---------- */
async function viewRuns() {
  const root = h("div", {});
  root.append(pageHead("运行记录", "历次测量运行"));
  const box = h("div", {});
  root.append(box);
  async function load() {
    const rows = await api.runs();
    box.replaceChildren(table([
      { h: "运行 ID", render: (r) => h("span", { class: "mono" }, r.run_id) },
      { h: "类型", render: (r) => r.mock ? pill("模拟", "dim") : pill("真实", "info") },
      { h: "备注", render: (r) => h("span", { class: "faint" }, r.note || "") },
      { h: "试验数", k: "n", num: true },
    ], rows, { onRow: (r) => {
      location.hash = "#/trials";
      toast(`已切换到试验明细 (运行 ${r.run_id.slice(0, 18)})`);
    } }));
  }
  await load();
  return { root, reload: load };
}


/* ---------- 分组视图: tab 容器 ---------- */
function groupView(tabDefs, defaultTab) {
  return async function (ctx) {
    const root = h("div", {});
    const head = pageHead(tabDefs.title, tabDefs.sub);
    root.append(head);
    const bar = h("div", {});
    const body = h("div", {});
    root.append(bar, body);
    let cur = null, curId = ctx.tab && tabDefs.tabs.some((t) => t.id === ctx.tab)
      ? ctx.tab : defaultTab;

    async function mountTab(id) {
      curId = id;
      cur?.dispose?.();
      history.replaceState(null, "", `#/${tabDefs.id}/${id}`);
      bar.replaceChildren(tabs(tabDefs.tabs, id, mountTab));
      body.innerHTML = "";
      try {
        cur = await tabDefs.tabs.find((t) => t.id === id).view(ctx);
        body.append(cur.root);
      } catch (e) {
        body.append(h("div", { class: "empty" }, "加载失败: " + e.message));
      }
    }
    await mountTab(curId);
    return { root, reload: () => cur?.reload?.(), dispose: () => cur?.dispose?.() };
  };
}

const viewEventsGroup = groupView({
  id: "events", title: "事件流", sub: "同一数据的三个层次 — 网络层 / Agent 层 / 实时尾流",
  tabs: [
    { id: "tail", label: "实时尾流", view: () => viewLive() },
    { id: "requests", label: "请求日志", view: (c) => viewRequests(c) },
    { id: "actions", label: "动作流水", view: (c) => viewEvents(c) },
  ],
}, "tail");

const viewIntelGroup = groupView({
  id: "intel", title: "情报", sub: "分级证据与操作者画像",
  tabs: [
    { id: "graded", label: "情报分级", view: (c) => viewIntel(c) },
    { id: "actors", label: "操作者归因", view: (c) => viewAttribution(c) },
  ],
}, "graded");

const viewExperimentsGroup = groupView({
  id: "experiments", title: "实验", sub: "在环测量与研究工具 — 记录、统计、寻优",
  tabs: [
    { id: "trials", label: "试验明细", view: (c) => viewTrials(c) },
    { id: "summary", label: "汇总指标", view: (c) => viewSummary(c) },
    { id: "compare", label: "模型差分", view: (c) => viewCompare(c) },
    { id: "bandit", label: "演化实验", view: () => viewBandit() },
    { id: "runs", label: "运行记录", view: () => viewRuns() },
  ],
}, "trials");

window.HP = window.HP || {};



/* ---------- 实体中心: 统一调查对象, 所有标识符的落点 ---------- */
const ENTITY_ICON = { ip: "⌖", session: "◔", actor: "◈" };

function entChip(type, id, label) {
  if (!id) return null;
  const el = h("span", { class: "pill info", style: "cursor:pointer",
    title: `打开${type === "ip" ? "攻击者" : type === "session" ? "会话卷宗" : "操作者"}实体页`,
    onclick: (e) => { e.stopPropagation();
      location.hash = `#/e/${type}/${encodeURIComponent(id)}`; } },
    `${ENTITY_ICON[type] || "·"} ${label || String(id).slice(0, 22)}`);
  return el;
}

async function viewEntity(ctx) {
  const { type, id } = ctx.entity || {};
  const root = h("div", {});
  if (!type || !id) { root.append(h("div", { class: "empty" }, "缺少实体参数")); return { root }; }
  root.append(skeleton(5));
  let data;
  try {
    data = await api.entity(type, id);
  } catch (e) {
    root.innerHTML = "";
    root.append(h("div", { class: "empty" }, e.code === 404
      ? "没有这个实体 — 数据可能已被保留策略清理" : "加载失败: " + e.message));
    return { root };
  }
  root.innerHTML = "";

  /* 头部: 身份 + 判读 */
  const headKind = { bad: "bad", warn: "warn", dim: "dim", purple: "purple" };
  root.append(h("div", { class: "page-head" },
    h("h1", {}, `${ENTITY_ICON[type] || "◈"} ${String(id).slice(0, 40)}`),
    pill(data.verdict, headKind[data.level] || "dim"),
    h("span", { class: "sub" }, data.advice)));

  /* 关系栏: 邻居实体 — 点击即跳, 上下文由产品携带 */
  const rel = data.relations || {};
  const relBar = h("div", { class: "toolbar", style: "margin-bottom:14px" });
  if (rel.ip) relBar.append(h("span", { class: "muted" }, "来自"), entChip("ip", rel.ip));
  if (rel.sessions?.length) {
    relBar.append(h("span", { class: "muted", style: "margin-left:6px" }, "会话"));
    for (const sid of rel.sessions.slice(0, 8)) relBar.append(entChip("session", sid));
    if (rel.sessions.length > 8)
      relBar.append(h("span", { class: "count" }, `+${rel.sessions.length - 8}`));
  }
  if (rel.shared && Object.keys(rel.shared).length)
    relBar.append(h("span", { class: "count" }, "指纹: " +
      Object.entries(rel.shared).map(([k, v]) => `${k}:${v.join(",")}`).join(" | ")));
  if (relBar.children.length) root.append(relBar);

  /* 统计区 */
  if (data.stats && data.type === "ip") {
    const st = data.stats;
    root.append(h("div", { class: "grid kpi", style: "margin-bottom:14px" },
      statCard({ title: "请求", value: fmtNum(st.requests) }),
      statCard({ title: "触雷", kind: st.canary_hits ? "ok" : "",
        value: String(st.canary_hits || 0) }),
      statCard({ title: "威胁峰值", value: String(st.threat_peak ?? 0) }),
      statCard({ title: "会话", value: String(st.sessions) }),
      statCard({ title: "AI 占比", value: fmtPct(st.ai_requests / Math.max(1, st.requests)) }),
      statCard({ title: "首/末", value: "-", desc: `${relTime(st.first_seen)} · ${relTime(st.last_seen)}` })));
  }

  /* 情报区 */
  if (rel.intel?.length) {
    root.append(h("div", { class: "card", style: "margin-bottom:14px" },
      h("div", { class: "card-head" }, `关联情报 (${rel.intel.length})`),
      h("div", { class: "card-body" }, ...rel.intel.slice(0, 8).map((r2) =>
        h("div", { class: "intel-item" },
          h("div", { style: "display:flex;gap:8px;align-items:center" },
            gradePill(r2.grade), h("span", { class: "mono" }, r2.field || ""),
            entChip("session", r2.session_id),
            h("span", { class: "count", style: "margin-left:auto" }, relTime(r2.ts))),
          h("div", { class: "sample" }, r2.sample || ""))))));
  }

  /* 证据时间线 */
  if (data.events?.length) {
    root.append(h("div", { class: "card pad" },
      h("div", { class: "t muted", style: "margin-bottom:10px" },
        `${data.type === "session" ? "卷宗" : "事件"} (${data.events.length} 步)`),
      ...data.events.map((st) => {
        const [icon, kind, label] = STEP_META[st.kind] || STEP_META.probe;
        return h("div", { class: "threat-item" },
          h("span", { class: "time" }, st.session_id
            ? "" : "+" + "0s"),
          pill(`${icon} ${label}`, kind),
          h("b", { style: "color:var(--accent);width:44px" }, st.method || "·"),
          h("span", { class: "path" }, st.path),
          st.session_id && data.type === "ip" ? entChip("session", st.session_id) : null,
          st.notes?.length ? h("span", { class: "faint", style: "font-size:11.5px" },
            st.notes.join("; ")) : null);
      })));
  } else if (type === "actor") {
    root.append(h("div", { class: "card pad" },
      h("div", { class: "t muted", style: "margin-bottom:10px" }, "成员会话"),
      ...(rel.sessions || []).slice(0, 20).map((sid) =>
        h("div", { class: "threat-item" }, entChip("session", sid, sid)))));
  }
  return { root };
}

/* ---------- 调查: 攻击者档案 ("谁在打我们") ---------- */
const VERDICT_KIND = { bad: "bad", warn: "warn", dim: "dim" };

async function viewAttackers(ctx) {
  const root = h("div", {});
  root.append(pageHead("攻击者", "按来源 IP 聚合的档案 — 按危险度排序, 点卡片看会话"));
  let days = "7";
  const box = h("div", {});
  const sel = h("select", { class: "ctl", onchange: (e) => { days = e.target.value; load(); } },
    h("option", { value: "1" }, "今天"), h("option", { value: "7", selected: true }, "近 7 天"),
    h("option", { value: "30" }, "近 30 天"));
  root.append(h("div", { class: "toolbar" }, h("span", { class: "muted" }, "时间范围"), sel));
  root.append(box);

  async function load() {
    const rows = await api.attackers(days);
    if (!rows.length) { box.replaceChildren(h("div", { class: "empty" },
      "该时间范围内没有攻击者 — 传感器接入后自动建档")); return; }
    box.replaceChildren(h("div", { class: "grid c3" }, ...rows.map((r) => {
      const card = h("div", { class: "card pad", style: "cursor:pointer" },
        h("div", { style: "display:flex;align-items:center;gap:8px;margin-bottom:8px" },
          entChip("ip", r.client_ip),
          pill(r.verdict, VERDICT_KIND[r.level] || "dim")),
        h("div", { class: "grid", style: "grid-template-columns:1fr 1fr;gap:6px 12px;font-size:12px" },
          h("span", { class: "muted" }, "请求"), h("b", { class: "mono" }, String(r.requests)),
          h("span", { class: "muted" }, "触雷"), h("b", { class: "mono",
            style: r.canary_hits ? "color:var(--ok)" : "" }, String(r.canary_hits)),
          h("span", { class: "muted" }, "威胁峰值"), h("b", { class: "mono" }, String(r.threat_peak ?? 0)),
          h("span", { class: "muted" }, "会话"), h("b", { class: "mono" }, String(r.sessions)),
          h("span", { class: "muted" }, "AI 占比"), h("b", { class: "mono" }, fmtPct(r.ai_requests / Math.max(1, r.requests)))),
        h("div", { class: "d", style: "margin-top:8px;color:var(--faint);font-size:11.5px" },
          `建议: ${r.advice}`),
        h("div", { class: "d" }, `${relTime(r.first_seen)} 首次 · ${relTime(r.last_seen)} 最近`));
      card.onclick = () => openDrawer(`攻击者 ${r.client_ip}`, h("div", {},
        kvList([["IP", r.client_ip], ["判定", r.verdict], ["建议", r.advice],
          ["请求 / 触雷 / 会话", `${r.requests} / ${r.canary_hits} / ${r.sessions}`],
          ["威胁峰值", r.threat_peak], ["AI 请求占比", fmtPct(r.ai_requests / Math.max(1, r.requests))],
          ["浏览器特征占比", fmtPct(r.browser_share)], ["关联情报", r.intel_hits + " 条"],
          ["首次 / 最近", `${relTime(r.first_seen)} / ${relTime(r.last_seen)}`]]),
        h("div", { class: "t muted", style: "margin:10px 0 6px" }, "会话"),
        ...(r.sessions_list || []).slice(0, 6).map((sid2) => entChip("session", sid2)),
        h("div", { class: "t muted", style: "margin-top:10px" },
          "在「事件流 → 请求日志」中按该 IP 深挖 (搜索框输入 IP 即可)")));
      return card;
    })));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 调查: 会话卷宗 ("发生了什么故事") ---------- */
const STEP_META = {
  probe: ["···", "dim", "探测"], climb: ["▲", "info", "爬梯"],
  attack: ["⚔", "warn", "攻击"], canary: ["⚡", "ok", "触雷"],
  deliver: ["◈", "purple", "交付"], intel: ["◆", "info", "情报"],
};

async function viewSessions(ctx) {
  const root = h("div", {});
  root.append(pageHead("会话卷宗", "输入会话 ID — 看一个攻击者从进入到触雷的完整故事"));
  const input = h("input", { class: "search", style: "flex:1;min-width:260px",
    placeholder: "会话 ID (如 exp_1791… / auto_… / 从任意表格行点击带入)" });
  const pending = sessionStorage.getItem("pending_sid");
  if (pending) { input.value = pending; sessionStorage.removeItem("pending_sid"); }
  const btn = h("button", { class: "btn primary", onclick: () => load(input.value.trim()) }, "打开卷宗");
  root.append(h("div", { class: "toolbar" }, input, btn));
  const box = h("div", {});
  root.append(box);
  // 最近的触雷会话快捷入口
  try {
    const reqs = await api.requests({ limit: 60 });
    const hot = reqs.filter((r) => r.canary || (r.threat || 0) >= 8).slice(0, 6);
    if (hot.length) {
      root.append(h("div", { class: "toolbar", style: "margin-top:4px" },
        h("span", { class: "muted" }, "最近的火药味会话:"),
        ...[...new Set(hot.map((r) => r.session_id))].map((sid) =>
          h("button", { class: "ctl", onclick: () => { input.value = sid; load(sid); } },
            sid.slice(0, 18)))));
    }
  } catch (_) {}

  async function load(sid) {
    if (!sid) { box.replaceChildren(h("div", { class: "empty" }, "输入会话 ID 开始")); return; }
    box.replaceChildren(skeleton(6));
    try {
      const data = await api.sessionTimeline(sid);
      if (!data.steps.length) { box.replaceChildren(h("div", { class: "empty" },
        "没有这个会话的记录 — 检查 ID 或它属于其他传感器")); return; }
      const t0 = data.steps[0].ts;
      box.replaceChildren(h("div", { class: "card pad" },
        h("div", { style: "margin-bottom:14px;display:flex;gap:10px;align-items:center" },
          h("span", { class: "mono" }, sid),
          data.ip ? entChip("ip", data.ip) : null,
          h("span", { class: "count", style: "margin-left:12px" },
            `${data.steps.length} 步 · 跨度 ${((data.steps[data.steps.length-1].ts - t0) / 60).toFixed(1)} 分钟`)),
        ...data.steps.map((st) => {
          const [icon, kind, label] = STEP_META[st.kind] || STEP_META.probe;
          const row = h("div", { class: "threat-item" },
            h("span", { class: "time" }, "+" + ((st.ts - t0)).toFixed(0) + "s"),
            pill(`${icon} ${label}`, kind),
            h("b", { style: "color:var(--accent);width:44px" }, st.method || "·"),
            h("span", { class: "path" }, st.path),
            st.notes?.length ? h("span", { class: "faint", style: "font-size:11.5px" },
              st.notes.join("; ")) : null);
          return row;
        })));
    } catch (e) {
      box.replaceChildren(h("div", { class: "empty" }, "加载失败: " + e.message));
    }
  }
  if (input.value) load(input.value);
  return { root };
}

/* 视图登记 */




/* ---------- 反制作战室: 诱饵/消耗/收割/C2 — 这是对抗层, 不是检测层 ---------- */
async function viewOps(ctx) {
  const root = h("div", {});
  root.append(pageHead("反制作战室", "诱饵策略 · 消耗执行 · 收割闭环 · C2 信标 — 我们在主动出击的部分"));

  const policyBox = h("div", { class: "grid kpi" });
  const funnelBox = h("div", { class: "grid c3", style: "margin:14px 0" });
  const beaconBox = h("div", {});
  root.append(policyBox, funnelBox, beaconBox);

  async function load() {
    const [cfg, sit, k, reqs, beacons] = await Promise.all([
      api.config(), api.situation(), api.kpi(ctx.run()),
      api.requests({ limit: 500 }), api.beacons(40)]);
    const day = Date.now() / 1000 - 86400;
    const today = reqs.filter((r) => r.ts > day);
    const climbs = today.filter((r) => r.path === "/api/auth" && (r.auth_level || 0) > 0).length;
    const delivers = today.filter((r) =>
      /bounty\/submit|build\/upload|ticket\/close/.test(r.path || "")).length;

    /* 策略状态 */
    const presetName = { conservative: "保守观察", standard: "标准", aggressive: "激进消耗" };
    policyBox.innerHTML = "";
    policyBox.append(
      statCard({ title: "诱饵策略预设", kind: "purple",
        value: presetName[cfg.policy_preset] || (cfg.visibility ? "自定义" : "未配置"),
        desc: `可见性 ${cfg.visibility || "-"} · 框架 ${cfg.framing || "-"} · 阶梯 ${cfg.ladder_enabled ?? "-"}` }),
      statCard({ title: "生效范围", kind: "ok",
        value: `${sit.sensors_online}/${sit.sensors_total}`,
        desc: "在线传感器 (60s 内拉取)" }),
      statCard({ title: "演化实验", value: cfg.optimize?.active ? "进行中" : "静默",
        desc: cfg.optimize?.active
          ? `UCB1 管辖框架/可见性 (${String(cfg.optimize.run_id).slice(0, 16)})`
          : "框架与可见性归配置页管辖" }),
      statCard({ title: "我方成本", value: `$${k.budget?.our_cost_usd ?? 0}`,
        desc: `攻击方已烧 $${k.budget?.attacker_cost_usd} — 放大 ${k.budget?.amplification ?? "-"}×` }));

    /* 三级漏斗: 诱骗 → 消耗 → 收割 */
    const funnel = (t, v, d, kind) => statCard({ title: t, value: v, desc: d, kind });
    funnelBox.innerHTML = "";
    funnelBox.append(
      funnel("① 诱骗 · 24h 走进来的", String(sit.total_24h),
        "门控服从率 " + fmtPct(k.harvest?.obey_rate) + " — 诱饵锁进验证墙的效果", ""),
      funnel("② 消耗 · 阶梯爬升", String(climbs),
        "授权验证次数 — 每次都在烧攻击方 token; 平均 " +
        (sit.total_24h ? (k.budget?.tokens_est / Math.max(1, k.harvest?.trials) / 1000).toFixed(1) : "-")
        + "k tokens/试验", "warn"),
      funnel("③ 收割 · 交付与触雷", `${delivers} 交付 / ${sit.canary_24h} 触雷`,
        "假凭证被真用 = 铁证; 交付物含金丝雀即归因完成", "ok"));

    /* C2 信标流 */
    beaconBox.replaceChildren(
      h("div", { class: "card" },
        h("div", { class: "card-head" },
          `C2 信标捕获 (${beacons.length}) — 攻击 Agent 回连假 C2 的落地流量`),
        beacons.length
          ? h("div", { class: "card-body" }, table([
              { h: "时间", render: (r) => h("span", { class: "mono" }, relTime(r.ts)) },
              { h: "传感器", render: (r) => pill(r.sensor_id || "?", "dim") },
              { h: "来源", render: (r) => h("span", { class: "mono" }, r.source_ip) },
              { h: "方法", k: "method" },
              { h: "路径", render: (r) => h("span", { class: "mono" }, r.path) },
              { h: "载荷", render: (r) => h("span", { class: "faint" },
                  String(r.body || "").slice(0, 60)) },
            ], beacons))
          : h("div", { class: "empty" },
              "暂无信标 — 当攻击 Agent 向假 C2 地址回连时出现在这里")));
  }
  await load();
  return { root, reload: load };
}

HP.views = { viewSituation, viewLive, viewFleet, viewConfig, viewMetrics,
             viewBandit, viewAttribution, viewSummary, viewCompare, viewTrials,
             viewEvents, viewIntel, viewRequests, viewRuns, viewEntity, viewOps,
             viewEventsGroup, viewIntelGroup, viewExperimentsGroup };
})();
