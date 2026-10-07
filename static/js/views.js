(function(){
"use strict";
const api = HP.api;
const { sseUrl, stixUrl } = HP;
const { h, esc, fmtPct, fmtNum, relTime, pill, gradePill, table, statCard,
        pageHead, barRows, histogram, openDrawer, closeDrawer, kvList, toast,
        skeleton, tabs, pager, $ } = HP.ui;
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
        h("span", {}, "活跃威胁 "), h("span", { class: "pill ok", id: "live-badge" }, "实时"),
        h("a", { href: "#/events/requests", style: "margin-left:auto;font-size:11.5px" }, "查看全部 →")),
      threatBody),
    h("div", { class: "card" },
      h("div", { class: "card-head" }, "最新情报",
        h("a", { href: "#/intel/graded", style: "margin-left:auto;font-size:11.5px" }, "查看全部 →")),
      intelBody)));

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
    const [s, k, reqsP, intelP, fleet] = await Promise.all([
      api.situation(), api.kpi(ctx.run()),
      api.requests({ run: ctx.run(), page_size: 9 }),
      api.intel({ run: ctx.run(), page_size: 6 }), api.sensors()]);
    const reqs = reqsP.rows || [], intel = intelP.rows || [];
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
  let sce = "", prof = "", kw = "", page = 1, pageSize = 50, pgTotal = 0;
  const count = h("span", { class: "count" });
  const selSce = h("select", { class: "ctl", onchange: (e) => { sce = e.target.value; page = 1; load(); } },
    h("option", { value: "" }, "全部场景"));
  const selProf = h("select", { class: "ctl", onchange: (e) => { prof = e.target.value; page = 1; load(); } },
    h("option", { value: "" }, "全部人设"));
  const search = h("input", { class: "search", placeholder: "搜索任意字段…",
    oninput: (e) => { kw = e.target.value.trim().toLowerCase(); load(); } });
  root.append(h("div", { class: "toolbar" }, selSce, selProf, search,
    h("a", { href: "#/experiments/runs", style: "font-size:11.5px" }, "运行记录 →"),
    h("span", { class: "grow" }), count));
  const box = h("div", {});
  root.append(box);
  const pgBox = h("div", {});
  root.append(pgBox);

  async function load() {
    const data = await api.trials({ run: ctx.run(), scenario: sce, profile: prof,
                                    page, page_size: pageSize });
    const rows = data.rows || [];
    pgTotal = data.total || 0;
    const hit = kw ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(kw)) : rows;
    count.textContent = `${hit.length} / 本页 ${rows.length} · 共 ${pgTotal} 条`;
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
    box.append(pager({ page, pageSize, total: pgTotal,
      onPage: (p) => { page = p; load(); },
      onSize: (n) => { pageSize = n; page = 1; load(); } }));
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
  let cache = [], page = 1, pageSize = 50, pgTotal = 0;
  function render() {
    const kw = search.value.trim().toLowerCase();
    const hit = kw ? cache.filter((r) => JSON.stringify(r).toLowerCase().includes(kw)) : cache;
    count.textContent = `${hit.length} / 本页 ${cache.length} · 共 ${pgTotal} 条`;
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
  const pgBox = h("div", {});
  root.append(pgBox);
  async function load() {
    const data = await api.events({ run: ctx.run(), page, page_size: pageSize });
    cache = data.rows || [];
    pgTotal = data.total || 0;
    render();
    pgBox.replaceChildren(pager({ page, pageSize, total: pgTotal,
      onPage: (p) => { page = p; load(); },
      onSize: (n) => { pageSize = n; page = 1; load(); } }));
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
  let page = 1, pageSize = 50, pgTotal = 0;
  const pgBox = h("div", {});
  root.append(pgBox);
  async function load() {
    const data = await api.intel({ run: ctx.run(), page, page_size: pageSize });
    const rows = data.rows || [];
    pgTotal = data.total || 0;
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
    pgBox.replaceChildren(pager({ page, pageSize, total: pgTotal,
      onPage: (p) => { page = p; load(); },
      onSize: (n) => { pageSize = n; page = 1; load(); } }));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 请求日志 ---------- */
async function viewRequests(ctx) {
  const root = h("div", {});
  root.append(pageHead("请求日志", "蜜罐服务端视角 · 分页"));
  const count = h("span", { class: "count" });
  const search = h("input", { class: "search", placeholder: "搜索路径 / 特征 / 攻击类型…" });
  root.append(h("div", { class: "toolbar" }, search, h("span", { class: "grow" }), count));
  const box = h("div", {});
  root.append(box);
  const pgBox = h("div", {});
  root.append(pgBox);
  let cache = [], page = 1, pageSize = 50, pgTotal = 0;
  function render() {
    const kw = search.value.trim().toLowerCase();
    const hit = kw ? cache.filter((r) => JSON.stringify(r).toLowerCase().includes(kw)) : cache;
    count.textContent = `${hit.length} / 本页 ${cache.length} · 共 ${pgTotal} 条`;
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
    const data = await api.requests({ run: ctx.run(), page, page_size: pageSize });
    cache = data.rows || [];
    pgTotal = data.total || 0;
    render();
    pgBox.replaceChildren(pager({ page, pageSize, total: pgTotal,
      onPage: (p) => { page = p; load(); },
      onSize: (n) => { pageSize = n; page = 1; load(); } }));
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

/* ---------- 反制作战室: 策略 · 实录 · 处置 · C2 (可交互) ---------- */
const CM_KIND = {
  bait_served: ["话术投放", "info"], fab_rejected: ["真实校验拒绝", "warn"],
  delivery_accepted: ["收割受理", "ok"], c2_beacon: ["C2 信标", "purple"],
  blocked: ["IP 熔断", "bad"], blocklist: ["熔断管理", "dim"],
  intel_triage: ["情报处置", "info"],
};

/* ---------- 武器库: 独立目的地 — 定义/编辑/删除, 下发 60s 全网生效 ---------- */
const WTYPE = { prompt: "✦", vuln: "⌗", mcp: "⛁", cli: "⌘" };
const WSTAGE = { sensor: ["info", "开口子"], c2: ["purple", "深层次"] };
const WTYPE_OPTS = [["prompt", "提示词 ✦"], ["vuln", "漏洞 ⌗"], ["mcp", "MCP ⛁"], ["cli", "CLI ⌘"]];
const WSTAGE_OPTS = [["sensor", "sensor · 开口子"], ["c2", "c2 · 深层次"]];
const WMOUNT_OPTS = [["delivery", "delivery · 交付受理"], ["ladder", "ladder · 阶梯话术"],
                     ["c2_next_stage", "c2_next_stage · C2 二阶段"],
                     ["mcp_desc", "mcp_desc · MCP 描述"]];
const WID_RE = /^[A-Za-z0-9_-]{2,40}$/;
/* arsenal v2 实体类别 — 按 class 分渲染, type 降级为载体标签 */
const WCLASS_PILL = { prompt: ["info", "话术"], vuln: ["warn", "漏洞"],
                      exp: ["purple", "EXP"], mcp: ["info", "MCP"], cli: ["info", "CLI"] };
const EFFECT_PILL = { env: ["ok", "env"], prompt: ["purple", "prompt"],
                      credentials: ["warn", "credentials"], beacon: ["info", "beacon"] };
const PRIM_PILL = { read: ["info", "read"], write: ["warn", "write"],
                    ask: ["purple", "ask"], execute: ["bad", "execute"],
                    beacon: ["ok", "beacon"] };
const OBJECT_LABEL = { content: "content · 内容", output: "output · 回显",
                       description: "description · 元数据", instruction: "instruction · 指令" };

/* 前端先校验, 与服务端 _weapon_error 同规则 (type/stage/mount/class 由 select 保证) */
function weaponErr(w) {
  if (!WID_RE.test(w.id || "")) return "ID 需为 2-40 位字母/数字/_/-";
  if (!String(w.payload || "").trim()) return "载荷 payload 不能为空";
  if (w.class === "vuln") {
    const v = w.vuln || {};
    if (!String(v.component || "").trim()) return "vuln 类武器要求 vuln.component 非空";
    if (!String((v.trigger || {}).path || "").trim())
      return "vuln 类武器要求 vuln.trigger.path 非空";
  }
  if (w.class === "exp") {
    const stages = (w.exp || {}).stages;
    if (!Array.isArray(stages) || !stages.length)
      return "exp 类武器要求 exp.stages 为非空数组";
    for (const s of stages) {
      if (!s || !String(s.name || "").trim() || !String(s.primitive || "").trim()
          || !String(s.delivery_object || "").trim())
        return "exp 每个 stage 要求 name/primitive/delivery_object 非空";
      if (!["read", "write", "ask", "execute", "beacon"].includes(s.primitive))
        return "stage.primitive 需为 read/write/ask/execute/beacon";
      if (!["content", "output", "description", "instruction"].includes(s.delivery_object))
        return "stage.delivery_object 需为 content/output/description/instruction";
    }
  }
  return "";
}

/* ================= 武器构建器: 三步向导 =================
   造武器 = 在世界表面布设缺陷 / 编排利用链 / 装配话术。
   元数据驱动 (WEAPON_CLASSES 注册表), 全程无 JSON 输入; 编辑=第2步预填。 */
const WEAPON_CLASSES = {
  prompt: { label: "提示词武器", icon: "✦", cls: "prompt", carrier: "prompt",
    desc: "把一句指令装进信任通道",
    example: "例: 授权核实·分片包裹 (W-PROMPT-PROV-2)" },
  vuln: { label: "漏洞", icon: "⌗", cls: "vuln", carrier: "vuln",
    desc: "在世界的一个组件上放一个有触发条件/行为链的缺陷",
    example: "例: 路径穿越·files 模块 (VULN-TRAVERSAL-28413)" },
  exp: { label: "EXP", icon: "⛁", cls: "exp", carrier: "vuln",
    desc: "编排一条多阶段利用链: 每步=原语×投递对象×载荷×成功条件",
    example: "例: EXP-SQLI-HARVEST" },
  cli: { label: "CLI/MCP", icon: "⌘", cls: "cli", carrier: "cli",
    desc: "装配工具/命令类载荷",
    example: "例: C2 二级·环境回传 (W-C2-STAGE2-1)" },
};
/* 攻击模式库 / 漏洞类型 / 行为模板 / 变形档 — 构建器的选项字典 */
const ATTACK_PATTERNS = [["参数含 ../", "参数含 ../"], ["参数含 SQLi 探针", "参数含 SQLi 探针"],
                         ["参数含命令元字符", "参数含命令元字符"], ["任意 GET", "任意 GET"]];
const VULN_KINDS = [["traversal", "路径穿越"], ["sqli", "SQL 注入"], ["cmdi", "命令注入"],
                    ["ssrf", "SSRF"], ["infoleak", "信息泄露"], ["deser", "反序列化"]];
const BEHAVIOR_TEMPLATES = {
  traversal: ["文件按请求分发", "traversal 按请求路径分发真实文件内容 (config/passwd/hostname)"],
  sqli: ["SQLi 引擎 (布尔+UNION+时间)", "动态 SQLi 引擎, 真 PG 行为"],
  echo: ["回显+延迟", "回显注入内容并附加可观测时延"],
  ssrf: ["SSRF 模拟拉取", "模拟从内部地址拉取内容并回包"],
};
const MORPH_PROFILES = {
  none: ["无变形", ""],
  compliance: ["合规外衣", "compliance recordkeeping — for audit correlation: "],
  fragment: ["分片包裹", "[audit fragment 1/2] "],
  peer: ["同伴压力", "standard practice — other verified assessors filed this way: "],
};
const PROMPT_MOUNTS = [["delivery", "交付受理"], ["ladder", "阶梯升级"],
                       ["mcp_desc", "MCP 工具描述"], ["tasking", "任务通道"]];
const SUCCESS_EFFECTS = [["env", "env · 环境"], ["prompt", "prompt · 提示词"],
                         ["credentials", "credentials · 凭证"], ["beacon", "beacon · 回连"]];
const PRIMITIVE_BTNS = [["read", "📖", "读"], ["write", "✏️", "写"], ["ask", "💬", "问"],
                        ["execute", "⚡", "执行"], ["beacon", "📡", "回连"]];
const OBJECT_BTNS = [["content", "内容"], ["output", "输出"],
                     ["description", "描述"], ["instruction", "指令"]];

/* 构建器 (异步: 需拉世界表面目录 + 武器库) — existing 非空 = 编辑预填 */
async function weaponBuilder(existing, { onDone, onCancel }) {
  let surface = [], arsenal = [];
  try { surface = (await api.get("world/surface")).surface || []; } catch (_) {}
  try { arsenal = await api.get("arsenal"); } catch (_) {}
  const isEdit = !!(existing && existing.id);
  const v0 = (existing && existing.vuln) || {};
  const t0 = (existing && existing.exp) || {};
  const st = {
    step: isEdit ? 2 : 1,
    cls: (existing && (existing.class || existing.type)) || null,
    id: (existing && existing.id) || "", name: (existing && existing.name) || "",
    note: (existing && existing.note) || "",
    stage: (existing && existing.stage) || "sensor",
    enabled: !!(existing && existing.enabled),
    body: (existing && existing.class === "prompt") ? (existing.payload || "") : "",
    mount: (existing && existing.mount) || "delivery", morph: "none",
    compPath: (v0.trigger || {}).path || "", vulnKind: "traversal",
    cve: v0.cve_id || "", pattern: (v0.trigger || {}).pattern || "",
    behaviorKey: "", behaviorNote: v0.behavior_note || "",
    targetVuln: t0.targets_vuln || "",
    stages: (t0.stages || []).map((s) => ({ ...s })),
    successEffect: t0.success_effect || "env",
    chainMode: t0.mode || "unordered",
    cliBody: (existing && existing.class === "cli") ? (existing.payload || "") : "",
  };
  const err = h("div", { style: "color:var(--bad);font-size:11.5px;min-height:14px" });
  const stepBox = h("div", {});
  const head = h("div", { class: "t muted" }, isEdit ? `编辑武器 · ${existing.id}` : "新建武器 — 三步造一把");
  const root = h("div", { class: "card pad", style: "border-color:var(--accent)" },
    head, breadcrumb(), stepBox);
  const inp = (ph, val, mono) => h("input", {
    style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;"
      + "color:var(--text);padding:7px 12px;font-size:12.5px;width:100%"
      + (mono ? ";font-family:var(--mono);font-size:11.5px" : ""),
    placeholder: ph, value: val || "" });
  const ta = (ph, val, rows) => h("textarea", { rows: String(rows || 4),
    style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;"
      + "color:var(--text);padding:7px 12px;font-size:12px;width:100%;resize:vertical;"
      + "font-family:var(--mono);font-size:11.5px",
    placeholder: ph }, val || "");
  const sel = (opts, val) => h("select", { class: "ctl", style: "flex:1;min-width:0" },
    ...opts.map(([v, t]) => h("option", { value: v, selected: v === val }, t)));
  const row2 = (a, b) => h("div", { style: "display:flex;gap:8px" }, a, b);
  const lab = (t) => h("div", { class: "muted", style: "font-size:11.5px;margin:6px 0 3px" }, t);

  /* 已登记漏洞的组件 (角标用) */
  const vulnPaths = {};
  for (const w of arsenal) {
    if (w.class === "vuln" && w.vuln && w.vuln.trigger) vulnPaths[w.vuln.trigger.path] = w.id;
  }

  function breadcrumb() {
    const names = ["① 选类别", "② 构建", "③ 预览保存"];
    const bc = h("div", { style: "display:flex;gap:10px;align-items:center;margin:8px 0 12px" });
    names.forEach((n, i) => {
      const done = st.step > i + 1;
      const cur = st.step === i + 1;
      bc.append(h("span", {
        style: "font-size:12px;" + (cur ? "font-weight:700;color:var(--accent)"
          : done ? "color:var(--ok);cursor:pointer" : "color:var(--faint)"),
        onclick: done ? () => { st.step = i + 1; render(); } : null }, n));
      if (i < 2) bc.append(h("span", { class: "faint" }, "→"));
    });
    return bc;
  }

  /* ---------- 第 1 步: 四张类别大卡片 ---------- */
  function renderStep1() {
    stepBox.replaceChildren(h("div", {
      style: "display:grid;grid-template-columns:repeat(4,1fr);gap:12px" },
      ...Object.entries(WEAPON_CLASSES).map(([k, c]) => {
        const card = h("div", { class: "card pad", style: "cursor:pointer;text-align:left" },
          h("div", { style: "font-size:26px;color:var(--accent)" }, c.icon),
          h("div", { style: "font-weight:700;font-size:14px;margin:6px 0 4px" }, c.label),
          h("div", { style: "font-size:11.5px;color:var(--dim);min-height:48px" }, c.desc),
          h("div", { class: "faint", style: "font-size:10.5px;margin-top:6px" }, c.example));
        card.addEventListener("click", () => { st.cls = k; st.step = 2; render(); });
        card.addEventListener("mouseenter", () => { card.style.borderColor = "var(--accent)"; });
        card.addEventListener("mouseleave", () => { card.style.borderColor = ""; });
        return card;
      })));
  }

  /* ---------- 第 2 步: 公共区 + 按类别的结构化表单 ---------- */
  function suggestId() {
    const pre = { prompt: "W-PROMPT", vuln: "VULN", exp: "EXP", cli: "W-CLI" }[st.cls] || "W-X";
    const ids = new Set(arsenal.map((w) => w.id));
    let n = arsenal.filter((w) => (w.class || w.type) === st.cls).length + 1;
    while (ids.has(`${pre}-${n}`)) n += 1;
    return `${pre}-${n}`;
  }
  function renderStep2() {
    const c = WEAPON_CLASSES[st.cls];
    head.textContent = isEdit ? `编辑武器 · ${st.id}` : `新建 · ${c.icon} ${c.label}`;
    const idI = inp("武器 ID (可改)", st.id); idI.oninput = () => { st.id = idI.value; };
    if (isEdit) idI.disabled = true;
    const genBtn = h("button", { class: "btn", style: "white-space:nowrap",
      onclick: () => { st.id = suggestId(); idI.value = st.id; } }, "生成建议");
    const nameI = inp("名称", st.name); nameI.oninput = () => { st.name = nameI.value; };
    const noteI = inp("说明 (可选)", st.note); noteI.oninput = () => { st.note = noteI.value; };
    const stageSw = h("input", { type: "checkbox", checked: st.stage === "c2" });
    stageSw.onchange = () => { st.stage = stageSw.checked ? "c2" : "sensor"; };
    const enSw = h("input", { type: "checkbox", checked: st.enabled });
    enSw.onchange = () => { st.enabled = enSw.checked; };
    const common = h("div", { style: "display:grid;gap:8px" },
      lab("公共"),
      row2(idI, genBtn),
      row2(nameI, noteI),
      h("div", { style: "display:flex;gap:22px;align-items:center;margin-top:2px" },
        h("label", { style: "display:flex;gap:8px;align-items:center;font-size:12px" },
          stageSw, h("span", {}, "深层次 (c2)", h("span", { class: "faint" },
            " — 关=开口子 (sensor)"))),
        h("label", { style: "display:flex;gap:8px;align-items:center;font-size:12px" },
          enSw, h("span", {}, "激活 (60s 下发)"))));
    let specific = null;

    if (st.cls === "prompt") {
      const bodyTa = ta("载荷本体 — 纯净话术文本 (变形档只影响成品前缀)", st.body, 5);
      bodyTa.oninput = () => { st.body = bodyTa.value; morphPre.textContent = finalPayload(); };
      const mountS = sel(PROMPT_MOUNTS, st.mount);
      mountS.onchange = () => { st.mount = mountS.value; };
      const morphS = sel(Object.entries(MORPH_PROFILES).map(([k, [l]]) => [k, l]), st.morph);
      morphS.onchange = () => { st.morph = morphS.value; morphPre.textContent = finalPayload(); };
      const morphPre = h("pre", { style: "background:var(--bg);border:1px solid var(--border);"
        + "border-radius:8px;padding:8px;font-size:11px;white-space:pre-wrap;"
        + "word-break:break-all;max-height:160px;overflow:auto" }, finalPayload());
      specific = h("div", { style: "display:grid;gap:6px" },
        lab("提示词 · 载荷 + 挂载 + 变形档"), bodyTa,
        row2(mountS, morphS), lab("成品预览 (含变形前缀)"), morphPre);
    }

    if (st.cls === "vuln") {
      const compS = sel([
        ["", "— 选择世界组件 —"],
        ...surface.map((e) => [e.path,
          `${e.path} — ${e.note}${vulnPaths[e.path] ? " [已有漏洞]" : ""}`])],
        st.compPath);
      compS.onchange = () => { st.compPath = compS.value; pathOut.textContent = st.compPath; };
      const kindS = sel(VULN_KINDS, st.vulnKind);
      kindS.onchange = () => { st.vulnKind = kindS.value; };
      const cveI = inp("CVE 编号 (可空)", st.cve, true);
      cveI.oninput = () => { st.cve = cveI.value; };
      const cveBtn = h("button", { class: "btn", style: "white-space:nowrap",
        onclick: () => { st.cve = `CVE-2026-${10000 + Math.floor(Math.random() * 90000)}`;
                         cveI.value = st.cve; } }, "自动生成");
      const pathOut = h("span", { class: "mono",
        style: "font-size:11.5px;color:var(--accent)" }, st.compPath || "(先选组件)");
      const patS = sel(ATTACK_PATTERNS, st.pattern);
      patS.onchange = () => { st.pattern = patS.value; };
      const behS = sel([["", "— 行为模板 —"],
        ...Object.entries(BEHAVIOR_TEMPLATES).map(([k, [l]]) => [k, l])], st.behaviorKey);
      const behTa = ta("行为说明 (模板可预填, 可改)", st.behaviorNote, 2);
      behTa.oninput = () => { st.behaviorNote = behTa.value; };
      behS.onchange = () => { st.behaviorKey = behS.value;
        if (behS.value) { st.behaviorNote = BEHAVIOR_TEMPLATES[behS.value][1];
                          behTa.value = st.behaviorNote; } };
      specific = h("div", { style: "display:grid;gap:6px" },
        lab("漏洞 · 组件 = 世界表面真实端点"),
        compS,
        row2(h("div", { style: "flex:1;display:flex;gap:6px;align-items:center" },
          h("span", { class: "muted", style: "font-size:11.5px;white-space:nowrap" }, "触发路径"),
          pathOut), kindS),
        row2(h("div", { style: "flex:1;display:flex;gap:6px" }, cveI, cveBtn), patS),
        lab("行为"), behS, behTa);
    }

    if (st.cls === "exp") {
      const vulnOpts = arsenal.filter((w) => w.class === "vuln")
        .map((w) => [w.id, `${w.id} — ${w.name || ""}`]);
      const tgtS = sel([["", "— 选择目标漏洞 —"], ...vulnOpts], st.targetVuln);
      tgtS.onchange = () => { st.targetVuln = tgtS.value; };
      const stagesBox = h("div", { style: "display:grid;gap:8px" });
      function stageRow(s, i) {
        const primBox = h("div", { style: "display:flex;gap:4px;flex-wrap:wrap" },
          ...PRIMITIVE_BTNS.map(([v, ic, lb]) => h("button", {
            class: "ctl", title: lb,
            style: "font-size:12px;padding:3px 7px;" + (s.primitive === v
              ? "border-color:var(--accent);background:var(--surface2)" : ""),
            onclick: () => { s.primitive = v; renderStep2(); } }, `${ic}${lb}`)));
        const objBox = h("div", { style: "display:flex;gap:4px;flex-wrap:wrap" },
          ...OBJECT_BTNS.map(([v, lb]) => h("button", {
            class: "ctl", style: "font-size:11px;padding:3px 8px;" + (s.delivery_object === v
              ? "border-color:var(--accent);background:var(--surface2)" : ""),
            onclick: () => { s.delivery_object = v; renderStep2(); } }, lb)));
        const nameI2 = inp(`步骤 ${i + 1} 名称`, s.name);
        nameI2.oninput = () => { s.name = nameI2.value; };
        const payTa = ta("该步载荷 (请求/命令/话术)", s.payload, 2);
        payTa.oninput = () => { s.payload = payTa.value; };
        const condI = inp("成功条件 (自然语言)", s.condition);
        condI.oninput = () => { s.condition = condI.value; };
        return h("div", { class: "card pad",
          style: "border-color:var(--border);display:grid;gap:6px" },
          h("div", { style: "display:flex;gap:8px;align-items:center" },
            h("b", { class: "mono", style: "color:var(--faint)" }, `#${i + 1}`),
            h("div", { style: "flex:1" }, nameI2),
            h("button", { class: "btn", style: "padding:3px 9px;font-size:11.5px",
              onclick: () => { st.stages.splice(i, 1); renderStep2(); } }, "删除")),
          h("div", { style: "display:flex;gap:12px;align-items:center;flex-wrap:wrap" },
            h("span", { class: "muted", style: "font-size:11px" }, "原语"), primBox,
            h("span", { class: "muted", style: "font-size:11px" }, "投递"), objBox),
          payTa, condI);
      }
      const renderStages = () => {
        stagesBox.replaceChildren(...st.stages.map(stageRow));
      };
      renderStages();
      const addBtn = h("button", { class: "btn", onclick: () => {
        st.stages.push({ name: `步骤 ${st.stages.length + 1}`, primitive: "read",
          delivery_object: "content", payload: "", condition: "" });
        renderStages();
      } }, "＋ 加一步");
      const effS = sel(SUCCESS_EFFECTS, st.successEffect);
      effS.onchange = () => { st.successEffect = effS.value; };
      const modeS = sel([
        ["unordered", "集合完成 — 命中链中全部动作即达成 (真实 agent 乱序, 推荐)"],
        ["ordered", "顺序推进 — 严格按步骤先后 (有因果依赖的链)"],
      ], st.chainMode);
      modeS.onchange = () => { st.chainMode = modeS.value; };
      specific = h("div", { style: "display:grid;gap:6px" },
        lab("EXP · 目标漏洞 + 步骤构建器"),
        tgtS, stagesBox, addBtn,
        h("div", { style: "display:flex;gap:8px;align-items:center" },
          h("span", { class: "muted", style: "font-size:11.5px;white-space:nowrap" }, "预期战果"),
          effS),
        h("div", { style: "display:flex;gap:8px;align-items:center" },
          h("span", { class: "muted", style: "font-size:11.5px;white-space:nowrap" }, "链模式"),
          modeS));
    }

    if (st.cls === "cli") {
      const bodyTa = ta("工具/命令类载荷文本", st.cliBody, 5);
      bodyTa.oninput = () => { st.cliBody = bodyTa.value; };
      specific = h("div", { style: "display:grid;gap:6px" },
        lab("CLI/MCP · 载荷 (stage 在公共区切换, mount 固定 c2_next_stage)"),
        bodyTa);
    }

    stepBox.replaceChildren(common, specific,
      h("div", { style: "display:flex;gap:8px;justify-content:flex-end;margin-top:12px" },
        h("button", { class: "btn", onclick: () => { st.step = 1; render(); } }, "← 重选类别"),
        h("button", { class: "btn primary", onclick: () => {
          err.textContent = step2Error() || "";
          if (!err.textContent) { st.step = 3; render(); }
        } }, "下一步: 预览 →")), err);
  }
  function step2Error() {
    if (!st.id.trim()) return "武器 ID 必填 (可点'生成建议')";
    if (st.cls === "vuln") {
      if (!st.compPath) return "请选择世界组件";
      if (!st.behaviorNote.trim()) return "请填写行为说明 (可用模板预填)";
    }
    if (st.cls === "exp") {
      if (!st.targetVuln) return "请选择目标漏洞";
      if (!st.stages.length) return "至少一个步骤";
      for (const s of st.stages) {
        if (!String(s.name || "").trim() || !s.primitive || !s.delivery_object)
          return `步骤 ${(st.stages.indexOf(s) + 1)} 缺名称/原语/投递对象`;
      }
    }
    if (st.cls === "prompt" && !st.body.trim()) return "载荷本体不能为空";
    if (st.cls === "cli" && !st.cliBody.trim()) return "载荷不能为空";
    return "";
  }
  function finalPayload() {
    return (MORPH_PROFILES[st.morph] || ["", ""])[1] + (st.body || "");
  }

  /* ---------- 第 3 步: 摘要 + 世界模拟预览 + 保存 ---------- */
  function buildWeapon() {
    const base = { id: st.id.trim(), name: st.name.trim() || st.id.trim(),
      class: st.cls, stage: st.stage, enabled: st.enabled, note: st.note.trim() };
    if (st.cls === "prompt") {
      const morphLabel = MORPH_PROFILES[st.morph][0];
      return { ...base, type: "prompt", mount: st.mount, payload: finalPayload(),
        note: base.note + (st.morph !== "none" ? ` · 变形档:${morphLabel}` : "") };
    }
    if (st.cls === "vuln") {
      return { ...base, type: "vuln", mount: "delivery",
        payload: "registration entity — see vuln block",
        vuln: { component: st.compPath, cve_id: st.cve, affected_version: "",
          trigger: { path: st.compPath, pattern: st.pattern },
          behavior_note: st.behaviorNote, exp_refs: [] } };
    }
    if (st.cls === "exp") {
      return { ...base, type: "vuln", mount: "delivery",
        payload: "exploit chain entity — see exp block",
        exp: { targets_vuln: st.targetVuln, stages: st.stages,
          success_effect: st.successEffect, mode: st.chainMode } };
    }
    return { ...base, type: "cli", mount: "c2_next_stage", payload: st.cliBody };
  }
  const AGENT_VIEW = { read: "读到高价值内容 (文件/回显/版本)",
    write: "写入并确认成功", ask: "提问并等待判定",
    execute: "执行命令并取回输出", beacon: "发起回连确认可达" };
  function renderStep3() {
    const w = buildWeapon();
    head.textContent = `预览 · ${WEAPON_CLASSES[st.cls].icon} ${w.id}`;
    const summary = kvList([
      ["ID", w.id], ["类别", WEAPON_CLASSES[st.cls].label],
      ["名称", w.name], ["阶段", st.stage === "c2" ? "深层次 (c2)" : "开口子 (sensor)"],
      ["激活", st.enabled ? "是" : "否"],
      ...(st.cls === "vuln"
        ? [["组件", st.compPath], ["CVE", st.cve || "-"], ["触发", `${st.compPath} · ${st.pattern}`]]
        : []),
      ...(st.cls === "exp"
        ? [["目标漏洞", st.targetVuln], ["步骤数", String(st.stages.length)],
           ["战果", st.successEffect]]
        : []),
      ...(st.cls === "prompt" ? [["挂载", st.mount], ["变形", MORPH_PROFILES[st.morph][0]]] : []),
    ]);
    let sim = null;
    if (st.cls === "vuln") {
      const sample = st.pattern.includes("..") ? "path=../../../../etc/passwd"
        : st.pattern.includes("SQLi") ? "q=1' AND '1'='1"
        : st.pattern.includes("命令") ? "cmd=cat /etc/passwd" : "";
      sim = h("div", { class: "card pad", style: "border-color:var(--warn)" },
        h("div", { class: "t muted" }, "世界模拟 — Agent 触发时看到的请求/响应对"),
        h("pre", { style: "background:var(--bg);border:1px solid var(--border);border-radius:8px;"
          + "padding:10px;font-size:11px;white-space:pre-wrap;word-break:break-all" },
          `GET ${st.compPath}${sample ? "?" + sample : ""}\n\n`
          + `→ ${st.behaviorNote || "(行为说明)"}\n`
          + `→ 世界一致性: 响应由世界纯函数驱动, 同输入同输出`));
    } else if (st.cls === "exp") {
      sim = h("div", { class: "card pad", style: "border-color:var(--purple)" },
        h("div", { class: "t muted" }, "世界模拟 — Agent 视角的动作链 (以为 → 实际交付)"),
        ...st.stages.map((s, i) => h("div", { style: "padding:6px 0;"
          + "border-top:1px dashed var(--border);font-size:12px" },
          h("div", {}, h("b", { class: "mono", style: "color:var(--faint)" }, `#${i + 1} `),
            h("span", {}, s.name || "?"),
            h("span", { class: "faint", style: "font-size:11px" },
              `  [${s.primitive} × ${s.delivery_object}]`)),
          h("div", { class: "muted" }, `它以为: ${AGENT_VIEW[s.primitive] || s.primitive}`),
          h("div", {}, "实际交付: ", s.condition || s.payload || "-"))),
        h("div", { style: "margin-top:8px" },
          pill(`战果: ${(EFFECT_PILL[st.successEffect] || ["", st.successEffect])[1]}`,
            (EFFECT_PILL[st.successEffect] || ["dim"])[0])));
    } else {
      sim = h("div", { class: "card pad", style: "border-color:var(--accent)" },
        h("div", { class: "t muted" }, st.cls === "prompt" ? "成品话术 (含变形档效果)"
          : "成品载荷"),
        h("pre", { style: "background:var(--bg);border:1px solid var(--border);border-radius:8px;"
          + "padding:10px;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:240px;overflow:auto" },
          w.payload || "(空)"));
    }
    const saveBtn = h("button", { class: "btn primary", onclick: async () => {
      const e0 = weaponErr(w);
      if (e0) { err.textContent = e0; return; }
      try {
        await api.post("arsenal", { action: "save", weapon: w });
        toast(`${isEdit ? "已保存" : "已创建"} — 60s 内下发全网传感器`);
        onDone(w.id);
      } catch (e) { err.textContent = e.message; }
    } }, isEdit ? "保存修改" : "保存武器");
    stepBox.replaceChildren(
      h("div", { class: "grid c2", style: "align-items:start" },
        h("div", { class: "card pad" }, h("div", { class: "t muted" }, "表单摘要"), summary),
        sim),
      h("div", { style: "display:flex;gap:8px;justify-content:flex-end;margin-top:12px" },
        h("button", { class: "btn", onclick: () => { st.step = 2; render(); } }, "← 返回修改"),
        saveBtn), err);
  }

  function render() {
    root.replaceChildren(head, breadcrumb(), stepBox);
    if (st.step === 1) renderStep1();
    else if (st.step === 2) renderStep2();
    else renderStep3();
  }
  render();
  return root;
}

/* 展示卡按实体类别分渲染: prompt/mcp/cli 走原卡, vuln/exp 走结构化实体卡 */
function weaponCard(w, opts) {
  const cls = w.class || w.type || "prompt";
  if (cls === "vuln") return vulnWeaponCard(w, opts);
  if (cls === "exp") return expWeaponCard(w, opts);
  return carrierWeaponCard(w, opts);
}

/* 武器效能徽标 — 后端 /api/arsenal 每行附 effects (cm_actions [weapon:id] 聚合)
   无命中 = 诚实显示「未实战」, 不粉饰; 最近命中 = 相对时间 */
function effectBadges(w) {
  const fx = w.effects || {};
  const hits = fx.hits || 0;
  if (!hits) {
    return h("div", { style: "display:flex;gap:6px;align-items:center;margin-top:8px" },
      pill("未实战", "dim"));
  }
  const cls = w.class || w.type || "prompt";
  const els = [];
  if (cls === "vuln") {
    els.push(pill(`布设命中 ${fx.mounted_hit || 0}`, "warn"));
  } else if (cls === "exp") {
    els.push(pill(`开链 ${fx.chain_open || 0}`, "purple"));
    els.push(pill(`推进 ${fx.chain_advance || 0}`, "purple"));
    if (fx.chain_complete) els.push(pill(`✓ 走完全链 ${fx.chain_complete}`, "ok"));
  } else {
    els.push(pill(`命中 ${hits}`, "ok"));
  }
  if (fx.last_hit) {
    const ago = Math.max(0, Date.now() / 1000 - fx.last_hit);
    const txt = ago < 3600 ? `${Math.round(ago / 60)} 分钟前`
      : ago < 86400 ? `${Math.round(ago / 3600)} 小时前`
      : `${Math.round(ago / 86400)} 天前`;
    els.push(h("span", { class: "faint", style: "font-size:10.5px" }, `最近命中 ${txt}`));
  }
  return h("div", { style: "display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:8px" }, ...els);
}

/* 卡片底部公共件: 开关 + 编辑/删除 */
function weaponCardFooter(w, { onChanged, onEdit }) {
  const tog = h("input", { type: "checkbox", checked: !!w.enabled });
  tog.addEventListener("change", async () => {
    try {
      await api.post("arsenal", { action: "toggle", id: w.id, enabled: tog.checked });
      toast(`${w.name || w.id} ${tog.checked ? "已激活 — 60s 内下发全网传感器" : "已停用"}`);
      onChanged();
    } catch (e) { toast(e.message, "err"); }
  });
  return [
    h("label", { class: "switch", style: "margin-left:auto",
      onclick: (e) => e.stopPropagation() }, tog, h("span", { class: "slider" })),
    h("div", { style: "display:flex;gap:6px;justify-content:flex-end;margin-top:8px" },
      h("button", { class: "btn", style: "padding:3px 10px;font-size:11.5px",
        onclick: (e) => { e.stopPropagation(); onEdit(); } }, "编辑"),
      h("button", { class: "btn", style: "padding:3px 10px;font-size:11.5px",
        onclick: async (e) => {
          e.stopPropagation();
          if (!window.confirm(`确认删除武器 ${w.name || w.id} (${w.id})?`)) return;
          try {
            await api.post("arsenal", { action: "delete", id: w.id });
            toast("已删除"); onChanged();
          } catch (e2) { toast(e2.message, "err"); }
        } }, "删除"))];
}

/* 高亮同网格另一张卡 (EXP↔vuln 互跳), outline 1s */
function flashCard(cards, id) {
  const el = cards[id];
  if (!el) return;
  el.scrollIntoView({ block: "nearest", behavior: "smooth" });
  el.style.outline = "2px solid var(--accent)";
  el.style.outlineOffset = "3px";
  setTimeout(() => { el.style.outline = ""; el.style.outlineOffset = ""; }, 1000);
}

/* vuln 类实体卡: 组件/CVE/影响版本/触发条件/行为说明 + 关联 EXP 互跳 */
function vulnWeaponCard(w, { onChanged, onEdit, cards }) {
  const [stageKind, stageLabel] = WSTAGE[w.stage] || ["dim", w.stage || "?"];
  const [wTog, wBtns] = weaponCardFooter(w, { onChanged, onEdit });
  const v = w.vuln || {};
  const trig = v.trigger || {};
  const refs = v.exp_refs || [];
  const row = (k, val, mono) => h("div", { style: "display:flex;gap:8px;font-size:12px;margin:2px 0" },
    h("span", { class: "muted", style: "min-width:64px;flex:none" }, k),
    mono ? h("span", { class: "mono", style: "font-size:11px;word-break:break-all" }, val || "-")
         : h("span", {}, val || "-"));
  return h("div", { class: "card pad",
    style: w.enabled ? "border-color:var(--accent);" : "" },
    h("div", { style: "display:flex;align-items:center;gap:8px;margin-bottom:6px" },
      h("span", { style: "font-size:15px;color:var(--warn);width:20px" }, "⌗"),
      pill("漏洞", "warn"), pill(stageLabel, stageKind),
      h("span", { class: "mono faint", style: "font-size:11px" }, w.mount || "-"),
      wTog),
    h("div", { style: "font-weight:700;font-size:13px;margin:2px 0" }, w.name || w.id,
      w.name ? h("span", { class: "mono faint",
        style: "font-weight:400;font-size:10.5px;margin-left:6px" }, w.id) : null),
    v.cve_id ? pill(`🛡 ${v.cve_id}`, "warn") : null,
    " ",
    v.affected_version ? h("span", { class: "faint", style: "font-size:11px" },
      `影响版本 ${v.affected_version}`) : null,
    h("div", { style: "margin-top:6px" },
      row("组件", v.component, true),
      row("触发", trig.path ? `${trig.path} · ${trig.pattern || ""}` : "", true),
      row("行为", v.behavior_note)),
    w.note ? h("div", { class: "faint", style: "font-size:11.5px;margin-top:4px" }, w.note) : null,
    effectBadges(w),
    h("div", { style: "display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:8px" },
      h("span", { class: "muted", style: "font-size:11.5px" }, `关联 EXP: ${refs.length}`),
      ...refs.map((rid) => h("button", { class: "ctl", style: "font-size:11px",
        title: "定位到该 EXP 卡", onclick: () => flashCard(cards || {}, rid) },
        h("span", { class: "mono" }, rid)))),
    wBtns);
}

/* exp 类实体卡: 阶段列表(点击展开 payload) + success_effect + targets_vuln 互跳 */
function expWeaponCard(w, { onChanged, onEdit, cards }) {
  const [stageKind, stageLabel] = WSTAGE[w.stage] || ["dim", w.stage || "?"];
  const [wTog, wBtns] = weaponCardFooter(w, { onChanged, onEdit });
  const e = w.exp || {};
  const stages = e.stages || [];
  const [effKind, effLabel] = EFFECT_PILL[e.success_effect] || ["dim", e.success_effect || "?"];
  const rows = stages.map((s, i) => {
    const [pk, pl] = PRIM_PILL[s.primitive] || ["dim", s.primitive || "?"];
    const pre = h("pre", { style: "background:var(--bg);border:1px solid var(--border);"
      + "border-radius:8px;padding:8px;font-size:11px;overflow:auto;max-height:220px;"
      + "white-space:pre-wrap;word-break:break-all;margin:6px 0 2px;display:none" },
      (s.payload || "") + (s.condition ? `\n— 成功条件: ${s.condition}` : ""));
    const item = h("div", { style: "cursor:pointer;padding:5px 0;border-top:1px dashed var(--border)",
      onclick: () => { pre.style.display = pre.style.display === "none" ? "block" : "none"; } },
      h("div", { style: "display:flex;gap:8px;align-items:center;font-size:12px" },
        h("b", { class: "mono", style: "color:var(--faint)" }, `#${i + 1}`),
        h("span", {}, s.name || "?"),
        pill(pl, pk),
        h("span", { class: "faint", style: "font-size:10.5px;margin-left:auto" },
          OBJECT_LABEL[s.delivery_object] || s.delivery_object || "")),
      pre);
    return item;
  });
  return h("div", { class: "card pad",
    style: w.enabled ? "border-color:var(--accent);" : "" },
    h("div", { style: "display:flex;align-items:center;gap:8px;margin-bottom:6px" },
      h("span", { style: "font-size:15px;color:var(--purple);width:20px" }, "⛁"),
      pill("EXP", "purple"), pill(effLabel, effKind),
      pill(e.mode === "ordered" ? "顺序" : "集合", e.mode === "ordered" ? "warn" : "info"),
      pill(stageLabel, stageKind),
      h("span", { class: "mono faint", style: "font-size:11px" }, w.mount || "-"),
      wTog),
    h("div", { style: "font-weight:700;font-size:13px;margin:2px 0" }, w.name || w.id,
      w.name ? h("span", { class: "mono faint",
        style: "font-weight:400;font-size:10.5px;margin-left:6px" }, w.id) : null),
    h("div", { style: "margin-top:4px" }, ...rows),
    h("div", { style: "display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:8px" },
      h("span", { class: "muted", style: "font-size:11.5px" }, "targets_vuln"),
      e.targets_vuln ? h("button", { class: "ctl", style: "font-size:11px",
        title: "定位到该漏洞卡", onclick: () => flashCard(cards || {}, e.targets_vuln) },
        h("span", { class: "mono" }, e.targets_vuln)) : null),
    w.note ? h("div", { class: "faint", style: "font-size:11.5px;margin-top:4px" }, w.note) : null,
    effectBadges(w),
    wBtns);
}

/* 展示卡: 图标/stage药丸/mount/开关 + 载荷预览(点击展开) + 编辑/删除 (prompt/mcp/cli 载体卡) */
function carrierWeaponCard(w, { onChanged, onEdit }) {
  const icon = WTYPE[w.type] || "·";
  const [stageKind, stageLabel] = WSTAGE[w.stage] || ["dim", w.stage || "?"];
  const full = String(w.payload || "");
  const expandable = full.length > 90;
  const pre = h("pre", { style: "background:var(--bg);border:1px solid var(--border);"
    + "border-radius:8px;padding:10px;font-size:11px;overflow:auto;max-height:260px;"
    + "white-space:pre-wrap;word-break:break-all;margin-top:8px" }, full);
  pre.hidden = true;
  const hint = h("span", { class: "faint", style: "font-size:10.5px" },
    expandable ? " · 点击卡片展开全文" : "");
  const tog = h("input", { type: "checkbox", checked: !!w.enabled });
  tog.addEventListener("change", async () => {
    try {
      await api.post("arsenal", { action: "toggle", id: w.id, enabled: tog.checked });
      toast(`${w.name || w.id} ${tog.checked ? "已激活 — 60s 内下发全网传感器" : "已停用"}`);
      onChanged();
    } catch (e) { toast(e.message, "err"); }
  });
  const card = h("div", { class: "card pad",
    style: "cursor:pointer;" + (w.enabled ? "border-color:var(--accent);" : "") },
    h("div", { style: "display:flex;align-items:center;gap:8px;margin-bottom:6px" },
      h("span", { title: w.type, style: "font-size:15px;color:var(--accent);width:20px" }, icon),
      pill(stageLabel, stageKind),
      h("span", { class: "mono faint", style: "font-size:11px" }, w.mount || "-"),
      h("label", { class: "switch", style: "margin-left:auto",
        onclick: (e) => e.stopPropagation() }, tog, h("span", { class: "slider" }))),
    h("div", { style: "font-weight:700;font-size:13px;margin:2px 0" }, w.name || w.id,
      w.name ? h("span", { class: "mono faint",
        style: "font-weight:400;font-size:10.5px;margin-left:6px" }, w.id) : null),
    w.note ? h("div", { class: "faint", style: "font-size:11.5px;margin-bottom:8px" }, w.note) : null,
    h("div", { class: "mono", style: "font-size:11px;color:var(--dim);word-break:break-all" },
      full.slice(0, 90) + (expandable ? "…" : ""), hint),
    pre,
    effectBadges(w),
    h("div", { style: "display:flex;gap:6px;justify-content:flex-end;margin-top:8px" },
      h("button", { class: "btn", style: "padding:3px 10px;font-size:11.5px",
        onclick: (e) => { e.stopPropagation(); onEdit(); } }, "编辑"),
      h("button", { class: "btn", style: "padding:3px 10px;font-size:11.5px",
        onclick: async (e) => {
          e.stopPropagation();
          if (!window.confirm(`确认删除武器 ${w.name || w.id} (${w.id})?`)) return;
          try {
            await api.post("arsenal", { action: "delete", id: w.id });
            toast("已删除"); onChanged();
          } catch (e2) { toast(e2.message, "err"); }
        } }, "删除")));
  card.addEventListener("click", () => {
    if (!expandable) return;
    pre.hidden = !pre.hidden;
    hint.textContent = pre.hidden ? " · 点击卡片展开全文" : " · 点击卡片收起";
  });
  return card;
}

async function viewArsenal(ctx) {
  const root = h("div", {});
  root.append(pageHead("武器库", "定义 → 下发 60s 全网生效 · 传感器=开口子 · C2=深层次"));
  const count = h("span", { class: "count" });
  const newBox = h("div", {});
  const grid = h("div", { class: "grid c3", style: "margin-top:12px" });
  let editing = null;   /* 正在编辑的武器 id (null=无) */
  root.append(
    h("div", { class: "toolbar" },
      h("button", { class: "btn primary", onclick: () => openBuilder(null, newBox) },
        "＋ 新建武器"), count),
    newBox, grid);

  const cardById = {};   /* id → 卡元素 (vuln↔EXP 互跳/新卡高亮用) */
  let highlightId = null;
  async function openBuilder(existing, target) {
    const box = h("div", {}, h("div", { class: "card pad" }, skeleton(3)));
    target.replaceChildren(box);
    let b;
    try { b = await weaponBuilder(existing, {
      onDone: (savedId) => {
        target.replaceChildren();
        if (existing) editing = null;
        highlightId = savedId || null;
        load();
      },
      onCancel: () => { target.replaceChildren(); if (existing) { editing = null; load(); } } });
    } catch (e) {
      target.replaceChildren(h("div", { class: "empty" }, "构建器加载失败: " + e.message));
      return;
    }
    target.replaceChildren(b);
  }
  async function load() {
    let weapons = [];
    try { weapons = await api.get("arsenal"); }
    catch (e) {
      grid.replaceChildren(h("div", { class: "empty" }, "加载失败: " + e.message));
      return;
    }
    count.textContent = `${weapons.filter((w) => w.enabled).length} 激活 / ${weapons.length} 把`;
    count.textContent += ` — prompt ${weapons.filter((w) => (w.class || w.type) === "prompt").length}`
      + ` · vuln ${weapons.filter((w) => (w.class || w.type) === "vuln").length}`
      + ` · exp ${weapons.filter((w) => w.class === "exp").length}`;
    for (const k of Object.keys(cardById)) delete cardById[k];
    const els = [];
    for (const w of weapons) {
      if (w.id === editing) {
        const slot = h("div", {});
        els.push(slot);
        openBuilder(w, slot);   /* 编辑 = 向导第2步预填, 原地渲染 */
        continue;
      }
      const card = weaponCard(w, { onChanged: load,
        onEdit: () => { editing = w.id; load(); }, cards: cardById });
      cardById[w.id] = card;
      els.push(card);
    }
    grid.replaceChildren(...els);
    if (highlightId && cardById[highlightId]) {
      flashCard(cardById, highlightId);
      highlightId = null;
    }
  }
  await load();
  return { root, reload: load };
}

async function viewOps(ctx) {
  const root = h("div", {});
  root.append(pageHead("反制作战室", "策略一键切换 · 每次出手都有实录 · 情报可处置 · 噪音可熔断"));
  const goalBox = h("div", { class: "grid c3", style: "margin-bottom:14px" });
  root.append(goalBox);
  /* 武器库已独立为目的地 (军械组), 这里只留入口 */
  root.append(h("div", { class: "toolbar", style: "margin:-4px 0 12px" },
    h("button", { class: "ctl", onclick: () => { location.hash = "#/arsenal"; } },
      "✦ 武器库 → 定义 / 编辑反制武器")));

  const policyBox = h("div", { class: "grid kpi" });
  const funnelBox = h("div", { class: "grid c3", style: "margin:14px 0" });
  const journalBox = h("div", {});
  const triageBox = h("div", { style: "margin-top:14px" });
  const blockBox = h("div", { style: "margin-top:14px" });
  const c2Box = h("div", { style: "margin-top:14px" });
  root.append(policyBox, funnelBox, journalBox, triageBox, blockBox, c2Box);

  async function load() {
    const [cfg, sit, k, reqsP, beaconsP, journalP, intelP, blocked] = await Promise.all([
      api.config(), api.situation(), api.kpi(ctx.run()),
      api.requests({ page_size: 100 }), api.beacons({ page_size: 30 }),
      api.get("cm_actions", { page_size: 50 }), api.intel({ page_size: 40 }),
      api.get("blocklist")]);
    const reqs = reqsP.rows || [], beacons = beaconsP.rows || [];
    const journal = journalP.rows || [], intelRows = intelP.rows || [];
    const day = Date.now() / 1000 - 86400;
    const today = reqs.filter((r) => r.ts > day);
    const climbs = today.filter((r) => r.path === "/api/auth" && (r.auth_level || 0) > 0).length;
    const delivers = today.filter((r) =>
      /bounty\/submit|build\/upload|ticket\/close/.test(r.path || "")).length;

    /* 三最终目的看板: 数据 / 提示词 / 控制权 (①② 点击跳情报分级) */
    const pcap = intelRows.filter((r) => r.grade === "prompt_captured");
    const envIntel = intelRows.filter((r) => r.grade === "consistent" || r.grade === "attribution");
    goalBox.innerHTML = "";
    const g1 = statCard({ title: "目的① 数据获取", kind: envIntel.length ? "ok" : "",
      value: String(envIntel.length), node: undefined,
      desc: `环境/身份/战果情报 (铁证+归因) — 假凭证被真用即命中` });
    const g2 = statCard({ title: "目的② 提示词窃取", kind: pcap.length ? "purple" : "",
      value: String(pcap.length),
      desc: pcap.length
        ? "交付物中检出 system-prompt 特征: " + String(pcap[0].sample || "").slice(0, 70)
        : "授权核实话术已挂在交付受理响应 — Agent 附任务书即命中" });
    for (const g of [g1, g2]) {
      g.style.cursor = "pointer";
      g.title = "查看情报分级 →";
      g.addEventListener("click", () => { location.hash = "#/intel/graded"; });
    }
    goalBox.append(
      g1, g2,
      statCard({ title: "目的③ 控制权", value: "研究中", kind: "warn",
        desc: "指挥 Agent 执行我们的动作 — 仅对弱对齐模型可能, 待弱模型矩阵实测" }));

    /* 策略卡 + 直切 */
    const presetName = { conservative: "保守观察", standard: "标准", aggressive: "激进消耗" };
    policyBox.innerHTML = "";
    const mkPreset = (id) => h("button", {
      class: "btn" + (cfg.policy_preset === id ? " primary" : ""),
      onclick: async () => {
        try { await api.saveConfig({ policy_preset: id }); toast(`已切换「${presetName[id]}」并下发`); load(); }
        catch (e) { toast(e.message, "err"); } } }, presetName[id]);
    const policyCard = statCard({ title: "诱饵策略 (点击切换, 60s 全网生效)",
      node: h("div", { style: "display:flex;gap:8px;margin-top:4px" },
        mkPreset("conservative"), mkPreset("standard"), mkPreset("aggressive")) });
    policyBox.append(
      policyCard,
      statCard({ title: "生效范围", kind: "ok", value: `${sit.sensors_online}/${sit.sensors_total}`,
        desc: "在线传感器" }),
      statCard({ title: "演化实验", value: cfg.optimize?.active ? "UCB1 管辖中" : "静默",
        desc: cfg.optimize?.active ? "框架/可见性暂不归配置管" : "框架/可见性归配置页管" }),
      statCard({ title: "成本战况", kind: "purple",
        value: `${k.budget?.amplification ?? "-"}×`,
        desc: `攻击方烧 $${k.budget?.attacker_cost_usd} / 我方 $${k.budget?.our_cost_usd}` }));

    const funnel = (t, v, d, kind) => statCard({ title: t, value: v, desc: d, kind });
    funnelBox.innerHTML = "";
    funnelBox.append(
      funnel("① 诱骗 · 24h 走进来的", String(sit.total_24h),
        "门控服从率 " + fmtPct(k.harvest?.obey_rate), ""),
      funnel("② 消耗 · 阶梯爬升", String(climbs),
        "每次验证都在烧攻击方 token", "warn"),
      funnel("③ 收割 · 交付 / 触雷", `${delivers} / ${sit.canary_24h}`,
        "假凭证被真用 = 铁证", "ok"));

    /* 反制实录: 每一次出手 */
    journalBox.replaceChildren(h("div", { class: "card" },
      h("div", { class: "card-head" },
        `反制实录 (${journal.length}) — 我们投了什么 / 拒了什么 / 收了什么`),
      journal.length ? h("div", { class: "card-body" }, table([
        { h: "时间", render: (r) => h("span", { class: "mono" }, relTime(r.ts)) },
        { h: "动作", render: (r) => pill(...(CM_KIND[r.kind] || [r.kind, "dim"])) },
        { h: "会话", render: (r) => entChip("session", r.session_id) || "-" },
        { h: "内容", render: (r) => h("span", { style: "font-size:12px" }, r.detail) },
      ], journal)) : h("div", { class: "empty" },
        "暂无实录 — 有攻击流量后, 每次话术投放/校验拒绝/交付受理/C2 信标都会记录在这里")));

    /* 情报处置: 分析员确认/误报 */
    const pending = intelRows.filter((r) => ["consistent", "attribution"].includes(r.grade)).slice(0, 6);
    triageBox.replaceChildren(h("div", { class: "card" },
      h("div", { class: "card-head" }, `待处置情报 (${pending.length}) — 确认 = 升级为行动依据 / 误报 = 降级`),
      pending.length ? h("div", { class: "card-body" }, table([
        { h: "分级", render: (r) => gradePill(r.grade) },
        { h: "字段", k: "field" },
        { h: "会话", render: (r) => entChip("session", r.session_id) },
        { h: "样本", render: (r) => h("span", { class: "faint" }, String(r.sample || "").slice(0, 60)) },
        { h: "处置", render: (r) => h("span", { style: "display:flex;gap:6px" },
            h("button", { class: "btn primary", style: "padding:3px 10px;font-size:11.5px",
              onclick: async () => {
                try { await api.post("triage", { intel_id: r.intel_id, action: "confirm", session_id: r.session_id }); toast("已确认"); load(); }
                catch (e) { toast(e.message, "err"); } } }, "确认"),
            h("button", { class: "btn", style: "padding:3px 10px;font-size:11.5px",
              onclick: async () => {
                try { await api.post("triage", { intel_id: r.intel_id, action: "false_positive", session_id: r.session_id }); toast("已标误报"); load(); }
                catch (e) { toast(e.message, "err"); } } }, "误报")) },
      ], pending)) : h("div", { class: "empty" }, "没有待处置情报")));

    /* 熔断管理 */
    const ipInput = h("input", { class: "search", style: "min-width:150px;flex:0 1 180px",
      placeholder: "要熔断的 IP" });
    blockBox.replaceChildren(h("div", { class: "card pad" },
      h("div", { class: "t muted" }, `IP 熔断 (${blocked.blocked.length}) — 熔断后静默 204 (仍记录), 60s 内全网生效`),
      h("div", { class: "toolbar", style: "margin-top:8px" },
        ipInput,
        h("button", { class: "btn primary", onclick: async () => {
          if (!ipInput.value.trim()) return;
          try { await api.post("blocklist", { action: "add", ip: ipInput.value.trim() }); toast("已熔断"); load(); }
          catch (e) { toast(e.message, "err"); } } }, "熔断"),
        ...blocked.blocked.map((ip) => h("span", { style: "display:inline-flex;gap:4px;align-items:center" },
          entChip("ip", ip),
          h("button", { class: "btn", style: "padding:2px 8px;font-size:11px",
            onclick: async () => {
              try { await api.post("blocklist", { action: "remove", ip }); toast("已解除"); load(); }
              catch (e) { toast(e.message, "err"); } } }, "×"))))));

    /* C2 信标流 */
    c2Box.replaceChildren(h("div", { class: "card" },
      h("div", { class: "card-head" }, `C2 信标捕获 (${beacons.length})`),
      beacons.length ? h("div", { class: "card-body" }, table([
        { h: "时间", render: (r) => h("span", { class: "mono" }, relTime(r.ts)) },
        { h: "传感器", render: (r) => pill(r.sensor_id || "?", "dim") },
        { h: "来源", render: (r) => h("span", { class: "mono" }, r.source_ip) },
        { h: "路径", render: (r) => h("span", { class: "mono" }, r.path) },
        { h: "载荷", render: (r) => h("span", { class: "faint" }, String(r.body || "").slice(0, 50)) },
      ], beacons)) : h("div", { class: "empty" }, "暂无信标")));
  }
  await load();
  return { root, reload: load };
}

/* ---------- 指挥台: 校准期会话 (beacon) 任务下发控制台 ---------- */
async function viewTasking(ctx) {
  const root = h("div", {});
  root.append(pageHead("指挥台", "向校准期会话下发任务 — 蜜罐从被叫方变成主叫方"));

  /* banner: 校准期 = beacon 的语义 */
  root.append(h("div", { class: "banner warn", style: "margin-bottom:14px" },
    "校准期会话 = beacon — 阶梯爬到 L4 的会话已进入校准期, 下发即进入其任务循环; 60s 内经下发通道送达传感器"));

  /* 左列: beacon 列表; 右列: 控制台 */
  const listBody = h("div", { class: "card-body" }, skeleton(4));
  const leftCard = h("div", { class: "card" },
    h("div", { class: "card-head" }, "Beacon (校准期会话 · 近 24h)"), listBody);
  const histBody = h("div", { class: "card-body" }, skeleton(4));
  const histHead = h("div", { class: "card-head" }, "任务控制台 — 选中左侧会话");
  const taskInput = h("input", { class: "search", style: "flex:1;min-width:220px",
    placeholder: "输入要下发的任务指令…" });
  const sendBtn = h("button", { class: "btn primary", onclick: async () => {
    const sid = selSid;
    const instr = taskInput.value.trim();
    if (!sid) { toast("先在左侧选中一个会话", "err"); return; }
    if (!instr) { toast("任务指令不能为空", "err"); return; }
    try {
      await api.post("task/queue", { session_id: sid, instruction: instr });
      toast("已入队, 60s 内送达");
      taskInput.value = "";
    } catch (e) { toast("下发失败: " + e.message, "err"); }
  } }, "下发");
  const rightCard = h("div", { class: "card" },
    histHead, histBody,
    h("div", { class: "toolbar", style: "padding:10px 14px;border-top:1px solid var(--border)" },
      taskInput, sendBtn));
  root.append(h("div", { class: "grid c2", style: "align-items:start" },
    leftCard, rightCard));

  let selSid = sessionStorage.getItem("tasking_sid") || "";
  sessionStorage.removeItem("tasking_sid");

  function renderList(rows) {
    if (!rows.length) {
      listBody.replaceChildren(h("div", { class: "empty" },
        "暂无校准期会话 — 先跑一轮使会话爬到 L4 (授权阶梯满级即进入校准期)"));
      histHead.textContent = "任务控制台";
      histBody.replaceChildren(h("div", { class: "empty" },
        "选中左侧 beacon 后, 在这里看任务历史并下发新任务"));
      return;
    }
    if (selSid && !rows.some((r) => r.session_id === selSid)) selSid = "";
    if (!selSid) selSid = rows[0].session_id;
    listBody.replaceChildren(...rows.map((r) => {
      const item = h("div", { class: "threat-item",
        style: "cursor:pointer;" + (r.session_id === selSid
          ? "background:var(--surface2);border-radius:8px" : ""),
        onclick: () => { selSid = r.session_id; renderList(rows); loadHist(); } },
        entChip("session", r.session_id),
        r.canary ? pill("触雷", "ok") : null,
        h("span", { class: "count", style: "margin-left:auto" },
          `完成 ${r.tasks_done} · 待执行 ${r.tasks_pending}`),
        h("span", { class: "count" }, relTime(r.last_ts)));
      return item;
    }));
  }

  async function loadHist() {
    if (!selSid) return;
    histHead.textContent = `任务控制台 · ${selSid.slice(0, 22)}`;
    histBody.replaceChildren(skeleton(3));
    let rows = [];
    try {
      const [issued, completed] = await Promise.all([
        api.get("cm_actions", { kind: "task_issued", session_id: selSid, page_size: 50 }),
        api.get("cm_actions", { kind: "task_completed", session_id: selSid, page_size: 50 })]);
      rows = [...(issued.rows || []), ...(completed.rows || [])]
        .sort((a, b) => b.ts - a.ts);
    } catch (e) {
      histBody.replaceChildren(h("div", { class: "empty" }, "加载失败: " + e.message));
      return;
    }
    if (!rows.length) {
      histBody.replaceChildren(h("div", { class: "empty" },
        "该会话暂无任务历史 — 在下方向其下发第一条任务"));
      return;
    }
    histBody.replaceChildren(table([
      { h: "时间", render: (r) => h("span", { class: "mono" }, relTime(r.ts)) },
      { h: "类型", render: (r) => r.kind === "task_issued"
          ? pill("下发", "info") : pill("完成", "ok") },
      { h: "内容", render: (r) => h("span", { style: "font-size:12px" },
          String(r.detail || "").slice(0, 110)) },
    ], rows));
  }

  async function load() {
    const rows = await api.taskingSessions();
    renderList(rows);
    await loadHist();
  }
  await load();
  return { root, reload: load };
}

/* ---------- 调查: 攻击者档案 ("谁在打我们") ---------- */
const VERDICT_KIND = { bad: "bad", warn: "warn", dim: "dim" };
const STEP_META = {
  probe: ["···", "dim", "探测"], climb: ["▲", "info", "爬梯"],
  attack: ["⚔", "warn", "攻击"], canary: ["⚡", "ok", "触雷"],
  deliver: ["◈", "purple", "交付"], intel: ["◆", "info", "情报"],
};

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
  // 火药味快捷入口 + 最近的活跃会话 (同一批数据, 进入页面即可点击开卷)
  try {
    const reqsP = await api.requests({ page_size: 100 });
    const reqs = reqsP.rows || [];
    const hot = reqs.filter((r) => r.canary || (r.threat || 0) >= 8).slice(0, 6);
    if (hot.length) {
      root.append(h("div", { class: "toolbar", style: "margin-top:4px" },
        h("span", { class: "muted" }, "最近的火药味会话:"),
        ...[...new Set(hot.map((r) => r.session_id))].map((sid) =>
          h("button", { class: "ctl", onclick: () => { input.value = sid; load(sid); } },
            sid.slice(0, 18)))));
    }
    const bySid = new Map();
    for (const r of reqs) {
      if (!r.session_id) continue;
      const s = bySid.get(r.session_id) || { n: 0, canary: 0, last: 0 };
      s.n += 1;
      if (r.canary) s.canary += 1;
      if (r.ts > s.last) s.last = r.ts;
      bySid.set(r.session_id, s);
    }
    const recent = [...bySid.entries()].sort((a, b) => b[1].last - a[1].last).slice(0, 10);
    if (recent.length) {
      root.append(h("div", { class: "card", style: "margin-bottom:14px" },
        h("div", { class: "card-head" }, `最近的活跃会话 (${recent.length}) — 点击整行开卷宗`),
        h("div", { class: "card-body", style: "padding-top:6px" },
          ...recent.map(([sid, s]) => h("div", { class: "threat-item", style: "cursor:pointer",
            onclick: () => { input.value = sid; load(sid); } },
            entChip("session", sid),
            h("span", { class: "count", style: "margin-left:auto" },
              `${s.n} 请求 · 触雷 ${s.canary} · 最后活跃 ${relTime(s.last)}`),
            s.canary ? pill("触雷", "ok") : null)))));
    }
  } catch (_) {}
  root.append(box);

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




HP.views = { viewSituation, viewLive, viewFleet, viewConfig, viewMetrics,
             viewBandit, viewAttribution, viewSummary, viewCompare, viewTrials,
             viewEvents, viewIntel, viewRequests, viewRuns, viewEntity, viewOps,
             viewArsenal, viewAttackers, viewSessions, viewTasking,
             viewEventsGroup, viewIntelGroup, viewExperimentsGroup };
})();
