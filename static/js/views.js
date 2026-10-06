(function(){
"use strict";
const api = HP.api;
const { sseUrl, stixUrl } = HP;
const { h, esc, fmtPct, fmtNum, relTime, pill, gradePill, table, statCard,
        pageHead, barRows, histogram, openDrawer, kvList, toast, skeleton,
        tabs, $ } = HP.ui;
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
      h("div", { class: "threat-item" },
        h("span", { class: "time" }, relTime(r.ts)),
        h("b", { style: "color:var(--accent);width:38px" }, r.method || "GET"),
        h("span", { class: "path" }, r.path),
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
  root.append(pageHead("配置", "告警渠道与数据保留 · 环境变量优先级更高"));
  const wrap = h("div", { class: "card pad", style: "max-width:640px" });
  root.append(wrap);

  async function load() {
    const c = await api.config();
    const admin = c.role === "admin";
    wrap.innerHTML = "";
    if (!admin) wrap.append(h("div", { class: "banner warn" }, "只读账号 — 仅管理员可修改配置"));
    const mk = (label, node) => h("div", { class: "cfgrow" }, h("label", {}, label), node);
    const webhook = h("input", { type: "text", value: c.alert_webhook || "",
      placeholder: "https://oapi.dingtalk.com/robot/send?access_token=…", disabled: !admin });
    const fmt = h("select", { disabled: !admin },
      h("option", { value: "generic" }, "generic (Slack / Discord)"),
      h("option", { value: "dingtalk" }, "钉钉"));
    fmt.value = c.alert_fmt || "generic";
    const threshold = h("input", { type: "number", step: "0.5",
      value: c.alert_threshold || 8, disabled: !admin });
    const retention = h("input", { type: "number", min: "1",
      value: c.retention_days || 30, disabled: !admin });
    wrap.append(
      mk("告警 Webhook", webhook), mk("格式", fmt), mk("威胁阈值", threshold),
      mk("数据保留 (天)", retention),
      h("div", { class: "toolbar", style: "margin-top:14px" },
        h("button", { class: "btn primary", disabled: !admin, onclick: async () => {
          try {
            await api.saveConfig({ alert_webhook: webhook.value, alert_fmt: fmt.value,
              alert_threshold: threshold.value, retention_days: retention.value });
            toast("配置已保存");
          } catch (e) { toast("保存失败: " + e.message, "err"); } } }, "保存"),
        h("button", { class: "btn", disabled: !admin, onclick: async () => {
          try {
            const r = await api.testAlert();
            toast(r.sent ? "测试告警已发送" : "未发送 (请检查 webhook)");
          } catch (e) { toast("发送失败: " + e.message, "err"); } } }, "发送测试告警")));
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
      { h: "会话", render: (r) => h("span", { class: "mono" }, String(r.session_id || "").slice(0, 18)) },
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
      { h: "来源 IP", render: (r) => h("span", { class: "mono" }, r.client_ip) },
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
      r.query ? h("div", {}, h("div", { class: "t muted" }, "Query"), h("pre", {}, r.query)) : null)) }));
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
HP.views = { viewSituation, viewLive, viewFleet, viewConfig, viewMetrics,
             viewBandit, viewAttribution, viewSummary, viewCompare, viewTrials,
             viewEvents, viewIntel, viewRequests, viewRuns,
             viewEventsGroup, viewIntelGroup, viewExperimentsGroup };
})();
