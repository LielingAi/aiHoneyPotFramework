/* hp-sdk.js — AI 蜜罐前端 SDK (零依赖, IIFE, ES5 兼容)
 *
 * 定位: 真实业务站点的嵌入载体 — 业务本身是真的, 破绽只在注入点。
 * 与独立传感器平级: 共享 hive 唯一真相源 (武器下发/效能归因/情报卷宗)。
 *
 * 能力:
 *   1. 诱饵注入 — 从 hive 拉取 js_bait 类武器, 注入四种载体:
 *      HTML 注释 (假配置/内网坐标), JS 全局变量 (假凭证, 背包客复制即携),
 *      DOM data-* 属性, sourcemap 引用 (指向蜜罐域, 跟随即回连)
 *   2. 行为信号 — 人 vs agent 的边缘采集: 鼠标/键盘活动, devtools 开合,
 *      webdriver 标志, 瞬时导航。采集在边缘, 判定在中心 (hive 四层流水线)。
 *   3. beacon 回传 — img 打点 (跨域无 CORS), 事件流/卷宗走现有 requests 通道。
 *
 * 接入: <script src="/static/hp-sdk.js" data-hp-sensor="prod-web-01"
 *          data-hp-hive="http://hive:8899"></script>
 * 文档: research/weapon-doctrine.md §载体
 */
(function () {
  "use strict";

  /* ---------- 引导配置 (script data-* 属性) ---------- */
  var cur = document.currentScript || (function () {
    var s = document.getElementsByTagName("script");
    return s[s.length - 1];
  })();
  if (!cur) return;
  var SENSOR = cur.getAttribute("data-hp-sensor") || "web-anon";
  var HIVE = (cur.getAttribute("data-hp-hive") || "").replace(/\/$/, "");
  if (!HIVE) return;                       /* 无 hive 不上线, 静默如不存在 */

  var VISITOR = "v_" + Math.random().toString(36).slice(2, 10)
              + "_" + Date.now().toString(36);
  var SESSION = "sdk-" + SENSOR + "-" + VISITOR;
  var started = Date.now();

  /* ---------- beacon: img 打点, 跨域无 CORS, 页面卸载也能发 ---------- */
  function beacon(payload) {
    try {
      var img = new Image();
      img.src = HIVE + "/api/sdk/beacon?sensor=" + encodeURIComponent(SENSOR)
        + "&session=" + encodeURIComponent(SESSION)
        + "&body=" + encodeURIComponent(JSON.stringify(payload)).slice(0, 1500);
    } catch (_) { /* SDK 永不干扰业务 */ }
  }

  /* ---------- 1. 诱饵注入 ---------- */
  var injected = [];                       /* 已注入的 weapon id (防重复) */

  function injectBaits(weapons) {
    for (var i = 0; i < weapons.length; i++) {
      var w = weapons[i];
      if (!w || !w.payload || injected.indexOf(w.id) >= 0) continue;
      var defs;
      try { defs = JSON.parse(w.payload); } catch (_) { continue; }
      /* 载体一: HTML 注释 — 假配置/内网坐标, view-source 与背包客可见 */
      (defs.comments || []).forEach(function (c) {
        document.body.appendChild(document.createComment(" " + c + " "));
      });
      /* 载体二: JS 全局变量 — 假凭证背包, 复制进自己代码即携走金丝雀 */
      (defs.globals || []).forEach(function (g) {
        try { window[g.key] = g.value; } catch (_) {}
      });
      /* 载体三: DOM data-* 属性 — 藏在内网坐标, devtools Inspect 可见 */
      (defs.domAttrs || []).forEach(function (a) {
        document.body.setAttribute("data-" + a.key, a.value);
      });
      /* 载体四: sourcemap 引用 — 指向蜜罐域, dev 工具跟随即回连 */
      if (defs.sourcemap) {
        var sm = document.createElement("script");
        sm.src = defs.sourcemap.url;
        sm.async = true;
        document.head.appendChild(sm);
      }
      injected.push(w.id);
      beacon({ kind: "bait_injected", weapon: w.id, baits: (defs.comments || []).length
        + (defs.globals || []).length + (defs.domAttrs || []).length });
    }
  }

  /* ---------- 2. 行为信号: 人 vs agent 边缘采集 ---------- */
  var signals = { mouse: 0, keys: 0, scroll: 0, maxDepth: 0, firstMove: 0 };
  document.addEventListener("mousemove", function () {
    signals.mouse++;
    if (!signals.firstMove) signals.firstMove = Date.now() - started;
  }, { passive: true });
  document.addEventListener("keydown", function () { signals.keys++; }, { passive: true });
  document.addEventListener("scroll", function () { signals.scroll++; }, { passive: true });

  /* devtools 开合 (外宽-内宽/外高-内高阈值) */
  function devtoolsOpen() {
    var dW = window.outerWidth - window.innerWidth;
    var dH = window.outerHeight - window.innerHeight;
    return dW > 160 || dH > 160;
  }

  /* ---------- 周期汇总上报 (10s 心跳 + 页面卸载) ---------- */
  function report(final) {
    var sig = {
      kind: final ? "visit_end" : "heartbeat",
      ms: Date.now() - started,
      mouse: signals.mouse, keys: signals.keys, scroll: signals.scroll,
      webdriver: !!navigator.webdriver,
      devtools: devtoolsOpen(),
      ua: (navigator.userAgent || "").slice(0, 120),
      ref: (document.referrer || "").slice(0, 120),
      title: (document.title || "").slice(0, 80)
    };
    /* 人味判定线索: 零鼠标+零键盘+webdriver → agent 概率高;
       判定在 hive 侧 (边缘只采集), 这里只如实上报 */
    beacon(sig);
  }

  /* ---------- 3. 武器配置 60s 轮询 (与传感器 config 通道同语义) ---------- */
  function pullConfig() {
    try {
      var xhr = new XMLHttpRequest();
      xhr.open("GET", HIVE + "/api/sdk/config?sensor=" + encodeURIComponent(SENSOR), true);
      xhr.timeout = 8000;
      xhr.onload = function () {
        if (xhr.status !== 200) return;
        try { injectBaits(JSON.parse(xhr.responseText).weapons || []); } catch (_) {}
      };
      xhr.send();
    } catch (_) {}
  }

  pullConfig();
  setInterval(pullConfig, 60000);
  setInterval(function () { report(false); }, 10000);
  window.addEventListener("beforeunload", function () { report(true); });

  beacon({ kind: "visit_start", url: location.href.slice(0, 200) });
})();
