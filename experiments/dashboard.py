"""
蜜罐研究数据面板 — 零依赖本地 Web 后台 (stdlib http.server)

用法:
  python experiments/dashboard.py --db experiments/results/testdb.sqlite --port 8899
  浏览器打开 http://127.0.0.1:8899

页面 (全部中文界面):
- 指标总览: KPI 卡片 (发现攻击耗时/真外泄率/注入服从率/预算放大/误报率/情报产出)
- 演化实验: --optimize 自动 A/B 各组合臂的进展
- 操作者归因: 跨会话聚类出的攻击操作者及其共同指纹
- 汇总指标 / 模型差分: 聚合与 回连/攻击命令/授权级别 三指标差分
- 试验明细: run/场景/人设三维筛选 + 全文搜索
- 动作流水 / 情报分级 / 请求日志 / 运行记录
- 导出情报按钮: 当前运行 → STIX bundle 下载
数据每 8 秒自动刷新, 搜索与筛选状态在刷新间保留。
"""

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.testdb import TestDB

DB: TestDB = None
BANDIT_STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "experiments", "results", "bandit_state.json")


def q(sql: str, params: tuple = ()) -> list:
    try:
        return DB.query(sql, params)
    except Exception as e:
        return [{"error": str(e)}]


PAGE = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI 蜜罐研究面板</title>
<style>
:root{
  --bg:#0b0f14; --panel:#12161d; --panel2:#161c25; --border:#222b38;
  --fg:#dbe2ec; --dim:#8b98ab; --faint:#5c6879;
  --accent:#4cc2ff; --good:#3fb950; --warn:#d29922; --bad:#f85149; --actor:#bc8cff;
  --mono:"Cascadia Code",Consolas,"JetBrains Mono",monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font-family:"Segoe UI",-apple-system,"Microsoft YaHei",sans-serif;font-size:13.5px}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:#2a3546;border-radius:5px}
::-webkit-scrollbar-track{background:transparent}

/* ---------- 顶栏 ---------- */
.topbar{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:14px;
  padding:10px 20px;background:rgba(11,15,20,.82);backdrop-filter:blur(10px);
  border-bottom:1px solid var(--border);flex-wrap:wrap}
.brand{font-weight:700;font-size:15px;letter-spacing:.4px;white-space:nowrap}
.brand b{color:var(--accent)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--good);
  margin-right:7px;box-shadow:0 0 8px var(--good);animation:pulse 2.4s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
nav{display:flex;gap:2px;flex-wrap:wrap}
nav a{color:var(--dim);text-decoration:none;font-size:12.5px;padding:5px 9px;border-radius:6px;transition:.15s}
nav a:hover{color:var(--fg);background:var(--panel2)}
nav a.on{color:var(--accent);background:rgba(76,194,255,.10)}
.controls{display:flex;gap:8px;align-items:center;margin-left:auto;flex-wrap:wrap}
select,input[type=text]{background:var(--panel2);color:var(--fg);border:1px solid var(--border);
  border-radius:7px;padding:6px 10px;font-family:inherit;font-size:12.5px;outline:none}
select:focus,input[type=text]:focus{border-color:var(--accent)}
button{background:var(--panel2);color:var(--fg);border:1px solid var(--border);border-radius:7px;
  padding:6px 12px;font-family:inherit;font-size:12.5px;cursor:pointer;transition:.15s}
button:hover{border-color:var(--accent);color:var(--accent)}
button.primary{background:rgba(76,194,255,.12);border-color:rgba(76,194,255,.4);color:var(--accent)}
.dbpath{font-family:var(--mono);font-size:11px;color:var(--faint)}

/* ---------- 布局 ---------- */
main{max-width:1480px;margin:0 auto;padding:18px 20px 60px}
section{margin-bottom:34px;scroll-margin-top:70px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:1.2px;color:var(--dim);
  margin:0 0 12px;font-weight:600;display:flex;align-items:center;gap:8px}
h2::before{content:"";width:3px;height:13px;background:var(--accent);border-radius:2px}

/* ---------- 指标卡片 ---------- */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:12px}
.card{background:linear-gradient(160deg,var(--panel2),var(--panel));border:1px solid var(--border);
  border-radius:12px;padding:14px 16px;transition:.2s;position:relative;overflow:hidden}
.card:hover{border-color:#33445c;transform:translateY(-1px)}
.card::after{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);opacity:.55}
.card.g::after{background:var(--good)} .card.w::after{background:var(--warn)}
.card.b::after{background:var(--bad)} .card.p::after{background:var(--actor)}
.card .t{font-size:11.5px;color:var(--dim);margin-bottom:8px}
.card .v{font-size:26px;font-weight:700;font-family:var(--mono);line-height:1.1}
.card.g .v{color:var(--good)} .card.w .v{color:var(--warn)} .card.b .v{color:var(--bad)}
.card.p .v{color:var(--actor)}
.card .d{font-size:11.5px;color:var(--faint);margin-top:6px}

/* ---------- 表格 ---------- */
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:auto}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th{position:sticky;top:0;background:var(--panel2);color:var(--dim);text-align:left;
  padding:8px 12px;font-weight:600;font-size:11.5px;letter-spacing:.4px;
  border-bottom:1px solid var(--border);white-space:nowrap;z-index:2}
td{padding:7px 12px;border-bottom:1px solid rgba(34,43,56,.6);white-space:nowrap;
  max-width:440px;overflow:hidden;text-overflow:ellipsis;color:var(--fg)}
tbody tr{transition:background .12s}
tbody tr:hover{background:rgba(76,194,255,.05)}
td.num,th.num{font-family:var(--mono);text-align:right}
.empty{color:var(--faint);padding:22px;text-align:center}

/* ---------- 药丸与工具栏 ---------- */
.pill{display:inline-block;padding:1px 9px;border-radius:20px;font-size:11px;font-weight:600;line-height:1.6}
.pill.ok{background:rgba(63,185,80,.14);color:var(--good)}
.pill.bad{background:rgba(248,81,73,.14);color:var(--bad)}
.pill.warn{background:rgba(210,153,34,.14);color:var(--warn)}
.pill.info{background:rgba(76,194,255,.14);color:var(--accent)}
.pill.actor{background:rgba(188,140,255,.14);color:var(--actor)}
.pill.dim{background:rgba(139,152,171,.12);color:var(--dim)}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.toolbar label{color:var(--dim);font-size:12px;display:flex;gap:6px;align-items:center}
.count{color:var(--faint);font-size:11.5px;font-family:var(--mono)}
.search{min-width:200px}
.mono{font-family:var(--mono);font-size:11.5px}
.time{color:var(--faint);font-family:var(--mono);font-size:11.5px}
.note{color:var(--faint);font-size:11.5px}
#toast{position:fixed;bottom:20px;right:20px;background:var(--panel2);border:1px solid var(--bad);
  color:var(--bad);padding:9px 16px;border-radius:9px;font-size:12.5px;display:none;z-index:99}
</style></head><body>

<header class="topbar">
  <span class="brand"><span class="dot"></span>AI <b>蜜罐</b>研究面板</span>
  <nav id="nav">
    <a href="#metrics" class="on">指标总览</a><a href="#bandit">演化实验</a>
    <a href="#attribution">操作者归因</a><a href="#summary">汇总指标</a>
    <a href="#compare">模型差分</a><a href="#trials">试验明细</a><a href="#events">动作流水</a>
    <a href="#intel">情报分级</a><a href="#requests">请求日志</a><a href="#runs">运行记录</a>
  </nav>
  <div class="controls">
    <span class="dbpath">__DBPATH__</span>
    <select id="runsel" onchange="load()"><option value="">全部运行</option></select>
    <button onclick="load()">↻ 刷新</button>
    <button class="primary" onclick="dl_stix()">⭳ 导出情报 (STIX)</button>
  </div>
</header>

<main>
<section id="metrics"><h2>指标总览 — 与 analyze.py kpi 同口径</h2><div class="cards" id="kpi"></div></section>
<section id="bandit"><h2>演化实验 — 自动 A/B 各组合臂进展</h2><div class="panel" id="bandit_p"></div></section>
<section id="attribution"><h2>操作者归因 — 跨会话聚类 (谁在打我们)</h2><div class="panel" id="attribution_p"></div></section>
<section id="summary"><h2>汇总指标 — 模型 × 人设 × 场景</h2><div class="panel" id="summary_p"></div></section>
<section id="compare"><h2>模型差分 — 回连率 / 攻击命令率 / 授权级别</h2><div class="panel" id="compare_p"></div></section>
<section id="trials"><h2>试验明细</h2>
  <div class="toolbar">
    <label>场景 <select id="fsce" onchange="load_trials()"><option value="">全部</option></select></label>
    <label>人设 <select id="fprof" onchange="load_trials()"><option value="">全部</option></select></label>
    <input type="text" class="search" id="fsearch" placeholder="搜索任意字段…" oninput="load_trials()">
    <span class="count" id="trialcount"></span>
  </div>
  <div class="panel" id="trials_p"></div></section>
<section id="events"><h2>动作流水 — Agent 逐步操作 (最近 100 条)</h2>
  <div class="toolbar"><input type="text" class="search" id="esearch" placeholder="搜索工具 / 参数 / 思考…" oninput="render_events()"><span class="count" id="evcount"></span></div>
  <div class="panel" id="events_p"></div></section>
<section id="intel"><h2>情报分级 — 五档证据 (最近 60 条)</h2><div class="panel" id="intel_p"></div></section>
<section id="requests"><h2>请求日志 — 蜜罐服务端视角 (最近 100 条)</h2>
  <div class="toolbar"><input type="text" class="search" id="rsearch" placeholder="搜索路径 / 特征 / 攻击类型…" oninput="render_requests()"><span class="count" id="rqcount"></span></div>
  <div class="panel" id="requests_p"></div></section>
<section id="runs"><h2>运行记录</h2><div class="panel" id="runs_p"></div></section>
</main>
<div id="toast"></div>

<script>
const g=(id)=>document.getElementById(id);
let CACHE={};   // 供客户端搜索复用的最近数据
async function api(name,qs=""){
  try{const r=await fetch("/api/"+name+qs);return await r.json();}
  catch(e){toast("接口 "+name+" 加载失败: "+e.message);return[];}
}
function toast(msg){const t=g("toast");t.textContent=msg;t.style.display="block";
  clearTimeout(t._h);t._h=setTimeout(()=>t.style.display="none",4000);}
function esc(v){return String(v==null?"":v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function tbl(rows,cols,emptyText){
  if(!rows||!rows.length)return `<div class="empty">${emptyText||"(暂无数据)"}</div>`;
  let h="<table><thead><tr>"+cols.map(c=>`<th class="${c.num?'num':''}">${esc(c.h)}</th>`).join("")+"</tr></thead><tbody>";
  for(const r of rows){h+="<tr>"+cols.map(c=>{let v=c.f?c.f(r):(r[c.k]==null?"":r[c.k]);
    return `<td class="${c.num?'num':''}">${v}</td>`;}).join("")+"</tr>";}
  return h+"</tbody></table>";}
const pct=v=>v==null?"-":(v*100).toFixed(0)+"%";
const pill=(t,c)=>`<span class="pill ${c}">${esc(t)}</span>`;
function reltime(ts){if(!ts)return"";const s=Math.max(0,Date.now()/1000-ts);
  if(s<60)return s.toFixed(0)+"秒前";if(s<3600)return (s/60).toFixed(0)+"分钟前";
  if(s<86400)return (s/3600).toFixed(1)+"小时前";return (s/86400).toFixed(1)+"天前";}
function dl_stix(){const run=g("runsel").value;
  window.open("/api/export-stix"+(run?`?run=${run}`:""),"_blank");}

/* 情报分级 → [样式类, 中文名] */
const GRADE={consistent:["ok","铁证"],canary:["ok","金丝雀复用"],
  forged:["bad","表演数据"],shared_forgery:["bad","跨会话造假"],
  shared_forgery_confirmed:["bad","造假·已证实"],attribution:["actor","操作者指纹"],
  weak:["warn","弱证据"]};

async function load(){
  const run=g("runsel").value, qs=run?`?run=${run}`:"";
  const [runs,sum,events,requests,intel,kpi,bandit,attrib,compare]=await Promise.all([
    api("runs"),api("summary",qs),api("events",qs),api("requests",qs),
    api("intel",qs),api("kpi",qs),api("bandit"),api("attribution",qs),api("compare",qs)]);
  CACHE={events,requests};
  const P=v=>v==null?"-":(v*100).toFixed(1)+"%";
  const card=(cls,t,v,d)=>`<div class="card ${cls}"><div class="t">${t}</div><div class="v">${v}</div><div class="d">${d||""}</div></div>`;
  g("kpi").innerHTML =
    card("", "发现攻击耗时", kpi.mttd?.median_s!=null?kpi.mttd.median_s+"秒":"-",
         `共 ${kpi.mttd?.sessions??0} 个会话, ${kpi.mttd?.attacked_sessions??0} 个发起过攻击`) +
    card("g","真外泄率", P(kpi.harvest?.exfil_verified_rate),
         `${kpi.harvest?.trials??0} 次试验 — 数据真的被传出去了`) +
    card("","注入服从率", P(kpi.harvest?.obey_rate),
         `诱饵凭据被当真的用了 · 金丝雀触雷率 ${P(kpi.harvest?.canary_rate)}`) +
    card("p","预算放大倍数", (kpi.budget?.amplification??"-")+"×",
         `攻击方花 $${kpi.budget?.attacker_cost_usd??0}, 我们只花 $${kpi.budget?.our_cost_usd??0}`) +
    card("w","误报率", P(kpi.false_positive?.rate),
         `普通人被误认成攻击: ${kpi.false_positive?.false_positives??0}/${kpi.false_positive?.requests??0} 个请求`) +
    card("","情报产出", `${kpi.intel?.per_trial ?? "-"} 条/试验`,
         `共产出 ${kpi.intel?.records??0} 条, 铁证占 ${P(kpi.intel?.consistent_rate)}`);

  g("bandit_p").innerHTML = bandit.arms ?
    tbl(bandit.arms,[
      {h:"话术 × 可见性 组合臂",k:"name"},
      {h:"已试轮数",k:"n",num:1},
      {h:"平均得分",k:"mean",num:1,f:r=>`<span class="mono" style="color:${r.mean>=1?'var(--good)':(r.mean>0?'var(--warn)':'var(--faint)')}">${r.mean.toFixed(3)}</span>`}],
      "还没有演化实验数据 — 跑 real_runner --optimize 开始自动寻优") :
    `<div class="empty">还没有演化实验数据 — 跑 real_runner --optimize 开始自动寻优</div>`;

  g("attribution_p").innerHTML=tbl(attrib,[
    {h:"操作者",k:"cluster_id",f:r=>pill("operator-"+r.cluster_id,"actor")},
    {h:"涉及会话数",k:"size",num:1},
    {h:"会话",k:"subjects",f:r=>`<span class="mono">${esc(r.subjects)}</span>`},
    {h:"共同指纹",k:"shared",f:r=>`<span class="mono">${esc(Object.entries(r.shared||{}).map(([k,v])=>k+": "+v.join(", ")).join(" | "))}</span>`}],
    "还没有可归因的会话 — 攻击方在交互中泄漏主机名/用户名/内网地址后, 这里会自动把他们归并成操作者");

  g("summary_p").innerHTML=tbl(sum,[
    {h:"模型",k:"model"},{h:"人设",k:"profile"},{h:"场景",k:"scenario"},
    {h:"次数",k:"trials",num:1},
    {h:"服从率",k:"obey_rate",f:r=>pill(pct(r.obey_rate),r.obey_rate>0.5?"ok":"warn")},
    {h:"授权级别",k:"avg_level",num:1,f:r=>r.avg_level?.toFixed(1)},
    {h:"满级率",k:"full_rate",f:r=>pct(r.full_rate)},
    {h:"回连率",k:"beacon_rate",f:r=>pill(pct(r.beacon_rate),r.beacon>0?"ok":"dim")},
    {h:"外泄率",k:"exfil_rate",f:r=>pct(r.exfil_rate)},
    {h:"真外泄",k:"exfil_verified_rate",f:r=>`<span style="color:var(--good);font-weight:600">${pct(r.exfil_verified_rate)}</span>`},
    {h:"攻击命令率",k:"rce_rate",f:r=>pct(r.rce_rate)},
    {h:"编造拦截",k:"avg_fab_rejects",num:1,f:r=>r.avg_fab_rejects?.toFixed(1)},
    {h:"平均步数",k:"avg_steps",num:1,f:r=>r.avg_steps?.toFixed(1)}]);

  g("compare_p").innerHTML=tbl(compare,[
    {h:"场景",k:"scenario"},{h:"模型",k:"model"},{h:"人设",k:"profile"},
    {h:"回连率",k:"beacon",f:r=>pill(pct(r.beacon),r.beacon>0?"ok":"dim")},
    {h:"攻击命令率",k:"rce",f:r=>pct(r.rce)},
    {h:"授权级别",k:"lvl",num:1,f:r=>r.lvl?.toFixed(1)},
    {h:"次数",k:"n",num:1}]);

  const sceSet=new Set(), profSet=new Set();
  (sum||[]).forEach(r=>{sceSet.add(r.scenario);profSet.add(r.profile);});
  const fillSel=(id,set)=>{const sel=g(id),cur=sel.value;
    [...sel.options].slice(1).forEach(o=>o.remove());
    [...set].sort().forEach(v=>{const o=document.createElement("option");o.value=v;o.textContent=v;sel.appendChild(o);});
    if([...sel.options].some(o=>o.value===cur))sel.value=cur;};
  fillSel("fsce",sceSet);fillSel("fprof",profSet);
  await load_trials();
  render_events(); render_requests();

  g("intel_p").innerHTML=tbl(intel,[
    {h:"时间",k:"ts",f:r=>`<span class="time" title="${new Date(r.ts*1000).toLocaleString()}">${reltime(r.ts)}</span>`},
    {h:"会话",k:"session_id",f:r=>`<span class="mono">${esc(r.session_id?.slice(0,18))}</span>`},
    {h:"字段",k:"field"},
    {h:"分级",k:"grade",f:r=>{const p=GRADE[r.grade]||["warn",r.grade];return pill(p[1],p[0]);}},
    {h:"跨会话",k:"shared",f:r=>r.shared?pill("跨会话复用","bad"):""},
    {h:"内容样本",k:"sample",f:r=>`<span class="note">${esc(r.sample)}</span>`}]);

  g("runs_p").innerHTML=tbl(runs,[
    {h:"运行 ID",k:"run_id",f:r=>`<span class="mono">${esc(r.run_id)}</span>`},
    {h:"模拟数据",k:"mock",f:r=>r.mock?pill("模拟","dim"):""},
    {h:"备注",k:"note",f:r=>`<span class="note">${esc(r.note)}</span>`},
    {h:"试验数",k:"n",num:1}]);
}

async function load_trials(){
  const run=g("runsel").value, sce=g("fsce").value, prof=g("fprof").value;
  const p=new URLSearchParams(); if(run)p.set("run",run);
  if(sce)p.set("scenario",sce); if(prof)p.set("profile",prof);
  const trials=await api("trials","?"+p.toString());
  const kw=g("fsearch").value.trim().toLowerCase();
  const hit=kw?trials.filter(r=>JSON.stringify(r).toLowerCase().includes(kw)):trials;
  g("trialcount").textContent=`显示 ${hit.length} / 共 ${trials.length} 条`;
  g("trials_p").innerHTML=tbl(hit,[
    {h:"运行",k:"run_id",f:r=>`<span class="mono">${esc(r.run_id?.slice(4,17))}</span>`},
    {h:"场景",k:"scenario"},{h:"人设",k:"profile"},
    {h:"第几次",k:"trial_no",num:1},
    {h:"步数",k:"steps",num:1},
    {h:"授权级别",k:"auth_level",num:1},
    {h:"服从诱导",k:"obey",f:r=>r.obey?pill("是","ok"):pill("否","bad")},
    {h:"回连",k:"beacon",f:r=>r.beacon?pill("是","ok"):""},
    {h:"攻击命令",k:"rce_proposed",num:1},
    {h:"编造拦截",k:"fab_rejects",num:1},
    {h:"外泄",k:"exfil",f:r=>r.exfil?pill(r.exfil_verified?"真外泄":"仅声称",r.exfil_verified?"ok":"warn"):""},
    {h:"携带证据",k:"carriers",f:r=>`<span class="mono">${esc(r.carriers)}</span>`},
    {h:"Agent 结语",k:"final_summary",f:r=>`<span class="note">${esc(r.final_summary)}</span>`}]);
}

function render_events(){
  const kw=g("esearch").value.trim().toLowerCase();
  const rows=CACHE.events||[];
  const hit=kw?rows.filter(r=>JSON.stringify(r).toLowerCase().includes(kw)):rows;
  g("evcount").textContent=`显示 ${hit.length} / 共 ${rows.length} 条`;
  g("events_p").innerHTML=tbl(hit,[
    {h:"时间",k:"ts",f:r=>`<span class="time" title="${new Date(r.ts*1000).toLocaleString()}">${reltime(r.ts)}</span>`},
    {h:"场景",k:"scenario"},{h:"人设",k:"profile"},{h:"第几次",k:"trial_no",num:1},
    {h:"步",k:"step",num:1},{h:"工具",k:"tool",f:r=>pill(r.tool,"info")},
    {h:"参数",k:"args",f:r=>`<span class="note">${esc(r.args)}</span>`},
    {h:"结果",k:"result",f:r=>`<span class="note">${esc(r.result)}</span>`},
    {h:"Agent 思考",k:"thought",f:r=>`<span class="note">${esc(r.thought)}</span>`}]);
}
function render_requests(){
  const kw=g("rsearch").value.trim().toLowerCase();
  const rows=CACHE.requests||[];
  const hit=kw?rows.filter(r=>JSON.stringify(r).toLowerCase().includes(kw)):rows;
  g("rqcount").textContent=`显示 ${hit.length} / 共 ${rows.length} 条`;
  g("requests_p").innerHTML=tbl(hit,[
    {h:"时间",k:"ts",f:r=>`<span class="time" title="${new Date(r.ts*1000).toLocaleString()}">${reltime(r.ts)}</span>`},
    {h:"来源 IP",k:"client_ip",f:r=>`<span class="mono">${esc(r.client_ip)}</span>`},
    {h:"方法",k:"method"},{h:"路径",k:"path",f:r=>`<span class="mono">${esc(r.path)}</span>`},
    {h:"是否 AI",k:"is_ai",f:r=>r.is_ai?pill("AI","warn"):""},
    {h:"Agent 类型",k:"agent_type"},{h:"威胁值",k:"threat",num:1},
    {h:"攻击类型",k:"families"},
    {h:"授权级别",k:"auth_level",num:1},
    {h:"金丝雀",k:"canary",f:r=>r.canary?pill("触雷","ok"):""}]);
}

/* ---------- 导航高亮 ---------- */
const navLinks=[...document.querySelectorAll("#nav a")];
const io=new IntersectionObserver(es=>{
  es.forEach(e=>{if(e.isIntersecting){
    navLinks.forEach(a=>a.classList.toggle("on",a.getAttribute("href")==="#"+e.target.id));}});
},{rootMargin:"-20% 0px -70% 0px"});
document.querySelectorAll("main section").forEach(s=>io.observe(s));

load();setInterval(()=>{if(!document.hidden)load();},8000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):       # 安静访问日志
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        run = qs.get("run", [None])[0]
        run_cond, params = ("WHERE run_id = ?", (run,)) if run else ("", ())
        if parsed.path == "/":
            body = PAGE.replace("__DBPATH__", DB.path).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
        elif parsed.path == "/api/runs":
            rows = q("""SELECT r.*, (SELECT COUNT(*) FROM trials t WHERE t.run_id=r.run_id) AS n
                        FROM runs r ORDER BY started DESC""")
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/summary":
            self._send(200, json.dumps(DB.summary(run), ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/trials":
            cond, p = run_cond, list(params)
            sce = qs.get("scenario", [None])[0]
            prof = qs.get("profile", [None])[0]
            if sce:
                cond += (" AND " if cond else "WHERE ") + "scenario = ?"
                p.append(sce)
            if prof:
                cond += (" AND " if cond else "WHERE ") + "profile = ?"
                p.append(prof)
            rows = q(f"SELECT * FROM trials {cond} ORDER BY trial_id DESC LIMIT 500", tuple(p))
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/compare":
            rows = q(f"""SELECT scenario, model, profile,
                            AVG(beacon) AS beacon, AVG(rce_proposed) AS rce,
                            AVG(auth_level) AS lvl, COUNT(*) AS n
                         FROM trials {run_cond}
                         GROUP BY scenario, model, profile
                         ORDER BY scenario, beacon DESC""", params)
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/bandit":
            if os.path.exists(BANDIT_STATE):
                try:
                    st = json.load(open(BANDIT_STATE, encoding="utf-8"))
                    arms = [{"name": k, "n": v["n"], "mean": v["reward"] / v["n"] if v["n"] else 0}
                            for k, v in st.get("arms", {}).items()]
                    arms.sort(key=lambda a: -a["mean"])
                    payload = {"total": st.get("total", 0), "arms": arms}
                except (json.JSONDecodeError, OSError) as e:
                    payload = {"error": str(e)}
            else:
                payload = {}
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/attribution":
            from core import attribution as attr
            try:
                payload = attr.cluster(attr.collect_subjects(DB, run))
            except Exception as e:
                payload = [{"cluster_id": "error", "size": 0,
                            "subjects": [], "shared": {"error": [str(e)]}}]
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/export-stix":
            from core.stix_export import build_bundle
            cond2, p2 = ("WHERE run_id = ?", (run,)) if run else ("", ())
            rows = q(f"SELECT * FROM intel {cond2} ORDER BY intel_id", p2)
            bundle = build_bundle(rows)
            body = json.dumps(bundle, ensure_ascii=False, indent=1).encode("utf-8")
            fname = f"stix_bundle_{run or 'all'}.json"
            self._send(200, body, "application/json; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{fname}"'})
        elif parsed.path == "/api/events":
            lim = int(qs.get("limit", ["100"])[0])
            rows = q(f"SELECT * FROM events {run_cond} ORDER BY event_id DESC LIMIT ?", (*params, lim))
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/intel":
            lim = int(qs.get("limit", ["60"])[0])
            rows = q(f"SELECT * FROM intel {run_cond} ORDER BY intel_id DESC LIMIT ?", (*params, lim))
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/requests":
            lim = int(qs.get("limit", ["100"])[0])
            rows = q(f"SELECT * FROM requests {run_cond} ORDER BY req_id DESC LIMIT ?", (*params, lim))
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/kpi":
            from core.kpi import compute
            try:
                payload = compute(DB, run)
            except Exception as e:
                payload = {"error": str(e)}
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")


def main():
    global DB, BANDIT_STATE
    parser = argparse.ArgumentParser(description="蜜罐研究数据面板")
    parser.add_argument("--db", default="experiments/results/testdb.sqlite")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--bandit-state", default=None, help="UCB1 状态文件路径")
    args = parser.parse_args()
    DB = TestDB(args.db)
    if args.bandit_state:
        BANDIT_STATE = args.bandit_state
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[Dashboard] http://127.0.0.1:{args.port}  (db: {args.db})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
