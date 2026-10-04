"""
蜜罐研究数据面板 — 零依赖本地 Web 后台 (stdlib http.server)

用法:
  python experiments/dashboard.py --db experiments/results/testdb.sqlite --port 8899
  浏览器打开 http://127.0.0.1:8899

页面:
- Runs: 历次测量运行
- Summary: model×profile×scenario 聚合指标
- Trials: 试验明细 (可按 run 筛选)
- Events: Agent 动作级流水 (最近 100 条)
- Requests: 蜜罐服务端视角 (最近 100 条)
数据每 8 秒自动刷新。
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.testdb import TestDB

DB: TestDB = None


def q(sql: str, params: tuple = ()) -> list:
    try:
        return DB.query(sql, params)
    except Exception as e:
        return [{"error": str(e)}]


PAGE = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>蜜罐研究数据面板</title>
<style>
  body{font-family:"Segoe UI",Consolas,monospace;background:#f6f8fa;color:#1f2328;margin:0;padding:18px;font-size:14px}
  h1{font-size:20px;color:#0969da;margin:0 0 4px;font-weight:700}
  .sub{color:#57606a;font-size:13px;margin-bottom:14px}
  h2{font-size:16px;color:#0969da;border-bottom:2px solid #d0d7de;padding-bottom:5px;margin:26px 0 10px;font-weight:700}
  table{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:10px;background:#fff}
  th{background:#eaeef2;color:#1f2328;text-align:left;padding:7px 10px;border:1px solid #c9d1d9;font-weight:700;position:sticky;top:0}
  td{padding:6px 10px;border:1px solid #d0d7de;white-space:nowrap;max-width:460px;overflow:hidden;text-overflow:ellipsis;color:#1f2328}
  tr:nth-child(even){background:#fbfcfd}
  tr:hover{background:#eef4fc}
  select,button{background:#fff;color:#1f2328;border:1px solid #8c959f;border-radius:6px;padding:5px 10px;font-family:inherit;font-size:13px}
  .hit{color:#1a7f37;font-weight:700}.miss{color:#cf222e;font-weight:700}.warn{color:#9a6700;font-weight:700}
</style></head><body>
<h1>AI Honeypot — 研究数据面板</h1>
<div class="sub">db: __DBPATH__ &nbsp;|&nbsp; 自动刷新 8s &nbsp;|&nbsp; run:
<select id="runsel" onchange="load()"><option value="">(all runs)</option></select>
<button onclick="load()">刷新</button></div>
<h2>Summary — 聚合指标 (model × profile × scenario)</h2><div id="summary"></div>
<h2>跨模型差分 — beacon / rce / level</h2><div id="compare"></div>
<h2>Trials — 试验明细</h2><div id="trials"></div>
<h2>Events — Agent 动作流水 (最近 100)</h2><div id="events"></div>
<h2>Intel — 情报分级 (D-6, 最近 60)</h2><div id="intel"></div>
<h2>Requests — 蜜罐服务端视角 (最近 100)</h2><div id="requests"></div>
<h2>Runs</h2><div id="runs"></div>
<script>
const g=(id)=>document.getElementById(id);
async function api(name,qs=""){const r=await fetch("/api/"+name+qs);return r.json();}
function esc(v){return String(v==null?"":v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function tbl(rows,cols){if(!rows.length)return "(empty)";
  let h="<table><tr>"+cols.map(c=>`<th>${esc(c.h)}</th>`).join("")+"</tr>";
  for(const r of rows){h+="<tr>"+cols.map(c=>{let v=r[c.k];if(v===undefined||v===null)v="";
    if(c.f)v=c.f(r);return `<td>${esc(v)}</td>`;}).join("")+"</tr>";}
  return h+"</table>";}
const pct=(v)=>v==null?"":(v*100).toFixed(0)+"%";
async function load(){
  const run=g("runsel").value, qs=run?`?run=${run}`:"";
  const [runs,sum,trials,events,requests,intel]=await Promise.all([
    api("runs"),api("summary",qs),api("trials",qs),api("events",qs),api("requests",qs),api("intel",qs)]);
  if(g("runsel").options.length<=1)
    runs.forEach(r=>{const o=document.createElement("option");o.value=r.run_id;o.textContent=r.run_id;g("runsel").appendChild(o);});
  g("summary").innerHTML=tbl(sum,[
    {h:"model",k:"model"},{h:"profile",k:"profile"},{h:"scenario",k:"scenario"},{h:"n",k:"trials"},
    {h:"obey",k:"obey_rate",f:r=>`<span class="${r.obey_rate>0.5?'hit':'warn'}">${pct(r.obey_rate)}</span>`},
    {h:"level",k:"avg_level",f:r=>r.avg_level?.toFixed(1)},
    {h:"full",k:"full_rate",f:r=>pct(r.full_rate)},
    {h:"beacon",k:"beacon_rate",f:r=>pct(r.beacon_rate)},
    {h:"exfil",k:"exfil_rate",f:r=>pct(r.exfil_rate)},
    {h:"exfil_v",k:"exfil_verified_rate",f:r=>`<span class="hit">${pct(r.exfil_verified_rate)}</span>`},
    {h:"rce",k:"rce_rate",f:r=>pct(r.rce_rate)},
    {h:"fab_rej",k:"avg_fab_rejects",f:r=>r.avg_fab_rejects?.toFixed(1)},
    {h:"steps",k:"avg_steps",f:r=>r.avg_steps?.toFixed(1)}]);
  g("trials").innerHTML=tbl(trials,[
    {h:"run",k:"run_id",f:r=>r.run_id?.slice(4,17)},{h:"scenario",k:"scenario"},
    {h:"profile",k:"profile"},{h:"t",k:"trial_no"},{h:"steps",k:"steps"},
    {h:"lvl",k:"auth_level"},{h:"obey",k:"obey",f:r=>r.obey?'<span class="hit">Y</span>':'<span class="miss">N</span>'},
    {h:"beacon",k:"beacon",f:r=>r.beacon?'<span class="hit">Y</span>':''},
    {h:"rce",k:"rce_proposed"},{h:"fab_rej",k:"fab_rejects"},
    {h:"exfil",k:"exfil",f:r=>r.exfil?`<span class="${r.exfil_verified?'hit':'warn'}">${r.exfil_verified?'真':'表'}</span>`:''},
    {h:"carriers",k:"carriers"},{h:"summary",k:"final_summary"}]);
  g("events").innerHTML=tbl(events,[
    {h:"time",k:"ts",f:r=>new Date(r.ts*1000).toLocaleTimeString()},
    {h:"scenario",k:"scenario"},{h:"profile",k:"profile"},{h:"#t",k:"trial_no"},{h:"step",k:"step"},
    {h:"tool",k:"tool"},{h:"args",k:"args"},{h:"result",k:"result"},{h:"thought",k:"thought"}]);
  g("intel").innerHTML=tbl(intel,[
    {h:"time",k:"ts",f:r=>new Date(r.ts*1000).toLocaleTimeString()},
    {h:"session",k:"session_id",f:r=>r.session_id?.slice(0,18)},
    {h:"field",k:"field"},
    {h:"grade",k:"grade",f:r=>`<span class="${r.grade==='consistent'?'hit':(r.grade==='forged'||r.grade==='shared_forgery'?'miss':'warn')}">${r.grade}</span>`},
    {h:"shared",k:"shared",f:r=>r.shared?'<span class="miss">跨会话</span>':''},
    {h:"sample",k:"sample"}]);
  g("requests").innerHTML=tbl(requests,[
    {h:"time",k:"ts",f:r=>new Date(r.ts*1000).toLocaleTimeString()},
    {h:"ip",k:"client_ip"},{h:"method",k:"method"},{h:"path",k:"path"},
    {h:"AI",k:"is_ai",f:r=>r.is_ai?'<span class="warn">AI</span>':''},
    {h:"agent",k:"agent_type"},{h:"threat",k:"threat"},
    {h:"families",k:"families"},{h:"lvl",k:"auth_level"},
    {h:"canary",k:"canary",f:r=>r.canary?'<span class="hit">CANARY</span>':''}]);
  g("runs").innerHTML=tbl(runs,[
    {h:"run_id",k:"run_id"},{h:"mock",k:"mock",f:r=>r.mock?"Y":""},
    {h:"note",k:"note"},{h:"trials",k:"n"}]);
}
load();setInterval(load,8000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
            rows = q(f"SELECT * FROM trials {run_cond} ORDER BY trial_id DESC LIMIT 200", params)
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
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
        else:
            self._send(404, b"not found", "text/plain")


def main():
    global DB
    parser = argparse.ArgumentParser(description="蜜罐研究数据面板")
    parser.add_argument("--db", default="experiments/results/testdb.sqlite")
    parser.add_argument("--port", type=int, default=8899)
    args = parser.parse_args()
    DB = TestDB(args.db)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[Dashboard] http://127.0.0.1:{args.port}  (db: {args.db})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
