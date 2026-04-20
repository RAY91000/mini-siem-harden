#!/usr/bin/env python3
"""
Ray-Axis SIEM — Dashboard web Flask
Interface SOC complète : alertes, corrélations, MITRE, GeoIP, recherche, acquittement
"""

from flask import Flask, render_template_string, jsonify, request, Response
import json

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Ray-Axis SOC</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#08090c;--bg2:#0d0f14;--bg3:#12151c;--bg4:#181c25;
  --border:#1d2333;--border2:#252d3f;
  --text:#bcc8dc;--muted:#3d4d66;--muted2:#566680;
  --accent:#00c8ff;
  --crit:#ff2d55;--high:#ff6b2b;--med:#ffc107;--low:#00e5a0;--info:#4dabf7;--corr:#c084fc;
  --mono:'JetBrains Mono',monospace;--display:'Syne',sans-serif;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--mono);font-size:12px}
::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}

.hdr{display:flex;align-items:center;justify-content:space-between;
  padding:10px 22px;background:var(--bg2);border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:100}
.brand{font-family:var(--display);font-size:16px;font-weight:800;color:#fff;letter-spacing:-.5px}
.brand span{color:var(--accent)}
.live{width:6px;height:6px;border-radius:50%;background:var(--low);
  animation:pulse 2s ease-in-out infinite;display:inline-block;margin-right:6px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.hdr-r{display:flex;align-items:center;gap:8px}
.search-box{background:var(--bg3);border:1px solid var(--border);color:var(--text);
  font-family:var(--mono);font-size:11px;padding:5px 12px;border-radius:3px;
  width:220px;outline:none;transition:border-color .15s}
.search-box:focus{border-color:var(--accent)}
.btn{background:var(--bg3);border:1px solid var(--border);color:var(--muted2);
  font-family:var(--mono);font-size:11px;padding:5px 12px;border-radius:3px;
  cursor:pointer;transition:all .15s}
.btn:hover{border-color:var(--accent);color:var(--accent)}
#ts{font-size:10px;color:var(--muted)}

.main{padding:16px 22px;display:grid;gap:12px}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:4px;
  padding:12px 14px;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.s-total::before{background:var(--accent)}.s-crit::before{background:var(--crit)}
.s-high::before{background:var(--high)}.s-med::before{background:var(--med)}
.s-corr::before{background:var(--corr)}.s-threat::before{background:var(--crit)}
.s-unacked::before{background:var(--high)}.s-events::before{background:var(--muted)}
.stat-l{font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:5px}
.stat-v{font-family:var(--display);font-size:26px;font-weight:800;color:#fff;line-height:1}
.v-crit{color:var(--crit)}.v-high{color:var(--high)}.v-med{color:var(--med)}
.v-corr{color:var(--corr)}.v-unacked{color:var(--high)}

.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
@media(max-width:1000px){.g2,.g3{grid-template-columns:1fr}}

.panel{background:var(--bg2);border:1px solid var(--border);border-radius:4px;overflow:hidden}
.ph{display:flex;align-items:center;justify-content:space-between;
  padding:9px 14px;border-bottom:1px solid var(--border)}
.pt{font-family:var(--display);font-size:12px;font-weight:600;color:#e0e8f8}
.pc{font-size:10px;color:var(--muted)}

.chart{padding:10px 14px;height:90px;display:flex;align-items:flex-end;gap:3px}
.bc{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:2px}
.bar{width:100%;background:var(--accent);border-radius:1px 1px 0 0;opacity:.6;min-height:2px}
.bl{font-size:8px;color:var(--muted)}

.rl{}.ri{display:flex;align-items:center;gap:8px;padding:7px 14px;
  border-bottom:1px solid rgba(29,35,51,.5);transition:background .15s}
.ri:last-child{border-bottom:none}.ri:hover{background:var(--bg3)}
.rn{font-size:9px;color:var(--muted);width:14px;flex-shrink:0}
.rlb{flex:1;font-size:11px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rb{width:55px;height:3px;background:var(--bg3);border-radius:2px;flex-shrink:0}
.rbf{height:100%;border-radius:2px}
.rc{font-size:11px;color:var(--muted);min-width:24px;text-align:right}
.dot{width:5px;height:5px;border-radius:50%;flex-shrink:0}
.d-crit{background:var(--crit)}.d-high{background:var(--high)}
.d-med{background:var(--med)}.d-low{background:var(--low)}
.d-info{background:var(--info)}.d-corr{background:var(--corr)}

.mtb{width:100%;border-collapse:collapse}
.mtb td,.mtb th{padding:6px 12px;font-size:11px;border-bottom:1px solid rgba(29,35,51,.5)}
.mtb th{color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:1px}
.mtb tr:last-child td{border-bottom:none}.mtb tr:hover td{background:var(--bg3)}
.mtag{display:inline-block;padding:1px 6px;border-radius:2px;font-size:9px;
  background:rgba(192,132,252,.12);color:var(--corr);border:1px solid rgba(192,132,252,.25)}

.fbar{display:flex;gap:6px;padding:8px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center}
.fb{padding:3px 10px;border-radius:2px;border:1px solid var(--border);
  background:transparent;color:var(--muted);font-family:var(--mono);
  font-size:10px;cursor:pointer;transition:all .15s}
.fb:hover,.fb.on{border-color:var(--accent);color:var(--accent)}
.fb.fc.on{border-color:var(--crit);color:var(--crit)}
.fb.fh.on{border-color:var(--high);color:var(--high)}
.fb.fm.on{border-color:var(--med);color:var(--med)}
.fb.fl.on{border-color:var(--low);color:var(--low)}
.fb.fco.on{border-color:var(--corr);color:var(--corr)}

.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;padding:6px 11px;font-size:9px;text-transform:uppercase;
  letter-spacing:1px;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap}
.tbl td{padding:6px 11px;border-bottom:1px solid rgba(29,35,51,.35);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tbody tr:hover td{background:var(--bg3)}

.badge{display:inline-block;padding:2px 6px;border-radius:2px;
  font-size:9px;font-weight:500;letter-spacing:.5px;text-transform:uppercase}
.bc2{background:rgba(255,45,85,.12);color:var(--crit);border:1px solid rgba(255,45,85,.25)}
.bh2{background:rgba(255,107,43,.12);color:var(--high);border:1px solid rgba(255,107,43,.25)}
.bm2{background:rgba(255,193,7,.1);color:var(--med);border:1px solid rgba(255,193,7,.2)}
.bl2{background:rgba(0,229,160,.08);color:var(--low);border:1px solid rgba(0,229,160,.2)}
.bi2{background:rgba(77,171,247,.08);color:var(--info);border:1px solid rgba(77,171,247,.2)}
.bco2{background:rgba(192,132,252,.1);color:var(--corr);border:1px solid rgba(192,132,252,.25)}

.tc{color:var(--muted);font-size:10px;white-space:nowrap}
.tip{color:var(--accent);font-size:11px}
.thost{color:var(--corr);font-size:10px}
.tmsg{color:var(--muted);font-size:10px;max-width:250px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tmitre{font-size:9px;color:var(--corr);opacity:.7}
.tf{color:var(--crit);font-size:9px;margin-left:3px}
.acked{opacity:.4}

.ack-btn{background:transparent;border:1px solid var(--muted);color:var(--muted);
  font-family:var(--mono);font-size:9px;padding:2px 6px;border-radius:2px;
  cursor:pointer;transition:all .15s}
.ack-btn:hover{border-color:var(--low);color:var(--low)}

.empty{padding:36px;text-align:center;color:var(--muted)}
.footer{text-align:center;padding:10px;font-size:9px;color:var(--muted);
  border-top:1px solid var(--border);letter-spacing:.5px}
body::after{content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.02) 2px,rgba(0,0,0,.02) 4px);
  pointer-events:none;z-index:9999}
</style>
</head>
<body>
<header class="hdr">
  <div style="display:flex;align-items:center;gap:10px">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0d0f14"/>
      <polygon points="12,3 21,20 3,20" stroke="#00c8ff" stroke-width="1.5" fill="none" stroke-linejoin="round"/>
      <circle cx="12" cy="14" r="2.2" fill="#00c8ff" opacity=".9"/>
    </svg>
    <span class="brand">Ray<span>-Axis</span></span>
    <span style="font-size:10px;color:var(--muted)"><span class="live"></span>SOC Live</span>
  </div>
  <div class="hdr-r">
    <input class="search-box" id="sb" placeholder="Recherche IP, règle, user..." oninput="doSearch(this.value)">
    <button class="btn" onclick="loadAll()">↻</button>
    <span id="ts"></span>
  </div>
</header>

<main class="main">
  <div class="stats">
    <div class="stat s-total"><div class="stat-l">Alertes</div><div class="stat-v" id="s0">—</div></div>
    <div class="stat s-crit"><div class="stat-l">Critique</div><div class="stat-v v-crit" id="s1">—</div></div>
    <div class="stat s-high"><div class="stat-l">Élevé</div><div class="stat-v v-high" id="s2">—</div></div>
    <div class="stat s-med"><div class="stat-l">Moyen</div><div class="stat-v v-med" id="s3">—</div></div>
    <div class="stat s-corr"><div class="stat-l">Corrélations</div><div class="stat-v v-corr" id="s4">—</div></div>
    <div class="stat s-threat"><div class="stat-l">IPs malveillantes</div><div class="stat-v v-crit" id="s5">—</div></div>
    <div class="stat s-unacked"><div class="stat-l">Non acquittées</div><div class="stat-v v-unacked" id="s6">—</div></div>
    <div class="stat s-events"><div class="stat-l">Événements</div><div class="stat-v" id="s7">—</div></div>
  </div>

  <div class="g2">
    <div class="panel">
      <div class="ph"><span class="pt">Alertes / heure (24h)</span><span class="pc" id="hc"></span></div>
      <div class="chart" id="hchart"></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Top règles</span></div>
      <div class="rl" id="trules"></div>
    </div>
  </div>

  <div class="g3">
    <div class="panel">
      <div class="ph"><span class="pt">Top IPs sources</span></div>
      <div class="rl" id="tips"></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Hôtes Filebeat</span></div>
      <div class="rl" id="thosts"></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Répartition sévérité</span></div>
      <div class="rl" id="tsev"></div>
    </div>
  </div>

  <div class="panel">
    <div class="ph"><span class="pt">MITRE ATT&CK</span></div>
    <div style="overflow-x:auto">
      <table class="mtb">
        <thead><tr><th>Technique</th><th>Tactique</th><th>Règle</th><th style="text-align:right">Hits</th></tr></thead>
        <tbody id="mitre"></tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="ph"><span class="pt">Dernières alertes</span><span class="pc" id="ac"></span></div>
    <div class="fbar">
      <button class="fb on"   onclick="filt(this,'')">Tout</button>
      <button class="fb fc"   onclick="filt(this,'critical')">Critique</button>
      <button class="fb fh"   onclick="filt(this,'high')">Élevé</button>
      <button class="fb fm"   onclick="filt(this,'medium')">Moyen</button>
      <button class="fb fl"   onclick="filt(this,'low')">Faible</button>
      <button class="fb"      onclick="filt(this,'info')">Info</button>
      <button class="fb fco"  onclick="filt(this,'correlation')">Corrélation</button>
      <button class="fb"      onclick="filtUnacked()">Non acquittées</button>
    </div>
    <div style="overflow-x:auto">
      <table class="tbl">
        <thead><tr>
          <th>Horodatage</th><th>Sév.</th><th>Règle</th>
          <th>Hôte/Source</th><th>IP</th><th>User</th>
          <th>MITRE</th><th style="text-align:right">N</th>
          <th>Message</th><th>Ack</th>
        </tr></thead>
        <tbody id="abody"><tr><td colspan="10" class="empty">Chargement...</td></tr></tbody>
      </table>
    </div>
  </div>
</main>
<footer class="footer">Ray-Axis SIEM &mdash; <span id="ft"></span></footer>

<script>
const SC={critical:'#ff2d55',high:'#ff6b2b',medium:'#ffc107',low:'#00e5a0',info:'#4dabf7',correlation:'#c084fc'};
const BD={critical:'bc2',high:'bh2',medium:'bm2',low:'bl2',info:'bi2',correlation:'bco2'};
let all=[], curF='', curSearch='', onlyUnacked=false;

async function api(u){const r=await fetch(u);if(!r.ok)throw new Error(r.status);return r.json();}
const ts=t=>t?(t.replace('T',' ').slice(0,19)):'—';

function renderStats(s){
  const b=s.by_severity||{};
  ['s0','s1','s2','s3','s4','s5','s6','s7'].forEach((id,i)=>{
    const vals=[s.total_alerts,b.critical,b.high,b.medium,s.total_corr,
                s.total_threats,s.total_unacked,s.total_events];
    document.getElementById(id).textContent=(vals[i]||0).toLocaleString();
  });
}

function renderHourly(h){
  if(!h||!h.length){document.getElementById('hchart').innerHTML='<div class="empty" style="padding:18px">—</div>';return;}
  const by={};h.forEach(x=>by[x.hour]=x.c);
  const mx=Math.max(1,...Object.values(by));
  let html='';
  for(let i=0;i<24;i++){
    const hr=String(i).padStart(2,'0'),c=by[hr]||0;
    const pct=Math.max(2,Math.round((c/mx)*70));
    html+=`<div class="bc"><div class="bar" style="height:${pct}px" title="${hr}h: ${c}"></div>${i%6===0?`<div class="bl">${hr}</div>`:'<div class="bl"></div>'}</div>`;
  }
  document.getElementById('hchart').innerHTML=html;
  document.getElementById('hc').textContent=`${h.reduce((s,x)=>s+x.c,0)} / 24h`;
}

function renderRank(id,items,labelFn,colorFn){
  if(!items||!items.length){document.getElementById(id).innerHTML='<div class="empty" style="padding:18px">—</div>';return;}
  const mx=items[0].c||1;
  document.getElementById(id).innerHTML=items.map((r,i)=>`
    <div class="ri">
      <span class="rn">${i+1}</span>
      ${colorFn?`<span class="dot d-${r.severity||'info'}"></span>`:''}
      <span class="rlb" title="${labelFn(r)}">${labelFn(r)}</span>
      <div class="rb"><div class="rbf" style="width:${Math.round(r.c/mx*100)}%;background:${SC[r.severity]||SC.info}"></div></div>
      <span class="rc">${r.c}</span>
    </div>`).join('');
}

function renderMitre(m){
  if(!m||!m.length){document.getElementById('mitre').innerHTML='<tr><td colspan="4" class="empty">—</td></tr>';return;}
  document.getElementById('mitre').innerHTML=m.map(x=>`
    <tr>
      <td><span class="mtag">${x.mitre_technique||'?'}</span></td>
      <td style="color:var(--muted2)">${x.mitre_tactic||'?'}</td>
      <td style="color:var(--text)">${x.rule_name||'?'}</td>
      <td style="text-align:right;color:var(--corr)">${x.c}</td>
    </tr>`).join('');
}

function applyFilters(){
  let a=all;
  if(onlyUnacked) a=a.filter(x=>!x.acknowledged);
  if(curF==='correlation') a=a.filter(x=>x.source_type==='correlation');
  else if(curF) a=a.filter(x=>x.severity===curF&&x.source_type!=='correlation');
  if(curSearch){
    const s=curSearch.toLowerCase();
    a=a.filter(x=>(x.remote_ip||'').includes(s)||(x.username||'').toLowerCase().includes(s)||
      (x.rule_name||'').toLowerCase().includes(s)||(x.message||'').toLowerCase().includes(s)||
      (x.beats_host||'').toLowerCase().includes(s));
  }
  renderAlerts(a);
}

function renderAlerts(alerts){
  document.getElementById('ac').textContent=`${alerts.length} alerte${alerts.length>1?'s':''}`;
  if(!alerts.length){
    document.getElementById('abody').innerHTML='<tr><td colspan="10" class="empty">Aucune alerte</td></tr>';
    return;
  }
  document.getElementById('abody').innerHTML=alerts.map(a=>{
    const isC=a.source_type==='correlation';
    const sev=isC?'correlation':a.severity;
    const geo=a.geo_country?`<span style="color:var(--muted);font-size:9px"> [${a.geo_country}]</span>`:'';
    const threat=a.threat_known?`<span class="tf">⚠</span>`:'';
    const host=a.beats_host
      ?`<span class="thost">${a.beats_host}</span>`
      :`<span style="color:var(--muted)">${a.source_type||'—'}</span>`;
    const acked=a.acknowledged?'class="acked"':'';
    return `<tr ${acked}>
      <td class="tc">${ts(a.timestamp)}</td>
      <td><span class="badge ${BD[sev]||'bi2'}">${sev}</span>${isC?'<span class="badge bco2" style="margin-left:3px">⚡</span>':''}</td>
      <td style="color:#e0e8f8;font-size:11px" title="${(a.description||'').replace(/"/g,'')}">${a.rule_name||a.rule_id}</td>
      <td>${host}</td>
      <td class="tip">${a.remote_ip||'—'}${geo}${threat}</td>
      <td style="color:var(--muted2);font-size:10px">${a.username||'—'}</td>
      <td class="tmitre">${a.mitre_technique||'—'}</td>
      <td style="color:var(--med);text-align:right;font-size:11px">${a.count>1?a.count:'—'}</td>
      <td class="tmsg" title="${(a.message||'').replace(/"/g,'')}">${a.message||'—'}</td>
      <td>${a.acknowledged
        ?`<span style="color:var(--low);font-size:9px">✓</span>`
        :`<button class="ack-btn" onclick="ack(${a.id})">ACK</button>`}</td>
    </tr>`;
  }).join('');
}

function filt(btn,sev){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  curF=sev; onlyUnacked=false; applyFilters();
}

function filtUnacked(){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('on'));
  curF=''; onlyUnacked=true; applyFilters();
}

function doSearch(v){ curSearch=v; applyFilters(); }

async function ack(id){
  try{
    await fetch(`/api/alerts/${id}/ack`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({notes:''})});
    const a=all.find(x=>x.id===id);
    if(a) a.acknowledged=1;
    applyFilters();
  }catch(e){console.error(e);}
}

async function loadAll(){
  try{
    const [stats,alerts]=await Promise.all([api('/api/stats'),api('/api/alerts?limit=400')]);
    renderStats(stats);
    renderHourly(stats.hourly||[]);
    renderRank('trules',stats.by_rule||[],r=>r.rule_name||r.rule_id,true);
    renderRank('tips',stats.top_ips||[],r=>{
      let l=r.remote_ip||'?';
      if(r.geo_country)l+=` [${r.geo_country}]`;
      if(r.is_threat)l+=' ⚠';
      return l;
    },false);
    renderRank('thosts',stats.top_hosts||[],r=>r.beats_host||'?',false);
    const sevItems=['critical','high','medium','low','info'].map(s=>({
      severity:s, c:(stats.by_severity||{})[s]||0
    })).filter(x=>x.c>0);
    renderRank('tsev',sevItems,r=>r.severity.charAt(0).toUpperCase()+r.severity.slice(1),true);
    renderMitre(stats.mitre||[]);
    all=alerts; applyFilters();
    const now=new Date().toLocaleTimeString('fr-FR');
    document.getElementById('ts').textContent=now;
    document.getElementById('ft').textContent='Mis à jour : '+now;
  }catch(e){console.error(e);}
}

loadAll();
setInterval(loadAll,15000);
</script>
</body>
</html>"""


def create_app(storage, config):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.get("dashboard", {}).get("secret_key", "ray-axis")

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/alerts")
    def api_alerts():
        limit        = min(int(request.args.get("limit", 200)), 1000)
        severity     = request.args.get("severity")
        source_type  = request.args.get("source_type")
        search       = request.args.get("search")
        only_threats = request.args.get("threats") == "1"
        only_unacked = request.args.get("unacked") == "1"
        rule_id      = request.args.get("rule_id")
        alerts = storage.get_recent_alerts(
            limit=limit, severity=severity, source_type=source_type,
            search=search, only_threats=only_threats,
            only_unacked=only_unacked, rule_id=rule_id,
        )
        return jsonify(alerts)

    @app.route("/api/alerts/<int:aid>")
    def api_alert(aid):
        return jsonify(storage.get_alert_by_id(aid))

    @app.route("/api/alerts/<int:aid>/ack", methods=["POST"])
    def api_ack(aid):
        body   = request.json or {}
        notes  = body.get("notes", "")
        ack_by = body.get("ack_by", "analyst")
        storage.acknowledge_alert(aid, notes, ack_by)
        return jsonify({"ok": True})

    @app.route("/api/stats")
    def api_stats():
        return jsonify(storage.get_stats())

    @app.route("/api/health")
    def api_health():
        return jsonify({"status": "ok"})

    return app
