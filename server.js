#!/usr/bin/env node
// GravityOS WebUI Backend v2
"use strict";
const express  = require("express");
const http     = require("http");
const { WebSocketServer } = require("ws");
const si       = require("systeminformation");
const { exec, execSync } = require("child_process");
const { promisify } = require("util");
const path     = require("path");
const fs       = require("fs");
const crypto   = require("crypto");
let Dockerode; try { Dockerode = require("dockerode"); } catch {}

const execAsync = promisify(exec);
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });
const docker = Dockerode ? new Dockerode({ socketPath: "/var/run/docker.sock" }) : null;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Config ────────────────────────────────────────────────────────────────────
const CFG      = "/etc/gravity";
const CREDS    = `${CFG}/credentials`;
const SESSIONS = `${CFG}/sessions.json`;
const WIZARD   = `${CFG}/.wizard_done`;

function getCreds() {
  try { const l = fs.readFileSync(CREDS,"utf8").trim().split("\n"); return { user: l[0]||"gravity", pass: l[1]||"gravity" }; }
  catch { return { user:"gravity", pass:"gravity" }; }
}

// ── Sessions ──────────────────────────────────────────────────────────────────
let sess = {};
try { sess = JSON.parse(fs.readFileSync(SESSIONS,"utf8")); } catch {}
function saveSess() { try { fs.writeFileSync(SESSIONS, JSON.stringify(sess)); } catch {} }
function newSid() { const s = crypto.randomBytes(32).toString("hex"); sess[s] = Date.now(); saveSess(); return s; }
function validSid(s) { if (!s||!sess[s]) return false; if (Date.now()-sess[s]>8*3600*1000) { delete sess[s]; return false; } sess[s]=Date.now(); return true; }
function getSid(req) { return (req.headers.cookie||"").match(/gravity_sid=([a-f0-9]+)/)?.[1]; }
function auth(req, res, next) { if (validSid(getSid(req))) return next(); res.status(401).json({ error:"Session expirée", redirect:"/login.html" }); }
function isLive() { return fs.existsSync("/run/live")||fs.existsSync("/lib/live/mount/medium"); }

// ── Routes publiques ──────────────────────────────────────────────────────────
app.get("/login.html",       (req,res) => res.sendFile(path.join(__dirname,"web","login.html")));
app.get("/wizard.html",      (req,res) => res.sendFile(path.join(__dirname,"web","wizard.html")));
app.get("/gravity-logo.png", (req,res) => res.sendFile(path.join(__dirname,"web","gravity-logo.png")));

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post("/api/auth/login", (req,res) => {
  const { username, password } = req.body;
  const c = getCreds();
  if (username===c.user && password===c.pass) {
    const sid = newSid();
    res.setHeader("Set-Cookie",`gravity_sid=${sid}; Path=/; HttpOnly; SameSite=Strict`);
    res.json({ ok:true, wizardDone: fs.existsSync(WIZARD) });
  } else res.status(401).json({ error:"Identifiants incorrects" });
});
app.post("/api/auth/logout", (req,res) => { const s=getSid(req); if(s) delete sess[s]; res.setHeader("Set-Cookie","gravity_sid=; Path=/; Max-Age=0"); res.json({ok:true}); });
app.get("/api/auth/status",  (req,res) => res.json({ authenticated: validSid(getSid(req)), wizardDone: fs.existsSync(WIZARD) }));

// ── Wizard (pas besoin d'auth — c'est la 1ère config) ─────────────────────────
app.post("/api/wizard/complete", async (req,res) => {
  const { hostname, username, password, timezone } = req.body;
  try {
    if (hostname) await execAsync(`hostnamectl set-hostname "${hostname.replace(/[^a-zA-Z0-9-]/g,"")}"` ).catch(()=>{});
    if (username && password) {
      const u = username.replace(/[^a-zA-Z0-9_-]/g,"");
      await execAsync(`id "${u}" 2>/dev/null || useradd -m -s /bin/bash -G sudo,libvirt,kvm,docker "${u}"`).catch(()=>{});
      await execAsync(`echo "${u}:${password}" | chpasswd`);
      await execAsync(`echo "root:${password}" | chpasswd`);
      fs.mkdirSync(CFG,{recursive:true});
      fs.writeFileSync(CREDS,`${u}\n${password}`,{mode:0o600});
      await execAsync(`(echo "${password}"; echo "${password}") | smbpasswd -a "${u}" -s 2>/dev/null`).catch(()=>{});
    }
    if (timezone) await execAsync(`timedatectl set-timezone "${timezone}"`).catch(()=>{});
    fs.writeFileSync(WIZARD, new Date().toISOString());
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get("/install", (req,res) => {
  if (!validSid(getSid(req))) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname,"web","install.html"));
});
app.get("/install.html", (req,res) => {
  if (!validSid(getSid(req))) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname,"web","install.html"));
});
app.get("/", (req,res) => {
  if (!fs.existsSync(WIZARD)) return res.redirect("/wizard.html");
  if (!validSid(getSid(req))) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname,"web","index.html"));
});
app.use((req,res,next) => {
  if (req.path.startsWith("/api/")) return next();
  if (req.path === "/login.html" || req.path === "/wizard.html" || req.path === "/gravity-logo.png") return next();
  if (!validSid(getSid(req))) {
    if (!fs.existsSync(WIZARD)) return res.redirect("/wizard.html");
    return res.redirect("/login.html");
  }
  next();
});
app.use(express.static(path.join(__dirname,"web")));

// ── WebSocket ─────────────────────────────────────────────────────────────────
wss.on("connection", (ws, req) => {
  if (!validSid((req.headers.cookie||"").match(/gravity_sid=([a-f0-9]+)/)?.[1])) { ws.close(4401); return; }

  if (req.url.startsWith("/terminal")) {
    const send = d => { try{ ws.send(JSON.stringify({type:"output",data:d})); }catch{} };
    let pty = null;
    try { pty = require("node-pty"); } catch {}

    if (pty) {
      // node-pty disponible : terminal complet avec resize
      const t = pty.spawn("/bin/bash", [], {
        name: "xterm-256color", cols: 120, rows: 40,
        env: { ...process.env, TERM:"xterm-256color", LANG:"fr_FR.UTF-8" }
      });
      t.onData(d => send(d));
      ws.on("message", raw => {
        try {
          const m = JSON.parse(raw);
          if (m.type === "input")  t.write(m.data);
          if (m.type === "resize") t.resize(Math.max(1,m.cols), Math.max(1,m.rows));
        } catch { t.write(String(raw)); }
      });
      ws.on("close", () => { try{ t.kill(); }catch{} });
    } else {
      // Fallback : child_process.spawn sans pty (pas de couleurs mais fonctionnel)
      const { spawn } = require("child_process");
      const shell = spawn("/bin/bash", ["--login"], {
        env: { ...process.env, TERM:"xterm", LANG:"fr_FR.UTF-8" },
        stdio: ["pipe","pipe","pipe"]
      });
      shell.stdout.on("data", d => send(d.toString()));
      shell.stderr.on("data", d => send(d.toString()));
      shell.on("close", () => send("\r\n[Session terminée]\r\n"));
      ws.on("message", raw => {
        try {
          const m = JSON.parse(raw);
          if (m.type === "input") shell.stdin.write(m.data);
        } catch { shell.stdin.write(String(raw)); }
      });
      ws.on("close", () => { try{ shell.kill(); }catch{} });
      send("\r\n\x1b[33m[Mode dégradé — node-pty non disponible]\x1b[0m\r\n$ ");
    }
    return;
  }
  let iv;
  async function push() {
    try {
      const [cpu,mem,net,temp,disk] = await Promise.all([si.currentLoad(),si.mem(),si.networkStats(),si.cpuTemperature(),si.fsSize()]);
      ws.send(JSON.stringify({ type:"metrics", cpu:Math.round(cpu.currentLoad), ram:{used:mem.used,total:mem.total,pct:Math.round(mem.used/mem.total*100)}, net:net[0]?{rx:net[0].rx_sec,tx:net[0].tx_sec}:{rx:0,tx:0}, temp:temp.main||0, disks:disk.map(d=>({fs:d.fs,used:d.used,size:d.size,pct:Math.round(d.use)})) }));
    } catch {}
  }
  iv = setInterval(push, 2000); push();
  ws.on("close",()=>clearInterval(iv));
});

// ══════════════════════════════════════════════════════════════════════════════
//  SYSTÈME
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/system", auth, async (req,res) => {
  const [os,cpu,mem,t] = await Promise.all([si.osInfo(),si.cpu(),si.mem(),si.time()]);
  res.json({ os, cpu, mem, uptime:t.uptime, hostname:os.hostname, isLive:isLive() });
});
app.post("/api/system/reboot",   auth, (req,res) => { res.json({ok:true}); setTimeout(()=>exec("systemctl reboot"),1000); });
app.post("/api/system/shutdown", auth, (req,res) => { res.json({ok:true}); setTimeout(()=>exec("systemctl poweroff"),1000); });
app.post("/api/system/change-password", auth, async (req,res) => {
  const { username, password } = req.body;
  try {
    const u = (username||"gravity").replace(/[^a-zA-Z0-9_-]/g,"");
    await execAsync(`echo "${u}:${password}" | chpasswd`);
    fs.writeFileSync(CREDS,`${u}\n${password}`,{mode:0o600});
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  INSTALLATION SUR DISQUE
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/install/disks", auth, async (req,res) => {
  try {
    const { stdout } = await execAsync("lsblk -J -o NAME,SIZE,MODEL,TYPE,MOUNTPOINT 2>/dev/null");
    const disks = (JSON.parse(stdout).blockdevices||[]).filter(d=>d.type==="disk");
    res.json(disks);
  } catch(e) { res.status(500).json({error:e.message}); }
});

// Status d'installation (step, progress, done, error)
let installStatus = { running:false, step:0, stepName:"", progress:0, done:false, error:null };

app.get("/api/install/status", auth, (req,res) => res.json(installStatus));

app.post("/api/install/start", auth, (req,res) => {
  const { disk, hostname, username, password, timezone } = req.body;
  if (!disk||!password) return res.status(400).json({error:"disk et password requis"});
  const safeDisk     = disk.replace(/[^a-zA-Z0-9]/g,"");
  const safeHostname = (hostname||"gravity-nas").replace(/[^a-zA-Z0-9-]/g,"");
  const safeUser     = (username||"gravity").replace(/[^a-zA-Z0-9_-]/g,"");
  const safeTz       = (timezone||"Europe/Paris").replace(/[^a-zA-Z0-9/_-]/g,"");
  try { fs.writeFileSync("/var/log/gravity-install.log",""); } catch {}
  installStatus = { running:true, step:0, stepName:"Demarrage...", progress:0, done:false, error:null };
  res.json({ok:true});
  const env = { ...process.env, TERM:"xterm", DEBIAN_FRONTEND:"noninteractive", LANG:"C" };
  const child = require("child_process").spawn(
    "/usr/local/bin/gravity-install",
    ["--disk", safeDisk, "--hostname", safeHostname, "--user", safeUser, "--password", password, "--tz", safeTz],
    { env, detached:true, stdio:["ignore","pipe","pipe"] }
  );
  const logStream = fs.createWriteStream("/var/log/gravity-install.log");
  child.stdout.on("data", d => {
    logStream.write(d);
    const line = d.toString();
    // Parser les marqueurs de progression
    if (line.includes("STEP:")) {
      const m = line.match(/STEP:(\d+):(\d+):(.*)/);
      if (m) installStatus = { ...installStatus, step:parseInt(m[1]), stepName:m[3].trim(), progress:parseInt(m[2]) };
    }
    if (line.includes("DONE:OK")) installStatus = { ...installStatus, done:true, running:false, progress:100, stepName:"Installation terminee!" };
    if (line.includes("DONE:ERROR")) { const e=line.split("DONE:ERROR:")[1]||"Erreur"; installStatus = { ...installStatus, done:true, running:false, error:e.trim() }; }
  });
  child.stderr.on("data", d => logStream.write(d));
  child.on("close", code => { if(!installStatus.done) installStatus = { ...installStatus, running:false, done:true, error: code!==0?"Code erreur: "+code:null }; logStream.end(); });
  child.unref();
});

app.get("/api/install/logs", auth, (req,res) => {
  try { res.json({log:fs.readFileSync("/var/log/gravity-install.log","utf8")}); }
  catch { res.json({log:""}); }
});

app.post("/api/install/reboot", auth, (req,res) => {
  res.json({ok:true});
  setTimeout(() => exec("systemctl reboot"), 2000);
});

// ══════════════════════════════════════════════════════════════════════════════
//  STOCKAGE
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/disks",  auth, async (req,res) => { const [b,f]=await Promise.all([si.blockDevices(),si.fsSize()]); res.json({devices:b,filesystems:f}); });
app.get("/api/mdstat", auth, async (req,res) => { try{const{stdout}=await execAsync("cat /proc/mdstat");res.json({raw:stdout});}catch{res.json({raw:""}); } });

// ══════════════════════════════════════════════════════════════════════════════
//  SMB — version corrigée (parse natif, nmbd, testparm)
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/smb/shares", auth, (req,res) => {
  try {
    const conf = fs.readFileSync("/etc/samba/smb.conf","utf8");
    const shares = conf.split(/^\[/m).slice(1)
      .filter(s=>!/^(global|homes|printers|print\$)/.test(s))
      .map(s => {
        const name = s.match(/^([^\]]+)\]/)?.[1]?.trim()||"";
        const g = k => s.match(new RegExp(`${k}\\s*=\\s*(.+)`))?.[1]?.trim()||"";
        return { name, path:g("path"), guest_ok:g("guest ok")||"no", read_only:g("read only")||"no", comment:g("comment") };
      }).filter(s=>s.name);
    res.json(shares);
  } catch { res.json([]); }
});
app.post("/api/smb/shares", auth, async (req,res) => {
  const { name, path:p, comment, public:pub, readonly } = req.body;
  const block = `\n[${name}]\n   comment = ${comment||name}\n   path = ${p}\n   browseable = yes\n   read only = ${readonly?"yes":"no"}\n   guest ok = ${pub?"yes":"no"}\n   create mask = 0664\n   directory mask = 0775\n   force group = gravity\n`;
  try {
    fs.mkdirSync(p,{recursive:true});
    fs.appendFileSync("/etc/samba/smb.conf", block);
    await execAsync("systemctl reload smbd 2>/dev/null; systemctl reload nmbd 2>/dev/null").catch(()=>{});
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.delete("/api/smb/shares/:name", auth, async (req,res) => {
  try {
    let conf = fs.readFileSync("/etc/samba/smb.conf","utf8");
    conf = conf.replace(new RegExp(`\\[${req.params.name}\\][^\\[]*`,"g"),"");
    fs.writeFileSync("/etc/samba/smb.conf",conf);
    await execAsync("systemctl reload smbd 2>/dev/null; systemctl reload nmbd 2>/dev/null").catch(()=>{});
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.get("/api/smb/status", auth, async (req,res) => {
  try {
    const [smbd,nmbd] = await Promise.all([
      execAsync("systemctl is-active smbd").catch(()=>({stdout:"inactive"})),
      execAsync("systemctl is-active nmbd").catch(()=>({stdout:"inactive"}))
    ]);
    const ip = (await execAsync("hostname -I 2>/dev/null").catch(()=>({stdout:"?"}))).stdout.trim().split(" ")[0];
    res.json({ smbd:smbd.stdout.trim(), nmbd:nmbd.stdout.trim(), ip, path:`\\\\${ip}\\public` });
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  NFS / FTP / PROXY (inchangé)
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/nfs/exports", auth, (req,res) => { try{const r=fs.readFileSync("/etc/exports","utf8");res.json(r.split("\n").filter(l=>l.trim()&&!l.startsWith("#")).map(l=>{const[p,...o]=l.trim().split(/\s+/);return{path:p,options:o.join(" ")};} ));}catch{res.json([]);} });
app.post("/api/nfs/exports", auth, async (req,res) => { const{path:p,clients,options}=req.body;try{fs.mkdirSync(p,{recursive:true});fs.appendFileSync("/etc/exports",`\n${p}  ${clients||"*"}(${options||"rw,sync,no_subtree_check"})\n`);await execAsync("exportfs -ra");res.json({ok:true});}catch(e){res.status(500).json({error:e.message});} });
app.get("/api/ftp/status", auth, async (req,res) => { try{const{stdout}=await execAsync("systemctl is-active vsftpd");res.json({active:stdout.trim()==="active"});}catch{res.json({active:false});} });
app.post("/api/ftp/toggle", auth, async (req,res) => { try{const{stdout}=await execAsync("systemctl is-active vsftpd");const cmd=stdout.trim()==="active"?"stop":"start";await execAsync(`systemctl ${cmd} vsftpd`);res.json({ok:true,running:cmd==="start"});}catch(e){res.status(500).json({error:e.message});} });

const NSITES = "/etc/nginx/sites-enabled";
app.get("/api/proxy/hosts", auth, (req,res) => { try{const f=fs.readdirSync(NSITES).filter(f=>f!=="default"&&f!=="gravity-fallback");res.json(f.map(f=>{const c=fs.readFileSync(path.join(NSITES,f),"utf8");return{name:f,domain:c.match(/server_name\s+(.+);/)?.[1]?.trim(),upstream:c.match(/proxy_pass\s+http:\/\/(.+);/)?.[1]?.trim(),ssl:c.includes("ssl_certificate")};}));}catch{res.json([]);} });
app.post("/api/proxy/hosts", auth, async (req,res) => { const{domain,upstream,ssl}=req.body;if(!domain||!upstream)return res.status(400).json({error:"domain et upstream requis"});const fn=domain.replace(/[^a-zA-Z0-9.-]/g,"_");const tpl=`server {\n    listen 80;\n    server_name ${domain};\n    location / {\n        proxy_pass http://${upstream};\n        proxy_set_header Host $host;\n        proxy_http_version 1.1;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection "upgrade";\n    }\n}\n`;try{fs.writeFileSync(path.join(NSITES,fn),tpl);await execAsync("nginx -t && systemctl reload nginx");res.json({ok:true});}catch(e){res.status(500).json({error:e.message});} });
app.delete("/api/proxy/hosts/:n", auth, async (req,res) => { try{fs.unlinkSync(path.join(NSITES,req.params.n));await execAsync("systemctl reload nginx");res.json({ok:true});}catch(e){res.status(500).json({error:e.message});} });

// ══════════════════════════════════════════════════════════════════════════════
//  VMs
// ══════════════════════════════════════════════════════════════════════════════
async function virsh(cmd) { const{stdout}=await execAsync(`virsh --connect qemu:///system ${cmd} 2>/dev/null`);return stdout.trim(); }

app.get("/api/vms", auth, async (req,res) => {
  if (isLive()) return res.json({isLive:true,vms:[],message:"KVM indisponible en Live CD — installez GravityOS sur disque"});
  try {
    const raw = await virsh("list --all");
    const vms = raw.split("\n").slice(2).filter(Boolean).map(l=>{const p=l.trim().split(/\s{2,}/);return{id:p[0],name:p[1],state:p[2]};}).filter(v=>v.name);
    const detailed = await Promise.all(vms.map(async vm=>{
      try{const i=await virsh(`dominfo ${vm.name}`);return{...vm,vcpus:(i.match(/CPU\(s\):\s+(\d+)/)||[])[1]||"?",memMB:Math.round(parseInt((i.match(/Max memory:\s+(\d+)/)||[])[1]||0)/1024)};}catch{return vm;}
    }));
    res.json({isLive:false,vms:detailed});
  } catch(e) { res.json({isLive:false,vms:[],error:e.message}); }
});
app.post("/api/vms", auth, async (req,res) => {
  if(isLive()) return res.status(400).json({error:"Impossible en Live CD"});
  const{name,vcpus,memMB,diskGB,iso,network}=req.body;
  if(!name||!vcpus||!memMB) return res.status(400).json({error:"name, vcpus, memMB requis"});
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g,"");
  const dp=`/var/lib/libvirt/images/${safeName}.qcow2`;
  try {
    await execAsync(`mkdir -p /var/lib/libvirt/images && qemu-img create -f qcow2 "${dp}" ${diskGB||20}G`);
    const memKB = parseInt(memMB)*1024;
    const cdrom = iso ? `<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='${iso}'/><target dev='sdb' bus='sata'/><readonly/></disk>` : "";
    const bootDev = iso ? "<boot dev='cdrom'/><boot dev='hd'/>" : "<boot dev='hd'/>";
    // Détecter si KVM est disponible (pas dans VirtualBox)
    let domainType = 'kvm';
    try { await execAsync('test -e /dev/kvm'); } catch { domainType = 'qemu'; }
    // Détecter l'émulateur disponible
    let emulator = '/usr/bin/qemu-system-x86_64';
    try { const {stdout:em} = await execAsync('which qemu-system-x86_64 2>/dev/null || echo /usr/bin/qemu-system-x86_64'); emulator = em.trim(); } catch {}
    const xml = `<domain type='${domainType}'><name>${safeName}</name><memory unit='KiB'>${memKB}</memory><currentMemory unit='KiB'>${memKB}</currentMemory><vcpu>${vcpus}</vcpu><os><type arch='x86_64' machine='pc'>hvm</type>${bootDev}</os><features><acpi/><apic/></features><clock offset='utc'/><on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash><devices><emulator>${emulator}</emulator><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='${dp}'/><target dev='hda' bus='ide'/></disk>${cdrom}<interface type='network'><source network='${network||"default"}'/><model type='e1000'/></interface><graphics type='vnc' port='-1' listen='0.0.0.0'/><video><model type='vga' vram='16384'/></video><console type='pty'><target type='serial'/></console></devices></domain>`;
    const xmlPath = `/tmp/${safeName}-${Date.now()}.xml`;
    require("fs").writeFileSync(xmlPath, xml);
    const {stdout,stderr} = await execAsync(`virsh --connect qemu:///system define "${xmlPath}"`);
    require("fs").unlinkSync(xmlPath);
    res.json({ok:true, disk:dp, message:`VM ${safeName} definie — cliquez ▶ pour demarrer`});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/vms/:n/start",      auth, async (req,res)=>{try{await virsh(`start ${req.params.n}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/stop",       auth, async (req,res)=>{try{await virsh(`shutdown ${req.params.n}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/force-stop", auth, async (req,res)=>{try{await virsh(`destroy ${req.params.n}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/restart",    auth, async (req,res)=>{try{await virsh(`reboot ${req.params.n}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.delete("/api/vms/:n",          auth, async (req,res)=>{try{await virsh(`destroy ${req.params.n}`).catch(()=>{});await virsh(`undefine ${req.params.n} --remove-all-storage`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.get("/api/isos",           auth, (req,res)=>{try{const d="/var/lib/libvirt/images";res.json(fs.readdirSync(d).filter(f=>f.endsWith(".iso")).map(f=>({name:f,path:path.join(d,f),size:fs.statSync(path.join(d,f)).size})));}catch{res.json([]);}});
app.post("/api/isos/download", auth, (req,res)=>{const{url,name}=req.body;const dest=`/var/lib/libvirt/images/${name||path.basename(url)}`;res.json({ok:true,dest});exec(`wget -q "${url}" -O "${dest}"`);});
app.get("/api/usb",            auth, async(req,res)=>{try{const{stdout}=await execAsync("lsusb");res.json(stdout.split("\n").filter(Boolean).map(l=>{const m=l.match(/Bus (\d+) Device (\d+): ID (\S+) (.+)/);return m?{bus:m[1],device:m[2],id:m[3],name:m[4]}:null;}).filter(Boolean));}catch{res.json([]);}});
app.get("/api/networks",       auth, async(req,res)=>{try{const r=await virsh("net-list --all");res.json(r.split("\n").slice(2).filter(Boolean).map(l=>{const p=l.trim().split(/\s{2,}/);return{name:p[0],state:p[1]};}).filter(n=>n.name));}catch{res.json([]);}});

// ══════════════════════════════════════════════════════════════════════════════
//  DOCKER
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/containers", auth, async(req,res)=>{if(!docker)return res.json([]);try{const cs=await docker.listContainers({all:true});res.json(cs.map(c=>({id:c.Id.slice(0,12),name:c.Names[0]?.replace("/",""),image:c.Image,state:c.State,status:c.Status,ports:c.Ports.map(p=>`${p.PublicPort||""}:${p.PrivatePort}`).filter(p=>p!==":").join(", ")})));}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/containers/:id/start", auth, async(req,res)=>{try{await docker.getContainer(req.params.id).start();res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/containers/:id/stop",  auth, async(req,res)=>{try{await docker.getContainer(req.params.id).stop();res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.delete("/api/containers/:id",     auth, async(req,res)=>{try{await docker.getContainer(req.params.id).remove({force:true});res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});

// ══════════════════════════════════════════════════════════════════════════════
//  UTILISATEURS
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/users",  auth, async(req,res)=>{try{const{stdout}=await execAsync("getent passwd | awk -F: '$3>=1000 && $3<65534{print $1\",\"$5\",\"$6}'");res.json(stdout.trim().split("\n").filter(Boolean).map(l=>{const[n,g,h]=l.split(",");return{name:n,fullname:g,home:h};}));}catch{res.json([]);}});
app.post("/api/users", auth, async(req,res)=>{const{username,password,groups}=req.body;try{await execAsync(`useradd -m -s /bin/bash ${username}`);await execAsync(`echo "${username}:${password}" | chpasswd`);if(groups)for(const g of groups)await execAsync(`usermod -aG ${g} ${username}`).catch(()=>{});await execAsync(`(echo "${password}"; echo "${password}") | smbpasswd -a ${username}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});

// ══════════════════════════════════════════════════════════════════════════════
//  MISES À JOUR
// ══════════════════════════════════════════════════════════════════════════════
let updateLog = [];
let updateRunning = false;

function streamUpdate(cmd, res) {
  updateLog = [];
  updateRunning = true;
  res.json({ok:true, message:"Mise à jour lancée"});
  const child = require("child_process").spawn("bash",["-c",cmd],{env:{...process.env,DEBIAN_FRONTEND:"noninteractive",LANG:"C"}});
  child.stdout.on("data",d=>updateLog.push(d.toString()));
  child.stderr.on("data",d=>updateLog.push(d.toString()));
  child.on("close",()=>{ updateRunning=false; updateLog.push("=== DONE ==="); });
}

// Vérifier les mises à jour système disponibles
app.get("/api/updates/system/check", auth, async(req,res) => {
  try {
    await execAsync("apt-get update -qq 2>/dev/null");
    const {stdout} = await execAsync("apt list --upgradable 2>/dev/null | grep -v 'Listing' | wc -l");
    const {stdout:pkgs} = await execAsync("apt list --upgradable 2>/dev/null | grep -v 'Listing' | head -20");
    const count = parseInt(stdout.trim()) || 0;
    res.json({count, packages: pkgs.trim().split("\n").filter(Boolean)});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Lancer la mise à jour système
app.post("/api/updates/system/start", auth, (req,res) => {
  const cmd = "apt-get update -qq && apt-get upgrade -y 2>&1";
  streamUpdate(cmd, res);
});

// Vérifier les mises à jour GravityOS (via git)
app.get("/api/updates/gravity/check", auth, async(req,res) => {
  try {
    const REPO = "https://gitlab.com/syper/gravityos-webui.git";
    const isGit = fs.existsSync("/opt/gravity/.git");
    if(!isGit) return res.json({available:true, message:`Repo non initialisé — cliquez Mettre à jour pour connecter ${REPO}`, count:1, commits:["Premier déploiement depuis git"]});
    await execAsync("git -C /opt/gravity fetch origin 2>/dev/null");
    const {stdout} = await execAsync("git -C /opt/gravity log HEAD..origin/main --oneline 2>/dev/null");
    const commits = stdout.trim().split("\n").filter(Boolean);
    const {stdout:ver} = await execAsync("git -C /opt/gravity log -1 --format='%h — %s — %cr' 2>/dev/null").catch(()=>({stdout:"?"}));
    res.json({available: commits.length>0, commits, count: commits.length, currentVersion: ver.trim()});
  } catch(e){ res.json({available:false, message:"Impossible de vérifier: "+e.message}); }
});

// Mettre à jour GravityOS via git (logique inline, pas besoin de update.sh)
app.post("/api/updates/gravity/start", auth, (req,res) => {
  const REPO = "https://gitlab.com/syper/gravityos-webui.git";
  const cmd = `
    set -e
    echo "=== GravityOS WebUI Update ==="
    echo "Date: $(date)"
    cd /opt/gravity

    if [ ! -d ".git" ]; then
      echo "Initialisation du repo git..."
      git init
      git remote add origin ${REPO}
      git fetch origin
      git checkout -b main --track origin/main
    else
      echo "Mise a jour depuis ${REPO}..."
      git fetch origin
      git pull origin main
    fi

    echo ""
    echo "Mise a jour des dependances npm..."
    npm install --ignore-scripts --omit=optional 2>&1 | tail -5

    echo ""
    echo "Redemarrage du service..."
    systemctl restart gravity-webui

    echo ""
    echo "=== GravityOS mis a jour! ==="
    git log -1 --format='Version: %h - %s' 2>/dev/null || true
  `;
  streamUpdate(cmd, res);
});

// Lire les logs de mise à jour en cours
app.get("/api/updates/log", auth, (req,res) => {
  res.json({log: updateLog.join(""), running: updateRunning});
});;

const PORT = process.env.GRAVITY_PORT || 4000;
server.listen(PORT, "0.0.0.0", () => console.log(`\n  GravityOS WebUI v2 — http://0.0.0.0:${PORT}\n`));
