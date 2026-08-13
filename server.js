#!/usr/bin/env node
// GravityOS WebUI Backend v2
"use strict";
const express  = require("express");
const http     = require("http");
const { WebSocketServer } = require("ws");
const si       = require("systeminformation");
const { exec, execSync, spawn } = require("child_process");
const { promisify } = require("util");
const path     = require("path");
const fs       = require("fs");
const crypto   = require("crypto");
let Dockerode; try { Dockerode = require("dockerode"); } catch {}
let multer; try { multer = require("multer"); } catch {}

const execAsync = promisify(exec);
const app    = express();
const server = http.createServer(app);

// WebSocket server pour les métriques (/)
const wss = new WebSocketServer({ noServer: true });
// WebSocket server pour le terminal (/terminal)
const wssTerminal = new WebSocketServer({ noServer: true });

// Routing des connexions WebSocket selon le path
server.on("upgrade", (req, socket, head) => {
  if (req.url.startsWith("/terminal")) {
    wssTerminal.handleUpgrade(req, socket, head, ws => {
      wssTerminal.emit("connection", ws, req);
    });
  } else {
    wss.handleUpgrade(req, socket, head, ws => {
      wss.emit("connection", ws, req);
    });
  }
});
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
      exec("/usr/local/bin/gravity-configure-terminal", ()=>{}); // terminal connecté auto sur ce compte admin
    }
    if (timezone) await execAsync(`timedatectl set-timezone "${timezone}"`).catch(()=>{});
    fs.writeFileSync(WIZARD, new Date().toISOString());
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// /install et /wizard accessibles SANS auth (avant login)
app.get("/install",     (req,res) => res.sendFile(path.join(__dirname,"web","install.html")));
app.get("/install.html",(req,res) => res.sendFile(path.join(__dirname,"web","install.html")));

// ── Routing principal ─────────────────────────────────────────────────────────
app.get("/", (req,res) => {
  if (!fs.existsSync(WIZARD)) return res.redirect("/wizard.html");
  if (!validSid(getSid(req))) return res.redirect("/login.html");
  res.sendFile(path.join(__dirname,"web","index.html"));
});
app.use((req,res,next) => {
  if (req.path.startsWith("/api/")) return next();
  // Pages publiques
  const pub = ["/login.html","/wizard.html","/install.html","/install","/gravity-logo.png"];
  if (pub.some(p => req.path === p || req.path.startsWith(p+"/") || req.path.startsWith(p+"?"))) return next();
  if (!validSid(getSid(req))) {
    if (!fs.existsSync(WIZARD)) return res.redirect("/wizard.html");
    return res.redirect("/login.html");
  }
  next();
});
app.use(express.static(path.join(__dirname,"web")));

// ── WebSocket Terminal ────────────────────────────────────────────────────────
wssTerminal.on("connection", (ws, req) => {
  // Auth via cookie
  if (!validSid((req.headers.cookie||"").match(/gravity_sid=([a-f0-9]+)/)?.[1])) {
    ws.close(4401, "Unauthorized"); return;
  }
  const send = d => { try{ ws.send(JSON.stringify({type:"output",data:d})); }catch{} };
  let pty = null;
  try { pty = require("node-pty"); } catch {}

  if (pty) {
    const t = pty.spawn("/bin/bash", [], {
      name:"xterm-256color", cols:120, rows:40,
      env:{...process.env, TERM:"xterm-256color", LANG:"fr_FR.UTF-8", HOME:"/root"}
    });
    t.onData(d => send(d));
    ws.on("message", raw => {
      try {
        const m = JSON.parse(raw);
        if (m.type==="input")  t.write(m.data);
        if (m.type==="resize") t.resize(Math.max(2,m.cols), Math.max(2,m.rows));
      } catch { t.write(String(raw)); }
    });
    ws.on("close", () => { try{ t.kill(); }catch{} });
  } else {
    // Fallback sans pty
    const { spawn } = require("child_process");
    const shell = spawn("/bin/bash", ["--login"], {
      env:{...process.env, TERM:"xterm", LANG:"fr_FR.UTF-8", HOME:"/root"},
      stdio:["pipe","pipe","pipe"]
    });
    shell.stdout.on("data", d => send(d.toString()));
    shell.stderr.on("data", d => send(d.toString()));
    shell.on("close", () => send("\r\n[Session terminée]\r\n"));
    ws.on("message", raw => {
      try { const m=JSON.parse(raw); if(m.type==="input") shell.stdin.write(m.data); }
      catch { shell.stdin.write(String(raw)); }
    });
    ws.on("close", () => { try{ shell.kill(); }catch{} });
    send("\r\n\x1b[33m[Mode dégradé — node-pty non disponible]\x1b[0m\r\n");
  }
});

// ── WebSocket Métriques ───────────────────────────────────────────────────────
wss.on("connection", (ws, req) => {
  if (!validSid((req.headers.cookie||"").match(/gravity_sid=([a-f0-9]+)/)?.[1])) {
    ws.close(4401); return;
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
    await execAsync(`id "${u}" &>/dev/null || useradd -m -s /bin/bash -G sudo,libvirt,kvm,docker "${u}"`);
    await execAsync(`echo "${u}:${password}" | chpasswd`);
    fs.writeFileSync(CREDS,`${u}\n${password}`,{mode:0o600});
    // Reconnecte le terminal web sur ce compte (admin, sans re-login)
    exec("/usr/local/bin/gravity-configure-terminal", ()=>{});
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  INSTALLATION SUR DISQUE
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/install/disks", async (req,res) => {
  try {
    const { stdout } = await execAsync("lsblk -J -o NAME,SIZE,MODEL,TYPE,MOUNTPOINT 2>/dev/null");
    const disks = (JSON.parse(stdout).blockdevices||[]).filter(d=>d.type==="disk");
    res.json(disks);
  } catch(e) { res.status(500).json({error:e.message}); }
});

// Status d'installation (step, progress, done, error)
let installStatus = { running:false, step:0, stepName:"", progress:0, done:false, error:null };

app.get("/api/install/status", (req,res) => res.json(installStatus));

app.post("/api/install/start", (req,res) => {
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

app.get("/api/install/logs", (req,res) => {
  try { res.json({log:fs.readFileSync("/var/log/gravity-install.log","utf8")}); }
  catch { res.json({log:""}); }
});

app.post("/api/install/reboot", (req,res) => {
  res.json({ok:true});
  setTimeout(() => exec("systemctl reboot"), 2000);
});

// ══════════════════════════════════════════════════════════════════════════════
//  STOCKAGE — Disques, Volumes (façon ZimaOS : Volume 1 = disque système, disques
//  ajoutés = nouveaux volumes), RAID logiciel (mdadm)
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/disks",  auth, async (req,res) => { const [b,f]=await Promise.all([si.blockDevices(),si.fsSize()]); res.json({devices:b,filesystems:f}); });
app.get("/api/mdstat", auth, async (req,res) => { try{const{stdout}=await execAsync("cat /proc/mdstat");res.json({raw:stdout});}catch{res.json({raw:""}); } });

const VOL_ROOT = "/srv/volumes";
const BROWSE_ROOTS = [VOL_ROOT, "/srv/shares", "/var/lib/libvirt/images"];
function isPathAllowed(p){
  const resolved = path.resolve(p);
  return BROWSE_ROOTS.some(root => resolved===root || resolved.startsWith(root+path.sep));
}

// Navigateur de dossiers (pour le sélecteur de volume dans le wizard Docker) —
// limité aux volumes NAS (/srv/volumes) et au stockage système (/srv/shares),
// ne liste que les dossiers (on choisit un point de montage, pas un fichier)
app.get("/api/storage/browse", auth, (req,res)=>{
  const p = req.query.path || VOL_ROOT;
  if (!isPathAllowed(p)) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    if (!fs.existsSync(p)) return res.status(404).json({error:"Dossier introuvable"});
    const all = fs.readdirSync(p, {withFileTypes:true});
    const entries = all.filter(e=>e.isDirectory()).map(e=>e.name).sort((a,b)=>a.localeCompare(b));
    const parent = BROWSE_ROOTS.includes(path.resolve(p)) ? null : path.dirname(p);
    const out = { path:p, parent, roots:BROWSE_ROOTS, entries };
    // Optionnel : lister aussi les fichiers (utilisé par l'import de disque VM)
    if (req.query.files) {
      out.files = all.filter(e=>e.isFile()).map(e=>e.name).sort((a,b)=>a.localeCompare(b));
    }
    res.json(out);
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/storage/browse/mkdir", auth, (req,res)=>{
  const { path:p, name } = req.body;
  if (!p || !name || !/^[a-zA-Z0-9._ -]+$/.test(name)) return res.status(400).json({error:"Nom de dossier invalide"});
  if (!isPathAllowed(p)) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    const dest = path.join(p, name);
    if (!isPathAllowed(dest)) return res.status(400).json({error:"Chemin non autorisé"});
    fs.mkdirSync(dest, {recursive:true});
    res.json({ok:true, path:dest});
  } catch(e){ res.status(500).json({error:e.message}); }
});

async function lsblkTree(){
  const {stdout} = await execAsync("lsblk -J -b -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,TRAN,PATH 2>/dev/null").catch(()=>({stdout:'{"blockdevices":[]}'}));
  return JSON.parse(stdout).blockdevices || [];
}
function lsblkFlat(tree){ const flat=[]; (function walk(nodes){for(const n of nodes){flat.push(n);if(n.children)walk(n.children);}})(tree); return flat; }

// Disques/partitions "libres" : pas de fs, pas montés, aucune partition-enfant montée,
// pas déjà membre d'un RAID — utilisables pour créer un volume ou un RAID.
app.get("/api/storage/available-disks", auth, async(req,res)=>{
  try {
    const flat = lsblkFlat(await lsblkTree());
    const free = flat.filter(n =>
      (n.type==="disk"||n.type==="part") &&
      !n.mountpoint &&
      n.fstype!=="linux_raid_member" &&
      (!n.children || n.children.every(c=>!c.mountpoint))
    );
    res.json(free.map(d=>({ path:d.path||("/dev/"+d.name), name:d.name, size:Number(d.size)||0, model:(d.model||"").trim(), tran:d.tran||"", type:d.type })));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Volumes ───────────────────────────────────────────────────────────────────
app.get("/api/storage/volumes", auth, async(req,res)=>{
  try {
    fs.mkdirSync(VOL_ROOT,{recursive:true});
    const {stdout:rootSrc} = await execAsync("findmnt -n -o SOURCE /").catch(()=>({stdout:"—"}));
    const {stdout:rootDf}  = await execAsync("df -B1 --output=size,used --no-headers / 2>/dev/null").catch(()=>({stdout:"0 0"}));
    const [rsz,rus] = rootDf.trim().split(/\s+/);
    const volumes = [{ name:"Volume 1 (système)", path:"/srv/shares", device:rootSrc.trim()||"—", size:Number(rsz)||0, used:Number(rus)||0, system:true }];
    for (const name of fs.readdirSync(VOL_ROOT)) {
      const p = path.join(VOL_ROOT, name);
      if (!fs.statSync(p).isDirectory()) continue;
      const {stdout:info} = await execAsync(`df -B1 --output=source,size,used --no-headers ${sh(p)} 2>/dev/null`).catch(()=>({stdout:""}));
      const [device,sz,us] = info.trim().split(/\s+/);
      volumes.push({ name, path:p, device:device||"—", size:Number(sz)||0, used:Number(us)||0, system:false });
    }
    res.json(volumes);
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/storage/volumes", auth, (req,res)=>{
  const { name, device } = req.body;
  if(!name || !/^[a-zA-Z0-9_-]+$/.test(name)) return res.status(400).json({error:"Nom de volume invalide (lettres/chiffres/-/_ uniquement)"});
  if(!device || !/^\/dev\/[a-zA-Z0-9]+$/.test(device)) return res.status(400).json({error:"Périphérique invalide"});
  const mnt = path.join(VOL_ROOT, name);
  const cmd = `
    mkfs.ext4 -F -L ${sh(name.slice(0,16))} ${sh(device)}
    UUID=$(blkid -s UUID -o value ${sh(device)})
    mkdir -p ${sh(mnt)}
    grep -q "$UUID" /etc/fstab || echo "UUID=$UUID  ${mnt}  ext4  defaults,nofail  0  2" >> /etc/fstab
    mount ${sh(mnt)}
    chown gravity:gravity ${sh(mnt)}
    echo "Volume '${name}' prêt sur ${mnt}"
  `;
  const jobId = runJob(cmd);
  res.json({ok:true, jobId});
});
app.delete("/api/storage/volumes/:name", auth, async(req,res)=>{
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,"");
  const mnt = path.join(VOL_ROOT, name);
  try {
    if(!fs.existsSync(mnt)) return res.status(404).json({error:"Volume introuvable"});
    await execAsync(`umount ${sh(mnt)} 2>/dev/null`).catch(()=>{});
    const fstab = fs.readFileSync("/etc/fstab","utf8").split("\n").filter(l=>!l.includes(mnt)).join("\n");
    fs.writeFileSync("/etc/fstab", fstab);
    res.json({ok:true, message:"Volume détaché — les données restent sur le disque (non effacées)"});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── RAID logiciel (mdadm) ────────────────────────────────────────────────────
app.get("/api/storage/raid", auth, async(req,res)=>{
  try {
    const {stdout} = await execAsync("cat /proc/mdstat").catch(()=>({stdout:""}));
    const arrays = [];
    for (const m of stdout.matchAll(/^(md\d+)\s*:\s*(active|inactive)\s*(\S+)?\s*(.*)$/gm)) {
      const [,dev,state,level,members] = m;
      arrays.push({ device:"/dev/"+dev, state, level:level||"?", members:(members.match(/\w+\[\d+\]/g)||[]).map(x=>"/dev/"+x.replace(/\[\d+\]/,"")) });
    }
    res.json(arrays);
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/storage/raid", auth, (req,res)=>{
  const { name, level, devices } = req.body;
  if(!name || !/^[a-zA-Z0-9_-]+$/.test(name)) return res.status(400).json({error:"Nom invalide (lettres/chiffres/-/_ uniquement)"});
  if(!["0","1","5","6","10"].includes(String(level))) return res.status(400).json({error:"Niveau RAID invalide"});
  if(!Array.isArray(devices) || devices.length<2 || devices.some(d=>!/^\/dev\/[a-zA-Z0-9]+$/.test(d))) return res.status(400).json({error:"Au moins 2 disques valides requis"});
  const minDevs = {0:2,1:2,5:3,6:4,10:4}[level];
  if(devices.length<minDevs) return res.status(400).json({error:`RAID${level} nécessite au moins ${minDevs} disques`});
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g,"");
  const cmd = `
    mdadm --create /dev/md/${safeName} --run --level=${level} --raid-devices=${devices.length} ${devices.map(sh).join(" ")} 2>&1
    mkdir -p /etc/mdadm
    mdadm --detail --scan >> /etc/mdadm/mdadm.conf 2>&1 || true
    update-initramfs -u 2>&1 || true
    echo "RAID${level} '${safeName}' créé — synchronisation en arrière-plan (voir /proc/mdstat)"
  `;
  const jobId = runJob(cmd);
  res.json({ok:true, jobId});
});
app.delete("/api/storage/raid/:dev", auth, async(req,res)=>{
  const dev = "/dev/"+req.params.dev.replace(/[^a-zA-Z0-9]/g,"");
  try { await execAsync(`mdadm --stop ${sh(dev)} 2>&1`); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

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

// ── Reverse Proxy — façon Nginx Proxy Manager ────────────────────────────────
// (Domaines multiples, WebSockets, blocage exploits, cache assets, SSL
//  none/Let's Encrypt/custom, force SSL, HTTP/2, HSTS, emplacements
//  personnalisés, config Nginx avancée)
const NSITES = "/etc/nginx/sites-enabled";
const PROXY_META = `${CFG}/proxy-hosts.json`;
function loadProxyMeta(){ try{ return JSON.parse(fs.readFileSync(PROXY_META,"utf8")); } catch{ return {}; } }
function saveProxyMeta(m){ fs.mkdirSync(CFG,{recursive:true}); fs.writeFileSync(PROXY_META, JSON.stringify(m,null,2)); }

function proxyPassBlock(scheme,host,port,indent="        "){
  return `${indent}proxy_pass ${scheme}://${host}:${port};
${indent}proxy_set_header Host $host;
${indent}proxy_set_header X-Real-IP $remote_addr;
${indent}proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
${indent}proxy_set_header X-Forwarded-Proto $scheme;`;
}
function buildProxyConf(h){
  const names = h.domains.join(" ");
  const mainLoc = `    location / {
${proxyPassBlock(h.scheme||"http", h.forwardHost, h.forwardPort)}
${h.websockets ? `        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";\n` : ""}    }`;
  const exploits = h.blockExploits ? `
    location ~ /\\.(?!well-known) { deny all; }
    location ~* "(eval\\(|base64_(en|de)code|globals|encode|\\.\\./)" { deny all; }` : "";
  const cache = h.cacheAssets ? `
    location ~* \\.(jpg|jpeg|png|gif|ico|css|js|svg|woff2?|ttf)$ {
${proxyPassBlock(h.scheme||"http", h.forwardHost, h.forwardPort)}
        expires 7d;
        add_header Cache-Control "public";
    }` : "";
  const customLocs = (h.customLocations||[]).filter(l=>l.path&&l.host&&l.port).map(l=>`
    location ${l.path} {
${proxyPassBlock(l.scheme||"http", l.host, l.port)}
    }`).join("");
  const advanced = h.advanced ? `\n    ${h.advanced.split("\n").join("\n    ")}\n` : "";
  const hstsHdr = h.hsts ? `        add_header Strict-Transport-Security "max-age=63072000${h.hstsSubdomains?"; includeSubDomains":""}" always;\n` : "";

  if (h.sslMode!=="letsencrypt" && h.sslMode!=="custom") {
    return `server {
    listen 80;
    server_name ${names};
${mainLoc}
${exploits}${cache}${customLocs}${advanced}
}
`;
  }
  const certPath = h.sslMode==="custom" ? h.certPath : `/etc/letsencrypt/live/${h.domains[0]}/fullchain.pem`;
  const keyPath  = h.sslMode==="custom" ? h.keyPath  : `/etc/letsencrypt/live/${h.domains[0]}/privkey.pem`;
  const httpBlock = `server {
    listen 80;
    server_name ${names};
    ${h.forceSsl ? `location / { return 301 https://$host$request_uri; }` : mainLoc}
}
`;
  const httpsBlock = `server {
    listen 443 ssl${h.http2?" http2":""};
    server_name ${names};
    ssl_certificate ${certPath};
    ssl_certificate_key ${keyPath};
${hstsHdr}${mainLoc}
${exploits}${cache}${customLocs}${advanced}
}
`;
  return httpBlock + "\n" + httpsBlock;
}

app.get("/api/proxy/hosts", auth, (req,res) => {
  try {
    const meta = loadProxyMeta();
    const files = fs.readdirSync(NSITES).filter(f=>f!=="default"&&f!=="gravity-fallback");
    res.json(files.map(f => ({ name:f, ...( meta[f] || {domains:[f],forwardHost:"?",forwardPort:"",sslMode:"none"} ) })));
  } catch { res.json([]); }
});

app.post("/api/proxy/hosts", auth, async (req,res) => {
  const h = req.body;
  if (!Array.isArray(h.domains) || !h.domains.length || !h.forwardHost || !h.forwardPort)
    return res.status(400).json({error:"Au moins un domaine, un hôte et un port de destination sont requis"});
  const fn = h.domains[0].replace(/[^a-zA-Z0-9.-]/g,"_");
  try {
    if (h.sslMode==="letsencrypt") {
      // 1) vhost HTTP simple d'abord, requis pour la validation ACME (webroot via le / existant)
      fs.writeFileSync(path.join(NSITES,fn), buildProxyConf({...h, sslMode:"none"}));
      await execAsync("nginx -t && systemctl reload nginx");
      const meta = loadProxyMeta(); meta[fn]=h; saveProxyMeta(meta);
      const emailArg = h.letsencryptEmail ? `-m ${sh(h.letsencryptEmail)}` : "--register-unsafely-without-email";
      const domainArgs = h.domains.map(d=>`-d ${sh(d)}`).join(" ");
      const jobId = runJob(`certbot certonly --nginx --non-interactive --agree-tos ${emailArg} ${domainArgs} 2>&1 && echo "=== Certificat obtenu — finalisation... ===" && curl -s -X POST -H 'Content-Type: application/json' -b "gravity_sid=${getSid(req)}" http://127.0.0.1:${process.env.GRAVITY_PORT||4000}/api/proxy/hosts/${fn}/finalize-ssl >/dev/null && echo "=== Hôte HTTPS actif ✓ ==="`);
      return res.json({ok:true, jobId, name:fn});
    }
    fs.writeFileSync(path.join(NSITES,fn), buildProxyConf(h));
    await execAsync("nginx -t && systemctl reload nginx");
    const meta = loadProxyMeta(); meta[fn]=h; saveProxyMeta(meta);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:"Erreur Nginx : "+e.message}); }
});

// Réécrit le vhost avec le bloc HTTPS complet une fois le certificat Let's Encrypt obtenu
app.post("/api/proxy/hosts/:name/finalize-ssl", auth, async (req,res) => {
  try {
    const meta = loadProxyMeta();
    const h = meta[req.params.name];
    if (!h) return res.status(404).json({error:"Hôte introuvable"});
    fs.writeFileSync(path.join(NSITES,req.params.name), buildProxyConf(h));
    await execAsync("nginx -t && systemctl reload nginx");
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:"Erreur Nginx : "+e.message}); }
});

app.delete("/api/proxy/hosts/:n", auth, async (req,res) => {
  try {
    fs.unlinkSync(path.join(NSITES,req.params.n));
    const meta = loadProxyMeta(); delete meta[req.params.n]; saveProxyMeta(meta);
    await execAsync("systemctl reload nginx");
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Certificat custom : cert + clé collés en texte (pas d'upload multipart dans ce projet)
app.post("/api/proxy/custom-cert", auth, (req,res) => {
  const { name, cert, key } = req.body;
  if (!name || !cert || !key) return res.status(400).json({error:"Certificat et clé requis"});
  try {
    const dir = "/etc/nginx/custom-certs";
    fs.mkdirSync(dir,{recursive:true, mode:0o700});
    const safe = name.replace(/[^a-zA-Z0-9_-]/g,"");
    fs.writeFileSync(path.join(dir,safe+".crt"), cert);
    fs.writeFileSync(path.join(dir,safe+".key"), key, {mode:0o600});
    res.json({ok:true, certPath:path.join(dir,safe+".crt"), keyPath:path.join(dir,safe+".key")});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  VMs
// ══════════════════════════════════════════════════════════════════════════════
async function virsh(cmd) {
  try {
    const {stdout} = await execAsync(`virsh --connect qemu:///system ${cmd}`);
    return stdout.trim();
  } catch(e) {
    throw new Error((e.stderr || e.message || '').trim());
  }
}

// Stats CPU/RAM en direct pour une VM en cours d'exécution (2 échantillons
// de cpu.time à 300ms d'écart pour un %CPU instantané, RSS réel via dommemstat)
async function vmLiveStat(name){
  try {
    const [mem, cpu1] = await Promise.all([
      execAsync(`virsh --connect qemu:///system dommemstat ${sh(name)} 2>/dev/null`),
      execAsync(`virsh --connect qemu:///system domstats ${sh(name)} --cpu-total 2>/dev/null`)
    ]);
    const rssKB = parseInt((mem.stdout.match(/rss\s+(\d+)/)||[])[1] || 0);
    const cpuTime1 = parseInt((cpu1.stdout.match(/cpu\.time=(\d+)/)||[])[1] || 0);
    await new Promise(r=>setTimeout(r,300));
    const {stdout:cpu2raw} = await execAsync(`virsh --connect qemu:///system domstats ${sh(name)} --cpu-total 2>/dev/null`);
    const cpuTime2 = parseInt((cpu2raw.match(/cpu\.time=(\d+)/)||[])[1] || 0);
    const cpuPct = Math.max(0, Math.min(999, ((cpuTime2-cpuTime1)/(300*1e6))*100));
    return { memUsedMB: rssKB ? Math.round(rssKB/1024) : null, cpuPct: Math.round(cpuPct*10)/10 };
  } catch { return { memUsedMB:null, cpuPct:null }; }
}

// Démarre tout réseau libvirt référencé par la VM mais actuellement inactif —
// évite l'échec "Requested operation is not valid: network 'default' is not
// active" au clic sur "Démarrer" (le réseau default n'est censé être autostart
// qu'au premier boot, gravity-first-boot.sh, mais peut rester inactif si ce
// script n'a jamais tourné sur ce système, ex. session live/VM de test).
async function ensureVmNetworksActive(name) {
  const xml = await virsh(`dumpxml ${sh(name)}`);
  const nets = [...new Set([...xml.matchAll(/<source network='([^']+)'/g)].map(m => m[1]))];
  for (const net of nets) await virsh(`net-start ${sh(net)}`).catch(() => {});
}

async function detectDomainTypeAndEmulator() {
  let domainType = 'kvm';
  try { await execAsync('test -e /dev/kvm'); } catch { domainType = 'qemu'; }
  let emulator = '/usr/bin/qemu-system-x86_64';
  try { const {stdout:em} = await execAsync('which qemu-system-x86_64 2>/dev/null || echo /usr/bin/qemu-system-x86_64'); emulator = em.trim(); } catch {}
  return {domainType, emulator};
}

// Bloc <os> — BIOS Legacy/SeaBIOS (machine='pc') ou UEFI/OVMF (machine='q35',
// NVRAM par VM copié depuis le template au premier passage en UEFI)
async function buildOsBlock(safeName, bios, bootDev) {
  if (bios !== "uefi") return `<type arch='x86_64' machine='pc'>hvm</type>${bootDev}`;
  const nvramDir = "/var/lib/libvirt/qemu/nvram";
  await execAsync(`mkdir -p ${nvramDir}`).catch(() => {});
  const nvramPath = `${nvramDir}/${safeName}_VARS.fd`;
  await execAsync(`test -f "${nvramPath}" || cp /usr/share/OVMF/OVMF_VARS.fd "${nvramPath}"`);
  return `<type arch='x86_64' machine='q35'>hvm</type><loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.fd</loader><nvram>${nvramPath}</nvram>${bootDev}`;
}

function buildUsbBlock(usbDevices) {
  return (Array.isArray(usbDevices) ? usbDevices : []).filter(d => /^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$/.test(d)).map(d => {
    const [vendor,product] = d.split(":");
    return `<hostdev mode='subsystem' type='usb'><source><vendor id='0x${vendor}'/><product id='0x${product}'/></source></hostdev>`;
  }).join("");
}

function buildDomainXml({name, uuid, domainType, emulator, memKB, vcpus, osBlock, diskFile, cdrom, network, usbBlock}) {
  return `<domain type='${domainType}'><name>${name}</name>${uuid ? `<uuid>${uuid}</uuid>` : ""}<memory unit='KiB'>${memKB}</memory><currentMemory unit='KiB'>${memKB}</currentMemory><vcpu>${vcpus}</vcpu><os>${osBlock}</os><features><acpi/><apic/></features><clock offset='utc'/><on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash><devices><emulator>${emulator}</emulator><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='${diskFile}'/><target dev='hda' bus='ide'/></disk>${cdrom}<interface type='network'><source network='${network||"default"}'/><model type='e1000'/></interface><graphics type='vnc' port='-1' listen='0.0.0.0'/><video><model type='vga' vram='16384'/></video><console type='pty'><target type='serial'/></console>${usbBlock}</devices></domain>`;
}

app.get("/api/vms", auth, async (req,res) => {
  if (isLive()) return res.json({isLive:true,vms:[],message:"KVM indisponible en Live CD — installez GravityOS sur disque"});
  try {
    const raw = await virsh("list --all");
    const vms = raw.split("\n").slice(2).filter(Boolean).map(l=>{const p=l.trim().split(/\s{2,}/);return{id:p[0],name:p[1],state:p[2]};}).filter(v=>v.name);
    const detailed = await Promise.all(vms.map(async vm=>{
      let d = vm;
      try{const i=await virsh(`dominfo ${vm.name}`);d={...vm,vcpus:(i.match(/CPU\(s\):\s+(\d+)/)||[])[1]||"?",memMB:Math.round(parseInt((i.match(/Max memory:\s+(\d+)/)||[])[1]||0)/1024)};}catch{}
      if (vm.state?.includes("running")) {
        const live = await vmLiveStat(vm.name);
        d = { ...d, ...live };
      }
      return d;
    }));
    res.json({isLive:false,vms:detailed});
  } catch(e) { res.json({isLive:false,vms:[],error:e.message}); }
});
app.post("/api/vms", auth, async (req,res) => {
  if(isLive()) return res.status(400).json({error:"Impossible en Live CD"});
  const{name,vcpus,memMB,diskGB,iso,network,bios,usbDevices,importDisk}=req.body;
  if(!name||!vcpus||!memMB) return res.status(400).json({error:"name, vcpus, memMB requis"});
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g,"");
  const dp=`/var/lib/libvirt/images/${safeName}.qcow2`;
  try {
    await execAsync(`mkdir -p /var/lib/libvirt/images`);
    // Disque : soit un nouveau qcow2 vide, soit importé/converti depuis un
    // disque existant (qcow2 réutilisé tel quel, vdi/vmdk/raw convertis via
    // qemu-img — potentiellement long sur un gros disque, donc en job async)
    let diskCmd;
    if (importDisk) {
      if (!isPathAllowed(importDisk) || !fs.existsSync(importDisk)) return res.status(400).json({error:"Disque à importer introuvable ou hors des volumes autorisés"});
      const ext = path.extname(importDisk).toLowerCase().replace(".","");
      const fmtMap = { qcow2:"qcow2", vdi:"vdi", vmdk:"vmdk", img:"raw", raw:"raw" };
      const srcFmt = fmtMap[ext];
      diskCmd = srcFmt === "qcow2"
        ? `cp ${sh(importDisk)} ${sh(dp)}`
        : `qemu-img convert -p ${srcFmt ? "-f "+srcFmt : ""} -O qcow2 ${sh(importDisk)} ${sh(dp)}`;
    } else {
      diskCmd = `qemu-img create -f qcow2 ${sh(dp)} ${diskGB||20}G`;
    }
    const memKB = parseInt(memMB)*1024;
    const cdrom = iso ? `<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='${iso}'/><target dev='sdb' bus='sata'/><readonly/></disk>` : "";
    const bootDev = iso ? "<boot dev='cdrom'/><boot dev='hd'/>" : "<boot dev='hd'/>";
    const {domainType, emulator} = await detectDomainTypeAndEmulator();
    const osBlock = await buildOsBlock(safeName, bios, bootDev);
    // Passthrough USB — usbDevices: ["vendorId:productId", ...] (depuis /api/usb)
    const usbBlock = buildUsbBlock(usbDevices);

    const xml = buildDomainXml({name:safeName, domainType, emulator, memKB, vcpus, osBlock, diskFile:dp, cdrom, network, usbBlock});
    const xmlPath = `/tmp/${safeName}-${Date.now()}.xml`;
    fs.writeFileSync(xmlPath, xml);
    // Le disque (création ou import/conversion) tourne en job asynchrone —
    // une conversion vdi/vmdk→qcow2 peut prendre plusieurs minutes sur un
    // gros disque, pas question de bloquer la requête HTTP dessus
    const jobId = runJob(`${diskCmd} 2>&1 && echo "Disque prêt : ${dp}" && virsh --connect qemu:///system define ${sh(xmlPath)} 2>&1 && rm -f ${sh(xmlPath)} && echo "VM '${safeName}' définie — démarrez-la depuis la liste"`);
    res.json({ok:true, jobId, disk:dp});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/vms/:n/start",      auth, async (req,res)=>{try{await ensureVmNetworksActive(req.params.n).catch(()=>{});await virsh(`start ${req.params.n}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/stop",       auth, async (req,res)=>{try{await virsh(`shutdown ${req.params.n}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/force-stop", auth, async (req,res)=>{try{await virsh(`destroy ${req.params.n}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/restart",    auth, async (req,res)=>{try{await virsh(`reboot ${req.params.n}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.delete("/api/vms/:n",          auth, async (req,res)=>{try{await virsh(`destroy ${req.params.n}`).catch(()=>{});await virsh(`undefine ${req.params.n} --remove-all-storage`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});

// Config actuelle d'une VM (pour préremplir le formulaire d'édition)
app.get("/api/vms/:n", auth, async (req,res) => {
  try {
    const xml = await virsh(`dumpxml ${sh(req.params.n)}`);
    const vcpus = (xml.match(/<vcpu[^>]*>(\d+)</)||[])[1];
    const memKB = (xml.match(/<currentMemory[^>]*>(\d+)</)||[])[1];
    const network = (xml.match(/<source network='([^']+)'/)||[])[1];
    const bios = /machine='q35'/.test(xml) ? 'uefi' : 'legacy';
    const iso = (xml.match(/device='cdrom'[\s\S]*?<source file='([^']+)'/)||[])[1] || "";
    const usbDevices = [...xml.matchAll(/<hostdev[^>]*type='usb'>[\s\S]*?vendor id='0x([0-9a-fA-F]{4})'\/>\s*<product id='0x([0-9a-fA-F]{4})'/g)].map(m=>`${m[1]}:${m[2]}`);
    res.json({ok:true, vcpus:vcpus?parseInt(vcpus):null, memMB:memKB?Math.round(parseInt(memKB)/1024):null, network, bios, iso, usbDevices});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// Édition d'une VM à l'arrêt : vCPU, RAM, réseau, BIOS/UEFI, USB (disque/ISO
// non modifiables ici — trop risqué de changer le stockage à chaud, cf.
// décision OVA hors scope pour la création)
app.put("/api/vms/:n", auth, async (req,res) => {
  if (isLive()) return res.status(400).json({error:"Impossible en Live CD"});
  const name = req.params.n;
  try {
    const state = await virsh(`domstate ${sh(name)}`);
    if (!state.includes("shut off")) return res.status(400).json({error:"Éteignez la VM avant de la modifier"});
    const oldXml = await virsh(`dumpxml ${sh(name)}`);
    const uuid = (oldXml.match(/<uuid>([^<]+)<\/uuid>/)||[])[1];
    const diskFile = (oldXml.match(/device='disk'[\s\S]*?<source file='([^']+)'/)||[])[1];
    if (!diskFile) return res.status(500).json({error:"Disque introuvable dans la config existante"});
    const {vcpus,memMB,network,bios,iso,usbDevices} = req.body;
    if (!vcpus||!memMB) return res.status(400).json({error:"vcpus, memMB requis"});
    const memKB = parseInt(memMB)*1024;
    const cdrom = iso ? `<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='${iso}'/><target dev='sdb' bus='sata'/><readonly/></disk>` : "";
    const bootDev = iso ? "<boot dev='cdrom'/><boot dev='hd'/>" : "<boot dev='hd'/>";
    const {domainType, emulator} = await detectDomainTypeAndEmulator();
    const osBlock = await buildOsBlock(name, bios, bootDev);
    const usbBlock = buildUsbBlock(usbDevices);
    const xml = buildDomainXml({name, uuid, domainType, emulator, memKB, vcpus, osBlock, diskFile, cdrom, network, usbBlock});
    const xmlPath = `/tmp/${name}-edit-${Date.now()}.xml`;
    fs.writeFileSync(xmlPath, xml);
    await virsh(`define ${sh(xmlPath)}`);
    fs.unlinkSync(xmlPath);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── Console VM temps réel (noVNC dans le navigateur, via un pont websockify) ─
// Chaque VM utilise déjà <graphics type='vnc' port='-1'/> (port assigné par
// libvirt) ; websockify fait le pont TCP brut ↔ WebSocket pour que le canvas
// noVNC (servi en statique depuis le paquet Debian, pas de CDN) puisse s'y
// connecter. Un seul pont par VM, réutilisé s'il tourne déjà.
const vncBridges = new Map(); // nom de VM -> { wsPort, proc }
app.get("/api/vms/:n/console", auth, async (req,res) => {
  const name = req.params.n;
  try {
    const state = (await virsh(`domstate ${sh(name)}`)).trim();
    if (state !== "running") return res.status(400).json({error:"La VM doit être démarrée pour ouvrir la console"});
    const existing = vncBridges.get(name);
    if (existing) return res.json({ok:true, wsPort:existing.wsPort});

    const display = (await virsh(`vncdisplay ${sh(name)}`)).trim(); // ex: "127.0.0.1:0" ou ":0"
    const dispNum = parseInt(display.split(":").pop(), 10);
    if (isNaN(dispNum)) return res.status(500).json({error:"Port VNC introuvable pour cette VM"});
    const vncPort = 5900 + dispNum;
    const wsPort = 6900 + (vncBridges.size % 100); // pool 6900-6999, réutilisé si une VM est arrêtée entre-temps

    const proc = spawn("websockify", [String(wsPort), `127.0.0.1:${vncPort}`], { stdio: "ignore" });
    proc.on("exit", () => vncBridges.delete(name));
    vncBridges.set(name, { wsPort, proc });
    res.json({ok:true, wsPort});
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Sert les fichiers statiques noVNC (canvas VNC en JS pur, installés localement
// par le paquet Debian "novnc" — pas de dépendance CDN)
if (fs.existsSync("/usr/share/novnc")) app.use("/novnc", express.static("/usr/share/novnc"));
app.get("/api/isos", auth, (req,res)=>{try{const d="/var/lib/libvirt/images";fs.mkdirSync(d,{recursive:true});res.json(fs.readdirSync(d).filter(f=>f.endsWith(".iso")).map(f=>({name:f,path:path.join(d,f),size:fs.statSync(path.join(d,f)).size})));}catch{res.json([]);}});
// Envoi direct depuis l'ordinateur de l'utilisateur (ISO ou disque qcow2/vdi/vmdk)
// — atterrit dans /var/lib/libvirt/images, visible à la fois dans la liste
// ISOs et dans le sélecteur "importer un disque" de la création de VM
if (multer) {
  fs.mkdirSync("/var/lib/libvirt/images", {recursive:true});
  const upload = multer({
    storage: multer.diskStorage({
      destination: (req,file,cb)=>cb(null, "/var/lib/libvirt/images"),
      filename: (req,file,cb)=>cb(null, file.originalname.replace(/[^a-zA-Z0-9._-]/g,"_"))
    }),
    limits: { fileSize: 20 * 1024 * 1024 * 1024 } // 20 Go max (ISO/disques peuvent être volumineux)
  });
  app.post("/api/vms/upload", auth, upload.single("file"), (req,res)=>{
    if (!req.file) return res.status(400).json({error:"Aucun fichier reçu"});
    res.json({ok:true, name:req.file.filename, path:req.file.path, size:req.file.size});
  });
} else {
  app.post("/api/vms/upload", auth, (req,res)=> res.status(500).json({error:"Module d'upload indisponible — relancez 'Mettre à jour' pour l'installer"}) );
}
app.post("/api/isos/download", auth, (req,res)=>{
  const { url, name } = req.body;
  if (!url || !/^https?:\/\//.test(url)) return res.status(400).json({error:"URL invalide (http/https requis)"});
  const fname = (name || path.basename(new URL(url).pathname) || `image-${Date.now()}.iso`).replace(/[^a-zA-Z0-9._-]/g,"_");
  const dest = `/var/lib/libvirt/images/${fname}`;
  const jobId = runJob(`mkdir -p /var/lib/libvirt/images && wget --progress=dot:giga ${sh(url)} -O ${sh(dest)} 2>&1`);
  res.json({ok:true, jobId, dest});
});
app.delete("/api/isos/:name", auth, (req,res)=>{
  try {
    const f = path.join("/var/lib/libvirt/images", req.params.name.replace(/[^a-zA-Z0-9._-]/g,""));
    if (!f.endsWith(".iso") || !fs.existsSync(f)) return res.status(404).json({error:"ISO introuvable"});
    fs.unlinkSync(f);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.get("/api/usb",            auth, async(req,res)=>{try{const{stdout}=await execAsync("lsusb");res.json(stdout.split("\n").filter(Boolean).map(l=>{const m=l.match(/Bus (\d+) Device (\d+): ID (\S+) (.+)/);return m?{bus:m[1],device:m[2],id:m[3],name:m[4]}:null;}).filter(Boolean));}catch{res.json([]);}});
app.get("/api/networks",       auth, async(req,res)=>{try{const r=await virsh("net-list --all");res.json(r.split("\n").slice(2).filter(Boolean).map(l=>{const p=l.trim().split(/\s{2,}/);return{name:p[0],state:p[1]};}).filter(n=>n.name));}catch{res.json([]);}});

// ── Jobs asynchrones génériques (pull d'image, compose, volumes, RAID, backup)
//    même principe que streamUpdate mais plusieurs jobs concurrents, par id ────
const jobs = new Map();
function runJob(cmd) {
  const jobId = crypto.randomBytes(8).toString("hex");
  // Toujours une première ligne immédiate : sans ça la boîte de log reste
  // vide tant que la commande n'a rien écrit (ex: pull d'une grosse image
  // qui met du temps avant le premier octet), donnant l'impression que rien
  // ne se passe.
  const job = { log: ["$ "+cmd.trim().split("\n")[0]+"\n"], running: true };
  jobs.set(jobId, job);
  const child = spawn("bash", ["-c", cmd], { env:{...process.env, DEBIAN_FRONTEND:"noninteractive", LANG:"C"} });
  child.stdout.on("data", d=>job.log.push(d.toString()));
  child.stderr.on("data", d=>job.log.push(d.toString()));
  child.on("close", code=>{ job.running=false; job.log.push(`\n=== ${code===0?"Terminé ✓":"Erreur (code "+code+")"} ===`); });
  return jobId;
}
app.get("/api/jobs/:id", auth, (req,res)=>{
  const job = jobs.get(req.params.id);
  if(!job) return res.status(404).json({error:"Job introuvable"});
  res.json({log: job.log.join(""), running: job.running});
});
function sh(v){ return `'${String(v).replace(/'/g,"'\\''")}'`; }

// ══════════════════════════════════════════════════════════════════════════════
//  DOCKER
// ══════════════════════════════════════════════════════════════════════════════

// ── docker compose (v2 "docker compose" si dispo, sinon "docker-compose" v1) ──
let COMPOSE_CMD = null;
function composeCmd() {
  if (COMPOSE_CMD) return COMPOSE_CMD;
  try { execSync("docker compose version", {stdio:"ignore"}); COMPOSE_CMD = "docker compose"; }
  catch { COMPOSE_CMD = "docker-compose"; }
  return COMPOSE_CMD;
}
const COMPOSE_DIR = "/srv/docker/compose";

// ── Conteneurs ──────────────────────────────────────────────────────────────
app.get("/api/containers", auth, async(req,res)=>{
  if(!docker) return res.json([]);
  try {
    const cs = await docker.listContainers({all:true});
    // Stats CPU/RAM en un seul appel `docker stats` (bien plus rapide que
    // d'interroger chaque conteneur individuellement via l'API Docker)
    let statsById = {};
    if (cs.some(c=>c.State==="running")) {
      try {
        const {stdout} = await execAsync(`docker stats --no-stream --format "{{.ID}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}" 2>/dev/null`);
        for (const line of stdout.trim().split("\n").filter(Boolean)) {
          const [id,cpu,mem,memPct] = line.split("|");
          statsById[id] = { cpu, mem, memPct };
        }
      } catch {}
    }
    res.json(cs.map(c=>{
      const shortId = c.Id.slice(0,12);
      const st = Object.entries(statsById).find(([k])=>shortId.startsWith(k))?.[1];
      return {
        id: shortId,
        name: c.Names[0]?.replace("/",""),
        image: c.Image,
        state: c.State,
        status: c.Status,
        ports: c.Ports.map(p=>`${p.PublicPort||""}:${p.PrivatePort}`).filter(p=>p!==":").join(", "),
        cpu: st?.cpu || null,
        mem: st?.mem || null,
        memPct: st?.memPct || null
      };
    }));
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/containers/:id/start",   auth, async(req,res)=>{try{await docker.getContainer(req.params.id).start();res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/containers/:id/stop",    auth, async(req,res)=>{try{await docker.getContainer(req.params.id).stop();res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/containers/:id/restart", auth, async(req,res)=>{try{await docker.getContainer(req.params.id).restart();res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.delete("/api/containers/:id",       auth, async(req,res)=>{try{await docker.getContainer(req.params.id).remove({force:true});res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.get("/api/containers/:id/logs", auth, async(req,res)=>{
  try { const {stdout} = await execAsync(`docker logs --tail 300 ${sh(req.params.id)} 2>&1`); res.type("text/plain").send(stdout); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// Créer un conteneur (wizard) — image + nom + ports + volumes + env + politique de redémarrage
// Vérifie si un port hôte est déjà occupé (autre conteneur, ou tout autre
// service du NAS) — utilisé par le wizard pour surligner en rouge en direct
app.get("/api/docker/port-check", auth, async(req,res)=>{
  const port = parseInt(req.query.port,10);
  if(!port || port<1 || port>65535) return res.status(400).json({error:"Port invalide"});
  try {
    const {stdout} = await execAsync(`ss -tuln 2>/dev/null | awk '{print $5}' | grep -E ":${port}$" | head -1`);
    res.json({available: !stdout.trim(), port});
  } catch { res.json({available:true, port}); } // en cas d'erreur, ne pas bloquer l'utilisateur
});

app.post("/api/docker/containers/create", auth, (req,res)=>{
  const { image, name, ports, volumes, env, restartPolicy, network, command } = req.body;
  if(!image || !/^[a-zA-Z0-9._\-\/:]+$/.test(image)) return res.status(400).json({error:"Image invalide"});
  try {
    const args = ["run","-d"];
    if(name) args.push("--name", sh(name.replace(/[^a-zA-Z0-9_.-]/g,"")));
    args.push("--restart", sh(["always","unless-stopped","on-failure","no"].includes(restartPolicy)?restartPolicy:"unless-stopped"));
    if(network) args.push("--network", sh(network.replace(/[^a-zA-Z0-9_.-]/g,"")));
    for(const p of (ports||[])) if(p.host && p.container) args.push("-p", sh(`${p.host}:${p.container}${p.proto==="udp"?"/udp":""}`));
    for(const v of (volumes||[])) if(v.host && v.container) args.push("-v", sh(`${v.host}:${v.container}${v.ro?":ro":""}`));
    for(const e of (env||[])) if(e.key) args.push("-e", sh(`${e.key}=${e.value||""}`));
    args.push(sh(image));
    if(command && command.trim()) args.push(command.trim());
    const jobId = runJob(`docker ${args.join(" ")} 2>&1`);
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Ports exposés déclarés par une image (Dockerfile EXPOSE) — pour préremplir
// le wizard de création de conteneur avec des suggestions de ports pertinentes
app.get("/api/docker/images/ports", auth, async(req,res)=>{
  const ref = req.query.ref;
  if(!ref || !/^[a-zA-Z0-9._\-\/:]+$/.test(ref)) return res.status(400).json({error:"Image invalide"});
  try {
    const {stdout} = await execAsync(`docker image inspect ${sh(ref)} --format '{{json .Config.ExposedPorts}}' 2>/dev/null`);
    const exposed = JSON.parse(stdout.trim()||"{}") || {};
    // clés du type "80/tcp" → {port:"80", proto:"tcp"}
    const ports = Object.keys(exposed).map(k=>{ const [port,proto]=k.split("/"); return {port, proto:proto||"tcp"}; });
    res.json(ports);
  } catch(e){ res.json([]); } // image pas encore locale (pas tirée) — pas une erreur bloquante
});

// ── Images ────────────────────────────────────────────────────────────────
app.get("/api/docker/images", auth, async(req,res)=>{
  if(!docker) return res.json([]);
  try {
    const imgs = await docker.listImages();
    res.json(imgs.map(i=>{
      const tag = i.RepoTags?.[0] || "<none>:<none>";
      const sep = tag.lastIndexOf(":");
      return { id:i.Id.replace("sha256:","").slice(0,12), repo:tag.slice(0,sep), tag:tag.slice(sep+1), size:i.Size, created:i.Created };
    }));
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/docker/images/pull", auth, (req,res)=>{
  const { image } = req.body;
  if(!image || !/^[a-zA-Z0-9._\-\/:]+$/.test(image)) return res.status(400).json({error:"Nom d'image invalide"});
  const jobId = runJob(`docker pull ${sh(image)} 2>&1`);
  res.json({ok:true, jobId});
});
app.delete("/api/docker/images/:id", auth, async(req,res)=>{
  try { await docker.getImage(req.params.id).remove({force:true}); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// ── Registre (Docker Hub) ────────────────────────────────────────────────────
app.get("/api/docker/search", auth, async(req,res)=>{
  const q = (req.query.q||"").trim();
  if(!q) return res.json([]);
  try {
    const r = await fetch(`https://hub.docker.com/v2/search/repositories/?query=${encodeURIComponent(q)}&page_size=20`);
    const d = await r.json();
    res.json((d.results||[]).map(x=>({ name:x.repo_name, description:x.short_description, stars:x.star_count, official:x.is_official, automated:x.is_automated })));
  } catch(e){ res.status(500).json({error:"Recherche impossible (pas d'accès internet ?) — "+e.message}); }
});

// ── Docker Compose (stacks) ──────────────────────────────────────────────────
app.get("/api/docker/compose", auth, (req,res)=>{
  try {
    fs.mkdirSync(COMPOSE_DIR,{recursive:true});
    res.json(fs.readdirSync(COMPOSE_DIR).filter(d=>fs.existsSync(path.join(COMPOSE_DIR,d,"docker-compose.yml"))));
  } catch(e){ res.json([]); }
});
app.get("/api/docker/compose/:name", auth, (req,res)=>{
  try {
    const f = path.join(COMPOSE_DIR, req.params.name.replace(/[^a-zA-Z0-9_-]/g,""), "docker-compose.yml");
    res.type("text/plain").send(fs.readFileSync(f,"utf8"));
  } catch(e){ res.status(404).json({error:"Stack introuvable"}); }
});
app.post("/api/docker/compose", auth, (req,res)=>{
  const { name, content } = req.body;
  if(!name || !/^[a-zA-Z0-9_-]+$/.test(name)) return res.status(400).json({error:"Nom de stack invalide (lettres/chiffres/-/_ uniquement)"});
  if(!content || !content.trim()) return res.status(400).json({error:"Contenu docker-compose.yml requis"});
  try {
    const dir = path.join(COMPOSE_DIR, name);
    fs.mkdirSync(dir,{recursive:true});
    fs.writeFileSync(path.join(dir,"docker-compose.yml"), content);
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} up -d 2>&1`);
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/docker/compose/:name/up", auth, (req,res)=>{
  try {
    const dir = path.join(COMPOSE_DIR, req.params.name.replace(/[^a-zA-Z0-9_-]/g,""));
    if(!fs.existsSync(path.join(dir,"docker-compose.yml"))) return res.status(404).json({error:"Stack introuvable"});
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} up -d 2>&1`);
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/docker/compose/:name/down", auth, (req,res)=>{
  try {
    const dir = path.join(COMPOSE_DIR, req.params.name.replace(/[^a-zA-Z0-9_-]/g,""));
    if(!fs.existsSync(path.join(dir,"docker-compose.yml"))) return res.status(404).json({error:"Stack introuvable"});
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} down 2>&1`);
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  BACKUP — local / USB / distant (FTP, SMB) — config NAS, Docker, VMs, Volumes
// ══════════════════════════════════════════════════════════════════════════════
const BACKUP_REMOTES = `${CFG}/backup-remotes.json`;
function loadRemotes(){ try{ return JSON.parse(fs.readFileSync(BACKUP_REMOTES,"utf8")); } catch{ return []; } }
function saveRemotes(r){ fs.mkdirSync(CFG,{recursive:true}); fs.writeFileSync(BACKUP_REMOTES, JSON.stringify(r,null,2)); }

// Destinations "remote" enregistrées (FTP/SMB) — le mot de passe n'est jamais renvoyé au client
app.get("/api/backup/remotes", auth, (req,res)=> res.json(loadRemotes().map(({password,...r})=>r)) );
app.post("/api/backup/remotes", auth, (req,res)=>{
  const { name, type, host, port, path:rp, user, password } = req.body;
  if(!name || !["ftp","smb"].includes(type) || !host) return res.status(400).json({error:"Champs requis manquants (nom, type, hôte)"});
  const remotes = loadRemotes();
  remotes.push({ id:crypto.randomBytes(6).toString("hex"), name, type, host, port:port||(type==="ftp"?21:445), path:rp||"/", user:user||"", password:password||"" });
  saveRemotes(remotes);
  res.json({ok:true});
});
app.delete("/api/backup/remotes/:id", auth, (req,res)=>{ saveRemotes(loadRemotes().filter(r=>r.id!==req.params.id)); res.json({ok:true}); });

// Destinations "locales" utilisables : volumes NAS + clés USB montées
app.get("/api/backup/local-targets", auth, async(req,res)=>{
  try {
    const targets = [];
    fs.mkdirSync(VOL_ROOT,{recursive:true});
    for (const name of fs.readdirSync(VOL_ROOT)) targets.push({ label:"Volume : "+name, path:path.join(VOL_ROOT,name) });
    const flat = lsblkFlat(await lsblkTree());
    for (const d of flat.filter(x=>x.tran==="usb" && x.mountpoint)) targets.push({ label:"Clé USB : "+d.mountpoint, path:d.mountpoint });
    res.json(targets);
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Lance une sauvegarde : scope = tableau parmi ["config","docker","vms","volumes"]
app.post("/api/backup/run", auth, async(req,res)=>{
  const { scope, volumes, destType, destPath, remoteId } = req.body;
  const sc = Array.isArray(scope) ? scope : [];
  if(!sc.length) return res.status(400).json({error:"Sélectionnez au moins un élément à sauvegarder"});
  try {
    const stamp = new Date().toISOString().replace(/[:.]/g,"-");
    const archiveName = `gravityos-backup-${stamp}.tar.gz`;
    const tmpFile = `/tmp/${archiveName}`;
    const paths = [];
    if (sc.includes("config")) for (const p of ["/etc/gravity","/etc/samba/smb.conf","/etc/exports"]) if (fs.existsSync(p)) paths.push(p);
    if (sc.includes("docker") && fs.existsSync(COMPOSE_DIR)) paths.push(COMPOSE_DIR);
    let pre = "";
    if (sc.includes("vms")) {
      pre += `mkdir -p /tmp/gravity-vm-defs && for vm in $(virsh --connect qemu:///system list --all --name 2>/dev/null); do virsh --connect qemu:///system dumpxml "$vm" > "/tmp/gravity-vm-defs/$vm.xml" 2>/dev/null; done\n`;
      paths.push("/tmp/gravity-vm-defs");
    }
    if (sc.includes("volumes") && Array.isArray(volumes)) {
      for (const v of volumes) { const p = path.join(VOL_ROOT, String(v).replace(/[^a-zA-Z0-9_-]/g,"")); if (fs.existsSync(p)) paths.push(p); }
    }
    if (!paths.length) return res.status(400).json({error:"Rien à sauvegarder pour cette sélection"});

    let sendCmd;
    if (destType==="local" || destType==="usb") {
      if (!destPath) return res.status(400).json({error:"Destination requise"});
      sendCmd = `mkdir -p ${sh(destPath)} && cp ${sh(tmpFile)} ${sh(path.join(destPath,archiveName))}`;
    } else if (destType==="ftp" || destType==="smb") {
      const r = loadRemotes().find(x=>x.id===remoteId);
      if (!r) return res.status(400).json({error:"Destination distante introuvable"});
      const rpath = r.path.endsWith("/") ? r.path : r.path+"/";
      sendCmd = r.type==="ftp"
        ? `curl -sS -T ${sh(tmpFile)} ${sh(`ftp://${r.host}:${r.port}${rpath}${archiveName}`)} --user ${sh(r.user+":"+r.password)}`
        : `smbclient ${sh("//"+r.host+"/"+r.path)} -U ${sh(r.user+"%"+r.password)} -c ${sh("put "+tmpFile+" "+archiveName)}`;
    } else return res.status(400).json({error:"Type de destination invalide"});

    const cmd = `${pre}tar -czf ${sh(tmpFile)} ${paths.map(sh).join(" ")} 2>&1
echo "Archive créée : $(du -h ${sh(tmpFile)} | cut -f1)"
${sendCmd} 2>&1
rm -f ${sh(tmpFile)}
echo "=== Sauvegarde envoyée avec succès ==="`;
    const jobId = runJob(cmd);
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Liste les archives de sauvegarde (*.tar.gz) trouvées sur les volumes/clés USB
app.get("/api/backup/archives", auth, async(req,res)=>{
  try {
    const targets = [];
    fs.mkdirSync(VOL_ROOT,{recursive:true});
    for (const name of fs.readdirSync(VOL_ROOT)) targets.push(path.join(VOL_ROOT,name));
    const flat = lsblkFlat(await lsblkTree());
    for (const d of flat.filter(x=>x.tran==="usb" && x.mountpoint)) targets.push(d.mountpoint);
    const archives = [];
    for (const dir of targets) {
      try { for (const f of fs.readdirSync(dir)) if (f.endsWith(".tar.gz") && f.startsWith("gravityos-backup-")) archives.push(path.join(dir,f)); } catch {}
    }
    res.json(archives);
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Importer une configuration NAS depuis une archive de sauvegarde déjà présente
// sur un volume/clé USB (pas d'upload navigateur — cohérent avec le reste de
// l'appli qui pilote tout via des chemins locaux, pas de multipart/form-data)
app.post("/api/settings/import-config", auth, (req,res)=>{
  const { archivePath } = req.body;
  if(!archivePath || !fs.existsSync(archivePath)) return res.status(400).json({error:"Archive introuvable à ce chemin"});
  const cmd = `
    tar -tzf ${sh(archivePath)} etc/gravity >/dev/null 2>&1 || { echo "Cette archive ne contient pas de configuration NAS (créez une sauvegarde avec 'Config NAS' cochée)"; exit 1; }
    tar -xzf ${sh(archivePath)} -C / etc/gravity etc/samba/smb.conf etc/exports 2>&1
    exportfs -ra 2>&1 || true
    systemctl reload smbd nmbd 2>&1 || true
    echo "=== Configuration importée — redémarrage de la WebUI dans 3s ==="
    (sleep 3 && systemctl restart gravity-webui) &
    disown
  `;
  const jobId = runJob(cmd);
  res.json({ok:true, jobId});
});

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
    const REPO = "https://github.com/sy-per/gravityos-webui.git";
    const isGit = fs.existsSync("/opt/gravity/.git");
    if(!isGit) return res.json({available:true, message:"Repo non initialisé — cliquez Mettre à jour", count:1, commits:["Premier déploiement depuis git"]});
    // Fix ownership
    await execAsync("git config --global --add safe.directory /opt/gravity 2>/dev/null").catch(()=>{});
    await execAsync("git -C /opt/gravity fetch origin main 2>/dev/null");
    // Branche fixe "main" (cohérent avec /api/updates/gravity/start qui fait
    // désormais un reset --hard sur origin/main, pas de détection de branche)
    const {stdout} = await execAsync(`git -C /opt/gravity log HEAD..origin/main --oneline 2>/dev/null`).catch(()=>({stdout:""}));
    const commits = stdout.trim().split("\n").filter(Boolean);
    const {stdout:ver} = await execAsync("git -C /opt/gravity log -1 --format='%h — %s — %cr' 2>/dev/null").catch(()=>({stdout:"inconnu"}));
    res.json({available: commits.length>0, commits, count: commits.length, currentVersion: ver.trim()});
  } catch(e){ res.json({available:false, message:"Erreur: "+e.message}); }
});

// Mettre à jour GravityOS via git
app.post("/api/updates/gravity/start", auth, (req,res) => {
  const REPO = "https://github.com/sy-per/gravityos-webui.git";
  const cmd = `
    echo "=== GravityOS WebUI Update ==="
    echo "Date: $(date)"

    # Fix ownership pour git
    git config --global --add safe.directory /opt/gravity

    cd /opt/gravity

    if [ ! -d ".git" ]; then
      echo "Clonage initial..."
      cd /tmp
      git clone ${REPO} gravity-webui-tmp
      cp -r gravity-webui-tmp/. /opt/gravity/
      rm -rf gravity-webui-tmp
      cd /opt/gravity
      git config --global --add safe.directory /opt/gravity
    else
      echo "Mise a jour..."
      git config --global --add safe.directory /opt/gravity
      # /opt/gravity n'a jamais de commits locaux légitimes (c'est un
      # déploiement, pas un dépôt de dev) : fetch + reset --hard converge
      # TOUJOURS vers origin/main, peu importe l'état local (HEAD détaché,
      # branche locale bizarre, modifications non commitées...). L'ancienne
      # méthode (détection de branche via "git remote show origin" + "git
      # pull") pouvait échouer silencieusement (script sans "set -e") et
      # laisser le dépôt bloqué indéfiniment derrière origin, avec "Vérifier"
      # signalant sans cesse les mêmes commits disponibles après coup.
      if ! git fetch origin main 2>&1; then
        echo "ERREUR: impossible de contacter GitHub (fetch échoué)"
      elif ! git reset --hard origin/main 2>&1; then
        echo "ERREUR: git reset --hard a échoué"
      else
        echo "Dépôt synchronisé sur origin/main : $(git log -1 --format='%h %s')"
      fi
    fi

    echo ""
    echo "=== Correctifs système ==="
    # "Mettre à jour" ne fait que du git pull sur le code WebUI — ça ne livre
    # jamais les correctifs au niveau OS (paquets, pare-feu, config système)
    # qui, eux, ne sont normalement appliqués qu'au build d'une nouvelle ISO.
    # Un NAS déjà installé qui ne fait que cliquer "Mettre à jour" ne les
    # recevait donc jamais. Chaque correctif OS ajouté ici doit être
    # idempotent (sûr à relancer à chaque mise à jour, même déjà appliqué).

    # AppArmor requis par Docker (kernel Debian l'a activé, mais le paquet
    # fournissant apparmor_parser n'était pas installé avant le 2026-08-11)
    if ! command -v apparmor_parser &>/dev/null; then
      echo "Installation d'AppArmor (requis par Docker)..."
      apt-get update -qq 2>&1 | tail -2
      apt-get install -y apparmor 2>&1 | tail -3
      systemctl restart docker 2>/dev/null || true
      echo "AppArmor installé ✓"
    fi

    # smbclient requis pour les sauvegardes SMB distantes (absent avant le 2026-08-09)
    if ! command -v smbclient &>/dev/null; then
      echo "Installation de smbclient (requis pour les sauvegardes SMB distantes)..."
      apt-get install -y smbclient 2>&1 | tail -3
    fi

    # Ports UDP de découverte réseau (NetBIOS + WS-Discovery) — ufw n'ouvrait
    # que du TCP avant le 2026-08-11, rendant le NAS invisible dans "Réseau"
    # Windows malgré une connexion directe fonctionnelle
    ufw allow 137/udp  2>/dev/null || true
    ufw allow 138/udp  2>/dev/null || true
    ufw allow 3702/udp 2>/dev/null || true
    ufw allow 5357/tcp 2>/dev/null || true

    # Thème terminal shellinabox (blanc sur noir + couleurs, sinon texte
    # illisible sur certaines installs faites avant le fix)
    if [ -d /etc/shellinabox/options-available ]; then
      rm -f /etc/shellinabox/options-enabled/*.css
      ln -sf "../options-available/00_White On Black.css" "/etc/shellinabox/options-enabled/00_White On Black.css"
      ln -sf "../options-available/01+Color Terminal.css" "/etc/shellinabox/options-enabled/01+Color Terminal.css"
    fi

    # /usr/local/bin/gravity-configure-terminal n'existe pas sur les NAS
    # installés avant le 2026-08-11 (script livré uniquement par l'ISO, pas
    # par le dépôt git de la WebUI) — on le (ré)écrit ici pour que le
    # mécanisme "Mettre à jour" le livre aussi
    cat > /usr/local/bin/gravity-configure-terminal <<'TERMCFG'
#!/usr/bin/env bash
set -uo pipefail
CREDS="/etc/gravity/credentials"
USER_NAME=$(head -1 "$CREDS" 2>/dev/null)
[[ -z "$USER_NAME" ]] && USER_NAME="gravity"
if ! id "$USER_NAME" &>/dev/null; then
  useradd -m -s /bin/bash "$USER_NAME" 2>/dev/null || true
fi
usermod -aG sudo "$USER_NAME" 2>/dev/null || true
USER_UID=$(id -u "$USER_NAME" 2>/dev/null || echo 0)
USER_GID=$(id -g "$USER_NAME" 2>/dev/null || echo 0)
USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6)
[[ -z "$USER_HOME" ]] && USER_HOME="/root"
sed -i "s#^SHELLINABOX_ARGS=.*#SHELLINABOX_ARGS=\"--no-beep --disable-ssl -s /:$USER_UID:$USER_GID:$USER_HOME:/bin/bash\"#" /etc/default/shellinabox 2>/dev/null || true
systemctl restart shellinabox 2>/dev/null || true
TERMCFG
    chmod +x /usr/local/bin/gravity-configure-terminal
    /usr/local/bin/gravity-configure-terminal && echo "Terminal connecté auto sur le compte admin ✓"

    # noVNC + websockify requis pour la console VM temps réel (absents avant le 2026-08-13)
    if ! command -v websockify &>/dev/null || [ ! -d /usr/share/novnc ]; then
      echo "Installation de noVNC + websockify (console VM temps réel)..."
      apt-get update -qq 2>&1 | tail -2
      apt-get install -y novnc websockify 2>&1 | tail -3
    fi
    ufw allow 6900:6999/tcp 2>/dev/null || true

    echo "Correctifs système appliqués ✓"

    echo ""
    echo "Dependances npm..."
    npm install --ignore-scripts --omit=optional 2>&1 | tail -3

    echo "Installation node-pty (terminal)..."
    if [ ! -d node_modules/node-pty ]; then
      apt-get install -y --no-install-recommends build-essential python3 2>/dev/null | tail -2 || true
      npm install node-pty 2>&1 | tail -3 && echo "node-pty OK" || echo "node-pty en mode degrade"
    else
      echo "node-pty deja installe"
    fi

    echo ""
    systemctl restart gravity-webui 2>/dev/null || true

    echo ""
    echo "=== GravityOS mis a jour! ==="
    git log -1 --format='Version: %h - %s (%cr)' 2>/dev/null || true
  `;
  streamUpdate(cmd, res);
});

// Lire les logs de mise à jour en cours
app.get("/api/updates/log", auth, (req,res) => {
  res.json({log: updateLog.join(""), running: updateRunning});
});;

// Route de diagnostic terminal
app.get("/api/terminal/test", auth, (req,res) => {
  let pty = null; try { pty = require("node-pty"); } catch(e) {}
  res.json({ nodeVersion:process.version, ptyAvailable:!!pty, pid:process.pid });
});

const PORT = process.env.GRAVITY_PORT || 4000;
server.listen(PORT, "0.0.0.0", () => console.log(`\n  GravityOS WebUI v2 — http://0.0.0.0:${PORT}\n`));
