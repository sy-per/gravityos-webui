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

// Filet de sécurité — sans ça, Node (≥15) termine TOUT le process sur la
// moindre rejection de promesse jamais attrapée (ex: un callback "fire and
// forget" passé à runJob() qui échoue après coup, comme la création du
// raccourci après une installation Magasin). Un service NAS de fond ne doit
// jamais tomber pour une erreur async isolée — bug réel découvert : une
// installation Frigate réussie mais sans raccourci créé, corrélée à des
// arrêts intempestifs du backend observés pendant cette session de tests.
// On journalise et on continue, jamais process.exit().
process.on("unhandledRejection", (reason) => {
  console.error("Rejection non gérée (le service continue) :", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Exception non gérée (le service continue) :", err);
});

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
app.get("/api/auth/status",  (req,res) => res.json({ authenticated: validSid(getSid(req)), wizardDone: fs.existsSync(WIZARD), isLive: isLive() }));
// Rôle effectif de la session WebUI en cours — l'authentification reste un
// identifiant unique partagé (getCreds().user), donc "l'utilisateur connecté"
// est toujours ce même compte ; on résout son rôle réel (intégré ou
// personnalisé) pour que le bureau puisse masquer les applications non
// accordées (voir userRoleId()/loadRoles() plus bas dans ce fichier).
app.get("/api/auth/me", auth, async(req,res) => {
  try {
    const username = getCreds().user;
    const roleId = await userRoleId(username);
    const role = loadRoles().find(r=>r.id===roleId) || BUILTIN_ROLES[0];
    res.json({ username, roleId, isAdmin: !!role.isAdmin, apps: role.apps, volumes: role.volumes });
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Wizard (pas besoin d'auth — c'est la 1ère config) ─────────────────────────
app.post("/api/wizard/complete", async (req,res) => {
  const { hostname, username, password, timezone } = req.body;
  try {
    if (hostname) await execAsync(`hostnamectl set-hostname "${hostname.replace(/[^a-zA-Z0-9-]/g,"")}"` ).catch(()=>{});
    if (username && password) {
      const u = username.replace(/[^a-zA-Z0-9_-]/g,"");
      await ensureSharedGroup();
      await execAsync(`id ${sh(u)} 2>/dev/null || useradd -m -s /bin/bash -G sudo,libvirt,kvm,docker,${SHARED_GROUP} ${sh(u)}`).catch(()=>{});
      await execAsync(`echo ${sh(`${u}:${password}`)} | chpasswd`);
      await execAsync(`echo ${sh(`root:${password}`)} | chpasswd`);
      fs.mkdirSync(CFG,{recursive:true});
      fs.writeFileSync(CREDS,`${u}\n${password}`,{mode:0o600});
      await execAsync(`(echo ${sh(password)}; echo ${sh(password)}) | smbpasswd -a ${sh(u)} -s 2>/dev/null`).catch(()=>{});
      exec("/usr/local/bin/gravity-configure-terminal", ()=>{}); // terminal connecté auto sur ce compte admin
    }
    if (timezone) await execAsync(`timedatectl set-timezone "${timezone}"`).catch(()=>{});
    fs.writeFileSync(WIZARD, new Date().toISOString());
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// /install reste une page HTML à part (installeur disque du Live CD, en
// dehors du périmètre de la SPA Gravity2 — accessible sans auth, avant même
// le wizard, comme avant)
app.get("/install",     (req,res) => res.sendFile(path.join(__dirname,"web","install.html")));
app.get("/install.html",(req,res) => res.sendFile(path.join(__dirname,"web","install.html")));

// ── Routing principal ─────────────────────────────────────────────────────────
// Le frontend (Gravity2, SPA React) gère lui-même l'affichage wizard/login/
// desktop selon la réponse de GET /api/auth/status — plus de redirection
// serveur ni de pages HTML séparées pour /login.html ou /wizard.html.
app.use(express.static(path.join(__dirname,"web")));
// Fichiers statiques noVNC (canvas VNC en JS pur, installés localement par le
// paquet Debian "novnc" — pas de dépendance CDN), utilisés pour ouvrir la
// console d'une VM en plein écran dans un nouvel onglet (vnc.html) en plus
// du canvas intégré à l'app. DOIT être enregistré avant le catch-all SPA
// ci-dessous : Express matche les routes dans l'ordre d'enregistrement, et
// le catch-all interceptait déjà /novnc/vnc.html avant qu'il n'atteigne
// jamais ce middleware — /novnc n'était donc jamais réellement joignable
// malgré son existence, bug découvert en testant l'ouverture réelle de
// vnc.html dans le navigateur (retombait sur index.html au lieu du fichier).
if (fs.existsSync("/usr/share/novnc")) app.use("/novnc", express.static("/usr/share/novnc"));
// Toute route non-API qui ne correspond à aucun fichier statique retombe sur
// la SPA (utile si on ajoute un jour du routing côté client, ex. /files).
app.get(/^(?!\/api\/).*/, (req,res) => res.sendFile(path.join(__dirname,"web","index.html")));

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
      // cwd explicite requis : sans lui, node-pty hérite du cwd du process
      // Node (le dossier de lancement du serveur, ex. ~/gravityos-next-backend)
      // au lieu du dossier par défaut du shell — HOME seul ne suffit pas.
      cwd:"/root",
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
      cwd:"/root",
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
      // mem.used = total - free, ce qui compte le cache disque (pages
      // Samba/NFS/Docker mises en cache par le noyau) comme "utilisé" alors
      // que Linux le libère instantanément dès qu'un process en a besoin —
      // un NAS qui sert des fichiers affiche donc presque toujours un
      // mem.used proche de 100% même à vide, sans aucune pression mémoire
      // réelle (signalé par un utilisateur réel : widget à 98% avec 8 Go
      // alors qu'aucun processus ne consommait plus de 121 Mo). mem.available
      // (libre + cache récupérable) est la métrique correcte, celle utilisée
      // par "free -h" (colonne "disponible") et htop.
      const ramUsed = mem.total - mem.available;
      ws.send(JSON.stringify({ type:"metrics", cpu:Math.round(cpu.currentLoad), ram:{used:ramUsed,total:mem.total,pct:Math.round(ramUsed/mem.total*100)}, net:net[0]?{rx:net[0].rx_sec,tx:net[0].tx_sec}:{rx:0,tx:0}, temp:temp.main||0, disks:disk.map(d=>({fs:d.fs,used:d.used,size:d.size,pct:Math.round(d.use)})) }));
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
// Processus triés par RAM — pour que l'utilisateur puisse voir concrètement
// ce qui consomme la mémoire du NAS (demande explicite suite à un système
// qui sature en RAM sans rien installé), plutôt qu'un simple pourcentage
// global sans détail exploitable.
app.get("/api/system/top-processes", auth, async (req,res) => {
  try {
    const { list } = await si.processes();
    const top = list
      .slice()
      .sort((a,b) => b.mem - a.mem)
      .slice(0, 15)
      .map(p => ({ pid: p.pid, name: p.name, cpu: Math.round((p.cpu||0)*10)/10, memPct: Math.round((p.mem||0)*10)/10, memMB: Math.round((p.memRss||0)/1024) }));
    res.json(top);
  } catch(e) { res.status(500).json({error:e.message}); }
});
// Interface réseau active (nom + IPv4) — utilisé par l'onglet "Informations
// générales" des Paramètres, distinct des réseaux libvirt (/api/networks)
app.get("/api/system/network", auth, async (req,res) => {
  try {
    const ifaces = await si.networkInterfaces();
    const list = Array.isArray(ifaces) ? ifaces : [ifaces];
    const iface = list.find(i => i.ip4 && !i.internal && i.operstate==="up") || list.find(i => i.ip4 && !i.internal) || null;
    res.json({ iface: iface?.iface || "—", ip4: iface?.ip4 || "—" });
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.post("/api/system/reboot",   auth, (req,res) => { res.json({ok:true}); setTimeout(()=>exec("systemctl reboot"),1000); });
app.post("/api/system/shutdown", auth, (req,res) => { res.json({ok:true}); setTimeout(()=>exec("systemctl poweroff"),1000); });
app.post("/api/system/change-password", auth, async (req,res) => {
  const { username, password } = req.body;
  try {
    const u = (username||"gravity").replace(/[^a-zA-Z0-9_-]/g,"");
    await ensureSharedGroup();
    await execAsync(`id "${u}" &>/dev/null || useradd -m -s /bin/bash -G sudo,libvirt,kvm,docker,${SHARED_GROUP} "${u}"`);
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
const SYSTEM_VOLUME_DIR = "volume1";
const SHARED_GROUP = "gravity-share";
const BROWSE_ROOTS = [VOL_ROOT, "/srv/shares", "/var/lib/libvirt/images"];
// "Volume 1 (système)" — dossier partagé entre tous les utilisateurs NAS
// (Documents/Images/ISO/Téléchargements), sur le disque système, au même
// endroit que les volumes ajoutés (VOL_ROOT) plutôt que dans le dossier
// personnel d'un seul utilisateur (qui n'était pas partagé entre comptes).
function volume1Path(){ return path.join(VOL_ROOT, SYSTEM_VOLUME_DIR); }
function isoDir(){ return path.join(volume1Path(), "ISO"); }
// Groupe partagé donnant accès en lecture/écriture à Volume 1 à tous les
// comptes NAS — créé une fois (idempotent), chaque utilisateur y est ajouté
// à sa création (voir /api/users et /api/wizard/complete).
async function ensureSharedGroup(){
  await execAsync(`groupadd -f ${sh(SHARED_GROUP)}`).catch(()=>{});
}
function isPathAllowed(p){
  const resolved = path.resolve(p);
  // VOL_ROOT couvre déjà volume1Path() (sous-dossier de VOL_ROOT)
  return BROWSE_ROOTS.some(root => resolved===root || resolved.startsWith(root+path.sep));
}
// Restriction dédiée à l'app Fichiers : uniquement les volumes NAS (Volume 1
// partagé + volumes créés + partage système) — jamais /var/lib/libvirt/images
// ni le reste du système, contrairement à isPathAllowed() (plus large, pour
// les sélecteurs de fichiers VM/Docker). Le vrai dossier personnel Linux de
// chaque utilisateur n'est volontairement plus accessible ici : les fichiers
// doivent vivre dans Volume 1 (partagé) pour être visibles par tous les
// comptes, pas isolés dans le /home d'un seul utilisateur.
async function filesPathAllowed(p){
  const resolved = path.resolve(p);
  // Volumes NAS + périphériques externes montés (clé USB, disque USB...) +
  // partage système — mêmes racines que les sélecteurs de fichiers
  // (browseRoots()), pour que l'app Fichiers puisse naviguer dans les
  // périphériques externes comme dans un dossier normal.
  const roots = [...(await browseRoots()), "/srv/shares"];
  return roots.some(root => resolved===root || resolved.startsWith(root+path.sep));
}

// Racines autorisées pour tous les boutons "Parcourir" du NAS (sélecteur ISO/
// disque VM, destination et dossiers de sauvegarde, etc.) — alignées sur la
// même restriction que l'app Fichiers : uniquement les volumes (Volume 1
// partagé + volumes créés), et les périphériques connectés (clés USB
// montées). Jamais /srv/shares ni /var/lib/libvirt/images : ces boutons ne
// servent qu'à choisir un emplacement dans l'espace utilisateur, pas à
// explorer le système.
async function browseRoots(){
  const roots = [VOL_ROOT];
  try {
    const flat = lsblkFlat(await lsblkTree());
    for (const d of flat) if (d.tran==="usb" && d.mountpoint && !roots.includes(d.mountpoint)) roots.push(d.mountpoint);
  } catch {}
  return roots;
}
function pathUnderRoots(p, roots){
  const resolved = path.resolve(p);
  return roots.some(root => resolved===root || resolved.startsWith(root+path.sep));
}

// Navigateur de dossiers (ISO/disque VM, destination et contenu de sauvegarde,
// volume Docker...) — ne liste que les dossiers (on choisit un emplacement,
// pas un fichier, sauf si ?files=1)
app.get("/api/storage/browse", auth, async(req,res)=>{
  const roots = await browseRoots();
  // Par défaut, ouvre sur la liste des volumes (VOL_ROOT) plutôt que de
  // plonger directement dans Volume 1 — l'utilisateur doit pouvoir choisir
  // parmi tous les volumes, pas seulement le système.
  const p = req.query.path || VOL_ROOT;
  if (!pathUnderRoots(p, roots)) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    if (!fs.existsSync(p)) return res.status(404).json({error:"Dossier introuvable"});
    const all = fs.readdirSync(p, {withFileTypes:true});
    const entries = all.filter(e=>e.isDirectory()).map(e=>e.name).sort((a,b)=>a.localeCompare(b));
    const parent = roots.includes(path.resolve(p)) ? null : path.dirname(p);
    const out = { path:p, parent, roots, entries };
    // Optionnel : lister aussi les fichiers (utilisé par l'import de disque VM)
    if (req.query.files) {
      out.files = all.filter(e=>e.isFile()).map(e=>e.name).sort((a,b)=>a.localeCompare(b));
    }
    res.json(out);
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/storage/browse/mkdir", auth, async(req,res)=>{
  const { path:p, name } = req.body;
  if (!p || !name || !/^[a-zA-Z0-9._ -]+$/.test(name)) return res.status(400).json({error:"Nom de dossier invalide"});
  const roots = await browseRoots();
  if (!pathUnderRoots(p, roots)) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    const dest = path.join(p, name);
    if (!pathUnderRoots(dest, roots)) return res.status(400).json({error:"Chemin non autorisé"});
    fs.mkdirSync(dest, {recursive:true});
    res.json({ok:true, path:dest});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  FICHIERS — explorateur (raccourcis, listing réel, favoris)
// ══════════════════════════════════════════════════════════════════════════════
function fileKind(name, isDir){
  if (isDir) return "Dossier";
  const ext = path.extname(name).slice(1).toLowerCase();
  const KIND_MAP = {
    pdf:"PDF", doc:"Word", docx:"Word", odt:"Texte",
    xls:"Excel", xlsx:"Excel", ods:"Tableur",
    ppt:"PowerPoint", pptx:"PowerPoint",
    jpg:"Image", jpeg:"Image", png:"Image", gif:"Image", webp:"Image", svg:"Image", bmp:"Image",
    mp3:"Audio", wav:"Audio", flac:"Audio", ogg:"Audio",
    mp4:"Vidéo", mkv:"Vidéo", avi:"Vidéo", mov:"Vidéo", webm:"Vidéo",
    zip:"Archive", tar:"Archive", gz:"Archive", "7z":"Archive", rar:"Archive",
    txt:"Texte", md:"Texte",
    iso:"Image disque", qcow2:"Disque virtuel", vdi:"Disque virtuel", vmdk:"Disque virtuel",
  };
  return KIND_MAP[ext] || (ext ? ext.toUpperCase() : "Fichier");
}

// Raccourcis façon ZimaOS : Accueil (Volume 1, partagé entre tous les
// utilisateurs NAS — plus le dossier personnel Linux d'un seul utilisateur),
// Images/Documents/Téléchargements/ISO créés dedans s'ils n'existent pas
// encore. ISO est un vrai sous-dossier de Volume 1 (~/ISO n'existe plus ici),
// c'est aussi ce dossier que pointent le sélecteur d'ISO et l'envoi d'ISO du
// wizard VM (voir isoDir() et le multer de /api/vms/upload plus bas)
app.get("/api/files/shortcuts", auth, async (req,res)=>{
  try {
    const home = volume1Path();
    const dirs = {
      home,
      images: path.join(home,"Images"),
      documents: path.join(home,"Documents"),
      downloads: path.join(home,"Téléchargements"),
      iso: isoDir(),
      // Dossier listant tous les volumes (Volume 1 + volumes créés) — point
      // de départ des sélecteurs de fichiers/dossiers (import de disque VM,
      // destination de sauvegarde...) plutôt que de plonger directement
      // dans Volume 1
      volumesRoot: VOL_ROOT,
    };
    for (const d of Object.values(dirs)) fs.mkdirSync(d,{recursive:true, mode:0o2775});
    // Partagé entre tous les comptes NAS (groupe gravity-share + setgid, tout
    // nouveau fichier/dossier hérite du groupe) plutôt que réservé à un
    // utilisateur — ne refait le chgrp/chmod récursif que si nécessaire (pas
    // à chaque ouverture de l'app Fichiers)
    const { stdout: currentGroup } = await execAsync(`stat -c %G ${sh(home)}`).catch(()=>({stdout:""}));
    if (currentGroup.trim() !== SHARED_GROUP) {
      await ensureSharedGroup();
      await execAsync(`chgrp -R ${sh(SHARED_GROUP)} ${sh(home)} && chmod -R 2775 ${sh(home)}`).catch(()=>{});
    }
    res.json(dirs);
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Listing réel d'un dossier (nom, type, taille, date de modification, type
// de fichier) — utilisé par la vue principale de l'app Fichiers. Restreint à
// filesPathAllowed (volumes uniquement) : l'app Fichiers ne doit pas pouvoir
// naviguer ailleurs sur le système, contrairement aux sélecteurs VM/Docker.
app.get("/api/files/list", auth, async (req,res)=>{
  const p = req.query.path || volume1Path();
  if (!(await filesPathAllowed(p))) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    if (!fs.existsSync(p)) return res.status(404).json({error:"Dossier introuvable"});
    if (!fs.statSync(p).isDirectory()) return res.status(400).json({error:"Ce n'est pas un dossier"});
    const entries = fs.readdirSync(p)
      .filter(n=>!n.startsWith("."))
      .map(n=>{
        try {
          const full = path.join(p,n);
          const s = fs.statSync(full);
          return {
            name:n, type: s.isDirectory()?"folder":"file",
            size: s.isDirectory()?null:s.size,
            modified: s.mtime.toISOString(),
            kind: fileKind(n, s.isDirectory()),
          };
        } catch { return null; }
      })
      .filter(Boolean)
      .sort((a,b)=> a.type===b.type ? a.name.localeCompare(b.name) : (a.type==="folder"?-1:1));
    res.json({ path:p, entries });
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Périphériques externes montés (clé USB, disque dur USB...) — section
// "Périphériques externes" de l'app Fichiers, sous "Disques". Un
// périphérique n'apparaît que s'il est réellement monté (mountpoint via
// lsblk) ; navigable ensuite comme un dossier normal via /api/files/list
// (filesPathAllowed autorise déjà ces points de montage via browseRoots()).
app.get("/api/files/external", auth, async(req,res)=>{
  try {
    const flat = lsblkFlat(await lsblkTree());
    const devices = [];
    for (const d of flat) {
      if (d.tran!=="usb" || !d.mountpoint) continue;
      const { stdout } = await execAsync(`df -B1 --output=size,used ${sh(d.mountpoint)} 2>/dev/null | tail -n1`).catch(()=>({stdout:"0 0"}));
      const [sz,us] = stdout.trim().split(/\s+/);
      devices.push({
        name: d.model?.trim() || d.name,
        path: d.mountpoint,
        size: Number(sz)||Number(d.size)||0,
        used: Number(us)||0,
      });
    }
    res.json(devices);
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Raccourcis épinglés (dossiers "favoris" de l'app Fichiers) — partagés (un
// seul compte WebUI pour l'instant, pas de notion multi-utilisateur),
// persistés pour survivre à un redémarrage. Pré-remplis au premier accès
// avec les dossiers par défaut de Volume 1 (Images/Documents/ISO/
// Téléchargements) ; "Accueil" n'en fait pas partie — permanent, non
// désépinglable, géré côté frontend (vue Volumes).
const FILES_PINNED = `${CFG}/files-pinned.json`;
function loadPinned(){
  try { return JSON.parse(fs.readFileSync(FILES_PINNED,"utf8")); }
  catch {
    const home = volume1Path();
    const defaults = [
      { path: path.join(home,"Images"), name:"Images" },
      { path: path.join(home,"Documents"), name:"Documents" },
      { path: path.join(home,"Téléchargements"), name:"Téléchargements" },
      { path: isoDir(), name:"ISO" },
    ];
    savePinned(defaults);
    return defaults;
  }
}
function savePinned(list){ fs.mkdirSync(CFG,{recursive:true}); fs.writeFileSync(FILES_PINNED, JSON.stringify(list,null,2)); }

app.get("/api/files/pinned", auth, (req,res)=> res.json(loadPinned()));
app.post("/api/files/pinned", auth, async (req,res)=>{
  const { path:p } = req.body;
  if (!p || !(await filesPathAllowed(p))) return res.status(400).json({error:"Chemin non autorisé"});
  const list = loadPinned();
  if (!list.some(f=>f.path===p)) { list.push({ path:p, name: path.basename(p) || p }); savePinned(list); }
  res.json({ok:true});
});
app.delete("/api/files/pinned", auth, (req,res)=>{
  const p = req.query.path;
  savePinned(loadPinned().filter(f=>f.path!==p));
  res.json({ok:true});
});

// ── Opérations sur fichiers (créer, renommer, supprimer, déplacer, copier) ──
// Toutes restreintes à filesPathAllowed — jamais en dehors de home/volumes
app.post("/api/files/mkdir", auth, async (req,res)=>{
  const { path:p, name } = req.body;
  if (!name || !/^[^/\\]+$/.test(name) || name==="." || name==="..") return res.status(400).json({error:"Nom de dossier invalide"});
  if (!(await filesPathAllowed(p))) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    const dest = path.join(p, name);
    if (!(await filesPathAllowed(dest))) return res.status(400).json({error:"Chemin non autorisé"});
    if (fs.existsSync(dest)) return res.status(400).json({error:"Un élément du même nom existe déjà"});
    fs.mkdirSync(dest, {recursive:true});
    res.json({ok:true, path:dest});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/files/rename", auth, async (req,res)=>{
  const { path:p, name } = req.body;
  if (!name || !/^[^/\\]+$/.test(name) || name==="." || name==="..") return res.status(400).json({error:"Nom invalide"});
  if (!(await filesPathAllowed(p))) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    if (!fs.existsSync(p)) return res.status(404).json({error:"Élément introuvable"});
    const dest = path.join(path.dirname(p), name);
    if (!(await filesPathAllowed(dest))) return res.status(400).json({error:"Chemin non autorisé"});
    if (fs.existsSync(dest)) return res.status(400).json({error:"Un élément du même nom existe déjà"});
    fs.renameSync(p, dest);
    res.json({ok:true, path:dest});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.delete("/api/files/item", auth, async (req,res)=>{
  const p = req.query.path;
  if (!(await filesPathAllowed(p))) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    if (!fs.existsSync(p)) return res.status(404).json({error:"Élément introuvable"});
    fs.rmSync(p, { recursive:true, force:true });
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/files/move", auth, async (req,res)=>{
  const { from, toDir } = req.body;
  if (!(await filesPathAllowed(from)) || !(await filesPathAllowed(toDir))) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    if (!fs.existsSync(from)) return res.status(404).json({error:"Élément introuvable"});
    const dest = path.join(toDir, path.basename(from));
    if (!(await filesPathAllowed(dest))) return res.status(400).json({error:"Chemin non autorisé"});
    if (path.resolve(dest)===path.resolve(from)) return res.status(400).json({error:"Destination identique à la source"});
    if (fs.existsSync(dest)) return res.status(400).json({error:"Un élément du même nom existe déjà dans le dossier de destination"});
    // "from" et "toDir" peuvent être sur des volumes/disques différents —
    // renameSync échoue alors avec EXDEV, il faut copier puis effacer la source
    try { fs.renameSync(from, dest); }
    catch(e){ if(e.code==="EXDEV"){ fs.cpSync(from, dest, {recursive:true}); fs.rmSync(from, {recursive:true, force:true}); } else throw e; }
    res.json({ok:true, path:dest});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/files/copy", auth, async (req,res)=>{
  const { from, toDir } = req.body;
  if (!(await filesPathAllowed(from)) || !(await filesPathAllowed(toDir))) return res.status(400).json({error:"Chemin non autorisé"});
  try {
    if (!fs.existsSync(from)) return res.status(404).json({error:"Élément introuvable"});
    const base = path.basename(from);
    const ext = path.extname(base);
    const stem = ext ? base.slice(0, -ext.length) : base;
    let dest = path.join(toDir, base);
    let n = 1;
    while (fs.existsSync(dest)) { dest = path.join(toDir, `${stem} (copie${n>1?" "+n:""})${ext}`); n++; }
    if (!(await filesPathAllowed(dest))) return res.status(400).json({error:"Chemin non autorisé"});
    fs.cpSync(from, dest, { recursive:true });
    res.json({ok:true, path:dest});
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Upload dans l'app Fichiers : destination = n'importe quel dossier autorisé
// (contrairement à /api/vms/upload dont la destination est fixe). On upload
// d'abord dans un dossier temporaire puis on déplace, pour ne pas dépendre de
// l'ordre d'arrivée des champs du formulaire multipart.
if (multer) {
  const uploadTmpDir = "/tmp/gravity-files-upload";
  fs.mkdirSync(uploadTmpDir, {recursive:true});
  const uploadToTmp = multer({ dest: uploadTmpDir, limits: { fileSize: 20 * 1024 * 1024 * 1024 } });
  app.post("/api/files/upload", auth, uploadToTmp.single("file"), async (req,res)=>{
    if (!req.file) return res.status(400).json({error:"Aucun fichier reçu"});
    const dir = req.body.dir;
    if (!dir || !(await filesPathAllowed(dir))) { fs.unlink(req.file.path, ()=>{}); return res.status(400).json({error:"Dossier non autorisé"}); }
    try {
      fs.mkdirSync(dir, {recursive:true});
      const safeName = req.file.originalname.replace(/[^a-zA-Z0-9._ -]/g,"_");
      const dest = path.join(dir, safeName);
      // /tmp peut être un montage différent (tmpfs) de la destination (volume
      // NAS) — renameSync échoue alors avec EXDEV, il faut copier puis effacer
      try { fs.renameSync(req.file.path, dest); }
      catch(e){ if(e.code==="EXDEV"){ fs.copyFileSync(req.file.path, dest); fs.unlinkSync(req.file.path); } else throw e; }
      res.json({ok:true, name:path.basename(dest), path:dest, size:req.file.size});
    } catch(e){ res.status(500).json({error:e.message}); }
  });
} else {
  app.post("/api/files/upload", auth, (req,res)=> res.status(500).json({error:"Module d'upload indisponible — relancez 'Mettre à jour' pour l'installer"}) );
}

async function lsblkTree(){
  const {stdout} = await execAsync("lsblk -J -b -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,TRAN,PATH,SERIAL 2>/dev/null").catch(()=>({stdout:'{"blockdevices":[]}'}));
  return JSON.parse(stdout).blockdevices || [];
}
function lsblkFlat(tree){ const flat=[]; (function walk(nodes){for(const n of nodes){flat.push(n);if(n.children)walk(n.children);}})(tree); return flat; }

// Disques/partitions "libres" : pas de fs, pas montés, aucune partition-enfant montée,
// pas déjà membre d'un RAID — utilisables pour créer un volume ou un RAID.
app.get("/api/storage/available-disks", auth, async(req,res)=>{
  try {
    const flat = lsblkFlat(await lsblkTree());
    const free = flat.filter(n =>
      (n.type==="disk"||n.type==="part"||/^raid/.test(n.type||"")) &&
      !n.mountpoint &&
      n.fstype!=="linux_raid_member" &&
      (!n.children || n.children.every(c=>!c.mountpoint))
    );
    res.json(free.map(d=>({ path:d.path||("/dev/"+d.name), name:d.name, size:Number(d.size)||0, model:(d.model||"").trim() || (/^raid/.test(d.type||"") ? `RAID${d.type.replace("raid","")}` : ""), tran:d.tran||"", type:d.type })));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// État S.M.A.R.T. réel d'un disque via smartmontools (déjà inclus dans le
// paquet de l'ISO GravityOS). Pas de simulation : si smartctl est absent ou
// que le disque ne supporte pas SMART (courant sur les disques virtuels de
// certains hyperviseurs), on renvoie explicitement "indisponible" plutôt que
// d'inventer un statut.
let smartctlAvailable = null; // mis en cache après la 1ère vérification
async function hasSmartctl(){
  if (smartctlAvailable === null) {
    smartctlAvailable = await execAsync("command -v smartctl").then(()=>true).catch(()=>false);
  }
  return smartctlAvailable;
}
async function getSmartStatus(devicePath){
  if (!(await hasSmartctl())) return { available:false, healthy:null, reason:"smartctl non installé" };
  let stdout;
  try { ({stdout} = await execAsync(`smartctl -H -j ${sh(devicePath)} 2>&1`)); }
  catch(e){ stdout = e.stdout || ""; }
  try {
    const data = JSON.parse(stdout);
    if (data.smart_status && typeof data.smart_status.passed === "boolean") {
      return { available:true, healthy:data.smart_status.passed, reason:null };
    }
    return { available:false, healthy:null, reason:"SMART non supporté par ce disque" };
  } catch { return { available:false, healthy:null, reason:"Lecture SMART impossible" }; }
}

// Vue "matériel" des disques (onglet Disque) — un disque physique par
// entrée avec ses partitions réelles (via lsblk), utilisé pour afficher
// modèle/numéro de série/protocole/statut et distinguer interne/externe
// (tran==="usb"). Complémentaire de /api/storage/volumes (vue "volume NAS").
app.get("/api/storage/disks", auth, async(req,res)=>{
  try {
    const tree = await lsblkTree();
    const rootSrc = (await execAsync("findmnt -n -o SOURCE / 2>/dev/null").catch(()=>({stdout:""}))).stdout.trim();
    const volumes = await getVolumesList().catch(()=>[]);
    const physicalDisks = tree.filter(d=>d.type==="disk");
    const smartByPath = {};
    await Promise.all(physicalDisks.map(async d=>{
      const p = d.path || ("/dev/"+d.name);
      smartByPath[p] = await getSmartStatus(p);
    }));
    const disks = physicalDisks.map(d=>{
      const parts = (d.children||[]).filter(c=>c.type==="part").map(c=>({
        name: c.name, path: c.path || ("/dev/"+c.name), size: Number(c.size)||0,
        fstype: c.fstype || null, mountpoint: c.mountpoint || null,
      }));
      const devPath = d.path || ("/dev/"+d.name);
      const allMounts = [d.mountpoint, ...parts.map(p=>p.mountpoint)].filter(Boolean);
      const isSystem = allMounts.includes("/") || rootSrc.startsWith(devPath);
      const matchedVolume = volumes.find(v => typeof v.device==="string" && v.device.startsWith(devPath));
      return {
        name: d.name, path: devPath, size: Number(d.size)||0,
        model: (d.model||"").trim() || "—",
        serial: d.serial || "—",
        tran: (d.tran||"").toUpperCase() || "—",
        external: d.tran === "usb",
        isSystem,
        volumeName: matchedVolume ? matchedVolume.name : null,
        partitions: parts,
        smart: smartByPath[devPath] || { available:false, healthy:null, reason:"Lecture SMART impossible" },
      };
    });
    res.json(disks);
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Relance une vérification S.M.A.R.T. à la demande pour un seul disque
// (bouton "Vérifier" de l'onglet Disque) — même fonction que celle
// utilisée dans la liste, mais interrogée à la volée sans attendre le
// prochain chargement de la page.
app.get("/api/storage/disks/:name/smart", auth, async(req,res)=>{
  const name = req.params.name.replace(/[^a-zA-Z0-9]/g,"");
  if (!name) return res.status(400).json({error:"Disque invalide"});
  try { res.json(await getSmartStatus("/dev/"+name)); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// ── Volumes ───────────────────────────────────────────────────────────────────
async function getVolumesList(){
  fs.mkdirSync(VOL_ROOT,{recursive:true});
  const {stdout:rootSrc} = await execAsync("findmnt -n -o SOURCE /").catch(()=>({stdout:"—"}));
  const {stdout:rootDf}  = await execAsync("df -B1 --output=size,used / 2>/dev/null | tail -n1").catch(()=>({stdout:"0 0"}));
  const [rsz,rus] = rootDf.trim().split(/\s+/);
  // Volume 1 = le disque système, représenté par son dossier partagé dans
  // VOL_ROOT (pas /srv/shares — les stats ci-dessus viennent déjà du point
  // de montage racine, donc son chemin doit correspondre puisque VOL_ROOT
  // est lui-même sur la partition racine tant qu'aucun disque dédié n'y est
  // monté séparément)
  fs.mkdirSync(volume1Path(),{recursive:true, mode:0o2775});
  const volumes = [{ name:"Volume 1 (système)", path:volume1Path(), device:rootSrc.trim()||"—", size:Number(rsz)||0, used:Number(rus)||0, system:true }];
  for (const name of fs.readdirSync(VOL_ROOT)) {
    if (name === SYSTEM_VOLUME_DIR) continue; // déjà listé ci-dessus comme "Volume 1 (système)"
    const p = path.join(VOL_ROOT, name);
    if (!fs.statSync(p).isDirectory()) continue;
    const {stdout:info} = await execAsync(`df -B1 --output=source,size,used ${sh(p)} 2>/dev/null | tail -n1`).catch(()=>({stdout:""}));
    const [device,sz,us] = info.trim().split(/\s+/);
    volumes.push({ name, path:p, device:device||"—", size:Number(sz)||0, used:Number(us)||0, system:false });
  }
  return volumes;
}
app.get("/api/storage/volumes", auth, async(req,res)=>{
  try { res.json(await getVolumesList()); } catch(e){ res.status(500).json({error:e.message}); }
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
// mdadm --create /dev/md/<nom> assigne en interne un numéro de périphérique
// libre (souvent /dev/md127) et crée /dev/md/<nom> comme lien symbolique vers
// celui-ci — /proc/mdstat n'affiche que le nom numérique réel, donc pour
// retrouver le nom choisi par l'utilisateur il faut lire ces liens.
async function raidNameMap(){
  const {stdout} = await execAsync("ls -la /dev/md/ 2>/dev/null").catch(()=>({stdout:""}));
  const map = {};
  for (const line of stdout.split("\n")) {
    const m = line.match(/(\S+)\s*->\s*\.\.\/(md\d+)\s*$/);
    if (m) map[m[2]] = m[1];
  }
  return map;
}
app.get("/api/storage/raid", auth, async(req,res)=>{
  try {
    const [{stdout}, nameMap, flat, volumes] = await Promise.all([
      execAsync("cat /proc/mdstat").catch(()=>({stdout:""})),
      raidNameMap(),
      lsblkTree().then(lsblkFlat),
      getVolumesList().catch(()=>[]),
    ]);
    const lines = stdout.split("\n");
    const arrays = [];
    for (let i=0;i<lines.length;i++){
      const m = lines[i].match(/^(md\d+)\s*:\s*(active|inactive)\s*(\S+)?\s*(.*)$/);
      if (!m) continue;
      const [,dev,state,level,membersRaw] = m;
      const members = (membersRaw.match(/\S+\[\d+\]/g)||[]).map(x=>"/dev/"+x.replace(/\[\d+\].*/,""));
      // La ligne suivante contient l'état de santé "[UU]"/"[U_]" (un "_" =
      // disque manquant/dégradé) et la progression de resynchronisation
      // éventuelle ("resync"/"recovery = XX.X%") — absente une fois l'array
      // stable.
      const detailLine = lines[i+1] || "";
      const healthMatch = detailLine.match(/\[([U_]+)\]/);
      const resyncMatch = detailLine.match(/(?:resync|recovery)\s*=\s*([\d.]+)%/);
      const devPath = "/dev/"+dev;
      const lsblkEntry = flat.find(n => (n.path||("/dev/"+n.name)) === devPath);
      const volume = volumes.find(v => typeof v.device==="string" && v.device.startsWith(devPath));
      arrays.push({
        device: devPath,
        name: nameMap[dev] || dev,
        state,
        level: level ? level.replace(/^raid/,"") : "?",
        members,
        degraded: healthMatch ? healthMatch[1].includes("_") : false,
        resyncPercent: resyncMatch ? Number(resyncMatch[1]) : null,
        size: lsblkEntry ? Number(lsblkEntry.size)||0 : 0,
        volumeName: volume ? volume.name : null,
      });
    }
    res.json(arrays);
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/storage/raid", auth, (req,res)=>{
  const { name, level, devices } = req.body;
  if(!name || !/^[a-zA-Z0-9_-]+$/.test(name)) return res.status(400).json({error:"Nom invalide (lettres/chiffres/-/_ uniquement)"});
  if(!["0","1","5","6","10"].includes(String(level))) return res.status(400).json({error:"Niveau RAID invalide"});
  if(!Array.isArray(devices) || devices.length<2 || devices.some(d=>!/^\/dev\/[a-zA-Z0-9/]+$/.test(d))) return res.status(400).json({error:"Au moins 2 disques valides requis"});
  const minDevs = {0:2,1:2,5:3,6:4,10:4}[level];
  if(devices.length<minDevs) return res.status(400).json({error:`RAID${level} nécessite au moins ${minDevs} disques`});
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g,"");
  const cmd = `
    set -e
    mdadm --create /dev/md/${safeName} --run --level=${level} --raid-devices=${devices.length} ${devices.map(sh).join(" ")} 2>&1
    mkdir -p /etc/mdadm
    mdadm --detail --scan > /etc/mdadm/mdadm.conf 2>&1 || true
    update-initramfs -u 2>&1 || true
    echo "RAID${level} '${safeName}' créé — synchronisation en arrière-plan (voir l'onglet Raid)"
  `;
  const jobId = runJob(cmd);
  res.json({ok:true, jobId});
});
app.delete("/api/storage/raid/:dev", auth, async(req,res)=>{
  const dev = "/dev/"+req.params.dev.replace(/[^a-zA-Z0-9]/g,"");
  try {
    // Récupère les disques membres avant l'arrêt (impossible à interroger
    // une fois l'array stoppé) pour effacer leur signature RAID ensuite —
    // sinon ils resteraient marqués "linux_raid_member" indéfiniment et
    // n'apparaîtraient plus jamais comme disques libres.
    const {stdout} = await execAsync(`mdadm --detail ${sh(dev)} 2>&1`).catch(()=>({stdout:""}));
    const members = [...stdout.matchAll(/\/dev\/\S+/g)].map(m=>m[0]).filter(p=>p!==dev+":" && p!==dev);
    await execAsync(`mdadm --stop ${sh(dev)} 2>&1`);
    for (const m of members) await execAsync(`mdadm --zero-superblock ${sh(m)} 2>&1`).catch(()=>{});
    const conf = fs.existsSync("/etc/mdadm/mdadm.conf") ? fs.readFileSync("/etc/mdadm/mdadm.conf","utf8") : "";
    if (conf) fs.writeFileSync("/etc/mdadm/mdadm.conf", conf.split("\n").filter(l=>!l.includes(dev)).join("\n"));
    res.json({ok:true, message:"RAID arrêté — les disques membres sont de nouveau disponibles (données effacées)"});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Pool à parité façon Unraid (SnapRAID + mergerfs) ────────────────────────
// Contrairement au RAID classique ci-dessus (mdadm, striping en blocs),
// chaque disque de données garde ici son propre système de fichiers — lisible
// individuellement même si le pool est cassé — et un ou plusieurs disques de
// parité permettent de reconstruire un disque perdu. mergerfs fusionne les
// disques de données en un seul point de montage (qui devient un Volume
// GravityOS normal, réutilisant getVolumesList()) ; SnapRAID calcule la
// parité à la demande (pas en temps réel, contrairement au RAID) via une
// synchronisation manuelle ou planifiée.
const SNAPRAID_POOL_ROOT = "/srv/raid-pools";
function snapraidConfPath(name){ return `/etc/snapraid-${name}.conf`; }
function snapraidSyncMarker(name){ return `/etc/snapraid-${name}.lastsync`; }

async function listSnapraidPools(){
  if (!fs.existsSync("/etc")) return [];
  const confFiles = fs.readdirSync("/etc").filter(f=>/^snapraid-.+\.conf$/.test(f));
  const pools = [];
  for (const file of confFiles) {
    const name = file.replace(/^snapraid-/,"").replace(/\.conf$/,"");
    const conf = fs.readFileSync(path.join("/etc",file), "utf8");
    const dataDisks = [...conf.matchAll(/^data\s+\S+\s+(\S+)/gm)].map(m=>m[1]);
    const parityDisks = [...conf.matchAll(/^parity\s+(\S+)/gm), ...conf.matchAll(/^\d-parity\s+(\S+)/gm)]
      .map(m=>path.dirname(m[1]));
    const mnt = path.join(VOL_ROOT, name);
    const {stdout:info} = await execAsync(`df -B1 --output=size,used ${sh(mnt)} 2>/dev/null | tail -n1`).catch(()=>({stdout:""}));
    const [sz,us] = info.trim().split(/\s+/);
    let lastSync = null;
    try { lastSync = fs.statSync(snapraidSyncMarker(name)).mtime.toISOString(); } catch {}
    pools.push({ name, mountpoint: mnt, dataDisks, parityDisks, size:Number(sz)||0, used:Number(us)||0, lastSync });
  }
  return pools;
}
app.get("/api/storage/snapraid", auth, async(req,res)=>{
  try { res.json(await listSnapraidPools()); } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/storage/snapraid", auth, (req,res)=>{
  const { name, dataDisks, parityDisks } = req.body;
  if(!name || !/^[a-zA-Z0-9_-]+$/.test(name)) return res.status(400).json({error:"Nom invalide (lettres/chiffres/-/_ uniquement)"});
  if(!Array.isArray(dataDisks) || dataDisks.length<2 || dataDisks.some(d=>!/^\/dev\/[a-zA-Z0-9/]+$/.test(d))) return res.status(400).json({error:"Au moins 2 disques de données valides requis"});
  if(!Array.isArray(parityDisks) || parityDisks.length<1 || parityDisks.some(d=>!/^\/dev\/[a-zA-Z0-9/]+$/.test(d))) return res.status(400).json({error:"Au moins 1 disque de parité valide requis"});
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g,"");
  const poolDir = path.join(SNAPRAID_POOL_ROOT, safeName);
  const mnt = path.join(VOL_ROOT, safeName);
  const dataMnts = dataDisks.map((d,i)=>path.join(poolDir, `disk${i+1}`));
  const parityMnts = parityDisks.map((d,i)=>path.join(poolDir, `parity${i+1}`));

  const mkfsAndMount = (dev, target) => `
    mkfs.ext4 -F ${sh(dev)}
    mkdir -p ${sh(target)}
    UUID=$(blkid -s UUID -o value ${sh(dev)})
    grep -q "$UUID" /etc/fstab || echo "UUID=$UUID  ${target}  ext4  defaults,nofail  0  2" >> /etc/fstab
    mount ${sh(target)}
  `;

  const confLines = [
    // 1er disque de parité = directive "parity", les suivants (parité
    // double/triple) = "2-parity"/"3-parity" — SnapRAID n'accepte pas
    // plusieurs lignes "parity" pour ça, contrairement à "content"/"data".
    // Fichiers de contenu/parité préfixés d'un point (".snapraid.*") pour
    // qu'ils restent de simples fichiers cachés Unix plutôt que de polluer
    // la racine du pool fusionné vue par l'utilisateur (mergerfs expose le
    // contenu de chaque disque de données tel quel).
    ...parityMnts.map((p,i) => `${i===0 ? "parity" : `${i+1}-parity`} ${p}/.snapraid.parity`),
    ...dataMnts.map(d => `content ${d}/.snapraid.content`),
    ...dataMnts.map((d,i) => `data d${i+1} ${d}`),
    "exclude *.tmp",
    "exclude /lost+found/",
  ].join("\n");

  const mergerfsBranches = dataMnts.map(d=>d).join(":");
  // mergerfs refuse par défaut d'écrire sur une branche avec moins de 4 Gio
  // libres (option minfreespace) — sain sur un vrai NAS mais rend le pool
  // inutilisable dès qu'un disque approche du plein sans prévenir ("Aucun
  // espace disponible" alors qu'il en reste). Abaissé à 1 Gio, une marge
  // de sécurité réelle plutôt que ce seuil pensé pour de très gros volumes.

  const cmd = `
    set -e
    ${dataDisks.map((d,i)=>mkfsAndMount(d, dataMnts[i])).join("\n")}
    ${parityDisks.map((d,i)=>mkfsAndMount(d, parityMnts[i])).join("\n")}
    cat > ${sh(snapraidConfPath(safeName))} << 'EOF'
${confLines}
EOF
    mkdir -p ${sh(mnt)}
    grep -q " ${mnt} " /etc/fstab || echo "${mergerfsBranches}  ${mnt}  fuse.mergerfs  defaults,allow_other,use_ino,cache.files=partial,dropcacheonclose=true,category.create=mfs,minfreespace=1G,nofail  0  0" >> /etc/fstab
    mount ${sh(mnt)}
    chown gravity:${SHARED_GROUP} ${sh(mnt)}
    chmod 2775 ${sh(mnt)}
    snapraid -c ${sh(snapraidConfPath(safeName))} sync 2>&1
    touch ${sh(snapraidSyncMarker(safeName))}
    echo "Pool à parité '${safeName}' créé et première synchronisation terminée"
  `;
  const jobId = runJob(cmd);
  res.json({ok:true, jobId});
});
app.post("/api/storage/snapraid/:name/sync", auth, (req,res)=>{
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,"");
  if (!fs.existsSync(snapraidConfPath(name))) return res.status(404).json({error:"Pool introuvable"});
  const cmd = `
    set -e
    snapraid -c ${sh(snapraidConfPath(name))} sync 2>&1
    touch ${sh(snapraidSyncMarker(name))}
    echo "Synchronisation de '${name}' terminée"
  `;
  const jobId = runJob(cmd);
  res.json({ok:true, jobId});
});
app.delete("/api/storage/snapraid/:name", auth, async(req,res)=>{
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,"");
  const mnt = path.join(VOL_ROOT, name);
  const poolDir = path.join(SNAPRAID_POOL_ROOT, name);
  try {
    await execAsync(`umount ${sh(mnt)} 2>/dev/null`).catch(()=>{});
    if (fs.existsSync(poolDir)) {
      for (const sub of fs.readdirSync(poolDir)) {
        await execAsync(`umount ${sh(path.join(poolDir,sub))} 2>/dev/null`).catch(()=>{});
      }
    }
    const fstab = fs.readFileSync("/etc/fstab","utf8").split("\n").filter(l=>!l.includes(` ${mnt} `) && !l.includes(poolDir)).join("\n");
    fs.writeFileSync("/etc/fstab", fstab);
    fs.rmSync(snapraidConfPath(name), {force:true});
    fs.rmSync(snapraidSyncMarker(name), {force:true});
    res.json({ok:true, message:"Pool arrêté — les données restent sur chaque disque (non effacées), consultables individuellement"});
  } catch(e){ res.status(500).json({error:e.message}); }
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
app.post("/api/smb/toggle", auth, async (req,res) => {
  try {
    const { stdout } = await execAsync("systemctl is-active smbd").catch(()=>({stdout:"inactive"}));
    const cmd = stdout.trim()==="active" ? "stop" : "start";
    await execAsync(`systemctl ${cmd} smbd; systemctl ${cmd} nmbd`);
    res.json({ok:true, running: cmd==="start"});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  NFS / FTP / PROXY (inchangé)
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/nfs/exports", auth, (req,res) => { try{const r=fs.readFileSync("/etc/exports","utf8");res.json(r.split("\n").filter(l=>l.trim()&&!l.startsWith("#")).map(l=>{const[p,...o]=l.trim().split(/\s+/);return{path:p,options:o.join(" ")};} ));}catch{res.json([]);} });
app.post("/api/nfs/exports", auth, async (req,res) => { const{path:p,clients,options}=req.body;try{fs.mkdirSync(p,{recursive:true});fs.appendFileSync("/etc/exports",`\n${p}  ${clients||"*"}(${options||"rw,sync,no_subtree_check"})\n`);await execAsync("exportfs -ra");res.json({ok:true});}catch(e){res.status(500).json({error:e.message});} });
app.get("/api/ftp/status", auth, async (req,res) => { try{const{stdout}=await execAsync("systemctl is-active vsftpd");res.json({active:stdout.trim()==="active"});}catch{res.json({active:false});} });
// Bug corrigé le 2026-08-23 : "systemctl is-active" renvoie un code de
// sortie non-nul (donc une promesse rejetée) quand le service est déjà
// arrêté — sans le .catch() ci-dessous, activer vsftpd depuis l'arrêt
// échouait toujours (l'utilisateur ne pouvait jamais l'allumer), même
// pattern déjà correctement géré pour /api/smb/toggle juste au-dessus.
app.post("/api/ftp/toggle", auth, async (req,res) => {
  try {
    const { stdout } = await execAsync("systemctl is-active vsftpd").catch(()=>({stdout:"inactive"}));
    const cmd = stdout.trim()==="active" ? "stop" : "start";
    await execAsync(`systemctl ${cmd} vsftpd`);
    res.json({ok:true, running: cmd==="start"});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── FTP — identification (utilisateur/mot de passe dédiés) ───────────────────
// vsftpd.conf embarque userlist_enable=YES + userlist_deny=NO : seul un
// utilisateur listé dans /etc/vsftpd.userlist peut se connecter, quel que
// soit son mot de passe système. Le compte est créé sans shell de login
// (/usr/sbin/nologin) et ajouté au groupe "gravity" pour pouvoir écrire dans
// /srv/shares (chroot FTP, cf. local_root=/srv/shares dans vsftpd.conf).
const FTP_USERLIST = "/etc/vsftpd.userlist";
app.get("/api/ftp/account", auth, (req,res) => {
  try {
    const list = fs.readFileSync(FTP_USERLIST,"utf8").split("\n").map(l=>l.trim()).filter(Boolean);
    res.json({ username: list[0] || null });
  } catch { res.json({ username: null }); }
});
app.post("/api/ftp/account", auth, async (req,res) => {
  const { username, password } = req.body;
  if (!username || !/^[a-z][a-z0-9_-]{2,31}$/i.test(username)) return res.status(400).json({error:"Nom d'utilisateur invalide (3-32 caractères alphanumériques)"});
  if (!password || password.length < 4) return res.status(400).json({error:"Mot de passe trop court (minimum 4 caractères)"});
  try {
    await execAsync(`grep -qxF '/usr/sbin/nologin' /etc/shells || echo '/usr/sbin/nologin' >> /etc/shells`);
    // vsftpd exige que le répertoire personnel (passwd) existe réellement sur
    // le disque (vérification interne avant application de local_root), même
    // si le contenu servi est ensuite déterminé par local_root=/srv/shares —
    // useradd -M (sans home) fait donc échouer toute connexion FTP malgré un
    // compte valide (bug découvert en testant une vraie connexion FTP).
    const exists = await execAsync(`id ${sh(username)}`).then(()=>true).catch(()=>false);
    if (!exists) await execAsync(`useradd -m -s /usr/sbin/nologin -G gravity ${sh(username)}`);
    else await execAsync(`usermod -aG gravity ${sh(username)}`);
    await execAsync(`echo ${sh(`${username}:${password}`)} | chpasswd`);
    fs.writeFileSync(FTP_USERLIST, username+"\n");
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── WebDAV (rclone serve webdav) — désactivé par défaut après installation ──
const WEBDAV_ENV = "/etc/gravity/webdav.env";
function readWebdavEnv() {
  try {
    const conf = fs.readFileSync(WEBDAV_ENV,"utf8");
    return {
      username: conf.match(/^RCLONE_USER=(.*)$/m)?.[1]?.trim() || "gravity",
      password: conf.match(/^RCLONE_PASS=(.*)$/m)?.[1]?.trim() || "gravity",
    };
  } catch { return { username:"gravity", password:"gravity" }; }
}
app.get("/api/webdav/status", auth, async (req,res) => {
  try {
    const { stdout } = await execAsync("systemctl is-active gravity-webdav").catch(()=>({stdout:"inactive"}));
    const ip = (await execAsync("hostname -I 2>/dev/null").catch(()=>({stdout:"?"}))).stdout.trim().split(" ")[0];
    res.json({ active: stdout.trim()==="active", ip, port: 8081 });
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.post("/api/webdav/toggle", auth, async (req,res) => {
  try {
    const { stdout } = await execAsync("systemctl is-active gravity-webdav").catch(()=>({stdout:"inactive"}));
    const cmd = stdout.trim()==="active" ? "stop" : "start";
    await execAsync(`systemctl ${cmd} gravity-webdav`);
    res.json({ok:true, running: cmd==="start"});
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.get("/api/webdav/account", auth, (req,res) => {
  const { username } = readWebdavEnv();
  res.json({ username });
});
app.post("/api/webdav/account", auth, async (req,res) => {
  const { username, password } = req.body;
  if (!username || !/^[a-z][a-z0-9_-]{2,31}$/i.test(username)) return res.status(400).json({error:"Nom d'utilisateur invalide (3-32 caractères alphanumériques)"});
  if (!password || password.length < 4) return res.status(400).json({error:"Mot de passe trop court (minimum 4 caractères)"});
  try {
    fs.mkdirSync(path.dirname(WEBDAV_ENV), {recursive:true});
    fs.writeFileSync(WEBDAV_ENV, `RCLONE_USER=${username}\nRCLONE_PASS=${password}\n`);
    fs.chmodSync(WEBDAV_ENV, 0o600);
    await execAsync("systemctl is-active gravity-webdav").then(()=>execAsync("systemctl restart gravity-webdav")).catch(()=>{});
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── DLNA (minidlna) — désactivé par défaut après installation ───────────────
app.get("/api/dlna/status", auth, async (req,res) => {
  try {
    const { stdout } = await execAsync("systemctl is-active minidlna").catch(()=>({stdout:"inactive"}));
    const ip = (await execAsync("hostname -I 2>/dev/null").catch(()=>({stdout:"?"}))).stdout.trim().split(" ")[0];
    res.json({ active: stdout.trim()==="active", ip });
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.post("/api/dlna/toggle", auth, async (req,res) => {
  try {
    const { stdout } = await execAsync("systemctl is-active minidlna").catch(()=>({stdout:"inactive"}));
    const cmd = stdout.trim()==="active" ? "stop" : "start";
    await execAsync(`systemctl ${cmd} minidlna`);
    res.json({ok:true, running: cmd==="start"});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── Reverse Proxy — façon Nginx Proxy Manager ────────────────────────────────
// (Domaines multiples, WebSockets, blocage exploits, cache assets, SSL
//  none/Let's Encrypt/custom, force SSL, HTTP/2, HSTS, emplacements
//  personnalisés, config Nginx avancée)
const NSITES = "/etc/nginx/sites-enabled";
const NAVAIL = "/etc/nginx/sites-available";
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

function proxyIsActive(fn) {
  try { return fs.lstatSync(path.join(NSITES,fn)).isSymbolicLink(); } catch { return false; }
}
function proxyEnable(fn) {
  const link = path.join(NSITES,fn);
  try { fs.unlinkSync(link); } catch {}
  fs.symlinkSync(path.join(NAVAIL,fn), link);
}
function proxyDisable(fn) {
  try { fs.unlinkSync(path.join(NSITES,fn)); } catch {}
}

function nginxAvailable() { return fs.existsSync(NAVAIL) && fs.existsSync(NSITES); }

app.get("/api/proxy/hosts", auth, (req,res) => {
  try {
    const meta = loadProxyMeta();
    const files = fs.readdirSync(NAVAIL).filter(f=>f!=="default"&&f!=="gravity-fallback");
    res.json(files.map(f => ({ name:f, active: proxyIsActive(f), ...( meta[f] || {domains:[f],forwardHost:"?",forwardPort:"",sslMode:"none"} ) })));
  } catch { res.json([]); }
});

app.post("/api/proxy/hosts", auth, async (req,res) => {
  if (!nginxAvailable()) return res.status(503).json({error:"Nginx n'est pas installé sur cette machine (environnement de test) — cette fonctionnalité s'applique réellement sur un vrai NAS GravityOS."});
  const h = req.body;
  if (!Array.isArray(h.domains) || !h.domains.length || !h.forwardHost || !h.forwardPort)
    return res.status(400).json({error:"Au moins un domaine, un hôte et un port de destination sont requis"});
  const fn = h.domains[0].replace(/[^a-zA-Z0-9.-]/g,"_");
  try {
    if (h.sslMode==="letsencrypt") {
      // 1) vhost HTTP simple d'abord, requis pour la validation ACME (webroot via le / existant)
      fs.writeFileSync(path.join(NAVAIL,fn), buildProxyConf({...h, sslMode:"none"}));
      proxyEnable(fn);
      await execAsync("nginx -t && systemctl reload nginx");
      const meta = loadProxyMeta(); meta[fn]=h; saveProxyMeta(meta);
      const emailArg = h.letsencryptEmail ? `-m ${sh(h.letsencryptEmail)}` : "--register-unsafely-without-email";
      const domainArgs = h.domains.map(d=>`-d ${sh(d)}`).join(" ");
      const jobId = runJob(`certbot certonly --nginx --non-interactive --agree-tos ${emailArg} ${domainArgs} 2>&1 && echo "=== Certificat obtenu — finalisation... ===" && curl -s -X POST -H 'Content-Type: application/json' -b "gravity_sid=${getSid(req)}" http://127.0.0.1:${process.env.GRAVITY_PORT||4000}/api/proxy/hosts/${fn}/finalize-ssl >/dev/null && echo "=== Hôte HTTPS actif ✓ ==="`);
      return res.json({ok:true, jobId, name:fn});
    }
    fs.writeFileSync(path.join(NAVAIL,fn), buildProxyConf(h));
    proxyEnable(fn);
    await execAsync("nginx -t && systemctl reload nginx");
    const meta = loadProxyMeta(); meta[fn]=h; saveProxyMeta(meta);
    res.json({ok:true, name:fn});
  } catch(e){ res.status(500).json({error:"Erreur Nginx : "+e.message}); }
});

// Réécrit le vhost avec le bloc HTTPS complet une fois le certificat Let's Encrypt obtenu
app.post("/api/proxy/hosts/:name/finalize-ssl", auth, async (req,res) => {
  try {
    const meta = loadProxyMeta();
    const h = meta[req.params.name];
    if (!h) return res.status(404).json({error:"Hôte introuvable"});
    fs.writeFileSync(path.join(NAVAIL,req.params.name), buildProxyConf(h));
    await execAsync("nginx -t && systemctl reload nginx");
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:"Erreur Nginx : "+e.message}); }
});

// Édition d'un hôte existant (même nom de fichier tant que le 1er domaine ne change pas)
app.put("/api/proxy/hosts/:name", auth, async (req,res) => {
  const h = req.body;
  const fn = req.params.name;
  if (!fs.existsSync(path.join(NAVAIL,fn))) return res.status(404).json({error:"Hôte introuvable"});
  if (!Array.isArray(h.domains) || !h.domains.length || !h.forwardHost || !h.forwardPort)
    return res.status(400).json({error:"Au moins un domaine, un hôte et un port de destination sont requis"});
  try {
    fs.writeFileSync(path.join(NAVAIL,fn), buildProxyConf(h));
    if (proxyIsActive(fn)) await execAsync("nginx -t && systemctl reload nginx");
    const meta = loadProxyMeta(); meta[fn]=h; saveProxyMeta(meta);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:"Erreur Nginx : "+e.message}); }
});

app.post("/api/proxy/hosts/:name/toggle", auth, async (req,res) => {
  const fn = req.params.name;
  if (!fs.existsSync(path.join(NAVAIL,fn))) return res.status(404).json({error:"Hôte introuvable"});
  try {
    const active = !!req.body.active;
    if (active) proxyEnable(fn); else proxyDisable(fn);
    await execAsync("nginx -t && systemctl reload nginx");
    res.json({ok:true, active});
  } catch(e){ res.status(500).json({error:"Erreur Nginx : "+e.message}); }
});

app.delete("/api/proxy/hosts/:n", auth, async (req,res) => {
  try {
    proxyDisable(req.params.n);
    try { fs.unlinkSync(path.join(NAVAIL,req.params.n)); } catch {}
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
// LC_ALL=C forcé : sous la locale fr_FR.UTF-8 par défaut de GravityOS,
// "virsh dominfo" traduit ses libellés ("CPU :" au lieu de "CPU(s):", etc.)
// — cassait silencieusement le parsing regex de vcpus/memMB dans GET
// /api/vms depuis le début (jamais remarqué : "?"/"—" affichés sans erreur),
// même famille de bug que le "Listing..." d'apt corrigé plus tôt.
// "2>/dev/null" jetait le vrai message d'erreur de virsh — un échec ne
// remontait alors que "Command failed: virsh ... start 'x'" sans aucune
// explication (bug signalé par l'utilisateur : VM refusant de démarrer
// sans qu'on puisse savoir pourquoi). stderr est maintenant conservé et
// remonté dans l'erreur pour que les endpoints renvoient un message
// diagnosticable — les appelants qui attendent un échec silencieux
// utilisent déjà .catch(), donc rien ne change pour eux.
async function virsh(cmd) {
  try {
    const { stdout } = await execAsync(`LC_ALL=C virsh --connect qemu:///system ${cmd}`);
    return stdout.trim();
  } catch (e) {
    throw new Error((e.stderr || "").trim() || e.message);
  }
}

// Interface physique principale du NAS (celle de la route par défaut) —
// utilisée pour le mode réseau "pont direct" d'une VM (macvtap), qui la
// place directement sur le même sous-réseau que le NAS plutôt que sur le
// réseau NAT isolé de libvirt (192.168.122.0/24 par défaut, jamais joignable
// depuis le reste du LAN sans redirection de port) — signalé comme
// surprenant par un utilisateur ("l'IP de la VM n'est pas dans le même
// sous-réseau que le NAS").
async function primaryIface() {
  try {
    const { stdout } = await execAsync("ip route show default 2>/dev/null");
    return (stdout.match(/dev (\S+)/) || [])[1] || null;
  } catch { return null; }
}
// "__bridge__" est un identifiant réservé (jamais un vrai nom de réseau
// libvirt) qui sélectionne le mode pont direct plutôt qu'un réseau NAT.
const BRIDGE_NETWORK_ID = "__bridge__";
async function buildInterfaceXml(network) {
  if (network === BRIDGE_NETWORK_ID) {
    const iface = await primaryIface();
    if (!iface) throw new Error("Interface réseau physique introuvable — pont direct impossible");
    return `<interface type='direct'><source dev='${iface}' mode='bridge'/><model type='virtio'/></interface>`;
  }
  return `<interface type='network'><source network='${network || "default"}'/><model type='e1000'/></interface>`;
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

// IP d'une VM — la source par défaut ("lease") ne fonctionne que pour le
// réseau NAT géré par libvirt (bail dnsmasq) : une VM en pont direct
// (macvtap, voir buildInterfaceXml) obtient son IP du DHCP du LAN, invisible
// à libvirt, donc toujours vide sans repli. --source arp (table ARP/voisinage
// de l'hôte) est le seul moyen sans agent invité installé dans la VM — n'a
// une valeur qu'après que la VM ait déjà émis du trafic sur le réseau
// (rien d'instantané au premier démarrage, contrairement au bail DHCP).
async function vmIp(name){
  for (const source of ["lease", "arp"]) {
    try {
      const {stdout} = await execAsync(`virsh --connect qemu:///system domifaddr ${sh(name)} --source ${source} 2>/dev/null`);
      const m = stdout.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/\d+/);
      if (m) return m[1];
    } catch {}
  }
  return null;
}
// Taille virtuelle du disque principal (Go) — lu via qemu-img sur le fichier
// qcow2 attaché, indépendant de l'état running/stopped de la VM
async function vmDiskGB(name){
  try {
    const {stdout} = await execAsync(`virsh --connect qemu:///system domblklist ${sh(name)} --details 2>/dev/null`);
    const line = stdout.split("\n").find(l=>/\bdisk\b/.test(l));
    const diskPath = line?.trim().split(/\s+/).pop();
    if(!diskPath || !fs.existsSync(diskPath)) return null;
    const {stdout:info} = await execAsync(`qemu-img info -U --output=json ${sh(diskPath)} 2>/dev/null`);
    const j = JSON.parse(info);
    return j["virtual-size"] ? Math.round(j["virtual-size"]/(1024**3)) : null;
  } catch { return null; }
}

// Réseau/ISO/USB actuels d'une VM — lus depuis dumpxml pour pré-remplir
// l'assistant d'édition avec l'état réel plutôt que de deviner à partir des
// seuls paramètres de création (une VM peut avoir été éditée depuis).
async function vmDevicesFromXml(name) {
  try {
    const xml = await virsh(`dumpxml ${sh(name)}`);
    const network = /<interface type='direct'>/.test(xml)
      ? BRIDGE_NETWORK_ID
      : (xml.match(/<interface type='network'>[\s\S]*?<source network='([^']*)'/)||[])[1] || null;
    const iso = (xml.match(/<disk type='file' device='cdrom'>[\s\S]*?<source file='([^']*)'/)||[])[1] || null;
    const usbDevices = [...xml.matchAll(/<hostdev mode='subsystem' type='usb'>[\s\S]*?<vendor id='0x([0-9a-fA-F]{4})'\/>[\s\S]*?<product id='0x([0-9a-fA-F]{4})'\/>[\s\S]*?<\/hostdev>/g)]
      .map(m => `${m[1]}:${m[2]}`);
    const bios = /<loader readonly='yes' type='pflash'>/.test(xml) ? "uefi" : "legacy";
    return { network, iso, usbDevices, bios };
  } catch { return { network:null, iso:null, usbDevices:[], bios:"legacy" }; }
}

app.get("/api/vms", auth, async (req,res) => {
  if (isLive()) return res.json({isLive:true,vms:[],message:"KVM indisponible en Live CD — installez GravityOS sur disque"});
  try {
    const raw = await virsh("list --all");
    const vms = raw.split("\n").slice(2).filter(Boolean).map(l=>{const p=l.trim().split(/\s{2,}/);return{id:p[0],name:p[1],state:p[2]};}).filter(v=>v.name);
    const detailed = await Promise.all(vms.map(async vm=>{
      let d = vm;
      try{const i=await virsh(`dominfo ${vm.name}`);d={...vm,vcpus:(i.match(/CPU\(s\):\s+(\d+)/)||[])[1]||"?",memMB:Math.round(parseInt((i.match(/Max memory:\s+(\d+)/)||[])[1]||0)/1024)};}catch{}
      const diskGB = await vmDiskGB(vm.name);
      if (diskGB!=null) d = { ...d, diskGB };
      const devices = await vmDevicesFromXml(vm.name);
      d = { ...d, ...devices };
      if (vm.state?.includes("running")) {
        const [live, ip] = await Promise.all([vmLiveStat(vm.name), vmIp(vm.name)]);
        d = { ...d, ...live, ip };
      }
      return d;
    }));
    res.json({isLive:false,vms:detailed});
  } catch(e) { res.json({isLive:false,vms:[],error:e.message}); }
});
app.post("/api/vms", auth, async (req,res) => {
  if(isLive()) return res.status(400).json({error:"Impossible en Live CD"});
  const{name,vcpus,memMB,diskGB,diskDir,iso,network,bios,usbDevices,importDisk}=req.body;
  if(!name||!vcpus||!memMB) return res.status(400).json({error:"name, vcpus, memMB requis"});
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g,"");
  // Emplacement du disque : /var/lib/libvirt/images par défaut, ou un volume
  // NAS autorisé (mêmes racines que le parcoureur de dossiers du wizard Docker)
  const targetDir = diskDir && diskDir.trim() ? diskDir.trim() : "/var/lib/libvirt/images";
  if (!isPathAllowed(targetDir)) return res.status(400).json({error:"Emplacement de disque non autorisé"});
  const dp = path.join(targetDir, `${safeName}.qcow2`);
  try {
    await execAsync(`mkdir -p ${sh(targetDir)}`);
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
    // Détecter si KVM est disponible (pas dans VirtualBox)
    let domainType = 'kvm';
    try { await execAsync('test -e /dev/kvm'); } catch { domainType = 'qemu'; }
    // Détecter l'émulateur disponible
    let emulator = '/usr/bin/qemu-system-x86_64';
    try { const {stdout:em} = await execAsync('which qemu-system-x86_64 2>/dev/null || echo /usr/bin/qemu-system-x86_64'); emulator = em.trim(); } catch {}

    // Démarrage BIOS (Legacy/SeaBIOS, chipset i440fx) ou UEFI (OVMF, chipset q35)
    const useUefi = bios === "uefi";
    let osBlock;
    if (useUefi) {
      const nvramDir = "/var/lib/libvirt/qemu/nvram";
      await execAsync(`mkdir -p ${nvramDir}`).catch(()=>{});
      const nvramPath = `${nvramDir}/${safeName}_VARS.fd`;
      await execAsync(`test -f "${nvramPath}" || cp /usr/share/OVMF/OVMF_VARS.fd "${nvramPath}"`);
      osBlock = `<type arch='x86_64' machine='q35'>hvm</type><loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.fd</loader><nvram>${nvramPath}</nvram>${bootDev}`;
    } else {
      osBlock = `<type arch='x86_64' machine='pc'>hvm</type>${bootDev}`;
    }

    // Passthrough USB — usbDevices: ["vendorId:productId", ...] (depuis /api/usb)
    const usbBlock = (Array.isArray(usbDevices) ? usbDevices : []).filter(d=>/^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$/.test(d)).map(d=>{
      const [vendor,product] = d.split(":");
      return `<hostdev mode='subsystem' type='usb'><source><vendor id='0x${vendor}'/><product id='0x${product}'/></source></hostdev>`;
    }).join("");

    // Le chipset q35 (requis par UEFI/OVMF) n'a pas de contrôleur IDE — bus='ide'
    // échoue à la définition ("IDE controllers are unsupported for this QEMU
    // binary or machine type"), bug découvert via un vrai échec de création
    // UEFI signalé par l'utilisateur. i440fx (legacy) supporte IDE nativement,
    // mais autant utiliser SATA dans les deux cas pour rester cohérent avec le
    // lecteur CD-ROM (déjà en bus='sata', dev='sdb' plus bas) et n'avoir qu'un
    // seul chemin de code plutôt qu'un bus conditionnel en plus du chipset.
    const diskTarget = "<target dev='sda' bus='sata'/>";
    const interfaceXml = await buildInterfaceXml(network);
    const xml = `<domain type='${domainType}'><name>${safeName}</name><memory unit='KiB'>${memKB}</memory><currentMemory unit='KiB'>${memKB}</currentMemory><vcpu>${vcpus}</vcpu><os>${osBlock}</os><features><acpi/><apic/></features><clock offset='utc'/><on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash><devices><emulator>${emulator}</emulator><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='${dp}'/>${diskTarget}</disk>${cdrom}${interfaceXml}<graphics type='vnc' port='-1' listen='0.0.0.0'/><video><model type='vga' vram='16384'/></video><console type='pty'><target type='serial'/></console>${usbBlock}</devices></domain>`;
    const xmlPath = `/tmp/${safeName}-${Date.now()}.xml`;
    fs.writeFileSync(xmlPath, xml);
    // Le disque (création ou import/conversion) tourne en job asynchrone —
    // une conversion vdi/vmdk→qcow2 peut prendre plusieurs minutes sur un
    // gros disque, pas question de bloquer la requête HTTP dessus
    const jobId = runJob(`${diskCmd} 2>&1 && echo "Disque prêt : ${dp}" && virsh --connect qemu:///system define ${sh(xmlPath)} 2>&1 && rm -f ${sh(xmlPath)} && echo "VM '${safeName}' définie — démarrez-la depuis la liste"`);
    res.json({ok:true, jobId, disk:dp});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/vms/:n/start",      auth, async (req,res)=>{try{await virsh(`start ${sh(req.params.n)}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/stop",       auth, async (req,res)=>{try{await virsh(`shutdown ${sh(req.params.n)}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/force-stop", auth, async (req,res)=>{try{await virsh(`destroy ${sh(req.params.n)}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/restart",    auth, async (req,res)=>{try{await virsh(`reboot ${sh(req.params.n)}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/suspend",    auth, async (req,res)=>{try{await virsh(`suspend ${sh(req.params.n)}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.post("/api/vms/:n/resume",     auth, async (req,res)=>{try{await virsh(`resume ${sh(req.params.n)}`);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.delete("/api/vms/:n", auth, async (req,res)=>{
  const name = req.params.n;
  try {
    await virsh(`destroy ${sh(name)}`).catch(()=>{});
    // "--remove-all-storage" ne fait RIEN sur les disques de GravityOS : ils
    // sont écrits directement par qemu-img (voir POST /api/vms), jamais
    // enregistrés dans un pool de stockage libvirt, et libvirt refuse de
    // gérer un stockage qu'il ne "possède" pas ("Storage volume ... is not
    // managed by libvirt") — silencieusement ignoré, le fichier .qcow2 reste
    // sur le disque à chaque suppression de VM depuis le début du projet.
    // Bug découvert en supprimant réellement des VM de test (fichiers
    // orphelins accumulés dans /var/lib/libvirt/images/). Fix : on relève
    // nous-mêmes le(s) chemin(s) du disque principal depuis le XML (device=
    // 'disk' uniquement, jamais un cdrom — une ISO n'appartient pas à la VM)
    // et on les supprime à la main après le undefine.
    // "--nvram" est en plus requis pour une VM UEFI (sinon : "Impossible de
    // redéfinir le domaine avec nvram"), bug également découvert en testant
    // la suppression d'une vraie VM UEFI créée par l'assistant.
    const xml = await virsh(`dumpxml ${sh(name)}`).catch(()=>"");
    const diskPaths = [...xml.matchAll(/<disk type='file' device='disk'>[\s\S]*?<source file='([^']*)'/g)].map(m=>m[1]);
    await virsh(`undefine ${sh(name)} --nvram`);
    for (const p of diskPaths) { if (isPathAllowed(p)) fs.rmSync(p, {force:true}); }
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Édition d'une VM déjà définie — jusqu'ici seule la création et les
// actions start/stop/etc existaient, aucun moyen de modifier une VM après
// coup. vCPU/mémoire/réseau exigent la VM arrêtée (--config seul, jamais
// --live : simple et prévisible, s'applique au prochain démarrage plutôt
// que de risquer un hot-plug qui échoue silencieusement selon le pilote
// invité) ; ISO et USB restent modifiables même VM allumée (--config
// --live à la fois : persiste ET prend effet immédiatement), demande
// explicite de l'utilisateur ("si elle est en cours l'édition est possible
// que sur les USB et iso de démarrage").
async function vmIsRunning(name) {
  return (await virsh(`domstate ${sh(name)}`)).trim() === "running";
}
app.put("/api/vms/:n", auth, async (req,res) => {
  if (isLive()) return res.status(400).json({error:"Impossible en Live CD"});
  const name = req.params.n;
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) return res.status(400).json({error:"Nom de VM invalide"});
  const { vcpus, memMB, network, iso, usbDevices } = req.body;
  try {
    const running = await vmIsRunning(name);
    if (running && (vcpus || memMB || network)) {
      return res.status(400).json({error:"Arrêtez la VM pour modifier vCPU/mémoire/réseau — seuls l'ISO et l'USB restent modifiables pendant l'exécution"});
    }
    if (vcpus) {
      const n = parseInt(vcpus, 10);
      if (!n || n < 1 || n > 32) return res.status(400).json({error:"vCPU invalide (1-32)"});
      await virsh(`setvcpus ${sh(name)} ${n} --config --maximum`);
      await virsh(`setvcpus ${sh(name)} ${n} --config`);
    }
    if (memMB) {
      const kb = parseInt(memMB, 10) * 1024;
      if (!kb || kb < 256*1024) return res.status(400).json({error:"Mémoire invalide (minimum 256 Mo)"});
      await virsh(`setmaxmem ${sh(name)} ${kb} --config`);
      await virsh(`setmem ${sh(name)} ${kb} --config`);
    }
    if (network) {
      if (!/^[a-zA-Z0-9_-]+$/.test(network)) return res.status(400).json({error:"Nom de réseau invalide"});
      const xml = await virsh(`dumpxml ${sh(name)}`);
      // Remplace tout le bloc <interface>...</interface> (pas juste
      // l'attribut "network" comme avant) : passer du réseau NAT libvirt au
      // pont direct (macvtap) ou inversement change le type d'interface
      // lui-même, pas seulement sa source. Le MAC existant est préservé
      // (réinjecté dans le nouveau bloc) pour ne pas changer d'adresse
      // matérielle à chaque édition — évite une nouvelle demande DHCP.
      const ifaceMatch = xml.match(/<interface type='(?:network|direct)'>[\s\S]*?<\/interface>/);
      if (!ifaceMatch) {
        return res.status(400).json({error:"Interface réseau non reconnue dans le XML de cette VM — modification manuelle requise"});
      }
      const mac = (ifaceMatch[0].match(/<mac address='([^']*)'\/>/)||[])[1];
      let interfaceXml = await buildInterfaceXml(network);
      if (mac) interfaceXml = interfaceXml.replace(/^(<interface[^>]*>)/, `$1<mac address='${mac}'/>`);
      const updated = xml.replace(ifaceMatch[0], interfaceXml);
      const xmlPath = `/tmp/${name}-edit-${Date.now()}.xml`;
      fs.writeFileSync(xmlPath, updated);
      await virsh(`define ${sh(xmlPath)}`);
      fs.rmSync(xmlPath, {force:true});
    }
    // ISO de démarrage — target 'sdb' fixe (bus sata), convention utilisée
    // partout ailleurs dans le fichier (POST /api/vms). "change-media"
    // exige qu'un lecteur CD-ROM existe déjà dans le XML (créé avec une ISO
    // au départ) ; sinon on en attache un nouveau. iso==="" éjecte sans
    // rien attacher (VM créée sans ISO au départ, rien à éjecter).
    if (iso !== undefined) {
      if (iso && !isPathAllowed(iso)) return res.status(400).json({error:"ISO hors des volumes autorisés"});
      const liveFlags = running ? "--live --config" : "--config";
      const xml = await virsh(`dumpxml ${sh(name)}`);
      const hasCdrom = /<disk type='file' device='cdrom'>/.test(xml);
      if (iso) {
        if (hasCdrom) await virsh(`change-media ${sh(name)} sdb --update ${sh(iso)} ${liveFlags}`);
        else await virsh(`attach-disk ${sh(name)} ${sh(iso)} sdb --type cdrom --mode readonly ${liveFlags}`);
      } else if (hasCdrom) {
        await virsh(`change-media ${sh(name)} sdb --eject ${liveFlags}`).catch(()=>{});
      }
    }
    // USB passthrough — comparaison de la liste souhaitée avec les hostdev
    // USB actuellement présents dans le XML (format vendorId:productId,
    // même identifiant que /api/usb et POST /api/vms), attache/détache un
    // par un les différences plutôt que de tout redéfinir d'un coup (plus
    // sûr en live : un detach-device sur un device absent échoue proprement
    // sans toucher au reste).
    if (Array.isArray(usbDevices)) {
      const liveFlags = running ? "--live --config" : "--config";
      const xml = await virsh(`dumpxml ${sh(name)}`);
      const current = [...xml.matchAll(/<hostdev mode='subsystem' type='usb'>[\s\S]*?<vendor id='0x([0-9a-fA-F]{4})'\/>[\s\S]*?<product id='0x([0-9a-fA-F]{4})'\/>[\s\S]*?<\/hostdev>/g)]
        .map(m => `${m[1]}:${m[2]}`);
      const desired = usbDevices.filter(d => /^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$/.test(d));
      const toAdd = desired.filter(d => !current.includes(d));
      const toRemove = current.filter(d => !desired.includes(d));
      for (const d of [...toAdd, ...toRemove]) {
        const [vendor, product] = d.split(":");
        const devXml = `<hostdev mode='subsystem' type='usb'><source><vendor id='0x${vendor}'/><product id='0x${product}'/></source></hostdev>`;
        const devPath = `/tmp/${name}-usb-${vendor}${product}-${Date.now()}.xml`;
        fs.writeFileSync(devPath, devXml);
        const action = toAdd.includes(d) ? "attach-device" : "detach-device";
        await virsh(`${action} ${sh(name)} ${sh(devPath)} ${liveFlags}`).catch(()=>{});
        fs.rmSync(devPath, {force:true});
      }
    }
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// IP actuelle d'une VM — utilisé par les raccourcis "dynamiques" (voir
// /api/app-shortcuts) pour résoudre l'adresse au moment du clic plutôt que
// de la figer à la création : une VM a une IP attribuée par DHCP, qui peut
// changer d'un démarrage à l'autre, contrairement à l'IP du NAS lui-même.
app.get("/api/vms/:n/ip", auth, async (req,res) => {
  try { res.json({ ip: await vmIp(req.params.n) }); }
  catch(e){ res.status(500).json({error:e.message}); }
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
// Les ISOs vivent désormais dans le dossier personnel (~/ISO), pas
// /var/lib/libvirt/images — cohérent avec l'app Fichiers et son raccourci ISO
app.get("/api/isos", auth, (req,res)=>{try{const d=isoDir();fs.mkdirSync(d,{recursive:true});res.json(fs.readdirSync(d).filter(f=>f.endsWith(".iso")).map(f=>({name:f,path:path.join(d,f),size:fs.statSync(path.join(d,f)).size})));}catch{res.json([]);}});
// Envoi direct depuis l'ordinateur de l'utilisateur — une ISO atterrit dans
// ~/ISO (visible dans la liste ISOs et l'app Fichiers), tout autre disque
// (qcow2/vdi/vmdk) atterrit dans /var/lib/libvirt/images comme avant, pour
// le sélecteur "importer un disque" de la création de VM
if (multer) {
  fs.mkdirSync("/var/lib/libvirt/images", {recursive:true});
  const upload = multer({
    storage: multer.diskStorage({
      destination: (req,file,cb)=>{
        const dir = file.originalname.toLowerCase().endsWith(".iso") ? isoDir() : "/var/lib/libvirt/images";
        fs.mkdirSync(dir, {recursive:true});
        cb(null, dir);
      },
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
// Une entrée par job jamais nettoyée = fuite mémoire réelle découverte sur
// cette session : les 23 points d'appel de runJob() (VMs, Docker, Magasin,
// sauvegardes, tâches planifiées...) accumulaient chacun leur log complet en
// mémoire pour toute la durée de vie du service, sans jamais être libérés —
// plausiblement la cause d'un NAS qui sature en RAM même "sans rien
// installé" après des semaines d'utilisation normale (chaque pull d'image,
// chaque sauvegarde, chaque vérification planifiée laissant une trace
// permanente). Purge différée (le temps que l'UI lise l'état final) +
// plafond dur en garde-fou si un usage inhabituel accélère le rythme.
const JOB_TTL_MS = 15 * 60 * 1000;
const JOB_MAX_COUNT = 300;
function runJob(cmd, onDone) {
  if (jobs.size >= JOB_MAX_COUNT) jobs.delete(jobs.keys().next().value);
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
  child.on("close", code=>{
    job.running=false;
    job.log.push(`\n=== ${code===0?"Terminé ✓":"Erreur (code "+code+")"} ===`);
    // onDone optionnel : permet à un appelant (ex. tâche de sauvegarde planifiée)
    // de réagir à la fin du job sans avoir à repoller /api/jobs/:id
    onDone?.(code===0, job.log.join(""));
    setTimeout(() => jobs.delete(jobId), JOB_TTL_MS).unref();
  });
  return jobId;
}
app.get("/api/jobs/:id", auth, (req,res)=>{
  const job = jobs.get(req.params.id);
  if(!job) return res.status(404).json({error:"Job introuvable"});
  res.json({log: job.log.join(""), running: job.running});
});
function sh(v){ return `'${String(v).replace(/'/g,"'\\''")}'`; }

// ══════════════════════════════════════════════════════════════════════════════
//  RÉSEAU (HÔTE) — Paramètres > Réseau (Général + Interface réseau), distinct
//  des réseaux virtuels libvirt (/api/networks) et Docker ci-dessus. Repose sur
//  nmcli (NetworkManager, présent dans la liste de paquets de l'ISO GravityOS)
//  quand disponible ; renvoie explicitement une erreur "indisponible" sinon
//  plutôt que d'inventer un résultat (même principe que getSmartStatus).
// ══════════════════════════════════════════════════════════════════════════════
let nmcliAvailable = null;
async function hasNmcli() {
  if (nmcliAvailable === null) {
    nmcliAvailable = await execAsync("command -v nmcli").then(()=>true).catch(()=>false);
  }
  return nmcliAvailable;
}
const VIRTUAL_IFACE_RE = /^(lo|docker\d*|veth|br-|virbr|tap|vnet|tun|wg|ppp)/;

async function listPhysicalIfaces() {
  const { stdout } = await execAsync("ip -j addr show 2>/dev/null").catch(()=>({stdout:"[]"}));
  let links = [];
  try { links = JSON.parse(stdout); } catch {}
  return links.filter(l => (l.link_type === "ether" || /^bond/.test(l.ifname)) && !VIRTUAL_IFACE_RE.test(l.ifname));
}
async function nmcliConnFor(ifname) {
  const { stdout } = await execAsync("nmcli -t -f DEVICE,CONNECTION device status 2>/dev/null").catch(()=>({stdout:""}));
  for (const line of stdout.split("\n")) {
    const [dev, ...rest] = line.split(":");
    const conn = rest.join(":");
    if (dev === ifname && conn && conn !== "--") return conn;
  }
  return null;
}
function prefixToMask(prefix) {
  const n = parseInt(prefix, 10) || 24;
  const bits = "1".repeat(n) + "0".repeat(32 - n);
  return bits.match(/.{8}/g).map(b => parseInt(b, 2)).join(".");
}
function maskToPrefix(mask) {
  return (mask || "255.255.255.0").split(".").reduce((acc, o) => acc + ((parseInt(o, 10) >>> 0).toString(2).match(/1/g) || []).length, 0);
}
async function nmField(conn, f) {
  const { stdout } = await execAsync(`nmcli -t -f ${f} con show ${sh(conn)} 2>/dev/null`).catch(()=>({stdout:""}));
  const idx = stdout.indexOf(":");
  return idx === -1 ? "" : stdout.slice(idx + 1).trim();
}

app.get("/api/network/general", auth, async(req,res)=>{
  try {
    const hostname = (await execAsync("hostname").catch(()=>({stdout:""}))).stdout.trim();
    const gw4 = (await execAsync("ip route show default 2>/dev/null").catch(()=>({stdout:""}))).stdout;
    const gw6 = (await execAsync("ip -6 route show default 2>/dev/null").catch(()=>({stdout:""}))).stdout;
    const gwMatch = gw4.match(/default via ([\d.]+)/);
    const gw6Match = gw6.match(/default via ([0-9a-fA-F:]+)/);
    const resolv = fs.existsSync("/etc/resolv.conf") ? fs.readFileSync("/etc/resolv.conf", "utf8") : "";
    const nameservers = [...resolv.matchAll(/^nameserver\s+(\S+)/gm)].map(m => m[1]);
    const nm = await hasNmcli();
    let dnsManual = false;
    if (nm) {
      const active = (await execAsync("nmcli -t -f NAME con show --active 2>/dev/null").catch(()=>({stdout:""}))).stdout.split("\n").filter(Boolean)[0];
      if (active) dnsManual = (await nmField(active, "ipv4.ignore-auto-dns")) === "yes";
    }
    res.json({
      hostname,
      gateway: gwMatch ? gwMatch[1] : null,
      gatewayV6: gw6Match ? gw6Match[1] : null,
      dnsManual,
      dnsPreferred: nameservers[0] || "",
      dnsAlternate: nameservers[1] || "",
      nmcliAvailable: nm,
    });
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/network/general", auth, async(req,res)=>{
  const { hostname, dnsManual, dnsPreferred, dnsAlternate } = req.body;
  try {
    if (hostname) await execAsync(`hostnamectl set-hostname ${sh(hostname.replace(/[^a-zA-Z0-9-]/g,""))}`).catch(()=>{});
    if (dnsManual !== undefined) {
      if (!(await hasNmcli())) {
        return res.status(503).json({ error: "Configuration DNS manuelle indisponible : NetworkManager (nmcli) n'est pas actif sur cette machine." });
      }
      const active = (await execAsync("nmcli -t -f NAME con show --active 2>/dev/null").catch(()=>({stdout:""}))).stdout.split("\n").filter(Boolean)[0];
      if (!active) throw new Error("Aucune connexion réseau active trouvée");
      if (dnsManual) {
        const dns = [dnsPreferred, dnsAlternate].filter(Boolean).join(" ");
        await execAsync(`nmcli con mod ${sh(active)} ipv4.ignore-auto-dns yes ipv4.dns ${sh(dns)}`);
      } else {
        await execAsync(`nmcli con mod ${sh(active)} ipv4.ignore-auto-dns no ipv4.dns ""`);
      }
      await execAsync(`nmcli con up ${sh(active)}`).catch(()=>{});
    }
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/network/proxy", auth, async(req,res)=>{
  try {
    const env = fs.existsSync("/etc/environment") ? fs.readFileSync("/etc/environment", "utf8") : "";
    const m = env.match(/^https?_proxy=["']?http:\/\/([^:"'\s]+):(\d+)["']?/mi);
    res.json({ enabled: !!m, address: m ? m[1] : "", port: m ? m[2] : "" });
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/network/proxy", auth, async(req,res)=>{
  const { enabled, address, port } = req.body;
  try {
    let env = fs.existsSync("/etc/environment") ? fs.readFileSync("/etc/environment", "utf8") : "";
    env = env.split("\n").filter(l => !/^(https?|ftp)_proxy=/i.test(l)).join("\n").trim();
    if (enabled && address && port) {
      const url = `http://${address}:${port}`;
      env += (env ? "\n" : "") + `http_proxy="${url}"\nhttps_proxy="${url}"\n`;
    }
    fs.writeFileSync("/etc/environment", env.trim() + "\n");
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

function ifaceKind(ifname) {
  if (/^bond/.test(ifname)) return "bond";
  // Détection fiable indépendante du nom : /sys/class/net/<if>/wireless
  // n'existe que pour les interfaces Wi-Fi (piloté par le driver, pas une
  // convention de nommage) — repli sur le préfixe udev "wl*" si absent.
  try { if (fs.existsSync(`/sys/class/net/${ifname}/wireless`)) return "wifi"; } catch {}
  if (/^wl/.test(ifname)) return "wifi";
  return "ethernet";
}
app.get("/api/network/interfaces", auth, async(req,res)=>{
  try {
    const ifaces = await listPhysicalIfaces();
    const nm = await hasNmcli();
    const out = await Promise.all(ifaces.map(async l => {
      const addr4 = (l.addr_info || []).find(a => a.family === "inet");
      const connection = nm ? await nmcliConnFor(l.ifname).catch(()=>null) : null;
      return {
        name: l.ifname,
        mac: l.address || "",
        connected: l.operstate === "UP",
        mtu: l.mtu,
        ipv4: addr4 ? `${addr4.local}/${addr4.prefixlen}` : null,
        connection,
        type: ifaceKind(l.ifname),
      };
    }));
    res.json(out);
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/network/interfaces/:name/config", auth, async(req,res)=>{
  const name = req.params.name.replace(/[^a-zA-Z0-9.:_-]/g,"");
  try {
    const nm = await hasNmcli();
    if (!nm) {
      const { stdout } = await execAsync(`ip -j addr show ${sh(name)} 2>/dev/null`).catch(()=>({stdout:"[]"}));
      let l = null; try { l = JSON.parse(stdout)[0] || null; } catch {}
      const addr4 = l && (l.addr_info || []).find(a => a.family === "inet");
      return res.json({
        available: false,
        ipv4: { method: addr4 ? "static" : "dhcp", address: addr4?.local || "", netmask: addr4 ? prefixToMask(addr4.prefixlen) : "255.255.255.0", gateway: "", dns: "" },
        mtuManual: false, mtu: l?.mtu || 1500,
        vlanEnabled: false, vlanId: "", setDefault: true,
      });
    }
    const conn = await nmcliConnFor(name);
    if (!conn) return res.json({ available: true, noConnection: true });
    const method = await nmField(conn, "ipv4.method");
    const addresses = await nmField(conn, "ipv4.addresses");
    const gateway = await nmField(conn, "ipv4.gateway");
    const dns = await nmField(conn, "ipv4.dns");
    const mtu = await nmField(conn, "802-3-ethernet.mtu");
    const neverDefault = await nmField(conn, "ipv4.never-default");
    const [address, prefix] = (addresses || "").split("/");
    res.json({
      available: true,
      connection: conn,
      ipv4: {
        method: method === "auto" ? "dhcp" : "static",
        address: address || "",
        netmask: prefix ? prefixToMask(prefix) : "255.255.255.0",
        gateway: gateway || "",
        dns: dns || "",
      },
      mtuManual: !!(mtu && mtu !== "" && mtu !== "0" && mtu !== "auto"),
      mtu: mtu && mtu !== "" && mtu !== "0" && mtu !== "auto" ? parseInt(mtu, 10) : 1500,
      vlanEnabled: false, vlanId: "",
      setDefault: neverDefault !== "yes",
    });
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/network/interfaces/:name/config", auth, async(req,res)=>{
  const name = req.params.name.replace(/[^a-zA-Z0-9.:_-]/g,"");
  if (!(await hasNmcli())) {
    return res.status(503).json({ error: "Configuration indisponible : NetworkManager (nmcli) n'est pas actif sur cette machine." });
  }
  try {
    const conn = (await nmcliConnFor(name)) || name;
    const { method, address, netmask, gateway, dns } = req.body.ipv4 || {};
    const mtuManual = !!req.body.mtuManual;
    const mtu = req.body.mtu;
    if (method === "dhcp") {
      await execAsync(`nmcli con mod ${sh(conn)} ipv4.method auto`);
    } else {
      const prefix = maskToPrefix(netmask);
      await execAsync(`nmcli con mod ${sh(conn)} ipv4.method manual ipv4.addresses ${sh(`${address}/${prefix}`)} ipv4.gateway ${sh(gateway || "")} ipv4.dns ${sh(dns || "")}`);
    }
    await execAsync(`nmcli con mod ${sh(conn)} 802-3-ethernet.mtu ${mtuManual && mtu ? sh(String(mtu)) : "auto"}`).catch(()=>{});
    await execAsync(`nmcli con mod ${sh(conn)} ipv4.never-default ${req.body.setDefault ? "no" : "yes"}`).catch(()=>{});
    if (req.body.vlanEnabled && req.body.vlanId) {
      const vlanId = String(req.body.vlanId).replace(/[^0-9]/g,"");
      const vlanConn = `${name}.${vlanId}`;
      const exists = (await execAsync("nmcli -t -f NAME con show 2>/dev/null").catch(()=>({stdout:""}))).stdout.split("\n").includes(vlanConn);
      if (!exists) await execAsync(`nmcli con add type vlan con-name ${sh(vlanConn)} dev ${sh(name)} id ${sh(vlanId)}`);
      await execAsync(`nmcli con up ${sh(vlanConn)}`).catch(()=>{});
    }
    await execAsync(`nmcli con up ${sh(conn)}`);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/network/bonds", auth, async(req,res)=>{
  if (!(await hasNmcli())) {
    return res.status(503).json({ error: "Indisponible : NetworkManager (nmcli) n'est pas actif sur cette machine." });
  }
  const { name, mode, slaves } = req.body;
  const safeName = (name || "").replace(/[^a-zA-Z0-9_-]/g,"");
  if (!safeName || !Array.isArray(slaves) || slaves.length < 2) {
    return res.status(400).json({ error: "Nom de liaison et au moins 2 interfaces requis" });
  }
  try {
    await execAsync(`nmcli con add type bond ifname ${sh(safeName)} mode ${sh(mode || "active-backup")}`);
    for (const s of slaves) {
      const safeSlave = String(s).replace(/[^a-zA-Z0-9.:_-]/g,"");
      await execAsync(`nmcli con add type ethernet ifname ${sh(safeSlave)} master ${sh(safeName)}`);
    }
    await execAsync(`nmcli con up ${sh(safeName)}`);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/network/vpn-profiles", auth, async(req,res)=>{
  if (!(await hasNmcli())) return res.json([]);
  try {
    const { stdout } = await execAsync("nmcli -t -f NAME,TYPE,DEVICE con show 2>/dev/null").catch(()=>({stdout:""}));
    res.json(stdout.split("\n").filter(Boolean).map(l => {
      const [name, type, device] = l.split(":");
      return { name, type, active: !!device };
    }).filter(p => p.type === "vpn"));
  } catch { res.json([]); }
});
if (multer) {
  const vpnUpload = multer({ dest: "/tmp/gravity-vpn-upload" });
  app.post("/api/network/vpn-profiles", auth, vpnUpload.single("file"), async(req,res)=>{
    if (!(await hasNmcli())) return res.status(503).json({ error: "Indisponible : NetworkManager (nmcli) n'est pas actif sur cette machine." });
    if (!req.file) return res.status(400).json({ error: "Fichier .ovpn requis" });
    try {
      await execAsync(`nmcli con import type openvpn file ${sh(req.file.path)}`);
      res.json({ok:true});
    } catch(e){ res.status(500).json({error:e.message}); }
    finally { fs.unlink(req.file.path, ()=>{}); }
  });
}
app.post("/api/network/vpn-profiles/:name/toggle", auth, async(req,res)=>{
  try { await execAsync(`nmcli con ${req.body.active ? "up" : "down"} ${sh(req.params.name)}`); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.delete("/api/network/vpn-profiles/:name", auth, async(req,res)=>{
  try { await execAsync(`nmcli con delete ${sh(req.params.name)}`); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  TERMINAL — Paramètres > Terminal (activation SSH + port)
// ══════════════════════════════════════════════════════════════════════════════
const SSHD_CONFIG = "/etc/ssh/sshd_config";
app.get("/api/terminal/ssh", auth, async(req,res)=>{
  try {
    const available = await execAsync("command -v sshd").then(()=>true).catch(()=>false);
    if (!available) return res.json({available:false, active:false, port:22});
    const active = (await execAsync("systemctl is-active ssh 2>/dev/null").catch(e=>({stdout:e.stdout||"inactive"}))).stdout.trim()==="active";
    let port = 22;
    try {
      const m = fs.readFileSync(SSHD_CONFIG,"utf8").match(/^\s*Port\s+(\d+)/m);
      if (m) port = parseInt(m[1],10);
    } catch {}
    res.json({available:true, active, port});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/terminal/ssh", auth, async(req,res)=>{
  const available = await execAsync("command -v sshd").then(()=>true).catch(()=>false);
  if (!available) return res.status(503).json({error:"SSH (openssh-server) n'est pas installé sur cette machine."});
  const safePort = parseInt(req.body.port,10);
  if (!safePort || safePort<1 || safePort>65535) return res.status(400).json({error:"Port invalide (1-65535)"});
  try {
    let conf = fs.readFileSync(SSHD_CONFIG,"utf8");
    conf = /^\s*#?\s*Port\s+\d+/m.test(conf) ? conf.replace(/^\s*#?\s*Port\s+\d+/m, `Port ${safePort}`) : `Port ${safePort}\n${conf}`;
    fs.writeFileSync(SSHD_CONFIG, conf);
    await execAsync("sshd -t"); // valide la config avant de l'appliquer
    await execAsync(`ufw allow ${safePort}/tcp`).catch(()=>{});
    if (req.body.active) {
      await execAsync("systemctl enable ssh 2>/dev/null").catch(()=>{});
      await execAsync("systemctl restart ssh");
    } else {
      await execAsync("systemctl disable --now ssh 2>/dev/null").catch(()=>{});
    }
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:"Erreur SSH : "+e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  OPTIONS RÉGIONALES — Paramètres > Options régional
//  Seul le français est disponible pour le moment (interface WebUI non
//  internationalisée) — seule la langue d'affichage (locale système) a un
//  effet réel ; langue de notification et page de code restent informatifs.
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/system/locale", auth, async(req,res)=>{
  try {
    const { stdout } = await execAsync("localectl status 2>/dev/null").catch(()=>({stdout:""}));
    const m = stdout.match(/LANG=(\S+)/);
    res.json({ lang: m ? m[1] : "fr_FR.UTF-8" });
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/system/locale", auth, async(req,res)=>{
  try {
    await execAsync(`localectl set-locale LANG=fr_FR.UTF-8`);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Heure (sous-onglet "Heure" d'Options régional) ──────────────────────────
app.get("/api/system/time", auth, async(req,res)=>{
  try {
    const { stdout } = await execAsync("timedatectl show -p Timezone -p NTPSynchronized --value 2>/dev/null");
    const [timezone] = stdout.split("\n").filter(Boolean);
    const localTime = (await execAsync("date '+%Y-%m-%d %H:%M:%S'").catch(()=>({stdout:""}))).stdout.trim();
    res.json({ timezone: timezone || "Europe/Paris", localTime });
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.get("/api/system/timezones", auth, async(req,res)=>{
  try {
    const { stdout } = await execAsync("timedatectl list-timezones 2>/dev/null");
    res.json(stdout.split("\n").filter(Boolean));
  } catch { res.json(["Europe/Paris"]); }
});
app.post("/api/system/time", auth, async(req,res)=>{
  const tz = (req.body.timezone||"").replace(/[^a-zA-Z0-9/_-]/g,"");
  if (!tz) return res.status(400).json({error:"Fuseau horaire requis"});
  try {
    await execAsync(`timedatectl set-timezone ${sh(tz)}`);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Service NTP (sous-onglet "Service NTP" d'Options régional) ─────────────
const TIMESYNCD_CONFIG = "/etc/systemd/timesyncd.conf";
app.get("/api/system/ntp", auth, async(req,res)=>{
  try {
    const available = await execAsync("command -v timedatectl").then(()=>fs.existsSync("/lib/systemd/systemd-timesyncd")||fs.existsSync("/usr/lib/systemd/systemd-timesyncd")).catch(()=>false);
    const active = (await execAsync("timedatectl show -p NTP --value 2>/dev/null").catch(()=>({stdout:"no"}))).stdout.trim()==="yes";
    let server = "";
    try {
      const conf = fs.readFileSync(TIMESYNCD_CONFIG,"utf8");
      const m = conf.match(/^[ \t]*NTP[ \t]*=[ \t]*(.*)$/m);
      if (m) server = m[1].trim();
    } catch {}
    res.json({ available, active, server: server || "" });
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/system/ntp", auth, async(req,res)=>{
  const available = fs.existsSync("/lib/systemd/systemd-timesyncd")||fs.existsSync("/usr/lib/systemd/systemd-timesyncd");
  if (!available) return res.status(503).json({error:"systemd-timesyncd n'est pas installé sur cette machine (environnement de test)."});
  const server = String(req.body.server||"").trim().replace(/[^a-zA-Z0-9.\s-]/g,"");
  try {
    let conf = fs.existsSync(TIMESYNCD_CONFIG) ? fs.readFileSync(TIMESYNCD_CONFIG,"utf8") : "[Time]\n";
    if (!/\[Time\]/.test(conf)) conf += "\n[Time]\n";
    conf = /^[ \t]*#?[ \t]*NTP[ \t]*=/m.test(conf) ? conf.replace(/^[ \t]*#?[ \t]*NTP[ \t]*=.*$/m, `NTP=${server}`) : conf.replace(/\[Time\]/, `[Time]\nNTP=${server}`);
    fs.writeFileSync(TIMESYNCD_CONFIG, conf);
    await execAsync(`timedatectl set-ntp ${req.body.active ? "true" : "false"}`);
    await execAsync("systemctl restart systemd-timesyncd").catch(()=>{});
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  NOTIFICATIONS PAR E-MAIL — Paramètres > Notifications > E-mail
//  Envoi réel via le client SMTP intégré à curl (déjà présent dans l'ISO,
//  pas de dépendance npm supplémentaire type nodemailer nécessaire).
// ══════════════════════════════════════════════════════════════════════════════
const EMAIL_NOTIF_CONFIG = `${CFG}/notifications-email.json`;
function loadEmailNotifConfig() {
  try { return JSON.parse(fs.readFileSync(EMAIL_NOTIF_CONFIG,"utf8")); }
  catch { return { enabled:false, provider:"custom", smtpHost:"", smtpPort:"587", authRequired:true, username:"", password:"", tlsRequired:true, senderName:"", senderEmail:"" }; }
}
function saveEmailNotifConfig(c) {
  fs.mkdirSync(CFG,{recursive:true});
  fs.writeFileSync(EMAIL_NOTIF_CONFIG, JSON.stringify(c,null,2), {mode:0o600});
}

app.get("/api/notifications/email", auth, (req,res)=>{
  const { password, ...rest } = loadEmailNotifConfig();
  res.json({ ...rest, hasPassword: !!password });
});

app.post("/api/notifications/email", auth, (req,res)=>{
  const prev = loadEmailNotifConfig();
  const b = req.body;
  const next = {
    enabled: !!b.enabled,
    provider: "custom",
    smtpHost: String(b.smtpHost||"").trim(),
    smtpPort: String(b.smtpPort||"587").trim(),
    authRequired: !!b.authRequired,
    username: String(b.username||"").trim(),
    // Champ vide = on garde le mot de passe déjà enregistré (comme les
    // remotes de sauvegarde) plutôt que d'écraser avec une valeur vide.
    password: b.password ? b.password : prev.password,
    tlsRequired: !!b.tlsRequired,
    senderName: String(b.senderName||"").trim(),
    senderEmail: String(b.senderEmail||"").trim(),
  };
  saveEmailNotifConfig(next);
  res.json({ok:true});
});

function buildTestEmail({senderName, senderEmail}, to) {
  const date = new Date().toUTCString();
  return `From: ${senderName ? `${senderName} <${senderEmail}>` : senderEmail}
To: ${to}
Subject: Test de notification GravityOS
Date: ${date}

Ceci est un e-mail de test envoye depuis Parametres > Notifications > E-mail sur GravityOS.
Si vous recevez ce message, la configuration SMTP fonctionne correctement.
`;
}

app.post("/api/notifications/email/test", auth, async(req,res)=>{
  const c = loadEmailNotifConfig();
  if (!c.smtpHost || !c.senderEmail) return res.status(400).json({error:"Serveur SMTP et adresse e-mail de l'expéditeur requis"});
  const to = String(req.body.to||"").trim() || c.senderEmail;
  const tmp = path.join("/tmp", `gravity-test-mail-${crypto.randomBytes(6).toString("hex")}.eml`);
  try {
    fs.writeFileSync(tmp, buildTestEmail(c, to));
    const tlsFlag = c.tlsRequired ? "--ssl-reqd" : "";
    const authFlag = c.authRequired && c.username ? `--user ${sh(`${c.username}:${c.password}`)}` : "";
    const cmd = `curl -sS --url ${sh(`smtp://${c.smtpHost}:${c.smtpPort}`)} --mail-from ${sh(c.senderEmail)} --mail-rcpt ${sh(to)} --upload-file ${sh(tmp)} ${authFlag} ${tlsFlag}`;
    await execAsync(cmd);
    res.json({ok:true, to});
  } catch(e){ res.status(500).json({error:"Échec de l'envoi : "+(e.stderr||e.message).toString().trim()}); }
  finally { fs.unlink(tmp, ()=>{}); }
});

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
// Sous Volume 1 (et non plus /srv/docker/compose, un dossier hors des volumes
// donc invisible/inaccessible depuis l'app Fichiers) — demande explicite de
// l'utilisateur, notamment pour retrouver facilement le docker-compose.yml et
// les données persistantes d'une app du Magasin (ex: /srv/volumes/volume1/
// Docker/store-romm). S'applique à TOUS les projets Compose, pas seulement
// ceux du Magasin (mêmes stacks listées dans l'onglet "Projets" de l'app
// Docker) — cohérence : un seul et même dossier de stockage pour tous.
const COMPOSE_DIR = path.join(volume1Path(), "Docker");
// Migration one-shot : une installation existante peut avoir ses stacks sous
// l'ancien chemin — on les déplace plutôt que de les rendre invisibles.
(function migrateComposeDir(){
  const legacy = "/srv/docker/compose";
  try {
    if (fs.existsSync(legacy) && !fs.existsSync(COMPOSE_DIR)) {
      fs.mkdirSync(path.dirname(COMPOSE_DIR), {recursive:true});
      fs.renameSync(legacy, COMPOSE_DIR);
    }
  } catch (e) { console.error("Migration COMPOSE_DIR échouée:", e.message); }
})();

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
        memPct: st?.memPct || null,
        composeProject: c.Labels?.["com.docker.compose.project"] || null
      };
    }));
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Docker répond HTTP 304 (pas une vraie erreur, "déjà dans l'état demandé")
// quand on démarre un conteneur déjà démarré ou qu'on en arrête un déjà
// arrêté — dockerode le rejette quand même comme n'importe quel code non-2xx,
// ce qui remontait un "Action impossible" trompeur à l'utilisateur alors que
// le conteneur était en réalité déjà dans l'état voulu (souvent une simple
// course entre la liste affichée et le clic — le conteneur a redémarré tout
// seul entre-temps, ex. politique "restart" en boucle de crash). Traité
// comme un succès plutôt qu'une erreur.
app.post("/api/containers/:id/start", auth, async(req,res)=>{
  try{await docker.getContainer(req.params.id).start();res.json({ok:true});}
  catch(e){ if(e.statusCode===304) return res.json({ok:true}); res.status(500).json({error:e.message}); }
});
app.post("/api/containers/:id/stop", auth, async(req,res)=>{
  try{await docker.getContainer(req.params.id).stop();res.json({ok:true});}
  catch(e){ if(e.statusCode===304) return res.json({ok:true}); res.status(500).json({error:e.message}); }
});
app.post("/api/containers/:id/restart", auth, async(req,res)=>{try{await docker.getContainer(req.params.id).restart();res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
// "Forcer l'arrêt" — SIGKILL immédiat plutôt que le SIGTERM+délai de grâce de
// /stop, pour un conteneur qui ne répond plus (demande explicite de l'utilisateur).
app.post("/api/containers/:id/kill", auth, async(req,res)=>{
  try{await docker.getContainer(req.params.id).kill();res.json({ok:true});}
  catch(e){ if(e.statusCode===304 || e.statusCode===409) return res.json({ok:true}); res.status(500).json({error:e.message}); }
});
app.delete("/api/containers/:id",       auth, async(req,res)=>{try{await docker.getContainer(req.params.id).remove({force:true});res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.get("/api/containers/:id/logs", auth, async(req,res)=>{
  try { const {stdout} = await execAsync(`docker logs --tail 300 ${sh(req.params.id)} 2>&1`); res.type("text/plain").send(stdout); }
  catch(e){ res.status(500).json({error:e.message}); }
});
// Détail complet d'un conteneur — onglets "Général" (infos) et
// "Configuration" (formulaire pré-rempli, éditable seulement si le
// conteneur n'appartient à aucun stack et est arrêté) du détail conteneur.
app.get("/api/containers/:id/inspect", auth, async(req,res)=>{
  if(!docker) return res.status(500).json({error:"Docker indisponible"});
  try {
    const c = docker.getContainer(req.params.id);
    const d = await c.inspect();
    const portBindings = d.HostConfig?.PortBindings || {};
    const ports = Object.entries(portBindings).flatMap(([containerPort, bindings]) =>
      (bindings || []).map(b => ({ host: b.HostPort, container: containerPort.split("/")[0], proto: containerPort.split("/")[1] || "tcp" })));
    const volumes = (d.Mounts || []).filter(m => m.Type === "bind").map(m => ({ host: m.Source, container: m.Destination, ro: !m.RW }));
    const env = (d.Config?.Env || []).map(e => { const i = e.indexOf("="); return { key: e.slice(0,i), value: e.slice(i+1) }; });
    res.json({
      id: d.Id.slice(0,12),
      name: d.Name.replace(/^\//,""),
      image: d.Config?.Image,
      state: d.State?.Status,
      created: d.Created,
      startedAt: d.State?.StartedAt,
      restartPolicy: d.HostConfig?.RestartPolicy?.Name || "no",
      restartCount: d.RestartCount,
      network: Object.keys(d.NetworkSettings?.Networks || {})[0] || null,
      command: (d.Config?.Cmd || []).join(" "),
      composeProject: d.Config?.Labels?.["com.docker.compose.project"] || null,
      ports, volumes, env,
    });
  } catch(e){ res.status(404).json({error:"Conteneur introuvable"}); }
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
      const tag = i.RepoTags?.[0];
      if (tag) {
        const sep = tag.lastIndexOf(":");
        return { id:i.Id.replace("sha256:","").slice(0,12), repo:tag.slice(0,sep), tag:tag.slice(sep+1), size:i.Size, created:i.Created, dangling:false };
      }
      // Image "orpheline" — un tag repris par une image plus récente après un
      // pull (mise à jour), ou couche intermédiaire de build ; RepoTags est
      // alors vide côté Docker (affiché "<none>:<none>" par `docker images`).
      // RepoDigests garde trace du dépôt d'origine quand elle existe encore.
      const digestRef = i.RepoDigests?.[0];
      const repo = digestRef ? digestRef.slice(0, digestRef.lastIndexOf("@")) : null;
      return { id:i.Id.replace("sha256:","").slice(0,12), repo, tag:null, size:i.Size, created:i.Created, dangling:true };
    }));
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/docker/images/pull", auth, (req,res)=>{
  const { image } = req.body;
  if(!image || !/^[a-zA-Z0-9._\-\/:]+$/.test(image)) return res.status(400).json({error:"Nom d'image invalide"});
  const jobId = runJob(`docker pull ${sh(image)} 2>&1`);
  res.json({ok:true, jobId});
});
// Vérifie si une nouvelle version de l'image est disponible sur le registre —
// même principe que checkDockerImageUpdates() (tâche planifiée système) : un
// "docker pull" ne perturbe jamais un conteneur déjà démarré, seule une
// recréation applique l'image mise à jour (bouton "Mettre à jour" séparé).
app.get("/api/docker/images/check-update", auth, async(req,res)=>{
  const ref = req.query.ref;
  if(!ref || !/^[a-zA-Z0-9._\-\/:]+$/.test(ref)) return res.status(400).json({error:"Image invalide"});
  if(!docker) return res.status(500).json({error:"Docker indisponible"});
  try {
    const before = await docker.getImage(ref).inspect().catch(()=>null);
    await execAsync(`docker pull ${sh(ref)} 2>&1`);
    const after = await docker.getImage(ref).inspect().catch(()=>null);
    res.json({ hasUpdate: !!(before?.Id && after?.Id && before.Id !== after.Id) });
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Applique la mise à jour déjà téléchargée (voir check-update ci-dessus) à
// tous les conteneurs qui référencent directement cette image — recrée
// chaque projet Compose concerné (up -d --force-recreate) et chaque
// conteneur autonome à l'identique (mêmes ports/volumes/env/politique de
// redémarrage relus via inspect, comme "Recréer" dans le détail conteneur),
// pour ne perdre aucun réglage. Si l'image n'est utilisée par aucun
// conteneur, se contente de la télécharger.
app.post("/api/docker/images/update", auth, async(req,res)=>{
  const { ref } = req.body;
  if(!ref || !/^[a-zA-Z0-9._\-\/:]+$/.test(ref)) return res.status(400).json({error:"Image invalide"});
  if(!docker) return res.status(500).json({error:"Docker indisponible"});
  try {
    const containers = await docker.listContainers({all:true});
    const affected = containers.filter(c => c.Image === ref);
    const steps = [`echo "=== Telechargement de ${ref} ===" && docker pull ${sh(ref)}`];

    const projects = [...new Set(
      affected.filter(c => c.Labels?.["com.docker.compose.project"]).map(c => c.Labels["com.docker.compose.project"])
    )];
    for (const project of projects) {
      const dir = path.join(COMPOSE_DIR, project.replace(/[^a-zA-Z0-9_-]/g,""));
      if (fs.existsSync(path.join(dir,"docker-compose.yml"))) {
        steps.push(`echo "=== Recreation du projet ${project} ===" && cd ${sh(dir)} && ${composeCmd()} up -d --force-recreate`);
      }
    }

    const standalone = affected.filter(c => !c.Labels?.["com.docker.compose.project"]);
    for (const c of standalone) {
      const d = await docker.getContainer(c.Id).inspect();
      const name = d.Name.replace(/^\//,"");
      const args = ["run","-d","--name", sh(name), "--restart", sh(d.HostConfig?.RestartPolicy?.Name || "unless-stopped")];
      const network = Object.keys(d.NetworkSettings?.Networks||{})[0];
      if (network && network !== "bridge") args.push("--network", sh(network));
      for (const [containerPort, bindings] of Object.entries(d.HostConfig?.PortBindings || {})) {
        const proto = containerPort.split("/")[1] || "tcp";
        for (const b of (bindings||[])) args.push("-p", sh(`${b.HostPort}:${containerPort.split("/")[0]}${proto==="udp"?"/udp":""}`));
      }
      for (const m of (d.Mounts||[])) if (m.Type === "bind") args.push("-v", sh(`${m.Source}:${m.Destination}${m.RW ? "" : ":ro"}`));
      for (const e of (d.Config?.Env||[])) args.push("-e", sh(e));
      args.push(sh(ref));
      // Chaque argument de la commande individuellement échappé (pas
      // rejoint puis poussé tel quel) — le CMD par défaut de nombreuses
      // images contient des métacaractères shell (ex: nginx = ["nginx",
      // "-g","daemon off;"], le ";" cassait la commande une fois passée
      // dans le script bash de ce job, repéré en testant cette fonction).
      for (const part of (d.Config?.Cmd || [])) args.push(sh(part));
      steps.push(`echo "=== Recreation du conteneur ${name} ===" && docker stop ${sh(c.Id)} >/dev/null 2>&1; docker rm ${sh(c.Id)} >/dev/null 2>&1; docker ${args.join(" ")}`);
    }

    // Regroupé dans un bloc { ...; } pour que 2>&1 s'applique à toutes les
    // étapes (pull + chaque recréation), pas seulement à la dernière.
    const jobId = runJob("{ " + steps.join(" ; ") + " ; } 2>&1");
    res.json({ok:true, jobId, containers: affected.length});
  } catch(e){ res.status(500).json({error:e.message}); }
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
async function stackHasRunningContainer(name) {
  if (!docker) return false;
  const cs = await docker.listContainers({all:true}).catch(()=>[]);
  return cs.some(c => c.Labels?.["com.docker.compose.project"] === name && c.State === "running");
}
// "Forcer l'arrêt" d'un projet — SIGKILL immédiat à tous ses conteneurs
// (docker compose stop/down envoient un SIGTERM avec délai de grâce).
app.post("/api/docker/compose/:name/kill", auth, (req,res)=>{
  try {
    const dir = path.join(COMPOSE_DIR, req.params.name.replace(/[^a-zA-Z0-9_-]/g,""));
    if(!fs.existsSync(path.join(dir,"docker-compose.yml"))) return res.status(404).json({error:"Stack introuvable"});
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} kill 2>&1`);
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/docker/compose/:name/restart", auth, (req,res)=>{
  try {
    const dir = path.join(COMPOSE_DIR, req.params.name.replace(/[^a-zA-Z0-9_-]/g,""));
    if(!fs.existsSync(path.join(dir,"docker-compose.yml"))) return res.status(404).json({error:"Stack introuvable"});
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} restart 2>&1`);
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/docker/compose/:name/recreate", auth, (req,res)=>{
  try {
    const dir = path.join(COMPOSE_DIR, req.params.name.replace(/[^a-zA-Z0-9_-]/g,""));
    if(!fs.existsSync(path.join(dir,"docker-compose.yml"))) return res.status(404).json({error:"Stack introuvable"});
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} up -d --force-recreate 2>&1`);
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Suppression d'un projet — retire aussi les images devenues orphelines
// (même logique que la désinstallation d'une app du Magasin) et le
// raccourci associé s'il en existait un.
app.delete("/api/docker/compose/:name", auth, async(req,res)=>{
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,"");
  const dir = path.join(COMPOSE_DIR, name);
  const composeFile = path.join(dir, "docker-compose.yml");
  if(!fs.existsSync(composeFile)) return res.status(404).json({error:"Stack introuvable"});
  try {
    const images = [...fs.readFileSync(composeFile, "utf8").matchAll(/^\s*image:\s*(\S+)\s*$/gm)].map(m => m[1]);
    const storeAppId = name.startsWith("store-") ? name.slice(6) : null;
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} down -v 2>&1 && rm -rf ${sh(dir)}`, async (ok) => {
      // Callback fire-and-forget (pas de req/res ici, le job est déjà
      // répondu) : tout englobé dans un seul try/catch — une erreur
      // isolée (ex: écriture du fichier de raccourcis) ne doit jamais
      // remonter en rejection non gérée.
      try {
        if (!ok) return;
        if (storeAppId) saveAppShortcuts(loadAppShortcuts().filter(s => s.storeAppId !== storeAppId));
        if (!docker || !images.length) return;
        const remaining = await docker.listContainers({all:true});
        for (const image of images) {
          if (!remaining.some(c => c.Image === image)) await docker.getImage(image).remove({force:true}).catch(()=>{});
        }
      } catch (e) { console.error("Nettoyage post-suppression du projet échoué:", e.message); }
    });
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Édition du docker-compose.yml d'un projet — seulement autorisée à l'arrêt
// (demande explicite de l'utilisateur, onglet "Configuration" du détail
// projet) : modifier le fichier d'un projet en cours d'exécution le
// désynchroniserait de ce qui tourne réellement tant que "up -d" n'est pas
// relancé, ce qui prêterait à confusion dans l'UI.
app.put("/api/docker/compose/:name", auth, async(req,res)=>{
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g,"");
  const { content } = req.body;
  if(!content || !content.trim()) return res.status(400).json({error:"Contenu docker-compose.yml requis"});
  try {
    const dir = path.join(COMPOSE_DIR, name);
    const file = path.join(dir, "docker-compose.yml");
    if(!fs.existsSync(file)) return res.status(404).json({error:"Stack introuvable"});
    if(await stackHasRunningContainer(name)) return res.status(409).json({error:"Arrêtez le projet avant de modifier sa configuration"});
    fs.writeFileSync(file, content);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Journal d'un projet — logs agrégés de tous ses services (pas seulement
// ceux du dernier démarrage) : plus utile au quotidien que le seul log de
// création, et disponible même après un redémarrage du backend (les jobs
// en mémoire ne survivent pas à un restart).
app.get("/api/docker/compose/:name/logs", auth, async(req,res)=>{
  try {
    const dir = path.join(COMPOSE_DIR, req.params.name.replace(/[^a-zA-Z0-9_-]/g,""));
    if(!fs.existsSync(path.join(dir,"docker-compose.yml"))) return res.status(404).json({error:"Stack introuvable"});
    const {stdout} = await execAsync(`cd ${sh(dir)} && ${composeCmd()} logs --no-color --tail 300 2>&1`);
    res.type("text/plain").send(stdout);
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  MAGASIN — catalogue d'apps converties depuis umbrel-apps (voir
//  scripts/umbrel-catalog/, outil de curation hors-ligne). Chaque entrée
//  installée devient une stack Docker Compose comme les autres, préfixée
//  "store-" pour ne pas entrer en collision avec les stacks créées à la
//  main dans l'app Docker.
// ══════════════════════════════════════════════════════════════════════════════
const STORE_CATALOG_FILE = path.join(__dirname, "store-catalog.json");
function loadStoreCatalog() {
  try { return JSON.parse(fs.readFileSync(STORE_CATALOG_FILE, "utf8")); }
  catch { return []; }
}
function storeDir(id) { return path.join(COMPOSE_DIR, `store-${id}`); }

// Les apps umbrel-apps portées par scripts/umbrel-catalog/ peuvent contenir
// des placeholders ${APP_SEED}/${APP_PASSWORD}/${APP_XXX_SECRET_KEY}... —
// simples secrets aléatoires générés par umbrelOS à l'installation, sans
// équivalent GravityOS (voir convert.js, AUTO_SECRET_VAR_RE). Le même
// catalogue étant partagé par toutes les installations GravityOS, on ne
// peut pas figer une valeur dans store-catalog.json : elle est générée ici,
// à l'installation, une fois par app installée — puis écrite dans un
// fichier ".env" à côté du compose plutôt que réécrite en dur dans le YAML :
// Docker Compose charge automatiquement le ".env" du dossier du projet et
// résout lui-même les ${APP_XXX} restés dans le compose (mécanisme natif,
// pas de remplacement de texte fait à la main ici).
function generateSecrets(secretVars) {
  const generated = {};
  for (const name of secretVars || []) generated[name] = crypto.randomBytes(24).toString("hex");
  return generated;
}
function writeEnvFile(dir, values) {
  const lines = Object.entries(values).map(([k, v]) => `${k}=${v}`);
  if (lines.length) fs.writeFileSync(path.join(dir, ".env"), lines.join("\n") + "\n");
}

// Préfixe figé dans composeYaml par convert.js (voir remapPaths) au moment de
// la conversion du catalogue umbrel-apps — sert à repérer/remplacer les
// bind-mounts de données persistantes, quel que soit le dossier réellement
// choisi à l'installation (catalogue partagé par toutes les installations,
// donc ce préfixe ne peut pas être changé rétroactivement dans le catalogue
// lui-même). Le dossier proposé par défaut au wizard, lui, est
// storeDir(id) — même dossier que le docker-compose.yml (demande explicite
// de l'utilisateur : un seul dossier par app sous Volume 1, pas un dossier
// "AppData" séparé et surtout pas /srv/docker/compose, invisible depuis
// l'app Fichiers).
function catalogAppDataPrefix(id) { return `/srv/volumes/volume1/AppData/${id}`; }
function appUsesPersistentData(app_) { return app_.composeYaml.includes(catalogAppDataPrefix(app_.id)); }

app.get("/api/store/apps", auth, (req,res)=>{
  try {
    const catalog = loadStoreCatalog();
    res.json(catalog.map(app => ({
      ...app,
      composeYaml: undefined, // pas besoin côté liste, alourdit la réponse
      installed: fs.existsSync(path.join(storeDir(app.id), "docker-compose.yml")),
      hasPersistentData: appUsesPersistentData(app),
    })));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/store/apps/:id/install", auth, async(req,res)=>{
  const id = req.params.id.replace(/[^a-zA-Z0-9_-]/g,"");
  const app_ = loadStoreCatalog().find(a => a.id === id);
  if (!app_) return res.status(404).json({error:"Application introuvable dans le catalogue"});
  // Case "Créer un raccourci" cochée par défaut (demande explicite de
  // l'utilisateur — la case reste décochable pour ne pas en créer).
  const createShortcut = req.body?.createShortcut !== false;
  // Dossier de données alternatif choisi dans le wizard (ex: un autre volume
  // que volume1) — doit rester sous /srv/volumes/ pour éviter d'écrire n'importe
  // où sur le système via ce champ. Par défaut : même dossier que le
  // docker-compose.yml (storeDir), pas un "AppData" séparé.
  const dir = storeDir(id);
  let dataDir = dir;
  if (req.body?.dataDir && typeof req.body.dataDir === "string") {
    const candidate = path.normalize(req.body.dataDir);
    if (candidate.startsWith("/srv/volumes/")) dataDir = candidate;
  }
  try {
    fs.mkdirSync(dir, {recursive:true});
    const composeYaml = app_.composeYaml.split(catalogAppDataPrefix(id)).join(dataDir);
    fs.writeFileSync(path.join(dir, "docker-compose.yml"), composeYaml);
    // Beaucoup d'apps du catalogue (héritées d'umbrel-apps) font tourner un
    // service avec "user: 1000:1000" sur un volume bind-mount sous
    // AppData/<id>/... (convention umbrelOS) — si ce sous-dossier précis
    // n'existe pas encore, Docker le crée lui-même en root au moment du
    // bind-mount (peu importe le propriétaire d'un dossier parent déjà
    // chown), et le conteneur non-root ne peut plus y écrire ("Permission
    // denied"). umbrelOS pré-crée ces dossiers avec le bon propriétaire ;
    // GravityOS ne le faisait pas encore — bug découvert en installant
    // réellement Nextcloud (mariadb en crash-loop, "data/db" recréé en root
    // par Docker car un chown fait seulement sur AppData/<id> avant "compose
    // up" ne suffit pas : "data/db" n'existait pas encore à ce moment-là).
    // Fix : extraire CHAQUE chemin hôte de bind-mount du compose (regex sur
    // les lignes "- /srv/volumes/...:..."), les créer un par un avant
    // "compose up", puis chown -R une fois tous les sous-dossiers présents.
    // uid 1000 = premier compte NAS créé (convention Debian/GravityOS, cf.
    // `useradd` dans build-iso.sh), cohérent avec l'hypothèse uid 1000 des
    // apps umbrel.
    const bindMountPaths = [...composeYaml.matchAll(/^\s*-\s+(\/srv\/volumes\/\S+?):/gm)].map(m => m[1]);
    for (const p of bindMountPaths) fs.mkdirSync(p, {recursive:true});
    await execAsync(`chown -R 1000:1000 ${sh(dataDir)}`).catch(()=>{});
    const generated = generateSecrets(app_.secretVars);
    if (app_.urlVars?.length) {
      const ip = await nasIp();
      for (const name of app_.urlVars) generated[name] = ip;
    }
    writeEnvFile(dir, generated);
    if (app_.hasUserFacingPassword && generated.APP_PASSWORD) {
      fs.writeFileSync(path.join(dir, "credentials.json"), JSON.stringify({ password: generated.APP_PASSWORD }));
    }
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} up -d 2>&1`, async (ok) => {
      // Callback fire-and-forget — une erreur ici (ex: écriture disque du
      // fichier de raccourcis) ne doit jamais faire tomber tout le service ;
      // aussi ce qui explique un cas réel observé : app installée avec succès
      // mais raccourci manquant malgré la case cochée, sans la moindre trace.
      try {
        if (!ok || !createShortcut || !app_.hostPorts?.[0]) return;
        const ip = await nasIp();
        const list = loadAppShortcuts();
        if (!list.some(s => s.storeAppId === id)) {
          // Quelques apps (ex: Frigate, dont le port principal est en fait le
          // proxy nginx authentifié intégré) ne répondent qu'en HTTPS
          // (certificat auto-signé) sur leur port publié — usesHttps marqué
          // manuellement dans le catalogue au cas par cas, découvert en
          // testant réellement le port (curl http:// donnait 400 Bad
          // Request, seul https:// répondait avec le vrai contenu).
          const scheme = app_.usesHttps ? "https" : "http";
          list.push({ id: crypto.randomBytes(6).toString("hex"), name: app_.name, url: `${scheme}://${ip}:${app_.hostPorts[0]}`, icon: app_.icon, storeAppId: id });
          saveAppShortcuts(list);
        }
      } catch (e) { console.error(`Création du raccourci Magasin (${id}) échouée:`, e.message); }
    });
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/store/apps/:id/credentials", auth, (req,res)=>{
  const id = req.params.id.replace(/[^a-zA-Z0-9_-]/g,"");
  try {
    const file = path.join(storeDir(id), "credentials.json");
    res.json(fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : {});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/store/apps/:id/uninstall", auth, async(req,res)=>{
  const id = req.params.id.replace(/[^a-zA-Z0-9_-]/g,"");
  const dir = storeDir(id);
  const composeFile = path.join(dir, "docker-compose.yml");
  if (!fs.existsSync(composeFile)) return res.status(404).json({error:"Application non installée"});
  try {
    // Images utilisées par CETTE app, capturées avant "down" (le fichier
    // compose disparaît avec "rm -rf dir" une fois la désinstallation faite).
    const images = [...fs.readFileSync(composeFile, "utf8").matchAll(/^\s*image:\s*(\S+)\s*$/gm)].map(m => m[1]);
    const jobId = runJob(`cd ${sh(dir)} && ${composeCmd()} down -v 2>&1 && rm -rf ${sh(dir)}`, async (ok) => {
      try {
        if (!ok) return;
        saveAppShortcuts(loadAppShortcuts().filter(s => s.storeAppId !== id));
        // Une image encore utilisée ailleurs (autre app du Magasin partageant
        // la même image de base, conteneur créé à la main...) ne doit pas
        // être supprimée — seulement celles devenues orphelines après ce
        // "down".
        if (!docker || !images.length) return;
        const remaining = await docker.listContainers({all:true});
        for (const image of images) {
          const stillUsed = remaining.some(c => c.Image === image);
          if (!stillUsed) await docker.getImage(image).remove({force:true}).catch(()=>{});
        }
      } catch (e) { console.error(`Nettoyage post-désinstallation Magasin (${id}) échoué:`, e.message); }
    });
    res.json({ok:true, jobId});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  RACCOURCIS D'APPLICATIONS — entrées ajoutées au menu "Applications" (grille
//  ouverte depuis le dock) pour les apps auto-hébergées (installées depuis le
//  Magasin, ou un conteneur/stack créé à la main avec la case "créer un
//  raccourci" cochée) : ouvrent une nouvelle fenêtre vers leur IP:port plutôt
//  qu'une app OS native gérée par le WindowManager.
// ══════════════════════════════════════════════════════════════════════════════
const APP_SHORTCUTS_FILE = `${CFG}/app-shortcuts.json`;
function loadAppShortcuts(){ try{ return JSON.parse(fs.readFileSync(APP_SHORTCUTS_FILE,"utf8")); } catch { return []; } }
function saveAppShortcuts(list){ fs.mkdirSync(CFG,{recursive:true}); fs.writeFileSync(APP_SHORTCUTS_FILE, JSON.stringify(list,null,2)); }

async function nasIp() {
  try {
    const list = await si.networkInterfaces();
    const arr = Array.isArray(list) ? list : [list];
    const iface = arr.find(i=>i.ip4 && !i.internal && i.operstate==="up") || arr.find(i=>i.ip4 && !i.internal);
    return iface?.ip4 || "127.0.0.1";
  } catch { return "127.0.0.1"; }
}

// État "en cours d'exécution" par raccourci — pour griser l'icône d'une VM
// ou d'une app du Magasin éteinte (demande explicite de l'utilisateur),
// plutôt que de laisser l'icône identique qu'elle soit joignable ou non.
// Uniquement calculé pour les raccourcis rattachés à une VM ou une app du
// Magasin (les seuls dont l'état peut être vérifié de façon fiable) —
// "running" reste absent pour un raccourci manuel/URL classique.
app.get("/api/app-shortcuts", auth, async(req,res)=>{
  try {
    const list = loadAppShortcuts();
    const containers = list.some(s=>s.storeAppId) && docker
      ? await docker.listContainers({all:true}).catch(()=>[])
      : [];
    const withStatus = await Promise.all(list.map(async(s)=>{
      if (s.vmName) return { ...s, running: await vmIsRunning(s.vmName).catch(()=>false) };
      if (s.storeAppId) {
        const project = `store-${s.storeAppId}`;
        const running = containers.some(c => c.Labels?.["com.docker.compose.project"] === project && c.State === "running");
        return { ...s, running };
      }
      return s;
    }));
    res.json(withStatus);
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/app-shortcuts", auth, async(req,res)=>{
  const { id, name, ip, port, icon, https, vmName, dynamic, url, storeAppId, hidden } = req.body;
  if (!name || !String(name).trim()) return res.status(400).json({error:"Nom requis"});
  try {
    const baseId = id || crypto.randomBytes(6).toString("hex");
    let entry;
    if (url) {
      // Mode "URL" : l'utilisateur maîtrise tout (chemin, port non
      // standard...) — aucune reconstruction, juste une validation basique.
      let parsed;
      try { parsed = new URL(String(url)); } catch { return res.status(400).json({error:"URL invalide"}); }
      if (!["http:","https:"].includes(parsed.protocol)) return res.status(400).json({error:"Seuls http:// et https:// sont acceptés"});
      entry = { id: baseId, name: String(name).trim(), url: parsed.toString(), icon: icon || null };
    } else {
      const safePort = parseInt(port,10);
      if (!safePort || safePort<1 || safePort>65535) return res.status(400).json({error:"Port invalide"});
      if (dynamic && vmName) {
        // Mode "dynamique" pour une VM : pas d'IP figée à la création
        // (attribuée par DHCP, peut changer d'un démarrage à l'autre) — le
        // frontend résout l'IP réelle via GET /api/vms/:n/ip au moment du
        // clic. port/https/vmName stockés, "url" absent tant que non résolu.
        entry = { id: baseId, name: String(name).trim(), vmName: String(vmName), dynamic: true, port: safePort, https: !!https, icon: icon || null };
      } else {
        // Mode "IP manuelle"
        const scheme = https ? "https" : "http";
        const safeIp = (ip && String(ip).trim()) || await nasIp();
        entry = { id: baseId, name: String(name).trim(), url: `${scheme}://${safeIp}:${safePort}`, icon: icon || null };
      }
    }
    // "vmName" sert aussi de simple étiquette de provenance (même hors mode
    // dynamique) pour que l'assistant d'édition d'une VM puisse retrouver le
    // raccourci déjà créé pour elle, peu importe le mode choisi — sans ça,
    // rouvrir l'édition et cocher la case à nouveau créait un doublon à
    // chaque fois (signalé par un utilisateur réel).
    if (vmName && !entry.vmName) entry.vmName = String(vmName);
    // Même principe pour "storeAppId" — posé par le bouton "Modifier" du
    // détail d'une app du Magasin (recréer/éditer son raccourci), requis
    // pour que le statut "running" et le nettoyage à la désinstallation
    // continuent de fonctionner sur un raccourci recréé/édité ici plutôt
    // qu'automatiquement à l'installation.
    if (storeAppId) entry.storeAppId = String(storeAppId);
    // Masque l'icône du menu Applications et du bureau sans supprimer le
    // raccourci (nom/URL/icône restent en mémoire) — bouton "Modifier" du
    // détail d'une app du Magasin, demande explicite : pouvoir désactiver
    // l'icône d'une app qu'on ne veut pas voir dans ces deux endroits sans
    // perdre la config si on change d'avis ensuite.
    if (typeof hidden === "boolean") entry.hidden = hidden;
    const list = loadAppShortcuts();
    const idx = list.findIndex(s => s.id === baseId);
    if (idx !== -1) list[idx] = entry; else list.push(entry);
    saveAppShortcuts(list);
    res.json({ok:true, shortcut:entry});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.delete("/api/app-shortcuts/:id", auth, (req,res)=>{
  saveAppShortcuts(loadAppShortcuts().filter(s=>s.id!==req.params.id));
  res.json({ok:true});
});

// ── Réseaux Docker ────────────────────────────────────────────────────────────
app.get("/api/docker/networks", auth, async(req,res)=>{
  if(!docker) return res.json([]);
  try {
    const nets = await docker.listNetworks();
    res.json(nets.map(n=>({
      id: n.Id.slice(0,12),
      name: n.Name,
      driver: n.Driver,
      scope: n.Scope,
      subnet: n.IPAM?.Config?.[0]?.Subnet || "—",
      containers: Object.keys(n.Containers||{}).length,
    })));
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/docker/networks", auth, async(req,res)=>{
  const { name, driver, internal, subnet, gateway } = req.body;
  if(!name || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(name)) return res.status(400).json({error:"Nom de réseau invalide"});
  if(!docker) return res.status(500).json({error:"Docker indisponible"});
  try {
    const opts = { Name:name, Driver: driver||"bridge", Internal: !!internal };
    if (subnet) opts.IPAM = { Config: [ gateway ? {Subnet:subnet, Gateway:gateway} : {Subnet:subnet} ] };
    await docker.createNetwork(opts);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});
// bridge/host/none sont les réseaux prédéfinis de Docker — le daemon refuse
// déjà nativement leur suppression, mais on le vérifie ici aussi pour un
// message d'erreur clair plutôt qu'une erreur Docker brute
app.delete("/api/docker/networks/:id", auth, async(req,res)=>{
  if(!docker) return res.status(500).json({error:"Docker indisponible"});
  try {
    const info = await docker.getNetwork(req.params.id).inspect();
    if (["bridge","host","none"].includes(info.Name)) return res.status(400).json({error:"Réseau par défaut — impossible à supprimer"});
    await docker.getNetwork(req.params.id).remove();
    res.json({ok:true});
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

// Construit la commande shell d'une sauvegarde (archive + envoi vers la
// destination). Partagée entre le lancement à la demande (/api/backup/run)
// et les tâches planifiées (backup/tasks) pour ne pas dupliquer la logique.
// Inclut un marqueur SIZE_BYTES et un test d'intégrité (tar -tzf) dans le
// log de sortie, exploités par startTaskRun() pour mettre à jour la tâche.
function buildBackupCmd({ scope, volumes, folders, destType, destPath, remoteId, taskId }) {
  const sc = Array.isArray(scope) ? scope : [];
  if (!sc.length) throw new Error("Sélectionnez au moins un élément à sauvegarder");
  const stamp = new Date().toISOString().replace(/[:.]/g,"-");
  const archivePrefix = taskId ? `gravityos-backup-${taskId}-` : "gravityos-backup-";
  const archiveName = `${archivePrefix}${stamp}.tar.gz`;
  const tmpFile = `/tmp/${archiveName}`;
  const paths = [];
  let pre = "";
  if (sc.includes("config")) for (const p of ["/etc/gravity","/etc/samba/smb.conf","/etc/exports"]) if (fs.existsSync(p)) paths.push(p);
  if (sc.includes("docker") && fs.existsSync(COMPOSE_DIR)) paths.push(COMPOSE_DIR);
  if (sc.includes("vms")) {
    pre += `mkdir -p /tmp/gravity-vm-defs && for vm in $(virsh --connect qemu:///system list --all --name 2>/dev/null); do virsh --connect qemu:///system dumpxml "$vm" > "/tmp/gravity-vm-defs/$vm.xml" 2>/dev/null; done\n`;
    paths.push("/tmp/gravity-vm-defs");
  }
  if (sc.includes("volumes") && Array.isArray(volumes)) {
    for (const v of volumes) { const p = path.join(VOL_ROOT, String(v).replace(/[^a-zA-Z0-9_-]/g,"")); if (fs.existsSync(p)) paths.push(p); }
  }
  if (sc.includes("folders") && Array.isArray(folders)) {
    for (const f of folders) { if (isPathAllowed(f) && fs.existsSync(f)) paths.push(f); }
  }
  if (!paths.length) throw new Error("Rien à sauvegarder pour cette sélection");

  let sendCmd;
  if (destType==="local" || destType==="usb") {
    if (!destPath) throw new Error("Destination requise");
    sendCmd = `mkdir -p ${sh(destPath)} && cp ${sh(tmpFile)} ${sh(path.join(destPath,archiveName))}`;
  } else if (destType==="ftp" || destType==="smb") {
    const r = loadRemotes().find(x=>x.id===remoteId);
    if (!r) throw new Error("Destination distante introuvable");
    const rpath = r.path.endsWith("/") ? r.path : r.path+"/";
    sendCmd = r.type==="ftp"
      ? `curl -sS -T ${sh(tmpFile)} ${sh(`ftp://${r.host}:${r.port}${rpath}${archiveName}`)} --user ${sh(r.user+":"+r.password)}`
      : `smbclient ${sh("//"+r.host+"/"+r.path)} -U ${sh(r.user+"%"+r.password)} -c ${sh("put "+tmpFile+" "+archiveName)}`;
  } else throw new Error("Type de destination invalide");

  return `${pre}tar -czf ${sh(tmpFile)} ${paths.map(sh).join(" ")} 2>&1
echo "Archive créée : $(du -h ${sh(tmpFile)} | cut -f1)"
echo "SIZE_BYTES:$(stat -c%s ${sh(tmpFile)} 2>/dev/null || echo 0)"
tar -tzf ${sh(tmpFile)} >/dev/null 2>&1 && echo "INTEGRITY_OK" || echo "INTEGRITY_FAIL"
${sendCmd} 2>&1
rm -f ${sh(tmpFile)}
echo "=== Sauvegarde envoyée avec succès ==="`;
}

// Lance une sauvegarde à la demande : scope = tableau parmi ["config","docker","vms","volumes"]
app.post("/api/backup/run", auth, async(req,res)=>{
  try {
    const cmd = buildBackupCmd(req.body);
    const jobId = runJob(cmd);
    res.json({ok:true, jobId});
  } catch(e){ res.status(400).json({error:e.message}); }
});

// ── Tâches de sauvegarde planifiées ───────────────────────────────────────────
// Modèle "tâche nommée" (cible + planification propre), différent des
// "remotes" ci-dessus (une simple destination FTP/SMB réutilisable). Une
// tâche référence un remote (cloud/nas) ou un chemin local, avec son propre
// intervalle de planification — cohérent avec le design déjà pensé côté
// frontend (BackupApp), que le modèle backend d'origine ne couvrait pas.
const BACKUP_TASKS_FILE = `${CFG}/backup-tasks.json`;
function loadTasks(){ try{ return JSON.parse(fs.readFileSync(BACKUP_TASKS_FILE,"utf8")); } catch { return []; } }
function saveTasks(t){ fs.mkdirSync(CFG,{recursive:true}); fs.writeFileSync(BACKUP_TASKS_FILE, JSON.stringify(t,null,2)); }

const INTERVAL_MS = { "Quotidien": 86400000, "Hebdomadaire": 7*86400000, "Mensuel": 30*86400000 };
function nextRunFor(t){
  if (t.scheduleInterval === "Manuel" || !t.lastBackup) return null;
  const ms = INTERVAL_MS[t.scheduleInterval];
  return ms ? new Date(new Date(t.lastBackup).getTime() + ms) : null;
}
function isDue(t){
  if (t.enabled === false || t.scheduleInterval === "Manuel" || t.status === "running") return false;
  if (!t.lastBackup) return true; // jamais lancée -> due dès que possible
  const next = nextRunFor(t);
  return !!next && next.getTime() <= Date.now();
}
function taskTarget(t){
  if (t.type === "local") return { provider:"Disque local", location:"Interne", directory: t.destPath||"—", remoteId:null };
  const r = loadRemotes().find(x=>x.id===t.remoteId);
  if (!r) return { provider:"Destination distante", location:"—", directory:"—", remoteId:t.remoteId||null };
  return { provider: r.type==="ftp" ? "Serveur FTP" : "Partage SMB", location: r.host, directory: r.path, remoteId: r.id };
}
// Décrit les dossiers/éléments réellement inclus dans l'archive, pour
// affichage dans "Paramètres de la tâche" (remplace l'ancien champ libre
// "Dossier partagé" qui n'était jamais rattaché à ce qui était vraiment
// sauvegardé).
function describeSources(t){
  const sc = Array.isArray(t.scope) ? t.scope : [];
  const parts = [];
  if (sc.includes("config")) parts.push("Configuration système (/etc/gravity)");
  if (sc.includes("docker")) parts.push("Docker (compose)");
  if (sc.includes("vms")) parts.push("Machines virtuelles");
  if (sc.includes("volumes")) {
    const vols = Array.isArray(t.volumes) ? t.volumes : [];
    parts.push(vols.length ? `Volumes : ${vols.join(", ")}` : "Volumes (aucun sélectionné)");
  }
  if (sc.includes("folders")) {
    const fol = Array.isArray(t.folders) ? t.folders : [];
    parts.push(fol.length ? `Dossiers : ${fol.join(", ")}` : "Dossiers (aucun sélectionné)");
  }
  return parts.join(" · ") || "—";
}
function taskView(t){
  let nextScheduled;
  if (t.enabled === false) nextScheduled = "Désactivée";
  else if (t.scheduleInterval === "Manuel") nextScheduled = "Manuel";
  else if (t.status === "running") nextScheduled = "En cours";
  else if (!t.lastBackup) nextScheduled = "Dès que possible";
  else nextScheduled = nextRunFor(t)?.toISOString() || "—";
  return {
    id: t.id, name: t.name, type: t.type, status: t.status,
    enabled: t.enabled !== false,
    lastBackup: t.lastBackup, nextScheduled, keepVersions: t.keepVersions||5,
    target: { ...taskTarget(t), sizeGb: t.sizeGb||0, lastIntegrityCheck: t.lastIntegrityCheck },
    settings: {
      folder: describeSources(t),
      fileFilters: t.fileFilters ? "Activé" : "Désactivé",
      scheduleTime: t.scheduleTime, scheduleInterval: t.scheduleInterval,
      scope: t.scope, volumes: t.volumes||[], folders: t.folders||[],
    },
    // Historique des dernières exécutions (succès/erreur + log), le plus récent en premier
    history: (t.history||[]).slice().reverse(),
  };
}

// Liste les versions (archives) déjà envoyées pour une tâche donnée — utilisé
// par le bouton "Liste des versions" et par la purge automatique (keepVersions).
// Support complet pour le local ; best-effort pour FTP/SMB (listing distant).
async function listTaskVersions(t){
  const prefix = `gravityos-backup-${t.id}-`;
  if (t.type === "local") {
    if (!t.destPath) return [];
    try {
      return fs.readdirSync(t.destPath)
        .filter(f=>f.startsWith(prefix) && f.endsWith(".tar.gz"))
        .map(f=>{
          const st = fs.statSync(path.join(t.destPath,f));
          return { name:f, size:st.size, date:st.mtime.toISOString() };
        })
        .sort((a,b)=> b.date.localeCompare(a.date));
    } catch { return []; }
  }
  const r = loadRemotes().find(x=>x.id===t.remoteId);
  if (!r) return [];
  const rpath = r.path.endsWith("/") ? r.path : r.path+"/";
  try {
    if (r.type === "ftp") {
      const { stdout } = await execAsync(`curl -sS --user ${sh(r.user+":"+r.password)} ${sh(`ftp://${r.host}:${r.port}${rpath}`)}`);
      return stdout.split("\n").map(l=>l.trim()).filter(Boolean)
        .map(l=>l.split(/\s+/).pop())
        .filter(name=>name && name.startsWith(prefix) && name.endsWith(".tar.gz"))
        .map(name=>({ name, size:null, date:null }));
    } else {
      const { stdout } = await execAsync(`smbclient ${sh("//"+r.host+"/"+r.path)} -U ${sh(r.user+"%"+r.password)} -c ${sh("ls "+prefix+"*")}`);
      return stdout.split("\n")
        .map(l=>l.trim().match(/^(\S+\.tar\.gz)\s+[AD]?\s+(\d+)/))
        .filter(Boolean)
        .map(m=>({ name:m[1], size:parseInt(m[2],10)||null, date:null }));
    }
  } catch { return []; }
}

// Supprime les versions les plus anciennes au-delà de keepVersions — appelé
// après chaque sauvegarde réussie. Best-effort : une erreur de suppression
// distante n'échoue pas la tâche (le prochain cycle réessaiera).
async function pruneVersions(t){
  const keep = t.keepVersions || 5;
  const versions = await listTaskVersions(t);
  const excess = versions.slice(keep);
  if (!excess.length) return;
  for (const v of excess) {
    try {
      if (t.type === "local") {
        fs.unlinkSync(path.join(t.destPath, v.name));
      } else {
        const r = loadRemotes().find(x=>x.id===t.remoteId);
        if (!r) continue;
        const rpath = r.path.endsWith("/") ? r.path : r.path+"/";
        if (r.type === "ftp") {
          await execAsync(`curl -sS --user ${sh(r.user+":"+r.password)} -Q ${sh("DELE "+v.name)} ${sh(`ftp://${r.host}:${r.port}${rpath}`)}`);
        } else {
          await execAsync(`smbclient ${sh("//"+r.host+"/"+r.path)} -U ${sh(r.user+"%"+r.password)} -c ${sh("rm "+v.name)}`);
        }
      }
    } catch (e) { console.error("Purge version échouée:", v.name, e.message); }
  }
}

// Lance réellement une tâche (planifiée ou manuelle) et met à jour son état
// une fois le job terminé — partagé par le déclenchement manuel et le scheduler.
function startTaskRun(taskId){
  const tasks = loadTasks();
  const t = tasks.find(x=>x.id===taskId);
  if (!t || t.status === "running") return;
  t.status = "running";
  saveTasks(tasks);
  let cmd;
  try {
    cmd = buildBackupCmd({
      scope: t.scope, volumes: t.volumes, folders: t.folders,
      destType: t.type === "local" ? "local" : (loadRemotes().find(r=>r.id===t.remoteId)?.type || "ftp"),
      destPath: t.destPath, remoteId: t.remoteId, taskId: t.id,
    });
  } catch (e) {
    const tasks2 = loadTasks(); const t2 = tasks2.find(x=>x.id===taskId);
    if (t2) { t2.status = "warning"; saveTasks(tasks2); }
    return;
  }
  runJob(cmd, (ok, log) => {
    const tasks2 = loadTasks();
    const t2 = tasks2.find(x=>x.id===taskId);
    if (!t2) return;
    t2.status = ok ? "success" : "warning";
    t2.lastBackup = new Date().toISOString();
    const sizeMatch = log.match(/SIZE_BYTES:(\d+)/);
    if (sizeMatch) t2.sizeGb = Math.round((parseInt(sizeMatch[1],10)/1e9)*100)/100;
    if (log.includes("INTEGRITY_OK")) t2.lastIntegrityCheck = t2.lastBackup;
    t2.history = [...(t2.history||[]), { date:t2.lastBackup, ok, sizeGb:t2.sizeGb, log: log.slice(-4000) }].slice(-20);
    saveTasks(tasks2);
    if (ok) pruneVersions(t2).catch(()=>{});
  });
}

// Vérifie toutes les minutes si une tâche planifiée est due (façon cron léger)
setInterval(() => {
  for (const t of loadTasks()) if (isDue(t)) startTaskRun(t.id);
}, 60000);

function validateTaskPayload(body, { requireDest }) {
  const { name, type, destPath, remoteId, scope, folders, keepVersions } = body;
  if (!name) throw new Error("Nom requis");
  if (!["local","cloud","nas"].includes(type)) throw new Error("Type invalide (local, cloud ou nas)");
  if (type !== "local" && requireDest && !loadRemotes().some(r=>r.id===remoteId)) throw new Error("Destination distante introuvable — créez d'abord un remote");
  if (type === "local" && requireDest) {
    if (!destPath) throw new Error("Chemin local requis");
    if (!isPathAllowed(destPath)) throw new Error("Chemin non autorisé");
  }
  if (!Array.isArray(scope) || !scope.length) throw new Error("Sélectionnez au moins un élément à sauvegarder");
  if (scope.includes("folders")) {
    if (!Array.isArray(folders) || !folders.length) throw new Error("Sélectionnez au moins un dossier à sauvegarder");
    if (folders.some(f=>!isPathAllowed(f))) throw new Error("Un des dossiers sélectionnés n'est pas autorisé");
  }
  const kv = parseInt(keepVersions,10);
  if (kv && kv < 1) throw new Error("Nombre de versions invalide");
}

app.get("/api/backup/tasks", auth, (req,res) => res.json(loadTasks().map(taskView)));
app.post("/api/backup/tasks", auth, (req,res) => {
  try { validateTaskPayload(req.body, {requireDest:true}); } catch(e){ return res.status(400).json({error:e.message}); }
  const { name, type, destPath, remoteId, scope, volumes, folders, fileFilters, scheduleTime, scheduleInterval, keepVersions } = req.body;
  const tasks = loadTasks();
  tasks.push({
    id: crypto.randomBytes(6).toString("hex"), name, type,
    destPath: type === "local" ? destPath : undefined,
    remoteId: type !== "local" ? remoteId : undefined,
    scope: Array.isArray(scope) && scope.length ? scope : ["config"],
    volumes: Array.isArray(volumes) ? volumes : [],
    folders: Array.isArray(folders) ? folders : [],
    fileFilters: !!fileFilters,
    scheduleTime: /^\d{2}:\d{2}$/.test(scheduleTime) ? scheduleTime : "02:00",
    scheduleInterval: ["Quotidien","Hebdomadaire","Mensuel","Manuel"].includes(scheduleInterval) ? scheduleInterval : "Quotidien",
    keepVersions: parseInt(keepVersions,10) || 5,
    lastBackup: null, lastIntegrityCheck: null, sizeGb: 0, status: "never", history: [], enabled: true,
  });
  saveTasks(tasks);
  res.json({ok:true});
});
app.put("/api/backup/tasks/:id", auth, (req,res) => {
  const tasks = loadTasks();
  const t = tasks.find(x=>x.id===req.params.id);
  if (!t) return res.status(404).json({error:"Tâche introuvable"});
  if (t.status === "running") return res.status(409).json({error:"Impossible de modifier une tâche en cours d'exécution"});
  try { validateTaskPayload(req.body, {requireDest:true}); } catch(e){ return res.status(400).json({error:e.message}); }
  const { name, type, destPath, remoteId, scope, volumes, folders, fileFilters, scheduleTime, scheduleInterval, keepVersions } = req.body;
  Object.assign(t, {
    name, type,
    destPath: type === "local" ? destPath : undefined,
    remoteId: type !== "local" ? remoteId : undefined,
    scope: Array.isArray(scope) && scope.length ? scope : ["config"],
    volumes: Array.isArray(volumes) ? volumes : [],
    folders: Array.isArray(folders) ? folders : [],
    fileFilters: !!fileFilters,
    scheduleTime: /^\d{2}:\d{2}$/.test(scheduleTime) ? scheduleTime : "02:00",
    scheduleInterval: ["Quotidien","Hebdomadaire","Mensuel","Manuel"].includes(scheduleInterval) ? scheduleInterval : "Quotidien",
    keepVersions: parseInt(keepVersions,10) || 5,
  });
  saveTasks(tasks);
  res.json({ok:true});
});
app.post("/api/backup/tasks/:id/enabled", auth, (req,res) => {
  const tasks = loadTasks();
  const t = tasks.find(x=>x.id===req.params.id);
  if (!t) return res.status(404).json({error:"Tâche introuvable"});
  t.enabled = !!req.body.enabled;
  saveTasks(tasks);
  res.json({ok:true});
});
app.delete("/api/backup/tasks/:id", auth, (req,res) => { saveTasks(loadTasks().filter(t=>t.id!==req.params.id)); res.json({ok:true}); });
app.post("/api/backup/tasks/:id/run", auth, (req,res) => {
  const t = loadTasks().find(x=>x.id===req.params.id);
  if (!t) return res.status(404).json({error:"Tâche introuvable"});
  if (t.status === "running") return res.status(409).json({error:"Cette tâche est déjà en cours"});
  startTaskRun(t.id);
  res.json({ok:true});
});
app.get("/api/backup/tasks/:id/versions", auth, async(req,res) => {
  const t = loadTasks().find(x=>x.id===req.params.id);
  if (!t) return res.status(404).json({error:"Tâche introuvable"});
  try { res.json(await listTaskVersions(t)); } catch(e){ res.status(500).json({error:e.message}); }
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
//  PLANIFICATION — tâches génériques (commande shell ou script) exécutées sur
//  un horaire, façon "Planificateur des tâches" Synology. Système volontairement
//  séparé des tâches de sauvegarde ci-dessus (modèle différent : ici une simple
//  commande, pas de destination/scope/rétention) — demande explicite de
//  l'utilisateur pour un onglet Réglages dédié, indépendant de l'app Sauvegarde.
// ══════════════════════════════════════════════════════════════════════════════
const SCHEDULED_TASKS_FILE = `${CFG}/scheduled-tasks.json`;
function loadScheduledTasks(){ try{ return JSON.parse(fs.readFileSync(SCHEDULED_TASKS_FILE,"utf8")); } catch { return []; } }
function saveScheduledTasks(t){ fs.mkdirSync(CFG,{recursive:true}); fs.writeFileSync(SCHEDULED_TASKS_FILE, JSON.stringify(t,null,2)); }

// Calcule la prochaine exécution. Contrairement aux tâches de sauvegarde
// (INTERVAL_MS relatif au dernier lancement, l'heure choisie n'étant en
// réalité jamais utilisée pour le calcul), ici l'heure configurée compte
// vraiment — cohérent avec le vrai Planificateur des tâches Synology pris en
// référence par l'utilisateur (ex: "tous les jours à 2h", pas "toutes les 24h
// depuis le dernier lancement").
function nextScheduledRun(t){
  if (t.enabled === false) return null;
  const now = new Date();
  if (t.scheduleInterval === "Personnalisé") {
    const base = t.lastRun ? new Date(t.lastRun) : new Date(t.createdAt || now);
    return new Date(base.getTime() + Math.max(1, parseInt(t.intervalMinutes,10)||60) * 60000);
  }
  const [h,m] = /^\d{2}:\d{2}$/.test(t.scheduleTime) ? t.scheduleTime.split(":").map(Number) : [2,0];
  const candidate = new Date(now);
  candidate.setSeconds(0,0);
  candidate.setHours(h,m,0,0);
  if (t.scheduleInterval === "Hebdomadaire") {
    const targetDay = Number.isInteger(t.weekday) ? t.weekday : 0;
    const diff = (targetDay - candidate.getDay() + 7) % 7;
    candidate.setDate(candidate.getDate() + diff);
    if (candidate <= now) candidate.setDate(candidate.getDate() + 7);
  } else if (t.scheduleInterval === "Mensuel") {
    const targetDay = Math.min(Math.max(parseInt(t.dayOfMonth,10)||1,1), 28);
    candidate.setDate(targetDay);
    if (candidate <= now) { candidate.setMonth(candidate.getMonth()+1); candidate.setDate(targetDay); }
  } else if (candidate <= now) {
    candidate.setDate(candidate.getDate() + 1); // Quotidien
  }
  return candidate;
}
function scheduledTaskIsDue(t){
  if (t.enabled === false || t.status === "running") return false;
  const next = nextScheduledRun(t);
  return !!next && next.getTime() <= Date.now();
}
function scheduledTaskView(t){
  return {
    id: t.id, name: t.name, enabled: t.enabled !== false, status: t.status || "idle",
    builtin: !!t.builtin, builtinType: t.builtinType,
    kind: t.kind, command: t.kind === "command" ? t.command : undefined, scriptPath: t.kind === "script" ? t.scriptPath : undefined,
    scheduleInterval: t.scheduleInterval, scheduleTime: t.scheduleTime, weekday: t.weekday, dayOfMonth: t.dayOfMonth, intervalMinutes: t.intervalMinutes,
    lastRun: t.lastRun || null, lastOk: t.lastOk ?? null,
    nextRun: nextScheduledRun(t)?.toISOString() || null,
    history: (t.history||[]).slice().reverse().map(h => ({ date:h.date, ok:h.ok, durationMs:h.durationMs })),
    lastLog: (t.history && t.history.length) ? t.history[t.history.length-1].log : "",
  };
}

// Vérifie (et télécharge si une nouvelle version existe) les images Docker
// actuellement utilisées par un conteneur — même principe qu'un Watchtower :
// "docker pull" ne perturbe pas un conteneur déjà démarré, seul un
// redémarrage/recréation applique l'image mise à jour (volontairement pas
// fait ici, demande explicite = "vérifier", pas "appliquer").
async function checkDockerImageUpdates() {
  if (!docker) return { count: 0, images: [], log: "Docker indisponible" };
  const containers = await docker.listContainers({all:true}).catch(()=>[]);
  const images = [...new Set(containers.map(c => c.Image))];
  const updated = [];
  const lines = [];
  for (const image of images) {
    try {
      const before = await docker.getImage(image).inspect().catch(() => null);
      await execAsync(`docker pull ${sh(image)} 2>&1`);
      const after = await docker.getImage(image).inspect().catch(() => null);
      if (before?.Id && after?.Id && before.Id !== after.Id) {
        updated.push(image);
        lines.push(`${image} : mise à jour disponible et téléchargée`);
      } else {
        lines.push(`${image} : à jour`);
      }
    } catch (e) {
      lines.push(`${image} : erreur (${e.message})`);
    }
  }
  return { count: updated.length, images: updated, log: lines.join("\n") };
}

// Dispatche l'action réelle d'une tâche système (pas de commande/script
// utilisateur — voir la case "Système" du Planificateur). Chaque branche
// retourne {ok, log} comme runJob/runUpdateProcess pour rester compatible
// avec startScheduledTaskRun ci-dessous.
async function runBuiltinTask(t) {
  if (t.builtinType === "auto-update") {
    const sys = await runUpdateProcess(systemUpdateCmd());
    const grav = await runUpdateProcess(gravityUpdateCmd());
    return { ok: sys.ok && grav.ok, log: `${sys.log}\n\n${grav.log}` };
  }
  if (t.builtinType === "check-os-updates") {
    const r = await checkOsUpdatesCore();
    return { ok: true, log: r.count > 0 ? `${r.count} mise(s) à jour disponible(s) :\n${r.packages.join("\n")}` : "Système à jour." };
  }
  if (t.builtinType === "check-docker-updates") {
    const r = await checkDockerImageUpdates();
    return { ok: true, log: (r.count > 0 ? `${r.count} image(s) mise(s) à jour :\n${r.images.join("\n")}\n\n` : "Toutes les images sont à jour.\n\n") + r.log };
  }
  return { ok: false, log: "Type de tâche système inconnu : " + t.builtinType };
}

function startScheduledTaskRun(taskId){
  const tasks = loadScheduledTasks();
  const t = tasks.find(x=>x.id===taskId);
  if (!t || t.status === "running") return;
  t.status = "running";
  saveScheduledTasks(tasks);
  const startedAt = Date.now();
  const finish = (ok, log) => {
    const tasks2 = loadScheduledTasks();
    const t2 = tasks2.find(x=>x.id===taskId);
    if (!t2) return;
    t2.status = "idle";
    t2.lastRun = new Date().toISOString();
    t2.lastOk = ok;
    t2.history = [...(t2.history||[]), { date:t2.lastRun, ok, durationMs: Date.now()-startedAt, log: log.slice(-8000) }].slice(-20);
    saveScheduledTasks(tasks2);
  };
  if (t.kind === "builtin") {
    runBuiltinTask(t).then(({ok, log}) => finish(ok, log)).catch(e => finish(false, String(e?.message || e)));
    return;
  }
  const cmd = t.kind === "script" ? `bash ${sh(t.scriptPath)} 2>&1` : `bash -lc ${sh(t.command)} 2>&1`;
  runJob(cmd, finish);
}
// Vérifie toutes les minutes si une tâche planifiée est due (même mécanisme
// "cron léger" que les tâches de sauvegarde ci-dessus)
setInterval(() => {
  for (const t of loadScheduledTasks()) if (scheduledTaskIsDue(t)) startScheduledTaskRun(t.id);
}, 60000);

function validateScheduledTaskPayload(body){
  const { name, kind, command, scriptPath, scheduleInterval, scheduleTime, weekday, dayOfMonth, intervalMinutes } = body;
  if (!name || !String(name).trim()) throw new Error("Nom requis");
  if (!["command","script"].includes(kind)) throw new Error("Type invalide");
  if (kind === "command" && (!command || !String(command).trim())) throw new Error("Commande requise");
  if (kind === "script") {
    if (!scriptPath || !String(scriptPath).trim()) throw new Error("Chemin du script requis");
    if (!isPathAllowed(scriptPath)) throw new Error("Chemin non autorisé");
  }
  if (!["Quotidien","Hebdomadaire","Mensuel","Personnalisé"].includes(scheduleInterval)) throw new Error("Fréquence invalide");
  if (scheduleInterval !== "Personnalisé" && !/^\d{2}:\d{2}$/.test(scheduleTime)) throw new Error("Heure invalide (HH:MM)");
  if (scheduleInterval === "Hebdomadaire" && !(Number.isInteger(weekday) && weekday>=0 && weekday<=6)) throw new Error("Jour de la semaine invalide");
  if (scheduleInterval === "Mensuel" && !(Number.isInteger(dayOfMonth) && dayOfMonth>=1 && dayOfMonth<=28)) throw new Error("Jour du mois invalide (1-28)");
  if (scheduleInterval === "Personnalisé" && !(parseInt(intervalMinutes,10) >= 1)) throw new Error("Intervalle (minutes) invalide");
}
// Sous-ensemble de validateScheduledTaskPayload pour une tâche système
// (onglet "Système" du Planificateur) : ni commande/script ni suppression
// possibles pour ces tâches intégrées — seules la fréquence et l'activation
// sont modifiables (demande explicite de l'utilisateur).
function validateScheduleFields(body){
  const { scheduleInterval, scheduleTime, weekday, dayOfMonth, intervalMinutes } = body;
  if (!["Quotidien","Hebdomadaire","Mensuel","Personnalisé"].includes(scheduleInterval)) throw new Error("Fréquence invalide");
  if (scheduleInterval !== "Personnalisé" && !/^\d{2}:\d{2}$/.test(scheduleTime)) throw new Error("Heure invalide (HH:MM)");
  if (scheduleInterval === "Hebdomadaire" && !(Number.isInteger(weekday) && weekday>=0 && weekday<=6)) throw new Error("Jour de la semaine invalide");
  if (scheduleInterval === "Mensuel" && !(Number.isInteger(dayOfMonth) && dayOfMonth>=1 && dayOfMonth<=28)) throw new Error("Jour du mois invalide (1-28)");
  if (scheduleInterval === "Personnalisé" && !(parseInt(intervalMinutes,10) >= 1)) throw new Error("Intervalle (minutes) invalide");
}

app.get("/api/scheduled-tasks", auth, (req,res) => res.json(loadScheduledTasks().map(scheduledTaskView)));
app.post("/api/scheduled-tasks", auth, (req,res) => {
  try { validateScheduledTaskPayload(req.body); } catch(e){ return res.status(400).json({error:e.message}); }
  const { name, kind, command, scriptPath, scheduleInterval, scheduleTime, weekday, dayOfMonth, intervalMinutes } = req.body;
  const tasks = loadScheduledTasks();
  tasks.push({
    id: crypto.randomBytes(6).toString("hex"), name: String(name).trim(), kind,
    command: kind === "command" ? command : undefined,
    scriptPath: kind === "script" ? scriptPath : undefined,
    scheduleInterval, scheduleTime: scheduleTime || "02:00",
    weekday: scheduleInterval === "Hebdomadaire" ? weekday : undefined,
    dayOfMonth: scheduleInterval === "Mensuel" ? dayOfMonth : undefined,
    intervalMinutes: scheduleInterval === "Personnalisé" ? parseInt(intervalMinutes,10) : undefined,
    enabled: true, status: "idle", lastRun: null, lastOk: null, history: [],
    createdAt: new Date().toISOString(),
  });
  saveScheduledTasks(tasks);
  res.json({ok:true});
});
app.put("/api/scheduled-tasks/:id", auth, (req,res) => {
  const tasks = loadScheduledTasks();
  const t = tasks.find(x=>x.id===req.params.id);
  if (!t) return res.status(404).json({error:"Tâche introuvable"});
  if (t.status === "running") return res.status(409).json({error:"Impossible de modifier une tâche en cours d'exécution"});
  const { scheduleInterval, scheduleTime, weekday, dayOfMonth, intervalMinutes } = req.body;
  if (t.builtin) {
    // Tâche système : ni type/commande/script ni nom modifiables, seule la
    // fréquence compte — payload volontairement plus restreint que pour une
    // tâche utilisateur.
    try { validateScheduleFields(req.body); } catch(e){ return res.status(400).json({error:e.message}); }
    Object.assign(t, {
      scheduleInterval, scheduleTime: scheduleTime || "02:00",
      weekday: scheduleInterval === "Hebdomadaire" ? weekday : undefined,
      dayOfMonth: scheduleInterval === "Mensuel" ? dayOfMonth : undefined,
      intervalMinutes: scheduleInterval === "Personnalisé" ? parseInt(intervalMinutes,10) : undefined,
    });
    saveScheduledTasks(tasks);
    return res.json({ok:true});
  }
  try { validateScheduledTaskPayload(req.body); } catch(e){ return res.status(400).json({error:e.message}); }
  const { name, kind, command, scriptPath } = req.body;
  Object.assign(t, {
    name: String(name).trim(), kind,
    command: kind === "command" ? command : undefined,
    scriptPath: kind === "script" ? scriptPath : undefined,
    scheduleInterval, scheduleTime: scheduleTime || "02:00",
    weekday: scheduleInterval === "Hebdomadaire" ? weekday : undefined,
    dayOfMonth: scheduleInterval === "Mensuel" ? dayOfMonth : undefined,
    intervalMinutes: scheduleInterval === "Personnalisé" ? parseInt(intervalMinutes,10) : undefined,
  });
  saveScheduledTasks(tasks);
  res.json({ok:true});
});
app.post("/api/scheduled-tasks/:id/enabled", auth, (req,res) => {
  const tasks = loadScheduledTasks();
  const t = tasks.find(x=>x.id===req.params.id);
  if (!t) return res.status(404).json({error:"Tâche introuvable"});
  t.enabled = !!req.body.enabled;
  saveScheduledTasks(tasks);
  res.json({ok:true});
});
app.post("/api/scheduled-tasks/:id/run", auth, (req,res) => {
  const t = loadScheduledTasks().find(x=>x.id===req.params.id);
  if (!t) return res.status(404).json({error:"Tâche introuvable"});
  if (t.status === "running") return res.status(409).json({error:"Cette tâche est déjà en cours"});
  startScheduledTaskRun(t.id);
  res.json({ok:true});
});
app.delete("/api/scheduled-tasks/:id", auth, (req,res) => {
  const tasks = loadScheduledTasks();
  const t = tasks.find(x=>x.id===req.params.id);
  if (!t) return res.status(404).json({error:"Tâche introuvable"});
  if (t.builtin) return res.status(403).json({error:"Cette tâche système ne peut pas être supprimée — désactivez-la plutôt"});
  saveScheduledTasks(tasks.filter(x=>x.id!==req.params.id));
  res.json({ok:true});
});

// Tâches système par défaut, créées une seule fois (si absentes) à chaque
// démarrage — couvre à la fois l'installation initiale et une mise à niveau
// depuis une version de GravityOS antérieure à leur ajout (auto-réparant,
// pas besoin de réinstaller pour les récupérer).
function seedBuiltinScheduledTasks() {
  const tasks = loadScheduledTasks();
  const defaults = [
    { builtinType: "auto-update", name: "Mise à jour automatique", scheduleInterval: "Hebdomadaire", scheduleTime: "02:00", weekday: 1 },
    { builtinType: "check-os-updates", name: "Vérification des mises à jour (OS)", scheduleInterval: "Personnalisé", intervalMinutes: 360 },
    { builtinType: "check-docker-updates", name: "Vérification des mises à jour (Docker)", scheduleInterval: "Quotidien", scheduleTime: "03:00" },
  ];
  let changed = false;
  for (const def of defaults) {
    if (tasks.some(t => t.builtinType === def.builtinType)) continue;
    tasks.push({
      id: crypto.randomBytes(6).toString("hex"), name: def.name, kind: "builtin", builtin: true, builtinType: def.builtinType,
      scheduleInterval: def.scheduleInterval, scheduleTime: def.scheduleTime, weekday: def.weekday, dayOfMonth: def.dayOfMonth, intervalMinutes: def.intervalMinutes,
      enabled: true, status: "idle", lastRun: null, lastOk: null, history: [],
      createdAt: new Date().toISOString(),
    });
    changed = true;
  }
  if (changed) saveScheduledTasks(tasks);
}
seedBuiltinScheduledTasks();

// ══════════════════════════════════════════════════════════════════════════════
//  RÔLES — deux rôles intégrés (Administrateur/Utilisateur, dérivés du groupe
//  réel "sudo") + rôles personnalisés stockés, avec pour chacun une liste de
//  volumes visibles et d'applications accessibles. Purement une couche de
//  configuration : l'authentification de la WebUI reste un identifiant unique
//  partagé (voir /api/auth/login) — il n'y a pas encore de session par
//  utilisateur système pour appliquer ces permissions à l'affichage.
// ══════════════════════════════════════════════════════════════════════════════
const ROLES_FILE = `${CFG}/roles.json`;
const USER_ROLES_FILE = `${CFG}/user-roles.json`;
const BUILTIN_ROLES = [
  { id:"admin", name:"Administrateur", builtin:true, isAdmin:true, volumes:"all", apps:"all" },
  { id:"user",  name:"Utilisateur",    builtin:true, isAdmin:false, volumes:[], apps:[] },
];
function loadRoles(){
  let custom = [];
  try { custom = JSON.parse(fs.readFileSync(ROLES_FILE,"utf8")); } catch {}
  return [...BUILTIN_ROLES.map(r=>{
    const saved = custom.find(c=>c.id===r.id);
    return saved ? { ...r, volumes: saved.volumes ?? r.volumes, apps: saved.apps ?? r.apps } : r;
  }), ...custom.filter(c=>!BUILTIN_ROLES.some(b=>b.id===c.id))];
}
function saveRoles(roles){
  fs.mkdirSync(CFG,{recursive:true});
  // Seuls les champs modifiables des rôles intégrés (volumes/apps) et les
  // rôles personnalisés complets sont persistés — pas les rôles intégrés
  // en entier (id/name/isAdmin restent fixes, définis dans BUILTIN_ROLES)
  const toSave = roles.map(r => BUILTIN_ROLES.some(b=>b.id===r.id) ? { id:r.id, volumes:r.volumes, apps:r.apps } : r);
  fs.writeFileSync(ROLES_FILE, JSON.stringify(toSave,null,2));
}
function loadUserRoles(){ try{ return JSON.parse(fs.readFileSync(USER_ROLES_FILE,"utf8")); } catch{ return {}; } }
function saveUserRoles(m){ fs.mkdirSync(CFG,{recursive:true}); fs.writeFileSync(USER_ROLES_FILE, JSON.stringify(m,null,2)); }

// Rôle effectif d'un utilisateur : l'assignation explicite si elle existe,
// sinon dérivée du groupe réel "sudo" (comportement historique préservé)
async function userRole(username){
  const assigned = loadUserRoles()[username];
  const roles = loadRoles();
  if (assigned && roles.some(r=>r.id===assigned)) return roles.find(r=>r.id===assigned).name;
  try { const {stdout} = await execAsync(`groups ${sh(username)}`); return /\bsudo\b/.test(stdout) ? "Administrateur" : "Utilisateur"; }
  catch { return "Utilisateur"; }
}
async function userRoleId(username){
  const assigned = loadUserRoles()[username];
  if (assigned && loadRoles().some(r=>r.id===assigned)) return assigned;
  try { const {stdout} = await execAsync(`groups ${sh(username)}`); return /\bsudo\b/.test(stdout) ? "admin" : "user"; }
  catch { return "user"; }
}
app.get("/api/roles", auth, async(req,res)=>{
  try {
    const roles = loadRoles();
    const userRoleMap = loadUserRoles();
    const rows = await execAsync("getent passwd | awk -F: '$3>=1000 && $3<65534{print $1}'").catch(()=>({stdout:""}));
    const usernames = rows.stdout.trim().split("\n").filter(Boolean);
    const counts = {};
    for (const u of usernames) { const rid = await userRoleId(u); counts[rid] = (counts[rid]||0)+1; }
    res.json(roles.map(r=>({ ...r, userCount: counts[r.id]||0 })));
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.post("/api/roles", auth, (req,res)=>{
  const { name, volumes, apps } = req.body;
  if (!name || !name.trim()) return res.status(400).json({error:"Nom de rôle requis"});
  const roles = loadRoles();
  const id = name.trim().toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"") || crypto.randomBytes(4).toString("hex");
  if (roles.some(r=>r.id===id)) return res.status(400).json({error:"Un rôle avec ce nom existe déjà"});
  // "settings" reste réservé au rôle Administrateur — jamais accordable à
  // un rôle personnalisé, même via un appel direct de cette API
  const safeApps = (Array.isArray(apps)?apps:[]).filter(a=>a!=="settings");
  roles.push({ id, name:name.trim(), builtin:false, isAdmin:false, volumes: Array.isArray(volumes)?volumes:[], apps: safeApps });
  saveRoles(roles);
  res.json({ok:true, id});
});
app.put("/api/roles/:id", auth, (req,res)=>{
  const roles = loadRoles();
  const role = roles.find(r=>r.id===req.params.id);
  if (!role) return res.status(404).json({error:"Rôle introuvable"});
  if (role.id === "admin") return res.status(400).json({error:"Le rôle Administrateur n'est pas modifiable — il a toujours accès à tout"});
  const { name, volumes, apps } = req.body;
  if (!role.builtin) { if (!name || !name.trim()) return res.status(400).json({error:"Nom de rôle requis"}); role.name = name.trim(); }
  role.volumes = Array.isArray(volumes) ? volumes : role.volumes;
  // "settings" reste réservé au rôle Administrateur (voir POST /api/roles)
  role.apps = Array.isArray(apps) ? apps.filter(a=>a!=="settings") : role.apps;
  saveRoles(roles);
  res.json({ok:true});
});
app.delete("/api/roles/:id", auth, async(req,res)=>{
  const roles = loadRoles();
  const role = roles.find(r=>r.id===req.params.id);
  if (!role) return res.status(404).json({error:"Rôle introuvable"});
  if (role.builtin) return res.status(400).json({error:"Les rôles intégrés ne peuvent pas être supprimés"});
  try {
    const rows = await execAsync("getent passwd | awk -F: '$3>=1000 && $3<65534{print $1}'").catch(()=>({stdout:""}));
    const usernames = rows.stdout.trim().split("\n").filter(Boolean);
    for (const u of usernames) if (await userRoleId(u) === role.id) return res.status(400).json({error:"Ce rôle est encore assigné à au moins un utilisateur"});
    saveRoles(roles.filter(r=>r.id!==role.id));
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Statut réel du compte (verrouillé via `usermod -L`/`passwd -l` ou non)
async function userStatus(username){
  try { const {stdout} = await execAsync(`passwd -S ${sh(username)}`); return /^\S+\s+L\s/.test(stdout.trim()) ? "Désactivé" : "Actif"; }
  catch { return "Actif"; }
}
// Dernière connexion réelle via lastlog (peut être absent sur certains
// systèmes minimaux — dans ce cas on affiche "Inconnu" plutôt qu'inventer)
async function userLastLogin(username){
  try {
    const {stdout} = await execAsync(`lastlog -u ${sh(username)} 2>/dev/null | tail -n +2`);
    const line = stdout.trim();
    if (!line) return "Inconnu";
    if (/\*\*Never logged in\*\*/.test(line)) return "Jamais";
    const parts = line.trim().split(/\s+/);
    return parts.slice(3).join(" ") || "Inconnu";
  } catch { return "Inconnu"; }
}
app.get("/api/users",  auth, async(req,res)=>{
  try{
    const{stdout}=await execAsync("getent passwd | awk -F: '$3>=1000 && $3<65534{print $1\",\"$5\",\"$6}'");
    const rows = stdout.trim().split("\n").filter(Boolean).map(l=>{const[n,g,h]=l.split(",");return{username:n,fullname:g,home:h};});
    const users = await Promise.all(rows.map(async u=>{
      const [role,roleId,status,lastLogin] = await Promise.all([userRole(u.username), userRoleId(u.username), userStatus(u.username), userLastLogin(u.username)]);
      return { ...u, role, roleId, status, lastLogin };
    }));
    res.json(users);
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Applique un rôle (intégré ou personnalisé) à un compte : ajuste le vrai
// groupe "sudo" (seul le rôle Administrateur y donne accès) et persiste
// l'assignation choisie pour les rôles personnalisés / Utilisateur explicite
async function applyRole(username, roleId){
  const role = loadRoles().find(r=>r.id===roleId);
  if (!role) throw new Error("Rôle introuvable");
  if (role.isAdmin) await execAsync(`usermod -aG sudo ${sh(username)}`);
  else await execAsync(`gpasswd -d ${sh(username)} sudo`).catch(()=>{});
  const map = loadUserRoles();
  map[username] = roleId;
  saveUserRoles(map);
}
app.post("/api/users", auth, async(req,res)=>{
  const{username,password,roleId}=req.body;
  if(!username || !/^[a-z_][a-z0-9_-]*$/.test(username)) return res.status(400).json({error:"Nom d'utilisateur invalide"});
  if(!password) return res.status(400).json({error:"Mot de passe requis"});
  const role = loadRoles().find(r=>r.id===(roleId||"user"));
  if (!role) return res.status(400).json({error:"Rôle invalide"});
  try{
    await ensureSharedGroup();
    // Groupe gravity-share : donne accès à Volume 1 (Documents/Images/ISO/
    // Téléchargements), partagé avec tous les autres comptes NAS
    await execAsync(`useradd -m -s /bin/bash -G ${SHARED_GROUP} ${sh(username)}`);
    await execAsync(`echo ${sh(`${username}:${password}`)} | chpasswd`);
    await execAsync(`(echo ${sh(password)}; echo ${sh(password)}) | smbpasswd -a ${sh(username)} -s`).catch(()=>{});
    await applyRole(username, role.id);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.put("/api/users/:username", auth, async(req,res)=>{
  const { username } = req.params;
  const { password, roleId } = req.body;
  if (!/^[a-z_][a-z0-9_-]*$/.test(username)) return res.status(400).json({error:"Utilisateur invalide"});
  try {
    if (password) {
      await execAsync(`echo ${sh(`${username}:${password}`)} | chpasswd`);
      await execAsync(`(echo ${sh(password)}; echo ${sh(password)}) | smbpasswd -a ${sh(username)} -s`).catch(()=>{});
    }
    if (roleId) await applyRole(username, roleId);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.delete("/api/users/:username", auth, async(req,res)=>{
  const { username } = req.params;
  if (!/^[a-z_][a-z0-9_-]*$/.test(username)) return res.status(400).json({error:"Utilisateur invalide"});
  try {
    await execAsync(`userdel -r ${sh(username)}`);
    const map = loadUserRoles();
    delete map[username];
    saveUserRoles(map);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});
// Change de rôle (intégré ou personnalisé) — conservé en plus de PUT
// /api/users pour le menu rapide rôle/statut de la liste des comptes
app.post("/api/users/:username/role", auth, async(req,res)=>{
  const { username } = req.params;
  const { roleId } = req.body;
  if (!/^[a-z_][a-z0-9_-]*$/.test(username)) return res.status(400).json({error:"Utilisateur invalide"});
  try {
    await applyRole(username, roleId);
    res.json({ok:true});
  } catch(e){ res.status(400).json({error:e.message}); }
});
// Active/désactive un compte via le verrouillage réel du mot de passe
// (passwd -l/-u) — cohérent avec userStatus() qui lit ce même état
app.post("/api/users/:username/status", auth, async(req,res)=>{
  const { username } = req.params;
  const { status } = req.body;
  if (!/^[a-z_][a-z0-9_-]*$/.test(username)) return res.status(400).json({error:"Utilisateur invalide"});
  if (!["Actif","Désactivé"].includes(status)) return res.status(400).json({error:"Statut invalide"});
  try {
    await execAsync(`passwd ${status==="Désactivé"?"-l":"-u"} ${sh(username)}`);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  MISES À JOUR
// ══════════════════════════════════════════════════════════════════════════════
let updateLog = [];
let updateRunning = false;

// Séparé de streamUpdate() en deux : ce cœur retourne une Promise résolue à
// la fin du process, utilisée aussi bien par les endpoints HTTP (fire-and-
// forget, réponse immédiate) que par la tâche planifiée système "Mise à jour
// automatique" (qui a besoin d'attendre la fin réelle pour enregistrer un
// historique correct — voir startScheduledTaskRun/runBuiltinTask plus bas).
function runUpdateProcess(cmd) {
  return new Promise((resolve) => {
    updateLog = [];
    updateRunning = true;
    const child = require("child_process").spawn("bash",["-c",cmd],{env:{...process.env,DEBIAN_FRONTEND:"noninteractive",LANG:"C"}});
    child.stdout.on("data",d=>updateLog.push(d.toString()));
    child.stderr.on("data",d=>updateLog.push(d.toString()));
    child.on("close",(code)=>{ updateRunning=false; updateLog.push("=== DONE ==="); resolve({ok: code===0, log: updateLog.join("")}); });
  });
}
function streamUpdate(cmd, res) {
  runUpdateProcess(cmd);
  res.json({ok:true, message:"Mise à jour lancée"});
}
function systemUpdateCmd() { return "apt-get update -qq && apt-get upgrade -y 2>&1"; }

// Cœur de la vérification des mises à jour système, réutilisé par l'endpoint
// HTTP et par la tâche planifiée système "Vérification des mises à jour (OS)".
async function checkOsUpdatesCore() {
  // LANG=fr_FR.UTF-8 par défaut sur GravityOS (locale de l'ISO) : sans
  // LC_ALL=C, l'en-tête informatif d'apt ("Listing... Done") s'affiche en
  // français ("Listage... Fait") et n'est plus filtré par le grep -v
  // 'Listing' ci-dessous (qui ne matche que l'anglais) — cette ligne
  // trainait alors dans la liste comme un faux "paquet", comptée dans le
  // total sans jamais correspondre à une vraie mise à jour installable.
  await execAsync("LC_ALL=C apt-get update -qq 2>/dev/null");
  const {stdout} = await execAsync("LC_ALL=C apt list --upgradable 2>/dev/null | grep -v 'Listing' | wc -l");
  const {stdout:pkgs} = await execAsync("LC_ALL=C apt list --upgradable 2>/dev/null | grep -v 'Listing' | head -20");
  const count = parseInt(stdout.trim()) || 0;
  return {count, packages: pkgs.trim().split("\n").filter(Boolean)};
}
// Vérifier les mises à jour système disponibles
app.get("/api/updates/system/check", auth, async(req,res) => {
  try { res.json(await checkOsUpdatesCore()); } catch(e){ res.status(500).json({error:e.message}); }
});

// Lancer la mise à jour système
app.post("/api/updates/system/start", auth, (req,res) => {
  streamUpdate(systemUpdateCmd(), res);
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

// Extrait en fonction (au lieu d'inline dans le handler) pour être réutilisé
// par la tâche planifiée système "Mise à jour automatique".
function gravityUpdateCmd() {
  const REPO = "https://github.com/sy-per/gravityos-webui.git";
  return `
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

    # smartmontools requis pour l'état S.M.A.R.T. des disques (onglet
    # Stockage > Disque) — déjà dans la liste de paquets de l'ISO, ce
    # correctif ne sert qu'aux NAS déjà installés avant son ajout
    if ! command -v smartctl &>/dev/null; then
      echo "Installation de smartmontools (requis pour l'état S.M.A.R.T. des disques)..."
      apt-get install -y smartmontools 2>&1 | tail -3
    fi

    # network-manager requis pour la config des interfaces réseau (onglet
    # Paramètres > Réseau) — déjà dans la liste de paquets de l'ISO, ce
    # correctif ne sert qu'aux NAS déjà installés avant son ajout
    if ! command -v nmcli &>/dev/null; then
      echo "Installation de network-manager (requis pour la configuration réseau)..."
      apt-get install -y network-manager 2>&1 | tail -3
      systemctl enable --now NetworkManager 2>/dev/null || true
    fi

    # nginx + certbot requis pour le Proxy inversé (onglet Paramètres >
    # Réseau > Proxy inversé) — déjà dans la liste de paquets de l'ISO, ce
    # correctif ne sert qu'aux NAS déjà installés avant son ajout
    if ! command -v nginx &>/dev/null; then
      echo "Installation de nginx + certbot (requis pour le proxy inversé)..."
      apt-get install -y nginx certbot python3-certbot-nginx 2>&1 | tail -3
      mkdir -p /etc/nginx/sites-enabled /etc/nginx/sites-available
      rm -f /etc/nginx/sites-enabled/default
      systemctl enable --now nginx 2>/dev/null || true
      ufw allow 80/tcp  2>/dev/null || true
      ufw allow 443/tcp 2>/dev/null || true
    fi

    # openssh-server requis par l'onglet Paramètres > Terminal (activation
    # SSH + port) — déjà dans la liste de paquets de l'ISO, ce correctif ne
    # sert qu'aux NAS déjà installés avant son ajout. Volontairement PAS
    # activé automatiquement (systemctl enable --now) : SSH doit rester
    # désactivé par défaut, à activer soi-même via Paramètres > Terminal.
    if ! command -v sshd &>/dev/null; then
      echo "Installation d'openssh-server (requis pour l'onglet Terminal, désactivé par défaut)..."
      apt-get install -y openssh-server 2>&1 | tail -3
      systemctl disable --now ssh 2>/dev/null || true
      ufw allow 22/tcp 2>/dev/null || true
    fi

    # pam_shells (config PAM par défaut de vsftpd) rejette toute connexion FTP
    # dont le shell n'est pas listé dans /etc/shells — requis pour les comptes
    # FTP créés en /usr/sbin/nologin depuis Paramètres > Services
    grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells

    # rclone (WebDAV) + minidlna (DLNA) requis par l'onglet Paramètres >
    # Services — déjà dans la liste de paquets de l'ISO, ce correctif ne sert
    # qu'aux NAS déjà installés avant leur ajout. Volontairement PAS activés
    # automatiquement : désactivés par défaut, à activer depuis la WebUI.
    if ! command -v rclone &>/dev/null; then
      echo "Installation de rclone (requis pour le WebDAV, désactivé par défaut)..."
      apt-get install -y rclone 2>&1 | tail -3
      mkdir -p /etc/gravity
      if [ ! -f /etc/gravity/webdav.env ]; then
        printf 'RCLONE_USER=gravity\nRCLONE_PASS=gravity\n' > /etc/gravity/webdav.env
        chmod 600 /etc/gravity/webdav.env
      fi
      cat > /etc/systemd/system/gravity-webdav.service <<'WEBDAVUNIT'
[Unit]
Description=GravityOS WebDAV (rclone)
After=network.target

[Service]
EnvironmentFile=-/etc/gravity/webdav.env
ExecStart=/usr/bin/rclone serve webdav /srv/shares --addr :8081 --user \${RCLONE_USER} --pass \${RCLONE_PASS} --vfs-cache-mode writes
Restart=on-failure

[Install]
WantedBy=multi-user.target
WEBDAVUNIT
      systemctl daemon-reload
      systemctl disable gravity-webdav 2>/dev/null || true
      ufw allow 8081/tcp 2>/dev/null || true
    fi
    if ! command -v minidlnad &>/dev/null; then
      echo "Installation de minidlna (requis pour le DLNA, désactivé par défaut)..."
      apt-get install -y minidlna 2>&1 | tail -3
      sed -i "s|^media_dir=.*|media_dir=/srv/shares|" /etc/minidlna.conf 2>/dev/null || echo "media_dir=/srv/shares" >> /etc/minidlna.conf
      sed -i "s|^friendly_name=.*|friendly_name=GravityOS|" /etc/minidlna.conf 2>/dev/null || echo "friendly_name=GravityOS" >> /etc/minidlna.conf
      systemctl disable --now minidlna 2>/dev/null || true
      ufw allow 8200/tcp 2>/dev/null || true
      ufw allow 1900/udp 2>/dev/null || true
    fi

    # systemd-timesyncd requis par l'onglet Options régional > Service NTP
    # — pas inclus par défaut dans debootstrap (paquet séparé de systemd
    # depuis Debian buster), ce correctif ne sert qu'aux NAS déjà installés
    # avant son ajout à l'ISO
    if [ ! -e /lib/systemd/systemd-timesyncd ] && [ ! -e /usr/lib/systemd/systemd-timesyncd ]; then
      echo "Installation de systemd-timesyncd (requis pour le service NTP)..."
      apt-get install -y systemd-timesyncd 2>&1 | tail -3
      systemctl enable --now systemd-timesyncd 2>/dev/null || true
    fi

    # Module tun requis par le réseau virtuel "default" de libvirt (bridge
    # virbr0 + interfaces TAP des VM) — sans lui, toute VM branchée sur ce
    # réseau échouait au démarrage ("Unable to open /dev/net/tun, is tun
    # module loaded?"), signalé par un utilisateur réel. Chargé tout de
    # suite (utile immédiatement, pas juste au prochain redémarrage) et
    # persisté pour survivre aux redémarrages suivants.
    if [ ! -e /dev/net/tun ]; then
      echo "Chargement du module tun (requis pour le réseau virtuel des VM)..."
      # Pas de "2>/dev/null || true" ici : un modprobe qui échoue vraiment
      # (module absent du noyau, /lib/modules désynchronisé...) doit
      # apparaître dans ce journal au lieu d'être avalé en silence — sinon
      # "Mettre à jour" prétend avoir réussi alors que /dev/net/tun manque
      # toujours, symptôme observé chez un utilisateur réel malgré ce
      # correctif déjà appliqué une première fois.
      modprobe tun
      ls -la /dev/net/tun 2>&1 || echo "ATTENTION: /dev/net/tun toujours absent après modprobe — voir dmesg"
    fi
    [ -f /etc/modules-load.d/gravity-tun.conf ] || echo "tun" > /etc/modules-load.d/gravity-tun.conf

    # Volume 1 partagé (Documents/Images/ISO/Téléchargements) — avant le
    # 2026-08-23, ces dossiers vivaient dans le /home Linux de l'admin,
    # invisibles/non partagés pour les autres comptes NAS. Migration
    # idempotente : groupe gravity-share créé, tous les comptes NAS (uid
    # >= 1000, hors comptes système) y sont ajoutés, et l'ancien contenu du
    # home est déplacé vers /srv/volumes/volume1 puis remplacé par un lien
    # symbolique (pour que tout chemin absolu déjà utilisé ailleurs, ex.
    # une VM référençant un ancien ~/ISO/xxx.iso, continue de fonctionner).
    groupadd -f gravity-share
    for u in $(getent passwd | awk -F: '$3>=1000 && $3<60000 {print $1}'); do
      usermod -aG gravity-share "$u" 2>/dev/null || true
    done
    NEW_VOL1=/srv/volumes/volume1
    mkdir -p "$NEW_VOL1"
    ADMIN_USER=$(head -1 /etc/gravity/credentials 2>/dev/null)
    if [ -n "$ADMIN_USER" ]; then
      OLD_HOME="/home/$ADMIN_USER"
      for d in Documents Images "Téléchargements" ISO; do
        OLD="$OLD_HOME/$d"
        NEW="$NEW_VOL1/$d"
        if [ -d "$OLD" ] && [ ! -L "$OLD" ]; then
          mkdir -p "$NEW"
          rsync -a "$OLD"/ "$NEW"/ 2>/dev/null || cp -a "$OLD"/. "$NEW"/ 2>/dev/null || true
          rm -rf "$OLD"
          ln -s "$NEW" "$OLD"
        fi
      done
    fi
    chgrp -R gravity-share "$NEW_VOL1" 2>/dev/null || true
    chmod -R 2775 "$NEW_VOL1" 2>/dev/null || true

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
    echo "=== GravityOS mis a jour! ==="
    git log -1 --format='Version: %h - %s (%cr)' 2>/dev/null || true

    # Redemarrage differe et decouple du cgroup courant : "systemctl restart
    # gravity-webui" tue tout le cgroup du service (KillMode par defaut =
    # control-group), qui contient CE script (spawn() par le node de
    # gravity-webui.service) — l'executer directement ici tuait le script
    # avant qu'il ait fini d'ecrire "=== DONE ===", ET coupait node pendant
    # RestartSec=5s pile pendant que le frontend interrogeait /api/updates/log
    # (d'ou le "Bad Gateway" au clic sur Installer). systemd-run cree un
    # transient unit hors du cgroup de gravity-webui : le redemarrage reel
    # n'a lieu que 3s plus tard, une fois ce script (et son "DONE") termines
    # normalement et lus par le frontend.
    # --unit doit etre unique a chaque appel (PID + timestamp) : un nom fixe
    # entre en collision si deux mises a jour se suivent de pres (le
    # transient unit precedent n'a pas encore ete nettoye par systemd), ce
    # qui fait echouer systemd-run et retombe sur le fallback direct —
    # exactement le bug qu'on cherche a eviter. Bug decouvert en relancant
    # une deuxieme mise a jour juste apres la premiere en test reel.
    echo ""
    echo "Redemarrage du service dans quelques secondes..."
    systemd-run --on-active=3 --unit="gravity-webui-restart-$$-$(date +%s)" --description="Redemarrage differe apres mise a jour" /usr/bin/systemctl restart gravity-webui 2>/dev/null \
      || systemctl restart gravity-webui 2>/dev/null || true
  `;
}
app.post("/api/updates/gravity/start", auth, (req,res) => {
  streamUpdate(gravityUpdateCmd(), res);
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
