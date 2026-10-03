#!/usr/bin/env node
"use strict";
// Authentification du service WebDAV (rclone --auth-proxy).
//
// rclone lance ce programme pour chaque nouvelle connexion : il reçoit
// {"user":"...","pass":"..."} sur STDIN et doit répondre avec la configuration
// du backend (code 0) ou refuser (code ≠ 0). Seuls les utilisateurs cochés dans
// Paramètres > Services > WebDAV (/etc/gravity/service-access.json) peuvent se
// connecter, avec le MOT DE PASSE DE LEUR COMPTE NAS (vérifié contre
// /etc/shadow) : plus d'identifiant WebDAV séparé, et un administrateur n'a pas
// accès au service tant qu'il n'est pas coché.
//
// Sans dépendance (démarre à chaque connexion). Chemins surchargeables par
// variables d'environnement, uniquement pour les tests.
const fs = require("fs");
const { execFileSync } = require("child_process");

const ACCESS = process.env.GRAVITY_SERVICE_ACCESS || "/etc/gravity/service-access.json";
const PASSWD = process.env.GRAVITY_PASSWD || "/etc/passwd";
const SHADOW = process.env.GRAVITY_SHADOW || "/etc/shadow";
const STATE = process.env.GRAVITY_AUTH_STATE || "/run/gravity-webdav-auth.json";
const ROOT = process.env.GRAVITY_WEBDAV_ROOT || "/srv/shares";
const FAIL_DELAY_MS = process.env.GRAVITY_AUTH_FAIL_DELAY_MS !== undefined ? Number(process.env.GRAVITY_AUTH_FAIL_DELAY_MS) : 1000;
const MAX_FAILS = 20, FAIL_WINDOW_MS = 10 * 60 * 1000, LOCK_MS = 2 * 60 * 1000;

function sleep(ms) { if (ms > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function loadState() { try { return JSON.parse(fs.readFileSync(STATE, "utf8")); } catch { return {}; } }
function saveState(s) { try { fs.writeFileSync(STATE, JSON.stringify(s), { mode: 0o600 }); } catch {} }

// Refus : ralentit chaque échec (force brute) et verrouille brièvement un compte
// visé par trop d'essais. Rien de secret n'est écrit dans le journal.
function deny(user, reason, countFailure = true) {
  if (countFailure && user) {
    const st = loadState(), now = Date.now();
    const r = st[user] && now - st[user].first < FAIL_WINDOW_MS ? st[user] : { count: 0, first: now, lockedUntil: 0 };
    r.count++;
    if (r.count >= MAX_FAILS) { r.lockedUntil = now + LOCK_MS; r.count = 0; r.first = now; }
    st[user] = r;
    saveState(st);
    sleep(FAIL_DELAY_MS);
  }
  process.stderr.write(`webdav-auth: refus (${reason})${user ? " pour " + user : ""}\n`);
  process.exit(1);
}

function readInput() {
  try { return JSON.parse(fs.readFileSync(0, "utf8")); } catch { return null; }
}

function fieldOf(file, user, index) {
  try {
    const line = fs.readFileSync(file, "utf8").split("\n").find(l => l.startsWith(user + ":"));
    return line ? line.split(":")[index] : undefined;
  } catch { return undefined; }
}

// crypt(3) via libcrypt (yescrypt, sha512... : tous les formats de /etc/shadow).
// Le mot de passe passe par STDIN, jamais en argument (visible dans `ps`).
function passwordMatches(password, hash) {
  const code = [
    "import ctypes,sys,json",
    "d=json.load(sys.stdin)",
    'l=ctypes.CDLL("libcrypt.so.1")',
    "l.crypt.restype=ctypes.c_char_p",
    "l.crypt.argtypes=[ctypes.c_char_p,ctypes.c_char_p]",
    'r=l.crypt(d["pw"].encode(),d["hash"].encode())',
    'print("ok" if r and r.decode()==d["hash"] else "no")',
  ].join("\n");
  try {
    return execFileSync("python3", ["-c", code], { input: JSON.stringify({ pw: password, hash }), timeout: 8000 }).toString().trim() === "ok";
  } catch { return false; }
}

const input = readInput();
if (!input || typeof input.user !== "string") deny("", "entrée invalide", false);
const user = input.user;
if (typeof input.pass !== "string" || !input.pass) deny(user, "mot de passe absent");
if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(user)) deny("", "nom d'utilisateur invalide", false);

const st = loadState();
if (st[user] && st[user].lockedUntil > Date.now()) deny(user, "compte temporairement bloqué (trop d'essais)", false);

let allowed = [];
try { allowed = JSON.parse(fs.readFileSync(ACCESS, "utf8")).webdav || []; } catch {}
if (!Array.isArray(allowed) || !allowed.includes(user)) deny(user, "utilisateur non autorisé pour WebDAV");

const uid = Number(fieldOf(PASSWD, user, 2));
if (!(uid >= 1000 && uid < 60000)) deny(user, "compte inexistant ou système"); // 60000+ : comptes de service

const hash = fieldOf(SHADOW, user, 1) || "";
if (!hash.startsWith("$")) deny(user, "compte désactivé ou sans mot de passe");
if (!passwordMatches(input.pass, hash)) deny(user, "mot de passe incorrect");

if (st[user]) { delete st[user]; saveState(st); }
process.stdout.write(JSON.stringify({ type: "local", _root: ROOT }) + "\n");
