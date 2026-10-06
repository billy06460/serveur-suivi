'use strict';
/*
 * Serveur de suivi de convois — sécurisé, sans dépendance d'exécution.
 *
 *  - Les conducteurs (app) envoient leur position en HTTPS avec une CLÉ CONDUCTEUR.
 *  - Les contrôleurs ouvrent la page de suivi avec IDENTIFIANT + MOT DE PASSE.
 *  - Tout passe par UN SEUL domaine, en HTTPS (port 443) : la carte (Leaflet) et
 *    les tuiles sont servies par ce serveur, la diffusion en direct utilise
 *    Server-Sent Events (HTTP classique, passe les pare-feu d'entreprise).
 *
 * Variables d'environnement : voir .env.example et README.md.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ------------------------------------------------------------------ config
const PORT = parseInt(process.env.PORT || '3000', 10);
const DRIVER_KEY = process.env.DRIVER_KEY || '';
const VIEWER_USERS = parseUsers(process.env.VIEWER_USERS || '');
const TRUST_PROXY = process.env.TRUST_PROXY !== '0';
const FORCE_HTTPS = process.env.FORCE_HTTPS !== '0';
const DATA_DIR = process.env.DATA_DIR || '';
const KEEP_HISTORY = process.env.KEEP_HISTORY === '1' && !!DATA_DIR;
const TILE_URL = process.env.TILE_URL || 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
const TILE_CONTACT = process.env.TILE_CONTACT || 'non-renseigne';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://localhost,http://localhost,capacitor://localhost,ionic://localhost')
  .split(',').map(s => s.trim()).filter(Boolean);

const BODY_LIMIT = 16 * 1024;
const MAX_CONVOYS = 200;
const MAX_VEHICLES = 100;
const DROP_AFTER_MS = 30 * 60 * 1000;   // véhicule sans nouvelle : retiré
const MIN_INTERVAL_MS = 900;            // 1 position / seconde / véhicule au maximum
const FAIL_WINDOW_MS = 10 * 60 * 1000;
const FAIL_MAX = 8;
const FAIL_BLOCK_MS = 10 * 60 * 1000;

function parseUsers(s){
  return s.split(',').map(x => x.trim()).filter(Boolean).map(x => {
    const i = x.indexOf(':');
    return i > 0 ? { user: x.slice(0, i), pass: x.slice(i + 1) } : null;
  }).filter(u => u && u.pass.length >= 8);
}

function die(msg){
  console.error('\n[ERREUR DE CONFIGURATION] ' + msg + '\n');
  process.exit(1);
}
if (require.main === module){
  if (DRIVER_KEY.length < 16){
    die('DRIVER_KEY manquante ou trop courte (16 caractères minimum).\n  Exemple : DRIVER_KEY=' + crypto.randomBytes(18).toString('base64url'));
  }
  if (!VIEWER_USERS.length){
    die('VIEWER_USERS manquant (ou mots de passe de moins de 8 caractères).\n  Format : VIEWER_USERS="controle1:MotDePasseLong1,controle2:MotDePasseLong2"');
  }
}

// ------------------------------------------------------------------ utilitaires
function log(evt, extra){
  console.log(JSON.stringify(Object.assign({ t: new Date().toISOString(), evt: evt }, extra || {})));
}
function safeEq(a, b){
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function clientIp(req){
  if (TRUST_PROXY){
    const x = req.headers['x-forwarded-for'];
    if (x) return String(x).split(',')[0].trim();
  }
  return req.socket.remoteAddress || '?';
}
function parseBasic(req){
  const h = req.headers.authorization || '';
  if (!/^Basic /i.test(h)) return null;
  let s;
  try { s = Buffer.from(h.slice(6), 'base64').toString('utf8'); } catch (e) { return null; }
  const i = s.indexOf(':');
  return i < 0 ? null : { user: s.slice(0, i), pass: s.slice(i + 1) };
}

// blocage temporaire après trop d'échecs d'authentification
const fails = new Map();
function isBlocked(key){ const f = fails.get(key); return !!(f && f.until > Date.now()); }
function recordFail(key){
  const now = Date.now();
  let f = fails.get(key);
  if (!f || now - f.first > FAIL_WINDOW_MS){ f = { n: 0, first: now, until: 0 }; fails.set(key, f); }
  if (++f.n >= FAIL_MAX) f.until = now + FAIL_BLOCK_MS;
}
function clearFails(key){ fails.delete(key); }

// limitation de débit par IP (fenêtre glissante simple)
const hits = new Map();
function rateLimited(key, max, windowMs){
  const now = Date.now();
  let h = hits.get(key);
  if (!h || now - h.start > windowMs){ h = { start: now, n: 0 }; hits.set(key, h); }
  return ++h.n > max;
}

function readBody(req){
  return new Promise((resolve, reject) => {
    let n = 0, over = false;
    const chunks = [];
    req.on('data', c => {
      if (over) return;                      // on jette la suite sans la garder en mémoire
      n += c.length;
      if (n > BODY_LIMIT){ over = true; chunks.length = 0; reject(Object.assign(new Error('trop gros'), { status: 413 })); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// ------------------------------------------------------------------ validation
const RE_CODE = /^[A-Z0-9]{4,16}$/;
const RE_VEH = /^[A-Z0-9]{3,12}$/;
const num = (v, min, max) => (typeof v === 'number' && isFinite(v) && v >= min && v <= max) ? v : null;
const cleanText = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, max);

function cleanPos(b){
  if (!b || typeof b !== 'object') return null;
  const lat = num(b.lat, -90, 90), lon = num(b.lon, -180, 180);
  if (lat === null || lon === null) return null;
  return {
    name: cleanText(b.name, 24) || 'Véhicule',
    lat: lat, lon: lon,
    speed: num(b.speed, 0, 200),
    heading: num(b.heading, 0, 360),
    ts: Date.now(),                       // horloge du serveur
    dest: cleanText(b.dest, 60) || null,
    remKm: num(b.remKm, 0, 20000),
    etaMin: num(b.etaMin, 0, 100000),
    nextToll: cleanText(b.nextToll, 60) || null,
    nextTollKm: num(b.nextTollKm, 0, 20000)
  };
}
function cleanRoute(b){
  if (!b || !Array.isArray(b.r) || b.r.length < 2 || b.r.length > 400) return null;
  const r = [];
  for (const p of b.r){
    if (!Array.isArray(p) || p.length !== 2) return null;
    const la = num(p[0], -90, 90), lo = num(p[1], -180, 180);
    if (la === null || lo === null) return null;
    r.push([+la.toFixed(5), +lo.toFixed(5)]);
  }
  return r;
}

// ------------------------------------------------------------------ état
const convoys = new Map();     // code -> Map(vehicleId -> {pos, route})
const listeners = new Map();   // code -> Set(res)
const lastPost = new Map();    // code/vid -> timestamp
let dirty = false;

function sseSend(res, ev, data){
  try { res.write('event: ' + ev + '\ndata: ' + JSON.stringify(data) + '\n\n'); } catch (e) { /* connexion fermée */ }
}
function broadcast(code, ev, data){
  const set = listeners.get(code);
  if (!set) return;
  data.t = Date.now();
  set.forEach(res => sseSend(res, ev, data));
}
function snapshot(code){
  const m = convoys.get(code);
  const vehicles = [];
  if (m) m.forEach((v, id) => { if (v.pos) vehicles.push({ id: id, pos: v.pos, route: v.route || null }); });
  return { t: Date.now(), vehicles: vehicles };
}
function removeVehicle(code, vid){
  const m = convoys.get(code);
  if (!m || !m.has(vid)) return false;
  m.delete(vid);
  if (!m.size) convoys.delete(code);
  lastPost.delete(code + '/' + vid);
  dirty = true;
  broadcast(code, 'remove', { id: vid });
  return true;
}

// persistance facultative (redémarrage du serveur)
function stateFile(){ return path.join(DATA_DIR, 'state.json'); }
function loadState(){
  if (!DATA_DIR) return;
  try {
    const o = JSON.parse(fs.readFileSync(stateFile(), 'utf8'));
    Object.keys(o).forEach(code => {
      const m = new Map();
      Object.keys(o[code]).forEach(vid => m.set(vid, o[code][vid]));
      convoys.set(code, m);
    });
    log('state_loaded', { convoys: convoys.size });
  } catch (e) { /* premier démarrage */ }
}
function saveState(){
  if (!DATA_DIR || !dirty) return;
  dirty = false;
  const o = {};
  convoys.forEach((m, code) => { o[code] = {}; m.forEach((v, vid) => { o[code][vid] = v; }); });
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(stateFile() + '.tmp', JSON.stringify(o));
    fs.renameSync(stateFile() + '.tmp', stateFile());
  } catch (e) { log('state_save_error', { msg: String(e.message) }); }
}
function sweep(){
  const now = Date.now();
  convoys.forEach((m, code) => {
    Array.from(m.keys()).forEach(vid => {
      const v = m.get(vid);
      if (!v.pos || now - v.pos.ts > DROP_AFTER_MS) removeVehicle(code, vid);
    });
  });
  hits.forEach((h, k) => { if (now - h.start > 120000) hits.delete(k); });
  fails.forEach((f, k) => { if (now - f.first > FAIL_WINDOW_MS && f.until < now) fails.delete(k); });
}

// ------------------------------------------------------------------ réponses
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000',
  'Content-Security-Policy': "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
};
function send(res, status, body, headers){
  const h = Object.assign({}, SEC_HEADERS, headers || {});
  if (typeof body === 'object' && !Buffer.isBuffer(body)){ body = JSON.stringify(body); h['Content-Type'] = 'application/json; charset=utf-8'; }
  if (!h['Content-Type']) h['Content-Type'] = 'text/plain; charset=utf-8';
  h['Cache-Control'] = h['Cache-Control'] || 'no-store';
  res.writeHead(status, h);
  res.end(body === undefined ? '' : body);
}
function corsHeaders(req){
  const o = req.headers.origin;
  if (o && ALLOWED_ORIGINS.indexOf(o) >= 0){
    return {
      'Access-Control-Allow-Origin': o, 'Vary': 'Origin',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Api-Key',
      'Access-Control-Max-Age': '600'
    };
  }
  return {};
}

// ------------------------------------------------------------------ authentification
function requireViewer(req, res, ip){
  const key = 'v:' + ip;
  if (isBlocked(key)){ send(res, 429, 'Trop de tentatives. Réessaie plus tard.', { 'Retry-After': '600' }); return null; }
  const cred = parseBasic(req);
  let who = null;
  if (cred){
    for (const u of VIEWER_USERS){
      const a = safeEq(cred.user, u.user), b = safeEq(cred.pass, u.pass);
      if (a && b) who = u.user;
    }
  }
  if (!who){
    if (cred){ recordFail(key); log('viewer_login_fail', { ip: ip, user: String(cred.user).slice(0, 40) }); }
    send(res, 401, 'Authentification requise.', { 'WWW-Authenticate': 'Basic realm="Suivi de convoi", charset="UTF-8"' });
    return null;
  }
  clearFails(key);
  return who;
}
function requireDriver(req, res, ip){
  const key = 'd:' + ip;
  if (isBlocked(key)){ send(res, 429, 'Trop de tentatives.', Object.assign({ 'Retry-After': '600' }, corsHeaders(req))); return false; }
  const k = req.headers['x-api-key'] || '';
  if (!k || !safeEq(k, DRIVER_KEY)){
    recordFail(key);
    log('driver_key_fail', { ip: ip });
    send(res, 401, 'Clé invalide.', corsHeaders(req));
    return false;
  }
  clearFails(key);
  return true;
}

// ------------------------------------------------------------------ fichiers statiques
const PAGE_PATH = path.join(__dirname, 'public', 'suivi.html');
const LEAFLET_DIR = path.join(__dirname, 'node_modules', 'leaflet', 'dist');
const MIME = { '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png' };
const RE_VENDOR = /^\/vendor\/leaflet\/(leaflet\.js|leaflet\.css|images\/[A-Za-z0-9._-]+\.png)$/;

// ------------------------------------------------------------------ tuiles de carte (relais + cache)
const tileCache = new Map();
const TILE_CACHE_MAX = 600;
function fetchTile(z, x, y){
  return new Promise((resolve, reject) => {
    const url = TILE_URL.replace('{s}', 'a').replace('{z}', z).replace('{x}', x).replace('{y}', y);
    const req = https.get(url, {
      headers: { 'User-Agent': 'ItinerairePeages-Suivi/1.0 (contact: ' + TILE_CONTACT + ')', 'Accept': 'image/png,image/*' },
      timeout: 8000
    }, r => {
      if (r.statusCode !== 200){ r.resume(); reject(new Error('HTTP ' + r.statusCode)); return; }
      const chunks = [];
      let n = 0;
      r.on('data', c => { n += c.length; if (n > 300 * 1024){ req.destroy(); reject(new Error('trop gros')); } else chunks.push(c); });
      r.on('end', () => resolve({ body: Buffer.concat(chunks), type: r.headers['content-type'] || 'image/png' }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

// ------------------------------------------------------------------ routage
async function handle(req, res){
  const ip = clientIp(req);
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  if (p === '/healthz') return send(res, 200, 'ok');

  if (FORCE_HTTPS && req.headers['x-forwarded-proto'] === 'http' && req.headers.host){
    res.writeHead(301, { Location: 'https://' + req.headers.host + req.url });
    return res.end();
  }
  if (rateLimited('ip:' + ip, 3000, 60000)) return send(res, 429, 'Trop de requêtes.');

  // ---- API conducteurs (clé) ----
  let m = /^\/api\/(pos|route|clear)\/([A-Za-z0-9]+)\/([A-Za-z0-9]+)$/.exec(p);
  if (m){
    if (req.method === 'OPTIONS') return send(res, 204, '', corsHeaders(req));
    if (req.method !== 'POST') return send(res, 405, 'Méthode non autorisée.', corsHeaders(req));
    const kind = m[1], code = m[2].toUpperCase(), vid = m[3].toUpperCase();
    if (!RE_CODE.test(code) || !RE_VEH.test(vid)) return send(res, 400, 'Code ou identifiant invalide.', corsHeaders(req));
    if (!requireDriver(req, res, ip)) return;

    if (kind === 'clear'){
      removeVehicle(code, vid);
      log('vehicle_clear', { ip: ip, convoy: code, vehicle: vid });
      return send(res, 204, '', corsHeaders(req));
    }

    const k = code + '/' + vid;
    const now = Date.now();
    if (kind === 'pos' && now - (lastPost.get(k) || 0) < MIN_INTERVAL_MS) return send(res, 429, 'Trop rapide.', corsHeaders(req));

    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch (e) {
      const tooBig = e.status === 413;
      return send(res, tooBig ? 413 : 400, tooBig ? 'Message trop gros.' : 'JSON invalide.', Object.assign({}, corsHeaders(req), tooBig ? { Connection: 'close' } : {}));
    }

    let cm = convoys.get(code);
    if (!cm){
      if (convoys.size >= MAX_CONVOYS) return send(res, 503, 'Trop de convois.', corsHeaders(req));
      cm = new Map(); convoys.set(code, cm);
      log('convoy_created', { ip: ip, convoy: code });
    }
    let v = cm.get(vid);
    if (!v){
      if (cm.size >= MAX_VEHICLES) return send(res, 503, 'Trop de véhicules dans ce convoi.', corsHeaders(req));
      v = { pos: null, route: null }; cm.set(vid, v);
      log('vehicle_joined', { ip: ip, convoy: code, vehicle: vid });
    }

    if (kind === 'pos'){
      const pos = cleanPos(body);
      if (!pos) return send(res, 400, 'Position invalide.', corsHeaders(req));
      v.pos = pos; lastPost.set(k, now); dirty = true;
      broadcast(code, 'pos', { id: vid, pos: pos });
      if (KEEP_HISTORY){
        try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.appendFileSync(path.join(DATA_DIR, 'history.jsonl'), JSON.stringify({ convoy: code, vehicle: vid, pos: pos }) + '\n'); }
        catch (e) { /* ignore */ }
      }
    } else {
      const r = cleanRoute(body);
      if (!r) return send(res, 400, 'Tracé invalide.', corsHeaders(req));
      v.route = r; dirty = true;
      broadcast(code, 'route', { id: vid, route: r });
    }
    return send(res, 204, '', corsHeaders(req));
  }

  // ---- tout le reste : contrôleurs authentifiés ----
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Méthode non autorisée.');
  const who = requireViewer(req, res, ip);
  if (!who) return;

  if (p === '/' || p === '/suivi' || p === '/suivi.html'){
    let html;
    try { html = fs.readFileSync(PAGE_PATH); } catch (e) { return send(res, 500, 'Page introuvable.'); }
    return send(res, 200, html, { 'Content-Type': 'text/html; charset=utf-8' });
  }

  if (p === '/api/convoys'){
    const list = [];
    convoys.forEach((cm, code) => {
      let last = 0, n = 0;
      cm.forEach(v => { if (v.pos){ n++; last = Math.max(last, v.pos.ts); } });
      if (n) list.push({ code: code, vehicles: n, last: last });
    });
    list.sort((a, b) => b.last - a.last);
    return send(res, 200, { t: Date.now(), convoys: list });
  }

  m = /^\/api\/stream\/([A-Za-z0-9]+)$/.exec(p);
  if (m){
    const code = m[1].toUpperCase();
    if (!RE_CODE.test(code)) return send(res, 400, 'Code invalide.');
    res.writeHead(200, Object.assign({}, SEC_HEADERS, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store, no-transform', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no'
    }));
    res.write('retry: 3000\n\n');
    sseSend(res, 'snapshot', snapshot(code));
    if (!listeners.has(code)) listeners.set(code, new Set());
    listeners.get(code).add(res);
    log('stream_open', { ip: ip, user: who, convoy: code });
    const beat = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) { /* ignore */ } }, 20000);
    req.on('close', () => {
      clearInterval(beat);
      const set = listeners.get(code);
      if (set){ set.delete(res); if (!set.size) listeners.delete(code); }
      log('stream_close', { ip: ip, user: who, convoy: code });
    });
    return;
  }

  m = RE_VENDOR.exec(p);
  if (m){
    const file = path.join(LEAFLET_DIR, m[1]);
    if (file.indexOf(LEAFLET_DIR) !== 0) return send(res, 404, 'Introuvable.');
    let data;
    try { data = fs.readFileSync(file); } catch (e) { return send(res, 404, 'Bibliothèque de carte absente (npm install ?).'); }
    return send(res, 200, data, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'private, max-age=86400' });
  }

  m = /^\/tiles\/(\d{1,2})\/(\d{1,7})\/(\d{1,7})\.png$/.exec(p);
  if (m){
    const z = +m[1], x = +m[2], y = +m[3];
    if (z > 19 || x >= Math.pow(2, z) || y >= Math.pow(2, z)) return send(res, 400, 'Tuile invalide.');
    if (rateLimited('tile:' + ip, 900, 60000)) return send(res, 429, 'Trop de tuiles demandées.');
    const key = z + '/' + x + '/' + y;
    let t = tileCache.get(key);
    if (!t){
      try { t = await fetchTile(z, x, y); }
      catch (e) { return send(res, 502, 'Fond de carte indisponible.'); }
      if (tileCache.size >= TILE_CACHE_MAX) tileCache.delete(tileCache.keys().next().value);
      tileCache.set(key, t);
    }
    return send(res, 200, t.body, { 'Content-Type': t.type, 'Cache-Control': 'private, max-age=86400' });
  }

  return send(res, 404, 'Introuvable.');
}

function createServer(){
  return http.createServer((req, res) => {
    handle(req, res).catch(e => {
      log('error', { msg: String(e && e.message) });
      try { send(res, 500, 'Erreur interne.'); } catch (x) { /* ignore */ }
    });
  });
}

if (require.main === module){
  loadState();
  const server = createServer();
  server.requestTimeout = 0;           // flux SSE longs
  server.headersTimeout = 20000;
  server.listen(PORT, () => {
    log('listening', { port: PORT, viewers: VIEWER_USERS.length, history: KEEP_HISTORY, persist: !!DATA_DIR });
    if (!fs.existsSync(LEAFLET_DIR)) console.warn('[ATTENTION] node_modules/leaflet absent : lance "npm install" (la carte ne s\'affichera pas sinon).');
  });
  setInterval(sweep, 30000).unref();
  setInterval(saveState, 15000).unref();
  const bye = () => { saveState(); process.exit(0); };
  process.on('SIGTERM', bye);
  process.on('SIGINT', bye);
}

module.exports = { createServer, cleanPos, cleanRoute, parseUsers, convoys };
