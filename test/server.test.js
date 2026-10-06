'use strict';
// Lancer avec :  npm test
process.env.DRIVER_KEY = 'cle-conducteur-de-test-1234567890';
process.env.VIEWER_USERS = 'controle:MotDePasseLong1,autre:MotDePasseLong2';
process.env.TILE_URL = 'https://127.0.0.1:9/{z}/{x}/{y}.png';   // injoignable : on teste seulement la validation

const test = require('node:test');
const assert = require('node:assert');
const { createServer } = require('../server.js');

const KEY = process.env.DRIVER_KEY;
const basic = (u, p) => 'Basic ' + Buffer.from(u + ':' + p).toString('base64');
const GOOD = basic('controle', 'MotDePasseLong1');
let base;
let server;
const sleep = ms => new Promise(r => setTimeout(r, ms));

test.before(async () => {
  server = createServer();
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + server.address().port;
});
test.after(() => { server.closeAllConnections(); server.close(); });

let ipn = 0;
const nextIp = () => '10.0.0.' + (++ipn);
const post = (path, body, key, ip, extra) => fetch(base + path, {
  method: 'POST',
  headers: Object.assign({ 'Content-Type': 'application/json', 'X-Forwarded-For': ip || nextIp() }, key === null ? {} : { 'X-Api-Key': key || KEY }, extra || {}),
  body: typeof body === 'string' ? body : JSON.stringify(body)
});
const get = (path, auth, ip) => fetch(base + path, { headers: Object.assign({ 'X-Forwarded-For': ip || nextIp() }, auth ? { Authorization: auth } : {}) });

async function sse(path, auth) {
  const ctl = new AbortController();
  const r = await fetch(base + path, { headers: { Authorization: auth, 'X-Forwarded-For': nextIp() }, signal: ctl.signal });
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  const events = [];
  (async () => {
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        buf += dec.decode(value);
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const block = buf.slice(0, i); buf = buf.slice(i + 2);
          const ev = /^event: (.+)$/m.exec(block), da = /^data: (.+)$/m.exec(block);
          if (ev && da) events.push({ ev: ev[1], data: JSON.parse(da[1]) });
        }
      }
    } catch (e) { /* abort */ }
  })();
  return { status: r.status, events, close: () => ctl.abort() };
}
const waitFor = async (fn, ms = 2000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = fn(); if (v) return v; await sleep(25); } return null; };

test('santé : ouverte sans authentification', async () => {
  const r = await get('/healthz');
  assert.equal(r.status, 200);
});

test('contrôleurs : page protégée par identifiant et mot de passe', async () => {
  const ip = nextIp();
  assert.equal((await get('/', null, ip)).status, 401);
  const r = await get('/', null, ip);
  assert.match(r.headers.get('www-authenticate'), /^Basic/);
  assert.equal((await get('/', basic('controle', 'mauvais'), ip)).status, 401);
  assert.equal((await get('/', basic('inconnu', 'MotDePasseLong1'), ip)).status, 401);
  const ok = await get('/', GOOD, ip);
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /Suivi de convoi/);
  assert.match(ok.headers.get('content-security-policy'), /default-src 'none'/);
});

test('contrôleurs : tout est protégé (API, flux, tuiles, carte)', async () => {
  for (const p of ['/api/convoys', '/api/stream/ABCD1234', '/tiles/5/10/10.png', '/vendor/leaflet/leaflet.js']) {
    assert.equal((await get(p)).status, 401, p);
  }
});

test('contrôleurs : blocage après trop d\'essais ratés', async () => {
  const ip = nextIp();
  for (let i = 0; i < 8; i++) await get('/', basic('controle', 'faux' + i), ip);
  const r = await get('/', GOOD, ip);          // même le bon mot de passe est refusé pendant le blocage
  assert.equal(r.status, 429);
  assert.equal((await get('/', GOOD, nextIp())).status, 200);   // les autres IP ne sont pas touchées
});

test('conducteurs : clé obligatoire', async () => {
  const pos = { name: 'Camion 1', lat: 43.3, lon: 5.4 };
  assert.equal((await post('/api/pos/AAAA1111/VEH001', pos, null)).status, 401);
  assert.equal((await post('/api/pos/AAAA1111/VEH001', pos, 'mauvaise-cle')).status, 401);
  assert.equal((await post('/api/pos/AAAA1111/VEH001', pos)).status, 204);
});

test('conducteurs : validation des données', async () => {
  assert.equal((await post('/api/pos/AAAA1111/VEHVAL1', { lat: 999, lon: 5 })).status, 400);
  assert.equal((await post('/api/pos/AAAA1111/VEHVAL1', { lat: 'x', lon: 5 })).status, 400);
  assert.equal((await post('/api/pos/AAAA1111/VEHVAL1', '{pas du json')).status, 400);
  assert.equal((await post('/api/pos/AA/VEH001', { lat: 1, lon: 1 })).status, 400);               // code trop court
  assert.equal((await post('/api/pos/AAAA1111/V', { lat: 1, lon: 1 })).status, 400);              // véhicule trop court
  assert.equal((await post('/api/pos/AAAA1111/VEHVAL1', { lat: 1, lon: 1, pad: 'x'.repeat(20000) })).status, 413);
  assert.equal((await post('/api/route/AAAA1111/VEHVAL1', { r: [[1, 2]] })).status, 400);          // tracé trop court
  assert.equal((await post('/api/route/AAAA1111/VEHVAL1', { r: [[1, 2], [3, 'x']] })).status, 400);
});

test('conducteurs : une position par seconde et par véhicule', async () => {
  const ip = nextIp();
  const p = { lat: 44, lon: 5 };
  assert.equal((await post('/api/pos/RATE0001/VEHRATE', p, KEY, ip)).status, 204);
  assert.equal((await post('/api/pos/RATE0001/VEHRATE', p, KEY, ip)).status, 429);
  await sleep(1000);
  assert.equal((await post('/api/pos/RATE0001/VEHRATE', p, KEY, ip)).status, 204);
});

test('nettoyage : balises et caractères de contrôle retirés du nom', async () => {
  await post('/api/pos/CLEAN001/VEHCLEAN', { name: '<img src=x onerror=alert(1)>Camion\u0007', lat: 45, lon: 4 });
  const s = await sse('/api/stream/CLEAN001', GOOD);
  const snap = await waitFor(() => s.events.find(e => e.ev === 'snapshot'));
  s.close();
  assert.ok(snap);
  assert.ok(!/[<>\u0007]/.test(snap.data.vehicles[0].pos.name), snap.data.vehicles[0].pos.name);
});

test('flux en direct : instantané, positions, tracé, retrait', async () => {
  await post('/api/pos/LIVE0001/VEHLIVE1', { name: 'Camion A', lat: 43.3, lon: 5.4, heading: 90, speed: 20, remKm: 120, etaMin: 95, nextToll: 'La Barque', nextTollKm: 12 });
  const s = await sse('/api/stream/LIVE0001', GOOD);
  assert.equal(s.status, 200);
  const snap = await waitFor(() => s.events.find(e => e.ev === 'snapshot'));
  assert.ok(snap, 'instantané reçu à la connexion');
  assert.equal(snap.data.vehicles.length, 1);
  assert.equal(snap.data.vehicles[0].pos.nextToll, 'La Barque');
  assert.equal(typeof snap.data.t, 'number');

  await sleep(1000);
  await post('/api/pos/LIVE0001/VEHLIVE1', { name: 'Camion A', lat: 43.4, lon: 5.5 });
  const pos = await waitFor(() => s.events.find(e => e.ev === 'pos' && e.data.pos.lat === 43.4));
  assert.ok(pos, 'mise à jour reçue en direct');

  await post('/api/route/LIVE0001/VEHLIVE1', { r: [[43, 5], [44, 6], [45, 7]] });
  assert.ok(await waitFor(() => s.events.find(e => e.ev === 'route' && e.data.route.length === 3)), 'tracé reçu');

  await post('/api/clear/LIVE0001/VEHLIVE1', {});
  assert.ok(await waitFor(() => s.events.find(e => e.ev === 'remove' && e.data.id === 'VEHLIVE1')), 'retrait reçu');
  s.close();
});

test('deux convois = deux flux séparés', async () => {
  const a = await sse('/api/stream/CONVOYAA', GOOD);
  const b = await sse('/api/stream/CONVOYBB', GOOD);
  await waitFor(() => a.events.length && b.events.length);
  await post('/api/pos/CONVOYAA/VEHAAA', { name: 'Dans A', lat: 41, lon: 2 });
  await post('/api/pos/CONVOYBB/VEHBBB', { name: 'Dans B', lat: 42, lon: 3 });
  assert.ok(await waitFor(() => a.events.find(e => e.ev === 'pos')));
  assert.ok(await waitFor(() => b.events.find(e => e.ev === 'pos')));
  assert.deepEqual(a.events.filter(e => e.ev === 'pos').map(e => e.data.pos.name), ['Dans A']);
  assert.deepEqual(b.events.filter(e => e.ev === 'pos').map(e => e.data.pos.name), ['Dans B']);
  a.close(); b.close();
});

test('liste des convois actifs', async () => {
  await post('/api/pos/LISTE001/VEHLISTE', { lat: 1, lon: 1 });
  const r = await get('/api/convoys', GOOD);
  const d = await r.json();
  const c = d.convoys.find(x => x.code === 'LISTE001');
  assert.ok(c && c.vehicles === 1);
});

test('CORS : seules les origines de l\'app sont autorisées', async () => {
  const pre = (origin) => fetch(base + '/api/pos/AAAA1111/VEH001', { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'POST', 'X-Forwarded-For': nextIp() } });
  const ok = await pre('https://localhost');
  assert.equal(ok.status, 204);
  assert.equal(ok.headers.get('access-control-allow-origin'), 'https://localhost');
  assert.match(ok.headers.get('access-control-allow-headers'), /X-Api-Key/i);
  const bad = await pre('https://site-malveillant.example');
  assert.equal(bad.headers.get('access-control-allow-origin'), null);
});

test('tuiles : validation des coordonnées', async () => {
  assert.equal((await get('/tiles/25/1/1.png', GOOD)).status, 400);   // niveau de zoom trop grand
  assert.equal((await get('/tiles/5/99/1.png', GOOD)).status, 400);   // x hors de la grille
  assert.equal((await get('/tiles/5/1/1.png', GOOD)).status, 502);    // source injoignable dans le test
});

test('HTTP simple → redirigé vers HTTPS (derrière un proxy)', async () => {
  const r = await fetch(base + '/', { redirect: 'manual', headers: { 'X-Forwarded-Proto': 'http', Host: 'suivi.exemple.fr', 'X-Forwarded-For': nextIp() } });
  assert.equal(r.status, 301);
  assert.match(r.headers.get('location'), /^https:\/\/127\.0\.0\.1:\d+\/$/);   // reprend l'hôte demandé, en https
});

test('chemins inconnus et traversées de dossier refusés', async () => {
  assert.equal((await get('/inconnu', GOOD)).status, 404);
  assert.equal((await get('/vendor/leaflet/../../server.js', GOOD)).status, 404);
  assert.equal((await get('/vendor/leaflet/images/..%2f..%2fserver.js', GOOD)).status, 404);
});
