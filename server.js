'use strict';
/**
 * BiiLHex Studio — fullstack server (zero external dependencies)
 * Requires Node.js >= 22.5 (uses built-in node:sqlite).
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ALLOW_REGISTER = (process.env.ALLOW_REGISTER || 'true') !== 'false';
const MAX_UPLOAD = (Number(process.env.MAX_UPLOAD_MB) || 25) * 1024 * 1024;
const SESSION_MS = 30 * 24 * 3600 * 1000;
const SECURE_COOKIE = process.env.NODE_ENV === 'production';

const PUB = path.join(__dirname, 'public');
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPL = path.join(DATA, 'uploads');
fs.mkdirSync(UPL, { recursive: true });

/* ───────────── Database ───────────── */
const db = new DatabaseSync(path.join(DATA, 'studio.db'));
db.exec(`
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  hash TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS animations(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, anim_id TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, type TEXT NOT NULL, filename TEXT NOT NULL, stored TEXT NOT NULL,
  size INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS history(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  workspace TEXT NOT NULL DEFAULT 'BiiLHex Studio');
CREATE INDEX IF NOT EXISTS idx_projects_u ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_anims_u ON animations(user_id);
CREATE INDEX IF NOT EXISTS idx_assets_u ON assets(user_id);
CREATE INDEX IF NOT EXISTS idx_hist_u ON history(user_id);
`);
const q = (sql) => db.prepare(sql);
db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now());

/* ───────────── Helpers ───────────── */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const now = () => Date.now();

function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': typeof body === 'string' || Buffer.isBuffer(body) ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(data);
}

function readJson(req, limit = 100 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, 'Payload terlalu besar')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new HttpError(400, 'JSON tidak valid')); }
    });
    req.on('error', reject);
  });
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function cookieHeader(token, maxAgeMs) {
  return `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}${SECURE_COOKIE ? '; Secure' : ''}`;
}

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [alg, saltHex, keyHex] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const key = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 64);
  const expected = Buffer.from(keyHex, 'hex');
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}
const DUMMY_HASH = hashPassword('dummy-password-for-timing');

// naive in-memory login rate limiter
const attempts = new Map();
function rateLimit(ip, max = 10, windowMs = 15 * 60 * 1000) {
  const t = now();
  const rec = attempts.get(ip);
  if (!rec || rec.reset < t) { attempts.set(ip, { count: 1, reset: t + windowMs }); return; }
  if (++rec.count > max) throw new HttpError(429, 'Terlalu banyak percobaan, coba lagi nanti');
}
setInterval(() => { const t = now(); for (const [k, v] of attempts) if (v.reset < t) attempts.delete(k); }, 60_000).unref();

function currentUser(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;
  const row = q(`SELECT u.id, u.username, s.expires FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`).get(sid);
  if (!row || row.expires < now()) return null;
  return { id: row.id, username: row.username, sid };
}
function requireUser(req) {
  const u = currentUser(req);
  if (!u) throw new HttpError(401, 'Silakan login');
  return u;
}

function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  q('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(token, userId, now() + SESSION_MS);
  return cookieHeader(token, SESSION_MS);
}

const str = (v, max, field, { required = true } = {}) => {
  if (typeof v !== 'string') v = v == null ? '' : String(v);
  v = v.trim();
  if (required && !v) throw new HttpError(400, `${field} wajib diisi`);
  if (v.length > max) throw new HttpError(400, `${field} maksimal ${max} karakter`);
  return v;
};

/* ───────────── Upload rules ───────────── */
const ALLOWED_EXT = {
  Decal: ['png', 'jpg', 'jpeg', 'bmp', 'tga'],
  Audio: ['mp3', 'ogg'],
  Animation: ['rbxm', 'rbxmx', 'fbx'],
  Model: ['fbx', 'obj', 'rbxm', 'rbxmx', 'gltf', 'glb'],
};

function handleUpload(req, res, user, url) {
  const name = str(url.searchParams.get('name'), 80, 'Nama aset');
  const type = url.searchParams.get('type');
  if (!ALLOWED_EXT[type]) throw new HttpError(400, 'Tipe aset tidak valid');
  const filename = path.basename(str(url.searchParams.get('filename'), 200, 'Nama file')).replace(/[^\w.\- ]/g, '_');
  const ext = path.extname(filename).slice(1).toLowerCase();
  if (!ALLOWED_EXT[type].includes(ext)) throw new HttpError(400, `Ekstensi .${ext || '?'} tidak diizinkan untuk ${type} (boleh: ${ALLOWED_EXT[type].join(', ')})`);
  const declared = Number(req.headers['content-length']);
  if (!declared || declared > MAX_UPLOAD) throw new HttpError(declared ? 413 : 411, `Ukuran file maksimal ${MAX_UPLOAD / 1048576} MB`);

  const dir = path.join(UPL, String(user.id));
  fs.mkdirSync(dir, { recursive: true });
  const stored = crypto.randomBytes(16).toString('hex') + '.' + ext;
  const full = path.join(dir, stored);
  const out = fs.createWriteStream(full, { flags: 'wx' });
  let size = 0, failed = false;

  const fail = (err) => {
    if (failed) return; failed = true;
    out.destroy(); fs.rm(full, { force: true }, () => {});
    if (!res.headersSent) send(res, err.status || 500, { error: err.message || 'Upload gagal' });
    req.unpipe(); req.resume();
  };
  req.on('data', (c) => { size += c.length; if (size > MAX_UPLOAD) fail(new HttpError(413, 'File terlalu besar')); });
  req.on('error', fail);
  out.on('error', fail);
  out.on('finish', () => {
    if (failed) return;
    if (size === 0) return fail(new HttpError(400, 'File kosong'));
    const t = now();
    const r = q('INSERT INTO assets(user_id,name,type,filename,stored,size,created_at) VALUES(?,?,?,?,?,?,?)')
      .run(user.id, name, type, filename, stored, size, t);
    q('INSERT INTO history(user_id,text,created_at) VALUES(?,?,?)').run(user.id, `${name} · ${type} · ${filename}`, t);
    send(res, 201, { id: Number(r.lastInsertRowid), name, type, filename, size, created_at: t });
  });
  req.pipe(out);
}

/* ───────────── API routes ───────────── */
async function api(req, res, url) {
  const m = req.method, p = url.pathname.replace(/\/+$/, '');
  const ip = req.socket.remoteAddress || 'x';

  if (m !== 'GET' && m !== 'HEAD' && req.headers['x-requested-with'] !== 'studio')
    throw new HttpError(403, 'Permintaan ditolak');

  /* — auth — */
  if (p === '/api/auth/register' && m === 'POST') {
    if (!ALLOW_REGISTER) throw new HttpError(403, 'Pendaftaran dinonaktifkan');
    rateLimit('reg:' + ip, 10);
    const b = await readJson(req);
    const username = str(b.username, 32, 'Username');
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) throw new HttpError(400, 'Username 3–32 karakter: huruf, angka, _ . -');
    const password = typeof b.password === 'string' ? b.password : '';
    if (password.length < 8 || password.length > 128) throw new HttpError(400, 'Password 8–128 karakter');
    if (q('SELECT 1 FROM users WHERE username = ?').get(username)) throw new HttpError(409, 'Username sudah dipakai');
    const r = q('INSERT INTO users(username,hash,created_at) VALUES(?,?,?)').run(username, hashPassword(password), now());
    const id = Number(r.lastInsertRowid);
    q('INSERT INTO settings(user_id) VALUES(?)').run(id);
    return send(res, 201, { id, username }, { 'Set-Cookie': startSession(res, id) });
  }
  if (p === '/api/auth/login' && m === 'POST') {
    rateLimit('login:' + ip);
    const b = await readJson(req);
    const row = q('SELECT id, username, hash FROM users WHERE username = ?').get(String(b.username || ''));
    const ok = verifyPassword(String(b.password || ''), row ? row.hash : DUMMY_HASH);
    if (!row || !ok) throw new HttpError(401, 'Username atau password salah');
    return send(res, 200, { id: row.id, username: row.username }, { 'Set-Cookie': startSession(res, row.id) });
  }
  if (p === '/api/auth/logout' && m === 'POST') {
    const u = currentUser(req);
    if (u) q('DELETE FROM sessions WHERE token = ?').run(u.sid);
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
  }
  if (p === '/api/auth/me' && m === 'GET') {
    const u = currentUser(req);
    if (!u) return send(res, 200, { user: null, registration: ALLOW_REGISTER });
    const s = q('SELECT workspace FROM settings WHERE user_id = ?').get(u.id);
    return send(res, 200, { user: { id: u.id, username: u.username }, workspace: s ? s.workspace : 'BiiLHex Studio', registration: ALLOW_REGISTER });
  }

  /* — everything below needs login — */
  const user = requireUser(req);

  if (p === '/api/auth/password' && m === 'POST') {
    const b = await readJson(req);
    const row = q('SELECT hash FROM users WHERE id = ?').get(user.id);
    if (!verifyPassword(String(b.current || ''), row.hash)) throw new HttpError(400, 'Password lama salah');
    const next = typeof b.next === 'string' ? b.next : '';
    if (next.length < 8 || next.length > 128) throw new HttpError(400, 'Password baru 8–128 karakter');
    q('UPDATE users SET hash = ? WHERE id = ?').run(hashPassword(next), user.id);
    q('DELETE FROM sessions WHERE user_id = ? AND token != ?').run(user.id, user.sid);
    return send(res, 200, { ok: true });
  }

  if (p === '/api/stats' && m === 'GET') {
    const c = (t) => q(`SELECT COUNT(*) n FROM ${t} WHERE user_id = ?`).get(user.id).n;
    return send(res, 200, { projects: c('projects'), animations: c('animations'), assets: c('assets'), uploads: c('history') });
  }

  /* projects */
  if (p === '/api/projects' && m === 'GET')
    return send(res, 200, q('SELECT id,name,note,created_at FROM projects WHERE user_id = ? ORDER BY id DESC').all(user.id));
  if (p === '/api/projects' && m === 'POST') {
    const b = await readJson(req);
    const name = str(b.name, 80, 'Nama project'), note = str(b.note, 500, 'Catatan', { required: false });
    const t = now();
    const r = q('INSERT INTO projects(user_id,name,note,created_at) VALUES(?,?,?,?)').run(user.id, name, note, t);
    return send(res, 201, { id: Number(r.lastInsertRowid), name, note, created_at: t });
  }
  let mm;
  if ((mm = p.match(/^\/api\/projects\/(\d+)$/))) {
    const id = Number(mm[1]);
    if (m === 'PUT') {
      const b = await readJson(req);
      const name = str(b.name, 80, 'Nama project'), note = str(b.note, 500, 'Catatan', { required: false });
      const r = q('UPDATE projects SET name = ?, note = ? WHERE id = ? AND user_id = ?').run(name, note, id, user.id);
      if (!r.changes) throw new HttpError(404, 'Project tidak ditemukan');
      return send(res, 200, { id, name, note });
    }
    if (m === 'DELETE') {
      const r = q('DELETE FROM projects WHERE id = ? AND user_id = ?').run(id, user.id);
      if (!r.changes) throw new HttpError(404, 'Project tidak ditemukan');
      return send(res, 200, { ok: true });
    }
  }

  /* animations */
  if (p === '/api/animations' && m === 'GET')
    return send(res, 200, q('SELECT id,name,anim_id,created_at FROM animations WHERE user_id = ? ORDER BY id DESC').all(user.id));
  if (p === '/api/animations' && m === 'POST') {
    const b = await readJson(req);
    const name = str(b.name, 80, 'Nama animasi');
    const animId = str(b.anim_id, 40, 'Animation ID').replace(/^rbxassetid:\/\//i, '');
    if (!/^\d{1,20}$/.test(animId)) throw new HttpError(400, 'Animation ID harus berupa angka (boleh diawali rbxassetid://)');
    const t = now();
    const r = q('INSERT INTO animations(user_id,name,anim_id,created_at) VALUES(?,?,?,?)').run(user.id, name, animId, t);
    return send(res, 201, { id: Number(r.lastInsertRowid), name, anim_id: animId, created_at: t });
  }
  if ((mm = p.match(/^\/api\/animations\/(\d+)$/)) && m === 'DELETE') {
    const r = q('DELETE FROM animations WHERE id = ? AND user_id = ?').run(Number(mm[1]), user.id);
    if (!r.changes) throw new HttpError(404, 'Animasi tidak ditemukan');
    return send(res, 200, { ok: true });
  }

  /* assets */
  if (p === '/api/assets' && m === 'GET')
    return send(res, 200, q('SELECT id,name,type,filename,size,created_at FROM assets WHERE user_id = ? ORDER BY id DESC').all(user.id));
  if (p === '/api/assets' && m === 'POST') return handleUpload(req, res, user, url);
  if ((mm = p.match(/^\/api\/assets\/(\d+)(\/download)?$/))) {
    const id = Number(mm[1]);
    const a = q('SELECT * FROM assets WHERE id = ? AND user_id = ?').get(id, user.id);
    if (!a) throw new HttpError(404, 'Aset tidak ditemukan');
    const file = path.join(UPL, String(user.id), a.stored);
    if (mm[2] && m === 'GET') {
      if (!fs.existsSync(file)) throw new HttpError(404, 'File hilang dari penyimpanan');
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': fs.statSync(file).size,
        'Content-Disposition': `attachment; filename="${a.filename.replace(/"/g, '')}"; filename*=UTF-8''${encodeURIComponent(a.filename)}`,
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'private, no-store',
      });
      return fs.createReadStream(file).pipe(res);
    }
    if (!mm[2] && m === 'DELETE') {
      q('DELETE FROM assets WHERE id = ?').run(id);
      fs.rm(file, { force: true }, () => {});
      return send(res, 200, { ok: true });
    }
  }

  /* history */
  if (p === '/api/history' && m === 'GET')
    return send(res, 200, q('SELECT id,text,created_at FROM history WHERE user_id = ? ORDER BY id DESC LIMIT 200').all(user.id));
  if (p === '/api/history' && m === 'DELETE') {
    q('DELETE FROM history WHERE user_id = ?').run(user.id);
    return send(res, 200, { ok: true });
  }

  /* settings */
  if (p === '/api/settings' && m === 'GET') {
    const s = q('SELECT workspace FROM settings WHERE user_id = ?').get(user.id);
    return send(res, 200, { workspace: s ? s.workspace : 'BiiLHex Studio' });
  }
  if (p === '/api/settings' && m === 'PUT') {
    const b = await readJson(req);
    const workspace = str(b.workspace, 60, 'Workspace name');
    q(`INSERT INTO settings(user_id,workspace) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET workspace = excluded.workspace`).run(user.id, workspace);
    return send(res, 200, { workspace });
  }

  throw new HttpError(404, 'Endpoint tidak ditemukan');
}

/* ───────────── Static files ───────────── */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.txt': 'text/plain; charset=utf-8',
};
function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method tidak diizinkan');
  let rel;
  try { rel = decodeURIComponent(url.pathname); } catch { throw new HttpError(400, 'URL tidak valid'); }
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUB, rel));
  if (file !== PUB && !file.startsWith(PUB + path.sep)) throw new HttpError(403, 'Dilarang');
  let st;
  try { st = fs.statSync(file); } catch { throw new HttpError(404, 'Tidak ditemukan'); }
  if (!st.isFile()) throw new HttpError(404, 'Tidak ditemukan');
  res.writeHead(200, {
    'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
    'Content-Length': st.size,
    'Cache-Control': 'no-cache',
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(file).pipe(res);
}

/* ───────────── Server ───────────── */
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) await api(req, res, url);
    else serveStatic(req, res, url);
  } catch (err) {
    if (res.headersSent) return res.destroy();
    const status = err instanceof HttpError ? err.status : 500;
    if (status === 500) console.error(err);
    send(res, status, { error: status === 500 ? 'Kesalahan server' : err.message });
  }
});

server.listen(PORT, HOST, () => console.log(`BiiLHex Studio berjalan di http://localhost:${PORT}`));

function shutdown() { server.close(() => { db.close(); process.exit(0); }); setTimeout(() => process.exit(0), 3000).unref(); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
