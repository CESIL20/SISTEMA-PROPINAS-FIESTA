'use strict';
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
const TOKEN_TTL = 7 * 24 * 3600 * 1000; // sesión de 7 días

// ---------- Configuración ----------
const { SUPABASE_URL, SUPABASE_SERVICE_KEY } = process.env;
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Faltan SUPABASE_URL y SUPABASE_SERVICE_KEY. Copia .env.example como .env y complétalo.');
  process.exit(1);
}
let SECRET = process.env.SESSION_SECRET;
if (!SECRET || SECRET.length < 16) {
  if (PROD) { console.error('En producción debes definir SESSION_SECRET (mínimo 16 caracteres).'); process.exit(1); }
  SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('SESSION_SECRET no definido: se usa una clave temporal (las sesiones se pierden al reiniciar).');
}

// La clave service_role se queda SOLO en el servidor. Nunca la envíes al navegador.
const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const T_USERS = 'propinas_users';
const T_STATE = 'propinas_state';

async function q(promise) {
  const { data, error } = await promise;
  if (error) throw error;
  return data;
}

// ---------- Claves (scrypt, sin dependencias extra) ----------
function hashPw(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function checkPw(pw, u) {
  const h = crypto.scryptSync(pw, u.salt, 64);
  const b = Buffer.from(u.hash, 'hex');
  return b.length === h.length && crypto.timingSafeEqual(h, b);
}
const okName = (n) => typeof n === 'string' && /^[\w.-]{3,30}$/.test(n);
const COLS = 'id,username,role';

async function addUser(username, password, role) {
  const { salt, hash } = hashPw(password);
  return q(sb.from(T_USERS).insert({ username, role, salt, hash }).select(COLS).single());
}
async function countMasters() {
  const { count, error } = await sb.from(T_USERS).select('id', { count: 'exact', head: true }).eq('role', 'master');
  if (error) throw error;
  return count || 0;
}

// ---------- Usuario máster inicial ----------
async function seedMaster() {
  if ((await countMasters()) > 0) return;
  const name = process.env.MASTER_USER || 'master';
  let pass = process.env.MASTER_PASS;
  let generated = false;
  if (!pass) { pass = crypto.randomBytes(6).toString('base64url'); generated = true; }
  await addUser(name, pass, 'master');
  console.log('\n=== USUARIO MÁSTER CREADO ===');
  console.log('Usuario: ' + name);
  console.log('Clave:   ' + pass + (generated ? '   (guárdala ahora; luego cámbiala desde la app)' : ''));
  console.log('=============================\n');
}

// ---------- Sesiones (cookie firmada) ----------
const b64 = (s) => Buffer.from(s).toString('base64url');
function sign(payload) {
  const body = b64(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verify(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const exp = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(exp);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > 0) o[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return o;
}

// Envuelve handlers async para responder 500 sin tumbar el servidor
const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((e) => {
  console.error(e);
  res.status(500).json({ error: 'Error del servidor' });
});

// TODO: si hay mucho tráfico, cachear el usuario por unos segundos en memoria para no consultar Supabase en cada petición.
const auth = h(async (req, res, next) => {
  const p = verify(cookies(req).sid);
  if (!p) return res.status(401).json({ error: 'No autenticado' });
  const u = await q(sb.from(T_USERS).select(COLS).eq('id', p.id).maybeSingle()); // el rol se lee siempre de la base
  if (!u) return res.status(401).json({ error: 'No autenticado' });
  req.user = u;
  next();
});
function master(req, res, next) {
  if (req.user.role !== 'master') return res.status(403).json({ error: 'Solo el máster puede hacer esto' });
  next();
}

// ---------- Límite de intentos de login ----------
// TODO: con varias instancias del servidor, mover este contador a Supabase o Redis.
const tries = new Map();
function limited(ip) {
  const now = Date.now();
  const a = (tries.get(ip) || []).filter((t) => now - t < 15 * 60e3);
  tries.set(ip, a);
  return a.length >= 10;
}
function failed(ip) { const a = tries.get(ip) || []; a.push(Date.now()); tries.set(ip, a); }

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

app.post('/api/login', h(async (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: 'Demasiados intentos, espera unos minutos' });
  const { username, password } = req.body || {};
  const u = typeof username === 'string' && typeof password === 'string'
    ? await q(sb.from(T_USERS).select('*').eq('username_lc', username.trim().toLowerCase()).maybeSingle())
    : null;
  if (!u || !checkPw(password, u)) { failed(req.ip); return res.status(401).json({ error: 'Credenciales incorrectas' }); }
  res.setHeader('Set-Cookie', 'sid=' + sign({ id: u.id, exp: Date.now() + TOKEN_TTL }) +
    '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + (TOKEN_TTL / 1000) + (PROD ? '; Secure' : ''));
  res.json({ id: u.id, username: u.username, role: u.role });
}));
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' + (PROD ? '; Secure' : ''));
  res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json(req.user));

// Datos de propinas: todos leen, solo el máster escribe
app.get('/api/state', auth, h(async (req, res) => {
  const r = await q(sb.from(T_STATE).select('state,rev').eq('id', 1).single());
  res.json({ state: r.state, rev: r.rev });
}));
app.put('/api/state', auth, master, h(async (req, res) => {
  const s = req.body && req.body.state;
  if (!s || typeof s !== 'object' || !Array.isArray(s.people) || !s.periods || typeof s.periods !== 'object' || typeof s.anchor !== 'string') {
    return res.status(400).json({ error: 'Datos inválidos' });
  }
  const rev = await q(sb.rpc('propinas_save_state', { p_state: s }));
  res.json({ rev });
}));

// Gestión de usuarios: solo el máster
app.get('/api/users', auth, master, h(async (req, res) => {
  res.json({ users: await q(sb.from(T_USERS).select(COLS).order('created_at')) });
}));
app.post('/api/users', auth, master, h(async (req, res) => {
  const { username, password, role } = req.body || {};
  if (!okName(username) || typeof password !== 'string' || password.length < 6 || !['master', 'usuario'].includes(role)) {
    return res.status(400).json({ error: 'Usuario de 3 a 30 letras o números y clave de mínimo 6 caracteres' });
  }
  try {
    res.json(await addUser(username, password, role));
  } catch (e) {
    if (e && e.code === '23505') return res.status(409).json({ error: 'Ese usuario ya existe' });
    throw e;
  }
}));
app.patch('/api/users/:id', auth, master, h(async (req, res) => {
  const u = await q(sb.from(T_USERS).select(COLS).eq('id', req.params.id).maybeSingle());
  if (!u) return res.status(404).json({ error: 'No existe' });
  const { password, role } = req.body || {};
  const patch = {};
  if (password !== undefined) {
    if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Clave de mínimo 6 caracteres' });
    Object.assign(patch, hashPw(password));
  }
  if (role !== undefined) {
    if (!['master', 'usuario'].includes(role)) return res.status(400).json({ error: 'Rol inválido' });
    if (u.role === 'master' && role !== 'master' && (await countMasters()) <= 1) {
      return res.status(400).json({ error: 'Debe quedar al menos un máster' });
    }
    patch.role = role;
  }
  if (Object.keys(patch).length) await q(sb.from(T_USERS).update(patch).eq('id', u.id));
  res.json({ id: u.id, username: u.username, role: patch.role || u.role });
}));
app.delete('/api/users/:id', auth, master, h(async (req, res) => {
  const u = await q(sb.from(T_USERS).select(COLS).eq('id', req.params.id).maybeSingle());
  if (!u) return res.status(404).json({ error: 'No existe' });
  if (u.id === req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  if (u.role === 'master' && (await countMasters()) <= 1) return res.status(400).json({ error: 'Debe quedar al menos un máster' });
  await q(sb.from(T_USERS).delete().eq('id', u.id));
  res.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, 'public')));

seedMaster()
  .then(() => app.listen(PORT, () => console.log('Propinas escuchando en http://localhost:' + PORT)))
  .catch((e) => {
    console.error('No se pudo iniciar. ¿Ejecutaste supabase.sql y son correctas las claves?\n', e.message || e);
    process.exit(1);
  });
