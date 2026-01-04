const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');

console.log("REST service starting");

const app = express();
const PORT = 9000;

// --- Certs ---
const CERT_DIR = path.join(__dirname, 'cert');
const CRT_PATH = path.join(CERT_DIR, 'server.crt');
const KEY_PATH = path.join(CERT_DIR, 'server.key');

// --- Storage ---
const DATA_DIR = path.join(__dirname, 'data');
const STORE_FILE = path.join(DATA_DIR, 'store.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// --- Config ---
const JWT_SECRET = 'some-very-secret-key';
const TTL = 864000; // 10 weeks. 
// Should be less, but appropriate for this assignment to allow testing without creating new users

const ALLOWED_ORIGINS = 'https://localhost:8000'
  .split(',').map(s => s.trim()).filter(s => s.length > 0);

// --- Helpers ---
function readJson(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function writeJson(filePath, obj) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), { mode: 0o600 });
}

function getStore() { return readJson(STORE_FILE, {}); }
function saveStore(store) { writeJson(STORE_FILE, store); }
function getUsers() { return readJson(USERS_FILE, {}); }
function saveUsers(users) { writeJson(USERS_FILE, users); }

function b64urlEncode(buffer) {
  return Buffer.from(buffer).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(stringParam) {
  let padding = '';
  const remainder = stringParam.length % 4;
  if (remainder !== 0) {
    padding = '='.repeat(4 - remainder);
  }
  const b64 = (stringParam + padding).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64, 'base64');
}

function timingEqualStr(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function signJwt(payloadObj, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = b64urlEncode(JSON.stringify(header));
  const payloadB64 = b64urlEncode(JSON.stringify(payloadObj));
  const data = `${headerB64}.${payloadB64}`;
  const sig = crypto.createHmac('sha256', secret).update(data).digest();
  const sigB64 = b64urlEncode(sig);
  return `${data}.${sigB64}`;
}

function verifyJwt(token, secret) {
  if (!token || typeof token !== 'string') return { ok: false, reason: 'missing token' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'bad format' };
  const [h, p, s] = parts;
  let header, payload;
  try {
    header = JSON.parse(b64urlDecode(h).toString('utf8'));
    payload = JSON.parse(b64urlDecode(p).toString('utf8'));
  } catch {
    return { ok: false, reason: 'bad json' };
  }
  if (!header || header.alg !== 'HS256') return { ok: false, reason: 'bad alg' };
  const data = `${h}.${p}`;
  const expectedSig = b64urlEncode(crypto.createHmac('sha256', secret).update(data).digest());

  if (!timingEqualStr(expectedSig, s)) return { ok: false, reason: 'bad signature' };

  const now = Math.floor(Date.now() / 1000);
  if (payload.iat && typeof payload.iat !== 'number') return { ok: false, reason: 'missing iat' };
  if (payload.exp && typeof payload.exp !== 'number') return { ok: false, reason: 'missing exp' };
  if (payload.iss !== 'REST-service') return { ok: false, reason: 'bad issuer' };
  if (payload.nbf && typeof payload.nbf !== 'number') return { ok: false, reason: 'bad nbf' };
  if (payload.nbf && now < payload.nbf) return { ok: false, reason: 'not yet valid' };
  if (now > payload.exp) return { ok: false, reason: 'expired' };

  return { ok: true, payload };
}

// --- CORS middleware --- (And REST-resource recommendations)
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  }

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});


// --- Body parsers with limits --- (REST-resource recommendations)
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));
app.use(express.text({ type: ['text/*'], limit: '50kb' }));

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// --- Validation ---
function isValidUsername(username) {
  return typeof username === 'string' && /^[A-Za-z0-9_-]{3,30}$/.test(username);
}

function requireJwt(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  // Query token for browser (Only for demo use)
  const q = req.query && typeof req.query.token === 'string' ? req.query.token : null;
  const token = (m && m[1]) ? m[1] : q;
  if (!token) return res.status(401).json({ success: false, reason: 'missing token' });
  const result = verifyJwt(token, JWT_SECRET);
  if (!result.ok) {
    // If token is expired, delete the user + stored data
    if (result.reason === 'expired') {
      const username = req.params.username;
      if (isValidUsername(username)) {
        const users = getUsers();
        if (users[username]) {
          delete users[username];
          saveUsers(users);
          const store = getStore();
          if (store[username]) {
            delete store[username];
            saveStore(store);
          }
        }
      }
    }
    return res.status(401).json({ success: false, reason: result.reason });
  }
  const username = req.params.username;
  if (!isValidUsername(username)) return res.status(400).json({ success: false, reason: 'invalid username' });
  if (!result.payload || result.payload.sub !== username) {
    return res.status(403).json({ success: false, reason: 'token subject mismatch' });
  }
  req.jwt = result.payload;
  next();
}

// --- Routes ---
app.get('/', (_, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// POST
app.post('/register', (req, res) => {
  if (req.headers['content-type'] !== 'application/json') return res.status(400).json({ success: false, reason: 'bad content-type' });
  const { username } = req.body || {};
  if (!isValidUsername(username)) return res.status(400).json({ success: false, reason: 'invalid username' });
  const users = getUsers();
  if (users[username]) {
    // Check if user TTL has expired
    if (users[username].createdAt + (TTL * 1000) < Date.now()) {
      delete users[username];
      saveUsers(users);
      // Also remove stored data
      const store = getStore();
      if (store[username]) {
        delete store[username];
        saveStore(store);
      }
    } else {
      return res.status(409).json({ success: false, reason: 'user already exists' });
    }
  }
  users[username] = { createdAt: Date.now() };
  saveUsers(users);
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: username,
    iat: now,
    nbf: now,
    exp: now + TTL,
    iss: "REST-service"
  };
  const token = signJwt(payload, JWT_SECRET);
  res.setHeader('Cache-Control', 'no-store');
  return res.json({ success: true, username, token });
});

// POST
app.post('/store/:username', requireJwt, (req, res) => {
  if (!req.headers['content-type'] || (!req.headers['content-type'].startsWith('application/json') && !req.headers['content-type'].startsWith('text/'))) {
    return res.status(400).json({ success: false, reason: 'bad content-type' });
  }
  const username = req.params.username;
  const entry = {
    time: Date.now(),
    body: req.body
  };

  const store = getStore();
  if (!Array.isArray(store[username])) store[username] = [];
  store[username].unshift(entry);
  saveStore(store);

  res.setHeader('Cache-Control', 'no-store');
  return res.status(201).json({ success: true, stored: true, count: store[username].length });
});

// GET
app.get('/store/:username', requireJwt, (req, res) => {
  const username = req.params.username;
  const store = getStore();
  const items = Array.isArray(store[username]) ? store[username] : [];
  res.setHeader('Cache-Control', 'no-store');
  return res.json({ success: true, username, items });
});

app.use((_, res) => res.status(404).json({ success: false, reason: 'not found' }));

// --- Start HTTPS server ---
const httpsOpts = {
  key: fs.readFileSync(KEY_PATH),
  cert: fs.readFileSync(CRT_PATH)
};

https.createServer(httpsOpts, app).listen(PORT, () => {
  console.log(`REST service running at https://localhost:${PORT}/`);
  console.log(`CORS allowed origins: ${ALLOWED_ORIGINS}`);
});
