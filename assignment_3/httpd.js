const https = require('https');
const fs = require('fs');
const path = require('path');
const cookie = require('cookie');
const crypto = require('crypto');
const express = require('express');

console.log("Server starting");

const app = express();
const PORT = 8000;

// --- Certs ---
const CERT_DIR = path.join(__dirname, 'cert');
const CRT_PATH = path.join(CERT_DIR, 'server.crt');
const KEY_PATH = path.join(CERT_DIR, 'server.key');

// --- Config / constants ---
const PASSWD_FILE = path.join(__dirname, 'passwd');
const SQUEAKS_FILE = path.join(__dirname, 'squeaks');
const STATIC_DIR = path.join(__dirname, 'public');

const ID_BYTES = 32;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// --- In-memory session store ---
const sessions = new Map();

// --- Express middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(STATIC_DIR, { index: false }));

// --- Utility helpers ---
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(PASSWD_FILE, 'utf8') || '{}');
  } catch (e) {
    return {};
  }
}

function saveUsers(obj) {
  fs.writeFileSync(PASSWD_FILE, JSON.stringify(obj, null, 2), { mode: 0o600 });
}

function loadSqueaks() {
  try {
    const raw = fs.readFileSync(SQUEAKS_FILE, 'utf8') || '[]';
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

function saveSqueaks(arr) {
  fs.writeFileSync(SQUEAKS_FILE, JSON.stringify(arr, null, 2), { mode: 0o600 });
}

function newToken(bytes = ID_BYTES) {
  return crypto.randomBytes(bytes).toString('hex');
}

function setSqueakSessionCookie(res, sessionObj) {
  const cookieVal = JSON.stringify(sessionObj);
  const header = cookie.serialize('squeak-session', cookieVal, {
    path: '/',
    httpOnly: false,
    secure: true
  });
  res.setHeader('Set-Cookie', header);
}

// --- Session middleware ---
app.use((req, res, next) => {
  const raw = req.headers.cookie || '';
  const cookies = cookie.parse(raw);
  req.session = null;
  if (cookies['squeak-session']) {
    try {
      const session = JSON.parse(cookies['squeak-session']);
      const serverSession = sessions.get(session.sessionid);
      if (serverSession && serverSession.username === session.username) {
        // check expiration
        if (Date.now() - serverSession.createdAt <= SESSION_TTL_MS) {
          req.session = { sessionid: session.sessionid, username: session.username };
        } else {
          // expired
          sessions.delete(session.sessionid);
        }
      }
    } catch (e) {
      console.log('Error parsing session cookie. "app.use()" ERR: ', e);
      // ignore parse errors -> treat as no session
    }
  }
  next();
});


// --- Routes ---

app.get('/', (req, res) => {
  if (!req.session) {
    return res.sendFile(path.join(STATIC_DIR, 'login.html'));
  }

  const squeaks = loadSqueaks();
  let html = fs.readFileSync(path.join(STATIC_DIR, 'index.html'), 'utf8');
  const rendered = squeaks.map(s => {
    return `
    <div class="card mb-2">
      <div class="card-header">
      ${s.username} &nbsp; 
        <span class="float-right">${
          new Date(s.time).toLocaleDateString('en-GB',{weekday:'short', timeZone:'Europe/Stockholm'})
        } ${
          new Date(s.time).toLocaleTimeString('en-GB',{hour:'2-digit', minute:'2-digit', hour12:false, timeZone:'Europe/Stockholm'})
        }</span>
      </div>
      <div class="card-body">
          <p class="card-text">${s.squeak}</p>
      </div>
    </div>`;
  }).join('\n');

  html = html.replace('<!-- SQUEAKS -->', rendered)
    .replace('<!-- USERNAME -->', req.session.username);

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(html);
});


app.post('/signin', (req, res) => {
  const { username, password } = req.body || {};
  const users = loadUsers();
  const entry = users[username];
  if (!entry) return res.json({ success: false });

  try {
    const derived = crypto.pbkdf2Sync(password, entry.salt, entry.iterations, entry.keylen, entry.digest).toString('hex');
    if (derived === entry.hash) {
      const sid = newToken();
      sessions.set(sid, { username, createdAt: Date.now() });
      setSqueakSessionCookie(res, { sessionid: sid, username });
      return res.json({ success: true });
    } else {
      return res.json({ success: false });
    }
  } catch (e) {
    console.log('Error during signin:', e);
    return res.json({ success: false });
  }
});

// POST /signup - expects application/json { username, password }
app.post('/signup', (req, res) => {
  const { username, password } = req.body || {};
  const users = loadUsers();

  if (!username || !password) return res.status(400).json({ success: false, reason: 'missing' });
  if (username.length < 4) return res.json({ success: false, reason: 'username' });
  if (users[username]) return res.json({ success: false, reason: 'username' });
  if (password.length < 8) return res.json({ success: false, reason: 'password' });
  
  let validPassword = password !== undefined && password.length >= 8;
  if (validPassword) {
    let nameregex = new RegExp(username);
    validPassword &= !nameregex.test(password);
  }
  if (!validPassword) return res.json({ success: false, reason: 'password' });

  // create and save user to server
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 64, 'sha512').toString('hex');
  users[username] = { salt, hash, iterations: 210000, keylen: 64, digest: 'sha512' };
  saveUsers(users);

  // create session and set cookie
  const sid = newToken();
  sessions.set(sid, { username, createdAt: Date.now() });
  setSqueakSessionCookie(res, { sessionid: sid, username });
  return res.json({ success: true });
});

// POST /signout - invalidates session
app.post('/signout', (req, res) => {
  if (req.session) {
    sessions.delete(req.session.sessionid);
  }
  // clear cookie
  res.setHeader('Set-Cookie', cookie.serialize('squeak-session', '', { path: '/', expires: new Date(0) }));
  return res.json({ success: true });
});

// POST /squeak - expects application/x-www-form-urlencoded from the form with fields 'text'
app.post('/squeak', (req, res) => {
  if (!req.session || !req.body)
    return res.status(403).send('Forbidden');
  if (!req.body.squeak || req.body.squeak.length === 0)
    return res.status(400).send('Bad Request');

  const squeak = req.body.squeak;
  const username = req.session.username;
  const squeaks = loadSqueaks();
  squeaks.unshift({ username, time: Date.now(), squeak });
  saveSqueaks(squeaks);
  return res.redirect(302, '/');
});

app.use((_, res) => res.status(404).send('Not found'));

// --- Start HTTPS server ---
const httpsOpts = {
  key: fs.readFileSync(KEY_PATH),
  cert: fs.readFileSync(CRT_PATH)
};
https.createServer(httpsOpts, app).listen(PORT, () => {
  console.log(`✅ Squeak! HTTPS server running at https://localhost:${PORT}/`);
});
