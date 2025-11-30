const https = require('https');
const fs = require('fs');
const path = require('path');
const cookie = require('cookie');
const crypto = require('crypto');
const express = require('express');
const mustacheExpress = require('mustache-express');

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

app.engine('mustache', mustacheExpress());
app.set('view engine', 'mustache');
app.set('views', path.join(__dirname, 'templates'));

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
    httpOnly: true, // UPDATED
    sameSite: 'Lax', // UPDATED
    secure: true
  });
  res.setHeader('Set-Cookie', header);
}

// --- CSRF protection middleware ---
function verifyCookieCsrf(req, csrfFromBody) {
  const cookies = cookie.parse(req.headers.cookie || '');
  const cookieToken = cookies['cookieCsrf'];

  if (!csrfFromBody || !cookieToken) return false;

  const a = Buffer.from(csrfFromBody, 'utf8');
  const b = Buffer.from(cookieToken, 'utf8');
  if (a.length !== b.length) return false;

  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}


function requireCSRF(req, res, next) {
  // must be authenticated first
  if (!req.session || !req.session.sessionid) return res.status(401).end();
  const sess = sessions.get(req.session.sessionid);
  if (!sess) return res.status(401).end();
  const sent = (req.body && req.body.csrf);
  if (!sent || !sess.csrf) return res.status(403).send('CSRF token missing');

  const a = Buffer.from(sent, 'utf8');
  const b = Buffer.from(sess.csrf, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).send('Invalid CSRF token');
  }
  next();
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
    }
  }
  next();
});


// --- Routes ---

app.get('/', (req, res) => {
  if (!req.session) {
    // UPDATED SECTION
    const cookieCsrf = newToken();
    const header = cookie.serialize('cookieCsrf', cookieCsrf, {
      path: '/',
      httpOnly: false,   // must be readable by JS
      sameSite: 'Lax',
      secure: true
    });
    res.setHeader('Set-Cookie', header);
    return res.render('login', { cookieCsrf: cookieCsrf });
  }
  const squeaks = loadSqueaks().map(s => ({
    username: s.username,
    timeFmt: new Date(s.time).toLocaleDateString('en-GB', { weekday: 'short', timeZone: 'Europe/Stockholm' })
      + ' ' +
      new Date(s.time).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Europe/Stockholm' }),
    squeak: s.squeak
  }));

  const cur_session = sessions.get(req.session.sessionid);    // CSRF Token related
  return res.render('index', {
    username: req.session.username,
    squeaks,
    csrf: cur_session?.csrf    // CSRF Token related
  });
  // UPDATED SECTION END - Ends with rendering the index file with the variable values
});


app.post('/signin', (req, res) => {
  const { username, password, cookieCsrf } = req.body || {};

  if (!verifyCookieCsrf(req, cookieCsrf)) {
    console.log(cookieCsrf)
    console.log('CSRF verification failed during signin');
    return res.json({ success: false });
  }

  const users = loadUsers();
  const entry = users[username];
  if (!entry) return res.json({ success: false });

  try {
    const derived = crypto.pbkdf2Sync(password, entry.salt, entry.iterations, entry.keylen, entry.digest).toString('hex');
    if (derived === entry.hash) {
      // CSRF Token related
      const sid = newToken();
      const csrfToken = newToken();
      sessions.set(sid, {
        username,
        csrf: csrfToken,
        createdAt: Date.now()
      });
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
  const { username, password, cookieCsrf } = req.body || {};

  if (!verifyCookieCsrf(req, cookieCsrf)) {
    return res.json({ success: false, reason: 'cookie-csrf' });
  }

  const users = loadUsers();

  if (!username || !password)
    return res.status(400).json({ success: false, reason: 'missing' });
  if (username.length < 4)
    return res.json({ success: false, reason: 'username' });
  if (users[username])
    return res.json({ success: false, reason: 'username' });
  if (password.length < 8 || password.length > 128)
    return res.json({ success: false, reason: 'password' });

  const USERNAME_REGEX = /^[A-Za-z0-9_-]{4,64}$/;
  if (!USERNAME_REGEX.test(username))
    return res.json({ success: false, reason: 'username' });
  if (password.toLowerCase().includes(username.toLowerCase()))
    return res.json({ success: false, reason: 'password' });

  // create and save user to server
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 64, 'sha512').toString('hex');
  users[username] = { salt, hash, iterations: 210000, keylen: 64, digest: 'sha512' };
  saveUsers(users);

  // create session and set cookie
  const sid = newToken();
  const csrfToken = newToken();
  sessions.set(sid, {
    username,
    csrf: csrfToken,
    createdAt: Date.now()
  });
  setSqueakSessionCookie(res, { sessionid: sid, username });
  return res.json({ success: true });
});

// POST /signout - invalidates session
app.post('/signout', requireCSRF, (req, res) => { // CSRF Token related
  if (req.session) {
    sessions.delete(req.session.sessionid);
  }
  // clear cookie
  res.setHeader('Set-Cookie', cookie.serialize('squeak-session', '', { path: '/', expires: new Date(0) }));
  return res.redirect(302, '/');
});

// POST /squeak - expects application/x-www-form-urlencoded from the form with fields 'text'
app.post('/squeak', requireCSRF, (req, res) => {
  if (!req.session || !req.body)
    return res.redirect(303, '/?err=Forbidden');
  if (!req.body.squeak || req.body.squeak.length === 0)
    return res.redirect(303, '/?err=Bad Request');

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
