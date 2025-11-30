const https = require('https');
const fs = require('fs');
const path = require('path');
const cookie = require('cookie');
const crypto = require('crypto');
const express = require('express');
const mustacheExpress = require('mustache-express');
const { MongoClient } = require("mongodb");

// --- MongoDB globals ---
const url = "mongodb+srv://erja:IBkSDB46nE9ncS58@websec.4oqw5jp.mongodb.net/?retryWrites=true&w=majority&appName=websec";
const SECRET = 'short_and_easily_crackable_secret_key_that_should_be_longer_so_use_env_vars_instead_please_thanks_bye_now_hugs_and_kisses_/_Eric';

const client = new MongoClient(url);

let squeaks;
let credentials;
let sessionsMongo;

async function mongo() {
  try {
    let cluster = await client.connect();

    let db = await cluster.db('Squeak!');
    /* load collections into globals - maybe not the best, but suffices */
    squeaks = await db.collection('squeaks');
    credentials = await db.collection('credentials');
    sessionsMongo = await db.collection('sessions_with_username');

    console.log("Connected to MongoDB!");
  } catch (err) {
    console.log("MongoDB error:");
    console.log(err.stack);
    await client.close();
  }
}

mongo().catch(console.dir);


// UPDATED CODE    \/

function signStr(s) {
  return crypto.createHmac('sha256', SECRET).update(s, 'utf8').digest('hex');
}

function setSignedSessionCookie(res, sessionid, username) {
  const payload = `${sessionid}|${username}`;
  const b64 = Buffer.from(payload, 'utf8').toString('base64');
  const sig = signStr(b64);
  const cookieVal = `${b64}.${sig}`;
  const header = cookie.serialize('squeak-session', cookieVal, {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    secure: true
  });
  res.setHeader('Set-Cookie', header);
}

function verifySignedCookie(cookieVal) {
  if (typeof cookieVal !== 'string') return null;
  const parts = cookieVal.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  if (!/^[0-9a-f]{64}$/.test(sig)) return null;

  const expectedHex = signStr(b64);
  const a = Buffer.from(expectedHex, 'hex');
  const b = Buffer.from(sig, 'hex');
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try {
    payload = Buffer.from(b64, 'base64').toString('utf8');
  } catch (e) { return null; }
  const [sessionid, username] = payload.split('|');
  if (typeof sessionid !== 'string' || typeof username !== 'string') return null;

  return { sessionid, username };
}
// UPDATED CODE    /\



async function authenticate(username, password) {
  // UPDATED CODE  \/ 
  // Lightweight input validation    
  if (!username || !password) return false;
  if (typeof username !== 'string' || typeof password !== 'string') return false;
  // UPDATED CODE  /\

  let user = await credentials.findOne({
    username: username,
    password: password
  });
  return user !== null;
}

async function addUser(username, password) {
  const users = await getAllUsers();
  const userExist = users.some(u => u.username === username);
  if (userExist) {
    console.log("User already exists:", username);
    return false;
  }
  await credentials.insertOne({ username: username, password: password });
  console.log("User added:", username);
  return true;
}

async function getAllUsers() {
  const allUsernames = await credentials.find({}, { projection: { username: 1, _id: 0 } }).toArray();
  return allUsernames;
}

async function findSession(sessionid) {
  // UPDATED CODE   \/
  return await sessionsMongo.findOne(
    { id: sessionid },
    { projection: { _id: 0, id: 1, username: 1 } }
  );
  // UPDATED CODE   /\
}

async function newSession(username) {
  let sessionid = crypto.randomBytes(64).toString('hex');
  await sessionsMongo.insertOne({ id: sessionid, username: username });
  return sessionid;
}

async function invalidateSession(sessionid) {
  return await sessionsMongo.findOneAndDelete({ id: sessionid });
}

async function addSqueak(username, recipient, squeak) {
  // UPDATED CODE  \/
  if (typeof username !== 'string' || typeof recipient !== 'string' || typeof squeak !== 'string') {
    console.log("Type error in addSqueak - Username: ", typeof username, ", recipient: ", typeof recipient, ", squeak: ", typeof squeak);
    console.log('Invariant: addSqueak() expects strings');
    return false;
  }
  // UPDATED CODE  /\
  let options = { weekday: 'short', hour: 'numeric', minute: 'numeric' };
  let time = new Date().toLocaleDateString('sv-SE', options);
  await squeaks.insertOne({
    name: username,
    time: time,
    recipient: recipient,
    squeak: squeak
  });
  return true;
}

async function getSqueaks(username) {
  if (!username || typeof username !== "string") {
    console.log("Error getting squeaks for user:", username);
    console.log("username type:", typeof username);
    return null;
  }
  return await squeaks.find({ 
    recipient: username 
  }).sort({ _id: -1 }).toArray(); // Sort to get latest first
}

async function render(username, req, res) {
  let users = await getAllUsers();
  let squeaks = await getSqueaks("all");
  let squeals = await getSqueaks(username);

  res.render('index', {
    username: username,
    users: users,
    squeaks: squeaks,
    squeals: squeals
  });
}


// --- Certs ---
const CERT_DIR = path.join(__dirname, 'cert');
const CRT_PATH = path.join(CERT_DIR, 'server.crt');
const KEY_PATH = path.join(CERT_DIR, 'server.key');

// --- Config / constants ---
const STATIC_DIR = path.join(__dirname, 'public');

console.log("Server starting...");

const app = express();
const PORT = 8000;

app.engine('mustache', mustacheExpress());
app.set('view engine', 'mustache');
app.set('views', path.join(__dirname, 'templates'));

// --- Express middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(STATIC_DIR, { index: false }));


// --- Session middleware ---
async function sessionMiddleware(req, res, next) {
  const raw = req.headers.cookie || '';
  const cookies = cookie.parse(raw);
  req.session = null;

  const val = cookies['squeak-session'];
  if (!val) {
    console.log("No session cookie found");
    return next();
  }

  // UPDATED CODE    \/
  const verified = verifySignedCookie(val);
  if (!verified) {
    console.log("Not a valid signed cookie");
    return next();
  }

  const found = await findSession(verified.sessionid);
  if (!found) {
    console.log("Session not found in MongoDB");
    return next();
  }
  req.session = { sessionid: found.id, username: found.username };
  // UPDATED CODE    /\
  next();
}

app.use(sessionMiddleware);

// --- Routes ---

app.get('/', async (req, res) => {
  if (!req.session) {
    return res.render('login');
  }
  try {
    await render(req.session.username, req, res);
  } catch (e) {
    console.log('Render failed:', e);
    res.status(500).send('Server error');
  }
});

app.post('/signin', async (req, res) => {
  const { username, password } = req.body || {};
  // UPDATED CODE  \/
  if (!username || !password) {
    console.log("Error - /signin:")
    console.log('Username||password missing. Username: ', username, ', password: ', password);
    return res.json({ success: false });
  }
  if (typeof username !== 'string' || typeof password !== 'string') {
    console.log("Error - /signin:")
    console.log("Invalid username/password type. Username type: ", (typeof username), ", password type: ", (typeof password));
    return res.json({ success: false });
  }
  // UPDATED CODE  /\

  try {
    const ok = await authenticate(username, password);
    console.log("/signin:")
    console.log('Username status: ', username, ', password status: ', password);
    if (!ok) return res.json({ success: false });

    const sid = await newSession(username);
    setSignedSessionCookie(res, sid, username); // UPDATED CODE - Uses new function
    console.log("/signin: authentication successful");
    return res.json({ success: true });
  } catch (e) {
    console.log('Error during signin:', e);
    return res.json({ success: false });
  }
});

app.post('/signup', async (req, res) => {
  // UPDATED CODE  \/
  const { username, password } = req.body || {};
  if (!username || !password) {
    console.log("Error - /signup:")
    console.log('Username||password missing. Username: ', username, ', password: ', password);
    return res.status(400).json({ success: false, reason: 'missing' });
  }
  if (typeof username !== 'string' || typeof password !== 'string') {
    console.log("Error - /signup:")
    console.log("Invalid username/password type. Username type: ", (typeof username), ", password type: ", (typeof password));
    return res.status(400).json({ success: false, reason: 'type mismatch' });
  }
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(username)) {
    console.log("Error - /signup:")
    console.log('Invalid username format/length', { username, length: username.length });
    return res.status(400).json({ success: false, reason: 'username' });
  }
  // UPDATED CODE  /\
  if (password.length < 8 || password.length > 128) {
    console.log("Error - /signup:")
    console.log('Invalid password length', { length: password ? password.length : 0 });
    return res.status(400).json({ success: false, reason: 'password' });
  }

  const users = await getAllUsers();
  const userExist = users.some(u => u.username === username);
  console.log('signup attempt', { username: username || null, password: password });
  if (userExist) {
    console.log("User already exists (MongoDB):", username);
    console.log('signup: userExists check failed', { username });
    return res.json({ success: false, reason: 'username' });
  }

  const USERNAME_REGEX = /^[A-Za-z0-9_-]{4,64}$/;
  if (!USERNAME_REGEX.test(username)) {
    console.log('signup: username regex validation failed', { username });
    return res.json({ success: false, reason: 'username' });
  }
  if (password.toLowerCase().includes(username.toLowerCase())) {
    console.log('signup: password contains username', { username });
    return res.json({ success: false, reason: 'password' });
  }
  
  await addUser(username, password);

  const sid = await newSession(username);
  setSignedSessionCookie(res, sid, username); // UPDATED CODE - Uses new function

  return res.json({ success: true });
});

// POST /signout - invalidates session
app.post('/signout', async (req, res) => {
  if (req.session) {
    await invalidateSession(req.session.sessionid);
  } else {
    return res.redirect(303, '/?err=Forbidden');
  }
  res.setHeader('Set-Cookie', cookie.serialize('squeak-session', '', { path: '/', expires: new Date(0) }));
  return res.redirect(302, '/');
});

app.post('/squeak', (req, res) => {
  if (!req.session || !req.body)
    return res.redirect(303, '/?err=Forbidden');
  if (!req.body.squeak || req.body.squeak.length === 0)
    return res.redirect(303, '/?err=Bad Request: No message');
  if (!req.body.recipient || req.body.recipient.length === 0)
    return res.redirect(303, '/?err=Bad Request: No recipient');

  const squeak = req.body.squeak;
  const username = req.session.username;
  const recipient = req.body.recipient;

  // UPDATED CODE  \/
  if (!username || !recipient || !squeak) {
    console.log("Error /squeak - Data missing")
    return res.status(400).json({ success:false });
  }
  if (typeof recipient !== 'string' || typeof squeak !== 'string' || typeof username !== 'string') {
    console.log("Error /squeak - Type error")
    return res.status(400).json({ success:false });
  }
  if (squeak.length === 0 || squeak.length > 2000) {
    console.log("Error /squeak - ")
    return res.status(400).json({ success:false });
  }

  success = addSqueak(username, recipient, squeak);
  if (!success)
    return res.redirect(303, '/?err=Internal Server Error: Could not add squeak');
  // UPDATED CODE  /\
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

process.on('SIGINT', async () => {
  try {
    console.log("Shutting down server...");
    console.log("Closing MongoDB");
    await client.close();
  } finally {
    process.exit(0);
  }
});