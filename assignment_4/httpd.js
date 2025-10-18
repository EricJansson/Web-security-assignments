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
    sessionsMongo = await db.collection('sessions');

    console.log("Connected to MongoDB!");
  } catch (err) {
    console.log("MongoDB error:");
    console.log(err.stack);
    await client.close();
  }
}

mongo().catch(console.dir);

// setTimeout(testMongo, 1000); // wait for mongo connection

async function testMongo() {
  console.log("Testing MongoDB functions...");
  try {

    const ok = await authenticate("daniel", "fisksoppa")
    if (ok) {
      console.log("MongoDB: authenticate(daniel) successful");
    } else {
      console.log("MongoDB: authenticate(daniel) failed");
    }

    // const added = await addUser("daniel", "fisksoppa");
  } catch (e) {
    console.log("testMongo error:");
    console.log(e);
  }
}

async function authenticate(username, password) {
  console.log("Authenticating user:", username);
  let user = await credentials.findOne({
    username: username,
    password: password
  });
  console.log("User:");
  console.log(user);
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
  return await sessionsMongo.findOne({ id: sessionid });
}

async function newSession() {
  let sessionid = crypto.randomBytes(64).toString('hex');
  await sessionsMongo.insertOne({ id: sessionid });
  return sessionid;
}

async function invalidateSession(sessionid) {
  return await sessionsMongo.findOneAndDelete({ id: sessionid });
  // await sessions_mongo.deleteOne({ id: sessionid });
}

async function addSqueak(username, recipient, squeak) {
  let options = { weekday: 'short', hour: 'numeric', minute: 'numeric' };
  let time = new Date().toLocaleDateString('sv-SE', options);
  await squeaks.insertOne({
    name: username,
    time: time,
    recipient: recipient,
    squeak: squeak
  });
}

async function getSqueaks(username) {
  return await squeaks.find({ recipient: username }).sort({ _id: -1 }).toArray(); // Sort to get latest first
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

const ID_BYTES = 32;        // session id length (bytes)

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

function setSqueakSessionCookie(res, sessionObj) {
  const cookieVal = JSON.stringify(sessionObj);
  const header = cookie.serialize('squeak-session', cookieVal, {
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    secure: true
  });
  res.setHeader('Set-Cookie', header);
}

// --- Session middleware ---
async function sessionMiddleware(req, res, next) {
  const raw = req.headers.cookie || '';
  const cookies = cookie.parse(raw);
  req.session = null;

  const val = cookies['squeak-session'];
  if (!val) return next();

  try {
    const parsed = JSON.parse(val); // expected: { sessionid, username }
    const sid = parsed && parsed.sessionid;
    if (!sid) return next();

    const found = await findSession(sid); // looks up { id: sid } in Mongo
    if (!found) return next();

    // Trust username from cookie per assignment model (only id is server-side)
    req.session = { sessionid: sid, username: parsed.username || null };

  } catch (e) {
    console.log('Error parsing session cookie. "app.use()" ERR: ', e);
    // ignore parse errors -> treat as no session
  }

  next();
}

app.use(sessionMiddleware);

// --- Routes ---

app.get('/', async (req, res) => {
  if (!req.session) {
    return res.render('login');
  }
  try {
    // calls your render(username, req, res)
    await render(req.session.username, req, res);
  } catch (e) {
    console.log('Render failed:', e);
    res.status(500).send('Server error');
  }
});

app.post('/signin', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.json({ success: false });
  }

  try {
    const ok = await authenticate(username, password);
    if (!ok) return res.json({ success: false });

    const sid = await newSession();
    setSqueakSessionCookie(res, { sessionid: sid, username });
    return res.json({ success: true });
  } catch (e) {
    console.log('Error during signin:', e);
    return res.json({ success: false });
  }
});

// POST /signup - expects application/json { username, password }
// (vulnerable to ReDoS when username is attacker-controlled)
app.post('/signup', async (req, res) => {
  const { username, password } = req.body || {};
  const users = await getAllUsers();
  const userExist = users.some(u => u.username === username);
  console.log('signup attempt', { username: username || null, password: password });
  if (!username || !password) {
    console.log('signup: missing username or password', { usernamePresent: !!username, passwordPresent: !!password });
    return res.status(400).json({ success: false, reason: 'missing' });
  }
  if (username.length < 4) {
    console.log('signup: username too short', { username, length: username.length });
    return res.json({ success: false, reason: 'username' });
  }
  if (userExist) {
    console.log("User already exists (MongoDB):", username);
    console.log('signup: userExists check failed', { username });
    return res.json({ success: false, reason: 'username' });
  }
  if (password.length < 8 || password.length > 128) {
    console.log('signup: password length invalid', { length: password ? password.length : 0 });
    return res.json({ success: false, reason: 'password' });
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
  /*
    // create and save user to server
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 210000, 64, 'sha512').toString('hex');
    users[username] = { salt, hash, iterations: 210000, keylen: 64, digest: 'sha512' };
  */
  await addUser(username, password); // MongoDB

  const sid = await newSession();
  setSqueakSessionCookie(res, { sessionid: sid, username });
  
  return res.json({ success: true });
});

// POST /signout - invalidates session
app.post('/signout', async (req, res) => {
  if (req.session) {
    await invalidateSession(req.session.sessionid); // MongoDB
  } else {
    return res.redirect(303, '/?err=Forbidden');
  }
  // clear cookie
  res.setHeader('Set-Cookie', cookie.serialize('squeak-session', '', { path: '/', expires: new Date(0) }));
  return res.redirect(302, '/');
});

// POST /squeak - expects application/x-www-form-urlencoded from the form with fields 'text'
// requires a valid session; if missing, the request is dropped silently (per assignment)
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

  addSqueak(username, recipient, squeak); // MongoDB

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

// on shutdown (Ctrl+C, Docker stop, etc.)
process.on('SIGINT', async () => {
  try {
    console.log("Shutting down server...");
    console.log("Closing MongoDB");
    await client.close();
  } finally {
    process.exit(0);
  }
});