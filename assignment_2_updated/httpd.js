var https = require('https');
var fs = require('fs');
var path = require('path');
const cookie = require('cookie');
const crypto = require('crypto');

const options = {
  key: fs.readFileSync('cert/server.key'),
  cert: fs.readFileSync('cert/server.crt'),
};

const lights = {
  kitchen: { stove: false, ceiling: true },
  livingroom: { sofa: false, ceiling: true },
  bedroom: { bed: false, ceiling: false }
};

const temps = {
  kitchen: 24,
  livingroom: 22,
  bedroom: 20
};

// UPDATED - verify password using pbkdf2 and timingSafeEqual
function verifyPassword(password, userEntry, cb) {
  if (!userEntry || !userEntry.salt || !userEntry.hash) {
    return cb(null, false);
  }
  const iterations = userEntry.iterations || 210000;
  const keylen = userEntry.keylen || 64;
  const digest = userEntry.digest || 'sha512';

  crypto.pbkdf2(password, userEntry.salt, iterations, keylen, digest, (err, derivedKey) => {
    if (err) return cb(err);
    const stored = Buffer.from(userEntry.hash, 'hex');
    if (derivedKey.length !== stored.length) return cb(null, false);
    const match = crypto.timingSafeEqual(derivedKey, stored);
    cb(null, match);
  });
}


const getEndpoints = {
  // Lights
  "/kitchen/lights/stove": () => lights.kitchen.stove,
  "/kitchen/lights/ceiling": () => lights.kitchen.ceiling,
  "/livingroom/lights/sofa": () => lights.livingroom.sofa,
  "/livingroom/lights/ceiling": () => lights.livingroom.ceiling,
  "/bedroom/lights/bed": () => lights.bedroom.bed,
  "/bedroom/lights/ceiling": () => lights.bedroom.ceiling,

  // Temperature
  "/kitchen/temperature": () => temps.kitchen,
  "/livingroom/temperature": () => temps.livingroom,
  "/bedroom/temperature": () => temps.bedroom
};


// Map for lights POST handlers
const postEndpoints = {
  "/kitchen/lights/stove": () => (lights.kitchen.stove = !lights.kitchen.stove),
  "/kitchen/lights/ceiling": () => (lights.kitchen.ceiling = !lights.kitchen.ceiling),
  "/livingroom/lights/sofa": () => (lights.livingroom.sofa = !lights.livingroom.sofa),
  "/livingroom/lights/ceiling": () => (lights.livingroom.ceiling = !lights.livingroom.ceiling),
  "/bedroom/lights/bed": () => (lights.bedroom.bed = !lights.bedroom.bed),
  "/bedroom/lights/ceiling": () => (lights.bedroom.ceiling = !lights.bedroom.ceiling)
};

console.log("Server starting");

// UPDATED - Session management
const ID_BYTES = 32; // 256 bits
const ABS_TIMEOUT_MS = 8 * 60 * 60 * 1000;  // 8h

const sessions = new Map();
const preSessions = new Set();

// Helpers
function sendJson(res, obj, code = 200) {
  // UPDATED - Every response is sent with security headers
  res.writeHead(code, withSecurityHeaders({ 'Content-Type': 'application/json; charset=utf-8' }));
  res.end(JSON.stringify(obj));
}

function readUsers() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, 'passwd'), 'utf8');
    return JSON.parse(raw || '{}');
  } catch (e) {
    console.log("   Error reading passwd file. Error: " + e.message);
    return {};
  }
}

function getSessionId(req) {
  const cookies = cookie.parse(req.headers.cookie || '');
  return cookies['athome-session'] || null;
}

function isProtected(pathname) {
  return (
    pathname === '/' ||
    pathname === '/logout' ||
    pathname.startsWith('/kitchen') ||
    pathname.startsWith('/livingroom') ||
    pathname.startsWith('/bedroom')
  );
}

const routes = [];

function handleRequest(path, method, handlerFn) {
  routes.push({ path, method, handlerFn });
}

// UPDATED - Generate a new random token instead of an incrementing a counter
function newToken(bytes = ID_BYTES) {
  return crypto.randomBytes(bytes).toString('hex');
}

// UPDATED - Security headers helper
function withSecurityHeaders(extra = {}) {
  return Object.assign({
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store'
  }, extra);
}



/** ---------- ROUTES ---------- */

handleRequest('/', 'GET', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'index.html');
  handleStaticResult(filePath, '/index.html', res);
});

// UPDATED - login flow uses a random pre-session id

handleRequest('/login', 'GET', (req, res) => {
  const preId = newToken(16);
  preSessions.add(preId);

  const cookieHeader = cookie.serialize('athome-pre', preId, {
    path: '/', httpOnly: true, sameSite: 'Lax', secure: true
  });

  const filePath = path.join(__dirname, 'public', 'login.html');
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(500, withSecurityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }));
      res.end('Server error: ' + err.message);
      return;
    }
    res.writeHead(200, withSecurityHeaders({
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': cookieHeader
    }));
    res.end(data);
  });
});


handleRequest('/login', 'POST', (req, res) => {
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks);
    const ctype = req.headers['content-type'] || '';
    const body = parseBody(ctype, raw);
    const { username, password } = body || {};

    const cookies = cookie.parse(req.headers.cookie || '');
    const preId = cookies['athome-pre'];

    const users = readUsers();
    const userEntry = users[username];

    // helper to render login with the same error HTML you already use
    function renderLoginError() {
      const filePath = path.join(__dirname, 'public', 'login.html');
      fs.readFile(filePath, 'utf8', (err, html) => {
        if (err) {
          res.writeHead(500, withSecurityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }));
          res.end('Server error: ' + err.message);
          return;
        }
        const withError = html.replace(
          /<\/body>\s*<\/html>\s*$/i,
          `<div style="margin:1rem;padding:.75rem;border:1px solid red;color:#b00;background:#fee">
             Invalid credentials or missing pre-session.
           </div></body></html>`
        );
        res.writeHead(200, withSecurityHeaders({ 'Content-Type': 'text/html; charset=utf-8' }));
        res.end(withError);
      });
    }

    // validate basics
    if (!username || !password || !preId || !preSessions.has(preId) || !userEntry) {
      return renderLoginError();
    }

    // Verify using pbkdf2
    verifyPassword(password, userEntry, (err, ok) => {
      if (err) {
        console.error('Error verifying password:', err);
        res.writeHead(500, withSecurityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }));
        res.end('Server error');
        return;
      }
      if (!ok) return renderLoginError();

      const sid = newToken(); // 256-bit session ID
      preSessions.delete(preId);

      sessions.set(sid, {
        username,
        created: Date.now(),
        ua: req.headers['user-agent'] || '',
        ip: req.socket.remoteAddress || ''
      });

      const cookiesOut = [
        // real session cookie, secure by default
        cookie.serialize('athome-session', sid, {
          path: '/',
          httpOnly: true,
          sameSite: 'Strict',
          secure: true
        }),
        // clear pre-auth cookie
        cookie.serialize('athome-pre', '', {
          path: '/',
          httpOnly: true,
          sameSite: 'Lax',
          secure: true,
          maxAge: 0
        })
      ];

      res.writeHead(302, withSecurityHeaders({
        'Location': '/',
        'Set-Cookie': cookiesOut
      }));
      res.end();
    });
  });

  req.on('error', e => {
    res.writeHead(400, withSecurityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }));
    res.end('Bad request: ' + e.message);
  });
});


// GET /logout -> invalidate current session id and send user to /login
handleRequest('/logout', 'GET', (req, res) => {
  const sid = getSessionId(req);
  if (sid) sessions.delete(sid);

  res.writeHead(302, withSecurityHeaders({
    'Location': '/login',
    'Set-Cookie': cookie.serialize('athome-session', '', {
      path: '/',
      httpOnly: true,
      sameSite: 'Strict',
      secure: true,
      maxAge: 0
    })
  }));
  res.end();
});



/** ---------- SERVER ---------- */

const server = https.createServer(options, (req, res) => {
  var urlObj = new URL('http://localhost:8000' + (req.url || '/'));
  // AUTH check + idle/absolute timeout enforcement
  if (isProtected(urlObj.pathname)) {
    const sid = getSessionId(req);
    const s = sid && sessions.get(sid);
    const now = Date.now();

    if (!sid || !s) {
      res.writeHead(302, withSecurityHeaders({ Location: '/login' }));
      res.end();
      return;
    }
    // Invalidate session id if session is expired
    if ((now - s.created) > ABS_TIMEOUT_MS) {
      sessions.delete(sid);
      res.writeHead(302, withSecurityHeaders({
        Location: '/login',
        'Set-Cookie': cookie.serialize('athome-session', '', {
          path: '/', httpOnly: true, sameSite: 'Strict', secure: true, maxAge: 0
        })
      }));
      res.end();
      return;
    }
  }

  // 1) Try to match a registered route (exact path + method)
  for (let ii = 0; ii < routes.length; ii++) {
    if (routes[ii].path === urlObj.pathname && routes[ii].method === req.method) {
      console.log("Matched route. Executing handler function.");
      return routes[ii].handlerFn(req, res);
    }
  }

  // 2) API table dispatch (GET/POST)
  const pathOnly = urlObj.pathname;
  if (req.method === 'GET' && getEndpoints[pathOnly]) {
    return sendJson(res, getEndpoints[pathOnly]());
  }
  if (req.method === 'POST' && postEndpoints[pathOnly]) {
    // note: our POSTs have no body; content-type may be empty
    return sendJson(res, postEndpoints[pathOnly]());
  }

  // 3) Fallbacks: For GET and POST
  if (req.method === 'POST') {
    if (req.headers['content-type'] === "application/x-www-form-urlencoded") {

      handleFormUrlEncodedPost(req, res, urlObj);
      return;
    }
  }
  if (req.method === 'GET') {
    const pathname = req.url;
    const filePath = path.join(__dirname, 'public', pathname);

    fs.stat(filePath, (err, stats) => {
      if (err) {
        console.log("ERR: Server Error - fs.stat");
        const code = err.code === 'ENOENT' ? 404 : 500;
        res.writeHead(code, { 'Content-Type': 'text/plain' });
        res.end((code === 404 ? 'Not found: ' : 'Server error: ') + (err.message || ''));
        return;
      }

      if (stats.isDirectory()) {    // If it's a directory
        handleDirectoryRequest(filePath, pathname, res);
      } else {                      // If it's a file, serve normally
        handleStaticResult(filePath, pathname, res);
      }
    });
    return;
  }
  console.log("   ERROR: Unknown request method: " + req.method);
});


// -----     POST handlers     -----

function handleFormUrlEncodedPost(req, res, urlObj) {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const raw = Buffer.concat(chunks);
    const ctype = req.headers['content-type'] || '';
    const parsed = parseBody(ctype, raw);

    console.log('--- request ---');
    console.log('method              :', req.method);
    console.log('url                 :', req.url);
    console.log('content-type        :', ctype || '(none)');
    console.log('query               :', Object.fromEntries(urlObj.searchParams.entries()));
    console.log('Request body(raw)   :', raw.toString('utf8'));
    console.log('Request body(parsed):', parsed);
    console.log('--------------');

    // Echo JSON
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: true, parsed }, null, 2));
  });
  req.on('error', (e) => {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad request: ' + e.message);
  });
  return;
}

function parseBody(contentType, raw) {
  const text = raw.toString('utf8');
  if (!contentType)
    return { raw: text };

  if (contentType.startsWith('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(text);
    return Object.fromEntries(params.entries());
  }
  if (contentType.startsWith('application/json')) {
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  }
  return { raw: text };
}


// -----     GET handlers     -----


function handleStaticResult(filePath, urlPath, res) {
  let ext = urlPath.split('.').pop();
  var mime = 'text/html';
  if (ext === 'css') mime = 'text/css';
  else if (ext === 'json') mime = 'application/json';
  else if (ext === 'js') mime = 'application/javascript';
  else if (ext === 'jpg' || ext === 'jpeg') mime = 'image/jpeg';
  else if (ext === 'ico') mime = 'image/x-icon';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(500, withSecurityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }));
      res.end('Server error: ' + err.message);
      return;
    }
    res.writeHead(200, withSecurityHeaders({ 'Content-Type': mime }));
    res.end(data);
  });
}

function handleDirectoryRequest(filePath, urlPath, res) {
  const indexFile = path.join(filePath, 'index.html');
  fs.access(indexFile, fs.constants.F_OK, (indexErr) => {
    if (!indexErr) {
      // Serve index.html
      fs.readFile(indexFile, (err, data) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data);
      });
    } else {
      // Generate a directory listing
      fs.readdir(filePath, (err, files) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Error reading directory');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        res.write('<h1>Directory listing</h1><ul>');
        files.forEach(f => {
          const link = path.join(urlPath, f);
          res.write(`<li><a href="${link}">${f}</a></li>`);
        });
        res.end('</ul>');
      });
    }
  });
}

server.listen(8000, () => console.log("Server running at https://localhost:8000/"));
