var https = require('https');
var fs = require('fs');
var path = require('path');
const cookie = require('cookie');

const options = {
  key:  fs.readFileSync('cert/server.key'),
  cert: fs.readFileSync('cert/server.crt'),
};

const lights = {
  kitchen: { stove: false, ceiling: false },
  livingroom: { sofa: false, ceiling: false },
  bedroom: { bed: false, ceiling: false }
};

const temps = {
  kitchen: 24,
  livingroom: 22,
  bedroom: 20
};

const getEndpoints = {
  // Lights
  "/kitchen/lights/stove":      () => lights.kitchen.stove,
  "/kitchen/lights/ceiling":    () => lights.kitchen.ceiling,
  "/livingroom/lights/sofa":    () => lights.livingroom.sofa,
  "/livingroom/lights/ceiling": () => lights.livingroom.ceiling,
  "/bedroom/lights/bed":        () => lights.bedroom.bed,
  "/bedroom/lights/ceiling":    () => lights.bedroom.ceiling,

  // Temperature
  "/kitchen/temperature":       () => temps.kitchen,
  "/livingroom/temperature":    () => temps.livingroom,
  "/bedroom/temperature":       () => temps.bedroom
};


// Map for lights POST handlers
const postEndpoints = {
  "/kitchen/lights/stove":      () => ( lights.kitchen.stove      = !lights.kitchen.stove      ),
  "/kitchen/lights/ceiling":    () => ( lights.kitchen.ceiling    = !lights.kitchen.ceiling    ),
  "/livingroom/lights/sofa":    () => ( lights.livingroom.sofa    = !lights.livingroom.sofa    ),
  "/livingroom/lights/ceiling": () => ( lights.livingroom.ceiling = !lights.livingroom.ceiling ),
  "/bedroom/lights/bed":        () => ( lights.bedroom.bed        = !lights.bedroom.bed        ),
  "/bedroom/lights/ceiling":    () => ( lights.bedroom.ceiling    = !lights.bedroom.ceiling    )
};

console.log("Server starting");

let nextSessionId = 1;
const sessions = new Map();

// Helper
function sendJson(res, obj, code = 200) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
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

/** ---------- ROUTES ---------- */

handleRequest('/', 'GET', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'index.html');
  handleStaticResult(filePath, '/index.html', res);
});


handleRequest('/login', 'GET', (req, res) => {
  const cookies = cookie.parse(req.headers.cookie || '');
  let preId = cookies['athome-session'];
  console.log("   Auth check, session id (sID): ", preId);

  if (!preId || sessions.has(preId)) {
    preId = String(nextSessionId);
  }

  const cookieHeader = cookie.serialize('athome-session', preId, {path: '/'});

  const filePath = path.join(__dirname, 'public', 'login.html');
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Server error: ' + err.message);
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': cookieHeader
    });
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
    const { username, password } = body;

    const cookies = cookie.parse(req.headers.cookie || '');
    const preId = cookies['athome-session'];

    const users = readUsers();

    if (username && password && users[username] === password && preId) {
      sessions.set(preId, username);
      nextSessionId++;

      const cookie = `athome-session=${preId}; Path=/;`;

      res.writeHead(302, {
        'Location': '/',
        'Set-Cookie': cookie
      });
      res.end();
      return;
    }

    // On failure - Go to login page with an error message
    const filePath = path.join(__dirname, 'public', 'login.html');
    fs.readFile(filePath, 'utf8', (err, html) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Server error: ' + err.message);
        return;
      }
      const withError = html.replace(
        /<\/body>\s*<\/html>\s*$/i,
        `<div style="margin:1rem;padding:.75rem;border:1px solid red;color:#b00;background:#fee">
           Invalid credentials or missing pre-session.
         </div></body></html>`
      );
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(withError);
    });
  });
  req.on('error', e => {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bad request: ' + e.message);
  });
});

// GET /logout -> invalidate current session id and send user to /login
handleRequest('/logout', 'GET', (req, res) => {
  const sid = getSessionId(req);
  if (sid) sessions.delete(sid);

  res.writeHead(302, {
    'Location': '/login',
    'Set-Cookie': 'athome-session=; Path=/;' // clear cookie
  });
  res.end();
});



/** ---------- SERVER ---------- */

const server = https.createServer(options, (req, res) => {
  var urlObj = new URL('http://localhost:8000' + (req.url || '/'));
  console.log("req.url: " + req.url + " -> pathname: " + urlObj.pathname);
  // AUTH-check
  if (isProtected(urlObj.pathname)) {
    const sid = getSessionId(req);
    console.log("   Auth check, session id (sID): ", sid);
    if (!sid || !sessions.has(sid)) {
      // Not authorized -> forward to /login
      res.writeHead(302, { Location: '/login' });
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
  if (req.method === 'GET'  && getEndpoints[pathOnly])  {
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
  if (ext === 'css')
    mime = 'text/css';
  else if (ext === 'json')
    mime = 'application/json';
  else if (ext === 'js')
    mime = 'application/javascript';
  else if (ext === 'jpg' || ext === 'jpeg')
    mime = 'image/jpeg';
  else if (ext === 'ico')
    mime = 'image/x-icon';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Server error: ' + err.message);
      return;
    }
    res.writeHead(200, { 'Content-Type': mime });
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
