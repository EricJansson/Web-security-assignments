var http = require('http');
var fs = require('fs');
var path = require('path');

console.log("Server starting");

const routes = [];

function handleRequest(path, method, handlerFn) {
  routes.push({ path, method, handlerFn });
}

handleRequest('/information', 'GET', (req, res) => {
  // Handle GET request for /mypage
  fs.readFile(path.join(__dirname, 'templates/information.template'), 'utf8', (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end('Server error: ' + err.message);
      return;
    }

    const urlObj = new URL(req.url, 'http://localhost:8000');

    let queries = ""
    urlObj.searchParams.forEach((value, name) => {
      queries += `<li>${name}=${value}</li>\n`
    })

    let html = data
      .replace('{{method}}', req.method)
      .replace('{{path}}', urlObj.pathname)
      .replace('{{query}}', urlObj.search || '')
      .replace('{{queries}}', queries);

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });
})


const server = http.createServer((req, res) => {
  var urlObj = new URL(req.url, 'http://localhost:8000');

  for (let ii = 0; ii < routes.length; ii++) {
    if (routes[ii].path === urlObj.pathname && routes[ii].method === req.method) {
      console.log("Matched route. Executing handler function.");
      return routes[ii].handlerFn(req, res);
    }
  }
  
  if (req.method === 'POST') {
    if (req.headers['content-type'] === "application/x-www-form-urlencoded") {

      handleFormUrlEncodedPost(req, res, urlObj);
      return; // We handled the request
    }
  }
  if (req.method === 'GET') {
    let pathname = urlObj.pathname;
    if (urlObj.pathname === '/')
      pathname = '/index.html';
    
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
    return; // We handled the request
  }
  console.log("ERROR: Unknown request method: " + req.method);
});


// -----     POST handlers     -----

function handleFormUrlEncodedPost(req, res, urlObj) {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const raw = Buffer.concat(chunks);          // full body
    const ctype = req.headers['content-type'] || '';
    const parsed = parseBody(ctype, raw);       // now parse

    console.log('--- request ---');
    console.log('method              :', req.method);
    console.log('url                 :', req.url);
    console.log('content-type        :', ctype || '(none)');
    console.log('query               :', Object.fromEntries(urlObj.searchParams.entries()));
    console.log('Request body(raw)   :', raw.toString('utf8'));
    console.log('Request body(parsed):', parsed);
    console.log('--------------');

    // Respond (choose one):
    // A) Echo JSON
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: true, parsed }, null, 2));
  });
  // Handle errors on the request stream
  req.on('error', (e) => {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad request: ' + e.message);
  });
  return; // handled in 'end' callback
}

function parseBody(contentType, raw) {
  const text = raw.toString('utf8');
  if (!contentType) return { raw: text };

  if (contentType.startsWith('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(text);
    return Object.fromEntries(params.entries());
  }
  if (contentType.startsWith('application/json')) {
    try { return JSON.parse(text); } catch { return { raw: text }; }
  }
  // default: plain text or anything else
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
      res.writeHead(500, { 'Content-Type': 'text/plain' });
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

server.listen(8000, () => console.log("Server running at http://localhost:8000/"));
