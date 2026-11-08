// Static server for a staged site folder: node serve.js <dir> <port>
// Explicit content types (not the OS registry) so a Windows machine and a Linux runner serve the same.
const http = require('http');
const fs = require('fs');
const path = require('path');

const root = path.resolve(process.argv[2] || '');
const port = Number(process.argv[3] || 4173);
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.xml': 'application/xml; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
  '.png': 'image/png', '.ico': 'image/x-icon',
};

if (!root || !fs.existsSync(root)) {
  console.error('usage: node serve.js <staged site dir> [port]');
  process.exit(2);
}

http.createServer((req, res) => {
  let rel;
  try { rel = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { rel = null; }
  let file = rel === null ? null : path.join(root, rel);
  // Stay inside the staged folder.
  if (!file || (file !== root && !file.startsWith(root + path.sep))) {
    res.writeHead(400); return res.end('bad path');
  }
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  fs.readFile(file, (err, body) => {
    if (err) {
      // Like GitHub Pages: a missing address gets the site's 404.html, if there is one, with status 404.
      return fs.readFile(path.join(root, '404.html'), (err404, page) => {
        if (err404) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('not found'); }
        res.writeHead(404, { 'content-type': TYPES['.html'] });
        res.end(page);
      });
    }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
}).listen(port, '127.0.0.1', () => console.log(`serving ${root} on http://127.0.0.1:${port}`));
