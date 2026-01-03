Leak Service (HTTPS + JWT + CORS)

Folder layout
- server.js
- public/ (static UI)
- cert/ (put server.key + server.crt here)
- data/ (users.json + store.json)

Quick start
1) npm install
2) Create certs (example):
   mkdir cert
   openssl req -x509 -newkey rsa:2048 -nodes -keyout cert/server.key -out cert/server.crt -days 365 -subj "/CN=localhost"
3) Run:
   JWT_SECRET="change-me" ALLOWED_ORIGINS="https://localhost:8000" node server.js
4) Visit:
   https://localhost:9000/

Notes
- Bearer token required for /store/:username
- CORS is whitelist-based; adjust ALLOWED_ORIGINS to match your vulnerable app origin.
