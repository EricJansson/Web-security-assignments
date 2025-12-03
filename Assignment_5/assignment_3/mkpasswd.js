const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function showCommandAndExit() {
  console.log('Command: node mkpasswd.js <username> <password>');
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length < 2) showCommandAndExit();

const [username, password] = args;

if (!username || !password) showCommandAndExit();

const iterations = 210000;
const keylen = 64;
const digest = 'sha512';

const passwdPath = path.join(__dirname, 'passwd');

// generate salt and derived key
const salt = crypto.randomBytes(16).toString('hex');
const derived = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');

let users = {};

users[username] = {
  salt,
  hash: derived,
  iterations,
  keylen,
  digest
};

try {
  fs.writeFileSync(passwdPath, JSON.stringify(users, null, 2), { mode: 0o600 });
  console.log(`Updated '${username}' entry in passwd file.`);
} catch (e) {
  console.error('Failed to write passwd file:', e.message);
  process.exit(1);
}
