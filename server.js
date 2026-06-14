import express from 'express';
import jwt from 'jsonwebtoken';
import { scrypt, randomBytes, timingSafeEqual } from 'crypto';
import { promisify } from 'util';
import { readFileSync, writeFileSync, renameSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATA_PATH = process.env.DATA_PATH || 'data.json';

if (!JWT_SECRET) { console.error('Error: JWT_SECRET env var is required'); process.exit(1); }

const scryptAsync = promisify(scrypt);

async function hashPasscode(passcode) {
  const salt = randomBytes(16).toString('hex');
  const hash = await scryptAsync(String(passcode), salt, 64);
  return `${salt}:${hash.toString('hex')}`;
}

async function verifyPasscode(passcode, stored) {
  try {
    const [salt, hashHex] = stored.split(':');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = await scryptAsync(String(passcode), salt, 64);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch { return false; }
}

function loadDB() {
  if (!existsSync(DATA_PATH)) return {};
  try { return JSON.parse(readFileSync(DATA_PATH, 'utf8')); }
  catch { return {}; }
}

function saveDB(db) {
  const tmp = DATA_PATH + '.tmp';
  writeFileSync(tmp, JSON.stringify(db), 'utf8');
  renameSync(tmp, DATA_PATH);
}

const app = express();
app.use(express.json({ limit: '4mb' }));
app.use(express.static(__dirname));

function auth(req, res, next) {
  const header = req.headers.authorization;
  const token = header?.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.username = payload.username;
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/register', async (req, res) => {
  const { username, passcode } = req.body || {};
  if (!username || !passcode) return res.status(400).json({ error: 'Username and passcode required' });
  if (!/^[a-zA-Z0-9_-]{1,32}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 1–32 characters: letters, numbers, _ or -' });
  }
  const db = loadDB();
  if (db[username]) return res.status(409).json({ error: 'Username already taken' });
  db[username] = {
    hash: await hashPasscode(passcode),
    tasks: { q1: [], q2: [], q3: [], q4: [] },
    history: []
  };
  saveDB(db);
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

app.post('/api/auth', async (req, res) => {
  const { username, passcode } = req.body || {};
  if (!username || !passcode) return res.status(400).json({ error: 'Username and passcode required' });
  const db = loadDB();
  const user = db[username];
  if (!user || !(await verifyPasscode(passcode, user.hash))) {
    return res.status(401).json({ error: 'Invalid username or passcode' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

app.get('/api/data', auth, (req, res) => {
  const db = loadDB();
  const user = db[req.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ tasks: user.tasks, history: user.history });
});

app.put('/api/data', auth, (req, res) => {
  const { tasks, history } = req.body || {};
  if (!tasks || !Array.isArray(history)) return res.status(400).json({ error: 'Invalid data' });
  const db = loadDB();
  if (!db[req.username]) return res.status(404).json({ error: 'User not found' });
  db[req.username].tasks = tasks;
  db[req.username].history = history;
  saveDB(db);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Matrix running on http://localhost:${PORT}`));
