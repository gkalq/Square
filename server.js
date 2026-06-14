import express from 'express';
import jwt from 'jsonwebtoken';
import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const scryptAsync = promisify(scrypt);
const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 3000;
const DATA_PATH = process.env.DATA_PATH || join(__dirname, 'data.json');
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is required');
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(__dirname));

// ── Data store ──────────────────────────────────────────────
let writeLock = Promise.resolve();

function emptyTasks() {
  return { q1: [], q2: [], q3: [], q4: [] };
}

async function loadData() {
  if (!existsSync(DATA_PATH)) return {};
  try {
    const raw = await readFile(DATA_PATH, 'utf8');
    return raw.trim() ? JSON.parse(raw) : {};
  } catch (e) {
    console.error('Failed to read data file:', e.message);
    return {};
  }
}

async function saveData(data) {
  writeLock = writeLock.then(() =>
    writeFile(DATA_PATH, JSON.stringify(data, null, 2), 'utf8')
  ).catch((e) => console.error('Write failed:', e.message));
  return writeLock;
}

// ── Password hashing (scrypt) ───────────────────────────────
async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = await scryptAsync(String(password), salt, 64);
  return `${salt}:${derived.toString('hex')}`;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hashHex] = stored.split(':');
  const derived = await scryptAsync(String(password), salt, 64);
  const hashBuf = Buffer.from(hashHex, 'hex');
  if (hashBuf.length !== derived.length) return false;
  return timingSafeEqual(hashBuf, derived);
}

// ── JWT helpers ─────────────────────────────────────────────
function signToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.username = payload.username;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function validCreds(username, passcode) {
  return (
    typeof username === 'string' &&
    typeof passcode === 'string' &&
    username.trim().length >= 1 &&
    username.trim().length <= 40 &&
    passcode.length >= 1
  );
}

// ── Routes ──────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

app.post('/api/register', async (req, res) => {
  const { username, passcode } = req.body || {};
  if (!validCreds(username, passcode)) {
    return res.status(400).json({ error: 'Invalid username or passcode' });
  }
  const uname = username.trim();
  const data = await loadData();
  if (data[uname]) {
    return res.status(409).json({ error: 'User already exists' });
  }
  data[uname] = {
    hash: await hashPassword(passcode),
    tasks: emptyTasks(),
    history: [],
  };
  await saveData(data);
  res.json({ token: signToken(uname), username: uname });
});

app.post('/api/auth', async (req, res) => {
  const { username, passcode } = req.body || {};
  if (!validCreds(username, passcode)) {
    return res.status(400).json({ error: 'Invalid username or passcode' });
  }
  const uname = username.trim();
  const data = await loadData();
  const user = data[uname];
  if (!user || !(await verifyPassword(passcode, user.hash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ token: signToken(uname), username: uname });
});

app.get('/api/data', authMiddleware, async (req, res) => {
  const data = await loadData();
  const user = data[req.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ tasks: user.tasks || emptyTasks(), history: user.history || [] });
});

app.put('/api/data', authMiddleware, async (req, res) => {
  const { tasks, history } = req.body || {};
  const data = await loadData();
  const user = data[req.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (tasks && typeof tasks === 'object') {
    const next = emptyTasks();
    for (const q of ['q1', 'q2', 'q3', 'q4']) {
      if (Array.isArray(tasks[q])) next[q] = tasks[q];
    }
    user.tasks = next;
  }
  if (Array.isArray(history)) user.history = history.slice(0, 2000);
  await saveData(data);
  res.json({ ok: true });
});

app.put('/api/password', authMiddleware, async (req, res) => {
  const { oldPasscode, newPasscode } = req.body || {};
  if (typeof oldPasscode !== 'string' || typeof newPasscode !== 'string' || newPasscode.length < 1) {
    return res.status(400).json({ error: 'oldPasscode and newPasscode required' });
  }
  const data = await loadData();
  const user = data[req.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!(await verifyPassword(oldPasscode, user.hash))) {
    return res.status(401).json({ error: 'Current passcode is incorrect' });
  }
  user.hash = await hashPassword(newPasscode);
  await saveData(data);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Matrix server running on http://localhost:${PORT}`);
  console.log(`Data file: ${DATA_PATH}`);
});
