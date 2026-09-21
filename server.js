const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSION_SECRET = crypto.randomBytes(32).toString('hex');

app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

// Helpers
function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function generateApiKey() {
  return 'ak_' + crypto.randomBytes(24).toString('hex');
}

function generateId() {
  return crypto.randomBytes(8).toString('hex');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const verify = crypto.scryptSync(password, salt, 64).toString('hex');
  return hash === verify;
}

function createSessionToken(userId) {
  const payload = `${userId}:${Date.now()}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}:${sig}`).toString('base64');
}

function verifySession(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length < 3) return null;
    const sig = parts.pop();
    const payload = parts.join(':');
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
    if (sig !== expected) return null;
    const userId = parts[0];
    const users = readUsers();
    return users.find(u => u.id === userId) || null;
  } catch {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const user = verifySession(token);
  if (!user) return res.status(401).json({ error: 'Invalid session' });
  req.user = user;
  next();
}

// Routes

// Register
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const users = readUsers();

  if (users.find(u => u.email === email.toLowerCase())) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  const user = {
    id: generateId(),
    name,
    email: email.toLowerCase(),
    password: hashPassword(password),
    apiKey: generateApiKey(),
    createdAt: new Date().toISOString(),
  };

  users.push(user);
  writeUsers(users);

  const session = createSessionToken(user.id);
  res.cookie('session', session, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  res.json({
    ok: true,
    user: { id: user.id, name: user.name, email: user.email, apiKey: user.apiKey },
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const users = readUsers();
  const user = users.find(u => u.email === email.toLowerCase());

  if (!user || !verifyPassword(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const session = createSessionToken(user.id);
  res.cookie('session', session, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json({
    ok: true,
    user: { id: user.id, name: user.name, email: user.email, apiKey: user.apiKey },
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

// Get current user
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({
    ok: true,
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      apiKey: req.user.apiKey,
      createdAt: req.user.createdAt,
    },
  });
});

// Regenerate API key
app.post('/api/regenerate-key', authMiddleware, (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  users[idx].apiKey = generateApiKey();
  writeUsers(users);

  res.json({ ok: true, apiKey: users[idx].apiKey });
});

// Validate API key (POST)
app.post('/api/validate-key', (req, res) => {
  const { apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({ valid: false, error: 'apiKey is required' });
  }

  const users = readUsers();
  const user = users.find(u => u.apiKey === apiKey);

  if (!user) {
    return res.status(401).json({ valid: false, error: 'Invalid API key' });
  }

  res.json({
    valid: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
    },
    createdAt: user.createdAt,
  });
});

// Validate API key (GET — for quick testing)
app.get('/api/validate-key', (req, res) => {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;

  if (!apiKey) {
    return res.status(400).json({ valid: false, error: 'API key required (x-api-key header or ?api_key= param)' });
  }

  const users = readUsers();
  const user = users.find(u => u.apiKey === apiKey);

  if (!user) {
    return res.status(401).json({ valid: false, error: 'Invalid API key' });
  }

  res.json({
    valid: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
    },
    createdAt: user.createdAt,
  });
});

// Serve pages
app.get('/dashboard', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Redirect /dashboard to login if not auth (handled client-side)

app.listen(PORT, () => {
  console.log(`\n  AGENTIX server running at http://localhost:${PORT}\n`);
});
